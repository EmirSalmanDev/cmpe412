"""Guards of the test testbeds (D39, D47, D53, D57): one test per guard, on every test testbed."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb
import pandas as pd
import pytest
from typer.testing import CliRunner

from agent_fakes import FakeChat, open_tools, settings_for
from logtriage import guards
from logtriage import prepare as prepare_module
from logtriage.agents.runner import check_test_run, run_incidents
from logtriage.agents.tools import AgentTools
from logtriage.app.replay import check_live
from logtriage.cli import app
from logtriage.config import DEV_TESTBED, M11_TESTBEDS, TEST_TESTBED, Settings, load_settings
from logtriage.ml import detect as detect_module
from logtriage.ml import supervised as supervised_module
from logtriage.ml.detect import INCIDENTS_FILE, SCORES_FILE, run_detect
from logtriage.ml.supervised import (
    OOF_FILE,
    TEST_FILE_PATTERN,
    TRAINED,
    config_hash,
    run_dev,
    run_test,
)
from logtriage.prepare import run_prepare
from test_detect import ML, make_windows, write_testbed

ROOT = Path(__file__).parents[1]
CONFIG = ROOT / "configs" / "default.yaml"
REAL = load_settings(CONFIG, env_file=None)
TEST_TESTBEDS = REAL.test_testbeds
NEW_TESTBEDS = [name for name in TEST_TESTBEDS if name != TEST_TESTBED]
ALL_STAGES = [guards.DETECT, guards.SUPERVISED, guards.INVESTIGATE]

runner = CliRunner()


def settings_at(directory: Path) -> Settings:
    """Settings that write under a directory, with the real list of test testbeds."""
    settings = Settings(_env_file=None, ml=ML, test_testbeds=TEST_TESTBEDS)
    settings.paths.processed_dir = directory / "processed"
    settings.paths.reports_dir = directory / "reports"
    return settings


def agent_settings(directory: Path, **agents: bool) -> Settings:
    settings = settings_for(directory, **agents)
    settings.test_testbeds = TEST_TESTBEDS
    return settings


@pytest.fixture
def marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "container"
    path.touch()
    monkeypatch.setattr(guards, "CONTAINER_MARKER", path)
    return path


@pytest.fixture
def tools(tmp_path: Path) -> Iterator[AgentTools]:
    instance = open_tools(tmp_path, incidents=3)
    yield instance
    instance.close()


def test_the_config_lists_the_test_testbeds_and_not_dev() -> None:
    assert TEST_TESTBEDS[:3] == ["santos", "wardbeck", "harrison"]
    assert TEST_TESTBEDS[3:] == ["shaw", "fox"]  # M12: D74, D83, D85
    assert "wheeler" not in TEST_TESTBEDS  # fails the D55 criteria (D84)
    assert DEV_TESTBED not in TEST_TESTBEDS
    assert set(TEST_TESTBEDS) <= set(REAL.download.sources)
    extract = REAL.download.sources["ait_ads"].extract
    assert all(f"{name}_*.json" in extract for name in TEST_TESTBEDS)


def test_the_m11_evaluation_keeps_its_three_test_testbeds() -> None:
    assert M11_TESTBEDS == ("santos", "wardbeck", "harrison")
    assert set(M11_TESTBEDS) <= set(TEST_TESTBEDS)


# Prepare guard (D83).


class PastTheGuard(Exception):
    """Raised by a stand-in for the first step after the guard."""


@pytest.fixture
def prepare_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Settings whose testbeds all have their inputs, and a pipeline that stops after the guard."""
    settings = settings_at(tmp_path)
    settings.paths.raw_dir = tmp_path / "raw"
    settings.paths.data_meta_dir = tmp_path / "meta"
    settings.paths.data_meta_dir.mkdir()
    for name in [DEV_TESTBED, *TEST_TESTBEDS]:
        (settings.paths.raw_dir / name).mkdir(parents=True)
        (settings.paths.raw_dir / name / "dataset.yaml").write_text("name: x\n")
        (settings.paths.data_meta_dir / f"phases_{name}.csv").write_text("")

    def stop(*_: object) -> None:
        raise PastTheGuard

    monkeypatch.setattr(prepare_module, "read_phases_csv", stop)
    return settings


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_prepare_runs_once_on_every_test_testbed(testbed: str, prepare_inputs: Settings) -> None:
    with pytest.raises(PastTheGuard):
        run_prepare(testbed, prepare_inputs)
    assert [row["stage"] for row in guards.recorded_runs(prepare_inputs)] == [guards.PREPARE]
    with pytest.raises(ValueError, match="rerun-reason"):
        run_prepare(testbed, prepare_inputs)
    with pytest.raises(PastTheGuard):
        run_prepare(testbed, prepare_inputs, rerun_reason="why")
    assert [row["reason"] for row in guards.recorded_runs(prepare_inputs)] == ["", "why"]


def test_prepare_outputs_refuse_a_test_testbed_without_a_ledger_row(
    prepare_inputs: Settings,
) -> None:
    directory = prepare_inputs.paths.processed_dir / "santos"
    directory.mkdir(parents=True)
    (directory / "periods.json").write_text("{}")
    with pytest.raises(ValueError, match="rerun-reason"):
        run_prepare("santos", prepare_inputs)
    assert guards.recorded_runs(prepare_inputs) == []


def test_prepare_on_dev_is_neither_refused_nor_recorded(prepare_inputs: Settings) -> None:
    for _ in range(2):
        with pytest.raises(PastTheGuard):
            run_prepare(DEV_TESTBED, prepare_inputs)
    assert guards.recorded_runs(prepare_inputs) == []


def test_the_container_never_prepares_a_test_testbed(
    prepare_inputs: Settings, marker: Path
) -> None:
    with pytest.raises(ValueError, match="container"):
        run_prepare("shaw", prepare_inputs, rerun_reason="why")
    assert guards.recorded_runs(prepare_inputs) == []


def test_a_missing_download_does_not_use_up_the_run(prepare_inputs: Settings) -> None:
    (prepare_inputs.paths.raw_dir / "shaw" / "dataset.yaml").unlink()
    with pytest.raises(FileNotFoundError):
        run_prepare("shaw", prepare_inputs)
    assert guards.recorded_runs(prepare_inputs) == []


def test_prepare_is_never_retried_by_the_d69_rule() -> None:
    assert guards.PREPARE in guards.ONCE_ONLY
    assert not guards.is_paid_evaluation_stage(guards.PREPARE)


def test_the_committed_ledger_holds_every_santos_stage() -> None:
    settings = Settings(_env_file=None)
    settings.paths.reports_dir = ROOT / "reports"
    rows = guards.recorded_runs(settings)
    assert {row["stage"] for row in rows if row["testbed"] == TEST_TESTBED} >= set(ALL_STAGES)


# Freeze guard.


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_freeze_guard_covers_every_test_testbed(
    testbed: str, tmp_path: Path, tools: AgentTools
) -> None:
    chat = FakeChat()
    with pytest.raises(ValueError, match="freeze"):
        run_incidents(testbed, agent_settings(tmp_path), backend=chat, tools=tools)
    assert chat.calls == []


# Once-only guard, per stage.


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_investigate_runs_once_on_every_test_testbed(
    testbed: str, tmp_path: Path, tools: AgentTools
) -> None:
    settings = agent_settings(tmp_path, prompts_frozen=True)
    run_incidents(testbed, settings, ["x-0001"], backend=FakeChat(), tools=tools)
    chat = FakeChat()
    with pytest.raises(ValueError, match="rerun-reason"):
        run_incidents(testbed, settings, ["x-0001"], backend=chat, tools=tools)
    assert chat.calls == []
    again = run_incidents(
        testbed, settings, ["x-0001"], rerun_reason="why", backend=FakeChat(), tools=tools
    )
    assert again.rerun_reason == "why"
    assert [row["reason"] for row in guards.recorded_runs(settings)] == ["", "why"]


def test_a_lost_reports_folder_does_not_reopen_investigate(tmp_path: Path) -> None:
    settings = agent_settings(tmp_path, prompts_frozen=True)
    guards.record_run(guards.INVESTIGATE, "wardbeck", settings, None)
    with pytest.raises(ValueError, match="rerun-reason"):
        check_test_run("wardbeck", settings, tmp_path / "no-such-folder", None)


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_detect_runs_once_on_every_test_testbed(testbed: str, tmp_path: Path) -> None:
    settings = settings_at(tmp_path)
    write_testbed(settings.paths.processed_dir / testbed, {"vpn": make_windows()})
    run_detect(testbed, settings)
    with pytest.raises(ValueError, match="rerun-reason"):
        run_detect(testbed, settings)
    run_detect(testbed, settings, rerun_reason="why")
    assert [row["reason"] for row in guards.recorded_runs(settings)] == ["", "why"]


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_prepare_deleting_the_scores_does_not_reopen_detect(testbed: str, tmp_path: Path) -> None:
    settings = settings_at(tmp_path)
    directory = settings.paths.processed_dir / testbed
    write_testbed(directory, {"vpn": make_windows()})
    run_detect(testbed, settings)
    (directory / SCORES_FILE).unlink()  # what `prepare` does
    (directory / INCIDENTS_FILE).unlink()
    with pytest.raises(ValueError, match="rerun-reason"):
        run_detect(testbed, settings)


def test_detect_outputs_refuse_a_run_even_without_a_ledger_row(tmp_path: Path) -> None:
    settings = settings_at(tmp_path)
    directory = settings.paths.processed_dir / "harrison"
    write_testbed(directory, {"vpn": make_windows()})
    (directory / SCORES_FILE).touch()
    with pytest.raises(ValueError, match="rerun-reason"):
        run_detect("harrison", settings)


def test_the_dev_testbed_stays_free_to_rerun(tmp_path: Path) -> None:
    settings = settings_at(tmp_path)
    write_testbed(settings.paths.processed_dir / DEV_TESTBED, {"vpn": make_windows()})
    run_detect(DEV_TESTBED, settings)
    run_detect(DEV_TESTBED, settings)
    assert guards.recorded_runs(settings) == []


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_supervised_runs_once_on_every_test_testbed(testbed: str, tmp_path: Path) -> None:
    settings = settings_at(tmp_path)
    guards.record_run(guards.SUPERVISED, testbed, settings, None)
    with pytest.raises(ValueError, match="rerun-reason"):
        run_test(settings, testbed=testbed)
    with pytest.raises(duckdb.IOException):  # past the guard, and there is no data here
        run_test(settings, "why", testbed)


@pytest.mark.parametrize("testbed", NEW_TESTBEDS)
def test_supervised_results_refuse_a_run_even_without_a_ledger_row(
    testbed: str, tmp_path: Path
) -> None:
    settings = settings_at(tmp_path)
    results = settings.paths.reports_dir / "results"
    results.mkdir(parents=True)
    (results / TEST_FILE_PATTERN.format(testbed=testbed)).touch()
    with pytest.raises(ValueError, match="rerun-reason"):
        run_test(settings, testbed=testbed)


@pytest.mark.parametrize("testbed", NEW_TESTBEDS)
def test_a_missing_frozen_feature_stops_supervised_before_the_run_is_recorded(
    testbed: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_at(tmp_path)
    features = {"dns": ["n_queries"]}
    entry = {"baseline_capable": True, "features": [], "dropped_constant": []}
    monkeypatch.setattr(supervised_module, "inputs", lambda _: ({}, features, ["dns"]))
    monkeypatch.setattr(supervised_module, "feature_report", lambda *_: {"dns": entry})
    results = settings.paths.reports_dir / "results"
    results.mkdir(parents=True)
    pd.DataFrame(
        {"log_type": ["dns"], "status": [TRAINED], "config_hash": [config_hash(settings, features)]}
    ).to_csv(results / OOF_FILE, index=False)
    with pytest.raises(ValueError, match="without a known value"):
        run_test(settings, testbed=testbed)
    assert guards.recorded_runs(settings) == []


def test_supervised_scores_test_testbeds_only(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a test testbed"):
        run_test(settings_at(tmp_path), testbed=DEV_TESTBED)


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_the_dev_stage_stops_after_any_test_testbed_was_scored(
    testbed: str, tmp_path: Path
) -> None:
    settings = settings_at(tmp_path)
    results = settings.paths.reports_dir / "results"
    results.mkdir(parents=True)
    (results / TEST_FILE_PATTERN.format(testbed=testbed)).touch()
    with pytest.raises(FileExistsError):
        run_dev(settings)


# Container marker.


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
@pytest.mark.parametrize("stage", ALL_STAGES)
def test_the_container_refuses_every_stage_even_with_a_reason(
    stage: str, testbed: str, tmp_path: Path, marker: Path
) -> None:
    with pytest.raises(ValueError, match="container"):
        guards.check_run(stage, testbed, settings_at(tmp_path), [], "any reason")


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_the_container_refuses_the_agents_even_with_a_reason(
    testbed: str, tmp_path: Path, tools: AgentTools, marker: Path
) -> None:
    settings = agent_settings(tmp_path, prompts_frozen=True)
    chat = FakeChat()
    with pytest.raises(ValueError, match="container"):
        run_incidents(testbed, settings, rerun_reason="any", backend=chat, tools=tools)
    assert chat.calls == []


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_the_container_refuses_detect_and_supervised(
    testbed: str, tmp_path: Path, marker: Path
) -> None:
    settings = settings_at(tmp_path)
    write_testbed(settings.paths.processed_dir / testbed, {"vpn": make_windows()})
    with pytest.raises(ValueError, match="container"):
        run_detect(testbed, settings, rerun_reason="any")
    with pytest.raises(ValueError, match="container"):
        run_test(settings, "any", testbed)


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_the_container_ignores_a_list_changed_by_hand(
    testbed: str, tmp_path: Path, marker: Path
) -> None:
    settings = agent_settings(tmp_path, prompts_frozen=True)
    settings.test_testbeds = []
    with pytest.raises(ValueError, match="container"):
        check_test_run(testbed, settings, tmp_path, "any")
    with pytest.raises(ValueError, match="container"):
        guards.check_run(guards.DETECT, testbed, settings, [], "any")


def test_the_container_still_allows_dev(tmp_path: Path, marker: Path) -> None:
    settings = settings_at(tmp_path)
    guards.check_run(guards.DETECT, DEV_TESTBED, settings, [], None)
    check_test_run(DEV_TESTBED, settings, tmp_path, None)


# Live replay and the command line.


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_live_replay_is_refused_on_every_test_testbed(testbed: str) -> None:
    with pytest.raises(ValueError, match=testbed):
        check_live(testbed, REAL)


def test_the_cli_refuses_detect_on_santos_through_the_real_ledger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(ROOT)

    def refuse(*args: object, **kwargs: object) -> None:
        pytest.fail("detect reached the scoring of a test testbed")

    monkeypatch.setattr(detect_module, "score_testbed", refuse)
    result = runner.invoke(app, ["detect", "--testbed", TEST_TESTBED, "--config", str(CONFIG)])
    assert result.exit_code == 1
    assert "rerun-reason" in result.output


def test_a_recorded_run_needs_no_outputs_to_block(tmp_path: Path) -> None:
    settings = settings_at(tmp_path)
    assert guards.recorded_runs(settings) == []
    guards.record_run(guards.DETECT, "wardbeck", settings, None)
    guards.check_run(guards.DETECT, "harrison", settings, [], None)
    guards.check_run(guards.SUPERVISED, "wardbeck", settings, [], None)
    with pytest.raises(ValueError, match="wardbeck: detect"):
        guards.check_run(guards.DETECT, "wardbeck", settings, [], None)


def test_a_run_outside_the_list_leaves_the_ledger_alone(tmp_path: Path) -> None:
    settings = settings_at(tmp_path)
    guards.record_run(guards.DETECT, DEV_TESTBED, settings, None)
    assert not guards.runs_path(settings).exists()


@pytest.mark.parametrize("stage", [guards.DETECT, guards.SUPERVISED, guards.INVESTIGATE])
@pytest.mark.parametrize("testbed", ["santos", "wardbeck", "harrison"])
def test_the_retry_rule_never_covers_the_once_only_stages(
    tmp_path: Path, stage: str, testbed: str
) -> None:
    settings = Settings(_env_file=None)
    settings.paths.reports_dir = tmp_path
    guards.record_run(stage, testbed, settings, None)
    long_ago = datetime(2020, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="only ablation and LLM-only"):
        guards.check_retry(stage, testbed, settings, long_ago, [])


def test_a_retry_needs_a_failed_run_and_the_wait(tmp_path: Path) -> None:
    settings = Settings(_env_file=None)
    settings.paths.reports_dir = tmp_path
    stage = "ablation:rag0"
    ended = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    with pytest.raises(ValueError, match="nothing to retry"):
        guards.check_retry(stage, "santos", settings, ended, [])
    guards.record_stage(stage, "santos", settings, "why")
    with pytest.raises(ValueError, match="wait"):
        guards.check_retry(
            stage, "santos", settings, ended, [], ended + timedelta(minutes=9, seconds=59)
        )
    guards.check_retry(stage, "santos", settings, ended, [], ended + timedelta(minutes=10))
    guards.record_stage(guards.retry_name(stage), "santos", settings, "why")
    with pytest.raises(ValueError, match="stop and report"):
        guards.check_retry(stage, "santos", settings, ended, [], ended + timedelta(hours=1))


def test_a_stage_that_wrote_output_is_not_retried(tmp_path: Path) -> None:
    settings = Settings(_env_file=None)
    settings.paths.reports_dir = tmp_path
    guards.record_stage(guards.LLM_ONLY, "santos", settings, "why")
    output = tmp_path / "written"
    output.touch()
    long_ago = datetime(2020, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="wrote output"):
        guards.check_retry(guards.LLM_ONLY, "santos", settings, long_ago, [output])


def test_a_paid_stage_is_once_only_and_needs_a_reason(tmp_path: Path) -> None:
    settings = Settings(_env_file=None)
    settings.paths.reports_dir = tmp_path
    guards.check_once(guards.LLM_ONLY_CHECK, "russellmitchell", settings)
    with pytest.raises(ValueError, match="needs a reason"):
        guards.record_stage(guards.LLM_ONLY_CHECK, "russellmitchell", settings, " ")
    guards.record_stage(guards.LLM_ONLY_CHECK, "russellmitchell", settings, "why")
    with pytest.raises(ValueError, match="never runs twice"):
        guards.check_once(guards.LLM_ONLY_CHECK, "russellmitchell", settings)

"""v1 and v2 detection side by side on one testbed, and the M12 ledger fields (D86)."""

import csv
import hashlib
import json
import re
from pathlib import Path

import pandas as pd
import pytest

from agent_fakes import FakeChat, open_tools
from logtriage import guards
from logtriage.agents import runner as runner_module
from logtriage.agents.llm import EXPECTED_FINGERPRINT, CacheMissError, FingerprintChangedError
from logtriage.agents.runner import (
    AGENT_DB,
    MEMORY_DIR,
    RunSummary,
    expected_fingerprint,
    format_problems,
    run_incidents,
    run_paths,
)
from logtriage.config import (
    V1_MODE,
    V2_CONFIG_PATH,
    V2_MODE,
    Settings,
    config_chain,
    detection_mode,
    load_settings,
)
from logtriage.data.store import V2_DIR, build_agent_db, connect, detection_dir
from logtriage.eval.v2_compare import FROZEN, verdict
from logtriage.ml.detect import DETECT_REPORT_FILE, INCIDENTS_FILE, SCORES_FILE, run_detect
from test_detect import make_windows, write_testbed
from test_guards import TEST_TESTBEDS, agent_settings, settings_at

ROOT = Path(__file__).parents[1]
DEFAULT = ROOT / "configs" / "default.yaml"
V2 = ROOT / "configs" / "v2.yaml"
OUTPUTS = (SCORES_FILE, INCIDENTS_FILE, DETECT_REPORT_FILE)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def as_v2(settings: Settings) -> Settings:
    """The same settings, read as if from `configs/v2.yaml` (only the mode depends on it)."""
    settings.config_files = [V2, DEFAULT]
    return settings


def test_the_mode_comes_from_the_config_file() -> None:
    assert detection_mode(load_settings(DEFAULT, env_file=None)) == V1_MODE
    assert detection_mode(load_settings(V2, env_file=None)) == V2_MODE
    assert detection_mode(Settings(_env_file=None)) == V1_MODE  # built in code
    assert V2_CONFIG_PATH.resolve() == V2.resolve()


def test_the_config_chain_names_the_file_then_its_base() -> None:
    assert [path.name for path in config_chain(V2)] == ["v2.yaml", "default.yaml"]
    assert [path.name for path in config_chain(DEFAULT)] == ["default.yaml"]
    assert load_settings(V2, env_file=None).config_files == config_chain(V2)


def test_each_mode_has_its_folder() -> None:
    assert detection_dir(Path("d"), V1_MODE) == Path("d")
    assert detection_dir(Path("d"), V2_MODE) == Path("d") / V2_DIR
    with pytest.raises(ValueError, match="unknown mode"):
        detection_dir(Path("d"), "v3")


def test_v2_stages_are_once_only_and_never_retried() -> None:
    assert guards.mode_stage(guards.DETECT, V1_MODE) == "detect"
    assert guards.mode_stage(guards.DETECT, V2_MODE) == "detect:v2"
    assert guards.mode_stage(guards.INVESTIGATE, V2_MODE) == "investigate:v2"
    assert guards.is_once_only("detect:v2") and guards.is_once_only("investigate:v2")
    assert not guards.is_paid_evaluation_stage("detect:v2")
    assert guards.is_paid_evaluation_stage("ablation:rag0")


@pytest.mark.parametrize("testbed", TEST_TESTBEDS)
def test_v1_and_v2_each_detect_once_in_their_own_folders(testbed: str, tmp_path: Path) -> None:
    v1 = settings_at(tmp_path)
    v1.config_files = [DEFAULT]
    v2 = as_v2(settings_at(tmp_path))
    directory = v1.paths.processed_dir / testbed
    write_testbed(directory, {"vpn": make_windows()})

    run_detect(testbed, v2)
    assert all((directory / V2_DIR / name).is_file() for name in OUTPUTS)
    assert not any((directory / name).exists() for name in OUTPUTS)  # v1's files untouched
    with pytest.raises(ValueError, match="rerun-reason"):
        run_detect(testbed, v2)

    run_detect(testbed, v1)  # v2's run does not use up v1's
    v1_files = {name: sha(directory / name) for name in OUTPUTS}
    v2_files = {name: sha(directory / V2_DIR / name) for name in OUTPUTS}
    with pytest.raises(ValueError, match="rerun-reason"):
        run_detect(testbed, v1)
    assert {name: sha(directory / name) for name in OUTPUTS} == v1_files
    assert {name: sha(directory / V2_DIR / name) for name in OUTPUTS} == v2_files

    rows = guards.recorded_runs(v1)
    assert [(row["stage"], row["mode"]) for row in rows] == [("detect:v2", "v2"), ("detect", "v1")]
    assert rows[0]["config_sha256"] == sha(V2) and rows[0]["base_sha256"] == sha(DEFAULT)
    assert rows[1]["config_sha256"] == sha(DEFAULT) and rows[1]["base_sha256"] == ""
    assert all(re.fullmatch(r"[0-9a-f]{40}(\+dirty)?", row["commit"]) for row in rows)


def test_a_v2_output_alone_blocks_v2_but_not_v1(tmp_path: Path) -> None:
    v1 = settings_at(tmp_path)
    directory = v1.paths.processed_dir / "shaw"
    write_testbed(directory, {"vpn": make_windows()})
    (directory / V2_DIR).mkdir()
    (directory / V2_DIR / SCORES_FILE).touch()
    with pytest.raises(ValueError, match="rerun-reason"):
        run_detect("shaw", as_v2(settings_at(tmp_path)))
    run_detect("shaw", v1)


def test_the_v2_agent_tables_hold_v2_incidents_and_no_optional_feature(tmp_path: Path) -> None:
    windows = make_windows().assign(n_unseen_units=0.0)
    windows.to_parquet(tmp_path / "windows_audit.parquet", index=False)
    pd.DataFrame({"incident_id": ["v1-0001"]}).to_parquet(tmp_path / "incidents.parquet")
    detection = tmp_path / V2_DIR
    detection.mkdir()
    pd.DataFrame({"incident_id": ["v2-0001", "v2-0002"]}).to_parquet(
        detection / "incidents.parquet"
    )
    build_agent_db(tmp_path, detection)
    assert not (tmp_path / "agent.duckdb").exists()  # v1's database is not rebuilt
    with connect(detection / "agent.duckdb", read_only=True) as con:
        ids = [row[0] for row in con.execute("SELECT incident_id FROM incidents").fetchall()]
        columns = {row[0] for row in con.execute("DESCRIBE windows_audit").fetchall()}
    assert ids == ["v2-0001", "v2-0002"]
    assert "n_unseen_units" not in columns and "period" not in columns


def test_an_old_ledger_gains_the_new_columns_and_keeps_its_rows(tmp_path: Path) -> None:
    settings = settings_at(tmp_path)
    settings.config_files = [DEFAULT]
    path = guards.runs_path(settings)
    path.parent.mkdir(parents=True)
    path.write_text(
        "testbed,stage,utc,reason\nsantos,detect,2026-11-06T00:00:00+00:00,\n"
        'santos,investigate,2026-11-06T01:00:00+00:00,"a, reason"\n',
        encoding="utf-8",
    )
    guards.record_run(guards.PREPARE, "shaw", settings, None)
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    assert reader.fieldnames == guards.RUN_FIELDS
    assert [(row["testbed"], row["stage"], row["reason"]) for row in rows] == [
        ("santos", "detect", ""),
        ("santos", "investigate", "a, reason"),
        ("shaw", "prepare", ""),
    ]
    assert rows[0]["utc"] == "2026-11-06T00:00:00+00:00"
    assert rows[0]["mode"] == rows[0]["commit"] == rows[0]["config_sha256"] == ""
    assert rows[2]["mode"] == "" and rows[2]["config_sha256"] == sha(DEFAULT)


def test_a_commit_outside_git_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_git(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("git")

    monkeypatch.setattr(guards.subprocess, "run", no_git)
    assert guards.current_commit() == guards.UNKNOWN_COMMIT


# v2 investigate (D90): v2's incidents, reports, run table and memory, apart from v1's.


def test_each_mode_investigates_from_its_own_paths(tmp_path: Path) -> None:
    settings = agent_settings(tmp_path)
    base = settings.paths.processed_dir / "shaw"
    v1 = run_paths("shaw", settings, V1_MODE)
    v2 = run_paths("shaw", settings, V2_MODE)
    assert (v1.reports_dir, v1.database, v1.memory_dir) == (base / "reports", base / AGENT_DB, None)
    assert v1.table == settings.paths.reports_dir / "results" / "agents_shaw.csv"
    assert (v2.reports_dir, v2.database) == (base / "v2" / "reports", base / "v2" / AGENT_DB)
    assert v2.memory_dir == base / "v2" / MEMORY_DIR
    assert v2.table == settings.paths.reports_dir / "results" / "agents_shaw_v2.csv"


@pytest.mark.parametrize("testbed", ["shaw", "fox"])
def test_v1_and_v2_each_investigate_once_and_apart(testbed: str, tmp_path: Path) -> None:
    v1 = agent_settings(tmp_path, prompts_frozen=True)
    v2 = as_v2(agent_settings(tmp_path, prompts_frozen=True))
    base = v1.paths.processed_dir / testbed
    (base / "v2").mkdir(parents=True)
    tools = open_tools(base / "v2", incidents=2)  # builds v2/agent.duckdb
    try:
        run_incidents(testbed, v2, backend=FakeChat(), tools=tools)
        assert sorted(path.name for path in (base / "v2" / "reports").iterdir()) == [
            "run_summary.json",
            "x-0001.json",
            "x-0002.json",
        ]
        assert not (base / "reports").exists()  # v1's folder untouched
        assert (v2.paths.reports_dir / "results" / f"agents_{testbed}_v2.csv").is_file()
        assert not (v2.paths.reports_dir / "results" / f"agents_{testbed}.csv").exists()
        chat = FakeChat()
        with pytest.raises(ValueError, match="rerun-reason"):
            run_incidents(testbed, v2, backend=chat, tools=tools)
        assert chat.calls == []
        run_incidents(testbed, v1, ["x-0001"], backend=FakeChat(), tools=tools)  # v1's own run
        assert (base / "reports" / "x-0001.json").is_file()
    finally:
        tools.close()
    rows = guards.recorded_runs(v1)
    assert [(row["stage"], row["mode"]) for row in rows] == [
        ("investigate:v2", "v2"),
        ("investigate", "v1"),
    ]


def test_v2_investigate_opens_the_v2_tables_and_its_own_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = as_v2(agent_settings(tmp_path, prompts_frozen=True))
    directory = settings.paths.processed_dir / "shaw" / "v2"
    directory.mkdir(parents=True)
    (directory / AGENT_DB).touch()
    opened, closed = {}, []

    class Tools:
        def close(self) -> None:
            closed.append(True)

    def fake_open(testbed: str, settings: Settings, **kwargs: object) -> Tools:
        opened.update(kwargs, testbed=testbed)
        return Tools()

    def fake_queue(*args: object, **kwargs: object) -> RunSummary:
        assert isinstance(kwargs["tools"], Tools)
        return RunSummary("shaw", "run")

    monkeypatch.setattr(runner_module.AgentTools, "open", fake_open)
    monkeypatch.setattr(runner_module, "run_queue", fake_queue)
    run_incidents("shaw", settings)
    assert opened == {
        "testbed": "shaw",
        "database": directory / AGENT_DB,
        "memory_dir": directory / MEMORY_DIR,
    }
    assert closed == [True]


def test_v2_investigate_needs_v2_detect_first(tmp_path: Path) -> None:
    settings = as_v2(agent_settings(tmp_path, prompts_frozen=True))
    with pytest.raises(FileNotFoundError, match="configs/v2.yaml"):
        run_incidents("shaw", settings, backend=FakeChat())
    assert guards.recorded_runs(settings) == []


def test_the_m12_testbeds_keep_the_model_of_the_m11_reports(tmp_path: Path) -> None:
    settings = agent_settings(tmp_path)
    assert expected_fingerprint("shaw", settings) == EXPECTED_FINGERPRINT
    assert expected_fingerprint("fox", settings) == EXPECTED_FINGERPRINT
    assert expected_fingerprint("santos", settings) is None
    assert expected_fingerprint("russellmitchell", settings) is None


def test_a_paid_answer_from_another_model_stops_the_run(tmp_path: Path) -> None:
    settings = agent_settings(tmp_path)
    tools = open_tools(tmp_path, incidents=1)
    try:
        with pytest.raises(FingerprintChangedError):
            run_incidents(
                "russellmitchell",
                settings,
                backend=FakeChat(),  # answers as fp_fake
                tools=tools,
                expected_fingerprint=EXPECTED_FINGERPRINT,
            )
    finally:
        tools.close()


def test_a_cache_only_run_pays_nothing(tmp_path: Path) -> None:
    settings = agent_settings(tmp_path)
    tools = open_tools(tmp_path, incidents=1)
    chat = FakeChat()
    try:
        with pytest.raises(CacheMissError):
            run_incidents("russellmitchell", settings, backend=chat, tools=tools, cache_only=True)
    finally:
        tools.close()
    assert chat.calls == []


# The §7 reading of `reports/v2_plan.md`, as written (D86).


def summary_row(testbed: str, mode: str, credited: list[str], per_day: float = 5.0) -> dict:
    phases = ["a", "b", "c", "d"]
    return {
        "testbed": testbed,
        "mode": mode,
        "phases": len(phases),
        "detected": len(credited),
        "credited": " ".join(credited),
        "missed": " ".join(phase for phase in phases if phase not in credited),
        "within_budget": per_day <= 25,
    }


def credit_rows(testbed: str, mode: str, through: dict[str, str]) -> list[dict]:
    """Credit per phase: `through` maps a credited phase to the log type that credits it."""
    return [
        {
            "testbed": testbed,
            "mode": mode,
            "phase": phase,
            "audit": int(through.get(phase) == "audit"),
            "dns": int(through.get(phase) == "dns"),
            "detected": phase in through,
            "dns_only": through.get(phase) == "dns",
        }
        for phase in ["a", "b", "c", "d"]
    ]


def read(v1: dict[str, dict[str, str]], v2: dict[str, dict[str, str]], v2_per_day=5.0) -> dict:
    rows, credit = [], []
    for mode, plan in (("v1", v1), ("v2", v2)):
        for testbed, through in plan.items():
            per_day = v2_per_day if mode == "v2" and testbed == "fox" else 5.0
            rows.append(summary_row(testbed, mode, list(through), per_day))
            credit += credit_rows(testbed, mode, through)
    return verdict(pd.DataFrame(rows), pd.DataFrame(credit))


def test_a_gain_through_another_type_within_budget_helps() -> None:
    reading = read(
        {"shaw": {"a": "audit"}, "fox": {"a": "audit"}},
        {"shaw": {"a": "audit", "b": "audit"}, "fox": {"a": "audit"}},
    )
    assert reading["verdict"] == "helps"
    assert reading["gained"] == {"shaw": ["b"], "fox": []}


def test_a_gain_through_dns_alone_does_not_help() -> None:
    reading = read(
        {"shaw": {"a": "audit"}, "fox": {}},
        {"shaw": {"a": "audit"}, "fox": {"b": "dns"}},
    )
    assert reading["verdict"] == "does not help"
    assert not reading["extra_phase_through_non_dns"]


def test_the_same_total_does_not_help_and_the_lost_phase_is_named() -> None:
    reading = read(
        {"shaw": {"a": "audit"}, "fox": {"c": "audit"}},
        {"shaw": {"b": "audit"}, "fox": {"c": "audit"}},
    )
    assert reading["verdict"] == "does not help"
    assert reading["lost"] == {"shaw": ["a"], "fox": []}


def test_fewer_phases_or_a_testbed_over_budget_hurts() -> None:
    fewer = read(
        {"shaw": {"a": "audit", "b": "audit"}, "fox": {}}, {"shaw": {"a": "audit"}, "fox": {}}
    )
    assert fewer["verdict"] == "hurts"
    over = read(
        {"shaw": {"a": "audit"}, "fox": {}},
        {"shaw": {"a": "audit", "b": "audit"}, "fox": {}},
        v2_per_day=25.5,
    )
    assert over["verdict"] == "hurts" and over["v2_over_budget_on_a_testbed"]


def test_the_frozen_denominators_are_those_of_the_targets_files() -> None:
    for testbed, sizes in FROZEN.items():
        text = (ROOT / "reports" / f"targets_{testbed}.md").read_text(encoding="utf-8")
        frozen = text.split("## Frozen denominators", 1)[1]
        for variant, size in zip(["primary", "all parsed", "without exfil"], sizes, strict=True):
            assert f"| {variant} | {size} |" in frozen


def test_the_format_check_passes_a_clean_run_and_names_each_problem(tmp_path: Path) -> None:
    settings = agent_settings(tmp_path)
    tools = open_tools(tmp_path, incidents=2)
    try:
        run_incidents("russellmitchell", settings, backend=FakeChat(), tools=tools)
    finally:
        tools.close()
    reports = settings.paths.processed_dir / "russellmitchell" / "reports"
    assert format_problems(reports, ["x-0001", "x-0002"]) == []
    assert format_problems(reports, ["x-0001", "x-0002", "x-0003"]) == ["x-0003: no report"]
    report = json.loads((reports / "x-0002.json").read_text(encoding="utf-8"))
    report["summary"][0]["evidence"] = ["E99"]
    (reports / "x-0002.json").write_text(json.dumps(report), encoding="utf-8")
    (reports / "x-0001.json").write_text("{}", encoding="utf-8")
    problems = format_problems(reports, ["x-0001", "x-0002"])
    assert problems[0].startswith("x-0001: does not parse")
    assert problems[1] == "x-0002: cites eids outside its evidence: ['E99']"

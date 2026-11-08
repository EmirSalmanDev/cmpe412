"""The `evaluate` command (plan 10.6, D67): one command, and no paid call can happen."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest
from typer.testing import CliRunner

from agent_fakes import settings_for
from logtriage.agents.cache import LlmCache
from logtriage.agents.llm import CacheMissError
from logtriage.cli import app
from logtriage.config import load_settings
from logtriage.eval import ablations, faithfulness, llm_baseline, report, results_text
from logtriage.eval.report import PaidCallError, check_frozen_inputs, run_evaluate

ROOT = Path(__file__).parents[1]
runner = CliRunner()


def test_evaluate_does_not_load_the_scoring_code() -> None:
    code = (
        "import sys, logtriage.eval.report; "
        "print([m for m in sys.modules if m.startswith('logtriage.ml')])"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, cwd=ROOT
    )
    assert result.stdout.strip() == "[]"


def test_a_missing_input_of_a_once_only_stage_stops_it(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    with pytest.raises(FileNotFoundError, match="once-only"):
        check_frozen_inputs(settings)


def test_a_missing_answer_fails_the_command(monkeypatch: pytest.MonkeyPatch) -> None:
    def miss(*args: object) -> None:
        raise CacheMissError("llm_only: no saved answer")

    monkeypatch.setattr("logtriage.cli.run_evaluate", miss)
    result = runner.invoke(app, ["evaluate"])
    assert result.exit_code == 1
    assert "evaluate failed: llm_only: no saved answer" in result.output


def test_the_replay_of_the_baseline_cannot_pay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(tmp_path)
    seen = {}

    def ask(testbed, keys, settings_, backend, replay):
        seen[testbed] = replay
        return llm_baseline.SampleRun([{"position": 1}])

    monkeypatch.setattr(llm_baseline, "_ask", ask)
    monkeypatch.setattr(llm_baseline, "read_keys", lambda _: pd.DataFrame())
    monkeypatch.setattr(llm_baseline, "dev_keys", lambda _: pd.DataFrame())
    llm_baseline.replay_outputs(settings)
    assert seen == {"santos": True, "russellmitchell": True}


def test_a_moved_ledger_fails_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = settings_for(tmp_path)

    def pay(_: object) -> None:
        cache = LlmCache(tmp_path / "cache" / "llm.sqlite")
        cache.record_spend("m", "r", 0.01)
        cache.close()

    monkeypatch.setattr(report, "check_frozen_inputs", lambda _: None)
    monkeypatch.setattr(report.llm_baseline, "replay_outputs", pay)
    monkeypatch.setattr(report, "run_tables", lambda _: None)
    monkeypatch.setattr(report, "load_inputs", lambda *_: None)
    monkeypatch.setattr(report, "build_tables", lambda *_: {})
    monkeypatch.setattr(report, "ablation_tables", lambda *_: {})
    monkeypatch.setattr(report.llm_baseline, "metric_tables", lambda _: {})
    monkeypatch.setattr(report.faithfulness, "auto_table", lambda _: pd.DataFrame())
    monkeypatch.setattr(report, "ai_tables", lambda _: {})
    monkeypatch.setattr(report, "tool_table", lambda _: pd.DataFrame())
    monkeypatch.setattr(report, "dev_candidate_recall", lambda _: pd.DataFrame())
    monkeypatch.setattr(report, "render", lambda _: "text")
    with pytest.raises(PaidCallError, match="ledger moved"):
        run_evaluate(settings)


def test_tables_cover_tools_never_called() -> None:
    reports = {"a": {"meta": {"tool_calls": [{"tool": "log_search"}, {"tool": "run_sql"}]}}}
    item = type("Item", (), {"name": "t", "reports": reports})
    table = report.tool_table([item]).set_index("tool")["calls"]
    assert table.to_dict() == {"log_search": 1, "run_sql": 1, "similar_incidents": 0}


def test_percent_and_number_cells_show_a_gap() -> None:
    assert results_text.pct(float("nan")) == "n/a"
    assert results_text.num(float("nan")) == "n/a"
    assert results_text.pct(0.5) == "50.0%"


def test_a_lookup_refuses_anything_but_one_row() -> None:
    frame = pd.DataFrame({"a": [1, 1], "b": [2, 3]})
    assert results_text.one(frame, b=2)["a"] == 1
    with pytest.raises(ValueError, match="2 rows"):
        results_text.one(frame, a=1)


@pytest.mark.data
def test_one_command_regenerates_everything_without_paying(tmp_path: Path) -> None:
    """Run it on a copy of `reports/`, then compare with what is committed."""
    settings = load_settings()
    copy = tmp_path / "reports"
    shutil.copytree(ROOT / "reports", copy)
    cached = shutil.copy(settings.paths.cache_dir / "llm.sqlite", tmp_path / "llm.sqlite")
    for sheet in faithfulness.SHEETS:
        for path in (
            faithfulness.key_path(settings, sheet),
            faithfulness.paired_path(settings, sheet),
        ):
            shutil.copy(path, tmp_path / path.name)
    settings.paths.reports_dir = copy
    settings.paths.cache_dir = tmp_path
    before = ablations.ledger_state(settings)
    for path in (copy / "results").glob("eval_*.csv"):
        path.unlink()
    (copy / "results.md").unlink()
    run_evaluate(settings)
    assert ablations.ledger_state(settings) == before
    assert Path(cached).is_file()
    assert (copy / "results.md").read_text("utf-8") == (ROOT / "reports" / "results.md").read_text(
        "utf-8"
    )
    for path in sorted((ROOT / "reports" / "results").glob("*.csv")):
        assert (copy / "results" / path.name).read_bytes() == path.read_bytes(), path.name


@pytest.mark.parametrize("sheet", ["full_evidence", "raw_only"])
def test_the_sheet_on_file_names_no_testbed(sheet: str) -> None:
    path = ROOT / "reports" / "faithfulness" / sheet / "claims_sheet.csv"
    text = path.read_text("utf-8").lower()
    for name in ("santos", "wardbeck", "harrison", "russellmitchell", "verifier", "note"):
        assert name not in text
    header = text.splitlines()[0]
    assert header == "id,claim,cited_lines"


def test_the_two_sheets_share_no_id() -> None:
    ids = [
        set(pd.read_csv(ROOT / "reports" / "faithfulness" / sheet / "claims_sheet.csv")["id"])
        for sheet in ("full_evidence", "raw_only")
    ]
    assert not ids[0] & ids[1]


def test_the_key_is_not_in_the_repository() -> None:
    tracked = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True, cwd=ROOT
    ).stdout
    assert "faithfulness_key" not in tracked
    assert json.dumps("data/cache") not in tracked

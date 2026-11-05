"""Acceptance checks for M2 on the real datasets (plan 13)."""

import json
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pytest

from logtriage.config import load_settings
from logtriage.data.periods import load_periods
from logtriage.prepare import run_prepare

ROOT = Path(__file__).parents[1]
TESTBEDS = ["russellmitchell", "santos"]
FIRST_ATTACK = {
    "russellmitchell": datetime(2022, 1, 24, 3, 1, tzinfo=UTC),
    "santos": datetime(2022, 1, 16, 7, 16, 17, tzinfo=UTC),
}
MIN_PARSE_RATE = 0.99
MIN_PHASE_RATE = 0.95

pytestmark = [pytest.mark.data, pytest.mark.parametrize("testbed", TESTBEDS)]


def processed(testbed: str) -> Path:
    return ROOT / "data" / "processed" / testbed


def load_json(testbed: str, name: str) -> dict:
    return json.loads((processed(testbed) / name).read_text(encoding="utf-8"))


@pytest.fixture
def evaluation(testbed: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(ROOT)
    with duckdb.connect(str(processed(testbed) / "eval.duckdb"), read_only=True) as connection:
        yield connection


def test_periods(testbed: str) -> None:
    periods = load_periods(processed(testbed) / "periods.json")
    assert periods.first_attack == FIRST_ATTACK[testbed]
    assert periods.gap_hours == 24
    assert periods.training_hours >= 24
    assert periods.train_start < periods.fit_end < periods.train_end == periods.eval_start


def test_parse_rate_per_file(testbed: str) -> None:
    files = load_json(testbed, "prepare_report.json")["files"]
    assert files
    assert [f["file"] for f in files if f["parse_rate"] < MIN_PARSE_RATE] == []


def test_every_label_resolves_to_a_parsed_line(testbed: str, evaluation) -> None:
    report = load_json(testbed, "label_report.json")
    assert report["labeled"] == report["resolved"] > 0
    unparsed = evaluation.execute(
        "SELECT count(*) FROM labels JOIN lines USING (line_id) WHERE NOT parse_ok"
    ).fetchone()
    assert unparsed == (0,)


def test_labeled_lines_fall_in_a_phase_for_every_log_type(testbed: str) -> None:
    report = load_json(testbed, "label_report.json")
    assert report["in_phase_rate"] >= MIN_PHASE_RATE
    for name, item in report["files"].items():
        in_phase = item["resolved"] - item["phases"].get("unassigned", 0)
        assert in_phase / item["resolved"] >= MIN_PHASE_RATE, name


def test_label_lines_are_one_based(testbed: str, evaluation) -> None:
    def labeled_raw(file: str, shift: int) -> list[str]:
        return [
            row[0]
            for row in evaluation.execute(
                """
                SELECT l.raw FROM labels b
                JOIN lines l ON l.host = split_part(b.line_id, '|', 1)
                    AND l.file = split_part(b.line_id, '|', 2)
                    AND l.line_no = CAST(split_part(b.line_id, '|', 3) AS BIGINT) + ?
                WHERE split_part(b.line_id, '|', 2) = ?
                ORDER BY l.line_no
                """,
                [shift, file],
            ).fetchall()
        ]

    auth = labeled_raw("logs/auth.log", 0)
    assert "Successful su for" in auth[0]
    assert not any("CRON" in raw for raw in auth)
    assert "TLS: Initial packet" in labeled_raw("logs/openvpn.log", 0)[0]
    # If the numbers were 0-based, each would point one line further on.
    assert "Successful su for" not in labeled_raw("logs/auth.log", 1)[0]
    assert "TLS: Initial packet" not in labeled_raw("logs/openvpn.log", 1)[0]


def test_lines_contract(testbed: str, evaluation) -> None:
    periods = load_periods(processed(testbed) / "periods.json")
    total, distinct, first, last = evaluation.execute(
        "SELECT count(*), count(DISTINCT line_id), min(ts), max(ts) FROM lines"
    ).fetchone()
    assert total == distinct
    assert periods.sim_start <= first and last < periods.sim_end
    unparsed = evaluation.execute(
        "SELECT DISTINCT log_type FROM lines WHERE NOT parse_ok"
    ).fetchall()
    assert unparsed == [("apache_error",)]
    missing = evaluation.execute(
        "SELECT count(*) FROM lines WHERE parse_ok AND template_id IS NULL"
    ).fetchone()
    assert missing == (0,)


def test_fit_lines_are_never_unseen(testbed: str) -> None:
    for item in load_json(testbed, "prepare_report.json")["log_types"].values():
        assert item["unseen_fit_lines"] == 0


def test_agent_db_exposes_no_ground_truth(testbed: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    with duckdb.connect(str(processed(testbed) / "agent.duckdb"), read_only=True) as agent:
        names = {row[0] for row in agent.execute("SHOW TABLES").fetchall()}
    assert names and not any("label" in name or "phase" in name for name in names)


def test_rerun_gives_identical_template_ids(
    testbed: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    settings = load_settings("configs/default.yaml", env_file=None)
    settings.paths.processed_dir = tmp_path
    rerun = json.loads((run_prepare(testbed, settings) / "prepare_report.json").read_text())
    stored = load_json(testbed, "prepare_report.json")
    for log_type, item in stored["log_types"].items():
        assert rerun["log_types"][log_type]["template_digest"] == item["template_digest"], log_type

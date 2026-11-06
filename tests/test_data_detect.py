"""Acceptance checks for M5 on the real datasets (plan 13)."""

import json
from pathlib import Path

import pandas as pd
import pytest

from logtriage.config import load_settings
from logtriage.data.store import connect
from logtriage.ml.detect import DETECT_REPORT_FILE, INCIDENTS_FILE, SCORES_FILE

ROOT = Path(__file__).parents[1]
TESTBEDS = ["russellmitchell", "santos"]
KEY = ["testbed", "host", "log_type", "window_start"]

pytestmark = [pytest.mark.data, pytest.mark.parametrize("testbed", TESTBEDS)]


def processed(testbed: str) -> Path:
    return ROOT / "data" / "processed" / testbed


def scores_of(testbed: str) -> pd.DataFrame:
    return pd.read_parquet(processed(testbed) / SCORES_FILE)


def incidents_of(testbed: str) -> pd.DataFrame:
    return pd.read_parquet(processed(testbed) / INCIDENTS_FILE)


def report_of(testbed: str) -> dict:
    return json.loads((processed(testbed) / DETECT_REPORT_FILE).read_text(encoding="utf-8"))


def test_both_testbeds_use_the_values_chosen_on_dev(testbed: str) -> None:
    settings = load_settings(ROOT / "configs" / "default.yaml", env_file=None)
    report = report_of(testbed)
    assert report["q"] == settings.ml.q
    assert report["gap_minutes"] == settings.ml.gap_minutes


def test_every_window_of_a_capable_type_has_one_score(testbed: str) -> None:
    scores = scores_of(testbed)
    assert not scores.duplicated(KEY).any()
    for log_type in report_of(testbed)["log_types"]:
        windows = pd.read_parquet(processed(testbed) / f"windows_{log_type}.parquet")
        assert (scores["log_type"] == log_type).sum() == len(windows)


def test_apache_error_is_reported_and_not_scored(testbed: str) -> None:
    assert report_of(testbed)["no_baseline"] == ["apache_error"]
    assert "apache_error" not in set(scores_of(testbed)["log_type"])


def test_scores_follow_the_definitions(testbed: str) -> None:
    scores = scores_of(testbed)
    percentiles = scores[["pct_if", "pct_lof", "pct_pca"]]
    assert percentiles.stack().between(0, 1).all()
    assert (percentiles.mean(axis=1) - scores["score"]).abs().max() < 1e-12
    assert ((scores["score"] >= report_of(testbed)["q"]) == scores["is_anomalous"]).all()


def test_lof_stays_in_a_sane_range_on_calib_windows(testbed: str) -> None:
    scores = scores_of(testbed)
    assert scores.loc[scores["period"] == "calib", "score_lof"].max() < 1000


def test_incidents_hold_exactly_the_anomalous_eval_windows(testbed: str) -> None:
    scores = scores_of(testbed)
    nodes = scores[scores["is_anomalous"] & (scores["period"] == "eval")]
    assert nodes["incident_id"].notna().all()
    assert scores.loc[scores["period"] != "eval", "incident_id"].isna().all()
    incidents = incidents_of(testbed)
    assert incidents["n_windows"].sum() == len(nodes)
    assert set(nodes["incident_id"]) == set(incidents["incident_id"])


def test_window_keys_point_at_scored_windows(testbed: str) -> None:
    scores = scores_of(testbed).set_index(["host", "log_type", "window_start"])
    for _, row in incidents_of(testbed).iterrows():
        for name, host, log_type, start in json.loads(row["window_keys"]):
            assert name == testbed
            found = scores.loc[(host, log_type, pd.Timestamp(start))]
            assert found["incident_id"] == row["incident_id"]


def test_incidents_are_sorted_by_priority(testbed: str) -> None:
    assert incidents_of(testbed)["priority"].is_monotonic_decreasing


def test_detection_tables_are_in_the_agent_database(
    testbed: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    with connect(processed(testbed) / "agent.duckdb", read_only=True) as agent:
        names = {row[0] for row in agent.execute("SHOW TABLES").fetchall()}
        assert {"scores", "incidents"} <= names
        assert not any("label" in name or "phase" in name for name in names)
        count = agent.execute("SELECT count(*) FROM incidents").fetchone()[0]
    assert count == len(incidents_of(testbed))

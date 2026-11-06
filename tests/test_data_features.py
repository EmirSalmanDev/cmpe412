"""Acceptance checks for M4 on the real datasets (plan 13)."""

import json
from datetime import timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from logtriage.data.features import (
    FEATURE_SETS,
    SCALER_DIR,
    FeatureScaler,
    feature_columns,
    is_vocabulary_feature,
)
from logtriage.data.periods import load_periods
from logtriage.data.store import connect

ROOT = Path(__file__).parents[1]
TESTBEDS = ["russellmitchell", "santos"]
KEY = ["testbed", "host", "log_type", "window_start"]
WINDOW = timedelta(seconds=60)

pytestmark = [pytest.mark.data, pytest.mark.parametrize("testbed", TESTBEDS)]


def processed(testbed: str) -> Path:
    return ROOT / "data" / "processed" / testbed


def report_of(testbed: str) -> dict:
    return json.loads((processed(testbed) / "features_report.json").read_text(encoding="utf-8"))


def windows_of(testbed: str, log_type: str) -> pd.DataFrame:
    return pd.read_parquet(processed(testbed) / f"windows_{log_type}.parquet")


@pytest.mark.parametrize("log_type", FEATURE_SETS)
def test_windows_hold_every_parsed_line_and_nothing_else(testbed: str, log_type: str) -> None:
    path = processed(testbed) / f"lines_{log_type}.parquet"
    with connect() as con:
        parsed = con.execute(f"SELECT count(*) FROM '{path}' WHERE parse_ok").fetchone()[0]
    assert windows_of(testbed, log_type)["n_lines"].sum() == parsed


@pytest.mark.parametrize("log_type", FEATURE_SETS)
def test_window_key_is_unique_and_utc(testbed: str, log_type: str) -> None:
    windows = windows_of(testbed, log_type)
    assert not windows.duplicated(KEY).any()
    assert str(windows["window_start"].dt.tz) == "UTC"
    assert (windows["window_start"].dt.second == 0).all()


@pytest.mark.parametrize("log_type", FEATURE_SETS)
def test_features_are_finite(testbed: str, log_type: str) -> None:
    windows = windows_of(testbed, log_type)
    values = windows[feature_columns(windows)].to_numpy(dtype=float)
    assert np.isfinite(values).all()


@pytest.mark.parametrize("log_type", FEATURE_SETS)
def test_periods_follow_the_boundaries(testbed: str, log_type: str) -> None:
    periods = load_periods(processed(testbed) / "periods.json")
    windows = windows_of(testbed, log_type)
    ends = windows["window_start"] + WINDOW
    assert (ends[windows["period"] == "fit"] <= periods.fit_end).all()
    assert (ends[windows["period"] == "calib"] <= periods.train_end).all()
    assert (ends[windows["period"] == "calib"] > periods.fit_end).all()
    assert (ends[windows["period"] == "eval"] > periods.train_end).all()


def test_apache_error_has_no_vocabulary_features_or_scaler(testbed: str) -> None:
    entry = report_of(testbed)["apache_error"]
    assert entry["fit_lines"] < 200
    assert not entry["baseline_capable"]
    assert not [name for name in entry["features"] if is_vocabulary_feature(name)]
    assert not (processed(testbed) / SCALER_DIR / "apache_error.json").exists()


def test_baseline_capable_types_have_a_scaler_over_their_columns(testbed: str) -> None:
    for log_type, entry in report_of(testbed).items():
        if entry["baseline_capable"]:
            scaler = FeatureScaler.load(processed(testbed) / SCALER_DIR / f"{log_type}.json")
            windows = windows_of(testbed, log_type)
            assert scaler.columns == feature_columns(windows)
            assert np.isfinite(scaler.transform(windows)).all()


def test_scaled_fit_windows_have_median_zero(testbed: str) -> None:
    for log_type, entry in report_of(testbed).items():
        if entry["baseline_capable"]:
            scaler = FeatureScaler.load(processed(testbed) / SCALER_DIR / f"{log_type}.json")
            windows = windows_of(testbed, log_type)
            # The clip comes after the scaler, and a median over an even count can straddle it.
            scaled = scaler.transform(windows[windows["period"] == "fit"], clip=False)
            assert np.median(scaled, axis=0) == pytest.approx(0, abs=1e-9)


def test_dns_features_are_present(testbed: str) -> None:
    features = report_of(testbed)["dns"]["features"]
    assert {
        "n_queries",
        "mean_qname_len",
        "max_label_len",
        "mean_label_entropy",
        "max_label_entropy",
        "ratio_unique_qnames",
        "top_domain_share",
        "n_unique_clients",
        "n_unseen_domains",
    } <= set(features)


def test_window_views_are_in_the_agent_database(
    testbed: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    with connect(processed(testbed) / "agent.duckdb", read_only=True) as agent:
        names = {row[0] for row in agent.execute("SHOW TABLES").fetchall()}
        assert "windows" in names and "windows_dns" in names
        assert agent.execute("SELECT count(*) FROM windows").fetchone()[0] > 0

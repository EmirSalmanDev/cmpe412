"""The `detect` pipeline on hand-made windows. Nothing here has ground truth."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from logtriage.config import MLConfig, Settings
from logtriage.data.features import REPORT_FILE, SCALER_DIR, fit_scaler
from logtriage.ml.detect import (
    DETECT_REPORT_FILE,
    INCIDENTS_FILE,
    SCORES_FILE,
    detect,
    run_detect,
    score_log_type,
    score_testbed,
)

T0 = datetime(2022, 1, 14, tzinfo=UTC)
ML = MLConfig(if_estimators=30, lof_neighbors=5, oof_folds=3, min_calib_windows=20, q=0.95)


def settings_at(directory: Path) -> Settings:
    settings = Settings(ml=ML)
    settings.paths.processed_dir = directory
    return settings


def make_windows(
    n_fit: int = 60, n_calib: int = 30, n_eval: int = 40, log_type: str = "vpn", host: str = "h"
) -> pd.DataFrame:
    rng = np.random.default_rng(1)
    total = n_fit + n_calib + n_eval
    periods = ["fit"] * n_fit + ["calib"] * n_calib + ["eval"] * n_eval
    frame = pd.DataFrame(
        {
            "testbed": "tiny",
            "host": host,
            "log_type": log_type,
            "window_start": [pd.Timestamp(T0 + timedelta(minutes=item)) for item in range(total)],
            "n_lines": rng.integers(5, 15, total).astype(float),
            "ratio_x": rng.random(total),
            "src_ips": [["10.0.0.1"]] * total,
            "users": [[]] * total,
            "period": periods,
        }
    )
    frame.loc[total - 3 :, "n_lines"] = 5000.0
    return frame


def write_testbed(directory: Path, tables: dict[str, pd.DataFrame], skipped=()) -> None:
    directory.mkdir(parents=True)
    report = {}
    for log_type, windows in tables.items():
        windows.to_parquet(directory / f"windows_{log_type}.parquet", index=False)
        fit_scaler(windows).save(directory / SCALER_DIR / f"{log_type}.json")
        report[log_type] = {"baseline_capable": True}
    report |= {log_type: {"baseline_capable": False} for log_type in skipped}
    (directory / REPORT_FILE).write_text(json.dumps(report), encoding="utf-8")


def test_scores_have_the_columns_of_plan_5_5() -> None:
    windows = make_windows()
    table, _ = score_log_type(windows, fit_scaler(windows), Settings(ml=ML))
    expected = {"score_if", "score_lof", "score_pca", "pct_if", "pct_lof", "pct_pca", "score"}
    assert expected <= set(table.columns)
    assert len(table) == len(windows)
    assert table[["pct_if", "pct_lof", "pct_pca", "score"]].stack().between(0, 1).all()


def test_later_windows_do_not_change_the_fit_scores() -> None:
    windows = make_windows()
    scaler = fit_scaler(windows)
    changed = windows.copy()
    changed.loc[changed["period"] != "fit", "ratio_x"] = 50.0
    first, _ = score_log_type(windows, scaler, Settings(ml=ML))
    second, _ = score_log_type(changed, scaler, Settings(ml=ML))
    rows = first["period"] == "fit"
    assert np.array_equal(first.loc[rows, "score_if"], second.loc[rows, "score_if"])
    assert np.array_equal(first.loc[rows, "score_lof"], second.loc[rows, "score_lof"])


def test_a_clear_outlier_scores_near_one() -> None:
    windows = make_windows()
    table, _ = score_log_type(windows, fit_scaler(windows), Settings(ml=ML))
    assert table["score"].iloc[-1] > 0.95
    assert table["score"].iloc[-1] == table["score"].max()


def test_a_thin_log_type_gets_out_of_fold_scores() -> None:
    windows = make_windows(n_calib=7)
    _, report = score_log_type(windows, fit_scaler(windows), Settings(ml=ML))
    assert report["thin"] is True
    assert report["reference_size"] == 67
    assert report["reference_by_host"] == {"h": "log_type+oof"}


def test_a_log_type_with_enough_calib_windows_is_not_thin() -> None:
    windows = make_windows(n_calib=30)
    _, report = score_log_type(windows, fit_scaler(windows), Settings(ml=ML))
    assert report["thin"] is False
    assert report["reference_size"] == 30


def test_clip_changes_only_what_the_scaler_clips() -> None:
    windows = make_windows()
    windows.loc[windows["period"] == "eval", "ratio_x"] = -40.0
    scaler = fit_scaler(windows, ["ratio_x"])
    clipped, _ = score_log_type(windows, scaler, Settings(ml=ML))
    unclipped, _ = score_log_type(windows, scaler, Settings(ml=ML), clip=False)
    rows = clipped["period"] == "eval"
    assert (
        unclipped.loc[rows, "score"].iloc[:30].mean() > clipped.loc[rows, "score"].iloc[:30].mean()
    )


def test_types_without_a_baseline_are_reported_and_not_scored(tmp_path: Path) -> None:
    write_testbed(tmp_path / "tiny", {"vpn": make_windows()}, skipped=["apache_error"])
    scored = score_testbed("tiny", settings_at(tmp_path))
    assert scored.report["no_baseline"] == ["apache_error"]
    assert set(scored.scores["log_type"]) == {"vpn"}


def test_only_eval_windows_become_incidents(tmp_path: Path) -> None:
    windows = make_windows()
    windows.loc[5, "n_lines"] = 9000.0  # far out, but in the fit period
    write_testbed(tmp_path / "tiny", {"vpn": windows})
    scored = score_testbed("tiny", settings_at(tmp_path))
    scores, incidents = detect(scored, 0.5, 10, 60)
    assert scores.loc[scores["period"] != "eval", "incident_id"].isna().all()
    assert scores.loc[scores["incident_id"].notna(), "is_anomalous"].all()
    assert len(incidents) >= 1


def test_common_entities_are_found_per_log_type(tmp_path: Path) -> None:
    write_testbed(tmp_path / "tiny", {"vpn": make_windows()})
    scored = score_testbed("tiny", settings_at(tmp_path))
    assert scored.common == {("vpn", "ip", "10.0.0.1")}


def test_run_detect_writes_its_tables(tmp_path: Path) -> None:
    write_testbed(
        tmp_path / "tiny",
        {"vpn": make_windows(), "dns": make_windows(log_type="dns", host="d")},
    )
    run_detect("tiny", settings_at(tmp_path))
    directory = tmp_path / "tiny"
    scores = pd.read_parquet(directory / SCORES_FILE)
    incidents = pd.read_parquet(directory / INCIDENTS_FILE)
    report = json.loads((directory / DETECT_REPORT_FILE).read_text(encoding="utf-8"))
    assert report["q"] == 0.95 and report["incidents"] == len(incidents) > 0
    assert str(scores["window_start"].dt.tz) == "UTC"
    assert {"testbed", "host", "log_type", "window_start", "is_anomalous"} <= set(scores.columns)
    assert not {"src_ips", "users"} & set(scores.columns)


def test_run_detect_is_reproducible(tmp_path: Path) -> None:
    write_testbed(tmp_path / "tiny", {"vpn": make_windows()})
    settings = settings_at(tmp_path)
    run_detect("tiny", settings)
    first = pd.read_parquet(tmp_path / "tiny" / SCORES_FILE)
    run_detect("tiny", settings)
    pd.testing.assert_frame_equal(first, pd.read_parquet(tmp_path / "tiny" / SCORES_FILE))


def test_a_missing_testbed_raises() -> None:
    with pytest.raises(FileNotFoundError):
        score_testbed("nope", Settings())

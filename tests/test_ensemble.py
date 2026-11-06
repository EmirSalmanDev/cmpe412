"""Calibration, ensemble and threshold (plan 6.5)."""

import numpy as np
import pandas as pd
import pytest

from logtriage.config import MLConfig
from logtriage.ml.ensemble import apply_threshold, calibrate, empirical_cdf, ensemble_score
from logtriage.ml.models import MODEL_NAMES

CONFIG = MLConfig(min_calib_windows=3)


def same(values: list[float]) -> dict[str, np.ndarray]:
    """Give every model the same scores."""
    return {name: np.array(values) for name in MODEL_NAMES}


def test_empirical_cdf_counts_values_at_or_below() -> None:
    reference = np.array([1.0, 2.0, 3.0, 4.0])
    values = np.array([0.5, 1.0, 2.5, 4.0, 9.0])
    assert empirical_cdf(reference, values).tolist() == [0.0, 0.25, 0.5, 1.0, 1.0]


def test_a_host_with_enough_calib_windows_is_its_own_reference() -> None:
    raw = same([1.0, 2.0, 3.0, 2.5, 100.0, 200.0, 300.0, 250.0])
    hosts = np.array(["a"] * 4 + ["b"] * 4)
    is_calib = np.array([True, True, True, False] * 2)
    percentiles, sources = calibrate(raw, hosts, is_calib, None, CONFIG)
    assert sources == {"a": "host", "b": "host"}
    assert percentiles["if"][3] == pytest.approx(2 / 3)
    assert percentiles["if"][7] == pytest.approx(2 / 3)


def test_a_host_with_few_calib_windows_uses_the_log_type() -> None:
    raw = same([1.0, 2.0, 3.0, 2.5, 10.0, 2.5])
    hosts = np.array(["a"] * 4 + ["b"] * 2)
    is_calib = np.array([True, True, True, False, True, False])
    percentiles, sources = calibrate(raw, hosts, is_calib, None, CONFIG)
    assert sources == {"a": "host", "b": "log_type"}
    assert percentiles["if"][5] == pytest.approx(2 / 4)


def test_a_thin_log_type_adds_the_out_of_fold_scores() -> None:
    raw = same([1.0, 2.0, 2.5])
    hosts = np.array(["a"] * 3)
    is_calib = np.array([True, True, False])
    extra = same([0.0, 5.0, 6.0])
    percentiles, sources = calibrate(raw, hosts, is_calib, extra, CONFIG)
    assert sources == {"a": "log_type+oof"}
    assert percentiles["pca"][2] == pytest.approx(3 / 5)


def test_a_host_stream_ignores_the_extra_reference() -> None:
    raw = same([1.0, 2.0, 3.0, 2.5])
    hosts = np.array(["a"] * 4)
    is_calib = np.array([True, True, True, False])
    percentiles, sources = calibrate(raw, hosts, is_calib, same([9.0]), CONFIG)
    assert sources == {"a": "host"}
    assert percentiles["lof"][3] == pytest.approx(2 / 3)


def test_each_model_is_calibrated_on_its_own_scores() -> None:
    raw = {"if": np.array([1.0, 2.0, 3.0, 9.0]), "lof": np.array([3.0, 2.0, 1.0, 0.0])}
    raw["pca"] = raw["if"]
    hosts = np.array(["a"] * 4)
    is_calib = np.array([True, True, True, False])
    percentiles, _ = calibrate(raw, hosts, is_calib, None, CONFIG)
    assert percentiles["if"][3] == 1.0
    assert percentiles["lof"][3] == 0.0


def test_score_is_the_mean_percentile() -> None:
    percentiles = {"if": np.array([1.0]), "lof": np.array([0.5]), "pca": np.array([0.0])}
    assert ensemble_score(percentiles).tolist() == [0.5]


def test_threshold_is_inclusive() -> None:
    scores = pd.DataFrame({"score": [0.98, 0.99, 1.0]})
    assert apply_threshold(scores, 0.99)["is_anomalous"].tolist() == [False, True, True]
    assert "is_anomalous" not in scores

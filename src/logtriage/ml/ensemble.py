"""Percentile calibration, ensemble score and threshold (plan 6.5)."""

import numpy as np
import pandas as pd

from logtriage.config import MLConfig
from logtriage.ml.models import MODEL_NAMES

Scores = dict[str, np.ndarray]


def empirical_cdf(reference: np.ndarray, values: np.ndarray) -> np.ndarray:
    """Return the share of `reference` at or below each value."""
    ordered = np.sort(reference)
    return np.searchsorted(ordered, values, side="right") / len(ordered)


def calibrate(
    raw: Scores,
    hosts: np.ndarray,
    is_calib: np.ndarray,
    extra_reference: Scores | None,
    config: MLConfig,
) -> tuple[Scores, dict[str, str]]:
    """Turn raw scores into percentiles against the calibration reference.

    A host with at least `min_calib_windows` calib windows is its own reference. Other hosts
    use the calib windows of the whole log type, with `extra_reference` added to them.

    Args:
        raw: Raw scores per model, over all windows of a log type.
        hosts: Host of each window.
        is_calib: Whether each window is a calib window.
        extra_reference: Out-of-fold fit scores for a thin log type (D28), or None.
        config: Holds `min_calib_windows`.

    Returns:
        Percentiles per model, and the reference used by each host.
    """
    percentiles = {name: np.empty(len(hosts)) for name in MODEL_NAMES}
    sources: dict[str, str] = {}
    for host in sorted(set(hosts)):
        rows = hosts == host
        own = rows & is_calib
        is_stream = own.sum() >= config.min_calib_windows
        sources[host] = "host" if is_stream else "log_type"
        if not is_stream and extra_reference is not None:
            sources[host] = "log_type+oof"
        for name in MODEL_NAMES:
            if is_stream:
                reference = raw[name][own]
            else:
                reference = raw[name][is_calib]
                if extra_reference is not None:
                    reference = np.concatenate([reference, extra_reference[name]])
            percentiles[name][rows] = empirical_cdf(reference, raw[name][rows])
    return percentiles, sources


def ensemble_score(percentiles: Scores) -> np.ndarray:
    """Return the mean percentile of the models."""
    return np.mean([percentiles[name] for name in MODEL_NAMES], axis=0)


def apply_threshold(scores: pd.DataFrame, q: float) -> pd.DataFrame:
    """Return a copy of a scores table with `is_anomalous` set from `score >= q`."""
    return scores.assign(is_anomalous=scores["score"] >= q)

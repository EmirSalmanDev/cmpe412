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


def cross_fit_calibrate(
    fold_scores: list[Scores], blocks: list[np.ndarray], is_fit: np.ndarray, is_calib: np.ndarray
) -> tuple[Scores, Scores]:
    """Percentiles of a thin log type from fold models only (reports/v2_plan.md §3 (a), D75).

    Fold model `k` was fit on every fit block but block `k`. Its reference is its own scores
    of block `k` and of the calib windows, all of which it did not see, so each percentile is
    measured against scores of the same function on unseen data.

    Args:
        fold_scores: Raw scores of each fold model, per model name, over all windows.
        blocks: For each fold, the positions of its held-out fit windows among all windows.
        is_fit: Whether each window is a fit window.
        is_calib: Whether each window is a calib window.

    Returns:
        Raw scores and percentiles per model. A fit window of block `k` takes fold `k` alone;
        every other window takes the mean over the folds, of its raw scores and of its
        percentiles against each fold's reference.
    """
    calib = np.flatnonzero(is_calib)
    others = ~is_fit
    raw = {name: np.empty(len(is_fit)) for name in MODEL_NAMES}
    percentiles = {name: np.empty(len(is_fit)) for name in MODEL_NAMES}
    for name in MODEL_NAMES:
        per_fold = []
        for scores, block in zip(fold_scores, blocks, strict=True):
            reference = scores[name][np.concatenate([block, calib])]
            raw[name][block] = scores[name][block]
            percentiles[name][block] = empirical_cdf(reference, scores[name][block])
            per_fold.append(empirical_cdf(reference, scores[name][others]))
        raw[name][others] = np.mean([scores[name][others] for scores in fold_scores], axis=0)
        percentiles[name][others] = np.mean(per_fold, axis=0)
    return raw, percentiles


def ensemble_score(percentiles: Scores) -> np.ndarray:
    """Return the mean percentile of the models."""
    return np.mean([percentiles[name] for name in MODEL_NAMES], axis=0)


def apply_threshold(scores: pd.DataFrame, q: float) -> pd.DataFrame:
    """Return a copy of a scores table with `is_anomalous` set from `score >= q`."""
    return scores.assign(is_anomalous=scores["score"] >= q)

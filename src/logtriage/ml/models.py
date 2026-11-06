"""Anomaly models (plan 6.4): Isolation Forest, LOF and PCA reconstruction error.

Every score is oriented so that higher means more anomalous.
"""

from dataclasses import dataclass

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

from logtriage.config import MLConfig

MODEL_NAMES = ("if", "lof", "pca")
MIN_LOF_ROWS = 2


@dataclass(frozen=True)
class FittedModels:
    """The three models of one log type."""

    isolation_forest: IsolationForest
    lof: LocalOutlierFactor
    pca: PCA


def fit_models(matrix: np.ndarray, config: MLConfig, seed: int) -> FittedModels:
    """Fit the three models on fit-period windows.

    Args:
        matrix: Scaled features of the fit windows.
        config: Model settings.
        seed: Random seed.

    Returns:
        The fitted models.
    """
    forest = IsolationForest(
        n_estimators=config.if_estimators, contamination="auto", random_state=seed
    ).fit(matrix)
    lof = _fit_lof(matrix, config, seed)
    pca = PCA(n_components=config.pca_variance, svd_solver="full", random_state=seed).fit(matrix)
    return FittedModels(forest, lof, pca)


def _fit_lof(matrix: np.ndarray, config: MLConfig, seed: int) -> LocalOutlierFactor:
    """Fit LOF on the distinct rows of the matrix (D31).

    Quiet minutes give identical windows. With more copies of a row than neighbors, its k-distance
    is 0 and its density is near infinite, so ordinary windows next to it score around 1e10.
    """
    sample = np.unique(matrix, axis=0)
    if len(sample) < MIN_LOF_ROWS:
        sample = matrix
    if len(sample) > config.lof_max_windows:
        rows = np.random.default_rng(seed).choice(
            len(sample), config.lof_max_windows, replace=False
        )
        sample = sample[np.sort(rows)]
    neighbors = min(config.lof_neighbors, len(sample) - 1)
    return LocalOutlierFactor(n_neighbors=neighbors, novelty=True).fit(sample)


def score_models(models: FittedModels, matrix: np.ndarray) -> dict[str, np.ndarray]:
    """Return the raw score of each model, higher meaning more anomalous."""
    restored = models.pca.inverse_transform(models.pca.transform(matrix))
    return {
        "if": -models.isolation_forest.score_samples(matrix),
        "lof": -models.lof.score_samples(matrix),
        "pca": ((matrix - restored) ** 2).sum(axis=1),
    }


def out_of_fold_scores(matrix: np.ndarray, config: MLConfig, seed: int) -> dict[str, np.ndarray]:
    """Score fit windows with models that did not see them (D28).

    Args:
        matrix: Scaled features of the fit windows, in time order.
        config: Model settings, with `oof_folds`.
        seed: Random seed.

    Returns:
        Raw scores per model, one per row of `matrix`. Each contiguous time block is scored by
        models fit on the other blocks.
    """
    folds = np.array_split(np.arange(len(matrix)), config.oof_folds)
    scores = {name: np.empty(len(matrix)) for name in MODEL_NAMES}
    for fold in folds:
        rest = np.setdiff1d(np.arange(len(matrix)), fold)
        held_out = score_models(fit_models(matrix[rest], config, seed), matrix[fold])
        for name in MODEL_NAMES:
            scores[name][fold] = held_out[name]
    return scores

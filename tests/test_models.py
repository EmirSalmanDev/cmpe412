"""Anomaly models (plan 6.4)."""

import numpy as np
import pytest

from logtriage.config import MLConfig
from logtriage.ml.models import MODEL_NAMES, fit_models, out_of_fold_scores, score_models

CONFIG = MLConfig(if_estimators=50, lof_neighbors=10, oof_folds=4)


@pytest.fixture
def normal() -> np.ndarray:
    return np.random.default_rng(0).normal(size=(200, 4))


@pytest.mark.parametrize("name", MODEL_NAMES)
def test_higher_scores_mean_more_anomalous(normal: np.ndarray, name: str) -> None:
    models = fit_models(normal, CONFIG, 1)
    outlier = np.full((1, 4), 12.0)
    scores = score_models(models, np.vstack([normal[:50], outlier]))[name]
    assert scores[-1] == scores.max()


def test_pca_keeps_the_configured_variance() -> None:
    rng = np.random.default_rng(0)
    base = rng.normal(size=(300, 1))
    matrix = np.hstack([base, 2 * base, rng.normal(scale=0.01, size=(300, 1))])
    assert fit_models(matrix, CONFIG, 1).pca.n_components_ == 1


def test_pca_error_sees_a_feature_that_was_zero_in_fit(normal: np.ndarray) -> None:
    matrix = np.hstack([normal, np.zeros((len(normal), 1))])
    models = fit_models(matrix, CONFIG, 1)
    quiet = matrix[:1].copy()
    loud = quiet.copy()
    loud[0, -1] = 5.0
    assert score_models(models, loud)["pca"][0] > score_models(models, quiet)["pca"][0]


def test_same_seed_gives_same_scores(normal: np.ndarray) -> None:
    first = score_models(fit_models(normal, CONFIG, 1), normal)
    second = score_models(fit_models(normal, CONFIG, 1), normal)
    for name in MODEL_NAMES:
        assert np.array_equal(first[name], second[name])


def test_lof_neighbors_shrink_for_few_windows() -> None:
    matrix = np.random.default_rng(0).normal(size=(8, 3))
    assert fit_models(matrix, CONFIG, 1).lof.n_neighbors_ == 7


def test_lof_fits_on_a_sample_above_the_cap(normal: np.ndarray) -> None:
    config = CONFIG.model_copy(update={"lof_max_windows": 50})
    assert fit_models(normal, config, 1).lof.n_samples_fit_ == 50


def test_out_of_fold_scores_cover_every_window(normal: np.ndarray) -> None:
    scores = out_of_fold_scores(normal, CONFIG, 1)
    for name in MODEL_NAMES:
        assert scores[name].shape == (len(normal),)
        assert np.isfinite(scores[name]).all()


def test_out_of_fold_scores_come_from_models_that_did_not_see_the_window() -> None:
    # Two far clusters by time: the last block is alone, so held out it looks anomalous,
    # while a model that saw it scores it as ordinary.
    rng = np.random.default_rng(0)
    matrix = np.vstack([rng.normal(size=(150, 3)), rng.normal(loc=9.0, size=(50, 3))])
    held_out = out_of_fold_scores(matrix, CONFIG, 1)["lof"]
    in_sample = score_models(fit_models(matrix, CONFIG, 1), matrix)["lof"]
    assert held_out[-50:].mean() > 2 * in_sample[-50:].mean()

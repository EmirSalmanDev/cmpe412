"""Acceptance checks for M6 on the real datasets (plan 13). They never score santos."""

from pathlib import Path

import pandas as pd
import pytest

from logtriage.config import TEST_TESTBED, load_settings
from logtriage.eval import eda
from logtriage.eval.metrics import window_metrics, window_truth, with_truth
from logtriage.ml.detect import SCORES_FILE
from logtriage.ml.supervised import (
    ENSEMBLE,
    ERRORS_FILE,
    IMPORTANCE_FILE,
    MODELS,
    NOT_TRAINABLE,
    OOF_FILE,
    PHASES_FILE,
    POOLED,
    POOLED_TRAINED,
    PRIMARY,
    TEST_FILE,
    TRAINED,
    config_hash,
    inputs,
)

ROOT = Path(__file__).parents[1]
RESULTS = ROOT / "reports" / "results"
LOG_TYPES = ["apache_access", "audit", "auth", "dns", "vpn"]
NOT_TRAINABLE_POSITIVES = {"apache_access": 4, "audit": 3, "auth": 2, "vpn": 1}

pytestmark = pytest.mark.data


@pytest.fixture(scope="module")
def settings():
    return load_settings(ROOT / "configs" / "default.yaml", env_file=None)


@pytest.fixture(scope="module")
def oof() -> pd.DataFrame:
    return pd.read_csv(RESULTS / OOF_FILE)


@pytest.fixture(scope="module")
def primary() -> pd.DataFrame:
    table = pd.read_csv(RESULTS / TEST_FILE)
    return table[table["analysis"] == "primary"].set_index(["scope", "method"])


def test_every_type_and_model_has_a_dev_row(oof: pd.DataFrame) -> None:
    assert len(oof) == len(LOG_TYPES) * len(MODELS) * 2
    assert set(oof["log_type"]) == set(LOG_TYPES)


def test_only_dns_is_trainable_and_the_rest_are_below_the_minimum(oof: pd.DataFrame) -> None:
    assert set(oof.loc[oof["status"] == TRAINED, "log_type"]) == {"dns"}
    for log_type, positives in NOT_TRAINABLE_POSITIVES.items():
        rows = oof[oof["log_type"] == log_type]
        assert set(rows["status"]) == {NOT_TRAINABLE}
        assert set(rows["positives"]) == {positives}


def test_dns_kept_all_five_blocks_and_scored_every_window(oof: pd.DataFrame) -> None:
    rows = oof[oof["status"] == TRAINED]
    assert (rows["k_used"] == 5).all()
    assert rows["blocks_dropped"].isna().all()
    assert (rows["oof_windows"] == rows["windows"]).all()


def test_the_results_come_from_the_committed_config(settings, oof: pd.DataFrame) -> None:
    _, features, _ = inputs(settings)
    assert set(oof["config_hash"]) == {config_hash(settings, features)}


def test_the_supervised_features_hold_no_identity_column(settings) -> None:
    _, features, _ = inputs(settings)
    forbidden = {"host", "testbed", "src_ips", "users", "log_type", "window_start", "period"}
    assert not forbidden & {name for columns in features.values() for name in columns}


def test_the_ensemble_rows_match_the_m5_metrics(settings, primary: pd.DataFrame) -> None:
    with eda.connect(TEST_TESTBED, settings) as con:
        truth = window_truth(con, settings.features.window_seconds)
    scores = pd.read_parquet(ROOT / "data" / "processed" / TEST_TESTBED / SCORES_FILE)
    metrics = window_metrics(with_truth(scores, truth))
    for scope in [*LOG_TYPES, POOLED]:
        row = primary.loc[(scope, ENSEMBLE)]
        assert row["pr_auc"] == pytest.approx(metrics.loc[scope, "pr_auc"])
        assert row["n_pos"] == metrics.loc[scope, "attack"]
        assert row["windows"] == metrics.loc[scope, "windows"]


def test_cells_without_a_model_are_empty(primary: pd.DataFrame) -> None:
    for scope in NOT_TRAINABLE_POSITIVES:
        for name in MODELS:
            row = primary.loc[(scope, name)]
            assert row["status"] == NOT_TRAINABLE
            assert row[["pr_auc", "precision", "recall", "f1"]].isna().all()
    for name in MODELS:
        assert pd.isna(primary.loc[(POOLED, name), "pr_auc"])


def test_santos_thresholds_are_the_dev_thresholds(oof: pd.DataFrame, primary: pd.DataFrame) -> None:
    for name in MODELS:
        dev = oof[(oof["variant"] == PRIMARY) & (oof["log_type"] == "dns") & (oof["model"] == name)]
        assert primary.loc[("dns", name), "threshold"] == dev["threshold"].iloc[0]


def test_pooled_trained_covers_only_dns(primary: pd.DataFrame) -> None:
    for name in [ENSEMBLE, *MODELS]:
        assert primary.loc[(POOLED_TRAINED, name), "pr_auc"] == primary.loc[("dns", name), "pr_auc"]


def test_each_secondary_analysis_is_present() -> None:
    names = set(pd.read_csv(RESULTS / TEST_FILE)["analysis"])
    assert names == {
        "primary",
        "secondary_without_exfil_only",
        "secondary_with_ambiguous",
        "secondary_all_dev_periods",
    }


def test_the_side_outputs_exist() -> None:
    importance = pd.read_csv(RESULTS / IMPORTANCE_FILE)
    assert set(importance["model"]) == set(MODELS)
    assert len(pd.read_csv(RESULTS / PHASES_FILE)) == 8
    errors = pd.read_csv(RESULTS / ERRORS_FILE)
    assert set(errors["kind"]) == {"missed", "false_positive"}

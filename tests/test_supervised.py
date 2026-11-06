"""Supervised reference (plan 6.7): folds, thresholds, the n/a rule and the santos guard."""

import numpy as np
import pandas as pd
import pytest

from logtriage.config import Settings, SupervisedConfig
from logtriage.eval.metrics import EXFIL_PHASE
from logtriage.ml.supervised import (
    ALL_PERIODS,
    ENSEMBLE,
    NO_MODEL_FOR_ALL_TYPES,
    NOT_TRAINABLE,
    OK,
    POOLED,
    POOLED_TRAINED,
    PRIMARY,
    TRAINED,
    best_threshold,
    build_model,
    class_blocks,
    comparison,
    config_hash,
    dev_results,
    dev_row,
    error_windows,
    flagged_phases,
    fold_split,
    importance_table,
    minutes_since_start,
    out_of_fold,
    phase_rows,
    refuse_rerun,
    score_test,
    shared_features,
    training_rows,
    with_thresholds,
    without_exfil_only,
    zero_features,
)

CONFIG = SupervisedConfig(rf_trees=10, xgb_trees=10)
START = pd.Timestamp("2022-01-24 00:00", tz="UTC")


def windows(labels: list[bool], log_type: str = "dns", host: str = "fw") -> pd.DataFrame:
    """Build one window per minute. The `signal` feature follows the label."""
    flags = np.array(labels)
    table = pd.DataFrame(
        {
            "host": host,
            "log_type": log_type,
            "window_start": pd.date_range(START, periods=len(flags), freq="1min"),
            "period": "eval",
            "signal": flags.astype(float) * 10,
            "n_lines": np.arange(len(flags)) % 7,
            "is_attack": flags,
            "is_ambiguous": False,
        }
    )
    table["phases"] = [[EXFIL_PHASE] if flag else [] for flag in flags]
    return table


def tunnel_then_quiet(positives: int = 400, negatives: int = 200) -> pd.DataFrame:
    """Reproduce the dev dns layout: all positives first, all negatives after them."""
    return windows([True] * positives + [False] * negatives)


def scored(labels: list[bool], flagged: list[bool], log_type: str) -> pd.DataFrame:
    table = windows(labels, log_type)
    table["score"] = np.linspace(0.1, 0.9, len(labels))
    table["is_anomalous"] = flagged
    return table


def test_shared_features_keep_dev_order_and_drop_one_sided_columns() -> None:
    dev = {"a": {"features": ["n_lines", "n_unseen_src_ip", "ratio_4xx"]}}
    test = {"a": {"features": ["ratio_4xx", "n_lines"]}}
    assert shared_features(dev, test, "a") == ["n_lines", "ratio_4xx"]


def test_blocks_give_every_block_both_classes_when_the_series_changes_class_once() -> None:
    table = tunnel_then_quiet()
    labels = table["is_attack"].to_numpy()
    assigned = class_blocks(minutes_since_start(table["window_start"]), labels, 5)
    for block in range(5):
        assert labels[assigned == block].any()
        assert not labels[assigned == block].all()


def test_each_class_of_a_block_is_contiguous_in_time() -> None:
    labels = np.array([True, False] * 50)
    minutes = np.arange(100.0)
    assigned = class_blocks(minutes, labels, 5)
    for value in (True, False):
        sequence = assigned[labels == value]
        assert (np.diff(sequence) >= 0).all()


def test_the_purge_keeps_training_rows_away_from_the_held_out_spans() -> None:
    table = tunnel_then_quiet()
    labels = table["is_attack"].to_numpy()
    minutes = minutes_since_start(table["window_start"])
    assigned = class_blocks(minutes, labels, 5)
    for block in range(5):
        train, held = fold_split(minutes, labels, assigned, block, 30)
        assert not set(train) & set(held)
        for value in (True, False):
            span = minutes[held][labels[held] == value]
            distance = np.minimum(
                np.abs(minutes[train] - span.min()), np.abs(minutes[train] - span.max())
            )
            assert distance.min() > 30


def test_every_row_gets_a_score_on_the_dev_dns_layout() -> None:
    table = tunnel_then_quiet()
    labels = table["is_attack"].to_numpy()
    matrix = table[["signal", "n_lines"]].to_numpy(dtype=float)
    minutes = minutes_since_start(table["window_start"])
    result = out_of_fold("rf", matrix, labels, minutes, CONFIG, 1)
    assert result.used == [0, 1, 2, 3, 4]
    assert result.dropped == []
    assert not np.isnan(result.scores).any()


def test_a_fold_whose_training_loses_all_positives_is_dropped_and_logged() -> None:
    """Five positives inside the purge distance leave no positive to train on."""
    table = windows([False] * 100 + [True] * 5 + [False] * 100)
    labels = table["is_attack"].to_numpy()
    matrix = table[["signal", "n_lines"]].to_numpy(dtype=float)
    minutes = minutes_since_start(table["window_start"])
    result = out_of_fold("rf", matrix, labels, minutes, CONFIG, 1)
    assert result.used == []
    assert result.dropped == [0, 1, 2, 3, 4]
    assert np.isnan(result.scores).all()


def test_a_type_left_with_no_fold_is_not_trainable() -> None:
    table = windows([False] * 100 + [True] * 5 + [False] * 100)
    row = dev_row("rf", table, ["signal"], CONFIG, 1)
    assert row["status"] == NOT_TRAINABLE
    assert row["k_used"] == 0
    assert row["blocks_dropped"] == "0 1 2 3 4"


def test_the_threshold_maximizes_f1_on_a_separable_score() -> None:
    labels = np.array([False, False, True, True])
    assert best_threshold(labels, np.array([0.1, 0.2, 0.8, 0.9])) == 0.8


def test_a_tie_in_f1_goes_to_the_higher_threshold() -> None:
    labels = np.array([True, False, False, True, False, False, False, False])
    scores = np.array([0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2])
    # 0.9 gives P 1, R 1/2 and 0.6 gives P 1/2, R 1: both F1 2/3.
    assert best_threshold(labels, scores) == 0.9


def test_training_rows_keep_the_periods_and_leave_out_ambiguous_windows() -> None:
    table = windows([True, False, True, False])
    table["period"] = ["fit", "calib", "eval", "eval"]
    table["is_ambiguous"] = [False, False, False, True]
    kept = training_rows(table, ["calib", "eval"])
    assert kept["period"].tolist() == ["calib", "eval"]
    assert not kept["is_ambiguous"].any()


def test_xgb_weighs_positives_by_the_class_ratio() -> None:
    model = build_model("xgb", np.array([True] * 2 + [False] * 8), CONFIG, 1)
    assert model.get_params()["scale_pos_weight"] == 4


def test_rf_uses_the_configured_class_weight() -> None:
    model = build_model("rf", np.array([True, False]), CONFIG, 1)
    assert model.get_params()["class_weight"] == "balanced_subsample"


def test_a_type_under_the_minimum_is_not_trainable_and_gets_no_model() -> None:
    table = windows([True] * 4 + [False] * 200, "vpn")
    row = dev_row("rf", table, ["signal"], CONFIG, 1)
    assert row["status"] == NOT_TRAINABLE
    assert row["positives"] == 4
    assert "threshold" not in row


def test_dev_results_cover_both_variants_and_each_status() -> None:
    tables = {"dns": tunnel_then_quiet(), "vpn": windows([True] + [False] * 100, "vpn")}
    features = {"dns": ["signal", "n_lines"], "vpn": ["signal", "n_lines"]}
    table = dev_results(tables, features, CONFIG, 1)
    assert len(table) == 2 * 2 * 2
    assert set(table["variant"]) == {PRIMARY, ALL_PERIODS}
    assert set(table.loc[table["log_type"] == "dns", "status"]) == {TRAINED}
    assert set(table.loc[table["log_type"] == "vpn", "status"]) == {NOT_TRAINABLE}
    assert table.loc[table["log_type"] == "dns", "oof_f1"].min() == 1.0


def test_importance_covers_trained_types_only_and_sums_to_one() -> None:
    tables = {"dns": tunnel_then_quiet(), "vpn": windows([True] + [False] * 100, "vpn")}
    features = {"dns": ["signal", "n_lines"], "vpn": ["signal", "n_lines"]}
    rows = dev_results(tables, features, CONFIG, 1)
    table = importance_table(rows, tables, features, CONFIG, 1)
    assert set(table["log_type"]) == {"dns"}
    assert table.groupby("model")["importance"].sum().round(6).eq(1).all()
    assert table.groupby("model")["feature"].first().eq("signal").all()


def test_a_score_at_the_threshold_is_flagged() -> None:
    table = windows([True, False])

    class Fixed:
        def predict_proba(self, matrix: np.ndarray) -> np.ndarray:
            return np.array([[0.5, 0.5], [0.6, 0.4]])

    result = score_test(Fixed(), table, ["signal"], 0.5)
    assert result["is_anomalous"].tolist() == [True, False]


def comparison_inputs() -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
    ensemble = pd.concat(
        [
            scored([True, False, True, False], [True, False, False, False], "dns"),
            scored([True, False, False, False], [False, False, False, False], "vpn"),
        ],
        ignore_index=True,
    )
    models = {
        name: scored([True, False, True, False], [True, False, True, False], "dns")
        for name in ("rf", "xgb")
    }
    return ensemble, models


def test_a_type_without_a_model_keeps_counts_and_has_no_metrics() -> None:
    ensemble, models = comparison_inputs()
    table = comparison("primary", ensemble, models, ["dns", "vpn"]).set_index(["scope", "method"])
    cell = table.loc[("vpn", "rf")]
    assert cell["status"] == NOT_TRAINABLE
    assert cell["n_pos"] == 1
    assert np.isnan(cell["pr_auc"])
    assert np.isnan(cell["f1"])


def test_pooled_has_no_model_value_unless_every_type_has_one() -> None:
    ensemble, models = comparison_inputs()
    table = comparison("primary", ensemble, models, ["dns", "vpn"]).set_index(["scope", "method"])
    assert table.loc[(POOLED, ENSEMBLE), "status"] == OK
    assert table.loc[(POOLED, "rf"), "status"] == NO_MODEL_FOR_ALL_TYPES
    assert np.isnan(table.loc[(POOLED, "rf"), "pr_auc"])


def test_pooled_trained_compares_all_methods_on_the_same_windows() -> None:
    ensemble, models = comparison_inputs()
    table = comparison("primary", ensemble, models, ["dns", "vpn"]).set_index(["scope", "method"])
    rows = table.loc[POOLED_TRAINED]
    assert rows["windows"].nunique() == 1
    assert rows["n_pos"].nunique() == 1
    assert rows.loc["rf", "pr_auc"] == table.loc[("dns", "rf"), "pr_auc"]
    assert rows.loc[ENSEMBLE, "windows"] == table.loc[("dns", ENSEMBLE), "windows"]


def test_ambiguous_windows_count_only_when_asked() -> None:
    ensemble, models = comparison_inputs()
    extra = scored([False, False], [False, True], "dns").assign(is_ambiguous=True)
    ensemble = pd.concat([ensemble, extra], ignore_index=True)
    models = {name: pd.concat([part, extra], ignore_index=True) for name, part in models.items()}
    primary = comparison("p", ensemble, models, ["dns", "vpn"]).set_index(["scope", "method"])
    wider = comparison("s", ensemble, models, ["dns", "vpn"], include_ambiguous=True)
    wider = wider.set_index(["scope", "method"])
    assert primary.loc[("dns", "rf"), "windows"] == 4
    assert wider.loc[("dns", "rf"), "windows"] == 6
    assert wider.loc[("dns", "rf"), "precision"] < primary.loc[("dns", "rf"), "precision"]


def test_exfil_only_windows_are_dropped_and_mixed_windows_stay() -> None:
    table = windows([True, True, False])
    table.at[1, "phases"] = [EXFIL_PHASE, "dirb"]
    assert without_exfil_only(table)["phases"].tolist() == [[EXFIL_PHASE, "dirb"], []]


def test_a_flagged_phase_needs_a_flagged_attack_window() -> None:
    table = windows([True, True, False])
    table["phases"] = [["dirb"], ["wpscan"], []]
    table["is_anomalous"] = [True, False, True]
    assert flagged_phases(table, ["dirb", "wpscan"]) == {"dirb"}


def test_phase_rows_report_with_and_without_exfiltration() -> None:
    table = windows([True, True, False])
    table["phases"] = [[EXFIL_PHASE], ["dirb"], []]
    table["is_anomalous"] = [True, True, False]
    rows = phase_rows({("rf", "dns"): table}, ["dirb", "wpscan", EXFIL_PHASE])
    rows = rows.set_index("phases_scope")
    assert rows.loc["all_phases", "phases_flagged"] == 2
    assert rows.loc["all_phases", "phases"] == 3
    assert rows.loc["without_exfil", "phases_flagged"] == 1
    assert rows.loc["without_exfil", "not_flagged"] == "wpscan"


def test_error_windows_name_misses_and_false_positives_of_any_model() -> None:
    labels = [True, True, False, False]
    first = scored(labels, [True, False, False, False], "dns")
    second = scored(labels, [True, True, False, True], "dns")
    table = error_windows({"rf": first, "xgb": second})
    assert table["kind"].tolist() == ["missed", "false_positive"]
    assert table["rf_flag"].tolist() == [False, False]
    assert table["xgb_flag"].tolist() == [True, True]


def test_error_windows_leave_out_label_ambiguous_windows() -> None:
    labels = [True, False]
    first = scored(labels, [True, True], "dns").assign(is_ambiguous=[False, True])
    assert error_windows({"rf": first, "xgb": first}).empty


def test_thresholds_come_from_the_requested_variant() -> None:
    ensemble, models = comparison_inputs()
    table = comparison("primary", ensemble, models, ["dns", "vpn"])
    dev_rows = pd.DataFrame(
        {
            "variant": [PRIMARY, ALL_PERIODS],
            "log_type": ["dns", "dns"],
            "model": ["rf", "rf"],
            "threshold": [0.25, 0.75],
        }
    )
    merged = with_thresholds(table, dev_rows, ALL_PERIODS).set_index(["scope", "method"])
    assert merged.loc[("dns", "rf"), "threshold"] == 0.75
    assert len(merged) == len(table)


def test_the_config_hash_changes_with_a_frozen_value() -> None:
    features = {"dns": ["signal"]}
    first = Settings()
    second = Settings()
    second.ml.supervised.cv_blocks = 4
    assert config_hash(first, features) != config_hash(second, features)
    assert config_hash(first, features) != config_hash(first, {"dns": ["other"]})


def test_santos_is_refused_a_second_run_without_a_reason(tmp_path) -> None:
    path = tmp_path / "supervised_santos.csv"
    refuse_rerun(path, None)
    path.write_text("done", encoding="utf-8")
    with pytest.raises(FileExistsError):
        refuse_rerun(path, None)
    refuse_rerun(path, "a logged reason")


def feature_entry(kept: list[str], dropped: list[str], capable: bool = True) -> dict:
    return {"baseline_capable": capable, "features": kept, "dropped_constant": dropped}


def test_a_dropped_unseen_feature_is_restored_as_zero() -> None:
    report = {"dns": feature_entry(["n_queries"], ["n_unseen_templates", "ratio_unseen_templates"])}
    frozen = {"dns": ["n_queries", "n_unseen_templates", "ratio_unseen_templates"]}
    assert zero_features(report, frozen) == {
        "dns": ["n_unseen_templates", "ratio_unseen_templates"]
    }


def test_a_testbed_with_every_frozen_feature_restores_nothing() -> None:
    assert zero_features({"dns": feature_entry(["a"], [])}, {"dns": ["a"]}) == {"dns": []}


@pytest.mark.parametrize(
    "dropped",
    [["n_execve"], []],
    ids=["constant, but its value is not known", "not dropped as constant"],
)
def test_a_frozen_feature_without_a_known_value_stops_the_run(dropped: list[str]) -> None:
    with pytest.raises(ValueError, match="without a known value"):
        zero_features({"dns": feature_entry([], dropped)}, {"dns": ["n_execve"]})


def test_a_log_type_without_a_baseline_stops_the_run() -> None:
    with pytest.raises(ValueError, match="no baseline"):
        zero_features({"dns": feature_entry([], [], capable=False)}, {"dns": []})

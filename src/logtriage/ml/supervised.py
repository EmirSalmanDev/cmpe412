"""Supervised reference on window features (plan 6.7, M6).

The one module of `logtriage.ml` allowed to read ground truth (plan 5.2). It trains on the dev
testbed and tests on the test testbed, in two stages run from the repository root:

    uv run python -m logtriage.ml.supervised dev
    uv run python -m logtriage.ml.supervised test

The test stage scores the santos evaluation period once (D39).
"""

import argparse
import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, precision_recall_curve
from xgboost import XGBClassifier

from logtriage.config import (
    DEV_TESTBED,
    TEST_TESTBED,
    Settings,
    SupervisedConfig,
    load_settings,
)
from logtriage.eval import eda
from logtriage.eval.detection import truth_context
from logtriage.eval.metrics import EXFIL_PHASE, is_exfil_only, window_metrics, with_truth
from logtriage.eval.supervised_audit import feature_report, labeled_windows
from logtriage.ml.detect import SCORES_FILE

logger = logging.getLogger(__name__)

OOF_FILE = "supervised_dev_oof.csv"
TEST_FILE = "supervised_santos.csv"
PHASES_FILE = "supervised_santos_phases.csv"
IMPORTANCE_FILE = "supervised_importance.csv"

ENSEMBLE = "ensemble"
MODELS = ("rf", "xgb")
PRIMARY = "calib_eval"
ALL_PERIODS = "all_dev_periods"
TRAINED = "trained"
NOT_TRAINABLE = "not_trainable"
NO_MODEL_FOR_ALL_TYPES = "no_model_for_all_types"
OK = "ok"
POOLED = "pooled"
POOLED_TRAINED = "pooled_trained"


@dataclass
class OutOfFold:
    """Out-of-fold scores of one model on one log type."""

    scores: np.ndarray
    used: list[int] = field(default_factory=list)
    dropped: list[int] = field(default_factory=list)


def shared_features(dev_report: dict, test_report: dict, log_type: str) -> list[str]:
    """Return the feature columns kept on both testbeds, in dev order (D33).

    Args:
        dev_report: `features_report.json` of the dev testbed.
        test_report: The same of the test testbed.
        log_type: Log type.

    Returns:
        The columns. Identity columns are not features, so none can appear here.
    """
    kept = set(test_report[log_type]["features"])
    return [name for name in dev_report[log_type]["features"] if name in kept]


def minutes_since_start(times: pd.Series) -> np.ndarray:
    """Return timestamps as minutes after the earliest one."""
    return ((times - times.min()).dt.total_seconds() / 60).to_numpy()


def class_blocks(minutes: np.ndarray, labels: np.ndarray, blocks: int) -> np.ndarray:
    """Assign each row to a block, cut per class (D37).

    Args:
        minutes: Time of each row.
        labels: True for positives.
        blocks: Number of blocks.

    Returns:
        The block of each row. Within a class, a block is a contiguous equal-count time slice.
    """
    assigned = np.zeros(len(labels), dtype=int)
    for value in (False, True):
        rows = np.flatnonzero(labels == value)
        ordered = rows[np.argsort(minutes[rows], kind="stable")]
        for block, part in enumerate(np.array_split(ordered, blocks)):
            assigned[part] = block
    return assigned


def fold_split(
    minutes: np.ndarray, labels: np.ndarray, assigned: np.ndarray, block: int, purge: float
) -> tuple[np.ndarray, np.ndarray]:
    """Return the training and held-out rows of a fold.

    Args:
        minutes: Time of each row.
        labels: True for positives.
        assigned: Output of `class_blocks`.
        block: Block to hold out.
        purge: Minutes around each held-out span that training may not touch.

    Returns:
        Row indices for training and for scoring.
    """
    held = assigned == block
    allowed = ~held
    for value in (False, True):
        span = minutes[held & (labels == value)]
        if span.size:
            allowed &= (minutes < span.min() - purge) | (minutes > span.max() + purge)
    return np.flatnonzero(allowed), np.flatnonzero(held)


def build_model(
    name: str, labels: np.ndarray, config: SupervisedConfig, seed: int
) -> RandomForestClassifier | XGBClassifier:
    """Create an unfitted model with the fixed settings (D36).

    Args:
        name: `rf` or `xgb`.
        labels: Training labels, which set `scale_pos_weight`.
        config: Fixed values.
        seed: Random seed.

    Returns:
        The model.
    """
    if name == "rf":
        return RandomForestClassifier(
            n_estimators=config.rf_trees,
            class_weight=config.rf_class_weight,
            random_state=seed,
            n_jobs=-1,
        )
    positives = int(labels.sum())
    return XGBClassifier(
        n_estimators=config.xgb_trees,
        max_depth=config.xgb_max_depth,
        learning_rate=config.xgb_learning_rate,
        scale_pos_weight=(len(labels) - positives) / positives,
        importance_type="gain",
        eval_metric="logloss",
        random_state=seed,
        n_jobs=1,
    )


def out_of_fold(
    name: str,
    matrix: np.ndarray,
    labels: np.ndarray,
    minutes: np.ndarray,
    config: SupervisedConfig,
    seed: int,
) -> OutOfFold:
    """Score each row with a model that never saw its block (D37).

    Args:
        name: `rf` or `xgb`.
        matrix: Features.
        labels: True for positives.
        minutes: Time of each row.
        config: Fixed values.
        seed: Random seed.

    Returns:
        Scores, NaN for rows of a dropped fold, with the blocks used and dropped.
    """
    assigned = class_blocks(minutes, labels, config.cv_blocks)
    result = OutOfFold(np.full(len(labels), np.nan))
    for block in range(config.cv_blocks):
        train, held = fold_split(minutes, labels, assigned, block, config.purge_minutes)
        if not labels[held].any() or labels[train].all() or not labels[train].any():
            result.dropped.append(block)
            continue
        model = build_model(name, labels[train], config, seed).fit(matrix[train], labels[train])
        result.scores[held] = model.predict_proba(matrix[held])[:, 1]
        result.used.append(block)
    return result


def best_threshold(labels: np.ndarray, scores: np.ndarray) -> float:
    """Return the score threshold with the highest F1; ties go to the higher threshold (D37)."""
    precision, recall, thresholds = precision_recall_curve(labels, scores)
    total = precision[:-1] + recall[:-1]
    f1 = np.divide(
        2 * precision[:-1] * recall[:-1], total, out=np.zeros_like(total), where=total > 0
    )
    return float(thresholds[np.flatnonzero(f1 == f1.max())[-1]])


def training_rows(table: pd.DataFrame, periods: list[str]) -> pd.DataFrame:
    """Return the windows of the given periods, without label-ambiguous windows (D34, D35)."""
    kept = table[table["period"].isin(periods) & ~table["is_ambiguous"]]
    return kept.sort_values(["window_start", "host"]).reset_index(drop=True)


def dev_row(
    name: str, train: pd.DataFrame, features: list[str], config: SupervisedConfig, seed: int
) -> dict:
    """Compute the OOF threshold of one model on one log type.

    Args:
        name: `rf` or `xgb`.
        train: Output of `training_rows`.
        features: Feature columns.
        config: Fixed values.
        seed: Random seed.

    Returns:
        A row of `supervised_dev_oof.csv`.
    """
    labels = train["is_attack"].to_numpy()
    row = {
        "model": name,
        "status": NOT_TRAINABLE,
        "windows": len(train),
        "positives": int(labels.sum()),
        "negatives": int((~labels).sum()),
        "k_used": 0,
        "blocks_dropped": "",
    }
    if labels.sum() < config.min_positives:
        return row
    matrix = train[features].to_numpy(dtype=float)
    oof = out_of_fold(
        name, matrix, labels, minutes_since_start(train["window_start"]), config, seed
    )
    row["k_used"] = len(oof.used)
    row["blocks_dropped"] = " ".join(map(str, oof.dropped))
    scored = ~np.isnan(oof.scores)
    if not oof.used or labels[scored].all():
        return row
    threshold = best_threshold(labels[scored], oof.scores[scored])
    flagged = oof.scores[scored] >= threshold
    hits = int((flagged & labels[scored]).sum())
    precision, recall = hits / flagged.sum(), hits / labels[scored].sum()
    return row | {
        "status": TRAINED,
        "oof_windows": int(scored.sum()),
        "threshold": threshold,
        "oof_precision": precision,
        "oof_recall": recall,
        "oof_f1": 2 * precision * recall / (precision + recall) if hits else 0.0,
        "oof_pr_auc": average_precision_score(labels[scored], oof.scores[scored]),
    }


def dev_results(
    tables: dict[str, pd.DataFrame],
    features: dict[str, list[str]],
    config: SupervisedConfig,
    seed: int,
) -> pd.DataFrame:
    """Compute OOF thresholds for every training variant, log type and model.

    Args:
        tables: Dev windows with ground truth, per log type.
        features: Feature columns per log type.
        config: Fixed values.
        seed: Random seed.

    Returns:
        One row per variant, log type and model.
    """
    rows = []
    for variant, periods in ((PRIMARY, config.training_periods), (ALL_PERIODS, config.all_periods)):
        for log_type, table in tables.items():
            train = training_rows(table, periods)
            for name in MODELS:
                row = dev_row(name, train, features[log_type], config, seed)
                rows.append({"variant": variant, "log_type": log_type} | row)
                logger.info("%s %s %s: %s", variant, log_type, name, row["status"])
    return pd.DataFrame(rows)


def fit_final(
    name: str, train: pd.DataFrame, features: list[str], config: SupervisedConfig, seed: int
) -> RandomForestClassifier | XGBClassifier:
    """Fit a model on all training rows of a variant."""
    labels = train["is_attack"].to_numpy()
    matrix = train[features].to_numpy(dtype=float)
    return build_model(name, labels, config, seed).fit(matrix, labels)


def importance_table(
    dev_rows: pd.DataFrame,
    tables: dict[str, pd.DataFrame],
    features: dict[str, list[str]],
    config: SupervisedConfig,
    seed: int,
) -> pd.DataFrame:
    """Return the feature importance of the primary models: impurity for RF, gain for XGB.

    Args:
        dev_rows: Output of `dev_results`.
        tables: Dev windows with ground truth, per log type.
        features: Feature columns per log type.
        config: Fixed values.
        seed: Random seed.

    Returns:
        One row per model, log type and feature, with importances summing to 1 per model.
    """
    parts = []
    trained = dev_rows[(dev_rows["variant"] == PRIMARY) & (dev_rows["status"] == TRAINED)]
    for row in trained.itertuples():
        train = training_rows(tables[row.log_type], config.training_periods)
        model = fit_final(row.model, train, features[row.log_type], config, seed)
        part = pd.DataFrame(
            {"feature": features[row.log_type], "importance": model.feature_importances_}
        )
        parts.append(part.assign(model=row.model, log_type=row.log_type))
    columns = ["log_type", "model", "feature", "importance"]
    if not parts:
        return pd.DataFrame(columns=columns)
    table = pd.concat(parts, ignore_index=True)[columns]
    return table.sort_values(["log_type", "model", "importance"], ascending=[True, True, False])


def score_test(
    model: RandomForestClassifier | XGBClassifier,
    test: pd.DataFrame,
    features: list[str],
    threshold: float,
) -> pd.DataFrame:
    """Score test windows with a fitted model and its frozen threshold."""
    table = test.drop(columns=["score", "is_anomalous"], errors="ignore").copy()
    table["score"] = model.predict_proba(test[features].to_numpy(dtype=float))[:, 1]
    table["is_anomalous"] = table["score"] >= threshold
    return table


def model_tables(
    dev_rows: pd.DataFrame,
    variant: str,
    periods: list[str],
    dev: dict[str, pd.DataFrame],
    test: dict[str, pd.DataFrame],
    features: dict[str, list[str]],
    config: SupervisedConfig,
    seed: int,
) -> dict[str, pd.DataFrame]:
    """Return the scored test windows of each model of a variant, over its trained log types."""
    tables = {}
    for name in MODELS:
        parts = []
        rows = dev_rows[
            (dev_rows["variant"] == variant)
            & (dev_rows["model"] == name)
            & (dev_rows["status"] == TRAINED)
        ]
        for row in rows.itertuples():
            train = training_rows(dev[row.log_type], periods)
            model = fit_final(name, train, features[row.log_type], config, seed)
            eval_rows = test[row.log_type]
            eval_rows = eval_rows[eval_rows["period"] == "eval"]
            parts.append(score_test(model, eval_rows, features[row.log_type], row.threshold))
        if parts:
            tables[name] = pd.concat(parts, ignore_index=True)
    return tables


def _metric_row(analysis: str, scope: str, method: str, status: str, metrics: pd.Series) -> dict:
    """Shape one line of `window_metrics` for the results table."""
    row = {
        "analysis": analysis,
        "scope": scope,
        "method": method,
        "status": status,
        "windows": int(metrics["windows"]),
        "n_pos": int(metrics["attack"]),
        "attack_share": metrics["attack"] / metrics["windows"] if metrics["windows"] else np.nan,
    }
    if status == OK:
        row |= {
            "pr_auc": metrics["pr_auc"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "flagged": int(metrics["anomalous"]),
            "true_positives": int(metrics["true_positives"]),
        }
    return row


def comparison(
    analysis: str,
    ensemble: pd.DataFrame,
    models: dict[str, pd.DataFrame],
    log_types: list[str],
    include_ambiguous: bool = False,
) -> pd.DataFrame:
    """Compare the ensemble and the models per log type and pooled (D38).

    Args:
        analysis: Name of this table in the results.
        ensemble: Ensemble scores with ground truth, all log types.
        models: Scored windows of each model, over its trained log types.
        log_types: Log types to report.
        include_ambiguous: Count label-ambiguous windows as normal (D17).

    Returns:
        One row per scope and method. A method with no model for a scope keeps its window counts
        and has no metrics, and `status` says why.
    """
    reference = window_metrics(ensemble, include_ambiguous)
    rows = []
    for scope in [*log_types, POOLED]:
        rows.append(_metric_row(analysis, scope, ENSEMBLE, OK, reference.loc[scope]))
        for name in MODELS:
            metrics = (
                window_metrics(models[name], include_ambiguous) if name in models else reference
            )
            trained = set(models[name]["log_type"]) if name in models else set()
            if scope == POOLED and trained != set(log_types):
                rows.append(
                    _metric_row(analysis, scope, name, NO_MODEL_FOR_ALL_TYPES, reference.loc[scope])
                )
            elif scope != POOLED and scope not in trained:
                rows.append(_metric_row(analysis, scope, name, NOT_TRAINABLE, reference.loc[scope]))
            else:
                rows.append(_metric_row(analysis, scope, name, OK, metrics.loc[scope]))
    covered = set(log_types)
    for name in MODELS:
        covered &= set(models[name]["log_type"]) if name in models else set()
    if covered:
        common = ensemble[ensemble["log_type"].isin(covered)]
        metrics = window_metrics(common, include_ambiguous).loc[POOLED]
        rows.append(_metric_row(analysis, POOLED_TRAINED, ENSEMBLE, OK, metrics))
        for name in MODELS:
            part = models[name][models[name]["log_type"].isin(covered)]
            metrics = window_metrics(part, include_ambiguous).loc[POOLED]
            rows.append(_metric_row(analysis, POOLED_TRAINED, name, OK, metrics))
    return pd.DataFrame(rows)


def without_exfil_only(table: pd.DataFrame) -> pd.DataFrame:
    """Drop the windows whose only phase is `dnsteal_exfil`."""
    return table[~is_exfil_only(table["phases"])]


def flagged_phases(table: pd.DataFrame, counted: list[str]) -> set[str]:
    """Return the counted phases with at least one flagged attack window.

    This is window level, with no incident step, so it is not the phase recall of plan 10.2.
    """
    hits = table[table["is_anomalous"] & table["is_attack"]]
    return set(hits["phases"].explode().dropna()) & set(counted)


def phase_rows(tables: dict[tuple[str, str], pd.DataFrame], counted: list[str]) -> pd.DataFrame:
    """Return window-level phases per method, with and without `dnsteal_exfil`.

    Args:
        tables: `(method, log types covered)` to scored windows.
        counted: Phases with traces.

    Returns:
        Two rows per method.
    """
    rows = []
    for (method, covered), table in tables.items():
        found = flagged_phases(table, counted)
        for scope, phases in (
            ("all_phases", counted),
            ("without_exfil", [name for name in counted if name != EXFIL_PHASE]),
        ):
            hit = found & set(phases)
            rows.append(
                {
                    "method": method,
                    "log_types": covered,
                    "phases_scope": scope,
                    "phases_flagged": len(hit),
                    "phases": len(phases),
                    "flagged": " ".join(name for name in phases if name in hit),
                    "not_flagged": " ".join(name for name in phases if name not in hit),
                }
            )
    return pd.DataFrame(rows)


def with_thresholds(table: pd.DataFrame, dev_rows: pd.DataFrame, variant: str) -> pd.DataFrame:
    """Add the frozen threshold of each model and log type to a results table."""
    chosen = dev_rows.loc[
        dev_rows["variant"] == variant, ["log_type", "model", "threshold"]
    ].rename(columns={"log_type": "scope", "model": "method"})
    return table.merge(chosen, how="left", on=["scope", "method"])


def config_hash(settings: Settings, features: dict[str, list[str]]) -> str:
    """Fingerprint everything that decides a threshold, to detect a change after dev (D39)."""
    frozen = {
        "seed": settings.seed,
        "supervised": settings.ml.supervised.model_dump(),
        "features": features,
    }
    text = json.dumps(frozen, sort_keys=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def refuse_rerun(path: Path, reason: str | None) -> None:
    """Stop a second santos run, or a dev run after it, unless a reason is given (D39).

    Args:
        path: The santos results file.
        reason: Why the run must be repeated. It also needs an entry in status.md.

    Raises:
        FileExistsError: If santos was scored and no reason is given.
    """
    if path.exists() and not reason:
        raise FileExistsError(f"{path} exists; santos is scored once (D39)")
    if path.exists():
        logger.warning("re-run after santos: %s", reason)


def inputs(
    settings: Settings,
) -> tuple[dict[str, pd.DataFrame], dict[str, list[str]], list[str]]:
    """Return the dev windows with ground truth, the features and the log types (D32, D33)."""
    dev = labeled_windows(DEV_TESTBED, settings)
    dev_report = feature_report(DEV_TESTBED, settings)
    test_report = feature_report(TEST_TESTBED, settings)
    log_types = [name for name in dev if test_report[name]["baseline_capable"]]
    features = {name: shared_features(dev_report, test_report, name) for name in log_types}
    return {name: dev[name] for name in log_types}, features, log_types


def run_dev(settings: Settings, rerun_reason: str | None = None) -> Path:
    """Write the dev OOF thresholds and the feature importance. Santos windows are not read.

    Args:
        settings: Loaded settings.
        rerun_reason: Required once santos has been scored.

    Returns:
        The OOF results file.
    """
    results = settings.paths.reports_dir / "results"
    refuse_rerun(results / TEST_FILE, rerun_reason)
    results.mkdir(parents=True, exist_ok=True)
    config = settings.ml.supervised
    tables, features, _ = inputs(settings)
    rows = dev_results(tables, features, config, settings.seed)
    rows["config_hash"] = config_hash(settings, features)
    rows.to_csv(results / OOF_FILE, index=False)
    importance = importance_table(rows, tables, features, config, settings.seed)
    importance.to_csv(results / IMPORTANCE_FILE, index=False)
    return results / OOF_FILE


def run_test(settings: Settings, rerun_reason: str | None = None) -> Path:
    """Score the santos evaluation period with the frozen models and thresholds, once.

    Args:
        settings: Loaded settings.
        rerun_reason: Required if santos was already scored.

    Returns:
        The results file.

    Raises:
        ValueError: If the config changed after the dev stage.
    """
    results = settings.paths.reports_dir / "results"
    refuse_rerun(results / TEST_FILE, rerun_reason)
    config = settings.ml.supervised
    dev, features, log_types = inputs(settings)
    dev_rows = pd.read_csv(results / OOF_FILE)
    if set(dev_rows["config_hash"]) != {config_hash(settings, features)}:
        raise ValueError("the config changed after the dev stage (D39)")
    test = labeled_windows(TEST_TESTBED, settings)
    periods = eda.testbed_periods(TEST_TESTBED, settings)
    with eda.connect(TEST_TESTBED, settings) as con:
        context = truth_context(con, periods, log_types, settings)
    scores = pd.read_parquet(settings.paths.processed_dir / TEST_TESTBED / SCORES_FILE)
    ensemble = with_truth(scores, context.truth)
    primary = model_tables(
        dev_rows, PRIMARY, config.training_periods, dev, test, features, config, settings.seed
    )
    all_dev = model_tables(
        dev_rows, ALL_PERIODS, config.all_periods, dev, test, features, config, settings.seed
    )
    trimmed = {name: without_exfil_only(table) for name, table in primary.items()}
    table = pd.concat(
        [
            with_thresholds(comparison("primary", ensemble, primary, log_types), dev_rows, PRIMARY),
            with_thresholds(
                comparison(
                    "secondary_without_exfil_only", without_exfil_only(ensemble), trimmed, log_types
                ),
                dev_rows,
                PRIMARY,
            ),
            with_thresholds(
                comparison(
                    "secondary_with_ambiguous", ensemble, primary, log_types, include_ambiguous=True
                ),
                dev_rows,
                PRIMARY,
            ),
            with_thresholds(
                comparison("secondary_all_dev_periods", ensemble, all_dev, log_types),
                dev_rows,
                ALL_PERIODS,
            ),
        ],
        ignore_index=True,
    )
    table.to_csv(results / TEST_FILE, index=False)
    covered = sorted({name for part in primary.values() for name in part["log_type"]})
    methods = {(ENSEMBLE, " ".join(log_types)): ensemble}
    methods[(ENSEMBLE, " ".join(covered))] = ensemble[ensemble["log_type"].isin(covered)]
    methods |= {(name, " ".join(covered)): part for name, part in primary.items()}
    phase_rows(methods, context.counted).to_csv(results / PHASES_FILE, index=False)
    return results / TEST_FILE


def main() -> None:
    """Run one stage from the command line."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=["dev", "test"])
    parser.add_argument("--rerun-reason", help="Why santos is scored again; log it in status.md.")
    arguments = parser.parse_args()
    run = run_dev if arguments.stage == "dev" else run_test
    print(run(load_settings(), arguments.rerun_reason))


if __name__ == "__main__":
    main()

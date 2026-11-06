"""The `detect` pipeline: fit, score and group a testbed (plan 9.3). It reads no ground truth."""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from logtriage.config import Settings
from logtriage.data.features import REPORT_FILE, SCALER_DIR, FeatureScaler
from logtriage.ml.ensemble import apply_threshold, calibrate, ensemble_score
from logtriage.ml.incidents import KEY, common_entities, group_incidents
from logtriage.ml.models import MODEL_NAMES, fit_models, out_of_fold_scores, score_models

logger = logging.getLogger(__name__)

SCORES_FILE = "scores.parquet"
INCIDENTS_FILE = "incidents.parquet"
DETECT_REPORT_FILE = "detect_report.json"
ENTITY_COLUMNS = ["src_ips", "users"]


@dataclass
class ScoredTestbed:
    """Scores of all windows of a testbed, before any threshold."""

    testbed: str
    scores: pd.DataFrame
    common: set[tuple[str, str, str]]
    report: dict[str, Any]


def score_log_type(
    windows: pd.DataFrame, scaler: FeatureScaler, settings: Settings, clip: bool = True
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Fit the models of a log type and score its windows.

    Args:
        windows: Windows of every period.
        scaler: Scaler of the log type.
        settings: Loaded settings.
        clip: Apply the one-sided clip (D29).

    Returns:
        Key, entity columns, `period`, raw scores, percentiles and `score`, and a report entry.
    """
    config = settings.ml
    ordered = windows.sort_values(["window_start", "host"]).reset_index(drop=True)
    matrix = ordered.pipe(scaler.transform, clip=clip)
    is_fit = (ordered["period"] == "fit").to_numpy()
    is_calib = (ordered["period"] == "calib").to_numpy()
    models = fit_models(matrix[is_fit], config, settings.seed)
    raw = score_models(models, matrix)
    is_thin = is_calib.sum() < config.min_calib_windows
    extra = out_of_fold_scores(matrix[is_fit], config, settings.seed) if is_thin else None
    hosts = ordered["host"].to_numpy()
    percentiles, sources = calibrate(raw, hosts, is_calib, extra, config)
    table = ordered[[*KEY, *ENTITY_COLUMNS, "period"]].copy()
    for name in MODEL_NAMES:
        table[f"score_{name}"] = raw[name]
    for name in MODEL_NAMES:
        table[f"pct_{name}"] = percentiles[name]
    table["score"] = ensemble_score(percentiles)
    report = {
        "fit_windows": int(is_fit.sum()),
        "calib_windows": int(is_calib.sum()),
        "thin": bool(is_thin),
        "reference_size": int(is_calib.sum() + (is_fit.sum() if is_thin else 0)),
        "reference_by_host": sources,
        "pca_components": int(models.pca.n_components_),
    }
    return table, report


def score_testbed(testbed: str, settings: Settings, clip: bool = True) -> ScoredTestbed:
    """Score every baseline-capable log type of a testbed.

    Args:
        testbed: Testbed name.
        settings: Loaded settings.
        clip: Apply the one-sided clip (D29).

    Returns:
        The scores, common entities and report. Types without a baseline are listed in the
        report as not detectable, and have no scores.
    """
    directory = settings.paths.processed_dir / testbed
    feature_report = json.loads((directory / REPORT_FILE).read_text(encoding="utf-8"))
    parts, common = [], set()
    report: dict[str, Any] = {"log_types": {}, "no_baseline": []}
    for log_type, entry in feature_report.items():
        if not entry["baseline_capable"]:
            report["no_baseline"].append(log_type)
            continue
        windows = pd.read_parquet(directory / f"windows_{log_type}.parquet")
        scaler = FeatureScaler.load(directory / SCALER_DIR / f"{log_type}.json")
        table, report["log_types"][log_type] = score_log_type(windows, scaler, settings, clip)
        parts.append(table)
        fit = windows[windows["period"] == "fit"]
        found = common_entities(fit, settings.ml.common_entity_share)
        common |= {(log_type, kind, value) for kind, value in found}
        report["log_types"][log_type]["common_entities"] = sorted(map(list, found))
    scores = pd.concat(parts, ignore_index=True)
    return ScoredTestbed(testbed, scores, common, report)


def detect(
    scored: ScoredTestbed, q: float, gap_minutes: int, window_seconds: int
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Threshold the scores and build incidents from the anomalous evaluation windows.

    Fit and calib windows only build the baseline, so they form no incident.

    Args:
        scored: Output of `score_testbed`.
        q: Threshold on `score`.
        gap_minutes: Largest gap between linked windows.
        window_seconds: Window length.

    Returns:
        The scores with `is_anomalous` and `incident_id`, and the incidents.
    """
    scores = apply_threshold(scored.scores, q)
    nodes = scores[scores["is_anomalous"] & (scores["period"] == "eval")]
    incidents, ids = group_incidents(
        nodes, scored.common, gap_minutes, window_seconds, scored.testbed
    )
    return scores.assign(incident_id=ids.reindex(scores.index)), incidents


def run_detect(testbed: str, settings: Settings) -> Path:
    """Write `scores.parquet`, `incidents.parquet` and `detect_report.json`.

    Args:
        testbed: Testbed name.
        settings: Loaded settings, with the tuned `ml.q` and `ml.gap_minutes`.

    Returns:
        The output directory.
    """
    directory = settings.paths.processed_dir / testbed
    scored = score_testbed(testbed, settings)
    window_seconds = settings.features.window_seconds
    scores, incidents = detect(scored, settings.ml.q, settings.ml.gap_minutes, window_seconds)
    columns = [name for name in scores.columns if name not in ENTITY_COLUMNS]
    scores[columns].to_parquet(directory / SCORES_FILE, index=False)
    incidents.to_parquet(directory / INCIDENTS_FILE, index=False)
    is_eval = scores["period"] == "eval"
    report = {
        **scored.report,
        "q": settings.ml.q,
        "gap_minutes": settings.ml.gap_minutes,
        "anomalous_eval_windows": int((scores["is_anomalous"] & is_eval).sum()),
        "eval_windows": int(is_eval.sum()),
        "incidents": len(incidents),
    }
    text = json.dumps(report, indent=2, sort_keys=True, default=_plain) + "\n"
    (directory / DETECT_REPORT_FILE).write_text(text, encoding="utf-8")
    logger.info("%s: %d incidents", testbed, len(incidents))
    return directory


def _plain(value: Any) -> Any:
    """Convert NumPy scalars for JSON."""
    return value.item() if isinstance(value, np.generic) else value

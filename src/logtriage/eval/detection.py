"""Detection results of one run against ground truth (plan 10.2, 13 M5)."""

import json
from dataclasses import dataclass

import duckdb
import numpy as np
import pandas as pd

from logtriage.config import DEV_TESTBED, Settings
from logtriage.data.features import OPTIONAL_FEATURES, SCALER_DIR, FeatureScaler
from logtriage.data.periods import Periods
from logtriage.eval import eda
from logtriage.eval.metrics import (
    EXFIL_PHASE,
    candidate_recall,
    detected_phases,
    incident_phases,
    incidents_per_day,
    load_gold_mapping,
    phase_credit,
    phase_recall,
    window_metrics,
    window_truth,
    with_truth,
)


@dataclass
class TruthContext:
    """Ground truth of a testbed, read once."""

    truth: pd.DataFrame
    counted: list[str]
    eval_days: float


@dataclass
class DetectionResult:
    """Metrics of one set of scores and incidents."""

    table: pd.DataFrame
    windows: pd.DataFrame
    windows_with_ambiguous: pd.DataFrame
    credit: pd.DataFrame
    recall: dict
    incidents: int
    incidents_per_day: float


def counted_phases(
    con: duckdb.DuckDBPyConnection, periods: Periods, capable_log_types: list[str]
) -> list[str]:
    """Return the phases with traces of the primary denominator, in time order (plan 10.1)."""
    traces = eda.phase_traces(con, periods)
    table = eda.phase_denominators(con, traces, capable_log_types)
    return list(table.loc[table["primary"], "phase"])


def truth_context(
    con: duckdb.DuckDBPyConnection,
    periods: Periods,
    capable_log_types: list[str],
    settings: Settings,
) -> TruthContext:
    """Read the ground truth needed to score a testbed."""
    days = (periods.eval_end - periods.eval_start).total_seconds() / 86_400
    return TruthContext(
        truth=window_truth(con, settings.features.window_seconds),
        counted=counted_phases(con, periods, capable_log_types),
        eval_days=days,
    )


def evaluate(scores: pd.DataFrame, incidents: int, context: TruthContext) -> DetectionResult:
    """Score one run.

    Args:
        scores: Scores with `is_anomalous` and `incident_id`.
        incidents: Number of incidents.
        context: Ground truth of the testbed.

    Returns:
        Window metrics, phase recall, phase credit per log type and incidents per day.
    """
    table = with_truth(scores, context.truth)
    detected = detected_phases(table)
    return DetectionResult(
        table=table,
        windows=window_metrics(table),
        windows_with_ambiguous=window_metrics(table, include_ambiguous=True),
        credit=phase_credit(detected, context.counted),
        recall=phase_recall(detected, context.counted),
        incidents=incidents,
        incidents_per_day=incidents_per_day(incidents, context.eval_days),
    )


def anomalous_by_hour(scores: pd.DataFrame) -> pd.DataFrame:
    """Return the share of eval windows flagged per UTC hour of day and log type (D27).

    Args:
        scores: Scores with `is_anomalous`.

    Returns:
        Hours as rows, log types as columns. Uses no ground truth.
    """
    table = scores[scores["period"] == "eval"]
    hours = table["window_start"].dt.hour.rename("hour_utc")
    return table.groupby([hours, "log_type"])["is_anomalous"].mean().unstack().round(4)


def window_phase(phases: list[str]) -> str | None:
    """Name one phase for a window, for coloring: exfiltration only if nothing else is there."""
    others = [phase for phase in phases if phase != EXFIL_PHASE]
    return (others or phases or [None])[0]


def embedding_inputs(
    testbed: str, log_type: str, truth: pd.DataFrame, settings: Settings
) -> tuple[np.ndarray, pd.Series]:
    """Return the scaled eval windows of a log type and the phase of each, for plan 6.8.

    Args:
        testbed: Testbed name.
        log_type: Log type with a scaler.
        truth: Output of `window_truth`.
        settings: Loaded settings.

    Returns:
        The feature matrix and one phase or None per row.
    """
    directory = settings.paths.processed_dir / testbed
    windows = pd.read_parquet(directory / f"windows_{log_type}.parquet")
    windows = windows[windows["period"] == "eval"].reset_index(drop=True)
    scaler = FeatureScaler.load(directory / SCALER_DIR / f"{log_type}.json")
    scaler = scaler.without(OPTIONAL_FEATURES - set(settings.ml.optional_features))
    merged = windows[["host", "log_type", "window_start"]].merge(
        truth, how="left", on=["host", "log_type", "window_start"]
    )
    named = merged["phases"].map(
        lambda value: window_phase(list(value)) if isinstance(value, list | np.ndarray) else None
    )
    return scaler.transform(windows), named


def dev_candidate_recall(settings: Settings, testbed: str = DEV_TESTBED) -> pd.DataFrame:
    """Compute the candidate recall diagnostic of M8, on the dev testbed only.

    Santos is scored in M11 and nowhere else, so this refuses any other testbed.

    Args:
        settings: Loaded settings.
        testbed: Must be the dev testbed.

    Returns:
        The table of `metrics.candidate_recall`.

    Raises:
        ValueError: If `testbed` is not the dev testbed.
    """
    if testbed != DEV_TESTBED:
        raise ValueError(f"{testbed}: this diagnostic runs on {DEV_TESTBED} only")
    directory = settings.paths.processed_dir / testbed
    with eda.connect(testbed, settings) as con:
        truth = window_truth(con, settings.features.window_seconds)
    scores = pd.read_parquet(directory / "scores.parquet")
    reports = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((directory / "reports").glob(f"{testbed}-*.json"))
    ]
    gold = load_gold_mapping(settings.paths.gold_mapping_file)
    return candidate_recall(reports, incident_phases(with_truth(scores, truth)), gold)

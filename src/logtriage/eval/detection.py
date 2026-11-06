"""Detection results of one run against ground truth (plan 10.2, 13 M5)."""

from dataclasses import dataclass

import duckdb
import pandas as pd

from logtriage.config import Settings
from logtriage.data.periods import Periods
from logtriage.eval import eda
from logtriage.eval.metrics import (
    detected_phases,
    incidents_per_day,
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

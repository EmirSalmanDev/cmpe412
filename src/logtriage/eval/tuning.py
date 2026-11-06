"""Choosing `q` and `gap_minutes` on the dev testbed (plan 6.4, 6.5).

Reads ground truth, so it lives in `logtriage.eval`, and it refuses any other testbed: the
values it chooses are reused unchanged on the test testbed. Run it from the repository root
with `uv run python -m logtriage.eval.tuning`.
"""

import logging
import re
from pathlib import Path

import pandas as pd

from logtriage.config import DEFAULT_CONFIG_PATH, DEV_TESTBED, Settings, load_settings
from logtriage.eval import eda
from logtriage.eval.detection import TruthContext, evaluate, truth_context
from logtriage.ml.detect import ScoredTestbed, detect, score_testbed

logger = logging.getLogger(__name__)

RESULTS_FILE = "tuning_dev.csv"


def grid_results(scored: ScoredTestbed, context: TruthContext, settings: Settings) -> pd.DataFrame:
    """Evaluate every `(q, gap_minutes)` of the grid.

    Args:
        scored: Scores of the dev testbed. They do not depend on the grid.
        context: Ground truth of the dev testbed.
        settings: Holds the grids and the window length.

    Returns:
        One row per combination.
    """
    rows = []
    for q in settings.ml.q_grid:
        for gap in settings.ml.gap_grid:
            scores, incidents = detect(scored, q, gap, settings.features.window_seconds)
            result = evaluate(scores, len(incidents), context)
            rows.append(
                {
                    "q": q,
                    "gap_minutes": gap,
                    "anomalous_windows": int(result.table["is_anomalous"].sum()),
                    "incidents": result.incidents,
                    "incidents_per_day": result.incidents_per_day,
                    "phases_detected": result.recall["detected"],
                    "phases": result.recall["phases"],
                    "phase_recall": result.recall["recall"],
                    "missed": ", ".join(result.recall["missed"]),
                }
            )
    return pd.DataFrame(rows)


def select(grid: pd.DataFrame, budget: float) -> pd.Series:
    """Choose the combination of plan 6.5.

    Highest phase recall within the budget; ties go to fewer incidents. Remaining ties go to the
    higher `q` and then the smaller gap, which gives an analyst the fewest windows to read and
    links the least.

    Args:
        grid: Output of `grid_results`.
        budget: Most incidents per day.

    Returns:
        The chosen row.

    Raises:
        ValueError: If no combination fits the budget.
    """
    feasible = grid[grid["incidents_per_day"] <= budget]
    if feasible.empty:
        raise ValueError(f"no combination reaches {budget} incidents per day")
    ordered = feasible.sort_values(
        ["phase_recall", "incidents", "q", "gap_minutes"],
        ascending=[False, True, False, True],
    )
    return ordered.iloc[0]


def write_chosen(path: Path, q: float, gap_minutes: int) -> None:
    """Replace `ml.q` and `ml.gap_minutes` in a config file, keeping its comments."""
    text = path.read_text(encoding="utf-8")
    text, found_q = re.subn(r"(?m)^  q: .*$", f"  q: {q}", text)
    text, found_gap = re.subn(r"(?m)^  gap_minutes: .*$", f"  gap_minutes: {gap_minutes}", text)
    if (found_q, found_gap) != (1, 1):
        raise ValueError(f"{path}: expected one q and one gap_minutes line")
    path.write_text(text, encoding="utf-8")


def tune(settings: Settings, config_path: Path = DEFAULT_CONFIG_PATH) -> pd.Series:
    """Run the grid on the dev testbed and write the choice to the config.

    Args:
        settings: Loaded settings.
        config_path: Config file to update.

    Returns:
        The chosen row.
    """
    scored = score_testbed(DEV_TESTBED, settings)
    capable = list(scored.report["log_types"])
    periods = eda.testbed_periods(DEV_TESTBED, settings)
    with eda.connect(DEV_TESTBED, settings) as con:
        context = truth_context(con, periods, capable, settings)
    grid = grid_results(scored, context, settings)
    chosen = select(grid, settings.ml.incidents_per_day_budget)
    results = settings.paths.reports_dir / "results"
    results.mkdir(parents=True, exist_ok=True)
    grid.to_csv(results / RESULTS_FILE, index=False)
    write_chosen(config_path, float(chosen["q"]), int(chosen["gap_minutes"]))
    return chosen


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(tune(load_settings()).to_string())

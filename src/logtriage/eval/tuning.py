"""Choosing `q` and `gap_minutes` on the dev testbed (plan 6.4, 6.5).

Reads ground truth, so it lives in `logtriage.eval`, and it refuses any other testbed: the
values it chooses are reused unchanged on the test testbed. Run it from the repository root
with `uv run python -m logtriage.eval.tuning`.

`--v2` runs the v2 selection of `reports/v2_plan.md` §4 instead: every configuration of the
candidates once on the dev testbed, into `v2_dev_selection.csv`. It writes no config file.
"""

import argparse
import logging
import re
from pathlib import Path

import pandas as pd

from logtriage.config import DEFAULT_CONFIG_PATH, DEV_TESTBED, MLConfig, Settings, load_settings
from logtriage.eval import eda
from logtriage.eval.detection import DetectionResult, TruthContext, evaluate, truth_context
from logtriage.ml.detect import ScoredTestbed, detect, score_testbed

logger = logging.getLogger(__name__)

RESULTS_FILE = "tuning_dev.csv"
V2_CONFIG_PATH = Path("configs/v2.yaml")
V2_RESULTS_FILE = "v2_dev_selection.csv"
# In the order of reports/v2_plan.md §4, which is also the last tie-break.
CONFIGURATIONS = ("v1", "a", "b", "d", "a+b", "a+d", "b+d", "a+b+d")
# The `ml` setting each candidate takes from `configs/v2.yaml` (§3).
CANDIDATE_FIELDS = {"a": "thin_calibration", "b": "q_grid", "d": "optional_features"}


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
            rows.append(grid_row(q, gap, result))
    return pd.DataFrame(rows)


def grid_row(q: float, gap: int, result: DetectionResult) -> dict:
    """Return the `tuning_dev.csv` row of one `(q, gap_minutes)`."""
    return {
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


def phase_details(result: DetectionResult) -> dict:
    """Return which log types credit each detected phase, and the flagged windows per type.

    Args:
        result: One evaluated run.

    Returns:
        `credit` as `phase: type type; ...` over the detected phases, `dns_only` as the phases
        credited through `dns` alone (D29), and `anomalous_by_type` as `type n; ...` over the
        flagged eval windows.
    """
    credit = result.credit
    types = [name for name in credit.columns if name not in ("detected", "dns_only")]
    detected = credit[credit["detected"]]
    parts = [
        f"{phase}: {' '.join(name for name in types if row[name] > 0)}"
        for phase, row in detected.iterrows()
    ]
    flagged = result.table[result.table["is_anomalous"]]
    counts = flagged.groupby("log_type").size()
    return {
        "dns_only": ", ".join(sorted(credit.index[credit["dns_only"]])),
        "credit": "; ".join(parts),
        "anomalous_by_type": "; ".join(f"{name} {int(n)}" for name, n in counts.items()),
    }


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


def candidates_of(configuration: str) -> list[str]:
    """Return the candidates of a configuration name, such as `a+d`; `v1` has none."""
    if configuration not in CONFIGURATIONS:
        raise ValueError(f"{configuration}: not a configuration of reports/v2_plan.md §4")
    return [] if configuration == "v1" else configuration.split("+")


def configuration_settings(base: Settings, v2: Settings, configuration: str) -> Settings:
    """Return the v1 settings with the candidates of a configuration taken from v2.

    Args:
        base: Settings of `configs/default.yaml`, the v1 values.
        v2: Settings of `configs/v2.yaml`, which hold the value of every candidate.
        configuration: One of `CONFIGURATIONS`.

    Returns:
        A copy of `base`. `q` and `gap_minutes` stay those of `base`; the grid replaces them.

    Raises:
        ValueError: If a candidate's v2 value equals its v1 value, so it would change nothing.
    """
    update = {}
    for candidate in candidates_of(configuration):
        name = CANDIDATE_FIELDS[candidate]
        value = getattr(v2.ml, name)
        if value == getattr(base.ml, name):
            raise ValueError(f"candidate ({candidate}): ml.{name} is the same in v1 and v2")
        update[name] = value
    ml = MLConfig.model_validate({**base.ml.model_dump(), **update})
    return base.model_copy(update={"ml": ml})


def selection_grid(
    base: Settings, v2: Settings, context: TruthContext, configurations=CONFIGURATIONS
) -> pd.DataFrame:
    """Score the dev testbed once per configuration and evaluate its grid (§4).

    Args:
        base: v1 settings.
        v2: v2 settings, holding the candidate values.
        context: Ground truth of the dev testbed.
        configurations: Configurations to run, each once.

    Returns:
        One row per configuration and `(q, gap_minutes)`: the `tuning_dev.csv` columns after
        `configuration` and `n_candidates`, then the columns of `phase_details`.
    """
    rows = []
    for configuration in configurations:
        settings = configuration_settings(base, v2, configuration)
        logger.info("v2 selection: scoring %s", configuration)
        scored = score_testbed(DEV_TESTBED, settings)
        for q in settings.ml.q_grid:
            for gap in settings.ml.gap_grid:
                scores, incidents = detect(scored, q, gap, settings.features.window_seconds)
                result = evaluate(scores, len(incidents), context)
                rows.append(
                    {
                        "configuration": configuration,
                        "n_candidates": len(candidates_of(configuration)),
                        **grid_row(q, gap, result),
                        **phase_details(result),
                    }
                )
    return pd.DataFrame(rows)


def v1_rows_match(grid: pd.DataFrame, saved: Path) -> bool:
    """Return True if the v1 rows of a selection grid equal `tuning_dev.csv` as written (§4)."""
    v1 = grid.loc[grid["configuration"] == "v1", list(pd.read_csv(saved).columns)]
    return v1.to_csv(index=False) == saved.read_text(encoding="utf-8")


def select_v2(grid: pd.DataFrame, budget: float) -> pd.Series:
    """Choose the v2 row by the §6.5 rule over all configurations (reports/v2_plan.md §4).

    Highest phase recall within the budget; ties go to fewer incidents, then to fewer
    candidates (v1 first), then to the higher `q` and the smaller gap, and last to the
    order of `CONFIGURATIONS`.

    Args:
        grid: Output of `selection_grid`.
        budget: Most incidents per day.

    Returns:
        The chosen row.

    Raises:
        ValueError: If no row fits the budget.
    """
    feasible = grid[grid["incidents_per_day"] <= budget]
    if feasible.empty:
        raise ValueError(f"no combination reaches {budget} incidents per day")
    position = feasible["configuration"].map(CONFIGURATIONS.index).rename("position")
    ordered = feasible.assign(position=position).sort_values(
        ["phase_recall", "incidents", "n_candidates", "q", "gap_minutes", "position"],
        ascending=[False, True, True, False, True, True],
        kind="stable",
    )
    return ordered.drop(columns="position").iloc[0]


def run_v2_selection(
    base: Settings, v2: Settings, results_dir: Path | None = None
) -> tuple[pd.DataFrame, pd.Series]:
    """Run the v2 selection once on the dev testbed and write every row (§4).

    Args:
        base: v1 settings, of `configs/default.yaml`.
        v2: v2 settings, of `configs/v2.yaml` before the freeze.
        results_dir: Folder of the results, `reports/results` by default.

    Returns:
        All rows and the chosen one.

    Raises:
        FileExistsError: If the selection already ran: it runs once.
        ValueError: If the v1 rows differ from `tuning_dev.csv`, before any choice is made.
    """
    results = results_dir or base.paths.reports_dir / "results"
    output = results / V2_RESULTS_FILE
    if output.exists():
        raise FileExistsError(f"{output} exists: the v2 selection runs once")
    scored = score_testbed(DEV_TESTBED, base)
    capable = list(scored.report["log_types"])
    periods = eda.testbed_periods(DEV_TESTBED, base)
    with eda.connect(DEV_TESTBED, base) as con:
        context = truth_context(con, periods, capable, base)
    grid = selection_grid(base, v2, context)
    grid.to_csv(output, index=False)
    if not v1_rows_match(grid, results / RESULTS_FILE):
        raise ValueError(f"the v1 rows of {output} differ from {RESULTS_FILE}: stop")
    return grid, select_v2(grid, base.ml.incidents_per_day_budget)


def main() -> None:
    """Run the v1 tuning, or the v2 selection with `--v2`."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v2", action="store_true", help="Run the v2 selection (§4) once.")
    arguments = parser.parse_args()
    if not arguments.v2:
        print(tune(load_settings()).to_string())
        return
    grid, chosen = run_v2_selection(load_settings(), load_settings(V2_CONFIG_PATH))
    print(grid.to_string())
    print(chosen.to_string())


if __name__ == "__main__":
    main()

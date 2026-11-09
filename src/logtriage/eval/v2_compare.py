"""v1 against v2 detection on the unseen M12 testbeds, from saved outputs only (D86-D88).

It reads each mode's `scores.parquet` and `incidents.parquet` and scores them with the M5 rules
as they are (`eval.detection.evaluate`, plan 10.1-10.2): a phase is credited when an anomalous
window inside an incident holds one of its labeled lines, over the denominators frozen in
`reports/targets_<testbed>.md`. The verdict is `reports/v2_plan.md` §7, applied as written.
Nothing is fit, scored or changed.

    python -m logtriage.eval.v2_compare
"""

import json
import sys

import pandas as pd

from logtriage.config import V1_MODE, V2_CONFIG_PATH, V2_MODE, Settings, load_settings
from logtriage.data.store import detection_dir
from logtriage.eval import eda
from logtriage.eval.detection import evaluate, truth_context
from logtriage.eval.metrics import AMBIGUOUS_LOG_TYPE, EXFIL_PHASE
from logtriage.eval.tables import capable_log_types

# The files of `ml.detect`, named here so that evaluation never loads the scoring code (D57).
SCORES_FILE = "scores.parquet"
INCIDENTS_FILE = "incidents.parquet"
DETECT_REPORT_FILE = "detect_report.json"
UNSEEN_TESTBEDS = ("shaw", "fox")
MODES = (V1_MODE, V2_MODE)
BUDGET_PER_DAY = 25
# Frozen denominators, from `reports/targets_shaw.md` and `reports/targets_fox.md` (session 3A):
# primary, all parsed, without `dnsteal_exfil`. A run whose counts differ stops.
FROZEN = {"shaw": (8, 8, 8), "fox": (9, 9, 8)}
SUMMARY_FILE = "v2_test_detection.csv"
CREDIT_FILE = "v2_test_phase_credit.csv"
HELPS, NO_HELP, HURTS = "helps", "does not help", "hurts"


def _names(phases: list[str]) -> str:
    return " ".join(phases)


def mode_result(
    testbed: str, settings: Settings, mode: str, frozen: tuple[int, int, int] | None = None
) -> tuple[dict, pd.DataFrame]:
    """Score one mode of one testbed from its saved outputs.

    Args:
        testbed: Testbed name.
        settings: Settings whose paths hold the testbed.
        mode: `v1` or `v2`.
        frozen: The frozen denominators to check against; none checked if None.

    Returns:
        The summary row and the phase credit table (one row per counted phase).

    Raises:
        ValueError: If the counted phases differ from the frozen denominators.
    """
    directory = settings.paths.processed_dir / testbed
    outputs = detection_dir(directory, mode)
    scores = pd.read_parquet(outputs / SCORES_FILE)
    incidents = pd.read_parquet(outputs / INCIDENTS_FILE)
    report = json.loads((outputs / DETECT_REPORT_FILE).read_text(encoding="utf-8"))
    periods = eda.testbed_periods(testbed, settings)
    capable = capable_log_types(directory)
    with eda.connect(testbed, settings) as con:
        context = truth_context(con, periods, capable, settings)
        table = eda.phase_denominators(con, eda.phase_traces(con, periods), capable)
    primary = list(table.loc[table["primary"], "phase"])
    all_parsed = list(table.loc[table["all_parsed"], "phase"])
    without_exfil = [phase for phase in primary if phase != EXFIL_PHASE]
    sizes = (len(primary), len(all_parsed), len(without_exfil))
    if frozen is not None and sizes != frozen:
        raise ValueError(f"{testbed}: denominators {sizes} differ from the frozen {frozen}")
    if primary != context.counted:
        raise ValueError(f"{testbed}: the counted phases differ from the primary denominator")
    result = evaluate(scores, len(incidents), context)
    credit = result.credit
    credited = [phase for phase in primary if credit.loc[phase, "detected"]]
    found = set(credited)
    flagged = scores[scores["is_anomalous"] & (scores["period"] == "eval")]
    per_type = flagged.groupby("log_type").size()
    row = {
        "testbed": testbed,
        "mode": mode,
        "q": report["q"],
        "gap_minutes": report["gap_minutes"],
        "phases": len(primary),
        "detected": len(credited),
        "recall": len(credited) / len(primary),
        "required_80": -(-len(primary) * 4 // 5),
        "target_80_met": len(credited) >= -(-len(primary) * 4 // 5),
        "credited": _names(credited),
        "missed": _names([phase for phase in primary if phase not in found]),
        "dns_only": _names([phase for phase in credited if credit.loc[phase, "dns_only"]]),
        "all_parsed_detected": len(found & set(all_parsed)),
        "all_parsed_phases": len(all_parsed),
        "without_exfil_detected": len(found & set(without_exfil)),
        "without_exfil_phases": len(without_exfil),
        "incidents": result.incidents,
        "eval_days": round(context.eval_days, 6),
        "incidents_per_day": round(result.incidents_per_day, 4),
        "within_budget": result.incidents_per_day <= BUDGET_PER_DAY,
        "flagged_eval_windows": len(flagged),
        "flagged_by_log_type": " ".join(f"{name}:{count}" for name, count in per_type.items()),
    }
    columns = [name for name in credit.columns if name not in ("detected", "dns_only")]
    credit_rows = credit.reset_index(names="phase").assign(testbed=testbed, mode=mode)
    credit_rows = credit_rows[["testbed", "mode", "phase", *columns, "detected", "dns_only"]]
    return row, credit_rows


def changes(v1: dict, v2: dict) -> tuple[list[str], list[str]]:
    """Return the phases v2 gains over v1 and the phases v1 credits that v2 loses."""
    first, second = set(v1["credited"].split()), set(v2["credited"].split())
    order = (v1["credited"] + " " + v1["missed"]).split()
    return [p for p in order if p in second - first], [p for p in order if p in first - second]


def verdict(rows: pd.DataFrame, credit: pd.DataFrame) -> dict:
    """Read `reports/v2_plan.md` §7 on the sum over the testbeds, as written.

    - Hurts: fewer phases than v1 in total, or more than 25 incidents per day on either testbed.
    - Helps: more phases in total, at least one extra phase credited through a log type other
      than `dns`, and within 25 per day on each testbed.
    - Does not help: the same total, or a total gain that comes only through `dns` credit.

    Args:
        rows: One summary row per testbed and mode.
        credit: The phase credit tables of every testbed and mode.

    Returns:
        The totals, the gained and lost phases per testbed, and the verdict.
    """
    by_mode = {mode: rows[rows["mode"] == mode].set_index("testbed") for mode in MODES}
    testbeds = list(by_mode[V1_MODE].index)
    totals = {mode: int(by_mode[mode]["detected"].sum()) for mode in MODES}
    phases = int(by_mode[V1_MODE]["phases"].sum())
    gained, lost, non_dns_gain = {}, {}, False
    for testbed in testbeds:
        gained[testbed], lost[testbed] = changes(
            by_mode[V1_MODE].loc[testbed].to_dict(), by_mode[V2_MODE].loc[testbed].to_dict()
        )
        v2_credit = credit[(credit["testbed"] == testbed) & (credit["mode"] == V2_MODE)]
        v2_credit = v2_credit.set_index("phase")
        others = [
            name
            for name in v2_credit.columns
            if name not in ("testbed", "mode", "detected", "dns_only", AMBIGUOUS_LOG_TYPE)
        ]
        for phase in gained[testbed]:
            if v2_credit.loc[phase, others].sum() > 0:
                non_dns_gain = True
    over_budget = bool((~by_mode[V2_MODE]["within_budget"]).any())
    if totals[V2_MODE] < totals[V1_MODE] or over_budget:
        reading = HURTS
    elif totals[V2_MODE] > totals[V1_MODE] and non_dns_gain:
        reading = HELPS
    else:
        reading = NO_HELP
    return {
        "phases": phases,
        "v1_detected": totals[V1_MODE],
        "v2_detected": totals[V2_MODE],
        "gained": gained,
        "lost": lost,
        "extra_phase_through_non_dns": non_dns_gain,
        "v2_over_budget_on_a_testbed": over_budget,
        "verdict": reading,
    }


def compare(
    settings: Settings, testbeds: tuple[str, ...] = UNSEEN_TESTBEDS, check_frozen: bool = True
) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Score v1 and v2 on each testbed and read the verdict."""
    rows, credits = [], []
    for testbed in testbeds:
        for mode in MODES:
            row, credit = mode_result(
                testbed, settings, mode, FROZEN[testbed] if check_frozen else None
            )
            rows.append(row)
            credits.append(credit)
    summary = pd.DataFrame(rows)
    credit = pd.concat(credits, ignore_index=True)
    credit = credit.fillna(0)
    return summary, credit, verdict(summary, credit)


def main() -> None:
    """Write the two result files and print the verdict."""
    settings = load_settings()
    v2 = load_settings(V2_CONFIG_PATH)
    if settings.paths != v2.paths:
        sys.exit("v1 and v2 settings read different folders")
    summary, credit, reading = compare(settings)
    results = settings.paths.reports_dir / "results"
    summary.to_csv(results / SUMMARY_FILE, index=False)
    credit.to_csv(results / CREDIT_FILE, index=False)
    print(json.dumps(reading, indent=2))


if __name__ == "__main__":
    main()

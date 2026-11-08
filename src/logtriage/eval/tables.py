"""Metric tables of M11 that need no LLM call (plan 10.2, 10.3, 10.7), from saved outputs only.

This module scores nothing. It reads `scores.parquet`, `incidents.parquet`, the saved reports, the
AIT-ADS alerts and ground truth through `eval.duckdb`, and it must not import `logtriage.ml`: a
test holds it to that, because a test testbed runs each stage once (D57).

Window metrics and alert reduction are never pooled over testbeds (plan 10.7). The dev testbed is
reported apart and is never in a pooled row.
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from logtriage.config import DEV_TESTBED, M11_TESTBEDS, Settings, load_settings
from logtriage.data.features import REPORT_FILE
from logtriage.eval import baselines, eda
from logtriage.eval.detection import DetectionResult, evaluate, truth_context
from logtriage.eval.metrics import (
    EXFIL_PHASE,
    attack_incidents,
    attack_summary,
    citation_summary,
    cost_summary,
    detected_phases,
    incident_truth,
    load_gold_mapping,
    verdict_counts,
    verdict_scores,
    window_table,
)

logger = logging.getLogger(__name__)

DEV = "dev"
TEST = "test"
POOLED = "pooled"
RESULTS_DIR = "results"
INCIDENT_BUDGET_REDUCTION = baselines.REQUIRED_REDUCTION
# Never recomputed: that secondary needs a second scoring pass, and no output of it was saved.
# It exists for these two testbeds only (D61).
UNCLIPPED_DNS = (
    (DEV_TESTBED, DEV, 6, 10, "7.47 incidents/day, 17 dns windows, 0 true"),
    ("santos", TEST, 7, 9, "1.11 incidents/day, 1,012 dns windows, 5 true"),
)
UNCLIPPED_SOURCE = "status.md, Key results, M5 secondary"


@dataclass
class TestbedInputs:
    """What the tables need of one testbed."""

    __test__ = False

    name: str
    group: str
    result: DetectionResult
    denominators: pd.DataFrame
    reports: dict[str, dict]
    alerts: pd.DataFrame
    labeled: pd.DataFrame
    intervals: pd.DataFrame
    days: float


def capable_log_types(directory: Path) -> list[str]:
    """Return the baseline-capable log types of a testbed, from its saved features report."""
    report = json.loads((directory / REPORT_FILE).read_text(encoding="utf-8"))
    return [name for name, entry in report.items() if entry["baseline_capable"]]


def load_reports(directory: Path, testbed: str) -> dict[str, dict]:
    """Return the saved reports of a testbed by incident."""
    paths = sorted((directory / "reports").glob(f"{testbed}-*.json"))
    return {path.stem: json.loads(path.read_text(encoding="utf-8")) for path in paths}


def load_inputs(testbed: str, settings: Settings) -> TestbedInputs:
    """Read the saved outputs of a testbed. Nothing is written or scored.

    Args:
        testbed: Testbed name.
        settings: Loaded settings.

    Returns:
        Its inputs, with the alerts of the evaluation period only.

    Raises:
        ValueError: If reports and incidents do not match.
    """
    directory = settings.paths.processed_dir / testbed
    periods = eda.testbed_periods(testbed, settings)
    capable = capable_log_types(directory)
    with eda.connect(testbed, settings) as con:
        context = truth_context(con, periods, capable, settings)
        denominators = eda.phase_denominators(con, eda.phase_traces(con, periods), capable)
        labeled = con.execute(
            """
            SELECT DISTINCT l.raw, b.phase FROM labels b JOIN lines l USING (line_id)
            WHERE l.ts >= ? AND l.ts < ?
            """,
            [periods.eval_start, periods.eval_end],
        ).df()
        intervals = con.execute(
            "SELECT phase, start_utc, end_utc FROM phases ORDER BY start_utc"
        ).df()
    for column in ("start_utc", "end_utc"):
        intervals[column] = pd.to_datetime(intervals[column], utc=True)
    incidents = pd.read_parquet(directory / "incidents.parquet")
    scores = pd.read_parquet(directory / "scores.parquet")
    reports = load_reports(directory, testbed)
    if set(reports) != set(incidents["incident_id"]):
        raise ValueError(f"{testbed}: reports and incidents differ")
    alerts = baselines.load_ids_alerts(settings.paths.raw_dir / "ait_ads", testbed)
    return TestbedInputs(
        name=testbed,
        group=DEV if testbed == DEV_TESTBED else TEST,
        result=evaluate(scores, len(incidents), context),
        denominators=denominators,
        reports=reports,
        alerts=baselines.in_evaluation(alerts, periods).reset_index(drop=True),
        labeled=labeled,
        intervals=intervals,
        days=baselines.evaluation_days(periods),
    )


def recall_variants(denominators: pd.DataFrame) -> dict[str, list[str]]:
    """Return the phases of each denominator: the primary and both secondary ones (plan 10.1)."""
    primary = list(denominators.loc[denominators["primary"], "phase"])
    return {
        "primary": primary,
        "all_parsed": list(denominators.loc[denominators["all_parsed"], "phase"]),
        "without_exfil": [phase for phase in primary if phase != EXFIL_PHASE],
    }


def _recall_row(testbed: str, group: str, variant: str, found: set[str], names: list[str]) -> dict:
    """Return one row of a phase recall table."""
    detected = len(found & set(names))
    return {
        "testbed": testbed,
        "group": group,
        "variant": variant,
        "detected": detected,
        "phases": len(names),
        "recall": detected / len(names),
        "missed": " ".join(sorted(set(names) - found)),
    }


def _pooled_recall(rows: list[dict], keys: tuple[str, ...]) -> list[dict]:
    """Return sum of detected over sum of denominators, per variant (plan 10.7).

    Args:
        rows: Rows of `_recall_row`.
        keys: Columns that name a variant.

    Returns:
        One pooled row per variant, over the test testbeds.
    """
    table = pd.DataFrame([row for row in rows if row["group"] == TEST])
    pooled = []
    for values, part in table.groupby(list(keys), sort=False):
        entry = dict(zip(keys, values, strict=True))
        detected, phases = int(part["detected"].sum()), int(part["phases"].sum())
        pooled.append(
            {
                "testbed": POOLED,
                "group": POOLED,
                **entry,
                "detected": detected,
                "phases": phases,
                "recall": detected / phases,
                "missed": "",
            }
        )
    return pooled


def windows_table(items: list[TestbedInputs]) -> pd.DataFrame:
    """Return window metrics per testbed, with and without label-ambiguous windows. Never pooled."""
    parts = []
    for item in items:
        for variant, include in (("primary", False), ("with_ambiguous", True)):
            part = window_table(item.result.table, include).reset_index()
            part.insert(0, "variant", variant)
            part.insert(0, "group", item.group)
            part.insert(0, "testbed", item.name)
            parts.append(part)
    return pd.concat(parts, ignore_index=True)


def phase_recall_table(items: list[TestbedInputs]) -> pd.DataFrame:
    """Return phase recall per testbed and pooled, and the quoted unclipped secondary (D61)."""
    rows = []
    for item in items:
        found = set(detected_phases(item.result.table).index)
        for variant, names in recall_variants(item.denominators).items():
            rows.append(_recall_row(item.name, item.group, variant, found, names))
    rows += _pooled_recall(rows, ("variant",))
    table = pd.DataFrame(rows).assign(source="computed", note="")
    quoted = [
        {
            "testbed": testbed,
            "group": group,
            "variant": "unclipped_dns",
            "detected": detected,
            "phases": phases,
            "recall": detected / phases,
            "missed": "",
            "source": UNCLIPPED_SOURCE,
            "note": note,
        }
        for testbed, group, detected, phases, note in UNCLIPPED_DNS
    ]
    return pd.concat([table, pd.DataFrame(quoted)], ignore_index=True)


def phase_credit_table(items: list[TestbedInputs]) -> pd.DataFrame:
    """Return which log types detected each counted phase, so DNS-only credit shows (D29)."""
    parts = [
        item.result.credit.rename_axis("phase").reset_index().assign(testbed=item.name)
        for item in items
    ]
    table = pd.concat(parts, ignore_index=True)
    counts = [name for name in table.columns if name not in ("phase", "testbed")]
    table[counts] = table[counts].fillna(0)
    return table[["testbed", "phase", *counts]]


def alert_reduction_table(
    items: list[TestbedInputs], gap_minutes: int, budget: int
) -> pd.DataFrame:
    """Compare incidents with what an analyst would read otherwise, per day (plan 10.2).

    Args:
        items: Inputs of each testbed.
        gap_minutes: The gap of the incidents, reused for alerts.
        budget: Incidents per day allowed.

    Returns:
        One row per testbed; never pooled (plan 10.7).
    """
    rows = []
    for item in items:
        incidents = item.result.incidents
        windows = int(item.result.table["is_anomalous"].sum())
        raw = len(item.alerts)
        grouped = int(baselines.group_alerts(item.alerts, gap_minutes).nunique())
        per_day = incidents / item.days
        rows.append(
            {
                "testbed": item.name,
                "group": item.group,
                "days": item.days,
                "incidents": incidents,
                "anomalous_windows": windows,
                "raw_alerts": raw,
                "grouped_alerts": grouped,
                "incidents_per_day": per_day,
                "anomalous_windows_per_day": windows / item.days,
                "raw_alerts_per_day": raw / item.days,
                "grouped_alerts_per_day": grouped / item.days,
                "reduction_vs_windows": 1 - incidents / windows,
                "reduction_vs_raw_alerts": 1 - incidents / raw,
                "reduction_vs_grouped_alerts": 1 - incidents / grouped,
                "within_budget": per_day <= budget,
                "meets_reduction": 1 - incidents / raw >= INCIDENT_BUDGET_REDUCTION,
            }
        )
    return pd.DataFrame(rows)


def ids_tables(items: list[TestbedInputs]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return IDS phase recall by label and denominator, and the alerts of each phase (plan 10.3).

    Args:
        items: Inputs of each testbed.

    Returns:
        The recall rows, with pooled rows, and the per-phase counts.
    """
    rows, parts = [], []
    for item in items:
        names = list(item.denominators["phase"])
        event = baselines.event_phases(item.alerts, item.labeled)
        timed = baselines.time_phases(item.alerts, item.intervals)
        table = baselines.ids_phase_table(event, timed, names)
        variants = recall_variants(item.denominators)
        for label, column in (("event", "event_alerts"), ("time", "time_alerts")):
            found = set(table.index[table[column] > 0])
            for variant, counted in variants.items():
                row = _recall_row(item.name, item.group, variant, found, counted)
                rows.append({**row, "label": label})
        part = table.reset_index()
        part.insert(0, "testbed", item.name)
        part["counted"] = part["phase"].isin(variants["primary"])
        parts.append(part)
    rows += _pooled_recall(rows, ("label", "variant"))
    columns = ["testbed", "group", "label", "variant", "detected", "phases", "recall", "missed"]
    return pd.DataFrame(rows)[columns], pd.concat(parts, ignore_index=True)


def _verdict_row(method: str, variant: str, testbed: str, group: str, counts: dict) -> dict:
    """Return one row of the verdict table."""
    return {
        "method": method,
        "variant": variant,
        "testbed": testbed,
        "group": group,
        "incidents": sum(counts.values()),
        **counts,
        **verdict_scores(counts),
    }


def verdict_table(items: list[TestbedInputs]) -> pd.DataFrame:
    """Return the verdict metrics of the agents and of the ML-only baseline (plan 10.2, 10.3).

    The pooled row sums the matrices of the test testbeds, so its benign column holds their other
    incidents (D62).

    Args:
        items: Inputs of each testbed.

    Returns:
        One row per method, variant and testbed, and the pooled rows.
    """
    rows = []
    for method in ("agents", "ml_only"):
        for variant, include in (("primary", False), ("with_ambiguous", True)):
            pooled: dict[str, int] = {}
            for item in items:
                truth = incident_truth(item.result.table)
                if method == "agents":
                    verdicts = pd.Series(
                        {key: report["verdict"] for key, report in item.reports.items()}
                    )
                else:
                    verdicts = pd.Series("malicious", index=truth.index)
                counts = verdict_counts(truth, verdicts, include)
                rows.append(_verdict_row(method, variant, item.name, item.group, counts))
                if item.group == TEST:
                    pooled = {key: pooled.get(key, 0) + value for key, value in counts.items()}
            rows.append(_verdict_row(method, variant, POOLED, POOLED, pooled))
    return pd.DataFrame(rows)


def attack_tables(
    items: list[TestbedInputs], gold: dict[str, list[str]]
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return ATT&CK hits per testbed and pooled, and the row of each malicious incident."""
    parts, rows = [], []
    for item in items:
        incidents = attack_incidents(incident_truth(item.result.table), item.reports, gold)
        incidents.insert(0, "group", item.group)
        incidents.insert(0, "testbed", item.name)
        parts.append(incidents)
        rows.append({"testbed": item.name, "group": item.group, **attack_summary(incidents)})
    every = pd.concat(parts, ignore_index=True)
    tests = every[every["group"] == TEST]
    rows.append({"testbed": POOLED, "group": POOLED, **attack_summary(tests)})
    return pd.DataFrame(rows), every


def citations_table(items: list[TestbedInputs]) -> pd.DataFrame:
    """Return hallucinated citations before the Verifier, per testbed and pooled (plan 10.2)."""
    rows = [
        {"testbed": item.name, "group": item.group, **citation_summary(item.reports.values())}
        for item in items
    ]
    tests = [report for item in items if item.group == TEST for report in item.reports.values()]
    rows.append({"testbed": POOLED, "group": POOLED, **citation_summary(tests)})
    return pd.DataFrame(rows)


def cost_table(items: list[TestbedInputs], settings: Settings) -> pd.DataFrame:
    """Return cost, latency and tokens per incident, per testbed (plan 10.2)."""
    prices = settings.llm.pricing_usd_per_1m
    off_peak, peak = prices.off_peak.model_dump(), prices.peak.model_dump()
    return pd.DataFrame(
        [
            {
                "testbed": item.name,
                "group": item.group,
                **cost_summary(item.reports.values(), off_peak, peak),
            }
            for item in items
        ]
    )


def build_tables(items: list[TestbedInputs], settings: Settings) -> dict[str, pd.DataFrame]:
    """Return every table by its file name, without the extension."""
    gold = load_gold_mapping(settings.paths.gold_mapping_file)
    ids_recall_rows, ids_phases = ids_tables(items)
    attack, attack_rows = attack_tables(items, gold)
    return {
        "eval_windows": windows_table(items),
        "eval_phase_recall": phase_recall_table(items),
        "eval_phase_credit": phase_credit_table(items),
        "eval_alert_reduction": alert_reduction_table(
            items, settings.ml.gap_minutes, settings.ml.incidents_per_day_budget
        ),
        "eval_ids_recall": ids_recall_rows,
        "eval_ids_phases": ids_phases,
        "eval_verdict": verdict_table(items),
        "eval_attack": attack,
        "eval_attack_incidents": attack_rows,
        "eval_citations": citations_table(items),
        "eval_cost": cost_table(items, settings),
    }


def write_tables(tables: dict[str, pd.DataFrame], directory: Path) -> None:
    """Write each table as a CSV."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, table in tables.items():
        table.to_csv(directory / f"{name}.csv", index=False, float_format="%.6f")


def main() -> None:
    """Write the tables of the test testbeds and of the dev testbed. Run from the repo root."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = load_settings()
    items = []
    for testbed in [*M11_TESTBEDS, DEV_TESTBED]:
        logger.info("reading %s", testbed)
        items.append(load_inputs(testbed, settings))
    write_tables(build_tables(items, settings), settings.paths.reports_dir / RESULTS_DIR)


if __name__ == "__main__":
    main()

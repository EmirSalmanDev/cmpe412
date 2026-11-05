"""IDS baseline: AIT-ADS alerts per day and the alert budget check (plan 10.2, 10.3)."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from logtriage.data.periods import Periods

# Wazuh ingests these files as well as their twins (`eve.json`, `mail.log`), so each of their
# alerts repeats one from the twin. They count as raw alerts; the lower bound leaves them out.
MIRRORED_LOCATIONS = ("/var/log/suricata/fast.log", "/var/log/mail.info")


def wazuh_source(alert: dict) -> str:
    """Name the detector behind a Wazuh alert: `suricata` or `wazuh`."""
    groups = alert.get("rule", {}).get("groups") or []
    return (
        "suricata" if "suricata" in groups or "suricata" in alert.get("location", "") else "wazuh"
    )


def load_ids_alerts(directory: Path, testbed: str) -> pd.DataFrame:
    """Read the AIT-ADS alerts of a testbed.

    Args:
        directory: `data/raw/ait_ads`.
        testbed: Testbed name.

    Returns:
        One row per alert: `ts` (UTC), `source` (`wazuh`, `suricata`, `aminer`) and `location`
        (the log file, for Wazuh alerts).
    """
    rows: list[tuple[datetime, str, str | None]] = []
    with (directory / f"{testbed}_wazuh.json").open(encoding="utf-8") as handle:
        for line in handle:
            alert = json.loads(line)
            ts = datetime.fromisoformat(alert["@timestamp"].replace("Z", "+00:00"))
            rows.append((ts, wazuh_source(alert), alert.get("location")))
    with (directory / f"{testbed}_aminer.json").open(encoding="utf-8") as handle:
        for line in handle:
            stamps = json.loads(line)["LogData"]["Timestamps"]
            rows.append((datetime.fromtimestamp(float(stamps[0]), tz=UTC), "aminer", None))
    return pd.DataFrame(rows, columns=["ts", "source", "location"])


def evaluation_days(periods: Periods) -> float:
    """Length of the evaluation period in days: the denominator of every per-day rate."""
    return (periods.eval_end - periods.eval_start).total_seconds() / 86400


def in_evaluation(alerts: pd.DataFrame, periods: Periods) -> pd.DataFrame:
    """Keep the alerts inside the evaluation period."""
    return alerts[(alerts["ts"] >= periods.eval_start) & (alerts["ts"] < periods.eval_end)]


def alert_rates(alerts: pd.DataFrame, periods: Periods) -> pd.DataFrame:
    """Count evaluation-period alerts, in total, per source and without the mirrored files.

    Returns:
        One row per scope: `alerts` and `alerts_per_day`.
    """
    selected = in_evaluation(alerts, periods)
    counts = {"all raw alerts": len(selected)}
    mirrored = selected["location"].isin(MIRRORED_LOCATIONS)
    counts["without mirrored files"] = int((~mirrored).sum())
    for source, group in selected.groupby("source"):
        counts[f"{source} only"] = len(group)
    table = pd.DataFrame({"alerts": counts}).rename_axis("scope").reset_index()
    table["alerts_per_day"] = table["alerts"] / evaluation_days(periods)
    return table


def daily_alerts(alerts: pd.DataFrame, periods: Periods) -> pd.DataFrame:
    """Count evaluation-period alerts per UTC day and source. Edge days can be partial."""
    selected = in_evaluation(alerts, periods)
    days = selected["ts"].dt.strftime("%Y-%m-%d")
    table = selected.groupby([days, "source"]).size().unstack(fill_value=0)
    table["total"] = table.sum(axis=1)
    return table.rename_axis("day")


# Plan 10.5: incidents per day must be at least this much fewer than raw IDS alerts.
REQUIRED_REDUCTION = 0.9


@dataclass(frozen=True)
class BudgetCheck:
    """Whether an incidents/day budget can meet the alert reduction target."""

    alerts_per_day: float
    budget: int
    required_reduction: float

    @property
    def largest_budget(self) -> int:
        """The most incidents/day that still reach the required reduction."""
        # Rounded first: 1 - 0.9 is 0.0999... in floating point.
        return int(round(self.alerts_per_day * (1 - self.required_reduction), 9))

    @property
    def reduction_at_budget(self) -> float:
        """Reduction reached if incidents/day equal the budget."""
        return 1 - self.budget / self.alerts_per_day

    @property
    def feasible(self) -> bool:
        """True if the budget reaches the required reduction."""
        return self.budget <= self.largest_budget


def budget_table(rates: pd.DataFrame, budget: int) -> pd.DataFrame:
    """Check a budget against each row of `alert_rates`."""
    checks = [
        BudgetCheck(float(rate), budget, REQUIRED_REDUCTION) for rate in rates["alerts_per_day"]
    ]
    table = rates.copy()
    table["largest_budget"] = [check.largest_budget for check in checks]
    table["reduction_at_budget"] = [check.reduction_at_budget for check in checks]
    table["feasible"] = [check.feasible for check in checks]
    return table

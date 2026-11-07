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
ALERT_SOURCES = ("wazuh", "suricata", "aminer")


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
        One row per alert: `ts` (UTC), `source` (`wazuh`, `suricata`, `aminer`), `location` (the
        log file, for Wazuh alerts), `host` (the address of the reporting host: `agent.name` is
        the same on every alert) and `texts` (the log lines behind the alert, if any).
    """
    rows: list[tuple[datetime, str, str | None, str | None, tuple[str, ...]]] = []
    with (directory / f"{testbed}_wazuh.json").open(encoding="utf-8") as handle:
        for line in handle:
            alert = json.loads(line)
            ts = datetime.fromisoformat(alert["@timestamp"].replace("Z", "+00:00"))
            host = alert.get("agent", {}).get("ip")
            text = alert.get("full_log")
            texts = (text,) if text else ()
            rows.append((ts, wazuh_source(alert), alert.get("location"), host, texts))
    with (directory / f"{testbed}_aminer.json").open(encoding="utf-8") as handle:
        for line in handle:
            alert = json.loads(line)
            data = alert["LogData"]
            ts = datetime.fromtimestamp(float(data["Timestamps"][0]), tz=UTC)
            host = alert.get("AMiner", {}).get("ID")
            rows.append((ts, "aminer", None, host, tuple(data.get("RawLogData", ()))))
    return pd.DataFrame(rows, columns=["ts", "source", "location", "host", "texts"])


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


def group_alerts(alerts: pd.DataFrame, gap_minutes: int) -> pd.Series:
    """Group alerts with the gap rule of plan 6.6, with the host as the only entity (plan 10.2).

    Two alerts link if they are at most `gap_minutes` apart and come from the same host. Only
    neighbours in time need checking: anything closer lies between them.

    Args:
        alerts: Alerts with `ts` and `host`.
        gap_minutes: Largest gap between linked alerts.

    Returns:
        The group number of each alert.

    Raises:
        ValueError: If an alert has no host, as it could not be grouped.
    """
    if alerts["host"].isna().any():
        raise ValueError("every alert needs a host to be grouped")
    ordered = alerts.sort_values(["host", "ts"], kind="stable")
    new_host = ordered["host"].ne(ordered["host"].shift())
    too_far = ordered["ts"].diff() > pd.Timedelta(minutes=gap_minutes)
    return (new_host | too_far).cumsum().reindex(alerts.index)


def event_phases(alerts: pd.DataFrame, labeled: pd.DataFrame) -> pd.DataFrame:
    """Give alerts the event-based label: the phases of the labeled lines they quote.

    AIT-ADS has no label per alert, so this one is derived from the log text an alert carries.
    Alerts without such text, as all Suricata alerts, carry no event-based label.

    Args:
        alerts: Alerts with a unique index, `source` and `texts`.
        labeled: Labeled lines of the period: `raw` and `phase`.

    Returns:
        One row per alert and phase: `alert` (its index), `source` and `phase`.
    """
    texts = alerts["texts"].explode().dropna()
    quoted = pd.DataFrame({"alert": texts.index, "raw": texts.to_numpy()})
    found = quoted.merge(labeled[["raw", "phase"]].drop_duplicates(), on="raw")
    found = found[["alert", "phase"]].drop_duplicates()
    return found.assign(source=alerts.loc[found["alert"], "source"].to_numpy())


def time_phases(alerts: pd.DataFrame, intervals: pd.DataFrame) -> pd.DataFrame:
    """Give alerts the time-based label: the phases whose interval holds them.

    Args:
        alerts: Alerts with a unique index, `ts` and `source`.
        intervals: Rows of the phases file: `phase`, `start_utc` and `end_utc`.

    Returns:
        One row per alert and phase: `alert` (its index), `source` and `phase`.
    """
    parts = []
    for row in intervals.itertuples():
        inside = alerts[(alerts["ts"] >= row.start_utc) & (alerts["ts"] <= row.end_utc)]
        parts.append(pd.DataFrame({"alert": inside.index, "source": inside["source"].to_numpy()}))
        parts[-1]["phase"] = row.phase
    return pd.concat(parts, ignore_index=True)


def ids_phase_table(event: pd.DataFrame, timed: pd.DataFrame, phases: list[str]) -> pd.DataFrame:
    """Count the alerts of each phase, by label and source (plan 10.3).

    Args:
        event: Output of `event_phases`.
        timed: Output of `time_phases`.
        phases: The phases to list, in order.

    Returns:
        One row per phase: `event_alerts`, `event_<source>` and `time_alerts`.
    """
    table = pd.DataFrame(index=pd.Index(phases, name="phase"))
    table["event_alerts"] = event.groupby("phase").size().reindex(phases, fill_value=0)
    for source in ALERT_SOURCES:
        part = event[event["source"] == source]
        table[f"event_{source}"] = part.groupby("phase").size().reindex(phases, fill_value=0)
    table["time_alerts"] = timed.groupby("phase").size().reindex(phases, fill_value=0)
    return table


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

"""What the dashboard reads (plan 9.1): `agent.duckdb` and saved reports, as plain tables."""

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb
import pandas as pd

from logtriage.agents.cache import LlmCache
from logtriage.agents.chat import ROLE as CHAT_ROLE
from logtriage.agents.runner import REPORTS_DIR, load_report, report_row
from logtriage.agents.schemas import IncidentReport
from logtriage.app.replay import closed_incidents, finished_windows
from logtriage.config import DEFAULT_CONFIG_PATH, DEV_TESTBED, Settings

ENV_TESTBED = "LOGTRIAGE_UI_TESTBED"
ENV_CONFIG = "LOGTRIAGE_UI_CONFIG"
ENV_LIVE = "LOGTRIAGE_UI_LIVE"
ATTACK_URL = "https://attack.mitre.org/techniques/"
NO_REPORT = "no report"
MONITORING_COLUMNS = (
    "incident_id", "verdict", "cost_usd", "latency_s", "tokens_in", "tokens_cached", "tokens_out",
    "llm_calls", "tool_calls", "verifier_rounds", "removed_claims",
)  # fmt: skip
TOTAL_COLUMNS = ("cost_usd", "latency_s", "tokens_in", "tokens_cached", "tokens_out", "llm_calls")


@dataclass(frozen=True)
class AppOptions:
    """What `logtriage app` passes to the Streamlit script."""

    testbed: str
    config: Path
    live: bool

    @classmethod
    def from_env(cls) -> "AppOptions":
        """Read the options. Streamlit owns the command line, so they travel in the environment."""
        return cls(
            testbed=os.environ.get(ENV_TESTBED, DEV_TESTBED),
            config=Path(os.environ.get(ENV_CONFIG, DEFAULT_CONFIG_PATH)),
            live=os.environ.get(ENV_LIVE) == "1",
        )

    def to_env(self) -> dict[str, str]:
        """Return the options as environment variables."""
        return {
            ENV_TESTBED: self.testbed,
            ENV_CONFIG: str(self.config),
            ENV_LIVE: "1" if self.live else "0",
        }


@dataclass(frozen=True)
class Dataset:
    """Incidents and scored windows of a testbed."""

    incidents: pd.DataFrame
    scores: pd.DataFrame


@dataclass(frozen=True)
class View:
    """What the dashboard may show at one simulated time."""

    moment: datetime
    incidents: pd.DataFrame
    windows: pd.DataFrame
    reports: dict[str, IncidentReport]


def database_path(settings: Settings, testbed: str) -> Path:
    """Return the path of `agent.duckdb`."""
    return Path(settings.paths.processed_dir) / testbed / "agent.duckdb"


def reports_path(settings: Settings, testbed: str) -> Path:
    """Return the directory of the saved reports."""
    return Path(settings.paths.processed_dir) / testbed / REPORTS_DIR


def load_dataset(connection: duckdb.DuckDBPyConnection) -> Dataset:
    """Read incidents and scores from the locked connection, by named columns."""
    incidents = connection.execute(
        """
        SELECT incident_id, start, "end", hosts, log_types, src_ips, users, n_windows, max_score,
               mean_score, priority
        FROM incidents ORDER BY start, incident_id
        """
    ).df()
    scores = connection.execute(
        """
        SELECT host, log_type, window_start, score, is_anomalous, incident_id
        FROM scores ORDER BY window_start, host, log_type
        """
    ).df()
    return Dataset(incidents, scores)


def load_reports(reports_dir: Path, incident_ids: list[str]) -> dict[str, IncidentReport]:
    """Return the saved reports of some incidents. A report of any other incident stays unread."""
    found = {item: load_report(reports_dir, item) for item in incident_ids}
    return {item: report for item, report in found.items() if report is not None}


def build_view(dataset: Dataset, reports_dir: Path, moment: datetime, window_seconds: int) -> View:
    """Return what is visible at a simulated time: reports appear when their incident closes.

    Args:
        dataset: Incidents and windows.
        reports_dir: Directory of the saved reports.
        moment: Simulated time.
        window_seconds: Window length.

    Returns:
        The view.
    """
    incidents = closed_incidents(dataset.incidents, moment)
    reports = load_reports(reports_dir, incidents["incident_id"].tolist())
    return View(
        moment, incidents, finished_windows(dataset.scores, moment, window_seconds), reports
    )


def incident_table(incidents: pd.DataFrame, reports: dict[str, IncidentReport]) -> pd.DataFrame:
    """Return the table of the Incidents page, by priority (plan 9.1)."""
    ordered = incidents.sort_values(["priority", "start"], ascending=[False, True])
    rows = [
        {
            "incident": row.incident_id,
            "start": row.start,
            "end": row.end,
            "hosts": ", ".join(row.hosts),
            "log types": ", ".join(row.log_types),
            "score": row.max_score,
            "priority": row.priority,
            "verdict": reports[row.incident_id].verdict
            if row.incident_id in reports
            else NO_REPORT,
            "confidence": (
                reports[row.incident_id].confidence if row.incident_id in reports else None
            ),
        }
        for row in ordered.itertuples()
    ]
    return pd.DataFrame(rows)


def monitoring_table(reports: dict[str, IncidentReport]) -> pd.DataFrame:
    """Return one row of run figures per report (plan 9.1)."""
    rows = [report_row(report) for _, report in sorted(reports.items())]
    return pd.DataFrame(rows, columns=list(MONITORING_COLUMNS))


def monitoring_totals(table: pd.DataFrame) -> dict[str, float]:
    """Return the sums of the figures that add up."""
    return {column: float(table[column].sum()) for column in TOTAL_COLUMNS}


def ledger_spend(settings: Settings) -> dict[str, float]:
    """Return what was really paid, from the ledger: everything, and the chat alone."""
    cache = LlmCache(Path(settings.paths.cache_dir) / "llm.sqlite")
    try:
        return {"total": cache.total_spend(), "chat": cache.role_spend(CHAT_ROLE)}
    finally:
        cache.close()


def technique_url(technique_id: str) -> str:
    """Return the attack.mitre.org page of a technique; a sub-technique is a sub-path."""
    return f"{ATTACK_URL}{technique_id.replace('.', '/')}/"


def evidence_by_eid(report: IncidentReport) -> dict[str, Any]:
    """Return the evidence of a report by eid."""
    return {item.eid: item for item in report.evidence}

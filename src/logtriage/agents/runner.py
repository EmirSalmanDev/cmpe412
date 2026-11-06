"""The queue of the graph (plan 7.2): incidents by priority, one report each."""

import csv
import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import openai

from logtriage.agents.cache import LlmCache
from logtriage.agents.graph import AgentRuntime, IncidentState, build_graph
from logtriage.agents.llm import (
    BudgetExceededError,
    ChatBackend,
    LLMClient,
    LLMOutputError,
    build_chat_model,
)
from logtriage.agents.prompting import Prompt, load_prompts
from logtriage.agents.schemas import IncidentReport, report_claims
from logtriage.agents.tools import AgentTools
from logtriage.config import TEST_TESTBED, Settings

logger = logging.getLogger(__name__)

REPORTS_DIR = "reports"
RUN_FILE = "run_summary.json"
RECURSION_LIMIT = 50
ROW_FIELDS = (
    "incident_id", "verdict", "confidence", "claims", "summary_claims", "timeline_claims",
    "technique_claims", "removed_claims", "draft_claims", "draft_unknown_eid_claims",
    "verifier_rounds", "evidence_lines", "tool_calls", "techniques", "llm_calls", "retries",
    "tokens_in", "tokens_cached", "tokens_out", "cost_usd", "latency_s",
)  # fmt: skip


@dataclass
class RunSummary:
    """Outcome of one run."""

    testbed: str
    run: str
    finished: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    aborted: str | None = None
    spent_usd: float = 0.0
    total_spent_usd: float = 0.0
    rerun_reason: str | None = None


def run_name(settings: Settings, prompts: dict[str, Prompt]) -> str:
    """Name a run by its condition and prompts, so that runs never share incident memory."""
    condition = "-".join(f"{key}{int(on)}" for key, on in settings.agents.condition.items())
    versions = ",".join(sorted(prompt.version for prompt in prompts.values()))
    return f"{condition}-{hashlib.sha256(versions.encode()).hexdigest()[:8]}"


def incident_queue(tools: AgentTools) -> list[str]:
    """Return every incident, highest priority first."""
    rows = tools.connection.execute(
        "SELECT incident_id FROM incidents ORDER BY priority DESC, start, incident_id"
    ).fetchall()
    return [row[0] for row in rows]


def report_row(report: IncidentReport) -> dict[str, Any]:
    """Return the counts of a report for the run table."""
    meta = report.meta
    return {
        "incident_id": report.incident_id,
        "verdict": report.verdict,
        "confidence": report.confidence,
        "claims": len(report_claims(report)),
        "summary_claims": len(report.summary),
        "timeline_claims": len(report.timeline),
        "technique_claims": len(report.techniques),
        "removed_claims": len(report.unsupported_claims_removed),
        "draft_claims": meta["draft_claims"],
        "draft_unknown_eid_claims": meta["draft_unknown_eid_claims"],
        "verifier_rounds": report.verifier_rounds,
        "evidence_lines": len(report.evidence),
        "tool_calls": len(meta["tool_calls"]),
        "techniques": " ".join(item.technique_id for item in report.techniques),
        "llm_calls": meta["llm_calls"],
        "retries": meta["retries"],
        "tokens_in": meta["tokens_in"],
        "tokens_cached": meta["tokens_cached"],
        "tokens_out": meta["tokens_out"],
        "cost_usd": round(meta["cost_usd"], 6),
        "latency_s": round(meta["latency_s"], 2),
    }


def write_run_table(reports_dir: Path, path: Path) -> list[dict[str, Any]]:
    """Write one row per saved report.

    Args:
        reports_dir: Directory of the report files.
        path: The CSV to write.

    Returns:
        The rows, by incident.
    """
    rows = [
        report_row(IncidentReport.model_validate_json(item.read_text(encoding="utf-8")))
        for item in sorted(reports_dir.glob("*.json"))
        if item.name != RUN_FILE
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ROW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return rows


def check_test_run(
    testbed: str, settings: Settings, reports_dir: Path, rerun_reason: str | None
) -> None:
    """Allow a run on the test testbed only with frozen prompts, and once (status.md, M8).

    Raises:
        ValueError: If the prompts are not frozen, or the run would repeat without a reason.
    """
    if testbed != TEST_TESTBED:
        return
    if not settings.agents.prompts_frozen:
        raise ValueError(f"{testbed}: freeze the prompts first (agents.prompts_frozen)")
    if (reports_dir / RUN_FILE).exists() and not rerun_reason:
        raise ValueError(
            f"{testbed}: reports exist; a re-run needs --rerun-reason, logged in status"
        )


def run_incidents(
    testbed: str,
    settings: Settings,
    incident_ids: list[str] | None = None,
    use_cache: bool = True,
    rerun_reason: str | None = None,
    backend: ChatBackend | None = None,
    tools: AgentTools | None = None,
) -> RunSummary:
    """Investigate incidents, highest priority first.

    A failed incident is recorded and the queue goes on. A spending limit stops the run cleanly:
    every finished report stays saved and the unfinished incident leaves no file.

    Args:
        testbed: Testbed name.
        settings: Loaded settings.
        incident_ids: Only these incidents; all if None.
        use_cache: False bypasses reading the LLM cache.
        rerun_reason: Required to repeat a run on the test testbed.
        backend: Chat model; the configured one if None.
        tools: Agent tools; opened from the testbed if None.

    Returns:
        The outcome. `aborted` holds the reason if a limit stopped the run.
    """
    reports_dir = settings.paths.processed_dir / testbed / REPORTS_DIR
    check_test_run(testbed, settings, reports_dir, rerun_reason)
    prompts = load_prompts(settings.agents.few_shot)
    run = run_name(settings, prompts)
    owned = tools is None
    tools = tools or AgentTools.open(testbed, settings)
    tools.run = run
    cache = LlmCache(settings.paths.cache_dir / "llm.sqlite")
    client = LLMClient(
        backend or build_chat_model(settings),
        cache,
        settings.llm,
        settings.agents.condition,
        use_cache,
    )
    runtime = AgentRuntime(client, tools, settings, prompts, reports_dir, run)
    graph = build_graph(runtime)
    summary = RunSummary(testbed, run, rerun_reason=rerun_reason)
    try:
        if tools.attack is not None:
            # Load the embedding model now, so that it does not count as latency of one incident.
            tools.attack.search("warm up", 1)
        for incident_id in incident_ids or incident_queue(tools):
            logger.info("investigating %s", incident_id)
            try:
                graph.invoke(
                    IncidentState(incident_id=incident_id),
                    {"recursion_limit": RECURSION_LIMIT},
                )
            except BudgetExceededError as error:
                logger.error("stopped: %s", error)
                summary.aborted = str(error)
                break
            except (LLMOutputError, openai.APIError) as error:
                logger.error("%s failed: %s", incident_id, error)
                summary.failed[incident_id] = str(error)
                continue
            summary.finished.append(incident_id)
    finally:
        summary.spent_usd = client.run_spent
        summary.total_spent_usd = cache.total_spend()
        cache.close()
        if owned:
            tools.close()
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / RUN_FILE).write_text(json.dumps(asdict(summary), indent=2), encoding="utf-8")
    write_run_table(reports_dir, settings.paths.reports_dir / "results" / f"agents_{testbed}.csv")
    return summary

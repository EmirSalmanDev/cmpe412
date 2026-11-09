"""Ablations on santos (plan 10.4, D65): one run per condition, apart from the official outputs.

Each condition has its own ledger row, written before it starts, and it runs once, with no
override. Its reports, run table and incident memory live apart, so that nothing it writes can
reach the official reports, the official memory or the dashboard. `base` replays the saved run
from the cache with no key and a backend that refuses, so it cannot spend anything.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd
from langchain_core.messages import AIMessage, BaseMessage

from logtriage import guards
from logtriage.agents.cache import LlmCache
from logtriage.agents.llm import EXPECTED_FINGERPRINT
from logtriage.agents.runner import REPORTS_DIR, RUN_FILE, RunSummary, run_queue
from logtriage.agents.tools import AgentTools
from logtriage.config import Settings

ABLATION_TESTBED = "santos"
BASE = "base"
RETRY = guards.RETRY_SUFFIX
RECHECK = "recheck"
# Each row is a change of `agents`, in a copy of the settings in memory; the config stays as it is.
CONDITIONS: dict[str, dict[str, bool]] = {
    BASE: {},
    "verifier0": {"verifier": False},
    "rag0": {"rag": False},
    "few_shot1": {"few_shot": True},
}
# Far above the 0.04 USD estimated for one condition (m11_design.md 3a), so it only stops a fault.
MAX_USD_PER_CONDITION = 0.15
RESULTS_DIR = "results"
MEMORY_DIR = "memory"
LEDGER_FILE = "ledger.jsonl"
# What a replay cannot repeat: it pays nothing, and takes no time waiting for the model.
REPLAY_FIELDS = ("spent_usd", "cached_calls", "latency_s")


class RefusingBackend:
    """A chat model that fails if it is ever reached."""

    def invoke(self, messages: list[BaseMessage], **kwargs: Any) -> AIMessage:
        """Refuse every call."""
        raise RuntimeError("the replay reached the model")


@dataclass
class Ledger:
    """The paid calls in the cache file at one moment."""

    rows: int
    usd: float


def ledger_state(settings: Settings) -> Ledger:
    """Return the rows and the sum of the spending ledger."""
    cache = LlmCache(settings.paths.cache_dir / "llm.sqlite")
    try:
        rows = cache.connection.execute("SELECT count(*) FROM spend").fetchone()[0]
        return Ledger(rows, cache.total_spend())
    finally:
        cache.close()


def stage_name(condition: str) -> str:
    """Return the ledger stage of a condition."""
    return f"{guards.ABLATION}:{condition}"


def output_dir(settings: Settings, condition: str, testbed: str = ABLATION_TESTBED) -> Path:
    """Return the directory of a condition's reports, apart from `reports/` of the testbed."""
    return settings.paths.processed_dir / testbed / "ablations" / condition


def table_path(settings: Settings, condition: str) -> Path:
    """Return the run table of a condition."""
    return settings.paths.reports_dir / RESULTS_DIR / f"ablation_{condition}.csv"


def failed_at(target: Path) -> datetime:
    """Return when a run ended: the ledger file is written last, whatever happened."""
    return datetime.fromtimestamp((target / LEDGER_FILE).stat().st_mtime, UTC)


def condition_settings(settings: Settings, condition: str) -> Settings:
    """Return a copy of the settings with the switches of a condition."""
    agents = settings.agents.model_copy(update=CONDITIONS[condition])
    llm = settings.llm.model_copy(update={"max_usd_per_run": MAX_USD_PER_CONDITION})
    return settings.model_copy(update={"agents": agents, "llm": llm})


def check_ablation(
    condition: str,
    reason: str,
    settings: Settings,
    testbed: str = ABLATION_TESTBED,
    attempt: str | None = None,
) -> None:
    """Refuse an ablation that may not run (m11_design.md 3a).

    Args:
        condition: Name in `CONDITIONS`.
        reason: Why it runs; it goes in the ledger.
        settings: Loaded settings.
        testbed: Must be santos (plan 10.7).
        attempt: None for the one run, `RETRY` for the one retry, `RECHECK` for a second replay.

    Raises:
        ValueError: In the container whatever else holds (D53). Then on another testbed, an unknown
            condition, prompts that are not frozen, an empty reason, or a second run. A retry must
            also pass `guards.check_retry` (D69).
    """
    guards.check_container(testbed)
    if testbed != ABLATION_TESTBED:
        raise ValueError(f"{testbed}: ablations run on {ABLATION_TESTBED} only (plan 10.7)")
    if condition not in CONDITIONS:
        raise ValueError(f"unknown condition {condition}, choose from {sorted(CONDITIONS)}")
    if not settings.agents.prompts_frozen:
        raise ValueError(f"{testbed}: freeze the prompts first (agents.prompts_frozen)")
    if not reason.strip():
        raise ValueError("an ablation needs a reason")
    if attempt is None:
        guards.check_once(stage_name(condition), testbed, settings)
    elif attempt == RECHECK:
        if condition != BASE:
            raise ValueError("only the replay can be checked again: it cannot spend anything")
        guards.check_once(f"{stage_name(condition)}:{RECHECK}", testbed, settings)
    elif attempt == RETRY:
        target = output_dir(settings, condition, testbed)
        outputs = [*report_files(target), table_path(settings, condition)]
        guards.check_retry(stage_name(condition), testbed, settings, failed_at(target), outputs)
    else:
        raise ValueError(f"unknown attempt {attempt}")


def run_ablation(
    condition: str,
    reason: str,
    settings: Settings,
    testbed: str = ABLATION_TESTBED,
    backend: Any = None,
    tools: AgentTools | None = None,
    attempt: str | None = None,
) -> RunSummary:
    """Run one condition once.

    Args:
        condition: Name in `CONDITIONS`.
        reason: Why it runs; it goes in the ledger.
        settings: Loaded settings.
        testbed: Must be santos.
        backend: Chat model; the configured one if None. `base` always refuses.
        tools: Agent tools; opened here, with a memory of the condition's own, if None.
        attempt: None for the one run, `RETRY` for the one retry after an API failure, `RECHECK`
            to replay `base` again into a directory of its own (D69).

    Returns:
        The outcome of the run.

    Raises:
        CacheMissError: If `base` cannot be replayed. It costs nothing, and the saved reports
            then stand as the Verifier-on condition.
    """
    check_ablation(condition, reason, settings, testbed, attempt)
    stage = stage_name(condition) if attempt is None else f"{stage_name(condition)}:{attempt}"
    guards.record_stage(stage, testbed, settings, reason)
    name = f"{condition}_{RECHECK}" if attempt == RECHECK else condition
    target = output_dir(settings, name, testbed)
    target.mkdir(parents=True, exist_ok=True)
    changed = condition_settings(settings, condition)
    before = ledger_state(settings)
    owned = tools is None
    tools = tools or AgentTools.open(testbed, changed, memory_dir=target / MEMORY_DIR)
    replay = condition == BASE
    try:
        summary = run_queue(
            testbed,
            changed,
            target,
            table_path(settings, name),
            backend=RefusingBackend() if replay else backend,
            tools=tools,
            cache_only=replay,
            expected_fingerprint=None if replay else EXPECTED_FINGERPRINT,
            stop_on_failure=True,
        )
    finally:
        if owned:
            tools.close()
        after = ledger_state(settings)
        with (target / LEDGER_FILE).open("a", encoding="utf-8") as handle:
            state = {"stage": stage, "before": asdict(before), "after": asdict(after)}
            handle.write(json.dumps(state) + "\n")
    return summary


def report_files(directory: Path) -> list[Path]:
    """Return the report files of a directory, without the run summary."""
    return [path for path in sorted(directory.glob("*.json")) if path.name != RUN_FILE]


def comparable(report: dict[str, Any]) -> dict[str, Any]:
    """Return a report without the fields a replay cannot repeat."""
    meta = {key: value for key, value in report["meta"].items() if key not in REPLAY_FIELDS}
    return {**report, "meta": meta}


def replay_proof(
    settings: Settings, testbed: str = ABLATION_TESTBED, name: str = BASE
) -> pd.DataFrame:
    """Compare a replay with the official reports (m11_design.md 3a).

    Args:
        settings: Loaded settings.
        testbed: Santos.
        name: `base`, or `base_recheck` for the replay after the D69 fix.

    Returns:
        One row per official report, with the checks of the proof. A report the replay does not
        have is a row with `replayed` False.
    """
    official_dir = settings.paths.processed_dir / testbed / REPORTS_DIR
    replay_dir = output_dir(settings, name, testbed)
    rows = []
    for path in report_files(official_dir):
        twin = replay_dir / path.name
        saved = json.loads(path.read_text(encoding="utf-8"))
        row: dict[str, Any] = {
            "replay": name,
            "incident_id": path.stem,
            "official_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "replayed": twin.is_file(),
        }
        if twin.is_file():
            replayed = json.loads(twin.read_text(encoding="utf-8"))
            meta = replayed["meta"]
            row |= {
                "llm_calls": meta["llm_calls"],
                "cached_calls": meta["cached_calls"],
                "spent_usd": meta["spent_usd"],
                "identical": comparable(saved) == comparable(replayed),
            }
        rows.append(row)
    return pd.DataFrame(rows)


def condition_reports(settings: Settings, condition: str) -> dict[str, dict[str, Any]]:
    """Return the reports of a condition by incident; `base` means the official ones."""
    directory = (
        settings.paths.processed_dir / ABLATION_TESTBED / REPORTS_DIR
        if condition == BASE
        else output_dir(settings, condition)
    )
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8")) for path in report_files(directory)
    }

"""Agent graph (plan 7.2): a deterministic LangGraph over LLM roles with validated outputs."""

import json
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

from logtriage.agents.llm import LLMClient, LLMOutputError, parse_answer, retry_message
from logtriage.agents.prompting import Prompt, wrap_untrusted
from logtriage.agents.schemas import (
    Claim,
    Evidence,
    IncidentReport,
    InvestigatorOutput,
    MapperOutput,
    ReportDraft,
    TechniqueChoice,
    TimelineItem,
    UnsupportedClaim,
    UtcTime,
    VerifierOutput,
    draft_claims,
)
from logtriage.agents.tools import AgentTools, ToolResult
from logtriage.config import Settings

TOOL_NAMES = ("log_search", "run_sql", "ip_profile", "attack_search", "similar_incidents")
NO_EID = "not citable"
UNKNOWN_EID = "cites an evidence id that does not exist"
LIMIT_REACHED = "The tool call limit is reached. Give your final json answer now."


class WindowScore(BaseModel):
    """One scored window of an incident. These fields are all the model sees of a window."""

    host: str
    log_type: str
    window_start: UtcTime
    score: float
    pct_if: float
    pct_lof: float
    pct_pca: float


class IncidentContext(BaseModel):
    """The Investigator's starting point: incident metadata and window scores, nothing else."""

    incident_id: str
    start: UtcTime
    end: UtcTime
    hosts: list[str]
    log_types: list[str]
    src_ips: list[str]
    users: list[str]
    n_windows: int
    max_score: float
    mean_score: float
    priority: float
    windows: list[WindowScore]
    windows_not_listed: int = 0


class IncidentState(BaseModel):
    """State of the graph (plan 7.2)."""

    incident_id: str
    incident: IncidentContext | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    tool_log: list[dict[str, Any]] = Field(default_factory=list)
    behavior_summary: str = ""
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    techniques: list[TechniqueChoice] = Field(default_factory=list)
    draft: ReportDraft | None = None
    first_draft: dict[str, int] = Field(default_factory=dict)
    feedback: list[UnsupportedClaim] = Field(default_factory=list)
    round: int = 0
    began: float = 0.0
    report: IncidentReport | None = None


@dataclass
class AgentRuntime:
    """What the nodes need besides the state."""

    client: LLMClient
    tools: AgentTools
    settings: Settings
    prompts: dict[str, Prompt]
    reports_dir: Path
    run: str


def load_context(
    connection: duckdb.DuckDBPyConnection, incident_id: str, limit: int
) -> IncidentContext:
    """Read an incident and its window scores with plain code, outside the LLM.

    Args:
        connection: The locked agent connection.
        incident_id: The incident.
        limit: Most windows listed, highest scores first.

    Returns:
        The context, built from named columns only.

    Raises:
        KeyError: If the incident does not exist.
    """
    columns = (
        'incident_id, start, "end", hosts, log_types, src_ips, users, n_windows, '
        "max_score, mean_score, priority"
    )
    found = connection.execute(
        f"SELECT {columns} FROM incidents WHERE incident_id = ?", [incident_id]
    ).fetchone()
    if found is None:
        raise KeyError(incident_id)
    names = [item.strip().strip('"') for item in columns.split(",")]
    windows = connection.execute(
        """
        SELECT host, log_type, window_start, score, pct_if, pct_lof, pct_pca FROM scores
        WHERE incident_id = ? ORDER BY score DESC, window_start, host, log_type
        """,
        [incident_id],
    ).fetchall()
    keys = list(WindowScore.model_fields)
    return IncidentContext(
        **dict(zip(names, found, strict=True)),
        windows=[WindowScore(**dict(zip(keys, row, strict=True))) for row in windows[:limit]],
        windows_not_listed=max(0, len(windows) - limit),
    )


class EvidenceRegistry:
    """Gives every line shown to the LLM a short eid. Code alone knows the `line_id` (plan 5.7)."""

    def __init__(self, connection: duckdb.DuckDBPyConnection, chars: int, first: int = 1) -> None:
        self.connection = connection
        self.chars = chars
        self.next_number = first
        self.eids: dict[str, str] = {}
        self.rows: dict[str, dict[str, Any]] = {}

    def register(self, line_ids: Sequence[Any]) -> None:
        """Give an eid to each new line that has a reliable time (D14)."""
        new = [
            item
            for item in dict.fromkeys(line_ids)
            if isinstance(item, str) and item not in self.eids
        ]
        if not new:
            return
        marks = ", ".join("?" for _ in new)
        found = self.connection.execute(
            f"SELECT line_id, ts, host, log_type, raw FROM lines "
            f"WHERE parse_ok AND line_id IN ({marks})",
            new,
        ).fetchall()
        rows = {row[0]: row for row in found}
        for line_id in new:
            if line_id in rows:
                eid = f"E{self.next_number}"
                self.next_number += 1
                self.eids[line_id] = eid
                _, ts, host, log_type, raw = rows[line_id]
                self.rows[eid] = {
                    "eid": eid,
                    "line_id": line_id,
                    "ts": ts,
                    "host": host,
                    "log_type": log_type,
                    "raw": raw[: self.chars],
                }

    def show(self, result: ToolResult) -> str:
        """Register the lines of a tool result and put eids in place of their line_ids."""
        self.register(result.line_ids)
        ids = sorted({item for item in result.line_ids if isinstance(item, str)}, key=len)
        if not ids:
            return result.text
        pattern = "|".join(re.escape(item) for item in reversed(ids))
        return re.sub(
            f"(?:{pattern})(?!\\d)",
            lambda match: self.eids.get(match.group(0), NO_EID),
            result.text,
        )

    def evidence(self, eid: str, note: str) -> Evidence:
        """Return the evidence of a registered eid."""
        return Evidence(**self.rows[eid], note=note)


def tool_schemas(tools: AgentTools, rag: bool) -> list[dict[str, Any]]:
    """Return the tool schemas. Without RAG the Investigator loses `attack_search` too."""
    names = [name for name in TOOL_NAMES if rag or name != "attack_search"]
    return [convert_to_openai_tool(getattr(tools, name)) for name in names]


def run_tool(tools: AgentTools, call: dict[str, Any], allowed: set[str]) -> ToolResult:
    """Run one tool call. A bad call becomes an error text for the model."""
    name = call["name"]
    if name not in allowed:
        return ToolResult(f"error: unknown tool {name}")
    try:
        return getattr(tools, name)(**call["args"])
    except (TypeError, ValueError, duckdb.Error) as error:
        return ToolResult(f"error: bad arguments for {name}: {error}")


def evidence_lines(items: list[Evidence], notes: bool = True) -> str:
    """Render evidence, one line each."""
    rows = []
    for item in items:
        note = f" | note: {item.note}" if notes else ""
        rows.append(
            f"{item.eid} | {item.ts:%Y-%m-%d %H:%M:%S} | {item.host} | "
            f"{item.log_type} | {item.raw}{note}"
        )
    return "\n".join(rows)


def _investigator_check(
    registry: EvidenceRegistry, searched: bool, limit: int
) -> Callable[[InvestigatorOutput], None]:
    """Return the rules of the Investigator's final answer (plan 7.2, 7.4)."""

    def check(answer: InvestigatorOutput) -> None:
        if not searched:
            raise ValueError("call log_search at least once before the final answer")
        unknown = [pick.eid for pick in answer.evidence if pick.eid not in registry.rows]
        if unknown:
            raise ValueError(f"these eids were never shown in tool output: {unknown}")
        if len({pick.eid for pick in answer.evidence}) > limit:
            raise ValueError(f"select at most {limit} evidence lines")

    return check


def investigate(state: IncidentState, runtime: AgentRuntime) -> dict[str, Any]:
    """Run the ReAct loop of the Investigator (plan 7.4)."""
    client, tools, agents = runtime.client, runtime.tools, runtime.settings.agents
    schemas = tool_schemas(tools, agents.rag)
    allowed = {schema["function"]["name"] for schema in schemas}
    registry = EvidenceRegistry(tools.connection, agents.evidence_chars)
    conversation: list[BaseMessage] = [
        SystemMessage(runtime.prompts["investigator"].text),
        HumanMessage(
            "Incident to investigate:\n" + wrap_untrusted(state.incident.model_dump_json(indent=1))
        ),
    ]
    tool_log: list[dict[str, Any]] = []
    retries = 0
    while True:
        can_call = len(tool_log) < agents.max_tool_calls
        reply = client.chat(
            "investigator", conversation, tools=schemas if can_call else None, json_mode=True
        )
        conversation.append(reply)
        if reply.tool_calls:
            for call in reply.tool_calls:
                if len(tool_log) >= agents.max_tool_calls:
                    text = LIMIT_REACHED
                else:
                    result = run_tool(tools, call, allowed)
                    shown = registry.show(result)
                    tool_log.append(
                        {"tool": call["name"], "args": call["args"], "chars": len(shown)}
                    )
                    text = wrap_untrusted(shown)
                conversation.append(ToolMessage(text, tool_call_id=call["id"]))
            if len(tool_log) >= agents.max_tool_calls:
                conversation.append(HumanMessage(LIMIT_REACHED))
            continue
        searched = any(item["tool"] == "log_search" for item in tool_log)
        check = _investigator_check(registry, searched, agents.max_evidence)
        try:
            answer = parse_answer(reply, InvestigatorOutput, check)
        except ValueError as error:
            if retries >= runtime.settings.llm.json_retries:
                raise LLMOutputError(f"investigator: no valid answer: {error}") from error
            retries += 1
            client.tally.retries += 1
            conversation.append(retry_message(error))
            continue
        picks = {pick.eid: pick.note for pick in answer.evidence}
        return {
            "evidence": [registry.evidence(eid, note) for eid, note in picks.items()],
            "behavior_summary": answer.behavior_summary,
            "tool_log": tool_log,
        }


def _name_of(tools: AgentTools, technique_id: str) -> str:
    """Return the name of a technique in the index."""
    if tools.attack is None:
        return "unknown"
    return tools.attack.entries.get(technique_id, {}).get("name", "unknown")


def map_techniques(state: IncidentState, runtime: AgentRuntime) -> dict[str, Any]:
    """Retrieve candidates by code, then let one LLM call pick at most three (plan 7.4)."""
    tools, agents = runtime.tools, runtime.settings.agents
    candidates: list[dict[str, Any]] = []
    prompt = runtime.prompts["mapper"]
    data = (
        "Behavior summary:\n"
        + wrap_untrusted(state.behavior_summary)
        + "\n\nEvidence:\n"
        + wrap_untrusted(evidence_lines(state.evidence))
    )
    if agents.rag:
        hits = tools.attack.search(state.behavior_summary, agents.mapper_k)
        candidates = [
            {
                "id": hit["id"],
                "name": hit["name"],
                "tactics": hit["tactics"],
                "document": hit["document"][: agents.candidate_chars],
            }
            for hit in hits
        ]
        listing = "\n".join(f"- [{hit['tactics']}] {hit['document']}" for hit in candidates)
        data += f"\n\nCandidate techniques:\n{listing}"
    else:
        prompt = runtime.prompts["mapper_no_rag"]
    allowed = {hit["id"] for hit in candidates}

    def check(answer: MapperOutput) -> None:
        outside = [p.technique_id for p in answer.techniques if p.technique_id not in allowed]
        if agents.rag and outside:
            raise ValueError(f"these techniques are not in the candidate list: {outside}")

    messages = [SystemMessage(prompt.text), HumanMessage(data)]
    answer = runtime.client.structured("mapper", messages, MapperOutput, check)
    picks = list({pick.technique_id: pick for pick in answer.techniques}.values())
    return {
        "candidates": candidates,
        "techniques": [
            TechniqueChoice(
                technique_id=pick.technique_id,
                name=_name_of(tools, pick.technique_id),
                justification=pick.justification,
            )
            for pick in picks[: agents.max_techniques]
        ],
    }


def _reporter_input(state: IncidentState) -> str:
    """Render the data of the Reporter, and the review of the last draft if there is one."""
    mapped = [item.model_dump(mode="json") for item in state.techniques]
    data = (
        "Incident:\n"
        + wrap_untrusted(state.incident.model_dump_json(indent=1))
        + "\n\nBehavior summary:\n"
        + wrap_untrusted(state.behavior_summary)
        + "\n\nEvidence list:\n"
        + wrap_untrusted(evidence_lines(state.evidence))
        + "\n\nMapped techniques:\n"
        + wrap_untrusted(json.dumps(mapped, indent=1))
    )
    if state.feedback:
        reviews = [item.model_dump() for item in state.feedback]
        data += (
            "\n\nYour last draft:\n"
            + wrap_untrusted(state.draft.model_dump_json(indent=1))
            + "\n\nUnsupported claims to fix or remove:\n"
            + wrap_untrusted(json.dumps(reviews, indent=1))
        )
    return data


def known_eids(state: IncidentState) -> set[str]:
    """Return the eids a claim may cite: the evidence given to the Reporter (plan 7.4)."""
    return {item.eid for item in state.evidence}


def cites_unknown(claim: Claim, known: set[str]) -> bool:
    """Return True if a claim cites an eid outside the evidence."""
    return any(eid not in known for eid in claim.evidence)


def report(state: IncidentState, runtime: AgentRuntime) -> dict[str, Any]:
    """Write a draft, or rewrite it after a review (plan 7.4)."""
    mapped = {item.technique_id for item in state.techniques}
    rewrite = bool(state.feedback)

    def check(answer: ReportDraft) -> None:
        ids = [pick.technique_id for pick in answer.techniques]
        added = sorted(set(ids) - mapped)
        if added:
            raise ValueError(f"these techniques were not mapped: {added}")
        if not rewrite and set(ids) != mapped:
            raise ValueError(f"keep every mapped technique: {sorted(mapped - set(ids))}")

    messages = [
        SystemMessage(runtime.prompts["reporter"].text),
        HumanMessage(_reporter_input(state)),
    ]
    draft = runtime.client.structured("reporter", messages, ReportDraft, check)
    update: dict[str, Any] = {"draft": draft, "feedback": []}
    if rewrite:
        update["round"] = state.round + 1
    else:
        known = known_eids(state)
        claims = [claim for _, claim, _ in draft_claims(draft)]
        update["first_draft"] = {
            "claims": len(claims),
            "unknown_eid_claims": sum(cites_unknown(claim, known) for claim in claims),
        }
    return update


def verifier_request(
    draft: ReportDraft, evidence: list[Evidence], prompt: Prompt
) -> tuple[list[BaseMessage], dict[str, tuple[str, str, Claim]], list[UnsupportedClaim]]:
    """Build the Verifier's request for a draft (plan 7.4).

    Args:
        draft: The draft.
        evidence: The evidence given to the Reporter.
        prompt: The Verifier's prompt.

    Returns:
        The messages, empty if no claim is left to judge; the claims to judge by id, each with its
        key and text; and the claims that code rejects without a call.
    """
    known = {item.eid for item in evidence}
    by_eid = {item.eid: item for item in evidence}
    unsupported: list[UnsupportedClaim] = []
    to_judge: dict[str, tuple[str, str, Claim]] = {}
    for key, claim, text in draft_claims(draft):
        if cites_unknown(claim, known):
            unsupported.append(UnsupportedClaim(key=key, text=claim.text, reason=UNKNOWN_EID))
        else:
            to_judge[f"C{len(to_judge) + 1}"] = (key, text, claim)
    if not to_judge:
        return [], to_judge, unsupported
    blocks = [
        f"## {cid}\nClaim:\n{wrap_untrusted(text)}\nCited lines:\n"
        + wrap_untrusted(
            evidence_lines([by_eid[eid] for eid in dict.fromkeys(claim.evidence)], notes=False)
        )
        for cid, (_, text, claim) in to_judge.items()
    ]
    messages = [SystemMessage(prompt.text), HumanMessage("\n\n".join(blocks))]
    return messages, to_judge, unsupported


def verify(state: IncidentState, runtime: AgentRuntime) -> dict[str, Any]:
    """Check claims by code, then the rest in one LLM call (plan 7.4)."""
    messages, to_judge, unsupported = verifier_request(
        state.draft, state.evidence, runtime.prompts["verifier"]
    )
    if to_judge:

        def check(answer: VerifierOutput) -> None:
            missing = sorted(set(to_judge) - {item.id for item in answer.results})
            if missing:
                raise ValueError(f"judge every claim; missing: {missing}")

        answer = runtime.client.structured("verifier", messages, VerifierOutput, check)
        judged = {item.id: item for item in answer.results}
        for cid, (key, _, claim) in to_judge.items():
            if judged[cid].verdict == "unsupported":
                unsupported.append(
                    UnsupportedClaim(key=key, text=claim.text, reason=judged[cid].reason)
                )
    return {"feedback": unsupported}


def after_verifier(state: IncidentState, runtime: AgentRuntime) -> str:
    """Send unsupported claims back, at most `agents.max_rewrites` times (plan 7.2)."""
    if state.feedback and state.round < runtime.settings.agents.max_rewrites:
        return "reporter"
    return "finalize"


def _meta(state: IncidentState, runtime: AgentRuntime) -> dict[str, Any]:
    """Return the report meta (plan 5.7)."""
    settings = runtime.settings
    tally = runtime.client.tally
    latency = time.perf_counter() - state.began + tally.replayed_latency_s
    roles = {role: prompt.version for role, prompt in runtime.prompts.items()}
    if settings.agents.rag:
        roles.pop("mapper_no_rag", None)
    else:
        roles["mapper"] = roles.pop("mapper_no_rag")
    return {
        "model": settings.llm.model,
        "served_models": tally.served_models,
        "system_fingerprints": tally.fingerprints,
        "temperature": settings.llm.temperature,
        "thinking": settings.llm.thinking,
        "prompt_version": roles,
        "attack_version": settings.rag.attack_version,
        "run": runtime.run,
        **settings.agents.condition,
        "tokens_in": tally.tokens_in,
        "tokens_cached": tally.tokens_cached,
        "tokens_out": tally.tokens_out,
        "cost_usd": tally.cost_usd,
        "spent_usd": tally.spent_usd,
        "latency_s": latency,
        "llm_calls": tally.calls,
        "cached_calls": tally.cached_calls,
        "retries": tally.retries,
        "tool_calls": state.tool_log,
        "behavior_summary": state.behavior_summary,
        "retrieved_techniques": [hit["id"] for hit in state.candidates],
        "mapped_techniques": [item.technique_id for item in state.techniques],
        "draft_claims": state.first_draft["claims"],
        "draft_unknown_eid_claims": state.first_draft["unknown_eid_claims"],
    }


def finalize(state: IncidentState, runtime: AgentRuntime) -> dict[str, Any]:
    """Drop what stayed unsupported, then save the report and remember it (plan 7.2)."""
    draft = state.draft
    bad = {item.key for item in state.feedback}
    summary = [c for i, c in enumerate(draft.summary) if f"summary:{i}" not in bad]
    timeline: list[TimelineItem] = [
        item for i, item in enumerate(draft.timeline) if f"timeline:{i}" not in bad
    ]
    names = {item.technique_id: item.name for item in state.techniques}
    techniques = [
        TechniqueChoice(
            technique_id=pick.technique_id,
            name=names[pick.technique_id],
            justification=pick.justification,
        )
        for i, pick in enumerate(draft.techniques)
        if f"technique:{i}" not in bad
    ]
    verdict, confidence = draft.verdict, draft.confidence
    if not summary:
        verdict, confidence = "uncertain", min(confidence, 0.3)
    report_ = IncidentReport(
        incident_id=state.incident_id,
        summary=summary,
        timeline=sorted(timeline, key=lambda item: item.ts),
        techniques=techniques,
        verdict=verdict,
        confidence=confidence,
        recommended_actions=draft.recommended_actions,
        evidence=state.evidence,
        verifier_rounds=state.round,
        unsupported_claims_removed=[item.text for item in state.feedback],
        meta=_meta(state, runtime),
    )
    runtime.reports_dir.mkdir(parents=True, exist_ok=True)
    path = runtime.reports_dir / f"{state.incident_id}.json"
    path.write_text(report_.model_dump_json(indent=2), encoding="utf-8")
    store = runtime.tools.incidents
    if store is not None:
        store.add(
            report_.model_dump(mode="json"),
            runtime.tools.testbed,
            state.incident.start,
            runtime.run,
        )
    return {"report": report_}


def build_graph(runtime: AgentRuntime) -> Any:
    """Compile the graph of plan 7.2.

    Args:
        runtime: Client, tools, settings and prompts.

    Returns:
        The compiled graph; invoke it with an `IncidentState`.
    """

    def load_incident(state: IncidentState) -> dict[str, Any]:
        runtime.client.begin_incident()
        runtime.tools.before = None
        incident = load_context(
            runtime.tools.connection, state.incident_id, runtime.settings.agents.context_windows
        )
        runtime.tools.before = incident.start
        return {"incident": incident, "began": time.perf_counter()}

    graph = StateGraph(IncidentState)
    graph.add_node("load_incident", load_incident)
    graph.add_node("investigator", lambda state: investigate(state, runtime))
    graph.add_node("mapper", lambda state: map_techniques(state, runtime))
    graph.add_node("reporter", lambda state: report(state, runtime))
    graph.add_node("verifier", lambda state: verify(state, runtime))
    graph.add_node("finalize", lambda state: finalize(state, runtime))
    graph.add_edge(START, "load_incident")
    graph.add_edge("load_incident", "investigator")
    graph.add_edge("investigator", "mapper")
    graph.add_edge("mapper", "reporter")
    if runtime.settings.agents.verifier:
        graph.add_edge("reporter", "verifier")
        graph.add_conditional_edges(
            "verifier",
            lambda state: after_verifier(state, runtime),
            {"reporter": "reporter", "finalize": "finalize"},
        )
    else:
        graph.add_edge("reporter", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile()

"""Chat agent (plan 7.5): a ReAct loop on one incident, with its report in context.

Its calls go through `LLMClient`, so `create_react_agent`, which needs a chat model of its own, is
not used. Memory is a LangGraph checkpointer, one thread per incident. The chat writes no report and
nothing to the incident memory, so it is not a run of the agent graph (D47).
"""

import json
import operator
import re
import sqlite3
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langchain_core.messages import (
    AIMessage,
    AnyMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from logtriage.agents.cache import LlmCache
from logtriage.agents.graph import (
    LIMIT_REACHED,
    EvidenceRegistry,
    IncidentContext,
    evidence_lines,
    load_context,
    run_tool,
    tool_schemas,
)
from logtriage.agents.llm import (
    ChatBackend,
    LLMClient,
    build_chat_model,
    parse_answer,
    retry_message,
)
from logtriage.agents.prompting import Prompt, load_prompt, wrap_untrusted
from logtriage.agents.runner import REPORTS_DIR, load_report
from logtriage.agents.schemas import ChatAnswer, Claim, IncidentReport
from logtriage.agents.tools import AgentTools, ToolResult
from logtriage.config import Settings

ROLE = "chat"
PROMPT_NAME = "chat"
MEMORY_FILE = "chat.sqlite"
RECURSION_LIMIT = 60
NO_ANSWER = "No answer with valid citations came back, so none is shown. Please ask again."
REPORT_FIELDS = {
    "summary",
    "timeline",
    "techniques",
    "verdict",
    "confidence",
    "recommended_actions",
}
EID = re.compile(r"E(\d+)")


class ChatState(TypedDict, total=False):
    """State of a thread. Only plain data, so that the checkpointer can store it."""

    messages: Annotated[list[AnyMessage], add_messages]
    context: str
    question: str
    # Every citable line of the thread by eid: the report's, then those tools have shown.
    evidence: dict[str, dict[str, Any]]
    tool_log: list[dict[str, Any]]
    retries: int
    turns: Annotated[list[dict[str, Any]], operator.add]


def open_memory(settings: Settings) -> SqliteSaver:
    """Open the memory of the chat, `chat.sqlite` in the cache directory (plan 7.5).

    Args:
        settings: Loaded settings.

    Returns:
        The checkpointer. Streamlit calls it from several threads, so it allows that.
    """
    path = Path(settings.paths.cache_dir) / MEMORY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    return SqliteSaver(sqlite3.connect(str(path), check_same_thread=False))


def thread_config(incident_id: str) -> dict[str, Any]:
    """Return the graph config of an incident: one thread each (plan 7.5)."""
    return {"configurable": {"thread_id": incident_id}, "recursion_limit": RECURSION_LIMIT}


def thread_turns(saver: SqliteSaver, incident_id: str) -> list[dict[str, Any]]:
    """Return the finished turns of an incident, without needing the model or the tools."""
    found = saver.get_tuple(thread_config(incident_id))
    return [] if found is None else found.checkpoint["channel_values"].get("turns", [])


def report_context(report: IncidentReport, incident: IncidentContext) -> str:
    """Render what the model gets to know about an incident.

    Only named report fields pass: `meta` holds run data, and removed claims were found unsupported.

    Args:
        report: The current report.
        incident: Metadata and window scores of the incident.

    Returns:
        The first message of every request, all of it inside the data delimiters.
    """
    view = report.model_dump_json(include=REPORT_FIELDS, indent=1)
    return (
        "Incident:\n"
        + wrap_untrusted(incident.model_dump_json(indent=1))
        + "\n\nReport:\n"
        + wrap_untrusted(view)
        + "\n\nReport evidence:\n"
        + wrap_untrusted(evidence_lines(report.evidence))
    )


def seed_evidence(report: IncidentReport) -> dict[str, dict[str, Any]]:
    """Return the citable lines of a new thread: the report's, under the report's eids."""
    return {item.eid: item.model_dump(mode="json", exclude={"note"}) for item in report.evidence}


def registry_of(
    tools: AgentTools, chars: int, evidence: dict[str, dict[str, Any]]
) -> EvidenceRegistry:
    """Rebuild the registry of a thread. New lines number after the highest eid, as report eids
    have gaps, so that no eid ever changes its meaning.
    """
    numbers = [int(match.group(1)) for eid in evidence if (match := EID.fullmatch(eid))]
    registry = EvidenceRegistry(tools.connection, chars, first=max(numbers, default=0) + 1)
    registry.rows = dict(evidence)
    registry.eids = {row["line_id"]: eid for eid, row in evidence.items()}
    return registry


def stored_rows(registry: EvidenceRegistry) -> dict[str, dict[str, Any]]:
    """Return the lines of a registry as plain data."""
    return {
        eid: {**row, "ts": row["ts"] if isinstance(row["ts"], str) else row["ts"].isoformat()}
        for eid, row in registry.rows.items()
    }


def resolve(registry: EvidenceRegistry, citation: str) -> str | None:
    """Return the eid of a citation, an eid or a `line_id`; None if it names no citable line."""
    if citation in registry.rows:
        return citation
    registry.register([citation])
    return registry.eids.get(citation)


def citation_check(registry: EvidenceRegistry) -> Callable[[ChatAnswer], None]:
    """Return the rule of a final answer: every citation names a line of the thread."""

    def check(answer: ChatAnswer) -> None:
        cited = [item for claim in answer.claims for item in claim.evidence]
        unknown = [item for item in cited if resolve(registry, item) is None]
        if unknown:
            raise ValueError(f"these citations name no line you were shown: {unknown}")

    return check


def cited_claim(registry: EvidenceRegistry, claim: Claim) -> dict[str, Any]:
    """Return a claim with its citations resolved to real lines (plan 5.7)."""
    eids = dict.fromkeys(resolve(registry, item) for item in claim.evidence)
    return {"text": claim.text, "citations": [stored_rows(registry)[eid] for eid in eids]}


def complete_calls(messages: Sequence[BaseMessage]) -> list[BaseMessage]:
    """Drop tool calls without a reply, left by a crash, which the API would refuse for good."""
    answered = {message.tool_call_id for message in messages if isinstance(message, ToolMessage)}
    return [
        message
        for message in messages
        if not (
            isinstance(message, AIMessage)
            and any(call["id"] not in answered for call in message.tool_calls)
        )
    ]


class ChatAgent:
    """Answers questions on incidents of one testbed. One instance serves one turn at a time."""

    def __init__(
        self,
        tools: AgentTools,
        client: LLMClient,
        settings: Settings,
        saver: SqliteSaver,
        reports_dir: Path,
        prompt: Prompt | None = None,
    ) -> None:
        self.tools = tools
        self.client = client
        self.settings = settings
        self.saver = saver
        self.reports_dir = reports_dir
        self.prompt = prompt or load_prompt(PROMPT_NAME)
        self.schemas = tool_schemas(tools, settings.agents.rag)
        self.allowed = {schema["function"]["name"] for schema in self.schemas}
        self.lock = threading.Lock()
        self.graph = self._build_graph()

    @classmethod
    def open(
        cls,
        testbed: str,
        settings: Settings,
        tools: AgentTools | None = None,
        saver: SqliteSaver | None = None,
        backend: ChatBackend | None = None,
    ) -> "ChatAgent":
        """Open the chat of a testbed.

        Args:
            testbed: Testbed name.
            settings: Loaded settings.
            tools: Agent tools; opened from the testbed if None.
            saver: The memory; opened from the cache directory if None.
            backend: Chat model; the configured one if None.

        Returns:
            The agent. Its client lives as long as it does, so `llm.max_usd_per_run` covers all of
            its turns, and `llm.max_usd_total` covers them with every other run.
        """
        client = LLMClient(
            backend or build_chat_model(settings),
            LlmCache(Path(settings.paths.cache_dir) / "llm.sqlite"),
            settings.llm,
            settings.agents.condition,
        )
        return cls(
            tools or AgentTools.open(testbed, settings),
            client,
            settings,
            saver or open_memory(settings),
            Path(settings.paths.processed_dir) / testbed / REPORTS_DIR,
        )

    def _registry(self, state: ChatState) -> EvidenceRegistry:
        """Return the registry of a thread."""
        return registry_of(self.tools, self.settings.agents.evidence_chars, state["evidence"])

    def _turn(
        self, state: ChatState, claims: list[dict[str, Any]], remark: str, answered: bool
    ) -> dict[str, Any]:
        """Return the record of a finished turn."""
        tally = self.client.tally
        return {
            "question": state["question"],
            "claims": claims,
            "remark": remark,
            "answered": answered,
            "tools": [item["tool"] for item in state["tool_log"]],
            "llm_calls": tally.calls,
            "tokens_in": tally.tokens_in,
            "tokens_out": tally.tokens_out,
            "cost_usd": tally.cost_usd,
        }

    def _answer(self, state: ChatState) -> dict[str, Any]:
        """Ask the model for the next step: a tool call or the final answer."""
        request = [
            SystemMessage(self.prompt.text),
            HumanMessage(state["context"]),
            *complete_calls(state["messages"]),
        ]
        can_call = len(state["tool_log"]) < self.settings.agents.max_tool_calls
        reply = self.client.chat(
            ROLE, request, tools=self.schemas if can_call else None, json_mode=True
        )
        if reply.tool_calls:
            return {"messages": [reply]}
        registry = self._registry(state)
        try:
            answer = parse_answer(reply, ChatAnswer, citation_check(registry))
        except ValueError as error:
            if state["retries"] >= self.settings.llm.json_retries:
                closing = AIMessage(json.dumps({"claims": [], "remark": NO_ANSWER}))
                return {
                    "messages": [closing],
                    "turns": [self._turn(state, [], NO_ANSWER, answered=False)],
                }
            self.client.tally.retries += 1
            return {"messages": [reply, retry_message(error)], "retries": state["retries"] + 1}
        claims = [cited_claim(registry, claim) for claim in answer.claims]
        return {
            "messages": [reply],
            "evidence": stored_rows(registry),
            "turns": [self._turn(state, claims, answer.remark, answered=True)],
        }

    def _call_tool(self, call: dict[str, Any]) -> ToolResult:
        """Run a tool. A failure goes back to the model, so that no call stays without a reply."""
        try:
            return run_tool(self.tools, call, self.allowed)
        except Exception as error:
            return ToolResult(f"error: {call['name']} failed: {type(error).__name__}")

    def _use_tools(self, state: ChatState) -> dict[str, Any]:
        """Run the tool calls of the last reply. Their output goes back inside the delimiters."""
        limit = self.settings.agents.max_tool_calls
        registry = self._registry(state)
        tool_log = list(state["tool_log"])
        replies: list[BaseMessage] = []
        for call in state["messages"][-1].tool_calls:
            if len(tool_log) >= limit:
                text = LIMIT_REACHED
            else:
                shown = registry.show(self._call_tool(call))
                tool_log.append({"tool": call["name"], "args": call["args"], "chars": len(shown)})
                text = wrap_untrusted(shown)
            replies.append(ToolMessage(text, tool_call_id=call["id"]))
        if len(tool_log) >= limit:
            replies.append(HumanMessage(LIMIT_REACHED))
        return {"messages": replies, "evidence": stored_rows(registry), "tool_log": tool_log}

    @staticmethod
    def _next(state: ChatState) -> str:
        """Go to the tools, back to the model after a rejected answer, or end the turn."""
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and last.tool_calls:
            return "tools"
        return "model" if isinstance(last, HumanMessage) else END

    def _build_graph(self) -> Any:
        """Compile the ReAct loop with its memory."""
        graph = StateGraph(ChatState)
        graph.add_node("model", self._answer)
        graph.add_node("tools", self._use_tools)
        graph.add_edge(START, "model")
        graph.add_conditional_edges("model", self._next, ["tools", "model", END])
        graph.add_edge("tools", "model")
        return graph.compile(checkpointer=self.saver)

    def ask(self, incident_id: str, question: str) -> dict[str, Any]:
        """Answer one question in the thread of an incident.

        Args:
            incident_id: The incident. It needs a saved report.
            question: The analyst's question.

        Returns:
            The turn: `question`, `claims` with resolved `citations`, `remark`, `answered`, and
            what it used.

        Raises:
            FileNotFoundError: If the incident has no report.
            BudgetExceededError: If a spending limit stops a call. The thread stays usable.
        """
        report = load_report(self.reports_dir, incident_id)
        if report is None:
            raise FileNotFoundError(f"{incident_id} has no report")
        config = thread_config(incident_id)
        with self.lock:
            tools = self.tools
            incident = load_context(
                tools.connection, incident_id, self.settings.agents.context_windows
            )
            # `similar_incidents` sees what the report could see: its run, earlier incidents.
            tools.before, tools.run = incident.start, report.meta["run"]
            self.client.begin_incident()
            known = self.graph.get_state(config).values.get("evidence")
            state = self.graph.invoke(
                {
                    "messages": [HumanMessage(question)],
                    "question": question,
                    "context": report_context(report, incident),
                    "evidence": known or seed_evidence(report),
                    "tool_log": [],
                    "retries": 0,
                },
                config,
            )
        return state["turns"][-1]

    def turns(self, incident_id: str) -> list[dict[str, Any]]:
        """Return the finished turns of an incident."""
        return thread_turns(self.saver, incident_id)

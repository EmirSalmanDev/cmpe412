"""Live smoke tests (plan 7.1, M8): the real API, on dev data. Nothing is read from the cache."""

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langgraph.checkpoint.sqlite import SqliteSaver

from logtriage.agents.cache import LlmCache
from logtriage.agents.chat import ChatAgent
from logtriage.agents.graph import AgentRuntime, IncidentState, build_graph, tool_schemas
from logtriage.agents.llm import LLMClient, build_chat_model
from logtriage.agents.prompting import load_prompts
from logtriage.agents.runner import REPORTS_DIR
from logtriage.agents.schemas import report_claims
from logtriage.agents.tools import AgentTools
from logtriage.config import DEV_TESTBED, Settings, load_settings
from logtriage.rag.attack_index import cosine_collection, open_client
from logtriage.rag.incident_store import IncidentStore

pytestmark = [pytest.mark.live, pytest.mark.data]

INCIDENT = f"{DEV_TESTBED}-0005"


@pytest.fixture(scope="module")
def settings() -> Settings:
    loaded = load_settings()
    if loaded.deepseek_api_key is None:
        pytest.skip("DEEPSEEK_API_KEY is not set")
    return loaded


@pytest.fixture
def tools(settings: Settings, tmp_path: Path) -> Iterator[AgentTools]:
    instance = AgentTools.open(DEV_TESTBED, settings)
    store = cosine_collection(open_client(tmp_path), settings.rag.incidents_collection)
    instance.incidents = IncidentStore(store, instance.attack.embedder)
    yield instance
    instance.close()


@pytest.fixture
def client(settings: Settings, tmp_path: Path) -> Iterator[LLMClient]:
    """Answers stay in a temporary cache; what they cost goes to the real ledger."""
    cache = LlmCache(tmp_path / "llm.sqlite")
    instance = LLMClient(
        build_chat_model(settings), cache, settings.llm, settings.agents.condition, use_cache=False
    )
    yield instance
    ledger = LlmCache(settings.paths.cache_dir / "llm.sqlite")
    ledger.record_spend(settings.llm.model, "live-test", instance.run_spent)
    ledger.close()


def test_the_model_answers_under_the_configured_name(settings: Settings) -> None:
    reply = build_chat_model(settings).invoke("Say hello in one word.")
    assert reply.response_metadata["model_name"] == settings.llm.model
    assert reply.response_metadata["system_fingerprint"]
    assert reply.usage_metadata["input_tokens"] > 0
    assert not reply.additional_kwargs.get("reasoning_content")


def test_max_tokens_reaches_the_api(settings: Settings) -> None:
    model = build_chat_model(settings.model_copy(update={"llm": settings.llm.model_copy(
        update={"max_tokens": 5}
    )}))  # fmt: skip
    reply = model.invoke("Count from one to one hundred in words.")
    assert reply.usage_metadata["output_tokens"] <= 5
    assert reply.response_metadata["finish_reason"] == "length"


def test_a_tool_round_trip_in_json_mode(tools: AgentTools, client: LLMClient) -> None:
    schemas = tool_schemas(tools, rag=True)
    messages = [
        SystemMessage('Use tools, then reply with json like {"lines": 3}.'),
        HumanMessage(
            "Call log_search once for host vpn from 2022-01-24T03:00:00 to 2022-01-24T03:10:00, "
            "then report how many lines it found."
        ),
    ]
    first = client.chat("investigator", messages, tools=schemas, json_mode=True)
    assert [call["name"] for call in first.tool_calls] == ["log_search"]
    result = tools.log_search(**first.tool_calls[0]["args"])
    assert result.text
    tool = ToolMessage(result.text, tool_call_id=first.tool_calls[0]["id"])
    final = client.chat("investigator", [*messages, first, tool], tools=schemas, json_mode=True)
    assert final.tool_calls == []
    assert isinstance(json.loads(final.content)["lines"], int)


def test_a_call_after_the_tools_are_removed_still_answers(
    tools: AgentTools, client: LLMClient
) -> None:
    """The graph drops `tools` at the limit, while the conversation still holds tool calls."""
    schemas = tool_schemas(tools, rag=True)
    messages = [
        SystemMessage('Reply with json like {"done": true}.'),
        HumanMessage("Call ip_profile for 10.0.0.1."),
    ]
    first = client.chat("investigator", messages, tools=schemas, json_mode=True)
    tool = ToolMessage("no data", tool_call_id=first.tool_calls[0]["id"])
    stop = HumanMessage("The tool call limit is reached. Give your final json answer now.")
    final = client.chat("investigator", [*messages, first, tool, stop], json_mode=True)
    assert json.loads(final.content)


def test_one_full_incident(
    settings: Settings, tools: AgentTools, client: LLMClient, tmp_path: Path
) -> None:
    runtime = AgentRuntime(client, tools, settings, load_prompts(), tmp_path, "live-smoke")
    report = build_graph(runtime).invoke(IncidentState(incident_id=INCIDENT))["report"]
    known = {item.eid for item in report.evidence}
    assert report.incident_id == INCIDENT
    assert report.evidence
    assert all("|" in item.line_id for item in report.evidence)
    assert all(set(claim.evidence) <= known for claim in report_claims(report))
    assert report.meta["cost_usd"] > 0
    assert report.meta["tool_calls"]
    assert len(report.meta["retrieved_techniques"]) == settings.agents.mapper_k
    assert report.meta["draft_claims"] >= 1
    assert (tmp_path / f"{INCIDENT}.json").is_file()


def test_the_chat_answers_a_follow_up_with_citations(
    settings: Settings, tools: AgentTools, client: LLMClient, tmp_path: Path
) -> None:
    """Dev data only; `chat-1` is not iterated on the test testbed."""
    saver = SqliteSaver(sqlite3.connect(tmp_path / "chat.sqlite", check_same_thread=False))
    reports = settings.paths.processed_dir / DEV_TESTBED / REPORTS_DIR
    agent = ChatAgent(tools, client, settings, saver, reports)
    first = agent.ask(INCIDENT, "Which source addresses does this incident involve?")
    follow_up = agent.ask(
        INCIDENT, "Look in the raw logs: what else did the first of those addresses do that day?"
    )
    print(json.dumps([first, follow_up], indent=1))
    for turn in (first, follow_up):
        assert turn["answered"]
        assert turn["claims"]
        for claim in turn["claims"]:
            assert claim["citations"]
            assert all(item["line_id"].count("|") == 2 for item in claim["citations"])
    assert follow_up["tools"]
    assert len(agent.turns(INCIDENT)) == 2

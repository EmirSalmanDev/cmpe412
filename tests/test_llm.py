"""LLM client (plan 7.1): cache, cost, budget guards and retries, with no network."""

import json
from datetime import UTC, datetime

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from pydantic import BaseModel

from agent_fakes import FakeChat, llm_config
from logtriage.agents.cache import LlmCache, cache_key
from logtriage.agents.llm import (
    REASONING,
    BudgetExceededError,
    DeepSeekChat,
    LLMClient,
    LLMOutputError,
    build_chat_model,
    call_cost,
    rates_at,
)
from logtriage.config import PricingConfig, Settings, TokenPrices

CONDITION = {"verifier": True, "rag": True, "few_shot": False}
ASK = [SystemMessage("You are a security analyst"), HumanMessage("hello json")]
ONE_CALL_USD = (800 * 1.0 + 200 * 0.1 + 100 * 2.0) / 1_000_000


class Answer(BaseModel):
    value: int


def client_for(script: list, **changes) -> tuple[LLMClient, FakeChat]:
    chat = FakeChat({"investigator": script})
    return LLMClient(chat, LlmCache(":memory:"), llm_config(**changes), CONDITION), chat


def test_a_repeated_request_is_answered_by_the_cache_and_costs_nothing() -> None:
    client, chat = client_for(["one"])
    assert client.chat("investigator", ASK).content == "one"
    assert client.chat("investigator", ASK).content == "one"
    assert chat.count("investigator") == 1
    assert client.tally.calls == 2
    assert client.tally.cached_calls == 1
    assert client.tally.spent_usd == pytest.approx(ONE_CALL_USD)
    assert client.tally.cost_usd == pytest.approx(2 * ONE_CALL_USD)


def test_no_cache_bypasses_the_stored_answer() -> None:
    client, chat = client_for(["one", "two"])
    client.chat("investigator", ASK)
    client.use_cache = False
    assert client.chat("investigator", ASK).content == "two"
    assert chat.count("investigator") == 2


def test_the_cache_keeps_tool_calls_and_reasoning() -> None:
    reply = AIMessage(
        content="",
        tool_calls=[{"name": "ip_profile", "args": {"ip": "1.1.1.1"}, "id": "c1"}],
        additional_kwargs={REASONING: "because"},
    )
    client, _ = client_for([reply])
    client.chat("investigator", ASK)
    again = client.chat("investigator", ASK)
    assert again.tool_calls[0]["args"] == {"ip": "1.1.1.1"}
    assert again.additional_kwargs[REASONING] == "because"


@pytest.mark.parametrize(
    "change",
    [
        {"model": "other"},
        {"messages": [{"type": "human", "content": "b"}]},
        {"tools": [{"name": "t"}]},
        {"params": {"temperature": 1}},
        {"condition": {"verifier": False, "rag": True, "few_shot": False}},
        {"condition": {"verifier": True, "rag": False, "few_shot": False}},
        {"condition": {"verifier": True, "rag": True, "few_shot": True}},
    ],
)
def test_the_key_depends_on_every_part_of_the_request(change: dict) -> None:
    base = {
        "model": "m",
        "messages": [{"type": "human", "content": "a"}],
        "tools": None,
        "params": {"temperature": 0},
        "condition": CONDITION,
    }
    assert cache_key(**base) == cache_key(**base)
    assert cache_key(**base) != cache_key(**(base | change))


def test_prices_follow_the_peak_hours_of_a_weekday() -> None:
    pricing = PricingConfig(off_peak=TokenPrices(input=1), peak=TokenPrices(input=2))
    hours = [(1, 4), (6, 10)]
    friday = datetime(2026, 11, 6, 2, 0, tzinfo=UTC)
    assert rates_at(friday, pricing, hours).input == 2
    assert rates_at(friday.replace(hour=4), pricing, hours).input == 1
    assert rates_at(friday.replace(hour=9, minute=59), pricing, hours).input == 2
    assert rates_at(friday.replace(hour=10), pricing, hours).input == 1
    assert rates_at(friday.replace(day=7), pricing, hours).input == 1


def test_the_cost_charges_cached_tokens_at_the_cached_rate() -> None:
    rates = TokenPrices(input=0.3, cached_input=0.006, output=1.2)
    assert call_cost(1_000_000, 500_000, 1_000_000, rates) == pytest.approx(0.15 + 0.003 + 1.2)


def test_the_run_budget_stops_the_next_paid_call() -> None:
    client, chat = client_for(["one"], max_usd_per_run=ONE_CALL_USD / 2)
    client.chat("investigator", ASK)
    with pytest.raises(BudgetExceededError, match="max_usd_per_run"):
        client.chat("investigator", [*ASK, HumanMessage("more")])
    assert chat.count("investigator") == 1


def test_the_budget_does_not_stop_an_answer_from_the_cache() -> None:
    client, chat = client_for(["one"], max_usd_per_run=ONE_CALL_USD / 2)
    client.chat("investigator", ASK)
    assert client.chat("investigator", ASK).content == "one"


def test_the_total_budget_counts_spend_of_earlier_runs() -> None:
    client, chat = client_for(["one"], max_usd_total=1.0)
    client.cache.record_spend("m", "investigator", 1.5)
    with pytest.raises(BudgetExceededError, match="max_usd_total"):
        client.chat("investigator", ASK)
    assert chat.count("investigator") == 0


def test_invalid_json_is_retried_with_the_error_fed_back() -> None:
    client, chat = client_for(["not json", '{"value": 1}'])
    assert client.structured("investigator", ASK, Answer).value == 1
    second = chat.of("investigator")[1]["messages"]
    assert "rejected" in second[-1].content
    assert second[-2].content == "not json"
    assert client.tally.retries == 1


def test_a_schema_error_is_retried_too() -> None:
    client, chat = client_for(['{"value": "x"}', '{"value": 2}'])
    assert client.structured("investigator", ASK, Answer).value == 2
    assert "value" in chat.of("investigator")[1]["messages"][-1].content


def test_blank_content_counts_as_invalid() -> None:
    client, _ = client_for(["   ", '{"value": 3}'])
    assert client.structured("investigator", ASK, Answer).value == 3


def test_retries_are_limited_to_two() -> None:
    client, chat = client_for(["bad"])
    with pytest.raises(LLMOutputError, match="investigator"):
        client.structured("investigator", ASK, Answer)
    assert chat.count("investigator") == 3


def test_a_further_rule_can_reject_an_answer() -> None:
    def odd(answer: Answer) -> None:
        if answer.value % 2 == 0:
            raise ValueError("the value must be odd")

    client, chat = client_for(['{"value": 2}', '{"value": 3}'])
    assert client.structured("investigator", ASK, Answer, odd).value == 3
    assert "must be odd" in chat.of("investigator")[1]["messages"][-1].content


def test_json_mode_and_tools_reach_the_model() -> None:
    client, chat = client_for(["x"])
    client.chat("investigator", ASK, tools=[{"type": "function"}], json_mode=True)
    assert chat.calls[0]["kwargs"] == {
        "tools": [{"type": "function"}],
        "response_format": {"type": "json_object"},
    }


def model() -> DeepSeekChat:
    return DeepSeekChat(model="m", api_key="k", base_url="http://localhost", max_tokens=9)


def test_the_payload_echoes_reasoning_and_uses_max_tokens() -> None:
    turn = AIMessage(
        content="",
        additional_kwargs={REASONING: "because"},
        tool_calls=[{"name": "t", "args": {}, "id": "c1"}],
    )
    plain = AIMessage(content="no reasoning")
    tool = ToolMessage("out", tool_call_id="c1")
    payload = model()._get_request_payload([HumanMessage("a"), turn, tool, plain])
    assert payload["messages"][1][REASONING] == "because"
    assert REASONING not in payload["messages"][3]
    assert payload["max_tokens"] == 9
    assert "max_completion_tokens" not in payload


def test_the_result_keeps_reasoning_from_the_raw_answer() -> None:
    raw = {
        "id": "r",
        "object": "chat.completion",
        "model": "m",
        "created": 0,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "hi", REASONING: "because"},
            }
        ],
    }
    message = model()._create_chat_result(raw).generations[0].message
    assert message.additional_kwargs[REASONING] == "because"


def test_the_client_needs_the_key_from_the_environment() -> None:
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        build_chat_model(Settings(_env_file=None, deepseek_api_key=""))


def test_thinking_is_sent_explicitly() -> None:
    settings = Settings(_env_file=None, DEEPSEEK_API_KEY="k")
    assert build_chat_model(settings).extra_body == {"thinking": {"type": "disabled"}}


def test_the_spend_ledger_survives_a_reopen(tmp_path) -> None:
    path = tmp_path / "cache" / "llm.sqlite"
    cache = LlmCache(path)
    cache.record_spend("m", "mapper", 0.25)
    cache.put("k", {"a": 1})
    cache.close()
    reopened = LlmCache(path)
    assert reopened.total_spend() == 0.25
    assert json.dumps(reopened.get("k")) == '{"a": 1}'

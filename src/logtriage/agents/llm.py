"""LLM client (plan 7.1): one OpenAI-compatible model, a cache, cost tracking and budget guards."""

import json
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, TypeVar

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, SecretStr, ValidationError

from logtriage.agents.cache import LlmCache, cache_key
from logtriage.config import LLMConfig, PricingConfig, Settings, TokenPrices

REASONING = "reasoning_content"
JSON_MODE = {"type": "json_object"}
FEEDBACK_CHARS = 1500
Parsed = TypeVar("Parsed", bound=BaseModel)


class BudgetExceededError(RuntimeError):
    """A spending limit is reached, so no further call may be made."""


class LLMOutputError(RuntimeError):
    """The model did not produce a valid answer within the allowed retries."""


class EmptyResponseError(RuntimeError):
    """The endpoint answered with no body at all, which the HTTP client does not retry (D69)."""


class CacheMissError(RuntimeError):
    """A cache-only client would have to pay for a call (D65)."""


class FingerprintChangedError(RuntimeError):
    """The model behind the rolling alias is not the one the runs are compared with (D44)."""


class ChatBackend(Protocol):
    """The part of a chat model the client uses."""

    def invoke(self, messages: list[BaseMessage], **kwargs: Any) -> AIMessage:
        """Return the model's reply."""
        ...


class DeepSeekChat(ChatOpenAI):
    """`ChatOpenAI` that keeps `reasoning_content`, which DeepSeek needs echoed (plan 7.1, D44)."""

    def _get_request_payload(
        self, input_: Any, *, stop: list[str] | None = None, **kwargs: Any
    ) -> dict:
        """Adapt the request to DeepSeek, and echo the reasoning of earlier turns.

        `max_tokens` goes by that name. `response_format` goes in the extra body, because with it
        as a parameter `ChatOpenAI` calls the SDK's `parse`, which refuses non-strict tools.
        """
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)
        if "max_completion_tokens" in payload:
            payload["max_tokens"] = payload.pop("max_completion_tokens")
        if "response_format" in payload:
            extra = payload.get("extra_body") or {}
            payload["extra_body"] = {**extra, "response_format": payload.pop("response_format")}
        messages = self._convert_input(input_).to_messages()
        for sent, message in zip(payload["messages"], messages, strict=True):
            if isinstance(message, AIMessage) and message.additional_kwargs.get(REASONING):
                sent[REASONING] = message.additional_kwargs[REASONING]
        return payload

    def _create_chat_result(self, response: Any, generation_info: dict | None = None) -> Any:
        """Copy the reasoning of the raw answer onto the message.

        Raises:
            EmptyResponseError: If the endpoint sent nothing. The parent raises a plain ValueError
                there, which nothing could tell from a real fault.
        """
        if response is None:
            raise EmptyResponseError("the endpoint returned an empty response")
        result = super()._create_chat_result(response, generation_info)
        data = response if isinstance(response, dict) else response.model_dump()
        for generation, choice in zip(result.generations, data.get("choices", []), strict=False):
            reasoning = (choice.get("message") or {}).get(REASONING)
            if reasoning:
                generation.message.additional_kwargs[REASONING] = reasoning
        return result


def build_chat_model(settings: Settings) -> DeepSeekChat:
    """Build the configured chat model.

    Args:
        settings: Loaded settings.

    Returns:
        The model.

    Raises:
        ValueError: If `DEEPSEEK_API_KEY` is not set.
    """
    secret = settings.deepseek_api_key
    if secret is None or not secret.get_secret_value():
        raise ValueError("DEEPSEEK_API_KEY is not set")
    config = settings.llm
    return DeepSeekChat(
        model=config.model,
        base_url=config.base_url,
        api_key=SecretStr(secret.get_secret_value()),
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        timeout=config.timeout_seconds,
        max_retries=config.http_retries,
        extra_body={"thinking": {"type": config.thinking}},
    )


def rates_at(
    moment: datetime, pricing: PricingConfig, peak_hours: Sequence[Sequence[int]]
) -> TokenPrices:
    """Return the prices at a moment (D45).

    Args:
        moment: Tz-aware time.
        pricing: Rates of both bands.
        peak_hours: Start and end hour of each peak range, UTC, Monday to Friday. Public holidays
            are unknown here, so they count as peak, and the cost can only be too high.

    Returns:
        The rates of the band.
    """
    utc = moment.astimezone(UTC)
    weekday = utc.weekday() < 5
    return (
        pricing.peak
        if weekday and any(start <= utc.hour < end for start, end in peak_hours)
        else pricing.off_peak
    )


def call_cost(tokens_in: int, tokens_cached: int, tokens_out: int, rates: TokenPrices) -> float:
    """Return the USD of one call. `tokens_in` includes the cached tokens."""
    miss = tokens_in - tokens_cached
    total = miss * rates.input + tokens_cached * rates.cached_input + tokens_out * rates.output
    return total / 1_000_000


def plain_message(message: BaseMessage) -> dict[str, Any]:
    """Return the parts of a message that define a request, for the cache key."""
    plain: dict[str, Any] = {"type": message.type, "content": message.content}
    if isinstance(message, AIMessage):
        plain["tool_calls"] = [
            {"name": call["name"], "args": call["args"], "id": call["id"]}
            for call in message.tool_calls
        ]
        plain[REASONING] = message.additional_kwargs.get(REASONING)
    if message.type == "tool":
        plain["tool_call_id"] = message.tool_call_id
    return plain


def request_key(
    config: LLMConfig,
    condition: dict[str, bool],
    messages: list[BaseMessage],
    tools: list[dict[str, Any]] | None = None,
    json_mode: bool = False,
) -> str:
    """Return the cache key of a request, as the client computes it.

    Args:
        config: LLM settings.
        condition: Ablation switches.
        messages: The conversation.
        tools: Tool schemas, if any.
        json_mode: Whether a JSON object is asked for.

    Returns:
        The key, so that saved answers can be found again without a call.
    """
    params = {
        "temperature": config.temperature,
        "thinking": config.thinking,
        "max_tokens": config.max_tokens,
        "json_mode": json_mode,
    }
    return cache_key(config.model, [plain_message(m) for m in messages], tools, params, condition)


def _usage(reply: AIMessage) -> tuple[int, int, int]:
    """Return input, cached input and output tokens of a reply."""
    usage = reply.usage_metadata or {}
    details = usage.get("input_token_details") or {}
    return (
        int(usage.get("input_tokens", 0)),
        int(details.get("cache_read") or 0),
        int(usage.get("output_tokens", 0)),
    )


def parse_answer(
    reply: AIMessage,
    schema: type[Parsed],
    check: Callable[[Parsed], None] | None = None,
) -> Parsed:
    """Parse the JSON answer of a reply.

    Args:
        reply: The reply. JSON mode can return blank content (status.md).
        schema: The expected model.
        check: Further rule; it raises ValueError on a bad answer.

    Returns:
        The validated answer.

    Raises:
        ValueError: If the answer is blank or invalid. A Pydantic error is one.
    """
    text = reply.content if isinstance(reply.content, str) else ""
    if not text.strip():
        raise ValueError("the answer is empty; reply with the json object")
    parsed = schema.model_validate_json(text)
    if check is not None:
        check(parsed)
    return parsed


def retry_message(error: ValueError) -> HumanMessage:
    """Return the message that feeds a validation error back (plan 7.1)."""
    if isinstance(error, ValidationError):
        items = error.errors(include_url=False, include_input=False, include_context=False)
        detail = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in items)
    else:
        detail = str(error)
    return HumanMessage(
        f"Your answer was rejected: {detail[:FEEDBACK_CHARS]}\n"
        "Reply again with one valid json object in the required format."
    )


@dataclass
class Tally:
    """Counters of one incident. `cost_usd` includes answers replayed from the cache."""

    calls: int = 0
    cached_calls: int = 0
    tokens_in: int = 0
    tokens_cached: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    spent_usd: float = 0.0
    llm_latency_s: float = 0.0
    replayed_latency_s: float = 0.0
    retries: int = 0
    fingerprints: list[str] = field(default_factory=list)
    served_models: list[str] = field(default_factory=list)


class LLMClient:
    """Sends requests through the cache and keeps spending under its limits."""

    def __init__(
        self,
        backend: ChatBackend,
        cache: LlmCache,
        config: LLMConfig,
        condition: dict[str, bool],
        use_cache: bool = True,
        cache_only: bool = False,
        expected_fingerprint: str | None = None,
    ) -> None:
        self.backend = backend
        self.cache = cache
        self.config = config
        self.condition = condition
        self.use_cache = use_cache
        self.cache_only = cache_only
        self.expected_fingerprint = expected_fingerprint
        self.tally = Tally()
        self.run_spent = 0.0

    def begin_incident(self) -> None:
        """Reset the counters of the incident. The run total stays."""
        self.tally = Tally()

    def _check_budget(self) -> None:
        """Refuse a paid call once a limit is reached."""
        if self.run_spent >= self.config.max_usd_per_run:
            raise BudgetExceededError(
                f"run spend {self.run_spent:.4f} USD reached llm.max_usd_per_run "
                f"{self.config.max_usd_per_run}"
            )
        total = self.cache.total_spend()
        if total >= self.config.max_usd_total:
            raise BudgetExceededError(
                f"total spend {total:.4f} USD reached llm.max_usd_total {self.config.max_usd_total}"
            )

    def _invoke(self, role: str, messages: list[BaseMessage], kwargs: dict[str, Any]) -> AIMessage:
        """Call the model, sending the same request again after an empty response (D69).

        Raises:
            LLMOutputError: If `llm.json_retries` retries all come back empty.
        """
        for attempt in range(self.config.json_retries + 1):
            try:
                return self.backend.invoke(messages, **kwargs)
            except EmptyResponseError as error:
                last = error
                if attempt < self.config.json_retries:
                    self.tally.retries += 1
        raise LLMOutputError(f"{role}: no valid answer: {last}")

    def _paid_answer(
        self, role: str, messages: list[BaseMessage], kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        """Make the real call and record what it cost."""
        self._check_budget()
        began = time.perf_counter()
        reply = self._invoke(role, messages, kwargs)
        latency = time.perf_counter() - began
        tokens_in, tokens_cached, tokens_out = _usage(reply)
        rates = rates_at(
            datetime.now(UTC), self.config.pricing_usd_per_1m, self.config.peak_hours_utc
        )
        cost = call_cost(tokens_in, tokens_cached, tokens_out, rates)
        self.run_spent += cost
        self.tally.spent_usd += cost
        self.cache.record_spend(self.config.model, role, cost)
        metadata = reply.response_metadata or {}
        fingerprint = metadata.get("system_fingerprint")
        if self.expected_fingerprint and fingerprint != self.expected_fingerprint:
            raise FingerprintChangedError(
                f"{role}: system_fingerprint {fingerprint}, expected {self.expected_fingerprint}"
            )
        return {
            "content": reply.content,
            "tool_calls": [
                {"name": call["name"], "args": call["args"], "id": call["id"]}
                for call in reply.tool_calls
            ],
            REASONING: reply.additional_kwargs.get(REASONING),
            "tokens_in": tokens_in,
            "tokens_cached": tokens_cached,
            "tokens_out": tokens_out,
            "cost_usd": cost,
            "latency_s": latency,
            "served_model": metadata.get("model_name"),
            "fingerprint": fingerprint,
            "finish_reason": metadata.get("finish_reason"),
        }

    def _count(self, answer: dict[str, Any], cached: bool) -> None:
        """Add an answer to the counters of the incident."""
        tally = self.tally
        tally.calls += 1
        tally.cached_calls += int(cached)
        tally.tokens_in += answer["tokens_in"]
        tally.tokens_cached += answer["tokens_cached"]
        tally.tokens_out += answer["tokens_out"]
        tally.cost_usd += answer["cost_usd"]
        tally.llm_latency_s += answer["latency_s"]
        if cached:
            tally.replayed_latency_s += answer["latency_s"]
        for values, value in (
            (tally.fingerprints, answer["fingerprint"]),
            (tally.served_models, answer["served_model"]),
        ):
            if value and value not in values:
                values.append(value)

    def chat(
        self,
        role: str,
        messages: list[BaseMessage],
        tools: list[dict[str, Any]] | None = None,
        json_mode: bool = False,
    ) -> AIMessage:
        """Return the model's reply, from the cache if the same request was made.

        Args:
            role: Agent role, for the ledger.
            messages: The conversation.
            tools: Tool schemas, if the model may call tools.
            json_mode: Ask for a JSON object.

        Returns:
            The reply.

        Raises:
            BudgetExceededError: If a limit stops a call that the cache cannot answer.
            CacheMissError: If the client is cache-only and the cache cannot answer.
        """
        key = request_key(self.config, self.condition, messages, tools, json_mode)
        answer = self.cache.get(key) if self.use_cache else None
        cached = answer is not None
        if answer is None:
            if self.cache_only:
                raise CacheMissError(f"{role}: no saved answer for request {key[:12]}")
            kwargs: dict[str, Any] = {}
            if tools:
                kwargs["tools"] = tools
            if json_mode:
                kwargs["response_format"] = JSON_MODE
            answer = self._paid_answer(role, messages, kwargs)
            self.cache.put(key, answer)
        self._count(answer, cached)
        return AIMessage(
            content=answer["content"],
            tool_calls=[{**call, "type": "tool_call"} for call in answer["tool_calls"]],
            additional_kwargs={REASONING: answer[REASONING]} if answer[REASONING] else {},
        )

    def structured(
        self,
        role: str,
        messages: list[BaseMessage],
        schema: type[Parsed],
        check: Callable[[Parsed], None] | None = None,
    ) -> Parsed:
        """Ask for a JSON answer, retrying with the validation error (plan 7.1).

        Args:
            role: Agent role.
            messages: The conversation.
            schema: The expected model.
            check: Further rule; it raises ValueError on a bad answer.

        Returns:
            The validated answer.

        Raises:
            LLMOutputError: If the retries run out.
        """
        conversation = list(messages)
        for attempt in range(self.config.json_retries + 1):
            reply = self.chat(role, conversation, json_mode=True)
            try:
                return parse_answer(reply, schema, check)
            except ValueError as error:
                last = error
                if attempt < self.config.json_retries:
                    self.tally.retries += 1
                    conversation += [reply, retry_message(error)]
        raise LLMOutputError(f"{role}: no valid answer: {str(last)[:FEEDBACK_CHARS]}")

    def snapshot(self) -> dict[str, Any]:
        """Return the counters of the incident as plain data."""
        return json.loads(json.dumps(asdict(self.tally)))

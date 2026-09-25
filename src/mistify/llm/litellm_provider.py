"""LiteLLM adapter for the provider seam: one adapter, most vendors, and local models.

The model string is LiteLLM's own, vendor-prefixed: `gemini/gemini-3.5-flash-lite`,
`anthropic/claude-sonnet-5`, `openai/gpt-5`, `ollama_chat/qwen3:8b`. LiteLLM translates every
one of them to and from the OpenAI chat shape, so this adapter translates the seam to that
shape once. Callable is not the same as capable: small local models often fail at multi-step
tool calling, and which models actually work is what the compatibility matrix measures, not
something this adapter can promise.

Four things are worth naming, because each is a place where a naive translation produces a
loop that looks fine and behaves wrong.

**Tool-call ids are replayed verbatim.** For Gemini, LiteLLM carries the thought signature
*inside* the id (`call_..__thought__<signature>`) as well as in `provider_specific_fields`.
Regenerating ids does not fail loudly: measured 2026-09-23, a Gemini history with the
signatures stripped was still accepted, so the loss of the model's reasoning context would be
silent. The id and the provider fields both go back exactly as they came.

**Tool results are one message each.** The seam puts every result for a turn in one user
message; the OpenAI shape wants a `tool` message per call, correlated by id, before any text.

**Arguments that are not a JSON object are refused by name.** A model that cannot produce
valid tool-call JSON cannot run an investigation, and passing `{}` on would surface as a
misleading "missing argument" error three steps later.

**No task budgets, and LiteLLM does not retry.** `num_retries=0` keeps the retry policy here,
where it honours the server's advertised delay, rather than stacking two retry loops.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from mistify.llm.base import (
    Message,
    ProviderError,
    StopReason,
    ToolCall,
    ToolSpec,
    Turn,
    Usage,
)
from mistify.llm.retry import RETRYABLE_STATUS, send_with_retries, space_out

__all__ = ["LiteLLMProvider"]

#: A refused connection: no server at that address. Linux and macOS say "Connection refused";
#: Windows says the target machine "actively refused it".
_REFUSED = re.compile(r"(?i)connection refused|actively refused")

#: LiteLLM prefixes for servers that run on the user's machine.
_LOCAL_PREFIXES = ("ollama/", "ollama_chat/")

#: LiteLLM's exception classes for failures worth another attempt. Matched by name so this
#: module imports nothing from LiteLLM until a call is made.
_RETRYABLE_CLASSES = frozenset(
    {
        "RateLimitError",
        "Timeout",
        "APIConnectionError",
        "ServiceUnavailableError",
        "InternalServerError",
        "BadGatewayError",
    }
)


class LiteLLMProvider:
    """Talks to any model LiteLLM can route to, through its OpenAI-shaped `completion`."""

    supports_task_budget = False

    def __init__(
        self,
        model: str,
        *,
        completion: Any = None,
        max_retries: int = 5,
        min_interval_seconds: float = 0.0,
        timeout_seconds: float = 120.0,
        sleep: Any = time.sleep,
    ) -> None:
        self.name = "litellm"
        self.model = model
        #: Injected by tests; resolved to `litellm.completion` on first use otherwise, so
        #: importing this module does not import LiteLLM.
        self._completion = completion
        self.max_retries = max_retries
        self.min_interval_seconds = min_interval_seconds
        #: Passed on every request. Same reason as the Gemini adapter: an unbounded request
        #: does not fail, it hangs.
        self.timeout_seconds = timeout_seconds
        self._sleep = sleep
        self._last_call_at = 0.0

    @property
    def completion(self) -> Any:
        if self._completion is None:
            import litellm

            # Otherwise every retried error prints a feedback banner to stdout; the failure
            # that matters is reported once, by name, when retries run out.
            litellm.suppress_debug_info = True
            self._completion = litellm.completion
        return self._completion

    # ---------------------------------------------------------------- translation

    @staticmethod
    def _to_messages(system: str, messages: list[Message]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if system:
            out.append({"role": "system", "content": system})
        for message in messages:
            if message.role == "assistant":
                if not (message.text or message.tool_calls):
                    continue
                entry: dict[str, Any] = {"role": "assistant", "content": message.text or None}
                if message.tool_calls:
                    entry["tool_calls"] = [_to_tool_call(call) for call in message.tool_calls]
                out.append(entry)
                continue
            # Results first: the OpenAI shape requires every tool call to be answered before
            # the conversation moves on, and text in the same seam message comes after them.
            for outcome in message.tool_results:
                content = f"ERROR: {outcome.content}" if outcome.is_error else outcome.content
                out.append({"role": "tool", "tool_call_id": outcome.call_id, "content": content})
            if message.text:
                out.append({"role": "user", "content": message.text})
        return out

    @staticmethod
    def _to_tools(tools: list[ToolSpec] | None) -> list[dict[str, Any]] | None:
        if not tools:
            return None
        return [
            {
                "type": "function",
                "function": {
                    "name": spec.name,
                    "description": spec.description,
                    "parameters": spec.schema,
                },
            }
            for spec in tools
        ]

    def _to_calls(self, raw_calls: Any) -> tuple[ToolCall, ...]:
        calls: list[ToolCall] = []
        for raw in raw_calls or []:
            function = _field(raw, "function")
            name = _field(function, "name")
            arguments = _field(function, "arguments")
            try:
                parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
            except json.JSONDecodeError as exc:
                raise ProviderError(self._bad_arguments(name, arguments)) from exc
            if parsed is None:
                parsed = {}
            if not isinstance(parsed, dict):
                raise ProviderError(self._bad_arguments(name, arguments))
            calls.append(
                ToolCall(
                    id=_field(raw, "id"),
                    name=name,
                    arguments=parsed,
                    signature=_field(raw, "provider_specific_fields"),
                )
            )
        return tuple(calls)

    def _bad_arguments(self, name: Any, arguments: Any) -> str:
        return (
            f"{self.model} called tool {name!r} with arguments that are not a JSON object: "
            f"{str(arguments)[:200]!r}. The model may not support tool calling well enough "
            f"to run an investigation; try a larger model."
        )

    @staticmethod
    def _stop_reason(finish_reason: Any, tool_calls: tuple[ToolCall, ...]) -> StopReason:
        """Parts decide before the reason does, as in the Gemini adapter.

        Not every backend reports `tool_calls` as the finish reason when it made one; some
        local servers say `stop`.
        """
        if tool_calls:
            return "tool_use"
        reason = str(finish_reason or "").lower()
        if reason == "length":
            return "max_tokens"
        if reason == "content_filter":
            return "refusal"
        return "end_turn"

    @staticmethod
    def _usage(response: Any) -> Usage:
        """Token counts in the seam's contract: cached is a subset of input.

        LiteLLM normalises to the OpenAI convention, where `prompt_tokens` is the whole prompt
        and `prompt_tokens_details.cached_tokens` the part served from cache -- the same rule
        `Usage` documents. `cache_read_input_tokens` is LiteLLM's Anthropic-style field, read
        only when the OpenAI one is absent, and never added on top.
        """
        usage = _field(response, "usage")
        if usage is None:
            return Usage()
        details = _field(usage, "prompt_tokens_details")
        cached = _field(details, "cached_tokens") if details is not None else None
        if cached is None:
            cached = _field(usage, "cache_read_input_tokens")
        return Usage(
            input_tokens=int(_field(usage, "prompt_tokens") or 0),
            output_tokens=int(_field(usage, "completion_tokens") or 0),
            cached_input_tokens=int(cached or 0),
        )

    # ---------------------------------------------------------------- the call

    def converse(
        self,
        system: str,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        max_tokens: int = 8192,
        task_budget_tokens: int | None = None,
    ) -> Turn:
        request: dict[str, Any] = {
            "model": self.model,
            "messages": self._to_messages(system, messages),
            "max_tokens": max_tokens,
            "timeout": self.timeout_seconds,
            "num_retries": 0,
        }
        spec = self._to_tools(tools)
        if spec is not None:
            request["tools"] = spec
        response = self._send(request)

        choices = _field(response, "choices") or []
        if not choices:
            # No choice is a block, not an empty answer -- the same rule as Gemini's.
            return Turn(text="", stop_reason="refusal", usage=self._usage(response))
        choice = choices[0]
        message = _field(choice, "message")
        try:
            calls = self._to_calls(_field(message, "tool_calls"))
        except ProviderError as exc:
            if str(_field(choice, "finish_reason") or "").lower() != "length":
                raise
            # Cut off mid-call by the output ceiling, not a model that cannot write JSON:
            # the advice to try a larger model would send the user the wrong way.
            raise ProviderError(
                f"{self.model} reached llm.max_tokens while writing a tool call, so its "
                "arguments were cut off. Raise llm.max_tokens."
            ) from exc
        return Turn(
            text=_field(message, "content") or "",
            tool_calls=calls,
            stop_reason=self._stop_reason(_field(choice, "finish_reason"), calls),
            usage=self._usage(response),
        )

    def _send(self, request: dict[str, Any]) -> Any:
        return send_with_retries(
            lambda: self.completion(**request),
            is_retryable=self._is_retryable,
            max_retries=self.max_retries,
            sleep=self._sleep,
            before_each=self._space_out,
            failure=f"{self.model} call failed{self._local_hint()}",
        )

    def _local_hint(self) -> str:
        if self.model.startswith(_LOCAL_PREFIXES):
            return (
                " (is the local server running? LiteLLM reads its address from "
                "OLLAMA_API_BASE and defaults to http://localhost:11434)"
            )
        return ""

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        if _REFUSED.search(str(exc)):
            # Nothing is listening. Retrying a local server that is not running spends the
            # whole backoff schedule -- about a minute -- to report the same error.
            return False
        code = getattr(exc, "status_code", None)
        if isinstance(code, int) and code in RETRYABLE_STATUS:
            return True
        return any(cls.__name__ in _RETRYABLE_CLASSES for cls in type(exc).__mro__)

    def _space_out(self) -> None:
        self._last_call_at = space_out(self._last_call_at, self.min_interval_seconds, self._sleep)


def _to_tool_call(call: ToolCall) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": call.id,
        "type": "function",
        "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
    }
    if call.signature is not None:
        entry["provider_specific_fields"] = call.signature
    return entry


def _field(obj: Any, name: str) -> Any:
    """Read a field from a LiteLLM response object or a plain dict alike.

    LiteLLM returns pydantic-style objects; tests and some backends hand back dicts.
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)

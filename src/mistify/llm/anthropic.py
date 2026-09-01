"""The seam's Anthropic implementation.

This is the only file in the project that knows what an Anthropic request looks like. It
translates in both directions -- `Message` to content blocks on the way out, content blocks to
`Turn` on the way back -- so nothing above the seam has to hold a vendor's message shape in
its head.

Three details here are load-bearing and easy to lose in a refactor:

* **Tool results are batched per message.** One assistant turn may carry several `tool_use`
  blocks, and the API requires every result to come back in a *single* user message. The seam
  already models that -- `Message.tool_results` is a tuple -- so the translation just has to
  not split it.
* **The system prompt carries a cache breakpoint.** It is sent as a one-element block list
  rather than a bare string so a `cache_control` marker can sit on it. See `_system_blocks`.
* **`refusal` survives.** The seam keeps it distinct from `end_turn` and so does this adapter;
  flattening the two would let an investigation report a refusal as a conclusion.

Requests are non-streaming, which bounds usable `max_tokens` at roughly 16k before the SDK's
own HTTP timeout starts to bite. That is a deliberate limit of the seam -- it returns one
finished `Turn`, so there is nothing for a stream to be delivered into.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

import anthropic

from mistify.llm.base import (
    Message,
    ProviderError,
    StopReason,
    ToolCall,
    ToolResult,
    ToolSpec,
    Turn,
    Usage,
)

__all__ = ["AnthropicProvider", "Effort"]

#: Matches `LLMConfig.effort`. `xhigh` and `max` need `max_tokens` >= 64000 or the response
#: truncates mid-thought; `max_tokens` belongs to the caller, so this adapter cannot enforce it.
Effort = Literal["low", "medium", "high", "xhigh", "max"]

#: Task budgets are still behind a beta header, so a budgeted call goes to the beta endpoint
#: and an unbudgeted one does not. Nothing else about the request differs.
_TASK_BUDGET_BETA = "task-budgets-2026-03-13"
_MIN_TASK_BUDGET_TOKENS = 20_000

#: Anthropic reports more stop reasons than the seam models, because most of the extra ones
#: are not decisions the investigation makes differently. `stop_sequence` is the model
#: finishing on a boundary the caller set, which is an ordinary end of turn;
#: `model_context_window_exceeded` is the same problem as `max_tokens` from the caller's side
#: -- the answer was cut short and the history has to shrink before retrying.
_STOP_REASONS: dict[str, StopReason] = {
    "end_turn": "end_turn",
    "stop_sequence": "end_turn",
    "tool_use": "tool_use",
    "max_tokens": "max_tokens",
    "model_context_window_exceeded": "max_tokens",
    "refusal": "refusal",
}

#: Errors that are worth another attempt later and are therefore let through as themselves,
#: so a caller with its own backoff can catch the typed error. The SDK has already exhausted
#: its own retries by the time one of these surfaces. 5xx statuses are added by status code
#: rather than by class, which covers `OverloadedError` and anything added upstream later.
_RETRYABLE: tuple[type[BaseException], ...] = (
    anthropic.RateLimitError,
    anthropic.APIConnectionError,  # includes APITimeoutError
    anthropic.RetryableError,
)


class AnthropicProvider:
    """`LLMProvider` backed by the Anthropic Messages API."""

    name = "anthropic"

    #: The model can be given a ceiling it paces itself against, so the caller does not have
    #: to rely on its tool-call cap alone.
    supports_task_budget = True

    def __init__(
        self,
        model: str,
        *,
        client: Any = None,
        effort: Effort = "high",
        max_retries: int | None = None,
    ) -> None:
        """Configure the adapter. `client` is `anthropic.Anthropic` or a stand-in for tests.

        `client` is typed loosely on purpose: the real SDK client and the recording fake the
        tests inject have no common declared type, and narrowing to the SDK class would make
        the no-network tests impossible to write.
        """
        self.model = model
        self.effort: Effort = effort
        self._client: Any = client
        self._max_retries = max_retries

    @property
    def client(self) -> Any:
        """The SDK client, built on first use.

        Constructing `anthropic.Anthropic()` resolves credentials, so doing it in `__init__`
        -- or worse, at module import -- would make importing this module fail on any machine
        without a key, including one that only ever runs the scripted provider.
        """
        if self._client is None:
            kwargs: dict[str, Any] = {}
            if self._max_retries is not None:
                kwargs["max_retries"] = self._max_retries
            self._client = anthropic.Anthropic(**kwargs)
        return self._client

    def converse(
        self,
        system: str,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        max_tokens: int = 8192,
        task_budget_tokens: int | None = None,
    ) -> Turn:
        """Send one request and translate the response into a `Turn`."""
        output_config: dict[str, Any] = {"effort": self.effort}
        betas: list[str] = []
        if task_budget_tokens is not None:
            if task_budget_tokens < _MIN_TASK_BUDGET_TOKENS:
                # Failing here rather than on the wire: the API rejects it with a 400 either
                # way, and a local error names the floor instead of making the caller read it
                # out of a request id.
                raise ProviderError(
                    f"task_budget_tokens must be at least {_MIN_TASK_BUDGET_TOKENS}, "
                    f"got {task_budget_tokens}"
                )
            output_config["task_budget"] = {"type": "tokens", "total": task_budget_tokens}
            betas.append(_TASK_BUDGET_BETA)

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": _system_blocks(system),
            "messages": [_encode_message(m) for m in messages],
            # Adaptive thinking: the model decides its own depth and interleaves thinking
            # between tool calls. `budget_tokens` is removed on current models and 400s.
            "thinking": {"type": "adaptive"},
            "output_config": output_config,
        }
        if tools:
            kwargs["tools"] = [_encode_tool(t) for t in tools]

        if betas:
            create = self.client.beta.messages.create
            kwargs["betas"] = betas
        else:
            create = self.client.messages.create

        try:
            response = create(**kwargs)
        except _RETRYABLE:
            raise
        except anthropic.APIStatusError as exc:
            if exc.status_code >= 500:
                raise
            raise ProviderError(
                f"Anthropic request failed with status {exc.status_code} for model {self.model!r}"
            ) from exc
        except anthropic.AnthropicError as exc:
            raise ProviderError(f"Anthropic request failed for model {self.model!r}") from exc

        return _decode_response(response)


def _system_blocks(system: str) -> list[dict[str, Any]]:
    """The system prompt as a cached block.

    The system prompt plus the template digest is the large stable prefix that gets re-sent on
    every step of an investigation, and it is by far the biggest thing in the request. A
    breakpoint immediately after it means every step from the second onward reads that prefix
    from cache at about a tenth of the price. It sits *after* the system prompt and before the
    conversation because the conversation grows on every step, so anything cached below it
    would be invalidated on every step anyway.

    `Usage.cached_input_tokens` is how a run reports whether this actually worked: if it stays
    at zero across steps, something in the prefix is varying and the cache never lands.
    """
    return [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]


def _encode_tool(tool: ToolSpec) -> dict[str, Any]:
    return {"name": tool.name, "description": tool.description, "input_schema": tool.schema}


def _encode_message(message: Message) -> dict[str, Any]:
    """One seam `Message` as one Anthropic message.

    Tool results are emitted first within a user turn, which is the order the API requires,
    and all of them go into this one message -- that is what keeps parallel tool use intact.
    Splitting them across messages would break the correlation the model expects.
    """
    content: list[dict[str, Any]] = [_encode_tool_result(r) for r in message.tool_results]
    if message.text:
        content.append({"type": "text", "text": message.text})
    content.extend(_encode_tool_call(c) for c in message.tool_calls)

    if not content:
        # The API rejects an empty content list, and dropping the message instead would
        # silently change the conversation the model sees.
        raise ProviderError(
            f"{message.role} message has no text, tool calls or tool results to send"
        )
    return {"role": message.role, "content": content}


def _encode_tool_call(call: ToolCall) -> dict[str, Any]:
    return {"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments}


def _encode_tool_result(result: ToolResult) -> dict[str, Any]:
    return {
        "type": "tool_result",
        "tool_use_id": result.call_id,
        "content": result.content,
        "is_error": result.is_error,
    }


def _decode_response(response: Any) -> Turn:
    """An Anthropic response as a `Turn`.

    Thinking blocks are dropped: the seam has nowhere to put them and the caller never sends
    them back, so the model re-derives its reasoning each step. That is a real cost, and the
    place to fix it is the seam, not here.
    """
    texts: list[str] = []
    tool_calls: list[ToolCall] = []
    for block in getattr(response, "content", None) or []:
        block_type = getattr(block, "type", None)
        if block_type == "text":
            texts.append(str(block.text))
        elif block_type == "tool_use":
            tool_calls.append(_decode_tool_use(block))

    return Turn(
        text="\n".join(texts),
        tool_calls=tuple(tool_calls),
        stop_reason=_decode_stop_reason(getattr(response, "stop_reason", None)),
        usage=_decode_usage(getattr(response, "usage", None)),
    )


def _decode_tool_use(block: Any) -> ToolCall:
    arguments = block.input
    if not isinstance(arguments, Mapping):
        raise ProviderError(
            f"tool_use block {getattr(block, 'id', '?')!r} carried "
            f"{type(arguments).__name__} arguments, expected an object"
        )
    return ToolCall(id=str(block.id), name=str(block.name), arguments=dict(arguments))


def _decode_stop_reason(raw: Any) -> StopReason:
    """Map the vendor's stop reason, refusing to guess at ones the seam cannot express.

    `pause_turn` is the notable unmapped case: it means a server-side tool ran out of
    iterations mid-turn and the request should be re-sent to continue. The seam has no way to
    say "unfinished", so reporting it as `end_turn` would hand the caller a truncated answer
    dressed up as a complete one. This adapter offers no server-side tools, so it should not
    occur; if it ever does, it should be loud.
    """
    if isinstance(raw, str) and raw in _STOP_REASONS:
        return _STOP_REASONS[raw]
    raise ProviderError(f"unsupported stop_reason from Anthropic: {raw!r}")


def _decode_usage(raw: Any) -> Usage:
    """Token counts, normalised to the seam's contract: cached is a *subset* of input.

    Anthropic reports three disjoint numbers -- fresh input, cache writes and cache reads --
    so all three are summed into `input_tokens`, and cache reads are additionally reported as
    `cached_input_tokens`. Gemini's `prompt_token_count` is already inclusive, which is the
    shape `Usage` documents, so this is the adapter that has to do the work.

    Leaving cache reads out of `input_tokens` (as this did before there was anything totalling
    them) makes a cached run look cheaper than it was, by exactly the tokens the cache served.

    Cache *creation* is not folded into `cached_input_tokens`: it is billed at a premium
    rather than served cheaply, and counting it as cached would make a run that rewrites its
    cache every step look like a run that is reading one.
    """
    if raw is None:
        return Usage()
    cache_read = _as_int(getattr(raw, "cache_read_input_tokens", 0))
    return Usage(
        input_tokens=_as_int(getattr(raw, "input_tokens", 0))
        + _as_int(getattr(raw, "cache_creation_input_tokens", 0))
        + cache_read,
        output_tokens=_as_int(getattr(raw, "output_tokens", 0)),
        cached_input_tokens=cache_read,
    )


def _as_int(value: Any) -> int:
    """Usage fields are optional on the wire and arrive as `None` when absent."""
    return int(value) if isinstance(value, int) else 0

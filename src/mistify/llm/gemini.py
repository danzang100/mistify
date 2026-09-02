"""Gemini adapter for the provider seam.

Four things differ from the seam's shape enough to be worth naming, because each one is a
place where a naive translation produces a loop that looks fine and behaves wrong.

**Tool calls do not change the finish reason.** Gemini returns `STOP` whether or not it asked
for a tool, so tool use is detected by the presence of `function_call` parts. Mapping
`finish_reason` straight onto the seam's `StopReason` would end every investigation on its
first tool call.

**Function responses are keyed by name, not by call id.** The seam correlates a result to a
call with an id, as most vendors do; Gemini matches on the function name instead. The adapter
rebuilds an id-to-name map by walking the conversation each time it translates -- stateless,
and correct even when the caller replays a history the adapter never produced.

**`additionalProperties` is rejected.** Otherwise standard JSON Schema is accepted as-is, so
schemas are sanitised rather than rewritten into Gemini's uppercase dialect.

**There are no task budgets.** `supports_task_budget` is False, so the loop falls back to its
own tool-call cap. Free-tier quotas are tight enough that a 429 mid-investigation is routine
rather than exceptional, which is why retry with backoff lives here instead of being left to
the caller.
"""

from __future__ import annotations

import os
import random
import re
import time
from typing import TYPE_CHECKING, Any

from mistify.llm.base import (
    Message,
    ProviderError,
    StopReason,
    ToolCall,
    ToolSpec,
    Turn,
    Usage,
)

if TYPE_CHECKING:  # pragma: no cover - the SDK is imported lazily
    from google.genai import Client

__all__ = ["GeminiProvider", "http_options"]

#: JSON Schema keywords the Gemini function-declaration parser rejects outright. Everything
#: else in a standard schema is accepted, so this is a deny list rather than a translation.
_UNSUPPORTED_SCHEMA_KEYS = frozenset(
    {"additionalProperties", "$schema", "$id", "definitions", "$defs", "examples"}
)

#: Retryable failures, recognised two ways because they arrive two ways. The GenAI SDK raises
#: `ClientError`/`ServerError` carrying an HTTP `code`; wrappers elsewhere in Google's stack
#: raise typed exceptions (`ResourceExhausted`, `DeadlineExceeded`) whose message says nothing
#: and whose only signal is the class name.
_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})

#: Matched against the type name and message with punctuation removed, so `RESOURCE_EXHAUSTED`
#: on the wire and `ResourceExhausted` as a class name are the same marker.
_RETRYABLE_MARKERS = (
    "RESOURCEEXHAUSTED",
    "UNAVAILABLE",
    "DEADLINEEXCEEDED",
    "TOOMANYREQUESTS",
    "429",
    "503",
)

_PUNCTUATION = re.compile(r"[^A-Z0-9]")

#: Google returns a RetryInfo telling you exactly how long the quota window has left, e.g.
#: `'retryDelay': '54s'`. Ignoring it and backing off on a guess is how a retry budget gets
#: spent entirely inside a window that had not reset yet.
_RETRY_DELAY = re.compile(r"retryDelay['\"]?\s*:\s*['\"]?(\d+(?:\.\d+)?)s")


def http_options(timeout_seconds: float) -> Any:
    """Transport options for the SDK client.

    Split out so the seconds-to-milliseconds conversion is testable without a credential or a
    fake SDK: getting that factor wrong gives a 120-millisecond timeout that fails every call,
    or a 120,000-second one that fails none.
    """
    from google.genai import types

    return types.HttpOptions(timeout=int(timeout_seconds * 1000))


def _advertised_delay(exc: Exception) -> float | None:
    """Seconds the API asked us to wait, when it said so.

    Free-tier quotas are per-minute, so the wait is routinely longer than any exponential
    schedule reaches in the retries available. Honouring the server's own number is the
    difference between recovering and failing the investigation while the quota was about to
    reset anyway.
    """
    match = _RETRY_DELAY.search(str(exc))
    return float(match.group(1)) if match else None


def _sanitise_schema(schema: Any) -> Any:
    """Strip keywords Gemini refuses, recursively, leaving the rest of the schema intact."""
    if isinstance(schema, dict):
        return {
            key: _sanitise_schema(value)
            for key, value in schema.items()
            if key not in _UNSUPPORTED_SCHEMA_KEYS
        }
    if isinstance(schema, list):
        return [_sanitise_schema(item) for item in schema]
    return schema


class GeminiProvider:
    """Talks to Gemini through the Google GenAI SDK."""

    supports_task_budget = False

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        client: Client | None = None,
        max_retries: int = 5,
        min_interval_seconds: float = 0.0,
        timeout_seconds: float = 120.0,
        sleep: Any = time.sleep,
    ) -> None:
        self.name = "gemini"
        self.model = model
        self._client = client
        self._api_key = api_key
        self.max_retries = max_retries
        #: Enforced spacing between calls. Free-tier limits are per-minute, so a caller who
        #: knows theirs can trade wall clock for never being throttled; the default leaves
        #: pacing to the retry path, which is faster when the limit is generous.
        self.min_interval_seconds = min_interval_seconds
        #: Ceiling on one request. Without it the SDK waits forever: an investigation was seen
        #: blocked in a single call for over thirty minutes at zero CPU, having already
        #: finished its search, because nothing bounded the wait. A timeout turns that into a
        #: DEADLINE_EXCEEDED, which `_is_retryable` already treats as worth another attempt --
        #: the retry path existed and was simply unreachable.
        self.timeout_seconds = timeout_seconds
        self._sleep = sleep
        self._last_call_at = 0.0

    @property
    def client(self) -> Client:
        """Built on first use, so importing this module needs no credential."""
        if self._client is None:
            from google import genai

            key = (
                self._api_key
                or os.environ.get("GEMINI_API_KEY")
                or os.environ.get("GOOGLE_API_KEY")
            )
            if not key:
                raise ProviderError(
                    "No Gemini credential found. Set GEMINI_API_KEY (a .env file at the repo "
                    "root is loaded automatically)."
                )
            # Set on the client rather than per call, so every request is bounded -- including
            # ones added later that forget to ask for it.
            self._client = genai.Client(
                api_key=key, http_options=http_options(self.timeout_seconds)
            )
        return self._client

    # ---------------------------------------------------------------- translation

    @staticmethod
    def _call_names(messages: list[Message]) -> dict[str, str]:
        """Map tool-call id to function name by walking the conversation.

        Gemini matches a response to a call by name, and the seam addresses it by id. Rebuilt
        per translation rather than remembered, so replaying a history this adapter did not
        produce still works.
        """
        return {call.id: call.name for message in messages for call in message.tool_calls}

    def _to_contents(self, messages: list[Message]) -> list[Any]:
        from google.genai import types

        names = self._call_names(messages)
        contents: list[Any] = []
        for message in messages:
            parts: list[Any] = []
            if message.text:
                parts.append(types.Part(text=message.text))
            for call in message.tool_calls:
                # The thought signature must come back exactly as it was issued. Without it
                # the API rejects the whole request rather than degrading quietly.
                parts.append(
                    types.Part(
                        function_call=types.FunctionCall(name=call.name, args=call.arguments),
                        thought_signature=call.signature,
                    )
                )
            for outcome in message.tool_results:
                payload = (
                    {"error": outcome.content} if outcome.is_error else {"result": outcome.content}
                )
                parts.append(
                    types.Part(
                        function_response=types.FunctionResponse(
                            name=names.get(outcome.call_id, outcome.call_id), response=payload
                        )
                    )
                )
            if not parts:
                continue
            # Gemini names the assistant "model"; the seam calls it "assistant".
            role = "model" if message.role == "assistant" else "user"
            contents.append(types.Content(role=role, parts=parts))
        return contents

    @staticmethod
    def _to_tools(tools: list[ToolSpec] | None) -> list[Any] | None:
        if not tools:
            return None
        from google.genai import types

        return [
            types.Tool(
                function_declarations=[
                    types.FunctionDeclaration(
                        name=spec.name,
                        description=spec.description,
                        parameters=_sanitise_schema(spec.schema),
                    )
                    for spec in tools
                ]
            )
        ]

    @staticmethod
    def _stop_reason(candidate: Any, tool_calls: tuple[ToolCall, ...]) -> StopReason:
        """Gemini reports STOP even when it asked for a tool, so parts decide, not the reason."""
        if tool_calls:
            return "tool_use"
        reason = str(getattr(candidate, "finish_reason", "") or "").upper()
        if "MAX_TOKENS" in reason:
            return "max_tokens"
        if "SAFETY" in reason or "BLOCK" in reason or "PROHIBITED" in reason:
            return "refusal"
        return "end_turn"

    @staticmethod
    def _usage(response: Any) -> Usage:
        """Token counts, which already match the seam's contract.

        `prompt_token_count` is the whole prompt including whatever was served from cache, and
        `cached_content_token_count` is that subset -- which is exactly what `Usage` documents,
        so nothing is added or subtracted here -- an adapter for a vendor that reports the
        cached portion separately would be the one doing the adding. Fields are read
        defensively because the API omits them on blocked responses and sends explicit nulls
        when nothing was generated.
        """
        meta = getattr(response, "usage_metadata", None)
        if meta is None:
            return Usage()
        return Usage(
            input_tokens=int(getattr(meta, "prompt_token_count", 0) or 0),
            output_tokens=int(getattr(meta, "candidates_token_count", 0) or 0),
            cached_input_tokens=int(getattr(meta, "cached_content_token_count", 0) or 0),
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
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=system or None,
            tools=self._to_tools(tools),
            max_output_tokens=max_tokens,
            # We run the loop; the SDK must not. Left enabled it would execute tools itself
            # and return only the final answer, which would take the audit trail, the
            # tool-call budget and the forced-convergence path out of our hands.
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        response = self._send(self._to_contents(messages), config)

        candidates = getattr(response, "candidates", None) or []
        if not candidates:
            # A response with no candidate is a block, not an empty answer. Reporting it as
            # end_turn would present a refusal as a finished conclusion.
            return Turn(text="", stop_reason="refusal", usage=self._usage(response))

        candidate = candidates[0]
        parts = list(getattr(getattr(candidate, "content", None), "parts", None) or [])
        text = "".join(part.text for part in parts if getattr(part, "text", None))
        calls = tuple(
            ToolCall(
                id=f"{part.function_call.name}-{index}",
                name=part.function_call.name,
                arguments=dict(part.function_call.args or {}),
                signature=getattr(part, "thought_signature", None),
            )
            for index, part in enumerate(parts)
            if getattr(part, "function_call", None)
        )
        return Turn(
            text=text,
            tool_calls=calls,
            stop_reason=self._stop_reason(candidate, calls),
            usage=self._usage(response),
        )

    def _send(self, contents: list[Any], config: Any) -> Any:
        """One request, retrying the throttling the free tier hands out routinely."""
        for attempt in range(self.max_retries + 1):
            self._space_out()
            try:
                return self.client.models.generate_content(
                    model=self.model, contents=contents, config=config
                )
            except Exception as exc:
                if attempt >= self.max_retries or not self._is_retryable(exc):
                    raise ProviderError(f"Gemini call failed: {exc}") from exc
                # Full jitter: a loop that retries on a fixed schedule marches its own
                # retries into the next rate-limit window together.
                delay = min(2**attempt, 30) * (0.5 + random.random() / 2)
                # The server knows when the window resets and says so. Backing off for less
                # than that guarantees the next attempt fails too, which is how five retries
                # get spent inside one 60-second quota window.
                advertised = _advertised_delay(exc)
                if advertised is not None:
                    delay = max(delay, advertised + random.random())
                self._sleep(delay)
        raise ProviderError("unreachable: retry loop exited without returning")

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        """Is another attempt worth making?

        The status code is checked first because it is the only unambiguous signal; the text
        match is the fallback for errors that never carry one.
        """
        code = getattr(exc, "code", None)
        if isinstance(code, int) and code in _RETRYABLE_STATUS:
            return True
        text = _PUNCTUATION.sub("", f"{type(exc).__name__} {exc}".upper())
        return any(marker in text for marker in _RETRYABLE_MARKERS)

    def _space_out(self) -> None:
        if self.min_interval_seconds <= 0:
            return
        elapsed = time.monotonic() - self._last_call_at
        if elapsed < self.min_interval_seconds:
            self._sleep(self.min_interval_seconds - elapsed)
        self._last_call_at = time.monotonic()

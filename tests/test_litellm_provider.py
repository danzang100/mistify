"""The LiteLLM adapter, tested against a fake `completion` -- no credential, no network.

The shapes the fake returns are the ones LiteLLM returned for a real Gemini tool-call round
trip on 2026-09-23, including the thought signature carried inside the tool-call id. The
registry tests at the bottom import LiteLLM itself, which is an optional extra.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from mistify.common.config import LLMConfig
from mistify.llm.base import (
    LLMProvider,
    Message,
    ProviderError,
    ToolCall,
    ToolResult,
    ToolSpec,
)
from mistify.llm.litellm_provider import LiteLLMProvider

MODEL = "gemini/gemini-3.5-flash-lite"
SIGNED_ID = "call_197036__thought__El4KXAFpFH0TMThA"
SIGNATURE = {"thought_signature": "El4KXAFpFH0TMThA"}

SEARCH_TOOL = ToolSpec(
    name="search_logs",
    description="Search the log slice.",
    schema={
        "type": "object",
        "properties": {"q": {"type": "string"}},
        "required": ["q"],
        "additionalProperties": False,
    },
)


def _response(
    *,
    content: str | None = None,
    tool_calls: list[dict[str, Any]] | None = None,
    finish_reason: str = "stop",
    usage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "choices": [
            {
                "finish_reason": finish_reason,
                "message": {"role": "assistant", "content": content, "tool_calls": tool_calls},
            }
        ],
        "usage": usage or {"prompt_tokens": 58, "completion_tokens": 18},
    }


def _signed_call(arguments: str = '{"q": "timeout"}') -> dict[str, Any]:
    return {
        "id": SIGNED_ID,
        "type": "function",
        "function": {"name": "search_logs", "arguments": arguments},
        "provider_specific_fields": SIGNATURE,
    }


class _FakeCompletion:
    """Returns (or raises) each outcome in turn and records every request."""

    def __init__(self, *outcomes: Any) -> None:
        self.outcomes = list(outcomes)
        self.requests: list[dict[str, Any]] = []

    def __call__(self, **request: Any) -> Any:
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _provider(*outcomes: Any, **kwargs: Any) -> tuple[LiteLLMProvider, _FakeCompletion]:
    fake = _FakeCompletion(*outcomes)
    return LiteLLMProvider(MODEL, completion=fake, sleep=lambda _s: None, **kwargs), fake


# ------------------------------------------------------------------ the seam


def test_it_satisfies_the_protocol_and_declares_no_task_budget() -> None:
    provider, _ = _provider()
    assert isinstance(provider, LLMProvider)
    assert provider.supports_task_budget is False
    assert (provider.name, provider.model) == ("litellm", MODEL)


def test_the_request_bounds_itself_and_leaves_retries_to_the_adapter() -> None:
    provider, fake = _provider(_response(content="done"), timeout_seconds=30)
    provider.converse("system", [Message(role="user", text="go")], max_tokens=512)

    request = fake.requests[0]
    assert request["timeout"] == 30
    assert request["num_retries"] == 0
    assert request["max_tokens"] == 512
    assert request["model"] == MODEL


# ------------------------------------------------------------------ outbound translation


def test_system_prompt_leads_and_tools_are_offered_as_functions() -> None:
    provider, fake = _provider(_response(content="done"))
    provider.converse("be careful", [Message(role="user", text="go")], tools=[SEARCH_TOOL])

    request = fake.requests[0]
    assert request["messages"][0] == {"role": "system", "content": "be careful"}
    assert request["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "search_logs",
                "description": "Search the log slice.",
                "parameters": SEARCH_TOOL.schema,
            },
        }
    ]


def test_no_tools_key_is_sent_when_none_are_offered() -> None:
    provider, fake = _provider(_response(content="done"))
    provider.converse("system", [Message(role="user", text="go")])
    assert "tools" not in fake.requests[0]


def test_tool_call_ids_and_signatures_go_back_verbatim() -> None:
    """The thought signature rides inside the id. A regenerated id loses it without an error.

    Measured 2026-09-23: Gemini accepted a replayed history with the signatures stripped, so
    this test is the only thing that would notice them being dropped.
    """
    provider, fake = _provider(_response(tool_calls=[_signed_call()]), _response(content="done"))
    first = provider.converse("system", [Message(role="user", text="go")], tools=[SEARCH_TOOL])
    call = first.tool_calls[0]

    history = [
        Message(role="user", text="go"),
        Message(role="assistant", tool_calls=first.tool_calls),
        Message(role="user", tool_results=(ToolResult(call_id=call.id, content="pool exhausted"),)),
    ]
    provider.converse("system", history, tools=[SEARCH_TOOL])

    replayed = fake.requests[1]["messages"]
    assistant = replayed[2]
    assert assistant["tool_calls"][0]["id"] == SIGNED_ID
    assert assistant["tool_calls"][0]["provider_specific_fields"] == SIGNATURE
    assert json.loads(assistant["tool_calls"][0]["function"]["arguments"]) == {"q": "timeout"}
    assert replayed[3] == {"role": "tool", "tool_call_id": SIGNED_ID, "content": "pool exhausted"}


def test_each_result_is_its_own_tool_message_before_any_text() -> None:
    provider, fake = _provider(_response(content="done"))
    calls = (
        ToolCall(id="a", name="search_logs", arguments={"q": "x"}),
        ToolCall(id="b", name="search_logs", arguments={"q": "y"}),
    )
    history = [
        Message(role="assistant", tool_calls=calls),
        Message(
            role="user",
            text="You have one call left.",
            tool_results=(
                ToolResult(call_id="a", content="rows"),
                ToolResult(call_id="b", content="bad enum", is_error=True),
            ),
        ),
    ]
    provider.converse("", history)

    sent = fake.requests[0]["messages"]
    assert [m["role"] for m in sent] == ["assistant", "tool", "tool", "user"]
    assert sent[1] == {"role": "tool", "tool_call_id": "a", "content": "rows"}
    assert sent[2] == {"role": "tool", "tool_call_id": "b", "content": "ERROR: bad enum"}
    assert sent[3] == {"role": "user", "content": "You have one call left."}


def test_an_empty_assistant_message_is_not_sent() -> None:
    provider, fake = _provider(_response(content="done"))
    provider.converse("", [Message(role="assistant"), Message(role="user", text="go")])
    assert [m["role"] for m in fake.requests[0]["messages"]] == ["user"]


# ------------------------------------------------------------------ inbound translation


def test_a_tool_call_is_tool_use_even_when_the_backend_says_stop() -> None:
    """Some local servers report `stop` alongside a tool call; parts decide, as for Gemini."""
    provider, _ = _provider(_response(tool_calls=[_signed_call()], finish_reason="stop"))
    turn = provider.converse("system", [Message(role="user", text="go")], tools=[SEARCH_TOOL])

    assert turn.stop_reason == "tool_use"
    assert turn.tool_calls == (
        ToolCall(id=SIGNED_ID, name="search_logs", arguments={"q": "timeout"}, signature=SIGNATURE),
    )


@pytest.mark.parametrize(
    ("finish_reason", "expected"),
    [("stop", "end_turn"), ("length", "max_tokens"), ("content_filter", "refusal")],
)
def test_finish_reasons_map_onto_the_seam(finish_reason: str, expected: str) -> None:
    provider, _ = _provider(_response(content="text", finish_reason=finish_reason))
    turn = provider.converse("system", [Message(role="user", text="go")])
    assert turn.stop_reason == expected
    assert turn.text == "text"


def test_no_choices_is_a_refusal_not_an_empty_conclusion() -> None:
    provider, _ = _provider({"choices": [], "usage": {"prompt_tokens": 10}})
    turn = provider.converse("system", [Message(role="user", text="go")])
    assert turn.stop_reason == "refusal"
    assert turn.usage.input_tokens == 10


def test_null_arguments_are_an_empty_call() -> None:
    provider, _ = _provider(_response(tool_calls=[_signed_call(arguments="null")]))
    turn = provider.converse("system", [Message(role="user", text="go")], tools=[SEARCH_TOOL])
    assert turn.tool_calls[0].arguments == {}


@pytest.mark.parametrize("arguments", ['{"q": "timeout"', '["timeout"]'])
def test_arguments_that_are_not_a_json_object_are_refused_by_name(arguments: str) -> None:
    provider, _ = _provider(_response(tool_calls=[_signed_call(arguments=arguments)]))
    with pytest.raises(ProviderError, match=r"search_logs.*not a JSON object"):
        provider.converse("system", [Message(role="user", text="go")], tools=[SEARCH_TOOL])


def test_cached_tokens_are_a_subset_of_input_not_added_to_it() -> None:
    usage = {
        "prompt_tokens": 1000,
        "completion_tokens": 50,
        "prompt_tokens_details": {"cached_tokens": 800},
    }
    provider, _ = _provider(_response(content="x", usage=usage))
    turn = provider.converse("system", [Message(role="user", text="go")])

    assert (turn.usage.input_tokens, turn.usage.cached_input_tokens) == (1000, 800)
    assert turn.usage.total_tokens == 1050


def test_anthropic_style_cache_reads_are_read_when_the_openai_field_is_absent() -> None:
    usage = {"prompt_tokens": 1000, "completion_tokens": 50, "cache_read_input_tokens": 700}
    provider, _ = _provider(_response(content="x", usage=usage))
    turn = provider.converse("system", [Message(role="user", text="go")])
    assert turn.usage.cached_input_tokens == 700
    assert turn.usage.input_tokens == 1000


# ------------------------------------------------------------------ retries


class RateLimitError(Exception):
    """Named like LiteLLM's, which is how the adapter recognises it."""


class BadRequestError(Exception):
    status_code = 400


def test_a_rate_limit_is_retried_honouring_the_advertised_delay() -> None:
    slept: list[float] = []
    fake = _FakeCompletion(RateLimitError("quota. 'retryDelay': '40s'"), _response(content="ok"))
    provider = LiteLLMProvider(MODEL, completion=fake, sleep=slept.append)

    turn = provider.converse("system", [Message(role="user", text="go")])

    assert turn.text == "ok"
    assert len(fake.requests) == 2
    assert slept and slept[0] >= 40


def test_a_bad_request_is_not_retried() -> None:
    """The control for the retry test: the same path, a non-retryable error, one attempt."""
    provider, fake = _provider(BadRequestError("schema rejected"), _response(content="unused"))
    with pytest.raises(ProviderError, match="schema rejected"):
        provider.converse("system", [Message(role="user", text="go")])
    assert len(fake.requests) == 1


def test_a_retryable_status_code_is_retried() -> None:
    error = BadRequestError("overloaded")
    error.status_code = 503
    provider, fake = _provider(error, _response(content="ok"))
    assert provider.converse("system", [Message(role="user", text="go")]).text == "ok"
    assert len(fake.requests) == 2


# ------------------------------------------------------------------ config and registry


def test_the_same_model_reached_through_two_providers_is_not_an_independent_critic() -> None:
    with pytest.raises(ValueError, match="same model"):
        LLMConfig(
            provider="litellm",
            model="gemini/gemini-3.5-flash-lite",
            synthesis_model=None,
            adversarial_provider="gemini",
            adversarial_model="gemini-3.5-flash-lite",
        )


def test_different_models_across_providers_are_accepted() -> None:
    """The control: the rule refuses a shared model, not a mix of providers."""
    config = LLMConfig(
        provider="litellm",
        model="gemini/gemini-3.5-flash-lite",
        synthesis_model=None,
        adversarial_provider="gemini",
        adversarial_model="gemini-3.5-flash",
    )
    assert config.adversarial_provider_name() == "gemini"


def test_a_missing_vendor_key_is_refused_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("litellm")
    from mistify.llm.registry import MissingCredentialError, build_provider

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(MissingCredentialError, match="ANTHROPIC_API_KEY"):
        build_provider("litellm", "anthropic/claude-sonnet-5", LLMConfig())


def test_a_local_ollama_model_needs_no_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("litellm")
    from mistify.llm.registry import build_provider

    monkeypatch.delenv("OLLAMA_API_BASE", raising=False)
    provider = build_provider("litellm", "ollama_chat/qwen3:8b", LLMConfig())
    assert isinstance(provider, LiteLLMProvider)
    assert provider.model == "ollama_chat/qwen3:8b"


def test_the_registry_passes_timeout_and_spacing_through(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("litellm")
    from mistify.llm.registry import build_provider

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    config = LLMConfig(request_timeout_seconds=45, min_interval_seconds=2)
    provider = build_provider("litellm", MODEL, config)
    assert isinstance(provider, LiteLLMProvider)
    assert (provider.timeout_seconds, provider.min_interval_seconds) == (45, 2)


def test_a_tool_call_cut_off_by_the_output_ceiling_says_so() -> None:
    """Truncated JSON under finish_reason `length` is a ceiling, not an incapable model."""
    provider, _ = _provider(
        _response(tool_calls=[_signed_call(arguments='{"q": "time')], finish_reason="length")
    )
    with pytest.raises(ProviderError, match=r"Raise llm.max_tokens"):
        provider.converse("system", [Message(role="user", text="go")], tools=[SEARCH_TOOL])


def test_bad_arguments_without_truncation_still_blame_the_model() -> None:
    """The control: the same bad JSON with a normal finish keeps the capability message."""
    provider, _ = _provider(
        _response(tool_calls=[_signed_call(arguments='{"q": "time')], finish_reason="tool_calls")
    )
    with pytest.raises(ProviderError, match="try a larger model"):
        provider.converse("system", [Message(role="user", text="go")], tools=[SEARCH_TOOL])


class APIConnectionError(Exception):
    """Named like LiteLLM's."""


def test_a_refused_local_connection_fails_at_once_with_a_hint() -> None:
    fake = _FakeCompletion(
        APIConnectionError("[WinError 10061] the target machine actively refused it"),
        _response(content="unused"),
    )
    provider = LiteLLMProvider("ollama_chat/qwen3:8b", completion=fake, sleep=lambda _s: None)

    with pytest.raises(ProviderError, match="is the local server running"):
        provider.converse("system", [Message(role="user", text="go")])
    assert len(fake.requests) == 1


def test_a_dropped_connection_is_still_retried() -> None:
    """The control: a connection error that is not a refusal keeps its retries."""
    fake = _FakeCompletion(
        APIConnectionError("Server disconnected without sending a response."),
        _response(content="ok"),
    )
    provider = LiteLLMProvider("ollama_chat/qwen3:8b", completion=fake, sleep=lambda _s: None)

    assert provider.converse("system", [Message(role="user", text="go")]).text == "ok"
    assert len(fake.requests) == 2


def test_a_gateway_status_is_retried_whatever_its_body_says() -> None:
    """Found in review: a 502 whose body mentions a refused upstream was not retried."""
    error = APIConnectionError("upstream connect error: connection refused")
    error.status_code = 502  # type: ignore[attr-defined]
    fake = _FakeCompletion(error, _response(content="ok"))
    provider = LiteLLMProvider(MODEL, completion=fake, sleep=lambda _s: None)

    assert provider.converse("system", [Message(role="user", text="go")]).text == "ok"
    assert len(fake.requests) == 2


def test_the_local_server_hint_is_only_for_a_refused_connection() -> None:
    """The control for the hint: a running server missing the model gets no such advice."""
    fake = _FakeCompletion(BadRequestError("model 'qwen3:8b' not found, try pulling it first"))
    provider = LiteLLMProvider("ollama_chat/qwen3:8b", completion=fake, sleep=lambda _s: None)

    with pytest.raises(ProviderError) as caught:
        provider.converse("system", [Message(role="user", text="go")])
    assert "not found" in str(caught.value)
    assert "local server running" not in str(caught.value)

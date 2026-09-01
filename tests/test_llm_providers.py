"""Both provider adapters, tested without a credential or a network.

`AnthropicProvider` is exercised through an injected fake client that records the kwargs it
was handed and returns a canned response, so every assertion here is about *translation* --
the one thing this project owns on that side of the seam. Nothing in this module may reach the
network or read `ANTHROPIC_API_KEY`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import anthropic
import httpx2
import pytest

from mistify.llm.anthropic import AnthropicProvider
from mistify.llm.base import (
    LLMProvider,
    Message,
    ProviderError,
    ToolCall,
    ToolResult,
    ToolSpec,
    Turn,
    Usage,
)
from mistify.llm.scripted import ScriptedProvider, text_turn, tool_call_turn

SEARCH_TOOL = ToolSpec(
    name="search_logs",
    description="Search the log slice.",
    schema={"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]},
)


# ------------------------------------------------------------------ fake Anthropic client


@dataclass
class _Block:
    """One content block, exposing only the attributes the adapter reads."""

    type: str
    text: str = ""
    id: str = ""
    name: str = ""
    input: Any = None


@dataclass
class _FakeUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


@dataclass
class _FakeResponse:
    content: list[_Block]
    stop_reason: str | None = "end_turn"
    usage: _FakeUsage = field(default_factory=_FakeUsage)


class _Recorder:
    """Stands in for `client.messages` / `client.beta.messages`.

    Both endpoints record into the same list on the parent client, so a test can assert which
    one was used without caring how the adapter reached it.
    """

    def __init__(self, client: _FakeClient, endpoint: str) -> None:
        self._client = client
        self._endpoint = endpoint

    def create(self, **kwargs: Any) -> Any:
        self._client.calls.append((self._endpoint, kwargs))
        if self._client.raises is not None:
            raise self._client.raises
        return self._client.response


class _FakeClient:
    def __init__(self, response: Any = None, raises: BaseException | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.response = response if response is not None else _FakeResponse(content=[])
        self.raises = raises
        self.messages = _Recorder(self, "messages")
        self.beta = _Beta(self)

    @property
    def last_kwargs(self) -> dict[str, Any]:
        return self.calls[-1][1]

    @property
    def last_endpoint(self) -> str:
        return self.calls[-1][0]


class _Beta:
    def __init__(self, client: _FakeClient) -> None:
        self.messages = _Recorder(client, "beta.messages")


def _provider(response: Any = None, raises: BaseException | None = None) -> AnthropicProvider:
    return AnthropicProvider("claude-opus-5", client=_FakeClient(response, raises))


def _client_of(provider: AnthropicProvider) -> _FakeClient:
    client = provider.client
    assert isinstance(client, _FakeClient)
    return client


def _status_error(status: int) -> anthropic.APIStatusError:
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    return anthropic.APIStatusError(
        "boom", response=httpx2.Response(status_code=status, request=request), body=None
    )


# ------------------------------------------------------------------ the seam itself


def test_both_adapters_satisfy_the_protocol() -> None:
    assert isinstance(ScriptedProvider([]), LLMProvider)
    assert isinstance(AnthropicProvider("claude-opus-5", client=_FakeClient()), LLMProvider)


def test_only_anthropic_claims_task_budget_support() -> None:
    """The capability is declared, not assumed -- the caller branches on it."""
    assert AnthropicProvider("claude-opus-5", client=_FakeClient()).supports_task_budget is True
    assert ScriptedProvider([]).supports_task_budget is False
    assert ScriptedProvider([], supports_task_budget=True).supports_task_budget is True


# ------------------------------------------------------------------ ScriptedProvider: replay


def test_scripted_returns_turns_in_order() -> None:
    script = [
        tool_call_turn("search_logs", {"q": "timeout"}, call_id="call-a"),
        tool_call_turn("search_logs", {"q": "retry"}, call_id="call-b"),
        text_turn("The checkout service exhausted its connection pool."),
    ]
    provider = ScriptedProvider(script)

    got = [provider.converse("system", []) for _ in script]

    assert got == script
    assert provider.remaining == 0


def test_scripted_raises_once_the_script_runs_out() -> None:
    """A loop that asks for a turn the test never wrote has not stopped when the test thought."""
    provider = ScriptedProvider([text_turn("done")])
    provider.converse("system", [])

    with pytest.raises(ProviderError, match="ran out of script"):
        provider.converse("system", [])


def test_scripted_records_the_call_that_ran_off_the_end() -> None:
    """The over-run request is the evidence of why the loop kept going, so it is kept."""
    provider = ScriptedProvider([])

    with pytest.raises(ProviderError):
        provider.converse("system", [Message(role="user", text="go")], max_tokens=99)

    assert len(provider.calls) == 1
    assert provider.calls[0].max_tokens == 99


def test_scripted_helpers_build_the_two_common_turns() -> None:
    calling = tool_call_turn("search_logs", {"q": "timeout"}, call_id="call-a", text="Looking.")
    assert calling.stop_reason == "tool_use"
    assert calling.wants_tools
    assert calling.tool_calls == (
        ToolCall(id="call-a", name="search_logs", arguments={"q": "timeout"}),
    )
    assert calling.text == "Looking."

    ending = text_turn("Root cause: pool exhaustion.", usage=Usage(input_tokens=10))
    assert ending.stop_reason == "end_turn"
    assert not ending.wants_tools
    assert ending.usage == Usage(input_tokens=10)


# ------------------------------------------------------------------ ScriptedProvider: recording


def test_scripted_records_what_it_was_asked() -> None:
    provider = ScriptedProvider([text_turn("done")])
    history = [
        Message(role="user", text="investigate"),
        Message(
            role="user",
            tool_results=(ToolResult(call_id="call-a", content="3 rows"),),
        ),
    ]

    provider.converse(
        "SYSTEM PROMPT",
        history,
        tools=[SEARCH_TOOL],
        max_tokens=4096,
        task_budget_tokens=40_000,
    )

    call = provider.calls[0]
    assert call.system == "SYSTEM PROMPT"
    assert call.messages == tuple(history)
    assert call.tools == (SEARCH_TOOL,)
    assert call.max_tokens == 4096
    assert call.task_budget_tokens == 40_000


def test_scripted_snapshots_the_message_list() -> None:
    """Callers append to one history list; a recorded call must not follow it forward."""
    provider = ScriptedProvider([text_turn("a"), text_turn("b")])
    history = [Message(role="user", text="first")]

    provider.converse("system", history)
    history.append(Message(role="assistant", text="second"))
    provider.converse("system", history)

    assert len(provider.calls[0].messages) == 1
    assert len(provider.calls[1].messages) == 2


def test_scripted_records_a_stable_system_prompt_across_turns() -> None:
    """The shape of the cache assertion the loop tests actually need."""
    provider = ScriptedProvider([text_turn("a"), text_turn("b")])

    provider.converse("SYSTEM", [Message(role="user", text="one")])
    provider.converse("SYSTEM", [Message(role="user", text="two")])

    assert {c.system for c in provider.calls} == {"SYSTEM"}


# ------------------------------------------------------------------ Anthropic: request shape


def test_anthropic_puts_a_cache_breakpoint_after_the_system_prompt() -> None:
    provider = _provider()
    provider.converse("SYSTEM PROMPT", [Message(role="user", text="hi")])

    system = _client_of(provider).last_kwargs["system"]
    assert system == [
        {
            "type": "text",
            "text": "SYSTEM PROMPT",
            "cache_control": {"type": "ephemeral"},
        }
    ]


def test_anthropic_sends_adaptive_thinking_and_effort() -> None:
    provider = AnthropicProvider("claude-opus-5", client=_FakeClient(), effort="xhigh")
    provider.converse("system", [Message(role="user", text="hi")])

    kwargs = _client_of(provider).last_kwargs
    # Exact equality rather than a "no budget_tokens" check: `budget_tokens` 400s on current
    # models, and an equality assertion catches it without needing a control case to prove it
    # can fail.
    assert kwargs["thinking"] == {"type": "adaptive"}
    assert kwargs["output_config"]["effort"] == "xhigh"


def test_anthropic_sends_tools_only_when_it_has_them() -> None:
    with_tools = _provider()
    with_tools.converse("system", [Message(role="user", text="hi")], tools=[SEARCH_TOOL])
    assert _client_of(with_tools).last_kwargs["tools"] == [
        {
            "name": "search_logs",
            "description": "Search the log slice.",
            "input_schema": SEARCH_TOOL.schema,
        }
    ]

    without_tools = _provider()
    without_tools.converse("system", [Message(role="user", text="hi")])
    assert "tools" not in _client_of(without_tools).last_kwargs


def test_anthropic_refuses_a_message_with_nothing_in_it() -> None:
    """Dropping it instead would change the conversation the model sees, silently."""
    provider = _provider()

    with pytest.raises(ProviderError, match="no text, tool calls or tool results"):
        provider.converse("system", [Message(role="user")])


# ------------------------------------------------------------------ Anthropic: tool round trip


def test_anthropic_decodes_tool_use_blocks() -> None:
    response = _FakeResponse(
        content=[
            _Block(type="thinking"),
            _Block(type="text", text="Checking the pool."),
            _Block(type="tool_use", id="call-a", name="search_logs", input={"q": "timeout"}),
        ],
        stop_reason="tool_use",
    )
    turn = _provider(response).converse("system", [Message(role="user", text="go")])

    assert turn.stop_reason == "tool_use"
    assert turn.text == "Checking the pool."
    assert turn.tool_calls == (
        ToolCall(id="call-a", name="search_logs", arguments={"q": "timeout"}),
    )


def test_anthropic_encodes_an_assistant_turn_carrying_several_tool_calls() -> None:
    provider = _provider()
    provider.converse(
        "system",
        [
            Message(role="user", text="go"),
            Message(
                role="assistant",
                text="Two lookups.",
                tool_calls=(
                    ToolCall(id="call-a", name="search_logs", arguments={"q": "timeout"}),
                    ToolCall(id="call-b", name="search_logs", arguments={"q": "retry"}),
                ),
            ),
        ],
    )

    assistant = _client_of(provider).last_kwargs["messages"][1]
    assert assistant["role"] == "assistant"
    assert assistant["content"] == [
        {"type": "text", "text": "Two lookups."},
        {"type": "tool_use", "id": "call-a", "name": "search_logs", "input": {"q": "timeout"}},
        {"type": "tool_use", "id": "call-b", "name": "search_logs", "input": {"q": "retry"}},
    ]


def test_anthropic_returns_parallel_tool_results_in_one_user_message() -> None:
    """Parallel tool use only works if every result comes back in a single user turn."""
    provider = _provider()
    provider.converse(
        "system",
        [
            Message(role="user", text="go"),
            Message(
                role="assistant",
                tool_calls=(
                    ToolCall(id="call-a", name="search_logs", arguments={"q": "timeout"}),
                    ToolCall(id="call-b", name="search_logs", arguments={"q": "retry"}),
                ),
            ),
            Message(
                role="user",
                tool_results=(
                    ToolResult(call_id="call-a", content="3 rows"),
                    ToolResult(call_id="call-b", content="no such table", is_error=True),
                ),
            ),
        ],
    )

    sent = _client_of(provider).last_kwargs["messages"]
    assert len(sent) == 3
    results = sent[2]
    assert results["role"] == "user"
    assert results["content"] == [
        {
            "type": "tool_result",
            "tool_use_id": "call-a",
            "content": "3 rows",
            "is_error": False,
        },
        {
            "type": "tool_result",
            "tool_use_id": "call-b",
            "content": "no such table",
            "is_error": True,
        },
    ]


def test_anthropic_puts_tool_results_before_text_in_a_user_turn() -> None:
    provider = _provider()
    provider.converse(
        "system",
        [
            Message(
                role="user",
                text="Anything else?",
                tool_results=(ToolResult(call_id="call-a", content="3 rows"),),
            )
        ],
    )

    content = _client_of(provider).last_kwargs["messages"][0]["content"]
    assert [block["type"] for block in content] == ["tool_result", "text"]


def test_anthropic_rejects_tool_arguments_that_are_not_an_object() -> None:
    response = _FakeResponse(
        content=[_Block(type="tool_use", id="call-a", name="search_logs", input="timeout")],
        stop_reason="tool_use",
    )

    with pytest.raises(ProviderError, match="expected an object"):
        _provider(response).converse("system", [Message(role="user", text="go")])


# ------------------------------------------------------------------ Anthropic: stop reasons


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("end_turn", "end_turn"),
        ("stop_sequence", "end_turn"),
        ("tool_use", "tool_use"),
        ("max_tokens", "max_tokens"),
        ("model_context_window_exceeded", "max_tokens"),
        ("refusal", "refusal"),
    ],
)
def test_anthropic_maps_stop_reasons(raw: str, expected: str) -> None:
    response = _FakeResponse(content=[_Block(type="text", text="x")], stop_reason=raw)
    turn = _provider(response).converse("system", [Message(role="user", text="go")])
    assert turn.stop_reason == expected


def test_anthropic_surfaces_a_refusal_as_itself() -> None:
    """A refusal is not a conclusion; collapsing it into end_turn would end an investigation."""
    response = _FakeResponse(
        content=[_Block(type="text", text="I can't help with that.")], stop_reason="refusal"
    )
    turn = _provider(response).converse("system", [Message(role="user", text="go")])

    assert turn.stop_reason == "refusal"
    assert turn.stop_reason != "end_turn"


@pytest.mark.parametrize("raw", ["pause_turn", None, "something_new"])
def test_anthropic_refuses_to_guess_at_an_unmapped_stop_reason(raw: str | None) -> None:
    response = _FakeResponse(content=[_Block(type="text", text="x")], stop_reason=raw)

    with pytest.raises(ProviderError, match="unsupported stop_reason"):
        _provider(response).converse("system", [Message(role="user", text="go")])


# ------------------------------------------------------------------ Anthropic: usage


def test_anthropic_populates_usage_including_cached_tokens() -> None:
    response = _FakeResponse(
        content=[_Block(type="text", text="x")],
        usage=_FakeUsage(
            input_tokens=100,
            output_tokens=40,
            cache_creation_input_tokens=7,
            cache_read_input_tokens=2000,
        ),
    )
    turn = _provider(response).converse("system", [Message(role="user", text="go")])

    # `input_tokens` is every prompt token: fresh, cache writes and cache reads alike, per the
    # contract on `Usage`. Anthropic reports the three separately and this adapter is where
    # they are combined, so a run total adds up the same way against either provider.
    assert turn.usage == Usage(input_tokens=2107, output_tokens=40, cached_input_tokens=2000)
    # Cache reads are counted once, not twice: they are inside `input_tokens`, so the total is
    # input plus output and nothing else.
    assert turn.usage.total_tokens == 2147


def test_anthropic_survives_missing_usage_fields() -> None:
    response = _FakeResponse(content=[_Block(type="text", text="x")], usage=_FakeUsage())
    turn = _provider(response).converse("system", [Message(role="user", text="go")])
    assert turn.usage == Usage()


# ------------------------------------------------------------------ Anthropic: task budget


def test_anthropic_sends_a_task_budget_through_the_beta_endpoint() -> None:
    provider = _provider()
    provider.converse("system", [Message(role="user", text="go")], task_budget_tokens=40_000)

    client = _client_of(provider)
    assert client.last_endpoint == "beta.messages"
    assert client.last_kwargs["betas"] == ["task-budgets-2026-03-13"]
    assert client.last_kwargs["output_config"]["task_budget"] == {
        "type": "tokens",
        "total": 40_000,
    }


def test_anthropic_omits_the_budget_when_none_was_asked_for() -> None:
    provider = _provider()
    provider.converse("system", [Message(role="user", text="go")])

    client = _client_of(provider)
    assert client.last_endpoint == "messages"
    assert "task_budget" not in client.last_kwargs["output_config"]
    assert "betas" not in client.last_kwargs


def test_anthropic_rejects_a_budget_below_the_api_floor() -> None:
    provider = _provider()

    with pytest.raises(ProviderError, match="at least 20000"):
        provider.converse("system", [Message(role="user", text="go")], task_budget_tokens=5_000)

    assert _client_of(provider).calls == []


# ------------------------------------------------------------------ Anthropic: errors


def test_anthropic_wraps_a_client_error() -> None:
    cause = _status_error(400)
    provider = _provider(raises=cause)

    with pytest.raises(ProviderError) as caught:
        provider.converse("system", [Message(role="user", text="go")])

    assert caught.value.__cause__ is cause


@pytest.mark.parametrize(
    "error",
    [
        _status_error(503),
        anthropic.RateLimitError(
            "slow down",
            response=httpx2.Response(
                status_code=429,
                request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"),
            ),
            body=None,
        ),
        anthropic.APIConnectionError(
            request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
        ),
    ],
)
def test_anthropic_lets_retryable_errors_through_as_themselves(error: Exception) -> None:
    """A caller with its own backoff needs the typed error, not a flattened ProviderError."""
    provider = _provider(raises=error)

    with pytest.raises(type(error)):
        provider.converse("system", [Message(role="user", text="go")])


# ------------------------------------------------------------------ no credential required


def test_constructing_the_provider_needs_no_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """Importing and building the adapter must not touch the environment; only calling does."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)

    provider = AnthropicProvider("claude-opus-5")

    assert provider.model == "claude-opus-5"
    assert provider.name == "anthropic"


def test_scripted_turns_are_plain_seam_types() -> None:
    """Nothing vendor-shaped leaks out of the scripted provider."""
    turn = ScriptedProvider([text_turn("done")]).converse("system", [])
    assert isinstance(turn, Turn)

"""The provider seam and its scripted stand-in, tested without a credential or a network.

`ScriptedProvider` is what makes the agent loop testable at all: it replays a fixed sequence of
turns and records every request it was handed, so the half of the loop's behaviour that lives
in *what it sends* -- tool results fed back under the right id, a system prompt that stays
byte-identical across steps, the task budget passed through only when the provider claims to
support it -- is assertable without a model.

The Gemini adapter, the only real provider that ships, has its own module:
`tests/test_gemini_provider.py`.
"""

from __future__ import annotations

import pytest

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


# ------------------------------------------------------------------ the seam itself


def test_the_scripted_provider_satisfies_the_protocol() -> None:
    assert isinstance(ScriptedProvider([]), LLMProvider)


def test_task_budget_support_is_declared_not_assumed() -> None:
    """The caller branches on this rather than assuming every provider paces itself.

    No shipped provider supports task budgets today -- Gemini has no equivalent -- so the
    scripted provider is where the caller's supported path stays exercised.
    """
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


def test_scripted_turns_are_plain_seam_types() -> None:
    """Nothing vendor-shaped leaks out of the scripted provider."""
    turn = ScriptedProvider([text_turn("done")]).converse("system", [])
    assert isinstance(turn, Turn)

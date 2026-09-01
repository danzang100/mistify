"""A provider that replays a fixed script instead of calling a model.

This is what makes the agent loop testable. Every test that exercises the loop -- convergence,
the tool-call cap, what happens when the model refuses -- drives it through this class, with no
credential, no network and no bill, and gets the same answer every run.

It is deliberately strict in two places, because both looseness would hide loop bugs rather
than reveal them:

* Running past the end of the script raises instead of returning a canned "I'm done" turn. A
  loop that asks for more turns than the test wrote is a loop that did not stop when the test
  thought it stopped, and a synthesised final turn would turn that into a passing test.
* Every call is recorded in full. Half of what the loop does is decide *what to send* -- that
  the tool results were fed back, that the system prompt stayed byte-identical across steps so
  the cache holds, that the task budget was passed through -- and none of that is visible in
  the reply. Tests assert on `calls`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from mistify.llm.base import Message, ProviderError, ToolCall, ToolSpec, Turn, Usage

__all__ = ["RecordedCall", "ScriptedProvider", "text_turn", "tool_call_turn"]


@dataclass(frozen=True, slots=True)
class RecordedCall:
    """One request the loop made, kept exactly as it was made.

    The message list is snapshotted into a tuple rather than referenced: callers build their
    history by appending to one list, so holding the list itself would leave every recorded
    call pointing at the final state and quietly make any "what did step 2 send?" assertion
    describe step 5.
    """

    system: str
    messages: tuple[Message, ...]
    tools: tuple[ToolSpec, ...]
    max_tokens: int
    task_budget_tokens: int | None


class ScriptedProvider:
    """Replays `turns` in order, one per `converse()` call."""

    def __init__(
        self,
        turns: Sequence[Turn],
        *,
        name: str = "scripted",
        model: str = "scripted-model",
        supports_task_budget: bool = False,
    ) -> None:
        self.name = name
        self.model = model
        #: Off by default so the loop takes its no-budget path under test unless a test
        #: deliberately asks for the other one. A scripted provider cannot honour a budget
        #: anyway; what is under test is whether the caller passes one.
        self.supports_task_budget = supports_task_budget
        self._turns: tuple[Turn, ...] = tuple(turns)
        self.calls: list[RecordedCall] = []

    @property
    def remaining(self) -> int:
        """Turns left in the script.

        A test that finishes with this above zero exercised less of the loop than it meant to.
        """
        return len(self._turns) - len(self.calls)

    def converse(
        self,
        system: str,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        max_tokens: int = 8192,
        task_budget_tokens: int | None = None,
    ) -> Turn:
        """Record the request, then return the next scripted turn."""
        index = len(self.calls)
        # Recorded before the exhaustion check so the over-run call is still inspectable --
        # when a loop runs one step too far, that last request is the evidence of why.
        self.calls.append(
            RecordedCall(
                system=system,
                messages=tuple(messages),
                tools=tuple(tools or ()),
                max_tokens=max_tokens,
                task_budget_tokens=task_budget_tokens,
            )
        )
        if index >= len(self._turns):
            raise ProviderError(
                f"{type(self).__name__} {self.name!r} ran out of script: "
                f"{len(self._turns)} turn(s) were provided and the caller asked for turn "
                f"{index + 1}. Either the loop failed to stop, or the script is short a turn."
            )
        return self._turns[index]


def text_turn(text: str, *, usage: Usage | None = None) -> Turn:
    """A turn that ends the conversation with prose -- the shape every script finishes on."""
    return Turn(text=text, stop_reason="end_turn", usage=usage or Usage())


def tool_call_turn(
    name: str,
    arguments: dict[str, Any],
    *,
    call_id: str = "call-1",
    text: str = "",
    usage: Usage | None = None,
) -> Turn:
    """A turn that asks for one tool call.

    `call_id` is explicit because the correlation between a call and its result is the thing
    most worth asserting on: a loop that returns a result under the wrong id has broken the
    conversation in a way the model, not the test suite, would be the first to notice.
    """
    return Turn(
        text=text,
        tool_calls=(ToolCall(id=call_id, name=name, arguments=arguments),),
        stop_reason="tool_use",
        usage=usage or Usage(),
    )

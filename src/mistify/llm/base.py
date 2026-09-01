"""The seam between the investigation and whichever model runs it.

Everything above this line — the loop, the tools, the adversarial pass — is written against
these types and never against a vendor SDK. Two adapters satisfy it today: `GeminiProvider`
talks to a real model, and `ScriptedProvider` replays a fixed sequence of turns, which is what
lets the whole agent loop be tested without a credential, a network, or a bill.

The seam is deliberately narrow. A provider is handed a system prompt, a conversation, and a
set of tools, and returns one `Turn`. It does not run the loop, decide when to stop, dispatch
tools, or know what a scratchpad is — those are the caller's business, so swapping providers
cannot quietly change how an investigation is conducted.

Capabilities that genuinely differ between vendors are declared rather than assumed. Task
budgets, where the model paces itself against a token ceiling it can see, are the standing
example: no shipped provider offers one, so a caller checks `supports_task_budget` and falls
back to the hard tool-call cap instead of the seam pretending every provider is the same shape.

An earlier Anthropic adapter has been removed. Its fingerprints are deliberately left in the
comments below wherever it explains *why* a field exists, because "two vendors disagreed about
this" is the only reason several of them are shaped the way they are, and a seam that forgets
that will be flattened by the next person who sees only one implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "LLMProvider",
    "Message",
    "ProviderError",
    "ToolCall",
    "ToolResult",
    "ToolSpec",
    "Turn",
    "Usage",
]


class ProviderError(RuntimeError):
    """A model call failed in a way the caller cannot retry its way out of."""


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A tool offered to the model, in JSON Schema the way every vendor expects it."""

    name: str
    description: str
    schema: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ToolCall:
    """The model asking for a tool to be run.

    `id` is the vendor's correlation handle; results must quote it back, so it is carried
    through rather than regenerated.

    `signature` is an opaque provider blob attached to this call, carried so the adapter can
    hand it back verbatim when it replays the conversation. Nothing above the seam looks
    inside it, and nothing should: the moment this field acquires a meaning it stops being a
    seam and becomes one vendor's data model leaking upward. Gemini requires its thought
    signature to be replayed on every function call and rejects the request outright without
    it; the Anthropic adapter that once shared this seam had no equivalent and left it None,
    which is how the field came to be optional.
    """

    id: str
    name: str
    arguments: dict[str, Any]
    signature: Any = None


@dataclass(frozen=True, slots=True)
class ToolResult:
    call_id: str
    content: str
    is_error: bool = False


@dataclass(frozen=True, slots=True)
class Message:
    """One conversation turn, from either side.

    A single message can carry text, tool calls and tool results together, because that is how
    every provider actually models a turn -- splitting them would force adapters to reassemble
    what the caller took apart.
    """

    role: Literal["user", "assistant"]
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_results: tuple[ToolResult, ...] = ()


@dataclass(frozen=True, slots=True)
class Usage:
    """Tokens consumed by one call.

    **`input_tokens` counts every prompt token, and `cached_input_tokens` is the subset of
    them that was served from cache.** Subset, not a separate bucket -- so `total_tokens` is
    `input + output` and never double-counts, whatever the provider.

    That contract has to be stated because vendors disagree about it. Gemini's
    `prompt_token_count` already includes the cached portion; the Anthropic API reports cache
    reads and cache writes as fields *beside* `input_tokens`, and its adapter had to add them
    together. Any future adapter normalises to the rule above -- left to each one's own
    convention, a run total would silently undercount whichever disagreed.

    `cached_input` is kept because the whole point of caching the template digest is that it
    stops being paid for at full rate. A run where it stays zero across steps is either
    invalidating the cached prefix every step or talking to a provider that does not report
    cache reads, and those are worth telling apart before concluding anything about cost.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        """Prompt plus completion. Cached tokens are already inside `input_tokens`."""
        return self.input_tokens + self.output_tokens

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cached_input_tokens=self.cached_input_tokens + other.cached_input_tokens,
        )


#: Why the model stopped. `refusal` is kept distinct from `end_turn` because a refusal is not
#: a conclusion, and an investigation that ends on one has not finished.
StopReason = Literal["end_turn", "tool_use", "max_tokens", "refusal"]


@dataclass(frozen=True, slots=True)
class Turn:
    """One model response."""

    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    stop_reason: StopReason = "end_turn"
    usage: Usage = field(default_factory=Usage)

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


@runtime_checkable
class LLMProvider(Protocol):
    """What the investigation needs from a model, and nothing more."""

    #: Identifies the provider in health metrics and reports, so a conclusion can be traced
    #: to what produced it.
    name: str

    #: The model this provider instance speaks to. Distinct from `name`: the loop and the
    #: adversarial pass deliberately use different models, and a report that cannot say which
    #: was which cannot support the argument that they were independent.
    model: str

    #: Whether the provider can be given a token ceiling the model paces itself against.
    #: When False the caller relies on its own tool-call cap and forced convergence.
    supports_task_budget: bool

    def converse(
        self,
        system: str,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        max_tokens: int = 8192,
        task_budget_tokens: int | None = None,
    ) -> Turn:
        """Send one request and return one response.

        Implementations must not loop, retry past their own transport policy, or execute
        tools. `task_budget_tokens` is advisory and ignored by providers that do not support
        it -- the caller has already been told, via `supports_task_budget`, not to rely on it.
        """
        ...

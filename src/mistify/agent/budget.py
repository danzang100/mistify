"""A hard ceiling on the tokens one run may spend, across every stage that calls a model.

Before this existed a run that grew was reported, not stopped. The tool-call cap bounds how
many steps the loop takes, not what they cost: each step re-sends the conversation, so the
same thirty calls cost 150k tokens on one incident and 1.2M on another. With a paid model
behind LiteLLM that difference is money, and it is decided by the log rather than the user.

Two layers, because they answer different questions.

**The loop stops early, on purpose.** It projects its next step from its last one and stops
while there is still room for its own closing turn and everything after it -- synthesis and
the critique. That is the graceful path: the investigation ends budget-limited, and its notes
so far still get concluded and challenged.

**Every call is refused once the ceiling is spent.** `BudgetedProvider` wraps each provider
and raises `TokenCeilingReached` before a call starts past the ceiling. The loop's projection
is an estimate; this is the guarantee. A run can overshoot by at most the one call that was
already in flight when the ceiling was crossed, since a call's cost is known only after it.
"""

from __future__ import annotations

from dataclasses import dataclass

from mistify.llm.base import LLMProvider, Message, ProviderError, ToolSpec, Turn

__all__ = ["BudgetedProvider", "TokenBudget", "TokenCeilingReached"]

#: Share of the ceiling kept back from the loop for what runs after it. Measured 2026-09-24
#: over the 22 recorded runs with token metrics: synthesis peaked at 6.3k tokens and the
#: critique at 184k (rey-0811-v3, the rebuttal reading with tools); the next largest critique
#: was 34k. 15% of the 1.5M default is 225k, which covers the worst of both together.
POST_LOOP_SHARE = 0.15


class TokenCeilingReached(ProviderError):
    """A model call was refused because the run has spent its token ceiling."""


@dataclass
class TokenBudget:
    """Tokens spent so far by one run, against its ceiling. Shared by every stage's provider."""

    ceiling: int
    spent: int = 0

    @property
    def exhausted(self) -> bool:
        return self.spent >= self.ceiling

    @property
    def loop_limit(self) -> int:
        """What the investigation loop may spend before handing over to the stages after it."""
        return int(self.ceiling * (1 - POST_LOOP_SHARE))

    def loop_should_stop(self, last_step_tokens: int) -> bool:
        """Would one more step, plus the closing turn it forces, cross the loop's share?

        Projected from the last step because a step costs about what the one before it did plus
        a little -- the conversation only grows, and compaction keeps the growth small. Two
        steps' worth: the next search step, and the convergence turn that follows it.
        """
        return self.spent + 2 * last_step_tokens > self.loop_limit


class BudgetedProvider:
    """A provider that charges every call to a shared budget and refuses one past the ceiling.

    Transparent otherwise: `name`, `model` and `supports_task_budget` are the wrapped
    provider's, so metrics and reports still say which model did the work.
    """

    def __init__(self, inner: LLMProvider, budget: TokenBudget) -> None:
        self.inner = inner
        self.budget = budget
        self.name = inner.name
        self.model = inner.model
        self.supports_task_budget = inner.supports_task_budget

    def converse(
        self,
        system: str,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        max_tokens: int = 8192,
        task_budget_tokens: int | None = None,
    ) -> Turn:
        if self.budget.exhausted:
            raise TokenCeilingReached(
                f"token ceiling reached: {self.budget.spent:,} of {self.budget.ceiling:,} "
                f"tokens spent, so the call to {self.model} was not made. Raise "
                "pipeline.max_total_tokens to allow more."
            )
        turn = self.inner.converse(
            system=system,
            messages=messages,
            tools=tools,
            max_tokens=max_tokens,
            task_budget_tokens=task_budget_tokens,
        )
        self.budget.spent += turn.usage.total_tokens
        return turn

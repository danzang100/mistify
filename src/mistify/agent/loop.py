"""The bounded investigation loop.

The model is given the ranked template list and four tools, and works until it writes a
conclusion or runs out of tool calls. Three things about that are deliberate.

**It is bounded, and says when the bound bit.** An investigation that stops because it ran out
of budget has not finished, and a report that presents it as finished is the exact silent
failure this system exists to avoid. Hitting the cap triggers one final turn asking the model
to conclude from what it already has, and `investigate.budget_limited` is recorded so the
report can say so in words.

**Every tool call is logged before the model sees the result.** The audit trail is what lets
someone check a conclusion against what was actually looked at rather than re-reading the
narrative.

**The expensive prefix is stable.** The system prompt carries the template digest, which is
the largest thing in the conversation and identical on every step. It is built once and never
edited, so a provider that supports prompt caching can serve it from cache; the cached-token
count is recorded, and zero across a multi-step run means something is invalidating it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mistify.agent.tools import ToolBox
from mistify.common.models import ScratchpadNote
from mistify.llm.base import LLMProvider, Message, ToolSpec, Turn, Usage
from mistify.metrics import (
    INVESTIGATE_BUDGET_LIMITED,
    INVESTIGATE_CACHED_INPUT_TOKENS,
    INVESTIGATE_CAVEAT,
    INVESTIGATE_INPUT_TOKENS,
    INVESTIGATE_INVESTIGATOR,
    INVESTIGATE_MODEL,
    INVESTIGATE_NOTES_WRITTEN,
    INVESTIGATE_OUTCOME,
    INVESTIGATE_OUTPUT_TOKENS,
    INVESTIGATE_PROVIDER,
    INVESTIGATE_STEPS,
    INVESTIGATE_STOP_REASON,
    INVESTIGATE_TOOL_CALLS,
)
from mistify.scratchpad.db import ScratchpadDB

__all__ = ["INVESTIGATOR_NAME", "InvestigationLoop", "InvestigationResult", "build_system_prompt"]

INVESTIGATOR_NAME = "agent-loop"

CAVEAT = (
    "A model drove this investigation through the scratchpad tools. Every claim below cites "
    "rows that were checked to exist; whether those rows support the claim is the adversarial "
    "pass's job, and its argument is under The challenge."
)

SYSTEM_PROMPT = """You are investigating one incident from its logs.

The logs have already been parsed, redacted and clustered into templates. You cannot read the
original file; you work entirely through the tools, which read a SQLite scratchpad.

Values like [IPV4:a7f2] or [EMAIL:9c31] are redacted placeholders. The same source value always
produces the same placeholder within this incident, so you can correlate on them, but you
cannot recover what they stood for and should not speculate about it.

Templates are ranked by an anomaly score computed without any model involvement, from severity,
how concentrated the template is in time, and how rare it is. Treat that ranking as the search
order rather than as a conclusion: it says where to look first, not what is true.

How to work:

- Start from the ranked templates. Pull slices to see actual lines before forming a view.
- Prefer evidence over narrative. A plausible story with no supporting rows is worth less than
  a dull one with them.
- Consider whether this is one incident or several before concluding. Two unrelated failures
  in one window are common and collapsing them into one narrative loses both.
- Record every hypothesis with `write_note`. Evidence is mandatory: cite the template ids and
  log event ids that support the claim. A note whose evidence does not actually say what the
  note says will be caught, so cite what you read.
- When you have a conclusion, write it as a final note at your honest confidence and stop
  calling tools. Do not pad the investigation to use up your budget.

Be direct. If the logs do not support a root cause, say that instead of inventing one.
"""


@dataclass(slots=True)
class InvestigationResult:
    notes: list[ScratchpadNote] = field(default_factory=list)
    steps: int = 0
    tool_calls: int = 0
    budget_limited: bool = False
    stop_reason: str = "end_turn"
    usage: Usage = field(default_factory=Usage)


def build_system_prompt(db: ScratchpadDB, digest_limit: int = 40) -> str:
    """System prompt plus the incident's template digest.

    The digest goes in the system prompt rather than the first user message because it is the
    large stable prefix: identical on every step of the loop, and therefore the thing worth
    caching. Putting anything incident-specific after it that changes per step would defeat
    that.
    """
    incident = db.incident() or {}
    first_ts, last_ts = db.time_bounds()
    templates = db.top_templates(limit=digest_limit, order_by="anomaly_score")

    lines = [
        SYSTEM_PROMPT,
        "",
        "## This incident",
        "",
        f"- source: {incident.get('source', 'unknown')}",
        f"- events: {db.event_count()}",
        f"- templates: {db.template_count()}",
        f"- window: {first_ts} to {last_ts}",
        "",
        f"## Templates, most anomalous first (showing {len(templates)} of {db.template_count()})",
        "",
    ]
    for template in templates:
        mix = ", ".join(f"{k}:{v}" for k, v in sorted(template["severity_mix"].items()))
        lines.append(
            f"[{template['template_id']}] score={template['anomaly_score']:.3f} "
            f"n={template['occurrence_count']} {mix} :: {template['pattern']}"
        )
    return "\n".join(lines)


class InvestigationLoop:
    """Runs one incident to a conclusion, or to its budget."""

    def __init__(
        self,
        db: ScratchpadDB,
        provider: LLMProvider,
        toolbox: ToolBox,
        max_tool_calls: int = 20,
        max_tokens: int = 8192,
        task_budget_tokens: int | None = None,
    ) -> None:
        self.db = db
        self.provider = provider
        self.toolbox = toolbox
        self.max_tool_calls = max_tool_calls
        self.max_tokens = max_tokens
        self.task_budget_tokens = task_budget_tokens

    def run(self, incident_context: str = "") -> InvestigationResult:
        system = build_system_prompt(self.db)
        opening = incident_context.strip() or (
            "Investigate this incident. Start from the ranked templates above."
        )
        messages: list[Message] = [Message(role="user", text=opening)]

        result = InvestigationResult()
        specs = self.toolbox.specs()

        while True:
            turn = self._converse(system, messages, specs)
            result.steps += 1
            result.usage = result.usage + turn.usage
            result.stop_reason = turn.stop_reason

            if not turn.wants_tools:
                break

            messages.append(Message(role="assistant", text=turn.text, tool_calls=turn.tool_calls))
            results = [self.toolbox.dispatch(call) for call in turn.tool_calls]
            result.tool_calls += len(results)
            # All results from one assistant turn go back in a single user message. Splitting
            # them trains the model out of asking for tools in parallel.
            messages.append(Message(role="user", tool_results=tuple(results)))

            if result.tool_calls >= self.max_tool_calls:
                result.budget_limited = True
                self._converge(system, messages, result)
                break

        self._record(result)
        result.notes = self.db.notes()
        return result

    def _converse(self, system: str, messages: list[Message], specs: list[ToolSpec]) -> Turn:
        budget = self.task_budget_tokens if self.provider.supports_task_budget else None
        return self.provider.converse(
            system=system,
            messages=messages,
            tools=specs,
            max_tokens=self.max_tokens,
            task_budget_tokens=budget,
        )

    def _converge(self, system: str, messages: list[Message], result: InvestigationResult) -> None:
        """One last turn, with the tools taken away.

        Removing the tools is what makes this a conclusion rather than another step: the model
        cannot ask for more, so it must answer from what it already has. Asking politely while
        leaving the tools available would just spend another call.
        """
        messages.append(
            Message(
                role="user",
                text=(
                    f"You have used your budget of {self.max_tool_calls} tool calls and "
                    "none remain. State your conclusion now from what you have already seen. "
                    "Say honestly how confident you are, and name what you would have looked "
                    "at next if you could have."
                ),
            )
        )
        turn = self.provider.converse(
            system=system,
            messages=messages,
            tools=None,
            max_tokens=self.max_tokens,
            task_budget_tokens=None,
        )
        result.steps += 1
        result.usage = result.usage + turn.usage
        result.stop_reason = "budget_exhausted"

        if turn.text.strip():
            self.db.write_note(
                step=result.steps,
                note=(
                    "Investigation was budget-limited: it reached its tool-call cap before "
                    f"concluding. Stated conclusion at that point: {turn.text.strip()}"
                ),
                evidence={"budget_limited": True, "tool_calls": result.tool_calls},
                confidence="low",
            )

    def _record(self, result: InvestigationResult) -> None:
        notes = self.db.notes()
        self.db.record_many(
            [
                (INVESTIGATE_INVESTIGATOR, INVESTIGATOR_NAME),
                (INVESTIGATE_CAVEAT, CAVEAT),
                (INVESTIGATE_PROVIDER, self.provider.name),
                (INVESTIGATE_MODEL, self.provider.model),
                (INVESTIGATE_STEPS, result.steps),
                (INVESTIGATE_TOOL_CALLS, result.tool_calls),
                (INVESTIGATE_NOTES_WRITTEN, len(notes)),
                (INVESTIGATE_BUDGET_LIMITED, result.budget_limited),
                (INVESTIGATE_STOP_REASON, result.stop_reason),
                (INVESTIGATE_INPUT_TOKENS, result.usage.input_tokens),
                (INVESTIGATE_OUTPUT_TOKENS, result.usage.output_tokens),
                (INVESTIGATE_CACHED_INPUT_TOKENS, result.usage.cached_input_tokens),
                (
                    INVESTIGATE_OUTCOME,
                    "budget_limited"
                    if result.budget_limited
                    else ("converged" if notes else "no_conclusion"),
                ),
            ]
        )

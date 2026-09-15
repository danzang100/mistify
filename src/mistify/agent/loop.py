"""The bounded investigation loop.

The model is given the ranked template list and five tools, and works until it writes a
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

from mistify.agent.adversarial import unexplained_signal_templates
from mistify.agent.tools import ToolBox
from mistify.common.models import ScratchpadNote
from mistify.llm.base import LLMProvider, Message, ToolResult, ToolSpec, Turn, Usage
from mistify.metrics import (
    ANOMALY_SIGNAL_TEMPLATE_IDS,
    INVESTIGATE_BUDGET_LIMITED,
    INVESTIGATE_CACHED_INPUT_TOKENS,
    INVESTIGATE_CAVEAT,
    INVESTIGATE_COVERAGE_NUDGES,
    INVESTIGATE_DIGEST_CHARS,
    INVESTIGATE_DIGEST_NUDGES,
    INVESTIGATE_HISTORY_COMPACTIONS,
    INVESTIGATE_INPUT_GROWTH,
    INVESTIGATE_INPUT_TOKENS,
    INVESTIGATE_INPUT_TOKENS_PER_STEP,
    INVESTIGATE_INVESTIGATOR,
    INVESTIGATE_MODEL,
    INVESTIGATE_NOTES_WRITTEN,
    INVESTIGATE_NUDGED_TEMPLATES,
    INVESTIGATE_OUTCOME,
    INVESTIGATE_OUTPUT_TOKENS,
    INVESTIGATE_PROVIDER,
    INVESTIGATE_SILENT_NUDGES,
    INVESTIGATE_STEPS,
    INVESTIGATE_STOP_REASON,
    INVESTIGATE_TOOL_CALLS,
    MetricView,
)
from mistify.scratchpad.db import ScratchpadDB

__all__ = [
    "ELIDED",
    "ELIDE_MIN_LINES",
    "INVESTIGATOR_NAME",
    "InvestigationLoop",
    "InvestigationResult",
    "build_system_prompt",
]

INVESTIGATOR_NAME = "agent-loop"

#: Templates the digest shows, and therefore the set the coverage nudge holds the investigation
#: to. One constant rather than two defaults, because `build_system_prompt` and the nudge must
#: agree about what "you were shown this" means.
DIGEST_LIMIT = 40

#: Characters the digest's template listing may occupy, about six thousand tokens. The limit
#: above counts *templates*, which is the wrong unit when a template can be five kilobytes:
#: measured across twenty-two real incidents the digest is a median 7,222 characters, and on
#: a Java application log with JSON payloads on single lines it reached **208,843** -- 52k
#: tokens, re-sent on every step. That one investigation spent 1.58M input tokens, thirteen
#: times a normal case, and hit its tool-call cap before it could finish.
#:
#: Templates are never dropped to meet this, only shortened: dropping one changes what the
#: ranking says, while shortening one changes only how much of a line the model reads before
#: it opens the line properly with `get_slice`.
DIGEST_CHAR_BUDGET = 24_000

#: However tight the budget gets, a pattern is shown at least this far. Below roughly this
#: the prefix is all timestamp and thread id and two templates cannot be told apart, which
#: would make the digest useless rather than merely abbreviated.
MIN_PATTERN_CHARS = 160

#: How far into its tool-call budget an investigation may get with nothing written down.
#: Past this, having recorded no note at all, it is asked to write what it has -- once.
#:
#: Measured on a 2.19M-event application log: three runs of the same incident, and the two
#: that spent every call surveying wrote nothing and produced no diagnosis. The existing
#: nudges cannot help there, because both fire when a conclusion is *offered* and neither run
#: ever offered one. A run that never tries to conclude gets no pressure at all -- it just
#: reaches the wall. The one run that did produce the right answer had written its note at
#: two thirds of the way through its budget.
SILENT_NUDGE_AFTER = 0.6
#: How many unopened templates a single nudge may name. The digest holds forty and a nudge
#: listing thirty of them is a shopping list, not a question -- and the prompt tells the model
#: not to pad the investigation, which a long list invites it to do.
MAX_NUDGED_TEMPLATES = 3

CAVEAT = (
    "A model drove this investigation through the scratchpad tools. Every claim below cites "
    "rows that were checked to exist; whether those rows support the claim is the adversarial "
    "pass's job, and its argument is under The challenge."
)

SYSTEM_PROMPT = """You are investigating one incident from its logs.

The logs have already been parsed, redacted and clustered into templates. You cannot read the
original file; you work entirely through the tools, which read a SQLite scratchpad.

Values like [IPV4:a7f2c91e] or [EMAIL:9c31d804] are redacted placeholders. The same source
value always produces the same placeholder within this incident, so you can correlate on them,
but you cannot recover what they stood for and should not speculate about it.

Templates are ranked by an anomaly score computed without any model involvement, from severity,
how concentrated the template is in time, and how rare it is. Treat that ranking as the search
order rather than as a conclusion: it says where to look first, not what is true.

How to work:

- Start from the ranked templates. Pull slices to see actual lines before forming a view.
- Prefer evidence over narrative. A plausible story with no supporting rows is worth less than
  a dull one with them.
- Consider whether this is one incident or several before concluding. Two unrelated failures
  in one window are common and collapsing them into one narrative loses both.
- Cite only ids you have actually been shown. `write_note` refuses a log event id that was
  never returned to you: an id you did not read resolves to a real row that says nothing about
  your claim, which is worse than citing nothing. Take ids from the `id` column of a
  `get_slice` result, or select `log_events.id` in `run_sql`.
- Lines carry a `trace_id` where the source had one. Passing it back to `get_slice` returns
  every line of that one request across services, which is the correlation the template
  ranking cannot show you.
- Record every hypothesis with `write_note`. Evidence is mandatory: cite the template ids and
  log event ids that support the claim. A note whose evidence does not actually say what the
  note says will be caught, so cite what you read.
- Cite every template your note names, not only the one the claim is chiefly about. If you
  write that one template was preceded by another, both belong in `template_ids`: a template
  discussed in your prose but missing from your citations is reported as unaccounted for, and
  a reader checking your reasoning cannot follow it back to rows.
- Large tool output is summarised away as you work, so a wide slice you pulled ten steps ago
  may no longer be in front of you. Write the note when you finish looking at something, not
  at the end: a note is durable and the rows behind it are not. `read_notes` returns everything
  you have concluded so far, with its citations, and is cheap to call.
- When you have a conclusion, write it as a final note at your honest confidence and stop
  calling tools. Do not pad the investigation to use up your budget.

Be direct. If the logs do not support a root cause, say that instead of inventing one.
"""


#: Marks a tool result whose rows have been dropped. Checked to make compaction idempotent, and
#: visible to the model so it knows the rows existed rather than thinking the tool returned
#: nothing.
ELIDED = "[rows elided to keep the conversation bounded; re-run the tool to see them again]"


#: Results at or below this many lines are left alone. Compaction exists to stop one large
#: slice being re-sent for the rest of the investigation; a ten-row slice is not that, and
#: eliding it costs more than it saves. Measured: across five runs every investigation examined
#: the planted precursor with a ten-row slice at step three, had it summarised away by step
#: six, and concluded without it -- one run re-queried three templates it had already read.
#: Small evidence has to survive to the conclusion, because the conclusion is written last.
ELIDE_MIN_LINES = 20


def _summarise(outcome: ToolResult) -> ToolResult:
    """One tool result reduced to its first line -- the header the tool already wrote."""
    if outcome.is_error or ELIDED in outcome.content:
        # An error is short and is the whole message; there is nothing to trim.
        return outcome
    if outcome.content.count("\n") <= ELIDE_MIN_LINES:
        return outcome
    head, _, rest = outcome.content.partition("\n")
    if not rest.strip():
        return outcome
    return ToolResult(call_id=outcome.call_id, content=f"{head}\n{ELIDED}", is_error=False)


@dataclass(slots=True)
class InvestigationResult:
    notes: list[ScratchpadNote] = field(default_factory=list)
    steps: int = 0
    tool_calls: int = 0
    budget_limited: bool = False
    stop_reason: str = "end_turn"
    usage: Usage = field(default_factory=Usage)
    #: Input tokens on each step, in order. The total hides the curve, and the curve is what
    #: decides whether a longer incident is affordable.
    input_per_step: list[int] = field(default_factory=list)
    compactions: int = 0
    coverage_nudges: int = 0
    #: How many of those nudges were about unopened digest templates rather than about an
    #: unexplained signal template. Two different failures wearing one counter would make the
    #: next sweep unreadable.
    digest_nudges: int = 0
    #: Whether the run was asked to write something down before its budget ran out. A
    #: different failure from concluding badly, and it needs its own count for the same
    #: reason `digest_nudges` does.
    silent_nudges: int = 0

    @property
    def input_growth(self) -> float:
        """Last step's input over the first step's. 1.0 when there is nothing to compare."""
        if len(self.input_per_step) < 2 or not self.input_per_step[0]:
            return 1.0
        return self.input_per_step[-1] / self.input_per_step[0]


#: How the severity term was filled, in the words the model is given. `field` is the ordinary
#: case and says nothing -- the system prompt already describes it. The other two are the ones
#: worth a sentence, because they change how far the ranking can be trusted.
_RANKING_BASIS: dict[str, str] = {
    "lexical": (
        "this file carried no severity field, so the severity part of the score was read "
        "from the words in each template ('error', 'failed', 'timeout'). A template can look "
        "alarming and be routine, and a quietly-worded line can be the fault."
    ),
    "none": (
        "this file carried no severity field and its text yielded no severity either, so the "
        "score is rarity and burstiness alone. The order below is weak evidence about where "
        "to look."
    ),
}


def _severity_source(db: ScratchpadDB) -> str:
    """What the ingest recorded about where the severity term came from, or "field"."""
    row = next((r for r in db.metrics("anomaly") if r["metric"] == "severity_source"), None)
    return "field" if row is None else str(row["value"])


def build_system_prompt(db: ScratchpadDB, digest_limit: int = DIGEST_LIMIT) -> str:
    """System prompt plus the incident's template digest.

    The digest goes in the system prompt rather than the first user message because it is the
    large stable prefix: identical on every step of the loop, and therefore the thing worth
    caching. Putting anything incident-specific after it that changes per step would defeat
    that.
    """
    incident = db.incident() or {}
    first_ts, last_ts = db.time_bounds()
    templates = db.top_templates(limit=digest_limit, order_by="anomaly_score")
    ranking = _RANKING_BASIS.get(_severity_source(db))

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
    ]
    if ranking is not None:
        # Where the severity term came from, when it did not come from a severity field. The
        # prompt already tells the model the ranking is a search order rather than a verdict;
        # this says how much to trust it, which differs by a lot between a parsed level and a
        # word matched in the line.
        lines.extend([f"Ranking: {ranking}", ""])
    lines.extend(
        [
            "## Templates, most anomalous first "
            f"(showing {len(templates)} of {db.template_count()})",
            "",
        ]
    )
    allowance = max(MIN_PATTERN_CHARS, DIGEST_CHAR_BUDGET // max(len(templates), 1))
    shortened = 0
    for template in templates:
        mix = ", ".join(f"{k}:{v}" for k, v in sorted(template["severity_mix"].items()))
        pattern = str(template["pattern"])
        if len(pattern) > allowance:
            # Said in characters rather than elided silently: a model that cannot tell a
            # shortened pattern from a whole one will quote the shortening as if it were
            # the line, which is the same error as citing a row it never read.
            cut = len(pattern) - allowance
            pattern = f"{pattern[:allowance]} ... [+{cut} more chars]"
            shortened += 1
        lines.append(
            f"[{template['template_id']}] score={template['anomaly_score']:.3f} "
            f"n={template['occurrence_count']} {mix} :: {pattern}"
        )
    if shortened:
        lines.extend(
            [
                "",
                f"{shortened} of these patterns are shown shortened to keep this list "
                "readable. The ranking is over the whole template, not the part shown; use "
                "get_slice on the template id to read whole lines.",
            ]
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
        tool_result_history_steps: int = 3,
        coverage_nudges: int = 1,
    ) -> None:
        self.db = db
        self.provider = provider
        self.toolbox = toolbox
        self.max_tool_calls = max_tool_calls
        self.max_tokens = max_tokens
        self.task_budget_tokens = task_budget_tokens
        #: How many recent steps keep their tool output in full. Older ones are reduced to the
        #: summary line the tool already writes. Zero disables compaction.
        self.tool_result_history_steps = tool_result_history_steps
        #: How many times a conclusion may be sent back for leaving an acute signal template
        #: unaccounted for. Zero accepts the first conclusion offered.
        self.max_coverage_nudges = coverage_nudges

    def run(self, incident_context: str = "") -> InvestigationResult:
        system = build_system_prompt(self.db)
        # The largest thing in the conversation and the one re-sent on every step. Recorded
        # because nobody noticed a 52k-token digest until one run cost 1.58M input tokens.
        self.db.record(INVESTIGATE_DIGEST_CHARS, len(system))
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
            result.input_per_step.append(turn.usage.input_tokens)
            result.stop_reason = turn.stop_reason

            if not turn.wants_tools:
                if self._nudge(messages, turn, result):
                    continue
                break

            messages.append(Message(role="assistant", text=turn.text, tool_calls=turn.tool_calls))
            results = [self.toolbox.dispatch(call) for call in turn.tool_calls]
            result.tool_calls += len(results)
            # All results from one assistant turn go back in a single user message. Splitting
            # them trains the model out of asking for tools in parallel.
            messages.append(Message(role="user", tool_results=tuple(results)))
            result.compactions += self._compact(messages)
            self._ask_for_something_written(messages, result)

            if result.tool_calls >= self.max_tool_calls:
                result.budget_limited = True
                self._converge(system, messages, result)
                break

        self._record(result)
        result.notes = self.db.notes()
        return result

    def _signal_template_ids(self) -> list[int]:
        """The templates the anomaly ranking flagged, as the scoring stage recorded them."""
        raw = MetricView(self.db.metrics("anomaly")).text(ANOMALY_SIGNAL_TEMPLATE_IDS) or ""
        return [int(part) for part in raw.split(",") if part.strip()]

    def _unopened_digest_templates(self) -> list[int]:
        """Digest templates the model was never shown lines from, and never cited.

        The gap this closes was measured rather than supposed: across fifteen runs the loop
        opened a median of four of the forty templates it was handed, and **every** ground-truth
        marker it failed to cite lived in a template it never opened. The existing nudge asks
        only about the signal set -- the top few by score -- so on `pytest-pandas` the run cited
        all five, satisfied it, and stopped with its evidence unopened at ranks 16, 20 and 20.

        Cited-but-unopened is deliberately excluded: naming a template in a note is a claim
        about it, and asking the model to look at something it has already committed to is a
        different question from asking about something it ignored.
        """
        shown = self.toolbox.shown_templates
        cited: set[int] = set()
        for note in self.db.notes():
            cited.update(int(i) for i in note.evidence.get("template_ids", []))
        ranked = self.db.top_templates(limit=DIGEST_LIMIT, order_by="anomaly_score")
        unopened = [
            int(row["template_id"])
            for row in ranked
            if int(row["template_id"]) not in shown and int(row["template_id"]) not in cited
        ]
        return unopened[:MAX_NUDGED_TEMPLATES]

    def _ask_for_something_written(
        self, messages: list[Message], result: InvestigationResult
    ) -> None:
        """Ask a run that has recorded nothing to write down what it has. Once.

        The other two nudges answer a conclusion; this one answers the absence of one. Both
        of them fire when the model stops calling tools, so a run that spends every call
        searching is never spoken to at all -- which is exactly how two investigations of a
        2.19M-event log used twenty calls each and wrote not one note between them.

        Deliberately not a demand for a conclusion: a note is revisable and cheap, and the
        prompt already says to write one when you finish looking at something rather than at
        the end. This is that instruction arriving when it is nearly too late.
        """
        if result.silent_nudges or self.db.notes():
            return
        if result.tool_calls < self.max_tool_calls * SILENT_NUDGE_AFTER:
            return
        messages.append(
            Message(
                role="user",
                text=(
                    f"You have used {result.tool_calls} of your {self.max_tool_calls} tool "
                    "calls and recorded no findings. Write down what you have established so "
                    "far with write_note, citing the templates and log event ids you have "
                    "actually read. A note you can revise later is worth more than a "
                    "conclusion you run out of budget before writing, and an investigation "
                    "that records nothing is indistinguishable from one that found nothing."
                ),
            )
        )
        result.silent_nudges += 1

    def _nudge(self, messages: list[Message], turn: Turn, result: InvestigationResult) -> bool:
        """Refuse a conclusion that ignored something it was shown, up to `max_coverage_nudges`.

        Two questions, strongest first. The signal set is the acute one -- a high-scoring
        template active in the window that no note cites. Failing that, the weaker one: a
        template near the top of the digest the model never opened at all. The second exists
        because the first stopped being enough; see `_unopened_digest_templates`.

        `unexplained_signal_templates` is model-free and already existed -- it just ran too
        late to change anything, in the adversarial pass, after the investigation had ended.
        Measured over ten runs of the sample incident, every one concluded without citing the
        planted precursor and six never mentioned it at all; the check caught that every time
        and could do nothing but report it.

        Asking is deliberately weaker than requiring. "Cite it or say why it is not relevant"
        accepts a reasoned dismissal, which is itself a finding -- no run so far has explicitly
        dismissed the red herring, and this is the turn where that would be written down.

        Bounded by `max_coverage_nudges` so a model that keeps declining cannot spin the loop.
        """
        if result.coverage_nudges >= self.max_coverage_nudges:
            return False
        unexplained, _ = unexplained_signal_templates(self.db, self._signal_template_ids())
        if unexplained:
            self.toolbox.nudged_templates.update(int(i) for i in unexplained)
            question = (
                f"Before you finish: template(s) {', '.join(str(i) for i in unexplained)} were "
                "ranked as signal, were active during the incident window, and no note you have "
                "written cites them. For each one, either write a note citing it, or write a "
                "note saying why it is not relevant to this incident. A reasoned dismissal is a "
                "finding; silence is not."
            )
        else:
            unopened = self._unopened_digest_templates()
            if not unopened:
                return False
            self.toolbox.nudged_templates.update(int(i) for i in unopened)
            result.digest_nudges += 1
            question = (
                "Before you finish: you were shown the "
                f"{DIGEST_LIMIT} most anomalous templates and have pulled lines from "
                f"{len(self.toolbox.shown_templates)} of them. Template(s) "
                f"{', '.join(str(i) for i in unopened)} rank high and you have not looked at "
                "any of them. Read them with get_slice, then either cite what you find or "
                "write a note saying why they are not relevant. Do not restate your conclusion "
                "unchanged; if they change nothing, say so and why."
            )

        # The assistant's own turn goes back first: without it the conversation has two user
        # messages in a row, which is not a shape any provider accepts.
        messages.append(Message(role="assistant", text=turn.text))
        messages.append(Message(role="user", text=question))
        result.coverage_nudges += 1
        return True

    def _compact(self, messages: list[Message]) -> int:
        """Reduce tool output older than the recent window to its summary line, in place.

        The whole conversation is re-sent on every step, so a slice pulled at step two is paid
        for again at every step after it -- and a slice is the largest thing that ever enters
        the conversation. Left alone this makes cost quadratic in steps, which is what runs a
        long investigation into the context ceiling rather than into its tool-call budget.

        What survives is the header each tool writes: how many rows matched, how many were
        shown, what the filters were. That is the part the model reasons about several steps
        later; the rows themselves it has either already used or already cited, and the
        citation resolves against the scratchpad rather than against the transcript. Nothing is
        lost that the report reads.

        Tool *calls* are never touched. They carry the provider's thought signature, which has
        to be replayed byte-identical or the request is rejected outright.

        Returns how many messages were compacted, so a run can report whether this ran at all.
        """
        if self.tool_result_history_steps <= 0:
            return 0

        carrying = [i for i, message in enumerate(messages) if message.tool_results]
        stale = carrying[: -self.tool_result_history_steps] if carrying else []

        compacted = 0
        for index in stale:
            message = messages[index]
            trimmed = tuple(_summarise(outcome) for outcome in message.tool_results)
            if trimmed == message.tool_results:
                # Already compacted on an earlier pass. Counting it again would report work
                # that did not happen.
                continue
            messages[index] = Message(
                role=message.role,
                text=message.text,
                tool_calls=message.tool_calls,
                tool_results=trimmed,
            )
            compacted += 1
        return compacted

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
                    INVESTIGATE_INPUT_TOKENS_PER_STEP,
                    ",".join(str(n) for n in result.input_per_step),
                ),
                (INVESTIGATE_INPUT_GROWTH, round(result.input_growth, 2)),
                (INVESTIGATE_HISTORY_COMPACTIONS, result.compactions),
                (INVESTIGATE_COVERAGE_NUDGES, result.coverage_nudges),
                (INVESTIGATE_DIGEST_NUDGES, result.digest_nudges),
                (INVESTIGATE_SILENT_NUDGES, result.silent_nudges),
                (
                    INVESTIGATE_NUDGED_TEMPLATES,
                    ",".join(str(i) for i in sorted(self.toolbox.nudged_templates)),
                ),
                (
                    INVESTIGATE_OUTCOME,
                    "budget_limited"
                    if result.budget_limited
                    else ("converged" if notes else "no_conclusion"),
                ),
            ]
        )

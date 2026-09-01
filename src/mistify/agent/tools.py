"""The four tools the investigator is given, and the dispatcher behind them.

This is the whole surface the model gets on the incident: rank templates, pull a bounded
slice of raw lines, run read-only SQL, write a note. There is deliberately no way to reach
the scratchpad except through here, which is what makes two guarantees enforceable rather
than hoped for.

**Every call is auditable.** Each dispatch writes a `query_log` row, failures included. The
architecture asks for a record of every slice the investigator requested, because a
conclusion nobody can retrace is not evidence -- and a refused call is part of that record,
since what the model tried and could not do explains the shape of what it did next.

**Every result is bounded.** Results go straight into a context window, so limits are capped
here rather than trusted to the model's arguments, and every result says how many rows came
back against the cap. A silently truncated result is a lie: the model would read a partial
answer as a complete one and conclude from an absence it never actually established.

Errors come back as results, not exceptions. The model authored these arguments and is the
only thing that can correct them, so a bad enum, a mutation attempt or evidence that cites
nothing is returned as `ToolResult(is_error=True)` carrying the reason and the fix. The loop
keeps going; the model retries. `dispatch` raising would end an investigation over a typo.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from mistify.common.models import SEVERITIES, NoiseThresholds, parse_timestamp
from mistify.llm.base import ToolCall, ToolResult, ToolSpec
from mistify.scratchpad.db import ReadOnlyViolation, ScratchpadDB

__all__ = [
    "CONFIDENCE_LEVELS",
    "SLICE_LINES_DEFAULT",
    "SLICE_LINES_MAX",
    "SQL_ROW_CAP",
    "TEMPLATE_LIMIT_DEFAULT",
    "TEMPLATE_LIMIT_MAX",
    "TOOL_NAMES",
    "ToolBox",
]

#: Names in the order they are offered to the model.
TOOL_NAMES: Final[tuple[str, ...]] = (
    "query_templates",
    "get_slice",
    "run_sql",
    "read_notes",
    "write_note",
)

#: Template ranking. The default ordering is `anomaly_score` because the ranked list *is*
#: the search: anomaly is what puts a rare, severe template above a frequent dull one, and
#: an investigator reading top-down should meet the needle before the noise.
TEMPLATE_ORDERINGS: Final[tuple[str, ...]] = ("count", "severity", "recency", "anomaly_score")
TEMPLATE_ORDER_DEFAULT: Final = "anomaly_score"
TEMPLATE_LIMIT_DEFAULT: Final = 15
TEMPLATE_LIMIT_MAX: Final = 50

#: Raw-line pulls. The hard cap is what stops one call spending the entire context on lines.
#: Lines a slice returns by default, and the ceiling on asking for more.
#:
#: Lowered from 200/500. A slice is by far the largest thing that enters the conversation, and
#: it stays there for every remaining step -- 200 near-identical lines of one template is a few
#: thousand tokens re-sent a dozen times to say what forty lines already said. The tool now
#: reports how many lines matched in total, so a narrower default costs the investigation
#: nothing it cannot ask for: it knows what it did not see.
SLICE_LINES_DEFAULT: Final = 60
SLICE_LINES_MAX: Final = 200

#: Rows returned from model-authored SQL. Lower than the scratchpad's own 500 because an
#: unconstrained `SELECT *` is the easiest way for the model to flood its own context.
SQL_ROW_CAP: Final = 200

CONFIDENCE_LEVELS: Final[tuple[str, ...]] = ("low", "medium", "high")

#: Longest a single rendered value may be before it is clipped. Raw lines are unbounded in
#: principle -- a stack trace or a serialised payload arrives as one field.
CELL_CHARS: Final = 200

#: Longest audit description written to `query_log`. Model-authored SQL can be long.
AUDIT_CHARS: Final = 500


class _ArgumentError(ValueError):
    """Arguments the tool cannot use. Carries the message handed back to the model."""


@dataclass(frozen=True, slots=True)
class _Outcome:
    """What a handler produced: text for the model, and the audit trail for the scratchpad."""

    content: str
    row_count: int
    description: str
    is_error: bool = False


class ToolBox:
    """The scratchpad, a definition of noise, and a step counter, bound to four tools.

    One instance per investigation. The step counter is held here rather than passed per
    call so `query_log` and `scratchpad_notes` order the same way and a note can be lined up
    with the queries that produced it.
    """

    def __init__(
        self,
        db: ScratchpadDB,
        noise: NoiseThresholds,
        *,
        start_step: int = 0,
    ) -> None:
        self.db = db
        self.noise = noise
        #: Step of the most recent dispatch. The first dispatch is step `start_step + 1`.
        self.step = start_step
        self._handlers: dict[str, Callable[[dict[str, Any]], _Outcome]] = {
            "query_templates": self._query_templates,
            "get_slice": self._get_slice,
            "run_sql": self._run_sql,
            "read_notes": self._read_notes,
            "write_note": self._write_note,
        }
        #: Every log event id this investigation has actually been shown. A citation naming an
        #: id that is not in here was not read, it was produced -- which is how a run came to
        #: cite events 1 and 2, the first two lines of the file, for a claim about a service
        #: that appears in neither. The ids exist, so the report's existence check passed it.
        self._seen_events: set[int] = set()

    # ---------------------------------------------------------------- schema

    def specs(self) -> list[ToolSpec]:
        """The tool definitions handed to the model, in JSON Schema.

        Defaults and caps are stated in the descriptions as well as the schema, because a
        model that knows `max_lines` is capped at 500 asks for a narrower window instead of
        discovering the cap by hitting it.
        """
        return [
            ToolSpec(
                name="query_templates",
                description=(
                    "List the incident's log templates as a ranked table. A template is a "
                    "mined message shape standing in for every line matching it, so this "
                    "list is the search space for the whole investigation. Ordering by "
                    f"{TEMPLATE_ORDER_DEFAULT} (the default) puts rare, severe, bursty "
                    "templates first, which is usually where a root cause is; order by "
                    "count to see what dominates the file instead. High-volume, low-anomaly "
                    "templates are suppressed so a heartbeat cannot crowd out the list. "
                    f"Returns at most {TEMPLATE_LIMIT_MAX} rows."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "order_by": {
                            "type": "string",
                            "enum": list(TEMPLATE_ORDERINGS),
                            "default": TEMPLATE_ORDER_DEFAULT,
                            "description": (
                                "Ranking. anomaly_score combines severity, burstiness and "
                                "rarity; count is raw frequency; severity is the highest "
                                "level seen; recency is the most recent occurrence."
                            ),
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": TEMPLATE_LIMIT_MAX,
                            "default": TEMPLATE_LIMIT_DEFAULT,
                            "description": (
                                f"Rows to return, capped at {TEMPLATE_LIMIT_MAX}. Default "
                                f"{TEMPLATE_LIMIT_DEFAULT}."
                            ),
                        },
                    },
                    "required": [],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="get_slice",
                description=(
                    "Pull a bounded window of raw log lines, oldest first. Every filter is "
                    "optional and they combine with AND; with no filters you get the "
                    "earliest lines in the incident. High-volume, low-anomaly templates are "
                    "suppressed unless you ask for a template_id explicitly, which is "
                    "treated as deliberate and returns that template's lines regardless. "
                    f"max_lines defaults to {SLICE_LINES_DEFAULT} and is capped at "
                    f"{SLICE_LINES_MAX}; narrow the time window rather than raising it. "
                    "Each line comes back with its trace id where it has one, and passing "
                    "trace_id back returns every line of that one request across services."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "start_ts": {
                            "type": "string",
                            "description": (
                                "Inclusive lower bound, ISO-8601 UTC "
                                "(e.g. 2026-08-30T14:38:00Z). Partial timestamps are "
                                "accepted and read as the instant they name."
                            ),
                        },
                        "end_ts": {
                            "type": "string",
                            "description": "Inclusive upper bound, ISO-8601 UTC.",
                        },
                        "source": {
                            "type": "string",
                            "description": "Exact source or service name to filter on.",
                        },
                        "severity": {
                            "type": "string",
                            "enum": list(SEVERITIES),
                            "description": "Exact normalised severity level.",
                        },
                        "template_id": {
                            "type": "integer",
                            "description": (
                                "Return only lines of this template, from query_templates. "
                                "Overrides noise suppression."
                            ),
                        },
                        "trace_id": {
                            "type": "string",
                            "description": (
                                "Return only lines carrying this trace id, from the trace_id "
                                "column of an earlier slice. This is how one request is "
                                "followed across services; a trace that starts in one service "
                                "and ends in an error in another is the correlation no "
                                "template ranking can show you."
                            ),
                        },
                        "max_lines": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": SLICE_LINES_MAX,
                            "default": SLICE_LINES_DEFAULT,
                            "description": (
                                f"Lines to return, capped at {SLICE_LINES_MAX}. Default "
                                f"{SLICE_LINES_DEFAULT}."
                            ),
                        },
                    },
                    "required": [],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="run_sql",
                description=(
                    "Run one read-only SELECT against the incident scratchpad, for "
                    "aggregations the other tools do not cover -- counts per source, "
                    "severity over time, joins between events and templates. Tables: "
                    "templates(template_id, pattern, occurrence_count, first_seen, "
                    "last_seen, severity_mix_json, max_severity_rank, anomaly_score); "
                    "log_events(id, ts, source, severity, template_id, raw, message, "
                    "fields_json); incidents; scratchpad_notes; query_log; run_metadata. "
                    "Timestamps are fixed-width ISO-8601 UTC text and compare "
                    "lexicographically. The channel is enforced read-only: anything that "
                    "writes, ATTACHes or reaches outside the database is refused and the "
                    f"refusal comes back to you. At most {SQL_ROW_CAP} rows are returned, "
                    "so aggregate or add LIMIT rather than selecting everything."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "A single SELECT statement.",
                        },
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="read_notes",
                description=(
                    "Read back every note recorded in this investigation so far, with the "
                    "citations attached to each. Cheap, and worth calling before concluding: "
                    "older tool output is summarised away as the investigation runs, so a "
                    "hypothesis written earlier may no longer be visible in the conversation."
                ),
                schema={
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="write_note",
                description=(
                    "Record a hypothesis or finding in the scratchpad. Evidence is "
                    "mandatory and must cite at least one real template_id or log event "
                    "id: the notes are checked against their citations afterwards, so a "
                    "claim with nothing behind it is worse than no claim. Write a note "
                    "when you have concluded something, not to narrate your search."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "note": {
                            "type": "string",
                            "description": (
                                "The finding, in plain prose: what happened, and what in "
                                "the logs says so."
                            ),
                        },
                        "evidence": {
                            "type": "object",
                            "properties": {
                                "template_ids": {
                                    "type": "array",
                                    "items": {"type": "integer"},
                                    "description": "Template ids the claim rests on.",
                                },
                                "log_event_ids": {
                                    "type": "array",
                                    "items": {"type": "integer"},
                                    "description": (
                                        "log_events.id values, as returned in the id "
                                        "column of get_slice."
                                    ),
                                },
                            },
                            "required": ["template_ids", "log_event_ids"],
                            "description": (
                                "Citations. At least one of the two arrays must be non-empty."
                            ),
                        },
                        "confidence": {
                            "type": "string",
                            "enum": list(CONFIDENCE_LEVELS),
                            "description": (
                                "How well the evidence supports the note. Use low for a "
                                "lead worth recording but not established."
                            ),
                        },
                    },
                    "required": ["note", "evidence", "confidence"],
                    "additionalProperties": False,
                },
            ),
        ]

    # ---------------------------------------------------------------- dispatch

    def dispatch(self, call: ToolCall) -> ToolResult:
        """Run one tool call, log it, and return the result.

        Never raises for anything a model could plausibly send -- an unknown name, a wrong
        enum, a mutation attempt. Those are answers, and an answer the model can act on
        beats an exception that ends the run.
        """
        self.step += 1
        handler = self._handlers.get(call.name)
        if handler is None:
            return self._finish(
                call,
                _Outcome(
                    content=(
                        f"unknown tool {call.name!r}. Available tools: {', '.join(TOOL_NAMES)}."
                    ),
                    row_count=0,
                    description=f"unknown_tool({call.name!r})",
                    is_error=True,
                ),
            )
        try:
            outcome = handler(call.arguments)
        except _ArgumentError as exc:
            outcome = _Outcome(
                content=f"{call.name}: {exc}",
                row_count=0,
                description=f"{call.name}(<invalid arguments>)",
                is_error=True,
            )
        return self._finish(call, outcome)

    def _finish(self, call: ToolCall, outcome: _Outcome) -> ToolResult:
        """Write the audit row and shape the result.

        Failures are logged with their reason rather than dropped: the audit trail is meant
        to explain the investigation, and a query the scratchpad refused is part of that.
        """
        description = outcome.description
        if outcome.is_error:
            description = f"{description} -> error: {_clip(outcome.content, AUDIT_CHARS)}"
        self.db.log_query(self.step, _clip(description, AUDIT_CHARS), outcome.row_count)
        return ToolResult(call_id=call.id, content=outcome.content, is_error=outcome.is_error)

    # ---------------------------------------------------------------- handlers

    def _query_templates(self, args: dict[str, Any]) -> _Outcome:
        order_by = _enum_arg(args, "order_by", TEMPLATE_ORDERINGS, default=TEMPLATE_ORDER_DEFAULT)
        limit = _bounded_int(
            args, "limit", default=TEMPLATE_LIMIT_DEFAULT, maximum=TEMPLATE_LIMIT_MAX
        )

        rows = self.db.top_templates(limit=limit, order_by=order_by, noise=self.noise)
        total = self.db.template_count()
        suppressed = len(self.db.noise_template_ids(self.noise))

        header = (
            f"templates: {len(rows)} returned, ordered by {order_by}, limit {limit}; "
            f"{total} templates in the incident, {suppressed} suppressed as noise "
            "(high volume, low anomaly)."
        )
        if rows and len(rows) == limit and total > limit:
            header += " Result is at the limit -- raise limit or re-rank to see more."
        table = _table(
            (
                "template_id",
                "count",
                "max_severity",
                "anomaly",
                "first_seen",
                "last_seen",
                "pattern",
            ),
            [
                (
                    row["template_id"],
                    row["occurrence_count"],
                    _severity_name(row["max_severity_rank"]),
                    row["anomaly_score"],
                    row["first_seen"],
                    row["last_seen"],
                    row["pattern"],
                )
                for row in rows
            ],
        )
        return _Outcome(
            content=f"{header}\n{table}" if rows else header,
            row_count=len(rows),
            description=f"query_templates(order_by={order_by!r}, limit={limit})",
        )

    def _get_slice(self, args: dict[str, Any]) -> _Outcome:
        start_ts = _timestamp_arg(args, "start_ts")
        end_ts = _timestamp_arg(args, "end_ts")
        source = _str_arg(args, "source")
        severity = _severity_arg(args, "severity")
        template_id = _optional_int(args, "template_id")
        trace_id = _str_arg(args, "trace_id")
        max_lines = _bounded_int(
            args, "max_lines", default=SLICE_LINES_DEFAULT, maximum=SLICE_LINES_MAX
        )

        rows = self.db.get_slice(
            start_ts=start_ts,
            end_ts=end_ts,
            source=source,
            severity=severity,
            template_id=template_id,
            max_lines=max_lines,
            noise=self.noise,
            trace_id=trace_id,
        )
        self._seen_events.update(int(row["id"]) for row in rows)

        filters = _describe(
            start_ts=start_ts,
            end_ts=end_ts,
            source=source,
            severity=severity,
            template_id=template_id,
            trace_id=trace_id,
        )
        suppression = (
            "noise suppression off (explicit template_id)"
            if template_id is not None
            else "noise templates suppressed"
        )
        matched = self.db.slice_match_count(
            start_ts=start_ts,
            end_ts=end_ts,
            source=source,
            severity=severity,
            template_id=template_id,
            noise=self.noise,
            trace_id=trace_id,
        )
        header = (
            f"lines: {len(rows)} shown of {matched} matching (max_lines {max_lines}); "
            f"filters: {filters or 'none'}; {suppression}."
        )
        withheld = matched - len(rows)
        if withheld > 0:
            # The count, not just the fact of truncation: four withheld lines and forty
            # thousand are the difference between reading the rest and narrowing the window,
            # and the investigation cannot tell them apart from "hit the cap".
            header += (
                f" {withheld} matching line(s) are not shown. Narrow the window or filter "
                "further rather than raising max_lines."
            )
        table = _table(
            ("id", "ts", "source", "severity", "template_id", "trace_id", "text"),
            [
                (
                    row["id"],
                    row["ts"],
                    row["source"],
                    row["severity"],
                    row["template_id"],
                    row["trace_id"] or "-",
                    row["message"] or row["raw"],
                )
                for row in rows
            ],
        )
        return _Outcome(
            content=f"{header}\n{table}" if rows else header,
            row_count=len(rows),
            description=f"get_slice({filters or 'no filters'}, max_lines={max_lines})",
        )

    def _run_sql(self, args: dict[str, Any]) -> _Outcome:
        query = _required_str(args, "query")
        try:
            rows = self.db.run_readonly_sql(query, max_rows=SQL_ROW_CAP)
        except (ReadOnlyViolation, sqlite3.Error) as exc:
            return _Outcome(
                content=(
                    f"run_sql refused or failed: {exc}. This channel allows a single "
                    "read-only SELECT over the scratchpad tables; writes, ATTACH, PRAGMA "
                    "and extension loading are denied at the connection level. Rewrite the "
                    "query as a SELECT and try again."
                ),
                row_count=0,
                description=query,
                is_error=True,
            )

        header = f"sql: {len(rows)} rows returned (cap {SQL_ROW_CAP})."
        if len(rows) == SQL_ROW_CAP:
            header += (
                f" Result hit the {SQL_ROW_CAP}-row cap, so there are probably more rows "
                "-- aggregate, or add LIMIT/OFFSET."
            )
        if not rows:
            return _Outcome(content=header, row_count=0, description=query)
        columns = tuple(rows[0])
        if "id" in columns and "log_events" in query.lower():
            # Only when the query actually read log_events: `id` is a column on several
            # tables, and counting a note id as an event the model has seen would let a
            # fabricated citation back through the gate below.
            self._seen_events.update(
                int(row["id"]) for row in rows if isinstance(row.get("id"), int)
            )
        table = _table(columns, [tuple(row.get(column) for column in columns) for row in rows])
        return _Outcome(content=f"{header}\n{table}", row_count=len(rows), description=query)

    def _read_notes(self, args: dict[str, Any]) -> _Outcome:
        """Every note this investigation has written, with its citations.

        Without this the scratchpad is an output sink, not working memory: the model could
        write a hypothesis and never see it again, so its own earlier reasoning survived only
        in the conversation. That was tolerable while the conversation was kept whole. It is
        not now that older tool output is compacted away, and it is the difference between a
        scratchpad and a log file.
        """
        del args  # takes no arguments; the whole point is that it is cheap to call
        notes = self.db.notes()
        header = f"notes: {len(notes)} recorded so far."
        if not notes:
            return _Outcome(
                content=f"{header} Nothing has been concluded yet.",
                row_count=0,
                description="read_notes()",
            )
        table = _table(
            ("step", "confidence", "template_ids", "log_event_ids", "note"),
            [
                (
                    note.step,
                    note.confidence,
                    ",".join(str(i) for i in note.evidence.get("template_ids", [])) or "-",
                    ",".join(str(i) for i in note.evidence.get("log_event_ids", [])) or "-",
                    note.note,
                )
                for note in notes
            ],
        )
        return _Outcome(
            content=f"{header}\n{table}",
            row_count=len(notes),
            description="read_notes()",
        )

    def _write_note(self, args: dict[str, Any]) -> _Outcome:
        note = _required_str(args, "note")
        confidence = _enum_arg(args, "confidence", CONFIDENCE_LEVELS, default=None)
        evidence = _evidence_arg(args)
        template_ids: list[int] = evidence["template_ids"]
        event_ids: list[int] = evidence["log_event_ids"]

        description = (
            f"write_note(confidence={confidence!r}, template_ids={template_ids}, "
            f"log_event_ids={event_ids})"
        )

        # Refused before the note is written, unlike the existence check below, because these
        # two failures are different. A cited id that does not exist is a typo. A cited id
        # that exists but was never returned to this investigation was not read -- it was
        # produced, and it will resolve to a real row that says nothing about the claim, which
        # is the one kind of bad citation the report's verifier cannot catch. A run did
        # exactly this: it cited events 1 and 2, the first two lines of the file, for a claim
        # about a service appearing in neither, after switching to run_sql and selecting no
        # id column. Only the adversarial model caught it.
        unseen = sorted(set(event_ids) - self._seen_events)
        if unseen:
            return _Outcome(
                content=(
                    f"write_note rejected: log event id(s) {unseen} were never returned to "
                    "this investigation, so they cannot support a claim. Cite ids from the "
                    "`id` column of a get_slice result, or select log_events.id in run_sql "
                    "and cite from that. If the finding rests on templates rather than "
                    "individual lines, cite template_ids alone."
                ),
                row_count=0,
                description=description,
                is_error=True,
            )

        try:
            note_id = self.db.write_note(self.step, note, evidence, confidence)
        except (ValueError, TypeError, sqlite3.Error) as exc:
            return _Outcome(
                content=f"write_note rejected: {exc}",
                row_count=0,
                description=description,
                is_error=True,
            )

        content = (
            f"write_note: saved note {note_id} at step {self.step} (confidence={confidence}, "
            f"citing {len(template_ids)} template(s) and {len(event_ids)} log event(s))."
        )
        # Existence is checked but does not lose the note: refusing here over one mistyped id
        # would throw away a sound finding, and the report's verifier is the authority. Naming
        # the unresolved ids gives the model the chance to correct itself.
        unknown = _unresolved(self.db, template_ids, event_ids)
        if unknown:
            content += f" Warning: these cited ids do not exist in the scratchpad: {unknown}."
        return _Outcome(content=content, row_count=1, description=description)


# ---------------------------------------------------------------- argument coercion


def _coerce_int(value: object, name: str) -> int:
    """Accept the integer shapes a model actually emits, reject the rest.

    Numeric strings are accepted because models emit `"15"` often enough that refusing it
    would spend a turn on a value that was never ambiguous. Booleans are not, even though
    Python calls them integers.
    """
    if isinstance(value, bool):
        raise _ArgumentError(f"{name} must be an integer, not a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("+-").isdigit():
        return int(value.strip())
    raise _ArgumentError(f"{name} must be an integer, got {type(value).__name__} ({value!r})")


def _bounded_int(args: dict[str, Any], name: str, *, default: int, maximum: int) -> int:
    """A positive integer, clamped down to `maximum`.

    Over the cap is clamped rather than refused: the model asked for more than it can have,
    which is not a mistake it needs to fix, and every result header echoes the effective
    value so the clamp is visible. Below one is refused, because there is no sensible
    reading of a zero-row request.
    """
    raw = args.get(name)
    if raw is None:
        return default
    value = _coerce_int(raw, name)
    if value < 1:
        raise _ArgumentError(f"{name} must be at least 1, got {value}")
    return min(value, maximum)


def _optional_int(args: dict[str, Any], name: str) -> int | None:
    raw = args.get(name)
    return None if raw is None else _coerce_int(raw, name)


def _str_arg(args: dict[str, Any], name: str) -> str | None:
    raw = args.get(name)
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise _ArgumentError(f"{name} must be a string, got {type(raw).__name__}")
    stripped = raw.strip()
    return stripped or None


def _required_str(args: dict[str, Any], name: str) -> str:
    value = _str_arg(args, name)
    if value is None:
        raise _ArgumentError(f"{name} is required and must be a non-empty string")
    return value


def _enum_arg(
    args: dict[str, Any],
    name: str,
    allowed: Sequence[str],
    *,
    default: str | None,
) -> str:
    valid = ", ".join(allowed)
    raw = args.get(name)
    if raw is None:
        if default is None:
            raise _ArgumentError(f"{name} is required. Valid values: {valid}")
        return default
    if not isinstance(raw, str):
        raise _ArgumentError(f"{name} must be a string. Valid values: {valid}")
    value = raw.strip().lower()
    if value not in allowed:
        raise _ArgumentError(f"{name}={raw!r} is not valid. Valid values: {valid}")
    return value


def _severity_arg(args: dict[str, Any], name: str) -> str | None:
    """A severity, normalised to the stored casing.

    Matching is exact in SQL, so `"fatal"` would return an empty slice and read as "no such
    lines" rather than "wrong case" -- a silent wrong answer, which is the one outcome worth
    spending code to avoid.
    """
    raw = _str_arg(args, name)
    if raw is None:
        return None
    value = raw.upper()
    if value not in SEVERITIES:
        raise _ArgumentError(
            f"{name}={raw!r} is not a known severity. Valid values: {', '.join(SEVERITIES)}"
        )
    return value


def _timestamp_arg(args: dict[str, Any], name: str) -> str | None:
    """Normalise a timestamp to the fixed-width UTC form `ts` is stored in.

    Bounds are compared lexicographically against stored text, so an unnormalised string is
    not a rejected filter but a wrong one: `"2026-08-30 14:38"` sorts before every stored
    row and silently widens the window.
    """
    raw = _str_arg(args, name)
    if raw is None:
        return None
    try:
        moment = parse_timestamp(raw)
    except ValueError as exc:
        raise _ArgumentError(
            f"{name}={raw!r} is not a timestamp I can read ({exc}). Use ISO-8601 UTC, "
            "e.g. 2026-08-30T14:38:00Z"
        ) from exc
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _evidence_arg(args: dict[str, Any]) -> dict[str, Any]:
    """Validate the citations a note rests on.

    The scratchpad's own guards stop at *some* evidence: `write_note` rejects a falsy dict
    and the SQL CHECK rejects the literal `{}`, but `{"template_ids": [], "log_event_ids":
    []}` is truthy and passes both while citing nothing at all. The rule the design actually
    means -- a note points at something real -- has to be enforced here.
    """
    shape = 'evidence must be an object like {"template_ids": [12], "log_event_ids": [3401, 3402]}'
    raw = args.get("evidence")
    if raw is None:
        raise _ArgumentError(f"evidence is required: {shape}")
    if not isinstance(raw, dict):
        raise _ArgumentError(f"evidence must be an object, got {type(raw).__name__}. {shape}")

    evidence = dict(raw)
    template_ids = _id_list(evidence.get("template_ids"), "evidence.template_ids")
    event_ids = _id_list(evidence.get("log_event_ids"), "evidence.log_event_ids")
    if not template_ids and not event_ids:
        raise _ArgumentError(
            "evidence cites nothing. Give at least one template_id or log_event_id: a note "
            "without citations cannot be verified and will not be accepted. " + shape
        )
    evidence["template_ids"] = template_ids
    evidence["log_event_ids"] = event_ids
    return evidence


def _id_list(value: object, name: str) -> list[int]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise _ArgumentError(f"{name} must be an array of integers, got {type(value).__name__}")
    return [_coerce_int(item, f"{name}[{index}]") for index, item in enumerate(value)]


def _unresolved(db: ScratchpadDB, template_ids: Sequence[int], event_ids: Sequence[int]) -> str:
    """Cited ids with no row behind them, rendered for the model. Empty string when clean."""
    known_templates = db.known_template_ids(template_ids)
    missing_templates = [i for i in template_ids if i not in known_templates]
    known_events = {int(row["id"]) for row in db.events_by_id(event_ids)}
    missing_events = [i for i in event_ids if i not in known_events]
    parts = []
    if missing_templates:
        parts.append(f"template_ids {missing_templates}")
    if missing_events:
        parts.append(f"log_event_ids {missing_events}")
    return ", ".join(parts)


# ---------------------------------------------------------------- rendering


def _clip(text: str, limit: int = CELL_CHARS) -> str:
    """Flatten and bound one value, saying how much was dropped.

    The count matters more than the text it replaces. A model told `...(+4211 more chars)`
    knows to fetch the line by id; a model handed a quietly shortened string reads it as the
    whole line.
    """
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return f"{flat[:limit]}...(+{len(flat) - limit} more chars)"


def _cell(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.3f}"
    return _clip(str(value))


def _table(columns: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    """Rows as one pipe-delimited line each, under a single column legend.

    Repeating field names per row costs more tokens than the whole rest of the result on a
    200-line slice, so the names are stated once.
    """
    lines = ["columns: " + " | ".join(columns)]
    lines.extend(" | ".join(_cell(value) for value in row) for row in rows)
    return "\n".join(lines)


def _severity_name(rank: object) -> str:
    index = int(rank) if isinstance(rank, (int, float)) else 0
    return SEVERITIES[index] if 0 <= index < len(SEVERITIES) else str(rank)


def _describe(**filters: object) -> str:
    return ", ".join(f"{name}={value}" for name, value in filters.items() if value is not None)

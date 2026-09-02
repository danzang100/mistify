"""Which of an investigation's notes leads, and in what order the rest follow.

This is domain logic, not rendering. It used to live inside the report generator, which meant
the eval scorer had to call `collect()` -- building health warnings, token totals, per-source
activity and the whole glance section -- to answer one question: which templates does the
leading finding rest on. That is a rendering pipeline being run for its side effects, and it
coupled scoring to the shape of a document rather than to the shape of an investigation.

Both callers now ask here. The report renders what this returns; the eval scores what this
returns; neither depends on the other, and the ranking cannot drift between what a reader sees
and what a score claims about it.

The ordering itself is deliberately model-free. It keys on the anomaly score of the templates
each note cites, which no model touched, so two runs that reason differently but reach the same
templates present their findings in the same order. Measured across three runs of one incident,
note *position* meant nothing: the first note was an early narrow hypothesis twice, and the last
was a deliberate aside once.
"""

from __future__ import annotations

from typing import Any

from mistify.common.models import SYNTHESIS_MARKER, parse_timestamp

__all__ = [
    "CHRONIC_SHARE",
    "chronic_template_ids",
    "describe_issues",
    "duration_minutes",
    "rank_notes",
]

#: Confidence as an order, so notes can be ranked without a model.
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

#: A template active for at least this share of the log is chronic rather than part of the
#: event: it was already happening before the incident and did not stop after it.
#:
#: `ScratchpadDB.chronic_template_ids` answers the same question from SQL for callers that hold
#: a database. This one works from template rows the report has already loaded, and both read
#: the same constant so the two cannot disagree about where the line is.
CHRONIC_SHARE = 0.9


def rank_notes(notes: list[dict[str, Any]], scores: dict[int, float]) -> list[dict[str, Any]]:
    """Every recorded hypothesis, most significant first.

    Not in the order they were written, and not filtered: an investigation that found two
    unrelated problems has found two problems, and an overview with room for one of them loses
    the other.
    """

    def key(note: dict[str, Any]) -> tuple[int, float, int, int]:
        cited = [int(i) for i in note["evidence"].get("template_ids", [])]
        return (
            # A synthesis note *is* the conclusion, written from the whole scratchpad after the
            # search finished. It leads by construction rather than by out-scoring the notes it
            # was written from.
            1 if note["evidence"].get(SYNTHESIS_MARKER) else 0,
            max((scores.get(i, 0.0) for i in cited), default=0.0),
            _CONFIDENCE_RANK.get(str(note["confidence"]).lower(), 0),
            -int(note["step"]),
        )

    return sorted(notes, key=key, reverse=True)


def describe_issues(
    ranked: list[dict[str, Any]], scores: dict[int, float], chronic: set[int]
) -> list[dict[str, Any]]:
    """The ranked notes as the overview of what was found."""
    issues = []
    for position, note in enumerate(ranked, start=1):
        cited = [int(i) for i in note["evidence"].get("template_ids", [])]
        issues.append(
            {
                "rank": position,
                "note": note["note"],
                "step": note["step"],
                "confidence": note["confidence"],
                "template_ids": cited,
                "top_score": max((scores.get(i, 0.0) for i in cited), default=0.0),
                "synthesis": bool(note["evidence"].get(SYNTHESIS_MARKER)),
                # Only when every template it rests on is chronic. One acute template among them
                # means the note is about the event, whatever else it mentions.
                "chronic": bool(cited) and all(i in chronic for i in cited),
            }
        )
    return issues


def duration_minutes(first: str | None, last: str | None) -> float | None:
    """Minutes between two scratchpad timestamps, or None if either is missing."""
    if not first or not last:
        return None
    return (parse_timestamp(last) - parse_timestamp(first)).total_seconds() / 60


def chronic_template_ids(templates: list[dict[str, Any]], log_minutes: float | None) -> set[int]:
    """Templates active across essentially the whole log, from rows already in hand."""
    if not log_minutes:
        return set()
    chronic = set()
    for template in templates:
        minutes = duration_minutes(template["first_seen"], template["last_seen"])
        if minutes is not None and minutes >= log_minutes * CHRONIC_SHARE:
            chronic.add(int(template["template_id"]))
    return chronic

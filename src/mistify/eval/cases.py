"""Evaluation cases: a log file, and what a correct investigation of it would say.

A case is deliberately thin -- a way to produce the file, plus expectations expressed as
substrings of the log lines that were planted. Nothing here knows about template ids, because
template ids are assigned by clustering at ingest and change the moment a fixture does; the
scorer resolves a marker to whatever template carries it. Hardcoded ids would make the suite
break for the one reason that has nothing to do with investigation quality.

`source` is a callable that writes a file, so an external corpus is added by pointing a case at
a downloaded path rather than by teaching the harness a second notion of what a case is. That
matters more than it looks: the whole value of a harness is that adding a case is cheap, and
the plan's Loghub and LogDx-CI corpora are cases, not a different kind of thing.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from mistify.eval.fixtures import (
    FIXTURE_VERSION,
    RED_HERRING_MARKER,
    ROOT_CAUSE_MARKER,
    write_incident,
    write_incident_otlp,
    write_quiet_hour,
)

__all__ = ["CASES", "PRECURSOR_MARKER", "EvalCase", "case_names", "get_case"]

#: The rising connection-acquisition latency the incident fixture plants ahead of the outage.
#: Named here rather than in the fixture because it is an expectation, not a planted constant:
#: the fixture would still be correct if nothing ever checked for it.
PRECURSOR_MARKER = "Connection acquisition took"


@dataclass(frozen=True, slots=True)
class EvalCase:
    """One log file with a known answer."""

    name: str
    summary: str
    #: Writes the fixture and returns its path. Takes a directory so runs cannot collide.
    source: Callable[[Path], Path]

    #: True when the file contains an incident to find. False makes this a negative control,
    #: and the bar changes completely: the question stops being "did it find the answer" and
    #: becomes "did it invent one".
    expects_incident: bool = True

    #: Markers whose template a finding must cite. The claim has to be traceable to rows, so
    #: naming the thing in prose is not enough -- see issue 10.
    must_cite: tuple[str, ...] = ()

    #: Markers that must not carry the conclusion. Citing one is allowed when the finding marks
    #: it as background; leading with it is the failure a red herring is planted to provoke.
    must_not_lead: tuple[str, ...] = ()

    #: Bumped with the fixture generators. Recorded on every result, because a score compared
    #: against a differently generated file is not a comparison.
    fixture_version: int = FIXTURE_VERSION

    #: Free-form, rendered next to the result so a reader knows what "pass" meant here.
    notes: tuple[str, ...] = field(default_factory=tuple)


CASES: tuple[EvalCase, ...] = (
    EvalCase(
        name="pool-exhaustion",
        summary="One incident: pool exhaustion, a latency precursor, and a noisier red herring.",
        source=lambda directory: write_incident(directory / "pool_exhaustion.jsonl"),
        expects_incident=True,
        must_cite=(ROOT_CAUSE_MARKER, PRECURSOR_MARKER),
        must_not_lead=(RED_HERRING_MARKER,),
        notes=(
            "The herring fires 350 times to the root cause's 40, so anything ranking on volume "
            "leads with it.",
            "The precursor is the case's real difficulty: it is WARN-level, ends before the "
            "outage begins, and every run measured before the coverage nudge omitted it.",
        ),
    ),
    EvalCase(
        name="pool-exhaustion-otlp",
        summary="The same incident, exported as OTLP logs. Does the format survive the adapter?",
        source=lambda directory: write_incident_otlp(directory / "pool_exhaustion_otlp.jsonl"),
        expects_incident=True,
        must_cite=(ROOT_CAUSE_MARKER, PRECURSOR_MARKER),
        must_not_lead=(RED_HERRING_MARKER,),
        notes=(
            "Deliberately the same generator as pool-exhaustion, so the only variable is the "
            "format. A separate OTLP scenario would have measured two things at once.",
            "Severity moves from a JSON level field to a numeric severityNumber in bands, the "
            "service name moves from the record to the resource, and timestamps become "
            "nanosecond strings. Any of those read wrongly changes the ranking, not just the "
            "parse.",
        ),
    ),
    EvalCase(
        name="quiet-hour",
        summary="An hour of healthy service. There is nothing to find.",
        source=lambda directory: write_quiet_hour(directory / "quiet_hour.jsonl"),
        expects_incident=False,
        notes=(
            "The only case that asks whether the agent invents an answer, which is the "
            "failure mode that matters most on a page that turns out to be nothing.",
            "A low or medium note describing normal operation passes. A high-confidence "
            "finding does not, whatever it says.",
            "The coverage nudge still fires here -- the anomaly ranking always names a signal "
            "set -- and answering it with a reasoned dismissal is the correct behaviour.",
        ),
    ),
)


def case_names() -> list[str]:
    return [case.name for case in CASES]


def get_case(name: str) -> EvalCase:
    for case in CASES:
        if case.name == name:
            return case
    raise KeyError(f"unknown eval case {name!r}. Known: {', '.join(case_names())}")

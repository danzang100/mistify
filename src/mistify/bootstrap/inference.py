"""Model-assisted schema inference: the fallback when looking at the lines was not enough.

The model is never asked for a regex. It is asked to point at the substrings - for a handful of
sample lines, which part is the timestamp, which is the severity, which is the message - and
this module derives the schema from where those substrings actually sit.

That is the whole safety argument. A model-authored regex has to be trusted before it can be
tested: it may not compile, it may backtrack catastrophically, and a persisted one is a pattern
nobody reviewed being run on every future file from that source. A quoted substring can be
checked against the line it came from before anything is built, and a claim that does not
appear in its line is discarded rather than believed. Architecture §2.2a's risk table calls this
stage's failure mode *silent*; this is what makes it noisy instead.

The sub-sample is deduplicated and diverse rather than the first N lines, per §2.2a. Sequential
log lines are near-identical, so a raw prefix shows the model one shape several times and
teaches it nothing about the file.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from mistify.bootstrap.schema import TIMESTAMP_PATTERNS, FieldSchema, severity_pattern
from mistify.llm.base import LLMProvider, Message

__all__ = ["INFERENCE_PROMPT", "diverse_sample", "infer_with_model"]

INFERENCE_PROMPT = """You are identifying the fields in an unfamiliar log format.

For each numbered line you are given, quote the exact substring that is:

- the timestamp
- the severity or log level, if the line has one
- the free-text message: what a human reading the log would call the event, with the
  timestamp, level and any leading identifiers removed

Quote substrings exactly as they appear. Do not reformat, normalise, translate or explain them.
If a line has no severity, use an empty string for it. Do not invent a timestamp for a line
that has none -- use an empty string, and that line will be skipped.

Reply with JSON only:

{"lines": [{"n": <line number>, "timestamp": "...", "severity": "...", "message": "..."}]}
"""

_SEVERITY = re.compile(rf"^({severity_pattern()})$", re.IGNORECASE)
_COMPILED_TIMESTAMPS = {
    name: re.compile(rf"^{pattern}$") for name, pattern in TIMESTAMP_PATTERNS.items()
}


@dataclass(frozen=True, slots=True)
class _Reading:
    """One line's fields as the model quoted them, after checking they are really there."""

    timestamp_shape: str
    has_severity: bool
    has_source: bool


def diverse_sample(lines: list[str], limit: int = 40) -> list[str]:
    """A deduplicated spread across the file, not its first `limit` lines.

    Sequential log lines repeat: a raw prefix is often one shape many times over, which shows
    the model nothing about the variety it is being asked to describe. Digits are flattened to
    decide what counts as a duplicate, because two lines differing only in a request id are the
    same shape for this purpose.
    """
    seen: set[str] = set()
    picked: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        shape = re.sub(r"\d+", "#", line)
        if shape in seen:
            continue
        seen.add(shape)
        picked.append(line)
        if len(picked) >= limit:
            break
    return picked


def _classify(line: str, timestamp: str, severity: str, message: str) -> _Reading | None:
    """Turn one quoted reading into a schema fragment, or reject it.

    Every claim is checked against the line before it is used. A model that paraphrased a
    timestamp, hallucinated a level the line does not contain, or returned a message that is
    not a substring has said something about a line other than this one, and the reading is
    dropped instead of being averaged in.
    """
    if not timestamp or timestamp not in line:
        return None
    shape = next((name for name, p in _COMPILED_TIMESTAMPS.items() if p.match(timestamp)), None)
    if shape is None:
        # The substring is in the line but is not a timestamp shape this project can parse.
        # Better to fail the gate than to persist an adapter around a format we cannot read.
        return None
    if severity and (severity not in line or not _SEVERITY.match(severity.strip("[]() "))):
        return None
    if message and message not in line:
        return None

    # A source field is whatever sits between the severity and the message: if removing the
    # timestamp, the severity and the message leaves a `name:`-shaped remainder, the format has
    # one, and leaving it in the message would put hostnames into every template.
    remainder = line
    for part in (timestamp, severity, message):
        if part:
            remainder = remainder.replace(part, " ", 1)
    return _Reading(
        timestamp_shape=shape,
        has_severity=bool(severity),
        has_source=bool(re.search(r"[\w.\-/]+(?:\[\d+\])?:", remainder)),
    )


def infer_with_model(
    provider: LLMProvider, lines: list[str], max_tokens: int = 4096
) -> FieldSchema | None:
    """One call, then a schema built from what survived checking.

    Returns None rather than a guess when the readings disagree or none survive. The caller
    still runs the match-rate gate on the result: this function's job is to produce a candidate
    worth testing, never to decide that it is right.
    """
    sample = diverse_sample(lines)
    if not sample:
        return None

    numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(sample, start=1))
    turn = provider.converse(
        system=INFERENCE_PROMPT,
        messages=[Message(role="user", text=numbered)],
        max_tokens=max_tokens,
    )

    text = turn.text.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
    try:
        parsed = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None

    readings: list[_Reading] = []
    for entry in parsed.get("lines", []):
        try:
            index = int(entry.get("n", 0)) - 1
        except (TypeError, ValueError):
            continue
        if not 0 <= index < len(sample):
            continue
        reading = _classify(
            sample[index],
            str(entry.get("timestamp", "")),
            str(entry.get("severity", "")),
            str(entry.get("message", "")),
        )
        if reading is not None:
            readings.append(reading)

    if not readings:
        return None

    # Majority across surviving readings, not the first one: a single line can be read several
    # ways, and the shape the file mostly has is the one worth building a schema around.
    shapes = [r.timestamp_shape for r in readings]
    return FieldSchema(
        timestamp=max(set(shapes), key=shapes.count),
        has_severity=sum(r.has_severity for r in readings) > len(readings) / 2,
        has_source=sum(r.has_source for r in readings) > len(readings) / 2,
        origin="model",
        notes=(f"{len(readings)} of {len(sample)} sampled lines read consistently",),
    )

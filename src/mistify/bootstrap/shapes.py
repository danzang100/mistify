"""The structural pass: infer a format from the shape of the lines, with no model call.

This runs before any model is asked, for a reason. Most unknown formats are unknown only in the
sense that nobody wrote an adapter for them -- they still begin with a timestamp, name a
severity, and put free text at the end. That is recoverable by looking, and looking is free.

The model is the fallback, not the method. Every line this stage handles is a line that never
reaches a prompt, which matters for cost, for latency, and for the risk that hangs over this
whole stage: a schema derived by inspection can be explained, and one derived by
inference has to be taken on trust and then checked.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from mistify.bootstrap.schema import TIMESTAMP_PATTERNS, FieldSchema, match_rate, severity_pattern

__all__ = ["LineShape", "cluster_shapes", "infer_structurally"]

_SEVERITY = re.compile(rf"\b({severity_pattern()})\b", re.IGNORECASE)
_COMPILED_TIMESTAMPS = {name: re.compile(pattern) for name, pattern in TIMESTAMP_PATTERNS.items()}

#: A source field is only claimed when most lines have one. Claiming it on a minority pushes
#: the first word of every other line's message into a field, and the message is what Drain3
#: clusters on -- so a wrong guess here shows up as templates full of hostnames.
_SOURCE_SHARE = 0.8

#: How many candidate shapes a sub-template retry will consider. Two or three is the limit:
#: past that it stops being "this file has a couple of shapes" and becomes a parser that will
#: match anything, which is the same as not validating at all.
MAX_SUBSHAPES = 3


@dataclass(frozen=True, slots=True)
class LineShape:
    """What one line looks like, without reading what it says."""

    timestamp: str | None
    has_severity: bool
    has_source: bool
    #: Token count bucketed rather than exact: real logs vary line to line, and an exact count
    #: would put every line in its own cluster.
    width: str

    @property
    def signature(self) -> tuple[str | None, bool, bool, str]:
        return (self.timestamp, self.has_severity, self.has_source, self.width)


_SOURCE_TOKEN = re.compile(r"^[\w.\-/]+(?:\[\d+\])?:$")


def _shape_of(line: str) -> LineShape:
    timestamp = next(
        (name for name, pattern in _COMPILED_TIMESTAMPS.items() if pattern.search(line)), None
    )
    tokens = line.split()
    width = "short" if len(tokens) <= 6 else "medium" if len(tokens) <= 15 else "long"
    return LineShape(
        timestamp=timestamp,
        has_severity=bool(_SEVERITY.search(line)),
        has_source=any(_SOURCE_TOKEN.match(token) for token in tokens[:5]),
        width=width,
    )


def cluster_shapes(lines: list[str]) -> list[tuple[LineShape, int]]:
    """Distinct line shapes in the sample, commonest first.

    This is what makes the sub-template retry possible: when one schema cannot reach the match
    rate, the answer is usually that the file holds two or three shapes -- stack traces mixed
    with key-value lines is the common case -- rather than that inference failed.
    """
    shapes = [_shape_of(line) for line in lines if line.strip()]
    counts: Counter[tuple[str | None, bool, bool, str]] = Counter(s.signature for s in shapes)
    by_signature = {s.signature: s for s in shapes}
    return [(by_signature[sig], count) for sig, count in counts.most_common()]


def infer_structurally(lines: list[str]) -> FieldSchema | None:
    """A schema from inspection alone, or None when the lines do not look like logs.

    Returns the best candidate rather than the first: whether a format has a source field is a
    judgement the shapes cannot settle on their own -- a hostname and a bare first word look
    identical -- so both readings are built and the one that parses more lines wins.
    """
    candidates = [line for line in lines if line.strip()]
    if not candidates:
        return None

    timestamps = Counter(
        name
        for line in candidates
        for name, pattern in _COMPILED_TIMESTAMPS.items()
        if pattern.search(line)
    )
    if not timestamps:
        # No timestamp anywhere is the one thing this stage cannot work around: every later
        # stage orders on time, and inventing one would make the incident window fiction.
        return None

    severity_share = sum(1 for line in candidates if _SEVERITY.search(line)) / len(candidates)
    source_share = sum(1 for line in candidates if _shape_of(line).has_source) / len(candidates)

    best: FieldSchema | None = None
    # Below zero so the first candidate always wins. Starting at zero returned None whenever
    # every reading scored 0.0, and the caller then reported "no timestamp shape found" for a
    # file that had one and simply did not parse -- a wrong diagnosis of a real failure.
    best_rate = -1.0
    # Most common timestamp shape first, but try each: `epoch` matches digits inside other
    # formats, so the commonest hit is not always the right reading.
    for name, _ in timestamps.most_common():
        source_options = (True, False) if source_share >= _SOURCE_SHARE else (False,)
        for has_source in source_options:
            # Both field orders are tried rather than assumed. Neither is guessable from the
            # presence of the fields, and picking one silently failed every file using the
            # other -- which reads as "this format is unreadable" rather than "wrong sequence".
            for source_first in (False, True) if has_source else (False,):
                schema = FieldSchema(
                    timestamp=name,
                    has_severity=severity_share >= 0.5,
                    has_source=has_source,
                    source_first=source_first,
                    origin="structural",
                )
                rate = match_rate(schema, candidates)
                if rate > best_rate:
                    best, best_rate = schema, rate

    return best

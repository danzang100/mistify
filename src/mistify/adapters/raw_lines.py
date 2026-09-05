"""Last-resort adapter: every line is the message, and nothing is claimed about it.

Phase 4's exit criterion is that a file no adapter recognises "falls back to raw-line mode
loudly, with the reason in run_metadata". Loudly is the operative word. The two failure modes
this replaces are both worse than a degraded parse:

* **Refusing the file.** An investigation that cannot start is not safer than one that starts
  with less; an engineer holding an unrecognised log still needs the templating, the ranking
  and the search, all of which work on message text alone.
* **Guessing.** Inventing a timestamp or a severity produces a scratchpad that looks exactly
  like a well-parsed one, and every number downstream -- the incident window, the severity
  mix, the anomaly score -- silently describes a fiction.

So this adapter claims nothing it cannot read. It never wins detection on its own: `detect`
returns zero always, and the pipeline reaches for it only after everything else has declined,
which is why the fallback is a deliberate act recorded in the metrics rather than an adapter
quietly winning a vote.

What it costs is stated rather than hidden. Without timestamps the incident window collapses,
burstiness cannot be computed, and the anomaly score falls back to severity and rarity alone --
so the report says the file was read this way and why.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mistify.adapters.base import LogAdapter
from mistify.adapters.source import open_text
from mistify.bootstrap.schema import TIMESTAMP_PATTERNS
from mistify.common.models import LogRecord, normalize_severity, parse_timestamp

__all__ = ["RawLinesAdapter"]

#: Timestamp shapes to try, ordered by **how completely a match determines an instant**.
#:
#: Deliberately not `TIMESTAMP_PATTERNS`' own order, which is most-specific-first because the
#: bootstrapper is asking a different question: which pattern most precisely identifies this
#: format. Here the question is which match yields the most correct absolute time, and the two
#: orders disagree on real corpora. Measured on Loghub:
#:
#: * **Thunderbird matches `syslog` and `epoch` at 100% each, and they disagree.** `syslog`
#:   reads `Nov 10 00:05:01` and, having no year to read, infers the current one -- 2026 for a
#:   2005 log. `epoch` reads `1131523501` and gets it right.
#: * **Apache** carries `[Sun Dec 04 04:47:44 2005]`. The syslog pattern captures the middle of
#:   that and drops the year that was sitting next to it.
#:
#: So the year-bearing shapes come first. `clf` is last and is expected never to win:
#: `parse_timestamp` cannot read it, which the sampling gate below discovers by trying.
_TIMESTAMP_PREFERENCE = ("iso8601", "epoch", "syslog", "clf")

#: Shapes that carry no year, so the year is inferred from the clock at ingest time. Recorded,
#: because intervals from these are trustworthy and absolute dates are not -- and a log crossing
#: 31 December will appear to run backwards.
_YEARLESS_SHAPES = frozenset({"syslog", "clf"})

#: Share of sampled lines a shape must parse before it is adopted for the whole file.
#:
#: High on purpose. A shape matching most lines leaves the rest to be filled in, and the cure
#: for a mixed file is worse than the disease: a handful of 1970 rows among real timestamps
#: makes the incident window span fifty-five years, which is a worse lie than an honestly
#: synthetic ordering. Lines that miss an adopted shape inherit the previous line's timestamp
#: instead -- the right reading for a stack-trace continuation, which is what they usually are.
_TIMESTAMP_SHARE = 0.9

#: Lines examined to choose a shape. The same order of magnitude as the detection sample, and
#: enough that a file whose first few lines are a banner does not decide for the rest.
_TIMESTAMP_SAMPLE_LINES = 400

_COMPILED_TIMESTAMPS = {
    name: re.compile(TIMESTAMP_PATTERNS[name])
    for name in _TIMESTAMP_PREFERENCE
    if name in TIMESTAMP_PATTERNS
}

#: Severity words anywhere in the line. Deliberately crude: this is the one thing worth
#: attempting to recover, because severity is the heaviest term in the anomaly score and a file
#: read entirely as INFO ranks nothing above anything else.
_SEVERITY = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|FATAL|CRITICAL|CRIT|SEVERE)\b"
)


class RawLinesAdapter(LogAdapter):
    """Reads any text file as one record per line, inventing nothing."""

    format_name = "raw_lines"
    #: Last resort. Belt and braces alongside the always-zero `detect()`: this adapter must
    #: never be reachable by detection, and the tier says so even if a future change to the
    #: confidence floor would otherwise let a zero through.
    specificity = 0

    def detect(self, sample_lines: list[str]) -> float:
        """Always zero.

        This adapter would match every text file on earth, so letting it compete would make it
        win ties against adapters that actually understand the format. It is selected by the
        pipeline explicitly, after everything else has declined.
        """
        return 0.0

    def _adopt_timestamp_shape(self, path: Path) -> str | None:
        """The one timestamp shape this file will be read with, or None for ordinals.

        Chosen from a sample and then applied unchanged, for two reasons. Running four patterns
        against 16.6 million lines costs four times what running one costs, and -- more
        importantly -- a per-line choice would let two shapes win on different lines of the same
        file and produce timestamps that are not comparable with each other.

        A shape is only adopted if `parse_timestamp` can actually read what it matched. `clf`
        is in the table as a recognisable shape and is unreadable today, and matching without
        parsing is how a format once matched at 100% and then ingested zero records.
        """
        sample: list[str] = []
        with open_text(path) as handle:
            for line in handle:
                if line.strip():
                    sample.append(line.rstrip("\n"))
                if len(sample) >= _TIMESTAMP_SAMPLE_LINES:
                    break
        if not sample:
            return None

        for name in _TIMESTAMP_PREFERENCE:
            pattern = _COMPILED_TIMESTAMPS.get(name)
            if pattern is None:
                continue
            parsed = 0
            for line in sample:
                found = pattern.search(line)
                if found is None:
                    continue
                try:
                    parse_timestamp(found.group(0))
                except (ValueError, OverflowError):
                    continue
                parsed += 1
            if parsed / len(sample) >= _TIMESTAMP_SHARE:
                return name
        return None

    def parse(self, source: str | Path) -> Iterator[LogRecord]:
        """One record per line, timestamped from the line where the line carries one.

        The adapter still invents nothing. Reading a timestamp that is present in the text is
        not a guess; assigning one that is not is, and that is what the fallback below is for.

        When no shape reaches `_TIMESTAMP_SHARE`, timestamps are line ordinals from a fixed
        epoch, exactly as before: the schema requires a timestamp and every ordering query
        depends on one, so refusing to provide any would mean refusing the file. They carry no
        information beyond the order the lines appeared in, `unparseable_timestamp` counts every
        one of them, and the report says so rather than letting a six-minute "incident window"
        be read off them.
        """
        path = Path(source)
        # A fixed base rather than `now`: two ingests of the same file must produce the same
        # scratchpad, or nothing downstream is reproducible.
        base = datetime(1970, 1, 1, tzinfo=UTC)

        shape = self._adopt_timestamp_shape(path)
        self.stats.timestamp_shape = shape
        self.stats.timestamp_year_inferred = shape in _YEARLESS_SHAPES
        pattern = _COMPILED_TIMESTAMPS.get(shape) if shape else None
        previous: datetime | None = None

        with open_text(path) as handle:
            for lineno, line in enumerate(handle, start=1):
                raw = line.rstrip("\n")
                if not raw.strip():
                    continue
                self.stats.lines_read += 1

                match = _SEVERITY.search(raw)
                severity, mapped = normalize_severity(match.group(1) if match else None)
                if not mapped:
                    self.stats.unmapped_severity += 1

                ts: datetime | None = None
                if pattern is not None:
                    found = pattern.search(raw)
                    if found is not None:
                        try:
                            ts = parse_timestamp(found.group(0))
                        except (ValueError, OverflowError):
                            ts = None
                if ts is None:
                    # A line the adopted shape did not match, in a file where nine in ten do:
                    # almost always a stack-trace continuation, which belongs to the moment of
                    # the line above it. Inheriting is right there, and it keeps the window free
                    # of 1970 outliers. Before the first match -- and for a file with no shape at
                    # all -- this is the ordinal fallback.
                    ts = previous if previous is not None else base + timedelta(seconds=lineno)
                    self.stats.unparseable_timestamp += 1
                else:
                    previous = ts

                self.stats.records_emitted += 1
                yield LogRecord(
                    ts=ts,
                    source="unknown",
                    severity=severity,
                    raw=raw,
                    # `line_number` is the source line this came from, and the scratchpad
                    # already numbers rows in insertion order. When the two agree -- every file
                    # with no blank lines, which is most of them -- storing it writes the rowid
                    # again as JSON. Measured on 7.5M Thunderbird events: 22.4 bytes an event,
                    # 7% of the scratchpad, for a number already in the primary key.
                    fields=(
                        {} if lineno == self.stats.records_emitted else {"line_number": lineno}
                    ),
                    message=raw,
                    format=self.format_name,
                )

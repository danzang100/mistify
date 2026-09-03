"""The contract every format adapter implements.

Adapters are format-in, `LogRecord`-out. They never touch redaction, templating or the
scratchpad, so adding a format is a self-contained change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from mistify.common.models import LogRecord

__all__ = ["AdapterStats", "LogAdapter"]


@dataclass(slots=True)
class AdapterStats:
    """Counters an adapter accumulates while parsing.

    Malformed input is skipped rather than aborting the run, but it is always counted --
    a partially-parsed file must be visible as a number, never a silent shrug.
    """

    lines_read: int = 0
    records_emitted: int = 0
    parse_errors: int = 0
    unmapped_severity: int = 0
    unparseable_timestamp: int = 0
    error_samples: list[str] = field(default_factory=list)

    def record_error(self, detail: str, keep: int = 5) -> None:
        self.parse_errors += 1
        if len(self.error_samples) < keep:
            self.error_samples.append(detail)


class LogAdapter(ABC):
    """Base class for format adapters."""

    format_name: str = "base"

    #: How much this adapter's `detect()` claim is worth relative to another's, independent of
    #: the number it returns. Confidence alone cannot decide routing, because the scores of two
    #: adapters are not measuring the same thing.
    #:
    #: A Loki `logcli --output=jsonl` export scores a perfect 1.0 on `json_lines` -- correctly,
    #: because every line *is* a JSON object carrying a timestamp. Nothing the Loki adapter can
    #: return beats that, so under a plain `max()` the specific adapter can never win, and the
    #: file routes to the reader that sees `{labels, line, timestamp}` as three opaque fields
    #: instead of the one that knows `line` holds the message and `labels` holds the service.
    #: The parse succeeds, the pipeline runs, and every record is wrong in the same quiet way.
    #:
    #: So a generic reader's high score means "this file is JSON", and a specific reader's means
    #: "this file is *this format*" -- the second is the stronger statement even when its number
    #: is lower, and the tier is what says so. The cost is that a specific adapter's `detect()`
    #: must key on a structural marker unique to its format, never on plausibility, or it
    #: hijacks every file that clears the floor.
    #:
    #: 2 -- a named format with a specification or an export shape (otlp, loki)
    #: 1 -- a generic container that many formats are carried in (json_lines)
    #: 0 -- last resort, selected deliberately by the pipeline and never by detection (raw_lines)
    specificity: int = 1

    def __init__(self) -> None:
        self.stats = AdapterStats()

    @abstractmethod
    def detect(self, sample_lines: list[str]) -> float:
        """Confidence in [0.0, 1.0] that this adapter matches the sample."""

    @abstractmethod
    def parse(self, source: str | Path) -> Iterator[LogRecord]:
        """Stream-parse the source into normalized records."""

    @property
    def component_formats(self) -> frozenset[str]:
        """Every format actually used to read the source.

        One name, for every adapter that parses something itself. The exception is a wrapper
        over other adapters, where `format_name` is a summary -- `multi:json_lines+raw_lines`
        -- and a reader asking "was any of this read by the degraded reader?" cannot answer it
        by string equality against that summary.

        That question is load-bearing. `INGEST_FALLBACK` fires the report's strongest warning
        on the exact value `raw_lines`, so a directory that read half its files line by line
        matched nothing, fired no warning, and printed a log window running from 1970 to the
        present as though it were a fact.
        """
        return frozenset({self.format_name})

    def fresh(self) -> LogAdapter:
        """A new adapter of the same kind, with its counters reset.

        The pipeline reads a second pass over the file for calibration and needs an adapter
        whose `stats` are not already half-populated. It used to rebuild one by looking the
        format name up in the registry, which works only for adapters that are *in* the
        registry -- an inferred one is constructed from a schema and has no entry, so
        bootstrapping crashed the ingest at the calibration step.

        Overridden by any adapter that needs constructor arguments.
        """
        return type(self)()

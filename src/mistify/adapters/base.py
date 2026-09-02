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

    def __init__(self) -> None:
        self.stats = AdapterStats()

    @abstractmethod
    def detect(self, sample_lines: list[str]) -> float:
        """Confidence in [0.0, 1.0] that this adapter matches the sample."""

    @abstractmethod
    def parse(self, source: str | Path) -> Iterator[LogRecord]:
        """Stream-parse the source into normalized records."""

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

"""Shared data structures used across every pipeline stage.

The normalized record shape is the contract between adapters and everything downstream.
Adapters are the only place that knows about source formats; after `parse()` the rest of the
pipeline sees `LogRecord` and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from dateutil import parser as date_parser

__all__ = [
    "SEVERITIES",
    "LogRecord",
    "NoiseThresholds",
    "ScratchpadNote",
    "TemplateResult",
    "TemplateSummary",
    "normalize_severity",
    "parse_timestamp",
    "severity_rank",
]

SEVERITIES: tuple[str, ...] = ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL")

_SEVERITY_RANK: dict[str, int] = {name: i for i, name in enumerate(SEVERITIES)}

# Aliases seen in the wild, mapped onto the normalized enum. Anything not listed here is
# reported as unmapped rather than silently bucketed -- see `normalize_severity`.
_SEVERITY_ALIASES: dict[str, str] = {
    "TRACE": "TRACE",
    "VERBOSE": "TRACE",
    "FINEST": "TRACE",
    "DEBUG": "DEBUG",
    "FINE": "DEBUG",
    "INFO": "INFO",
    "INFORMATION": "INFO",
    "INFORMATIONAL": "INFO",
    "NOTICE": "INFO",
    "WARN": "WARN",
    "WARNING": "WARN",
    "ERROR": "ERROR",
    "ERR": "ERROR",
    "SEVERE": "ERROR",
    "FATAL": "FATAL",
    "CRIT": "FATAL",
    "CRITICAL": "FATAL",
    "ALERT": "FATAL",
    "EMERG": "FATAL",
    "EMERGENCY": "FATAL",
    "PANIC": "FATAL",
}

DEFAULT_SEVERITY = "INFO"


def normalize_severity(value: object) -> tuple[str, bool]:
    """Map a source severity onto the normalized enum.

    Returns `(severity, mapped)`. `mapped` is False when the input did not match a known
    alias and the default was substituted -- the caller is expected to count those and
    surface the count as a health metric rather than let an unknown level pass unnoticed.
    """
    if value is None:
        return DEFAULT_SEVERITY, False
    key = str(value).strip().upper()
    if not key:
        return DEFAULT_SEVERITY, False
    mapped = _SEVERITY_ALIASES.get(key)
    if mapped is None:
        return DEFAULT_SEVERITY, False
    return mapped, True


def severity_rank(severity: str) -> int:
    """Ordinal position of a normalized severity. Unknown values sort lowest."""
    return _SEVERITY_RANK.get(severity.upper(), 0)


def parse_timestamp(value: object) -> datetime:
    """Parse a timestamp into a timezone-aware UTC datetime.

    Accepts ISO-8601 strings, epoch seconds, epoch milliseconds, and epoch nanoseconds.
    Raises `ValueError` on anything else -- callers decide whether that kills the line or
    the run, but it is never silently defaulted to "now".
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) or (
        isinstance(value, str) and value.strip().lstrip("-").isdigit()
    ):
        dt = _from_epoch(float(value))
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty timestamp")
        try:
            dt = date_parser.isoparse(text)
        except (ValueError, OverflowError):
            try:
                dt = date_parser.parse(text)
            except (ValueError, OverflowError) as exc:
                raise ValueError(f"unparseable timestamp: {value!r}") from exc
    else:
        raise ValueError(f"unparseable timestamp: {value!r}")

    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _from_epoch(raw: float) -> datetime:
    """Disambiguate epoch seconds / milliseconds / nanoseconds by magnitude."""
    magnitude = abs(raw)
    if magnitude >= 1e17:
        raw /= 1e9
    elif magnitude >= 1e14:
        raw /= 1e6
    elif magnitude >= 1e11:
        raw /= 1e3
    return datetime.fromtimestamp(raw, tz=UTC)


@dataclass(slots=True)
class LogRecord:
    """One normalized log line.

    `raw` is the source line as it arrived, `message` is the free-text portion the templater
    clusters on. Splitting the two matters for structured formats: templating a whole JSON
    line produces templates full of key names, while templating only the message produces the
    template the incident is actually about.

    Both fields, and every string in `fields`, are redacted before this record reaches any
    other stage.
    """

    ts: datetime
    source: str
    severity: str
    raw: str
    message: str
    fields: dict[str, Any] = field(default_factory=dict)
    format: str = "unknown"

    def isoformat(self) -> str:
        """Fixed-width UTC ISO-8601, microseconds always present.

        The width matters because `ts` is stored as TEXT and compared lexicographically.
        `datetime.isoformat()` omits microseconds when they are zero, so a whole-second
        timestamp renders shorter than a fractional one in the same second -- and since "."
        sorts before "Z", `14:38:00.442Z` would compare as *earlier* than `14:38:00Z`.
        Padding to a constant width makes string order and chronological order the same
        thing, which is what every `ORDER BY ts`, `MIN(ts)` and time-window slice assumes.
        """
        return self.ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


@dataclass(frozen=True, slots=True)
class NoiseThresholds:
    """What counts as noise: a template big enough to crowd out everything else, and dull.

    Both halves are required together. Volume alone is not noise -- a flood can be the
    incident -- so a share without a ceiling would suppress exactly the templates worth
    reading. Passing them as one value is what stops a caller specifying half a rule.
    """

    share: float
    anomaly_ceiling: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.share <= 1.0:
            raise ValueError(f"noise share must be between 0 and 1, got {self.share}")
        if not 0.0 <= self.anomaly_ceiling <= 1.0:
            raise ValueError(
                f"noise anomaly ceiling must be between 0 and 1, got {self.anomaly_ceiling}"
            )


@dataclass(slots=True)
class TemplateResult:
    """Outcome of passing one message through the templater."""

    template_id: int
    pattern: str
    params: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TemplateSummary:
    """Aggregate statistics for one template across a whole incident."""

    template_id: int
    pattern: str
    occurrence_count: int
    first_seen: str
    last_seen: str
    severity_mix: dict[str, int] = field(default_factory=dict)
    max_severity_rank: int = 0
    anomaly_score: float = 0.0

    @property
    def max_severity(self) -> str:
        return SEVERITIES[self.max_severity_rank]


@dataclass(slots=True)
class ScratchpadNote:
    """A hypothesis written by the investigator, with its mandatory supporting evidence."""

    step: int
    note: str
    evidence: dict[str, Any]
    confidence: str
    id: int | None = None
    created_at: str | None = None

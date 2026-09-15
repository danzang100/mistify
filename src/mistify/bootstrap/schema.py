"""What an inferred format looks like, and how to check it against real lines.

A schema here is one regex with named groups -- `ts`, `severity`, `source`, `message` -- built
from a small vocabulary of timestamp shapes rather than written freely. That constraint is the
point. This stage's natural failure is *silent*: a confidently
inferred wrong schema produces templates that are garbage with no error thrown, and every
number downstream describes a misreading. A schema assembled from known parts can be checked;
an arbitrary regex from a model can only be trusted.

The match rate is the gate that makes inference safe to act on. It is deliberately measured
against lines the inference never saw: a schema derived from a sample will always fit that
sample, so scoring it there measures nothing at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from mistify.common.models import parse_timestamp

__all__ = [
    "TIMESTAMP_PATTERNS",
    "FieldSchema",
    "match_rate",
    "severity_pattern",
]

#: Timestamp shapes the bootstrapper can recognise, most specific first. Named because a schema
#: records *which* shape it found, so a persisted adapter is readable by a person deciding
#: whether to trust it.
TIMESTAMP_PATTERNS: dict[str, str] = {
    # 2026-08-30T14:00:02.037152Z / 2026-08-30 14:00:02,037 / with or without offset
    "iso8601": r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?",
    # Aug 30 14:22:01 -- syslog, no year, day space-padded
    "syslog": r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
    # 30/Aug/2026:14:22:01 +0000 -- common log format. Recognised as a *shape*, but
    # `parse_timestamp` cannot read it today, so the gate refuses any file using it and the
    # file goes to raw lines. Listed rather than dropped because the gate proving that is the
    # whole point: before it existed, CLF matched at 100% and then ingested zero records.
    "clf": r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?",
    # 1756476000 / 1756476000123 / nanoseconds. Last: it matches inside other numbers, so it
    # only wins when nothing structured did.
    "epoch": r"\d{10}(?:\d{3}|\d{6}|\d{9})?",
}

#: Severity words worth recognising, including the abbreviations people actually write. Ordered
#: longest-first so `WARNING` is not matched as `WARN` with a stray suffix left in the message.
_SEVERITY_WORDS = (
    "CRITICAL",
    "WARNING",
    "SEVERE",
    "NOTICE",
    "TRACE",
    "DEBUG",
    "ERROR",
    "FATAL",
    "CRIT",
    "WARN",
    "INFO",
    "ERR",
)


def severity_pattern() -> str:
    """Alternation over known severity words, case-insensitive at use."""
    return "|".join(_SEVERITY_WORDS)


@dataclass(frozen=True, slots=True)
class FieldSchema:
    """One inferred line format.

    `timestamp` names a member of `TIMESTAMP_PATTERNS` rather than carrying a pattern, so a
    persisted schema cannot smuggle in a regex nobody reviewed -- reloading one is a lookup,
    not an eval.
    """

    timestamp: str
    has_severity: bool = True
    #: A `name:` or `name[pid]:` field between severity and message, as syslog and many
    #: application formats write. Optional because plenty of formats have no such field, and
    #: requiring one would push its text into the message where it would pollute templates.
    has_source: bool = False
    #: Whether the source field comes before the severity. Both orders are common and neither
    #: is guessable from the fields alone: syslog writes `ts host proc[pid]: ERROR message`,
    #: while application loggers usually write `ts ERROR logger: message`. Fixing one order
    #: silently failed every file using the other, and the failure looked like "this format is
    #: unreadable" rather than "the parts are in the other sequence".
    source_first: bool = False

    #: What produced this schema: "structural" or "model". Recorded because the two carry very
    #: different amounts of trust, and a reader of a persisted adapter should be told which.
    origin: str = "structural"
    #: Match rate measured on held-out lines at the time it was accepted.
    validated_rate: float = 0.0
    notes: tuple[str, ...] = field(default_factory=tuple)

    def pattern(self) -> str:
        """The full line regex this schema describes."""
        severity = (
            rf"(?:\S+\s+)?(?:[\w.]+=)?[\[\(]?(?P<severity>{severity_pattern()})[\]\)]?:?\s+"
            if self.has_severity
            else ""
        )
        # The same one-token tolerance the severity group gets. Syslog writes
        # `ts host proc[pid]: ...`, so a hostname sits between the timestamp and the source and
        # is claimed by neither -- without this the whole format fails over one unowned word.
        source = r"(?:\S+\s+)?(?P<source>[\w.\-/]+(?:\[\d+\])?):\s+" if self.has_source else ""
        middle = (source + severity) if self.source_first else (severity + source)
        return (
            rf"^\s*(?:[\w.]+=)?[\[\(<]?\s*"
            rf"(?P<ts>{TIMESTAMP_PATTERNS[self.timestamp]})\s*[\]\)>]?\s+"
            + middle
            + r"(?P<message>.*)$"
        )

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.pattern(), re.IGNORECASE)

    @property
    def extracted_fields(self) -> int:
        """How many named fields this schema pulls out of the line, beyond the timestamp.

        A measure of how much of the line the schema *explains*. Two schemas can both parse a
        file at 100% while disagreeing about this: one that does not claim a severity still
        matches a line carrying `ERROR`, because the word simply lands inside `message`. The
        rate cannot tell them apart and this can.
        """
        return int(self.has_severity) + int(self.has_source)

    def slug(self) -> str:
        """A name that distinguishes schemas which parse differently.

        The cache key, and it has to be injective over exactly the fields `pattern()` reads:
        `timestamp`, `has_severity`, `has_source` and `source_first`. It was `timestamp` alone,
        so every syslog format in the world shared one cache entry -- an OpenSSH log (no
        severity word in the line) and an application log (`host app[1]: ERROR ...`) both
        persisted as `inferred_syslog`, and whichever was ingested first silently decided how
        the other was read. The second file's severities went into its messages, every line
        became the default level, and nothing anywhere reported a problem.

        Readable rather than hashed, because a persisted schema is meant to be inspectable by
        a person deciding whether to trust it -- `inferred_syslog_src_sev` says what it is.

        A field added to `pattern()` must be added here too, or the collision comes back.
        """
        parts = [self.timestamp]
        if self.has_severity and self.has_source:
            parts.append("src_sev" if self.source_first else "sev_src")
        elif self.has_severity:
            parts.append("sev")
        elif self.has_source:
            parts.append("src")
        return "_".join(parts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "has_severity": self.has_severity,
            "has_source": self.has_source,
            "source_first": self.source_first,
            "origin": self.origin,
            "validated_rate": round(self.validated_rate, 4),
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FieldSchema:
        name = str(payload.get("timestamp", ""))
        if name not in TIMESTAMP_PATTERNS:
            raise ValueError(f"unknown timestamp shape {name!r} in persisted schema")
        return cls(
            timestamp=name,
            has_severity=bool(payload.get("has_severity", True)),
            has_source=bool(payload.get("has_source", False)),
            source_first=bool(payload.get("source_first", False)),
            origin=str(payload.get("origin", "structural")),
            validated_rate=float(payload.get("validated_rate", 0.0)),
            notes=tuple(payload.get("notes", ())),
        )


def match_rate(schema: FieldSchema, lines: list[str]) -> float:
    """Share of `lines` the schema parses.

    Measure this on lines the inference did not see. A schema derived from a sample fits that
    sample by construction, so scoring it there reports how well it memorised, not how well it
    generalises -- and it is the number the 0.85 gate is read from.
    """
    candidates = [line for line in lines if line.strip()]
    if not candidates:
        return 0.0
    compiled = schema.compiled()
    return sum(1 for line in candidates if _reads(compiled, line)) / len(candidates)


def _reads(pattern: re.Pattern[str], line: str) -> bool:
    """Whether the schema both matches the line and yields a usable timestamp.

    Matching is not enough. A syslog timestamp carries no year, so `Aug 30 14:22:01` satisfies
    the regex and then fails to parse -- a schema that passed the gate at 100% and produced an
    ingest of zero records, silently, which is precisely the failure mode this gate exists to
    prevent. The gate has to test what the adapter will actually do, not a proxy for it.
    """
    match = pattern.match(line)
    if match is None:
        return False
    try:
        parse_timestamp(match.group("ts"))
    except ValueError:
        return False
    return True

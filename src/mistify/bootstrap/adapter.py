"""An adapter built from an inferred schema, and the store that lets one be reused.

Once a format has been worked out, the next file from the same source should not pay for it
again -- the last step of the bootstrap, and the reason inference is affordable at all. A
persisted schema is a lookup into a fixed vocabulary of timestamp shapes rather than a stored
regex, so reloading one cannot introduce a pattern nobody reviewed.

The adapter itself parses exactly like a hand-written one and reports the same counters, so
everything downstream is unaware it was inferred. What it must not do is pretend to more
certainty than it has: `detect` returns the validated match rate, not a flat high number, so an
inferred format competes on measured evidence against adapters that were written on purpose.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from mistify.adapters.base import LogAdapter
from mistify.adapters.source import open_text
from mistify.bootstrap.schema import FieldSchema
from mistify.common.models import LogRecord, normalize_severity, parse_timestamp

__all__ = ["InferredAdapter", "load_schemas", "save_schema"]


class InferredAdapter(LogAdapter):
    """Parses a format that was worked out rather than written."""

    def __init__(self, schema: FieldSchema, name: str = "inferred") -> None:
        super().__init__()
        self.schema = schema
        self.format_name = name
        self._pattern: re.Pattern[str] = schema.compiled()

    def fresh(self) -> InferredAdapter:
        """A sibling around the same schema: the schema is the configuration."""
        return InferredAdapter(self.schema, name=self.format_name)

    def detect(self, sample_lines: list[str]) -> float:
        """How much of the sample this schema actually parses.

        A measured share rather than a confident constant. An inferred adapter that half-fits a
        different file should lose to one that was written for it, and the only honest way to
        arrange that is to report what it can really read.
        """
        candidates = [line for line in sample_lines if line.strip()]
        if not candidates:
            return 0.0
        return sum(1 for line in candidates if self._pattern.match(line)) / len(candidates)

    def parse(self, source: str | Path) -> Iterator[LogRecord]:
        path = Path(source)
        with open_text(path) as handle:
            for lineno, line in enumerate(handle, start=1):
                raw = line.rstrip("\n")
                if not raw.strip():
                    continue
                self.stats.lines_read += 1
                record = self._parse_line(raw, lineno)
                if record is not None:
                    self.stats.records_emitted += 1
                    yield record

    def _parse_line(self, raw: str, lineno: int) -> LogRecord | None:
        match = self._pattern.match(raw)
        if match is None:
            # Expected on a share of lines: the schema was accepted at a match rate below 1.0,
            # and the shortfall is exactly these. Counted so the report can show how much of
            # the file the inferred format failed to read.
            self.stats.record_error(f"line {lineno}: does not match the inferred format")
            return None

        groups = match.groupdict()
        try:
            ts = parse_timestamp(groups["ts"])
        except ValueError:
            self.stats.unparseable_timestamp += 1
            self.stats.record_error(f"line {lineno}: unparseable timestamp {groups['ts']!r}")
            return None

        severity, mapped = normalize_severity(groups.get("severity"))
        if not mapped:
            self.stats.unmapped_severity += 1

        source_field = groups.get("source")
        return LogRecord(
            ts=ts,
            source=source_field.rstrip(":") if source_field else "unknown",
            severity=severity,
            raw=raw,
            message=groups.get("message") or raw,
            fields={"line_number": lineno},
            format=self.format_name,
        )


def save_schema(schema: FieldSchema, directory: Path, name: str) -> Path:
    """Persist an inferred schema so the next file from this source skips inference."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json"
    path.write_text(json.dumps({"name": name, **schema.as_dict()}, indent=2), encoding="utf-8")
    return path


def load_schemas(directory: Path) -> dict[str, FieldSchema]:
    """Every persisted schema, by name.

    A file that will not load is skipped rather than raising: a corrupt or hand-edited entry in
    a cache should cost one re-inference, not the whole run.
    """
    if not directory.exists():
        return {}
    schemas: dict[str, FieldSchema] = {}
    for path in sorted(directory.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            schemas[str(payload.get("name", path.stem))] = FieldSchema.from_dict(payload)
        except (ValueError, KeyError, json.JSONDecodeError):
            continue
    return schemas

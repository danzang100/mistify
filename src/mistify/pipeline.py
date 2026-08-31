"""Ingestion pipeline: adapter, redaction, templating, scratchpad load.

Stage order is the load-bearing detail here:

    parse -> REDACT -> template -> scratchpad

Redaction sits immediately after `parse()` rather than after templating (decisions G1 and
G2). That ordering is what makes the guarantee hold on every path -- including the
unknown-format path, where the bootstrapper sends sample lines to a model before templating
has happened at all, and including the Drain3 snapshot, which is a durable on-disk artifact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from mistify.adapters.base import LogAdapter
from mistify.adapters.registry import detect_format, get_adapter, read_sample
from mistify.common.config import MistifyConfig
from mistify.common.models import LogRecord
from mistify.redaction.redactor import Redactor
from mistify.scratchpad.db import ScratchpadDB
from mistify.templating.drain_wrapper import DrainTemplater

__all__ = ["IngestResult", "derive_incident_id", "ingest"]


class UnknownFormatError(RuntimeError):
    """No registered adapter matched with sufficient confidence.

    From Phase 4 this hands off to the unknown-format bootstrapper instead of raising.
    """


@dataclass(slots=True)
class IngestResult:
    incident_id: str
    scratchpad_path: Path
    format_name: str
    lines_read: int
    events_loaded: int
    unique_templates: int
    compression_ratio: float
    parse_errors: int
    redaction_counts: dict[str, int] = field(default_factory=dict)


def derive_incident_id(source: str | Path) -> str:
    """Build a default incident id from the source filename and today's date.

    `investigate` and `report` are both keyed on an incident id that nothing previously
    created, so ingestion is where an incident comes into existence (decision G6).
    """
    from datetime import UTC, datetime

    stem = Path(source).stem or "incident"
    slug = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-") or "incident"
    return f"{datetime.now(UTC):%Y-%m-%d}-{slug}"


def ingest(
    source: str | Path,
    config: MistifyConfig,
    incident_id: str | None = None,
    format_name: str | None = None,
) -> IngestResult:
    """Run a source file through the pipeline and load the scratchpad."""
    source_path = Path(source)
    if not source_path.exists():
        raise FileNotFoundError(f"source not found: {source_path}")

    incident_id = incident_id or derive_incident_id(source_path)

    # --- format selection -------------------------------------------------
    adapter: LogAdapter | None
    if format_name and format_name != "auto":
        adapter = get_adapter(format_name)
        scores = {format_name: 1.0}
    else:
        sample = read_sample(source_path, config.bootstrap.sample_size)
        adapter, scores = detect_format(
            sample,
            registered=config.adapters.registered,
            min_confidence=config.adapters.min_detect_confidence,
        )
        if adapter is None:
            best = max(scores.values(), default=0.0)
            raise UnknownFormatError(
                f"no registered adapter matched {source_path} "
                f"(best confidence {best:.2f}, threshold "
                f"{config.adapters.min_detect_confidence:.2f}). "
                "The unknown-format bootstrapper arrives in Phase 4."
            )

    redactor = Redactor(
        mode=config.redaction.mode,
        entities=config.redaction.entities,
        salt=config.redaction.salt,
    )
    templater = DrainTemplater(
        sim_th=config.drain3.sim_th,
        depth=config.drain3.depth,
        max_clusters=config.drain3.max_clusters,
        snapshot_path=config.snapshot_path(incident_id),
    )

    scratchpad_path = config.scratchpad_path(incident_id)
    if scratchpad_path.exists():
        scratchpad_path.unlink()

    rows: list[tuple[LogRecord, int]] = []
    with ScratchpadDB(scratchpad_path) as db:
        db.create_incident(
            incident_id,
            source=str(source_path),
            format_name=adapter.format_name,
            redaction_mode=config.redaction.mode,
        )

        for record in adapter.parse(source_path):
            # Redaction first. Nothing downstream -- templater, snapshot, database, or any
            # model call -- ever sees an unredacted record.
            record = redactor.redact_record(record)
            result = templater.process(
                record.message, ts=record.isoformat(), severity=record.severity
            )
            rows.append((record, result.template_id))

        events_loaded = db.bulk_insert_events(rows)
        summaries = templater.summaries()
        db.upsert_templates(summaries)
        templater.snapshot()

        stats = adapter.stats
        db.record_metric("ingest", "format", adapter.format_name)
        db.record_metric(
            "ingest", "detect_confidence", round(scores.get(adapter.format_name, 0.0), 3)
        )
        db.record_metric("ingest", "lines_read", stats.lines_read)
        db.record_metric("ingest", "events_loaded", events_loaded)
        db.record_metric("ingest", "parse_errors", stats.parse_errors)
        db.record_metric("ingest", "unmapped_severity", stats.unmapped_severity)
        db.record_metric("ingest", "unparseable_timestamp", stats.unparseable_timestamp)

        db.record_metric("redaction", "mode", config.redaction.mode)
        db.record_metric("redaction", "entities", ",".join(config.redaction.entities))
        for entity, count in sorted(redactor.counts.items()):
            db.record_metric("redaction", f"redacted_{entity}", count)
        db.record_metric("redaction", "redacted_total", sum(redactor.counts.values()))

        db.record_metric("templating", "unique_templates", templater.unique_templates)
        db.record_metric("templating", "compression_ratio", round(templater.compression_ratio, 5))
        db.record_metric("templating", "sim_th", config.drain3.sim_th)
        db.record_metric("templating", "depth", config.drain3.depth)

        db.record_metric("scratchpad", "orphan_events", db.orphan_event_count())

        return IngestResult(
            incident_id=incident_id,
            scratchpad_path=scratchpad_path,
            format_name=adapter.format_name,
            lines_read=stats.lines_read,
            events_loaded=events_loaded,
            unique_templates=templater.unique_templates,
            compression_ratio=templater.compression_ratio,
            parse_errors=stats.parse_errors,
            redaction_counts=redactor.counts,
        )

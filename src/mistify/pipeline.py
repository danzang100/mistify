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
from mistify.scratchpad.anomaly import score_templates
from mistify.scratchpad.db import ScratchpadDB
from mistify.templating.calibration import calibrate_sim_th, find_over_merged
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
    sim_th: float
    calibration_status: str
    over_merged: int
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
    # Calibration reads a sample through the same parse-then-redact path the real load
    # uses, so the thresholds are measured against the text Drain3 will actually cluster --
    # calibrating on unredacted lines would tune for a different input than the one used.
    calibration = None
    sim_th = config.drain3.sim_th
    if config.drain3.calibrate:
        sample_adapter = get_adapter(adapter.format_name)
        sample_messages: list[str] = []
        for record in sample_adapter.parse(source_path):
            sample_messages.append(redactor.redact(record.message))
            if len(sample_messages) >= config.drain3.calibration_sample_size:
                break
        calibration = calibrate_sim_th(
            sample_messages,
            candidates=config.drain3.calibration_candidates,
            target_min=config.drain3.target_ratio_min,
            target_max=config.drain3.target_ratio_max,
            depth=config.drain3.depth,
            max_clusters=config.drain3.max_clusters,
        )
        sim_th = calibration.chosen_sim_th
        # The calibration pass redacted its sample too; those counts are not part of the
        # real load and would double-count in the health metrics.
        redactor.reset_counts()

    templater = DrainTemplater(
        sim_th=sim_th,
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

        scored = score_templates(
            db.template_burst_stats(config.anomaly.bucket_minutes),
            total_buckets=db.bucket_count(config.anomaly.bucket_minutes),
            weights=config.anomaly.weights(),
        )
        db.update_anomaly_scores([(c.template_id, c.score) for c in scored])
        over_merged = find_over_merged(summaries, config.drain3.over_merge_severity_span)

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
        db.record_metric("templating", "sim_th", sim_th)
        db.record_metric("templating", "depth", config.drain3.depth)
        if calibration is not None:
            db.record_metric("templating", "calibration_status", calibration.status)
            db.record_metric("templating", "calibration_candidates", calibration.as_metric())
            db.record_metric("templating", "calibration_reason", calibration.reason)
        else:
            db.record_metric("templating", "calibration_status", "disabled")
        db.record_metric("templating", "over_merged_templates", len(over_merged))
        if over_merged:
            db.record_metric(
                "templating",
                "over_merged_ids",
                ",".join(str(t.template_id) for t in over_merged),
            )

        db.record_metric("anomaly", "scored_templates", len(scored))
        db.record_metric("anomaly", "weights", str(config.anomaly.weights()))
        db.record_metric("anomaly", "bucket_minutes", config.anomaly.bucket_minutes)
        if scored:
            db.record_metric("anomaly", "top_template_id", scored[0].template_id)
            db.record_metric("anomaly", "top_score", round(scored[0].score, 4))

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
            sim_th=sim_th,
            calibration_status=calibration.status if calibration else "disabled",
            over_merged=len(over_merged),
            redaction_counts=redactor.counts,
        )

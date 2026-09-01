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
from mistify.metrics import SCRATCHPAD_ORPHAN_EVENTS
from mistify.redaction.redactor import Redactor
from mistify.redaction.vault import RedactionVault
from mistify.scratchpad.anomaly import score_templates, select_signal_templates
from mistify.scratchpad.db import ScratchpadDB
from mistify.stage_metrics import (
    anomaly_metrics,
    ingest_metrics,
    redaction_metrics,
    templating_metrics,
)
from mistify.templating.calibration import calibrate_sim_th, find_over_merged
from mistify.templating.drain_wrapper import DrainTemplater

__all__ = ["EVENT_BATCH_SIZE", "IngestResult", "derive_incident_id", "ingest"]

#: Records held in memory between INSERTs. Bounds peak memory independently of file size.
EVENT_BATCH_SIZE = 5000


class UnknownFormatError(RuntimeError):
    """No usable adapter for the source.

    Covers both ways that happens: detection found nothing confident enough, and an explicit
    `--format` naming something that is not registered. The CLI catches this one type, so
    both paths have to arrive as it rather than as a bare `ValueError`.

    From Phase 4 the detection case hands off to the unknown-format bootstrapper instead of
    raising.
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
    template_coverage: float
    reduction_factor: float
    evicted_templates: int
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
        try:
            adapter = get_adapter(format_name)
        except ValueError as exc:
            # The registry signals an unregistered name with ValueError, but the CLI only
            # catches UnknownFormatError, so a typo in --format surfaced as a traceback.
            raise UnknownFormatError(str(exc)) from exc
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

    # Opt-in reversible redaction. The vault is its own file, never a table in the
    # scratchpad: the investigator's read-only SQL channel can read any table in the database
    # it is pointed at, so a vault living there would be one SELECT away from undoing
    # redaction entirely.
    vault_path = config.vault_path(incident_id)
    vault: RedactionVault | None = None
    if vault_path is not None:
        if vault_path.exists():
            vault_path.unlink()
        vault = RedactionVault(vault_path)

    redactor = Redactor(
        mode=config.redaction.mode,
        entities=config.redaction.entities,
        salt=config.redaction.salt,
        vault=vault,
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
            over_merge_span=config.drain3.over_merge_severity_span,
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

    with ScratchpadDB(scratchpad_path) as db:
        db.create_incident(
            incident_id,
            source=str(source_path),
            format_name=adapter.format_name,
            redaction_mode=config.redaction.mode,
        )

        # Streamed in fixed-size batches rather than buffered whole. Holding every record
        # until the end cost roughly a kilobyte per line, which is ~16 GB of resident memory
        # on the Thunderbird corpus the Phase 5 stress test is meant to run -- the pipeline
        # would die before reaching the thing it was measuring. Peak memory is now the batch
        # plus the template registry, both bounded.
        events_loaded = 0
        batch: list[tuple[LogRecord, int]] = []
        for record in adapter.parse(source_path):
            # Redaction first. Nothing downstream -- templater, snapshot, database, or any
            # model call -- ever sees an unredacted record.
            record = redactor.redact_record(record)
            result = templater.process(
                record.message, ts=record.isoformat(), severity=record.severity
            )
            batch.append((record, result.template_id))
            if len(batch) >= EVENT_BATCH_SIZE:
                events_loaded += db.bulk_insert_events(batch)
                batch.clear()
        if batch:
            events_loaded += db.bulk_insert_events(batch)
            batch.clear()

        summaries = templater.summaries()
        db.upsert_templates(summaries)
        templater.snapshot()

        stats = adapter.stats

        # Severity carries the heaviest weight, so a source with no severity field would
        # otherwise spend half the score on a constant. Detect that and redistribute.
        unmapped_share = stats.unmapped_severity / stats.lines_read if stats.lines_read else 0.0
        severity_informative = unmapped_share <= config.anomaly.severity_unmapped_ceiling

        scored = score_templates(
            db.template_burst_stats(config.anomaly.bucket_minutes),
            total_buckets=db.bucket_count(config.anomaly.bucket_minutes),
            weights=config.anomaly.weights(),
            severity_informative=severity_informative,
        )
        db.update_anomaly_scores([(c.template_id, c.score) for c in scored])
        over_merged = find_over_merged(summaries, config.drain3.over_merge_severity_span)

        orphans = db.orphan_event_count()
        coverage = 1.0 - (orphans / events_loaded) if events_loaded else 1.0

        signal_templates = select_signal_templates(
            scored,
            min_templates=config.anomaly.signal_min_templates,
            max_templates=config.anomaly.signal_max_templates,
        )
        noisy = db.noise_template_ids(config.anomaly.noise_thresholds())
        if vault is not None:
            vault.flush()

        # Each stage describes its own run; the pipeline only decides when they are written.
        db.record_many(
            [
                *ingest_metrics(adapter, scores, events_loaded),
                *redaction_metrics(config, redactor, vault, vault_path),
                *templating_metrics(config, templater, sim_th, coverage, calibration, over_merged),
                *anomaly_metrics(
                    config,
                    scored,
                    summaries,
                    signal_templates,
                    len(noisy),
                    severity_informative,
                    unmapped_share,
                ),
                (SCRATCHPAD_ORPHAN_EVENTS, orphans),
            ]
        )

        if vault is not None:
            vault.close()

        signal = templater.signal_stats()

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
            template_coverage=coverage,
            reduction_factor=signal["reduction_factor"],
            evicted_templates=templater.evicted_templates,
            redaction_counts=redactor.counts,
        )

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
from mistify.metrics import (
    ANOMALY_BUCKET_MINUTES,
    ANOMALY_NEEDLE_POSITION,
    ANOMALY_SCORED_TEMPLATES,
    ANOMALY_SEVERITY_INFORMATIVE,
    ANOMALY_SIGNAL_TEMPLATE_IDS,
    ANOMALY_SIGNAL_TEMPLATES,
    ANOMALY_SUPPRESSED_NOISE,
    ANOMALY_TOP_SCORE,
    ANOMALY_TOP_TEMPLATE_ID,
    ANOMALY_UNMAPPED_SEVERITY_SHARE,
    ANOMALY_WEIGHTS,
    INGEST_DETECT_CONFIDENCE,
    INGEST_EVENTS_LOADED,
    INGEST_FORMAT,
    INGEST_LINES_READ,
    INGEST_PARSE_ERRORS,
    INGEST_UNMAPPED_SEVERITY,
    INGEST_UNPARSEABLE_TIMESTAMP,
    REDACTED_BY_ENTITY,
    REDACTION_ENTITIES,
    REDACTION_MODE,
    REDACTION_TOTAL,
    REDACTION_VAULT,
    REDACTION_VAULT_ENTRIES,
    REDACTION_VAULT_PATH,
    SCRATCHPAD_ORPHAN_EVENTS,
    TEMPLATING_CALIBRATION_CANDIDATES,
    TEMPLATING_CALIBRATION_REASON,
    TEMPLATING_CALIBRATION_STATUS,
    TEMPLATING_COMPRESSION_RATIO,
    TEMPLATING_COVERAGE,
    TEMPLATING_DEPTH,
    TEMPLATING_EVICTED,
    TEMPLATING_LARGEST_SHARE,
    TEMPLATING_OVER_MERGED,
    TEMPLATING_OVER_MERGED_IDS,
    TEMPLATING_REDUCTION_FACTOR,
    TEMPLATING_SIM_TH,
    TEMPLATING_UNIQUE_TEMPLATES,
)
from mistify.redaction.redactor import Redactor
from mistify.redaction.vault import RedactionVault
from mistify.scratchpad.anomaly import score_templates, select_signal_templates
from mistify.scratchpad.db import ScratchpadDB
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

        db.record(INGEST_FORMAT, adapter.format_name)
        db.record(INGEST_DETECT_CONFIDENCE, round(scores.get(adapter.format_name, 0.0), 3))
        db.record(INGEST_LINES_READ, stats.lines_read)
        db.record(INGEST_EVENTS_LOADED, events_loaded)
        db.record(INGEST_PARSE_ERRORS, stats.parse_errors)
        db.record(INGEST_UNMAPPED_SEVERITY, stats.unmapped_severity)
        db.record(INGEST_UNPARSEABLE_TIMESTAMP, stats.unparseable_timestamp)

        db.record(REDACTION_MODE, config.redaction.mode)
        db.record(REDACTION_ENTITIES, ",".join(config.redaction.entities))
        for entity, count in sorted(redactor.counts.items()):
            db.record(REDACTED_BY_ENTITY.member(entity), count)
        db.record(REDACTION_TOTAL, sum(redactor.counts.values()))
        db.record(REDACTION_VAULT, vault is not None)
        if vault is not None:
            vault.flush()
            db.record(REDACTION_VAULT_ENTRIES, vault.count())
            db.record(REDACTION_VAULT_PATH, str(vault_path))

        orphans = db.orphan_event_count()
        coverage = 1.0 - (orphans / events_loaded) if events_loaded else 1.0
        signal = templater.signal_stats()

        # Coverage is the invariant, not compression. Every event must be reachable through
        # a template, because an event whose template was dropped is a line the agent can
        # never find -- and the compression ratio reports that loss as a success.
        db.record(TEMPLATING_COVERAGE, round(coverage, 6))
        db.record(TEMPLATING_UNIQUE_TEMPLATES, templater.unique_templates)
        db.record(TEMPLATING_REDUCTION_FACTOR, round(signal["reduction_factor"], 2))
        db.record(TEMPLATING_LARGEST_SHARE, round(signal["largest_template_share"], 4))
        db.record(TEMPLATING_EVICTED, templater.evicted_templates)
        # Diagnostic only. Kept because a ratio near 1.0 still means nothing was collapsed.
        db.record(TEMPLATING_COMPRESSION_RATIO, round(templater.compression_ratio, 5))
        db.record(TEMPLATING_SIM_TH, sim_th)
        db.record(TEMPLATING_DEPTH, config.drain3.depth)
        if calibration is not None:
            db.record(TEMPLATING_CALIBRATION_STATUS, calibration.status)
            db.record(TEMPLATING_CALIBRATION_CANDIDATES, calibration.as_metric())
            db.record(TEMPLATING_CALIBRATION_REASON, calibration.reason)
        else:
            db.record(TEMPLATING_CALIBRATION_STATUS, "disabled")
        db.record(TEMPLATING_OVER_MERGED, len(over_merged))
        if over_merged:
            db.record(
                TEMPLATING_OVER_MERGED_IDS,
                ",".join(str(t.template_id) for t in over_merged),
            )

        signal_templates = select_signal_templates(
            scored,
            min_templates=config.anomaly.signal_min_templates,
            max_templates=config.anomaly.signal_max_templates,
        )
        noisy = db.noise_template_ids(
            config.anomaly.noise_share_threshold, config.anomaly.noise_anomaly_ceiling
        )

        db.record(ANOMALY_SCORED_TEMPLATES, len(scored))
        db.record(ANOMALY_SEVERITY_INFORMATIVE, severity_informative)
        db.record(ANOMALY_UNMAPPED_SEVERITY_SHARE, round(unmapped_share, 4))
        # The set the Phase 3 adversarial check must account for, cut at the largest score
        # gap rather than at a threshold picked from whatever fixture was to hand.
        db.record(ANOMALY_SIGNAL_TEMPLATES, len(signal_templates))
        db.record(
            ANOMALY_SIGNAL_TEMPLATE_IDS,
            ",".join(str(c.template_id) for c in signal_templates),
        )
        db.record(ANOMALY_SUPPRESSED_NOISE, len(noisy))
        db.record(ANOMALY_WEIGHTS, str(config.anomaly.weights()))
        db.record(ANOMALY_BUCKET_MINUTES, config.anomaly.bucket_minutes)
        if scored:
            db.record(ANOMALY_TOP_TEMPLATE_ID, scored[0].template_id)
            db.record(ANOMALY_TOP_SCORE, round(scored[0].score, 4))
            # Where the most severe template lands in anomaly order. This is the needle
            # question stated directly: would an agent reading the ranked list from the top
            # meet the worst thing in the file early, or have to dig for it?
            worst = max(summaries, key=lambda s: s.max_severity_rank)
            order = [c.template_id for c in scored]
            db.record(ANOMALY_NEEDLE_POSITION, order.index(worst.template_id) + 1)

        db.record(SCRATCHPAD_ORPHAN_EVENTS, orphans)

        if vault is not None:
            vault.close()

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

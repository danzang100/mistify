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
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from mistify.adapters.base import LogAdapter
from mistify.adapters.registry import detect_format, get_adapter, read_sample
from mistify.common.config import MistifyConfig
from mistify.common.models import LogRecord
from mistify.metrics import SCRATCHPAD_ORPHAN_EVENTS
from mistify.redaction.parallel import RedactionPool
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
from mistify.templating.calibration import (
    CalibrationStatus,
    calibrate_sim_th,
    find_over_merged,
)
from mistify.templating.drain_wrapper import DrainTemplater

__all__ = ["EVENT_BATCH_SIZE", "IngestResult", "derive_incident_id", "ingest"]

#: Records held in memory between INSERTs. Bounds peak memory independently of file size.
EVENT_BATCH_SIZE = 5000

#: Records redacted per call. Sized so a parallel run has something worth sending to a worker
#: -- below a couple of thousand the pipe costs more than the regex -- while keeping the same
#: bounded-memory property as the insert batch.
REDACT_CHUNK_SIZE = 10_000


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


def _chunked(records: Iterator[LogRecord], size: int) -> Iterator[list[LogRecord]]:
    """Group a record stream into fixed-size lists, still lazily.

    `itertools.batched` would do this in 3.12, but it yields tuples and the redaction pool
    wants a list it can slice per worker. The generator matters more than the shape: the whole
    point of the ingest loop is that the file is never resident, and a chunker that materialised
    the stream would undo that in one line.
    """
    chunk: list[LogRecord] = []
    for record in records:
        chunk.append(record)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def _bootstrap(
    source_path: Path, config: MistifyConfig, reason: str
) -> tuple[LogAdapter, str] | None:
    """Try to work out an unknown format, returning an adapter and what to record about it.

    Returns None when nothing cleared the match-rate gate, which leaves the caller on its
    existing path -- raw lines, or refusal. A bootstrapper that returned a low-confidence
    schema rather than nothing would be the silent failure the architecture warns about.

    The provider is built only when the structural pass has already been given its chance, and
    a missing credential is not fatal here: inference is an improvement on reading raw lines,
    never a requirement for it.
    """
    from mistify.bootstrap import bootstrap_format, load_schemas, save_schema
    from mistify.bootstrap.adapter import InferredAdapter

    schema_dir = config.schema_dir()
    lines = read_sample(source_path, max(config.bootstrap.sample_size * 10, 1000))

    provider = None
    if config.bootstrap.use_model:
        try:
            from mistify.llm.registry import build_provider

            provider = build_provider(config.llm.provider, config.llm.bootstrap_model, config.llm)
        except Exception:
            # Inference improves on reading raw lines but is never required for it, so
            # nothing here is allowed to fail the ingest.
            provider = None

    result = bootstrap_format(
        lines,
        known=load_schemas(schema_dir),
        provider=provider,
        min_match_rate=config.bootstrap.min_match_rate,
        sample_size=config.bootstrap.sample_size,
    )
    if result.schema is None:
        return None

    # Named from every field that changes how the schema parses, not from the timestamp shape
    # alone. `inferred_syslog` was one cache entry shared by every syslog-shaped format there
    # is, so the first file ingested decided how all the others were read.
    name = f"inferred_{result.schema.slug()}"
    if config.bootstrap.persist_schemas and not result.route.startswith("known:"):
        # Persisted only once it has passed the gate, so the next file from this source skips
        # inference entirely -- and so a schema nobody validated never reaches the cache.
        save_schema(result.schema, schema_dir, name)
    return InferredAdapter(result.schema, name=name), f"{reason}; {result.reason}"


def _select_adapter(
    source_path: Path, config: MistifyConfig, format_name: str | None
) -> tuple[LogAdapter, dict[str, float], str | None]:
    """Pick the adapter for one file: explicit name, detection, bootstrap, or raw lines.

    Lifted out of `ingest` unchanged so a directory can run it per file. A directory holding
    JSON from one service and syslog from another has to be read as both, and the only way to
    guarantee each file gets the treatment it would get alone is for it to be the same code
    path -- a second, simpler selection rule for directories would drift from this one.
    """
    fallback_reason: str | None = None
    adapter: LogAdapter | None

    if format_name and format_name != "auto":
        try:
            adapter = get_adapter(format_name)
        except ValueError as exc:
            # The registry signals an unregistered name with ValueError, but the CLI only
            # catches UnknownFormatError, so a typo in --format surfaced as a traceback.
            raise UnknownFormatError(str(exc)) from exc
        return adapter, {format_name: 1.0}, None

    sample = read_sample(source_path, config.bootstrap.sample_size)
    adapter, scores = detect_format(
        sample,
        registered=config.adapters.registered,
        min_confidence=config.adapters.min_detect_confidence,
    )
    if adapter is None:
        best = max(scores.values(), default=0.0)
        reason = (
            f"no registered adapter matched (best confidence {best:.2f}, threshold "
            f"{config.adapters.min_detect_confidence:.2f})"
        )
        if config.bootstrap.enabled:
            bootstrapped = _bootstrap(source_path, config, reason)
            if bootstrapped is not None:
                adapter, fallback_reason = bootstrapped

        if adapter is None and config.adapters.on_unknown_format == "error":
            raise UnknownFormatError(f"{reason} for {source_path}")
        if adapter is None:
            # Degrade rather than refuse, and record that it happened. The metric is
            # load-bearing: a raw-line read has no real timestamps, so the incident window
            # and the burstiness term describe line order, and the report has to say so.
            adapter = get_adapter("raw_lines")
            fallback_reason = reason

    return adapter, scores, fallback_reason


def _select_for_directory(
    source_path: Path, config: MistifyConfig, format_name: str | None
) -> tuple[LogAdapter, dict[str, float], str | None]:
    """Build one adapter over every readable log file in a directory.

    An incident is usually a directory -- one log per service or per pod -- and pointing the
    pipeline at one used to fail with a bare `PermissionError` out of `open()`.

    Unreadable files are dropped here rather than inside the adapter, because selection has to
    open them anyway to detect a format: a PNG in a log directory raises on the detection read,
    and there is nothing to select for it. The count travels into the adapter so that the drop
    is reported rather than silent.

    Confidence scores are merged by taking each format's best across the files. There is one
    number for this in `run_metadata` and there are many files, so any merge loses something;
    the best is the one that answers "was anything confidently recognised", which is the
    question a reader of that metric is asking.
    """
    from mistify.adapters.multi_file import MultiFileAdapter, log_files
    from mistify.adapters.source import BinarySourceError

    candidates = log_files(source_path)
    if not candidates:
        raise UnknownFormatError(f"no files to read under {source_path}")

    members: list[tuple[Path, LogAdapter]] = []
    merged: dict[str, float] = {}
    reasons: list[str] = []
    skipped: list[str] = []

    for path in candidates:
        relative = path.relative_to(source_path).as_posix()
        try:
            adapter, scores, reason = _select_adapter(path, config, format_name)
        except (BinarySourceError, OSError) as exc:
            skipped.append(f"{relative}: {exc}")
            continue
        members.append((path, adapter))
        for name, score in scores.items():
            merged[name] = max(merged.get(name, 0.0), score)
        if reason is not None:
            reasons.append(f"{relative}: {reason}")

    if not members:
        raise UnknownFormatError(
            f"nothing under {source_path} could be read as a log file ({len(skipped)} skipped)"
        )

    multi = MultiFileAdapter(members, source_path)
    multi.files_skipped = len(skipped)
    for sample in skipped[:5]:
        multi.stats.record_error(sample)

    # One reason for the whole directory, naming how many files degraded rather than
    # concatenating forty explanations. The per-file detail is in the error samples.
    fallback_reason = None
    if reasons:
        fallback_reason = (
            f"{len(reasons)} of {len(members)} files did not match a registered adapter; "
            f"first: {reasons[0]}"
        )
    if skipped:
        note = f"{len(skipped)} file(s) skipped as unreadable"
        fallback_reason = f"{fallback_reason}; {note}" if fallback_reason else note

    return multi, merged, fallback_reason


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
    if source_path.is_dir():
        adapter, scores, fallback_reason = _select_for_directory(source_path, config, format_name)
    else:
        adapter, scores, fallback_reason = _select_adapter(source_path, config, format_name)

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
        sample_adapter = adapter.fresh()
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

    # A file that calibration could not compress is one where Drain3 will hold a cluster for
    # almost every line, and its per-line cost grows with how many it holds. Capping there
    # bought 5.6x throughput on a real CI log for 0.2% more template fragmentation, because
    # `DrainTemplater` keeps its own registry and eviction loses no template from the output.
    # Never applied to a file that *did* compress: there the cap would never bind anyway, and
    # on a genuinely diverse log that clusters well it would fragment for nothing.
    max_clusters = config.drain3.max_clusters
    uncompressible = (
        calibration is not None
        and calibration.status == CalibrationStatus.UNDER_CLUSTERED
        and config.drain3.uncompressible_max_clusters < max_clusters
    )
    if uncompressible:
        max_clusters = config.drain3.uncompressible_max_clusters

    templater = DrainTemplater(
        sim_th=sim_th,
        depth=config.drain3.depth,
        max_clusters=max_clusters,
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
        # Redaction is taken a chunk at a time rather than a record at a time, because it is
        # the one stage that parallelises and a process pool needs something to hand a worker.
        # The chunk is the same order of magnitude as the insert batch, so peak memory is
        # unchanged in kind: a bounded number of records, never the file.
        #
        # Templating stays strictly sequential and in this process. Drain3 builds its tree
        # incrementally, so the template a line gets depends on every line before it -- running
        # it in parallel would not be a speed-up of the same computation, it would be a
        # different clustering.
        with RedactionPool(redactor, config.redaction.workers) as pool:
            for chunk in _chunked(adapter.parse(source_path), REDACT_CHUNK_SIZE):
                # Redaction first. Nothing downstream -- templater, snapshot, database, or any
                # model call -- ever sees an unredacted record.
                for record in pool.redact(chunk):
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
                *ingest_metrics(adapter, scores, events_loaded, fallback_reason),
                *redaction_metrics(config, redactor, vault, vault_path),
                *templating_metrics(
                    config, templater, sim_th, coverage, calibration, over_merged, max_clusters
                ),
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

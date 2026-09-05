"""What each pipeline stage publishes about its own run.

A health metric belongs to the stage that produced it, not to whoever happens to be holding a
database handle. These functions are pure: each takes what its stage finished with and returns
the metrics that describe it, so the numbers can be checked without a log file, a scratchpad,
or a pipeline run.

They are grouped by stage because that is the seam the ingest pipeline will eventually be cut
along. Until then, extracting them is what stops `ingest()` from spending a third of its body
on bookkeeping unrelated to the ordering guarantee it exists to enforce.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mistify.metrics import (
    ANOMALY_BUCKET_MINUTES,
    ANOMALY_NEEDLE_POSITION,
    ANOMALY_SCORED_TEMPLATES,
    ANOMALY_SEVERITY_INFORMATIVE,
    ANOMALY_SEVERITY_SOURCE,
    ANOMALY_SIGNAL_TEMPLATE_IDS,
    ANOMALY_SIGNAL_TEMPLATES,
    ANOMALY_SUPPRESSED_NOISE,
    ANOMALY_TOP_SCORE,
    ANOMALY_TOP_TEMPLATE_ID,
    ANOMALY_UNMAPPED_SEVERITY_SHARE,
    ANOMALY_WEIGHTS,
    INGEST_DETECT_CONFIDENCE,
    INGEST_EVENTS_LOADED,
    INGEST_FALLBACK,
    INGEST_FALLBACK_REASON,
    INGEST_FORMAT,
    INGEST_LINES_READ,
    INGEST_PARSE_ERRORS,
    INGEST_TIMESTAMP_SHAPE,
    INGEST_TIMESTAMP_YEAR_INFERRED,
    INGEST_UNMAPPED_SEVERITY,
    INGEST_UNPARSEABLE_TIMESTAMP,
    REDACTED_BY_ENTITY,
    REDACTION_ENTITIES,
    REDACTION_MODE,
    REDACTION_TOTAL,
    REDACTION_VAULT,
    REDACTION_VAULT_ENTRIES,
    REDACTION_VAULT_PATH,
    TEMPLATING_CALIBRATION_CANDIDATES,
    TEMPLATING_CALIBRATION_REASON,
    TEMPLATING_CALIBRATION_STATUS,
    TEMPLATING_COMPRESSION_RATIO,
    TEMPLATING_COVERAGE,
    TEMPLATING_DEPTH,
    TEMPLATING_EVICTED,
    TEMPLATING_LARGEST_SHARE,
    TEMPLATING_MAX_CLUSTERS,
    TEMPLATING_OVER_MERGED,
    TEMPLATING_OVER_MERGED_IDS,
    TEMPLATING_REDUCTION_FACTOR,
    TEMPLATING_SIM_TH,
    TEMPLATING_UNIQUE_TEMPLATES,
    Metric,
)
from mistify.templating.calibration import CalibrationStatus

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to the type checker
    from pathlib import Path

    from mistify.adapters.base import LogAdapter
    from mistify.common.config import MistifyConfig
    from mistify.common.models import TemplateSummary
    from mistify.redaction.redactor import Redactor
    from mistify.redaction.vault import RedactionVault
    from mistify.scratchpad.anomaly import AnomalyComponents
    from mistify.templating.calibration import CalibrationResult, OverMergedTemplate
    from mistify.templating.drain_wrapper import DrainTemplater

__all__ = [
    "Entries",
    "anomaly_metrics",
    "ingest_metrics",
    "redaction_metrics",
    "templating_metrics",
]

#: What every stage hands back: declared metrics paired with their values.
Entries = list[tuple[Metric, Any]]


def ingest_metrics(
    adapter: LogAdapter,
    scores: dict[str, float],
    events_loaded: int,
    fallback_reason: str | None = None,
) -> Entries:
    """Adapter counters. Malformed lines are skipped, so these are how you know they were.

    `fallback_reason` is set only when no adapter recognised the file and it was read line by
    line. Recorded as its own metric rather than inferred from `format`, because a reader
    checking whether the timestamps mean anything should not have to know which format names
    happen to be fallbacks.
    """
    stats = adapter.stats
    # A wrapper's `format_name` is a summary of its members and is not a key in `scores`, so
    # looking it up returned 0.0 for a directory in which JSON Lines had matched at 1.0 --
    # a confidently-recognised source reported as recognised by nothing.
    confidence = scores.get(adapter.format_name)
    if confidence is None:
        confidence = max(scores.values(), default=0.0)
    entries: Entries = [
        (INGEST_FORMAT, adapter.format_name),
        (INGEST_DETECT_CONFIDENCE, round(confidence, 3)),
        (INGEST_LINES_READ, stats.lines_read),
        (INGEST_EVENTS_LOADED, events_loaded),
        (INGEST_PARSE_ERRORS, stats.parse_errors),
        (INGEST_UNMAPPED_SEVERITY, stats.unmapped_severity),
        (INGEST_UNPARSEABLE_TIMESTAMP, stats.unparseable_timestamp),
    ]
    if stats.timestamp_shape is not None:
        entries.append((INGEST_TIMESTAMP_SHAPE, stats.timestamp_shape))
        entries.append((INGEST_TIMESTAMP_YEAR_INFERRED, stats.timestamp_year_inferred))
    if fallback_reason is not None:
        # The *reader* that degraded, not the adapter's display name. `INGEST_FALLBACK` fires
        # the report's strongest warning by exact match on `raw_lines`, and a directory reports
        # a composite name -- so a source read half in raw lines matched nothing and warned
        # about nothing, while printing a 1970-to-now log window as fact.
        components = adapter.component_formats
        degraded = "raw_lines" if "raw_lines" in components else adapter.format_name
        entries.append((INGEST_FALLBACK, degraded))
        entries.append((INGEST_FALLBACK_REASON, fallback_reason))
    return entries


def redaction_metrics(
    config: MistifyConfig,
    redactor: Redactor,
    vault: RedactionVault | None,
    vault_path: Path | None,
) -> Entries:
    """Per-entity counts, plus whether a reversible vault was kept.

    Only entities that actually matched something appear: a run that redacted no addresses
    should not claim a zero it never measured.
    """
    entries: Entries = [
        (REDACTION_MODE, config.redaction.mode),
        (REDACTION_ENTITIES, ",".join(config.redaction.entities)),
    ]
    entries += [
        (REDACTED_BY_ENTITY.member(entity), count)
        for entity, count in sorted(redactor.counts.items())
    ]
    entries.append((REDACTION_TOTAL, sum(redactor.counts.values())))
    entries.append((REDACTION_VAULT, vault is not None))
    if vault is not None:
        entries.append((REDACTION_VAULT_ENTRIES, vault.count()))
        entries.append((REDACTION_VAULT_PATH, str(vault_path)))
    return entries


def templating_metrics(
    config: MistifyConfig,
    templater: DrainTemplater,
    sim_th: float,
    coverage: float,
    calibration: CalibrationResult | None,
    over_merged: list[OverMergedTemplate],
    max_clusters: int | None = None,
) -> Entries:
    """Coverage first, because it is the invariant rather than a statistic.

    Every event must be reachable through a template. An event whose template was dropped is a
    line no template search can surface, and the compression ratio reports that loss as a
    success -- which is why the ratio is kept only as a diagnostic.
    """
    signal = templater.signal_stats()
    entries: Entries = [
        (TEMPLATING_COVERAGE, round(coverage, 6)),
        (TEMPLATING_UNIQUE_TEMPLATES, templater.unique_templates),
        (TEMPLATING_REDUCTION_FACTOR, round(signal["reduction_factor"], 2)),
        (TEMPLATING_LARGEST_SHARE, round(signal["largest_template_share"], 4)),
        (TEMPLATING_EVICTED, templater.evicted_templates),
        (TEMPLATING_COMPRESSION_RATIO, round(templater.compression_ratio, 5)),
        (TEMPLATING_SIM_TH, sim_th),
        (TEMPLATING_DEPTH, config.drain3.depth),
        # What was used, not what was configured: the pipeline lowers it on a file
        # that would not compress, and a silent ceiling is the thing this vocabulary
        # exists to prevent.
        (
            TEMPLATING_MAX_CLUSTERS,
            config.drain3.max_clusters if max_clusters is None else max_clusters,
        ),
    ]
    if calibration is not None:
        entries.append((TEMPLATING_CALIBRATION_STATUS, calibration.status))
        entries.append((TEMPLATING_CALIBRATION_CANDIDATES, calibration.as_metric()))
        entries.append((TEMPLATING_CALIBRATION_REASON, calibration.reason))
    else:
        entries.append((TEMPLATING_CALIBRATION_STATUS, CalibrationStatus.DISABLED))
    entries.append((TEMPLATING_OVER_MERGED, len(over_merged)))
    if over_merged:
        entries.append(
            (TEMPLATING_OVER_MERGED_IDS, ",".join(str(t.template_id) for t in over_merged))
        )
    return entries


def anomaly_metrics(
    config: MistifyConfig,
    scored: list[AnomalyComponents],
    summaries: list[TemplateSummary],
    signal_templates: list[AnomalyComponents],
    suppressed_noise: int,
    severity_informative: bool,
    unmapped_share: float,
    severity_source: str,
) -> Entries:
    """Ranking outcome, including where the worst template landed.

    `severity_source` is recorded beside `severity_informative` because the two are no longer
    the same question: a file with no severity field now has its severity read out of the
    template text instead, and only on the text failing to discriminate either is the term
    dropped. A reader who sees the ranking put something odd first needs to know which of the
    three produced it.

    `max_severity_rank_position` is the needle question asked directly: reading the ranked
    list from the top, would an investigator meet the most severe thing in the file early, or
    have to dig for it?
    """
    entries: Entries = [
        (ANOMALY_SCORED_TEMPLATES, len(scored)),
        (ANOMALY_SEVERITY_INFORMATIVE, severity_informative),
        (ANOMALY_SEVERITY_SOURCE, severity_source),
        (ANOMALY_UNMAPPED_SEVERITY_SHARE, round(unmapped_share, 4)),
        (ANOMALY_SIGNAL_TEMPLATES, len(signal_templates)),
        (
            ANOMALY_SIGNAL_TEMPLATE_IDS,
            ",".join(str(c.template_id) for c in signal_templates),
        ),
        (ANOMALY_SUPPRESSED_NOISE, suppressed_noise),
        (ANOMALY_WEIGHTS, str(config.anomaly.weights())),
        (ANOMALY_BUCKET_MINUTES, config.anomaly.bucket_minutes),
    ]
    if scored:
        entries.append((ANOMALY_TOP_TEMPLATE_ID, scored[0].template_id))
        entries.append((ANOMALY_TOP_SCORE, round(scored[0].score, 4)))
        if summaries:
            worst = max(summaries, key=lambda s: s.max_severity_rank)
            order = [c.template_id for c in scored]
            entries.append((ANOMALY_NEEDLE_POSITION, order.index(worst.template_id) + 1))
    return entries

"""The health-metric vocabulary.

Every number or flag a stage publishes about its own run is declared here once, and both
writers and readers go through these declarations rather than agreeing on string literals.

Why this module exists: the `(stage, metric)` pair is a load-bearing contract -- fourteen
report warnings are driven by it -- and it used to be expressed only as string literals spread
across four packages and five test modules. Renaming a metric in the pipeline passed the whole
report suite while silently disabling the warning that read it, because the producer test and
the consumer test each asserted against their own copy of the string and never against each
other.

Two things are deliberately kept apart:

*   **Thresholds live here; wording lives in the report.** The cutoff at which a metric becomes
    worth mentioning is a fact about the metric. How that is phrased to a reader is the
    report's business.
*   **Rendering and acting are different reads.** `ScratchpadDB.metrics()` returns raw rows and
    is what the report's health table iterates, so a metric added tomorrow appears without a
    code change. `MetricView` is for acting on a specific metric, correctly typed. Neither
    replaces the other.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "ALL_METRICS",
    "Metric",
    "MetricFamily",
    "MetricView",
]

Kind = Literal["int", "float", "str", "bool"]


@dataclass(frozen=True, slots=True)
class Metric:
    """One declared health metric.

    `threshold` plus `comparison` describe when a reader should act. `floor` exists for the
    one two-sided case: a reduction factor of exactly 0.0 means an empty file rather than a
    badly compressed one, so the warning has a lower guard as well as an upper cutoff.
    `trigger_values` is the same idea for metrics whose trigger is a string rather than a
    number.
    """

    stage: str
    name: str
    kind: Kind
    #: True when some reader acts on this metric. Renaming a load-bearing metric changes
    #: behaviour; renaming a display-only one does not.
    load_bearing: bool = False
    threshold: float | None = None
    comparison: Literal["gt", "lt"] = "gt"
    floor: float = -math.inf
    trigger_values: frozenset[str] = field(default_factory=frozenset)

    @property
    def key(self) -> tuple[str, str]:
        return (self.stage, self.name)

    def __str__(self) -> str:
        return f"{self.stage}.{self.name}"


@dataclass(frozen=True, slots=True)
class MetricFamily:
    """A metric whose name carries a parameter.

    Only one exists: per-entity redaction counts. The member set is closed and validated at
    the call, so a typo produces an error rather than a row nobody will ever read.
    """

    stage: str
    prefix: str
    members: tuple[str, ...]
    kind: Kind

    def member(self, name: str) -> Metric:
        if name not in self.members:
            raise ValueError(
                f"{self.stage}.{self.prefix}* has no member {name!r}. "
                f"Known: {', '.join(sorted(self.members))}"
            )
        return Metric(stage=self.stage, name=f"{self.prefix}{name}", kind=self.kind)

    def all_members(self) -> tuple[Metric, ...]:
        return tuple(self.member(name) for name in self.members)


# --------------------------------------------------------------------- ingest

INGEST_FORMAT = Metric("ingest", "format", "str")
INGEST_DETECT_CONFIDENCE = Metric("ingest", "detect_confidence", "float")
INGEST_LINES_READ = Metric("ingest", "lines_read", "int")
INGEST_EVENTS_LOADED = Metric("ingest", "events_loaded", "int")
INGEST_PARSE_ERRORS = Metric(
    "ingest", "parse_errors", "int", load_bearing=True, threshold=0, comparison="gt"
)
INGEST_UNMAPPED_SEVERITY = Metric(
    "ingest", "unmapped_severity", "int", load_bearing=True, threshold=0, comparison="gt"
)
INGEST_UNPARSEABLE_TIMESTAMP = Metric("ingest", "unparseable_timestamp", "int")

# ------------------------------------------------------------------ redaction

REDACTION_MODE = Metric(
    "redaction", "mode", "str", load_bearing=True, trigger_values=frozenset({"off"})
)
REDACTION_ENTITIES = Metric("redaction", "entities", "str")
REDACTION_TOTAL = Metric("redaction", "redacted_total", "int")
REDACTION_VAULT = Metric("redaction", "vault", "bool")
REDACTION_VAULT_ENTRIES = Metric("redaction", "vault_entries", "int")
REDACTION_VAULT_PATH = Metric("redaction", "vault_path", "str")

#: Per-entity redaction counts. Members mirror `redaction.patterns.ENTITY_ORDER`; only
#: entities that actually matched something emit a row.
REDACTED_BY_ENTITY = MetricFamily(
    stage="redaction",
    prefix="redacted_",
    members=("api_key", "email", "ipv6", "ipv4", "ssn", "phone"),
    kind="int",
)

# ----------------------------------------------------------------- templating

TEMPLATING_COVERAGE = Metric(
    "templating",
    "template_coverage",
    "float",
    load_bearing=True,
    threshold=1.0,
    comparison="lt",
)
TEMPLATING_UNIQUE_TEMPLATES = Metric("templating", "unique_templates", "int")
TEMPLATING_REDUCTION_FACTOR = Metric(
    "templating",
    "reduction_factor",
    "float",
    load_bearing=True,
    threshold=2.0,
    comparison="lt",
    # A reduction factor of exactly 0.0 means an empty file, not a badly compressed one.
    floor=0.0,
)
TEMPLATING_LARGEST_SHARE = Metric(
    "templating",
    "largest_template_share",
    "float",
    load_bearing=True,
    threshold=0.6,
    comparison="gt",
)
TEMPLATING_EVICTED = Metric(
    "templating", "evicted_templates", "int", load_bearing=True, threshold=0, comparison="gt"
)
TEMPLATING_COMPRESSION_RATIO = Metric("templating", "compression_ratio", "float")
TEMPLATING_SIM_TH = Metric("templating", "sim_th", "float")
TEMPLATING_DEPTH = Metric("templating", "depth", "int")
TEMPLATING_CALIBRATION_STATUS = Metric(
    "templating",
    "calibration_status",
    "str",
    load_bearing=True,
    trigger_values=frozenset({"signal_at_risk", "under_clustered"}),
)
TEMPLATING_CALIBRATION_CANDIDATES = Metric("templating", "calibration_candidates", "str")
#: Load-bearing but has no trigger of its own: it supplies detail once the status has tripped.
TEMPLATING_CALIBRATION_REASON = Metric("templating", "calibration_reason", "str", load_bearing=True)
TEMPLATING_OVER_MERGED = Metric(
    "templating",
    "over_merged_templates",
    "int",
    load_bearing=True,
    threshold=0,
    comparison="gt",
)
TEMPLATING_OVER_MERGED_IDS = Metric("templating", "over_merged_ids", "str", load_bearing=True)

# -------------------------------------------------------------------- anomaly

ANOMALY_SCORED_TEMPLATES = Metric("anomaly", "scored_templates", "int")
ANOMALY_SEVERITY_INFORMATIVE = Metric("anomaly", "severity_informative", "bool")
ANOMALY_UNMAPPED_SEVERITY_SHARE = Metric("anomaly", "unmapped_severity_share", "float")
ANOMALY_SIGNAL_TEMPLATES = Metric("anomaly", "signal_templates", "int")
ANOMALY_SIGNAL_TEMPLATE_IDS = Metric("anomaly", "signal_template_ids", "str")
ANOMALY_SUPPRESSED_NOISE = Metric("anomaly", "suppressed_noise_templates", "int")
ANOMALY_WEIGHTS = Metric("anomaly", "weights", "str")
ANOMALY_BUCKET_MINUTES = Metric("anomaly", "bucket_minutes", "int")
ANOMALY_TOP_TEMPLATE_ID = Metric("anomaly", "top_template_id", "int")
ANOMALY_TOP_SCORE = Metric("anomaly", "top_score", "float")
ANOMALY_NEEDLE_POSITION = Metric(
    "anomaly",
    "max_severity_rank_position",
    "int",
    load_bearing=True,
    threshold=5,
    comparison="gt",
)

# ----------------------------------------------------------------- scratchpad

SCRATCHPAD_ORPHAN_EVENTS = Metric(
    "scratchpad", "orphan_events", "int", load_bearing=True, threshold=0, comparison="gt"
)

# ---------------------------------------------------------------- investigate

#: Read by the report to name which investigator produced the notes.
INVESTIGATE_INVESTIGATOR = Metric("investigate", "investigator", "str", load_bearing=True)
INVESTIGATE_STEPS = Metric("investigate", "steps", "int")
INVESTIGATE_OUTCOME = Metric("investigate", "outcome", "str")
INVESTIGATE_NOTES_WRITTEN = Metric("investigate", "notes_written", "int")
INVESTIGATE_TARGET_TEMPLATE_ID = Metric("investigate", "target_template_id", "int")


ALL_METRICS: tuple[Metric, ...] = (
    INGEST_FORMAT,
    INGEST_DETECT_CONFIDENCE,
    INGEST_LINES_READ,
    INGEST_EVENTS_LOADED,
    INGEST_PARSE_ERRORS,
    INGEST_UNMAPPED_SEVERITY,
    INGEST_UNPARSEABLE_TIMESTAMP,
    REDACTION_MODE,
    REDACTION_ENTITIES,
    REDACTION_TOTAL,
    REDACTION_VAULT,
    REDACTION_VAULT_ENTRIES,
    REDACTION_VAULT_PATH,
    *REDACTED_BY_ENTITY.all_members(),
    TEMPLATING_COVERAGE,
    TEMPLATING_UNIQUE_TEMPLATES,
    TEMPLATING_REDUCTION_FACTOR,
    TEMPLATING_LARGEST_SHARE,
    TEMPLATING_EVICTED,
    TEMPLATING_COMPRESSION_RATIO,
    TEMPLATING_SIM_TH,
    TEMPLATING_DEPTH,
    TEMPLATING_CALIBRATION_STATUS,
    TEMPLATING_CALIBRATION_CANDIDATES,
    TEMPLATING_CALIBRATION_REASON,
    TEMPLATING_OVER_MERGED,
    TEMPLATING_OVER_MERGED_IDS,
    ANOMALY_SCORED_TEMPLATES,
    ANOMALY_SEVERITY_INFORMATIVE,
    ANOMALY_UNMAPPED_SEVERITY_SHARE,
    ANOMALY_SIGNAL_TEMPLATES,
    ANOMALY_SIGNAL_TEMPLATE_IDS,
    ANOMALY_SUPPRESSED_NOISE,
    ANOMALY_WEIGHTS,
    ANOMALY_BUCKET_MINUTES,
    ANOMALY_TOP_TEMPLATE_ID,
    ANOMALY_TOP_SCORE,
    ANOMALY_NEEDLE_POSITION,
    SCRATCHPAD_ORPHAN_EVENTS,
    INVESTIGATE_INVESTIGATOR,
    INVESTIGATE_STEPS,
    INVESTIGATE_OUTCOME,
    INVESTIGATE_NOTES_WRITTEN,
    INVESTIGATE_TARGET_TEMPLATE_ID,
)


class MetricView:
    """Typed reads over the metrics recorded for one incident.

    Absent and zero are different answers here. Every reader used to write
    `(row["value_num"] or 0) > 0`, which collapses a legitimate 0.0 into the same result as a
    metric that was never recorded. The warning outcome happened to be identical in each case,
    but it meant nothing could ever report that a stage failed to publish at all.
    """

    def __init__(self, rows: Sequence[Mapping[str, Any]]):
        self._rows = {(row["stage"], row["metric"]): row for row in rows}

    def __contains__(self, metric: Metric) -> bool:
        return metric.key in self._rows

    def number(self, metric: Metric) -> float | None:
        """Numeric value, or None when the metric was never recorded."""
        row = self._rows.get(metric.key)
        if row is None or row["value_num"] is None:
            return None
        return float(row["value_num"])

    def text(self, metric: Metric) -> str | None:
        row = self._rows.get(metric.key)
        return None if row is None else str(row["value"])

    def flag(self, metric: Metric) -> bool | None:
        """Round-trip a bool, which is stored as `"True"` / `"False"` text."""
        value = self.number(metric)
        return None if value is None else bool(value)

    def triggers(self, metric: Metric) -> bool:
        """Whether this metric has reached the point a reader should act on.

        Returns False for an absent metric, and for one that was never declared with a
        trigger -- a detail metric such as a calibration reason has no cutoff of its own.
        """
        if metric.trigger_values:
            text = self.text(metric)
            return text is not None and text in metric.trigger_values
        if metric.threshold is None:
            return False
        value = self.number(metric)
        if value is None:
            return False
        if metric.comparison == "gt":
            return value > metric.threshold
        return metric.floor < value < metric.threshold


def as_rows(entries: Iterable[tuple[Metric, object]]) -> list[tuple[str, str, object]]:
    """Flatten declared metrics into the tuples the scratchpad writer takes.

    Stages hand back the metrics they produced rather than writing them mid-computation, so
    this is what turns a stage's return value into rows.
    """
    return [(metric.stage, metric.name, value) for metric, value in entries]

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
    "StageTokens",
    "token_usage",
    "total_tokens",
]

Kind = Literal["int", "float", "str", "bool"]

#: What a token count counts. Declared on the metric rather than inferred from its name, so
#: the report can total a run's token usage without holding a list of which metrics are token
#: metrics -- a list that goes stale the moment a stage starts calling a model.
#: `cached_input` is a *subset* of `input`, matching `llm.base.Usage`; totalling both would
#: double-count.
TokenRole = Literal["input", "cached_input", "output"]


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
    #: Set when this metric is a token count, saying which one. Every stage that calls a model
    #: declares the same three, which is what lets a run total be computed rather than
    #: maintained.
    token_role: TokenRole | None = None
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

#: Set when no adapter recognised the file and it was read line by line instead. Load-bearing:
#: a raw-line read has no real timestamps and no parsed severity, so the incident window and
#: half the anomaly score describe the file's line order rather than the incident. A report
#: that did not say so would present those numbers as facts.
INGEST_FALLBACK = Metric(
    "ingest", "fallback", "str", load_bearing=True, trigger_values=frozenset({"raw_lines"})
)

#: Why the fallback happened -- the best confidence any adapter managed, and against what
#: threshold. Detail rather than a trigger: it explains a warning that has already fired.
INGEST_FALLBACK_REASON = Metric("ingest", "fallback_reason", "str", load_bearing=True)

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

#: The cluster ceiling the run actually used. Load-bearing because the pipeline lowers it by
#: itself on a file calibration could not compress -- a 5.6x throughput trade that costs a
#: little template fragmentation -- and a limit the run chose is not a limit the config states.
#: A reader comparing two runs of the same file needs to see which one was capped.
TEMPLATING_MAX_CLUSTERS = Metric("templating", "max_clusters", "int", load_bearing=True)
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
#: Where the severity term's values came from: "field" when the source carried one, "lexical"
#: when it was recovered from the template text, "none" when neither discriminated and the
#: weight was redistributed. `severity_informative` alone cannot say which of the last two
#: happened, and they rank a file very differently.
ANOMALY_SEVERITY_SOURCE = Metric(
    "anomaly",
    "severity_source",
    "str",
    load_bearing=True,
    trigger_values=frozenset({"none"}),
)
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
#: How much to trust this investigator, in its own words. Recorded by whichever one ran, so
#: the report renders a caveat without needing to know what investigators exist.
INVESTIGATE_CAVEAT = Metric("investigate", "caveat", "str", load_bearing=True)
INVESTIGATE_PROVIDER = Metric("investigate", "provider", "str")
INVESTIGATE_MODEL = Metric("investigate", "model", "str")
INVESTIGATE_TOOL_CALLS = Metric("investigate", "tool_calls", "int")
#: The investigation ran out of tool calls before the model concluded. Load-bearing: the
#: report must say so rather than presenting a truncated search as a finished one.
INVESTIGATE_BUDGET_LIMITED = Metric(
    "investigate",
    "budget_limited",
    "bool",
    load_bearing=True,
    trigger_values=frozenset({"True"}),
)
INVESTIGATE_STOP_REASON = Metric("investigate", "stop_reason", "str")
#: Every prompt token the loop spent, cached ones included -- see `llm.base.Usage`.
INVESTIGATE_INPUT_TOKENS = Metric("investigate", "input_tokens", "int", token_role="input")
INVESTIGATE_OUTPUT_TOKENS = Metric("investigate", "output_tokens", "int", token_role="output")
#: The subset of `input_tokens` served from cache. Zero across a multi-step run means either
#: the cached prefix is being invalidated every step or the provider does not report cache
#: reads -- worth telling apart before concluding the investigation is expensive.
INVESTIGATE_CACHED_INPUT_TOKENS = Metric(
    "investigate", "cached_input_tokens", "int", token_role="cached_input"
)

#: Input tokens on each step, in order. The loop re-sends the whole conversation every step, so
#: this is the curve that decides what a long investigation costs -- and the total alone hides
#: it completely. A detail metric: the shape is for reading, the growth factor below is for
#: acting on.
INVESTIGATE_INPUT_TOKENS_PER_STEP = Metric("investigate", "input_tokens_per_step", "str")

#: Last step's input divided by the first step's. Growth is expected -- the conversation
#: accumulates -- but a large factor means the history is carrying more than the reasoning
#: needs, and on a longer incident it is what runs into the context ceiling.
INVESTIGATE_INPUT_GROWTH = Metric(
    "investigate",
    "input_growth_factor",
    "float",
    load_bearing=True,
    threshold=5.0,
    comparison="gt",
)

#: How many times old tool results were replaced by their summary line. Zero on a short
#: investigation is correct; zero on a long one means compaction is not running.
INVESTIGATE_HISTORY_COMPACTIONS = Metric("investigate", "history_compactions", "int")

#: Times the loop refused to accept a conclusion that left an acute signal template
#: unaccounted for, and asked for one more turn. The check itself is model-free; this counts
#: how often it had to fire.
INVESTIGATE_COVERAGE_NUDGES = Metric("investigate", "coverage_nudges", "int")
#: Of those nudges, the ones asking about a digest template the model never opened. Separate
#: from the total because the two questions fail for different reasons and the fix for one is
#: not the fix for the other.
INVESTIGATE_DIGEST_NUDGES = Metric("investigate", "digest_nudges", "int")

#: Whether a run had to be asked to write anything down before its budget ran out. Distinct
#: from the other two: those answer a conclusion, this one answers the absence of one.
INVESTIGATE_SILENT_NUDGES = Metric("investigate", "silent_nudges", "int")

#: Which templates the nudges named, comma-separated. The set a note's citations are tested
#: against to decide whether it is a finding or an answer, so without it a recorded run cannot
#: be re-scored: the note carries its role but nothing says what the role was judged on. Every
#: run before this metric existed is exactly that unanswerable, which is how it came to exist.
INVESTIGATE_NUDGED_TEMPLATES = Metric("investigate", "nudged_templates", "str")

#: Size of the system prompt, digest included. The prompt is re-sent on every step, so this
#: is the multiplier on a run's whole input cost -- and it is set by the corpus, not by
#: config. One real incident reached 208,843 characters before this had a name.
INVESTIGATE_DIGEST_CHARS = Metric(
    "investigate",
    "digest_chars",
    "int",
    load_bearing=True,
    threshold=40_000,
    comparison="gt",
)

# ------------------------------------------------------------------ synthesis

SYNTHESIS_PROVIDER = Metric("synthesis", "provider", "str")
SYNTHESIS_MODEL = Metric("synthesis", "model", "str")
SYNTHESIS_OUTCOME = Metric(
    "synthesis",
    "outcome",
    "str",
    load_bearing=True,
    trigger_values=frozenset({"unreadable", "no_usable_citations", "empty"}),
)
SYNTHESIS_MODEL_CALLS = Metric("synthesis", "model_calls", "int")
SYNTHESIS_INPUT_TOKENS = Metric("synthesis", "input_tokens", "int", token_role="input")
SYNTHESIS_OUTPUT_TOKENS = Metric("synthesis", "output_tokens", "int", token_role="output")
SYNTHESIS_CACHED_INPUT_TOKENS = Metric(
    "synthesis", "cached_input_tokens", "int", token_role="cached_input"
)
#: Ids the conclusion named that no note had cited, and which were therefore dropped. The
#: synthesis model has no tools and cannot gather evidence; reaching for some anyway is worth
#: counting even when the reach is harmless.
SYNTHESIS_DROPPED_CITATIONS = Metric(
    "synthesis", "dropped_citations", "int", load_bearing=True, threshold=0, comparison="gt"
)

# ---------------------------------------------------------------- adversarial

ADVERSARIAL_PROVIDER = Metric("adversarial", "provider", "str")
ADVERSARIAL_MODEL = Metric("adversarial", "model", "str")
#: Objections the critique raised. Load-bearing: an investigation with unanswered objections
#: has not been checked, it has been disagreed with.
ADVERSARIAL_OBJECTIONS = Metric(
    "adversarial", "objections", "int", load_bearing=True, threshold=0, comparison="gt"
)
#: Objections raised at high severity that cite rows. Counted *before* the rebuttal, so this
#: is how much was thrown at the investigation, not how much stuck. It was called
#: `unsupported_claims` and drove a warning, which asserted that claims were unsupported on the
#: strength of an accusation the investigation had not yet answered.
ADVERSARIAL_HIGH_SEVERITY_OBJECTIONS = Metric("adversarial", "high_severity_objections", "int")

#: High-severity objections the investigation never answered at all. Counted after the
#: rebuttal, and load-bearing: a conceded objection is bad news that the report states plainly,
#: and an answered one is the system working, but an unanswered one means nothing checked it.
ADVERSARIAL_UNREBUTTED_HIGH_SEVERITY = Metric(
    "adversarial",
    "unrebutted_high_severity",
    "int",
    load_bearing=True,
    threshold=0,
    comparison="gt",
)

#: Acute high-anomaly templates the conclusion never accounted for -- the one mechanical test
#: the adversarial pass performs that does not depend on a model's judgement. Chronic templates
#: are excluded and counted separately: a template active across the whole log was not part of
#: the incident, so declining to explain it is correct rather than an omission.
ADVERSARIAL_UNEXPLAINED_SIGNAL = Metric(
    "adversarial",
    "unexplained_signal_templates",
    "int",
    load_bearing=True,
    threshold=0,
    comparison="gt",
)

#: Chronic signal templates no note cites. An observation, deliberately not load-bearing: on
#: any log with a steady error stream this is permanently non-zero, and a warning that always
#: fires is one a reader learns to skip.
ADVERSARIAL_UNEXPLAINED_CHRONIC = Metric("adversarial", "unexplained_chronic_templates", "int")
ADVERSARIAL_REBUTTED = Metric("adversarial", "objections_rebutted", "int")
ADVERSARIAL_OUTCOME = Metric("adversarial", "outcome", "str")
#: Model calls the critique and rebuttal made between them. Without it the token counts below
#: cannot be read as a rate, and a pass that silently made two calls looks like one.
ADVERSARIAL_MODEL_CALLS = Metric("adversarial", "model_calls", "int")
ADVERSARIAL_INPUT_TOKENS = Metric("adversarial", "input_tokens", "int", token_role="input")
ADVERSARIAL_OUTPUT_TOKENS = Metric("adversarial", "output_tokens", "int", token_role="output")
ADVERSARIAL_CACHED_INPUT_TOKENS = Metric(
    "adversarial", "cached_input_tokens", "int", token_role="cached_input"
)
#: Only recorded when the rebuttal ran on a different model from the critique, which is the
#: normal case: the point of a rebuttal is that the *original reasoning* answers. Without it
#: this stage's tokens would be attributed entirely to the critique's model.
ADVERSARIAL_REBUTTAL_MODEL = Metric("adversarial", "rebuttal_model", "str")


ALL_METRICS: tuple[Metric, ...] = (
    INGEST_FORMAT,
    INGEST_DETECT_CONFIDENCE,
    INGEST_LINES_READ,
    INGEST_EVENTS_LOADED,
    INGEST_PARSE_ERRORS,
    INGEST_UNMAPPED_SEVERITY,
    INGEST_UNPARSEABLE_TIMESTAMP,
    INGEST_FALLBACK,
    INGEST_FALLBACK_REASON,
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
    TEMPLATING_MAX_CLUSTERS,
    TEMPLATING_DEPTH,
    TEMPLATING_CALIBRATION_STATUS,
    TEMPLATING_CALIBRATION_CANDIDATES,
    TEMPLATING_CALIBRATION_REASON,
    TEMPLATING_OVER_MERGED,
    TEMPLATING_OVER_MERGED_IDS,
    ANOMALY_SCORED_TEMPLATES,
    ANOMALY_SEVERITY_INFORMATIVE,
    ANOMALY_UNMAPPED_SEVERITY_SHARE,
    ANOMALY_SEVERITY_SOURCE,
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
    INVESTIGATE_CAVEAT,
    INVESTIGATE_PROVIDER,
    INVESTIGATE_MODEL,
    INVESTIGATE_TOOL_CALLS,
    INVESTIGATE_BUDGET_LIMITED,
    INVESTIGATE_STOP_REASON,
    INVESTIGATE_INPUT_TOKENS,
    INVESTIGATE_OUTPUT_TOKENS,
    INVESTIGATE_CACHED_INPUT_TOKENS,
    INVESTIGATE_INPUT_TOKENS_PER_STEP,
    INVESTIGATE_INPUT_GROWTH,
    INVESTIGATE_HISTORY_COMPACTIONS,
    INVESTIGATE_COVERAGE_NUDGES,
    INVESTIGATE_DIGEST_NUDGES,
    INVESTIGATE_NUDGED_TEMPLATES,
    INVESTIGATE_SILENT_NUDGES,
    INVESTIGATE_DIGEST_CHARS,
    SYNTHESIS_PROVIDER,
    SYNTHESIS_MODEL,
    SYNTHESIS_OUTCOME,
    SYNTHESIS_MODEL_CALLS,
    SYNTHESIS_INPUT_TOKENS,
    SYNTHESIS_OUTPUT_TOKENS,
    SYNTHESIS_CACHED_INPUT_TOKENS,
    SYNTHESIS_DROPPED_CITATIONS,
    ADVERSARIAL_PROVIDER,
    ADVERSARIAL_MODEL,
    ADVERSARIAL_OBJECTIONS,
    ADVERSARIAL_HIGH_SEVERITY_OBJECTIONS,
    ADVERSARIAL_UNREBUTTED_HIGH_SEVERITY,
    ADVERSARIAL_UNEXPLAINED_SIGNAL,
    ADVERSARIAL_UNEXPLAINED_CHRONIC,
    ADVERSARIAL_REBUTTED,
    ADVERSARIAL_MODEL_CALLS,
    ADVERSARIAL_INPUT_TOKENS,
    ADVERSARIAL_OUTPUT_TOKENS,
    ADVERSARIAL_CACHED_INPUT_TOKENS,
    ADVERSARIAL_REBUTTAL_MODEL,
    ADVERSARIAL_OUTCOME,
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


@dataclass(frozen=True, slots=True)
class StageTokens:
    """What one stage spent on model calls.

    `cached_input_tokens` is a subset of `input_tokens`, so `total_tokens` deliberately does
    not add it in -- see `llm.base.Usage` for why the adapters normalise to that shape.
    """

    stage: str
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    model: str | None = None
    calls: int | None = None

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def cached_share(self) -> float:
        """Share of the prompt served from cache. Zero when nothing was cached *or* measured."""
        return self.cached_input_tokens / self.input_tokens if self.input_tokens else 0.0

    def __add__(self, other: StageTokens) -> StageTokens:
        """Combine two stages. The result carries no model or call count, because it has two."""
        return StageTokens(
            stage="total",
            input_tokens=self.input_tokens + other.input_tokens,
            cached_input_tokens=self.cached_input_tokens + other.cached_input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
        )


#: The model a stage used and how many calls it made, so a token count can say what spent it.
#: A stage absent from here still reports its tokens, just without attribution.
_TOKEN_CONTEXT: dict[str, tuple[Metric, Metric]] = {
    "investigate": (INVESTIGATE_MODEL, INVESTIGATE_STEPS),
    "synthesis": (SYNTHESIS_MODEL, SYNTHESIS_MODEL_CALLS),
    "adversarial": (ADVERSARIAL_MODEL, ADVERSARIAL_MODEL_CALLS),
}

_TOKEN_FIELDS: dict[str, str] = {
    "input": "input_tokens",
    "cached_input": "cached_input_tokens",
    "output": "output_tokens",
}


def token_usage(rows: Sequence[Mapping[str, Any]]) -> list[StageTokens]:
    """Per-stage token counts for one run.

    Driven by `Metric.token_role` rather than by a list of metric names kept here, so a stage
    that starts calling a model tomorrow appears in the report's token table by declaring its
    metrics and nothing else.

    A stage that recorded no token metric is omitted rather than shown as zero: it did not
    spend nothing, it did not report, and those are different claims. Same reason
    `MetricView` distinguishes absent from zero.
    """
    view = MetricView(rows)

    by_stage: dict[str, dict[str, int]] = {}
    for metric in ALL_METRICS:
        if metric.token_role is None:
            continue
        value = view.number(metric)
        if value is not None:
            by_stage.setdefault(metric.stage, {})[_TOKEN_FIELDS[metric.token_role]] = int(value)

    stages: list[StageTokens] = []
    for stage, counts in by_stage.items():
        model_metric, calls_metric = _TOKEN_CONTEXT.get(stage, (None, None))
        calls = None if calls_metric is None else view.number(calls_metric)
        stages.append(
            StageTokens(
                stage=stage,
                model=None if model_metric is None else view.text(model_metric),
                calls=None if calls is None else int(calls),
                **counts,
            )
        )
    return stages


def total_tokens(stages: Iterable[StageTokens]) -> StageTokens:
    """Every stage added up. Nothing in means an all-zero total, which the caller should not
    print without checking that any stage reported at all."""
    combined = StageTokens(stage="total")
    for stage in stages:
        combined = combined + stage
    return combined


def as_rows(entries: Iterable[tuple[Metric, object]]) -> list[tuple[str, str, object]]:
    """Flatten declared metrics into the tuples the scratchpad writer takes.

    Stages hand back the metrics they produced rather than writing them mid-computation, so
    this is what turns a stage's return value into rows.
    """
    return [(metric.stage, metric.name, value) for metric, value in entries]

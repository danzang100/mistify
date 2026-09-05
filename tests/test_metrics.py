"""The declared health-metric vocabulary."""

from __future__ import annotations

import math

import pytest

from mistify.metrics import (
    ALL_METRICS,
    REDACTED_BY_ENTITY,
    TEMPLATING_CALIBRATION_REASON,
    TEMPLATING_COVERAGE,
    TEMPLATING_REDUCTION_FACTOR,
    Metric,
    MetricView,
    as_rows,
    token_usage,
    total_tokens,
)
from mistify.redaction.patterns import ENTITY_ORDER

# --------------------------------------------------------------- the frozen name list

#: Every `(stage, metric)` pair the vocabulary declares.
#:
#: This is the one place metric names are written as literals. Tests elsewhere import the
#: constants, so a rename updates them silently and no assertion notices — the safety there
#: comes from the type checker. Here it must fail loudly, because renaming a metric changes
#: the wire format of an existing scratchpad and breaks any report reading one.
EXPECTED_METRIC_KEYS = {
    ("ingest", "format"),
    ("ingest", "detect_confidence"),
    ("ingest", "lines_read"),
    ("ingest", "events_loaded"),
    ("ingest", "parse_errors"),
    ("ingest", "unmapped_severity"),
    ("ingest", "unparseable_timestamp"),
    ("ingest", "fallback"),
    ("ingest", "fallback_reason"),
    ("redaction", "mode"),
    ("redaction", "entities"),
    ("redaction", "redacted_total"),
    ("redaction", "vault"),
    ("redaction", "vault_entries"),
    ("redaction", "vault_path"),
    ("redaction", "redacted_api_key"),
    ("redaction", "redacted_email"),
    ("redaction", "redacted_ipv6"),
    ("redaction", "redacted_ipv4"),
    ("redaction", "redacted_ssn"),
    ("redaction", "redacted_phone"),
    ("templating", "template_coverage"),
    ("templating", "unique_templates"),
    ("templating", "reduction_factor"),
    ("templating", "largest_template_share"),
    ("templating", "evicted_templates"),
    ("templating", "compression_ratio"),
    ("templating", "sim_th"),
    ("templating", "depth"),
    ("templating", "max_clusters"),
    ("templating", "calibration_status"),
    ("templating", "calibration_candidates"),
    ("templating", "calibration_reason"),
    ("templating", "over_merged_templates"),
    ("templating", "over_merged_ids"),
    ("anomaly", "scored_templates"),
    ("anomaly", "severity_informative"),
    ("anomaly", "severity_source"),
    ("anomaly", "unmapped_severity_share"),
    ("anomaly", "signal_templates"),
    ("anomaly", "signal_template_ids"),
    ("anomaly", "suppressed_noise_templates"),
    ("anomaly", "weights"),
    ("anomaly", "bucket_minutes"),
    ("anomaly", "top_template_id"),
    ("anomaly", "top_score"),
    ("anomaly", "max_severity_rank_position"),
    ("scratchpad", "orphan_events"),
    ("investigate", "investigator"),
    ("investigate", "steps"),
    ("investigate", "outcome"),
    ("investigate", "notes_written"),
    ("investigate", "target_template_id"),
    ("investigate", "caveat"),
    ("investigate", "provider"),
    ("investigate", "model"),
    ("investigate", "tool_calls"),
    ("investigate", "budget_limited"),
    ("investigate", "stop_reason"),
    ("investigate", "input_tokens"),
    ("investigate", "output_tokens"),
    ("investigate", "cached_input_tokens"),
    ("investigate", "input_tokens_per_step"),
    ("investigate", "input_growth_factor"),
    ("investigate", "history_compactions"),
    ("investigate", "coverage_nudges"),
    ("investigate", "digest_chars"),
    ("investigate", "digest_nudges"),
    ("investigate", "silent_nudges"),
    ("investigate", "nudged_templates"),
    ("synthesis", "provider"),
    ("synthesis", "model"),
    ("synthesis", "outcome"),
    ("synthesis", "model_calls"),
    ("synthesis", "input_tokens"),
    ("synthesis", "output_tokens"),
    ("synthesis", "cached_input_tokens"),
    ("synthesis", "dropped_citations"),
    ("adversarial", "provider"),
    ("adversarial", "model"),
    ("adversarial", "objections"),
    ("adversarial", "high_severity_objections"),
    ("adversarial", "unrebutted_high_severity"),
    ("adversarial", "unexplained_signal_templates"),
    ("adversarial", "unexplained_chronic_templates"),
    ("adversarial", "objections_rebutted"),
    ("adversarial", "outcome"),
    ("adversarial", "model_calls"),
    ("adversarial", "input_tokens"),
    ("adversarial", "output_tokens"),
    ("adversarial", "cached_input_tokens"),
    ("adversarial", "rebuttal_model"),
}


def test_declared_names_match_the_frozen_list() -> None:
    """Renaming a metric must be a deliberate act, not a silent one."""
    assert {m.key for m in ALL_METRICS} == EXPECTED_METRIC_KEYS


def test_no_duplicate_declarations() -> None:
    keys = [m.key for m in ALL_METRICS]
    assert len(keys) == len(set(keys))


def test_load_bearing_metrics_are_the_minority() -> None:
    """Most of the vocabulary is display-only; only a handful drive behaviour.

    The exact count is deliberately not pinned. Nothing in production reads `load_bearing`,
    so a fixed number would only catch edits to the declarations. What matters is the shape:
    at least one metric is acted on, and acting on a metric stays the exception.
    """
    load_bearing = [m for m in ALL_METRICS if m.load_bearing]
    assert 0 < len(load_bearing) < len(ALL_METRICS) / 2


def test_thresholds_only_on_load_bearing_metrics() -> None:
    """A cutoff on a metric nobody reads would be a threshold that cannot fire."""
    for metric in ALL_METRICS:
        if metric.threshold is not None or metric.trigger_values:
            assert metric.load_bearing, f"{metric} has a trigger but is not load-bearing"


# --------------------------------------------------------------- the family


def test_family_members_match_the_entity_order() -> None:
    """The family exists to mirror the redaction entities; drift would leave a metric unwritable."""
    assert REDACTED_BY_ENTITY.members == ENTITY_ORDER


def test_family_member_builds_the_expected_name() -> None:
    assert REDACTED_BY_ENTITY.member("email").key == ("redaction", "redacted_email")


def test_family_rejects_an_unknown_member() -> None:
    """A typo should fail at the call, not write a row nobody will ever read."""
    with pytest.raises(ValueError, match="has no member"):
        REDACTED_BY_ENTITY.member("eyeball_scan")


# --------------------------------------------------------------- typed reads


def _rows(*entries: tuple[Metric, object, float | None]) -> list[dict[str, object]]:
    return [
        {"stage": m.stage, "metric": m.name, "value": str(v), "value_num": n} for m, v, n in entries
    ]


def test_absent_metric_reads_as_none() -> None:
    assert MetricView([]).number(TEMPLATING_COVERAGE) is None


def test_zero_is_distinguishable_from_absent() -> None:
    """The whole point of the typed read.

    Every reader used to write `(value_num or 0) > 0`, which collapses a recorded 0.0 into
    the same answer as a metric that was never written. Nothing could report that a stage
    failed to publish at all.
    """
    view = MetricView(_rows((TEMPLATING_COVERAGE, 0.0, 0.0)))
    assert view.number(TEMPLATING_COVERAGE) == 0.0
    assert MetricView([]).number(TEMPLATING_COVERAGE) is None


def test_membership_reflects_presence() -> None:
    view = MetricView(_rows((TEMPLATING_COVERAGE, 1.0, 1.0)))
    assert TEMPLATING_COVERAGE in view
    assert TEMPLATING_REDUCTION_FACTOR not in view


def test_text_reads_the_stored_string() -> None:
    view = MetricView(_rows((TEMPLATING_CALIBRATION_REASON, "because", None)))
    assert view.text(TEMPLATING_CALIBRATION_REASON) == "because"


def test_flag_round_trips_a_bool() -> None:
    """Bools are stored as "True"/"False" text; readers should not compare against that."""
    from mistify.metrics import ANOMALY_SEVERITY_INFORMATIVE

    assert (
        MetricView(_rows((ANOMALY_SEVERITY_INFORMATIVE, False, 0.0))).flag(
            ANOMALY_SEVERITY_INFORMATIVE
        )
        is False
    )
    assert (
        MetricView(_rows((ANOMALY_SEVERITY_INFORMATIVE, True, 1.0))).flag(
            ANOMALY_SEVERITY_INFORMATIVE
        )
        is True
    )
    assert MetricView([]).flag(ANOMALY_SEVERITY_INFORMATIVE) is None


# --------------------------------------------------------------- triggers


def test_absent_metric_never_triggers() -> None:
    assert MetricView([]).triggers(TEMPLATING_COVERAGE) is False


def test_detail_metric_never_triggers_on_its_own() -> None:
    """A calibration reason supplies text once the status has tripped; it has no cutoff."""
    view = MetricView(_rows((TEMPLATING_CALIBRATION_REASON, "anything", None)))
    assert view.triggers(TEMPLATING_CALIBRATION_REASON) is False


def test_total_coverage_loss_triggers() -> None:
    """Coverage 0.0 is the most severe reading there is, and `or 0` would have silenced it."""
    view = MetricView(_rows((TEMPLATING_COVERAGE, 0.0, 0.0)))
    assert view.triggers(TEMPLATING_COVERAGE) is True


def test_full_coverage_does_not_trigger() -> None:
    view = MetricView(_rows((TEMPLATING_COVERAGE, 1.0, 1.0)))
    assert view.triggers(TEMPLATING_COVERAGE) is False


def test_empty_file_reduction_does_not_trigger() -> None:
    """A reduction factor of exactly 0.0 means an empty file, not a badly compressed one."""
    view = MetricView(_rows((TEMPLATING_REDUCTION_FACTOR, 0.0, 0.0)))
    assert view.triggers(TEMPLATING_REDUCTION_FACTOR) is False


def test_weak_reduction_triggers() -> None:
    view = MetricView(_rows((TEMPLATING_REDUCTION_FACTOR, 1.4, 1.4)))
    assert view.triggers(TEMPLATING_REDUCTION_FACTOR) is True


def test_strong_reduction_does_not_trigger() -> None:
    view = MetricView(_rows((TEMPLATING_REDUCTION_FACTOR, 549.6, 549.6)))
    assert view.triggers(TEMPLATING_REDUCTION_FACTOR) is False


def test_string_trigger_matches_on_value() -> None:
    from mistify.metrics import REDACTION_MODE

    assert MetricView(_rows((REDACTION_MODE, "off", None))).triggers(REDACTION_MODE) is True
    assert MetricView(_rows((REDACTION_MODE, "strict", None))).triggers(REDACTION_MODE) is False


def test_floor_defaults_to_negative_infinity() -> None:
    """Only the two-sided case sets a floor; everything else compares against the threshold."""
    assert TEMPLATING_COVERAGE.floor == -math.inf
    assert TEMPLATING_REDUCTION_FACTOR.floor == 0.0


# --------------------------------------------------------------- stage returns


def test_as_rows_flattens_declared_metrics() -> None:
    """The shape a pipeline stage hands back rather than writing mid-computation."""
    assert as_rows([(TEMPLATING_COVERAGE, 1.0), (TEMPLATING_REDUCTION_FACTOR, 549.6)]) == [
        ("templating", "template_coverage", 1.0),
        ("templating", "reduction_factor", 549.6),
    ]


def test_as_rows_of_nothing_is_empty() -> None:
    assert as_rows([]) == []


# ------------------------------------------------------------- token accounting


def _token_rows(stage: str, **counts: int) -> list[dict[str, object]]:
    return [
        {"stage": stage, "metric": name, "value": str(value), "value_num": value}
        for name, value in counts.items()
    ]


def test_token_usage_groups_by_the_stage_that_spent_them() -> None:
    """A run total that lumped two stages together could not say which model cost what."""
    rows = _token_rows("investigate", input_tokens=1000, output_tokens=200)
    rows += _token_rows("adversarial", input_tokens=300, output_tokens=50)

    stages = {s.stage: s for s in token_usage(rows)}

    assert stages["investigate"].total_tokens == 1200
    assert stages["adversarial"].total_tokens == 350


def test_the_total_spans_every_stage_that_called_a_model() -> None:
    """The adversarial pass is a second model on a second bill; omitting it understates the run."""
    rows = _token_rows("investigate", input_tokens=1000, output_tokens=200)
    rows += _token_rows("adversarial", input_tokens=300, output_tokens=50)

    assert total_tokens(token_usage(rows)).total_tokens == 1550


def test_cached_tokens_are_not_added_on_top_of_input() -> None:
    """`cached_input_tokens` is a subset of `input_tokens` -- see `llm.base.Usage`.

    Counting it as a fourth bucket would inflate every cached run by exactly the tokens the
    cache saved, which is the wrong direction to be wrong in.
    """
    rows = _token_rows("investigate", input_tokens=1000, cached_input_tokens=900, output_tokens=100)

    stage = token_usage(rows)[0]

    assert stage.total_tokens == 1100
    assert stage.cached_share == pytest.approx(0.9)


def test_a_stage_that_reported_nothing_is_absent_rather_than_zero() -> None:
    """Absent and zero are different claims, the same distinction `MetricView` draws."""
    rows = _token_rows("investigate", input_tokens=10, output_tokens=2)

    assert [s.stage for s in token_usage(rows)] == ["investigate"]


def test_a_stage_that_reported_zero_is_present() -> None:
    """Control for the test above, which would also pass if token_usage returned nothing ever.

    A pass that made no model call records zeros, and those zeros are a measurement.
    """
    rows = _token_rows("adversarial", input_tokens=0, output_tokens=0)

    stages = token_usage(rows)

    assert [s.stage for s in stages] == ["adversarial"]
    assert stages[0].total_tokens == 0


def test_token_usage_follows_the_declarations_not_a_hardcoded_list() -> None:
    """Every declared token metric is one of the three roles, and every model-calling stage
    declares all three. A stage that declared only two would silently under-report."""
    by_stage: dict[str, set[str | None]] = {}
    for metric in ALL_METRICS:
        if metric.token_role is not None:
            by_stage.setdefault(metric.stage, set()).add(metric.token_role)

    assert by_stage, "no metric declares a token role"
    for stage, roles in by_stage.items():
        assert roles == {"input", "cached_input", "output"}, f"{stage} declares {roles}"


def test_the_total_of_nothing_is_empty() -> None:
    """A run with no model calls must not produce a confident zero attributed to a stage."""
    assert token_usage([]) == []
    assert total_tokens([]).total_tokens == 0


def test_stages_come_back_in_run_order_not_alphabetical() -> None:
    """The check reads as a footnote to the investigation, so it has to come after it.

    Sorted by name it does not: `adversarial` precedes `investigate`. The order is declaration
    order, which is the order the stages run.
    """
    rows = _token_rows("adversarial", input_tokens=1, output_tokens=1)
    rows += _token_rows("investigate", input_tokens=1, output_tokens=1)

    assert [s.stage for s in token_usage(rows)] == ["investigate", "adversarial"]

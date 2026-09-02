"""Deterministic template anomaly scoring (decision G3)."""

from __future__ import annotations

import pytest

from mistify.agent.skeleton import run_skeleton_investigation
from mistify.eval.fixtures import RED_HERRING_MARKER, ROOT_CAUSE_MARKER
from mistify.scratchpad.anomaly import (
    DEFAULT_WEIGHTS,
    AnomalyComponents,
    score_templates,
    select_signal_templates,
)
from mistify.scratchpad.db import ScratchpadDB

#: Buckets spanning the whole incident, for the pure-scoring tests below.
BUCKETS = 60


def _row(
    template_id: int,
    count: int,
    severity_rank: int,
    max_per_bucket: int | None = None,
) -> dict[str, object]:
    """One template's aggregates. `max_per_bucket` defaults to a uniform spread."""
    return {
        "template_id": template_id,
        "occurrence_count": count,
        "max_severity_rank": severity_rank,
        "max_per_bucket": (
            max_per_bucket if max_per_bucket is not None else max(1, count // BUCKETS)
        ),
    }


# --------------------------------------------------------------- pure scoring


def test_empty_input_scores_nothing() -> None:
    assert score_templates([], total_buckets=BUCKETS) == []


def test_scores_are_bounded() -> None:
    scored = score_templates(
        [_row(1, 5000, 5, max_per_bucket=5000), _row(2, 1, 0)], total_buckets=BUCKETS
    )
    assert all(0.0 <= c.score <= 1.0 for c in scored)


def test_results_are_ranked_descending() -> None:
    scored = score_templates(
        [_row(1, 100, 1), _row(2, 10, 5), _row(3, 500, 2)], total_buckets=BUCKETS
    )
    assert [c.score for c in scored] == sorted((c.score for c in scored), reverse=True)


def test_severity_dominates_between_otherwise_identical_templates() -> None:
    scored = {
        c.template_id: c
        for c in score_templates([_row(1, 100, 5), _row(2, 100, 2)], total_buckets=BUCKETS)
    }
    assert scored[1].score > scored[2].score


def test_burstiness_separates_templates_with_equal_frequency() -> None:
    """Forty events in one minute is a different signal from forty across an hour."""
    bursty = _row(1, 40, 4, max_per_bucket=40)
    spread = _row(2, 40, 4, max_per_bucket=2)
    scored = {c.template_id: c for c in score_templates([bursty, spread], total_buckets=BUCKETS)}
    assert scored[1].burstiness > scored[2].burstiness
    assert scored[1].score > scored[2].score


def test_burstiness_is_measured_against_the_incident_not_the_template() -> None:
    """Regression: dividing by the template's own active buckets inverted this.

    A template firing forty times inside a single bucket occupies that bucket uniformly, so
    measuring concentration against its own footprint scored it as perfectly even -- exactly
    backwards for the most concentrated shape there is.
    """
    scored = score_templates([_row(1, 40, 4, max_per_bucket=40)], total_buckets=BUCKETS)
    assert scored[0].burstiness > 0.9


def test_evenly_spread_template_has_zero_burstiness() -> None:
    scored = score_templates([_row(1, 120, 3, max_per_bucket=2)], total_buckets=BUCKETS)
    assert scored[0].burstiness == 0.0


def test_single_bucket_incident_has_no_burstiness_signal() -> None:
    """With one bucket there is no distribution to be peaked against."""
    scored = score_templates([_row(1, 40, 4, max_per_bucket=40)], total_buckets=1)
    assert scored[0].burstiness == 0.0


def test_rare_template_outscores_common_one_at_equal_severity() -> None:
    scored = {
        c.template_id: c
        for c in score_templates([_row(1, 3, 3), _row(2, 3000, 3)], total_buckets=BUCKETS)
    }
    assert scored[1].rarity > scored[2].rarity


def test_most_common_template_has_zero_rarity() -> None:
    scored = {
        c.template_id: c
        for c in score_templates([_row(1, 1000, 2), _row(2, 10, 2)], total_buckets=BUCKETS)
    }
    assert scored[1].rarity == 0.0


def test_a_zero_component_does_not_zero_the_score() -> None:
    """The reason this is a weighted sum and not a product.

    The most frequent template has rarity exactly 0. Under a product it would score 0 no
    matter how severe or bursty it was, silently hiding the loudest signal in the file.
    """
    scored = score_templates([_row(1, 1000, 5, max_per_bucket=1000)], total_buckets=BUCKETS)
    assert scored[0].rarity == 0.0
    assert scored[0].score > 0.0


def test_components_are_reported_alongside_the_score() -> None:
    """A bare number cannot be argued with; the parts explain why it ranked."""
    component = score_templates([_row(1, 40, 5, max_per_bucket=40)], total_buckets=BUCKETS)[0]
    assert set(component.as_dict()) == {"score", "severity", "burstiness", "rarity"}
    assert component.severity == 1.0


def test_weights_are_normalised_not_required_to_sum_to_one() -> None:
    rows = [_row(1, 40, 5), _row(2, 400, 2)]
    unit = score_templates(rows, total_buckets=BUCKETS, weights=dict(DEFAULT_WEIGHTS))
    scaled = score_templates(
        rows, total_buckets=BUCKETS, weights={k: v * 10 for k, v in DEFAULT_WEIGHTS.items()}
    )
    assert [c.score for c in unit] == pytest.approx([c.score for c in scaled])


def test_weights_can_isolate_a_single_component() -> None:
    rows = [_row(1, 40, 5), _row(2, 40, 1)]
    scored = score_templates(
        rows, total_buckets=BUCKETS, weights={"severity": 1.0, "burstiness": 0.0, "rarity": 0.0}
    )
    by_id = {c.template_id: c for c in scored}
    assert by_id[1].score == pytest.approx(1.0)


def test_zero_total_weight_is_rejected() -> None:
    with pytest.raises(ValueError, match="positive value"):
        score_templates([_row(1, 10, 3)], total_buckets=BUCKETS, weights={"severity": 0.0})


# --------------------------------------------------------------- against the incident


def test_burst_stats_cover_every_template(loaded_db: ScratchpadDB) -> None:
    stats = loaded_db.template_burst_stats()
    assert len(stats) == loaded_db.template_count()
    assert all(row["active_buckets"] > 0 for row in stats)
    assert all(row["max_per_bucket"] > 0 for row in stats)


def test_bucket_count_spans_the_incident(loaded_db: ScratchpadDB) -> None:
    """The synthetic incident covers roughly an hour, so about sixty one-minute buckets."""
    assert 50 <= loaded_db.bucket_count() <= 61


def test_wider_buckets_produce_fewer_of_them(loaded_db: ScratchpadDB) -> None:
    assert loaded_db.bucket_count(bucket_minutes=10) < loaded_db.bucket_count(bucket_minutes=1)


@pytest.mark.parametrize("method", ["template_burst_stats", "bucket_count"])
def test_invalid_bucket_width_is_rejected(loaded_db: ScratchpadDB, method: str) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        getattr(loaded_db, method)(0)


def test_planted_root_cause_ranks_top_five_by_anomaly(loaded_db: ScratchpadDB) -> None:
    """Phase 2 exit criterion.

    Scoring is what gives the Phase 3 adversarial check its only mechanical test -- "was a
    high-scoring template left out of the conclusion?" is meaningless while the column is a
    constant.
    """
    top = loaded_db.top_templates(limit=5, order_by="anomaly_score")
    assert any(ROOT_CAUSE_MARKER in t["pattern"] for t in top)


def test_root_cause_outscores_the_more_frequent_red_herring(loaded_db: ScratchpadDB) -> None:
    templates = loaded_db.top_templates(limit=500, order_by="anomaly_score")
    cause = next(t for t in templates if ROOT_CAUSE_MARKER in t["pattern"])
    herring = next(t for t in templates if RED_HERRING_MARKER in t["pattern"])
    assert herring["occurrence_count"] > cause["occurrence_count"]
    assert cause["anomaly_score"] > herring["anomaly_score"]


def test_routine_noise_scores_below_the_root_cause(loaded_db: ScratchpadDB) -> None:
    templates = loaded_db.top_templates(limit=500, order_by="anomaly_score")
    cause = next(t for t in templates if ROOT_CAUSE_MARKER in t["pattern"])
    heartbeat = next(t for t in templates if "Heartbeat" in t["pattern"])
    assert heartbeat["anomaly_score"] < cause["anomaly_score"]


def test_scores_are_not_all_identical(loaded_db: ScratchpadDB) -> None:
    """Guards against the column silently reverting to a constant."""
    scores = {t["anomaly_score"] for t in loaded_db.top_templates(limit=500)}
    assert len(scores) > 1
    assert scores != {0.0}


def test_anomaly_ordering_agrees_with_the_stored_column(loaded_db: ScratchpadDB) -> None:
    ordered = loaded_db.top_templates(limit=500, order_by="anomaly_score")
    scores = [t["anomaly_score"] for t in ordered]
    assert scores == sorted(scores, reverse=True)


def test_report_surfaces_the_anomaly_column(loaded_db: ScratchpadDB) -> None:
    from mistify.report.generator import generate_report

    run_skeleton_investigation(loaded_db)
    report = generate_report(loaded_db)
    assert "## Templates by anomaly score" in report
    assert "| ID | Anomaly |" in report


# --------------------------------------------------------------- uninformative severity


def test_uninformative_severity_weight_is_redistributed() -> None:
    """On a log with no severity field, every line normalises to the same default.

    The severity term then adds an identical constant to every template — the heaviest
    weight in the formula contributing nothing, silently. Dropping it hands that weight to
    the two components that still discriminate.
    """
    rows = [_row(1, 4, 2, max_per_bucket=4), _row(2, 1000, 2, max_per_bucket=20)]
    with_severity = {c.template_id: c for c in score_templates(rows, total_buckets=BUCKETS)}
    without = {
        c.template_id: c
        for c in score_templates(rows, total_buckets=BUCKETS, severity_informative=False)
    }

    assert with_severity[1].severity == with_severity[2].severity, "the constant term"
    # Separation between needle and noise widens once the constant is removed.
    assert (without[1].score - without[2].score) > (with_severity[1].score - with_severity[2].score)


def test_dropping_severity_leaves_the_components_reported() -> None:
    """The component is still measured and shown, it just stops contributing to the score."""
    scored = score_templates(
        [_row(1, 10, 5, max_per_bucket=10)], total_buckets=BUCKETS, severity_informative=False
    )
    assert scored[0].severity == 1.0


def test_dropping_severity_still_ranks() -> None:
    rows = [_row(1, 5, 0, max_per_bucket=5), _row(2, 900, 0, max_per_bucket=20)]
    scored = score_templates(rows, total_buckets=BUCKETS, severity_informative=False)
    assert scored[0].template_id == 1
    assert scored[0].score > 0.0


# --------------------------------------------------------------- signal selection


def _component(template_id: int, score: float) -> AnomalyComponents:
    return AnomalyComponents(template_id, score, 0.0, 0.0, 0.0)


def test_signal_set_cuts_at_the_largest_gap() -> None:
    """No magic threshold: the distribution decides where unusual stops."""
    scored = [
        _component(1, 0.90),
        _component(2, 0.88),
        _component(3, 0.85),
        _component(4, 0.20),
        _component(5, 0.19),
        _component(6, 0.18),
    ]
    assert [c.template_id for c in select_signal_templates(scored)] == [1, 2, 3]


def test_signal_set_respects_the_lower_bound() -> None:
    """There must always be something for the adversarial check to test against."""
    flat = [_component(i, 0.5 - i * 0.001) for i in range(1, 21)]
    assert len(select_signal_templates(flat, min_templates=3)) >= 3


def test_signal_set_respects_the_upper_bound() -> None:
    flat = [_component(i, 0.5 - i * 0.001) for i in range(1, 41)]
    assert len(select_signal_templates(flat, max_templates=6)) <= 6


def test_signal_set_handles_fewer_templates_than_the_floor() -> None:
    assert [c.template_id for c in select_signal_templates([_component(1, 0.9)])] == [1]


def test_signal_set_of_nothing_is_empty() -> None:
    assert select_signal_templates([]) == []


def test_signal_set_is_ranked_regardless_of_input_order() -> None:
    scrambled = [_component(3, 0.1), _component(1, 0.9), _component(2, 0.5)]
    assert [c.template_id for c in select_signal_templates(scrambled)] == [1, 2, 3]

"""Drain3 threshold calibration and over-clustering detection (architecture §6.1)."""

from __future__ import annotations

import pytest

from mistify.common.models import TemplateSummary
from mistify.templating.calibration import calibrate_sim_th, find_over_merged


def _repetitive(count: int = 400) -> list[str]:
    """Highly structured lines — should compress hard at any sane threshold."""
    return [f"Handled GET /api/v2/item/{i} in {i % 90}ms" for i in range(count)]


def _free_text(count: int = 200) -> list[str]:
    """Lines with no shared shape — nothing to cluster, so compression must fail."""
    return [
        " ".join(f"tok{i}{j}" for j in range(i % 11 + 3)) + f" unique-{i}" for i in range(count)
    ]


# --------------------------------------------------------------- selection


def test_picks_a_threshold_inside_the_band() -> None:
    result = calibrate_sim_th(_repetitive(), [0.3, 0.4, 0.5], 0.002, 0.30)
    assert result.status == "in_band"
    assert result.chosen_sim_th in {0.3, 0.4, 0.5}
    assert len(result.candidates) == 3


def test_prefers_the_highest_in_band_threshold() -> None:
    """Among acceptable options, take the least merging.

    Over-clustering destroys the signal being compressed for; under-clustering only costs
    tokens. When several thresholds are acceptable the conservative one wins.
    """
    result = calibrate_sim_th(_repetitive(), [0.2, 0.4, 0.6], 0.0, 1.0)
    assert result.chosen_sim_th == 0.6


def test_reports_every_candidate_it_measured() -> None:
    result = calibrate_sim_th(_repetitive(), [0.3, 0.5], 0.002, 0.30)
    thresholds = [th for th, _ in result.candidates]
    assert thresholds == [0.3, 0.5]
    assert "0.3=" in result.as_metric()


def test_candidates_are_deduplicated_and_ordered() -> None:
    result = calibrate_sim_th(_repetitive(), [0.5, 0.3, 0.5], 0.002, 0.30)
    assert [th for th, _ in result.candidates] == [0.3, 0.5]


# --------------------------------------------------------------- failure signalling


def test_unclusterable_input_is_flagged_rather_than_silently_accepted() -> None:
    """Free text produces one template per line. That must be visible, not swallowed."""
    result = calibrate_sim_th(_free_text(), [0.3, 0.4, 0.5], 0.002, 0.30)
    assert result.status == "out_of_band"
    assert "under-clustering" in result.reason


def test_out_of_band_still_returns_a_usable_threshold() -> None:
    result = calibrate_sim_th(_free_text(), [0.3, 0.5], 0.002, 0.30)
    assert result.chosen_sim_th in {0.3, 0.5}


def test_over_clustering_is_named_in_the_reason() -> None:
    """A band the input compresses straight past should read as over-clustering."""
    result = calibrate_sim_th(_repetitive(), [0.4], 0.90, 0.99)
    assert result.status == "out_of_band"
    assert "over-clustering" in result.reason


def test_empty_sample_is_skipped_not_guessed() -> None:
    result = calibrate_sim_th([], [0.4, 0.5], 0.002, 0.30)
    assert result.status == "skipped"
    assert result.chosen_sim_th == 0.4


def test_no_candidates_is_an_error() -> None:
    with pytest.raises(ValueError, match="at least one candidate"):
        calibrate_sim_th(_repetitive(), [], 0.002, 0.30)


# --------------------------------------------------------------- over-merge detection


def _summary(template_id: int, mix: dict[str, int]) -> TemplateSummary:
    return TemplateSummary(
        template_id=template_id,
        pattern=f"template {template_id} <*>",
        occurrence_count=sum(mix.values()),
        first_seen="2026-08-30T14:00:00Z",
        last_seen="2026-08-30T14:10:00Z",
        severity_mix=mix,
    )


def test_template_spanning_info_to_fatal_is_flagged() -> None:
    """The failure a good compression ratio cannot see.

    One template holding both routine INFO lines and FATAL ones means two different
    conditions were merged, and one of them is now invisible to the investigation.
    """
    flagged = find_over_merged([_summary(1, {"INFO": 40, "FATAL": 3})])
    assert len(flagged) == 1
    assert flagged[0].template_id == 1
    assert flagged[0].severities == ["INFO", "FATAL"]


def test_single_severity_template_is_not_flagged() -> None:
    assert find_over_merged([_summary(1, {"ERROR": 90})]) == []


def test_adjacent_severities_are_not_flagged() -> None:
    """WARN alongside ERROR is normal for one condition and must not cry wolf."""
    assert find_over_merged([_summary(1, {"WARN": 10, "ERROR": 4})]) == []


def test_span_threshold_is_configurable() -> None:
    summaries = [_summary(1, {"WARN": 10, "ERROR": 4})]
    assert find_over_merged(summaries, min_span=2) != []
    assert find_over_merged(summaries, min_span=3) == []


def test_empty_mix_is_ignored() -> None:
    assert find_over_merged([_summary(1, {})]) == []


def test_multiple_offenders_are_all_returned() -> None:
    flagged = find_over_merged(
        [
            _summary(1, {"INFO": 5, "FATAL": 1}),
            _summary(2, {"ERROR": 9}),
            _summary(3, {"DEBUG": 2, "ERROR": 2}),
        ]
    )
    assert [f.template_id for f in flagged] == [1, 3]

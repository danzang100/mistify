"""Drain3 threshold calibration and over-clustering detection."""

from __future__ import annotations

import pytest

from mistify.common.models import TemplateSummary
from mistify.metrics import TEMPLATING_CALIBRATION_STATUS
from mistify.templating.calibration import (
    CalibrationStatus,
    calibrate_sim_th,
    find_over_merged,
)


def _repetitive(count: int = 400) -> list[str]:
    """Highly structured lines - should compress hard at any sane threshold."""
    return [f"Handled GET /api/v2/item/{i} in {i % 90}ms" for i in range(count)]


def _over_mergeable(count: int = 200) -> list[str]:
    """One shared token and five varying ones.

    Below a similarity threshold of roughly 1/6 these all collapse into a single
    mostly-wildcard template: maximum compression, total loss of the distinctions.
    """
    return [f"event alpha{i} beta{i} gamma{i} delta{i} epsilon{i}" for i in range(count)]


def _free_text(count: int = 200) -> list[str]:
    """Lines with no shared shape - nothing to cluster, so compression must fail."""
    return [
        " ".join(f"tok{i}{j}" for j in range(i % 11 + 3)) + f" unique-{i}" for i in range(count)
    ]


# --------------------------------------------------------------- selection


def test_selects_a_threshold_on_clusterable_input() -> None:
    result = calibrate_sim_th(_repetitive(), [0.3, 0.4, 0.5], 0.002, 0.30)
    assert result.status == CalibrationStatus.SELECTED
    assert result.chosen_sim_th in {0.3, 0.4, 0.5}
    assert len(result.candidates) == 3


def test_prefers_the_threshold_that_collapses_the_most_noise() -> None:
    """The objective is a shorter haystack, not a target ratio.

    The agent's search space is the template list, so among thresholds that did not
    over-merge, the one leaving fewest templates is the one that made its job easiest.
    """
    result = calibrate_sim_th(_repetitive(), [0.2, 0.4, 0.6], 0.0, 1.0)
    counts = {th: ratio for th, ratio in result.candidates}
    assert counts[result.chosen_sim_th] == min(counts.values())


def test_reason_names_the_template_count_not_just_the_ratio() -> None:
    """The number that matters to the agent is how many templates it must read."""
    result = calibrate_sim_th(_repetitive(), [0.3, 0.5], 0.002, 0.30)
    assert "templates at sim_th=" in result.reason


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
    """Free text produces one template per line, leaving the agent the raw haystack."""
    result = calibrate_sim_th(_free_text(), [0.3, 0.4, 0.5], 0.002, 0.30)
    assert result.status == CalibrationStatus.UNDER_CLUSTERED
    assert "little noise could be collapsed" in result.reason


def test_out_of_band_still_returns_a_usable_threshold() -> None:
    result = calibrate_sim_th(_free_text(), [0.3, 0.5], 0.002, 0.30)
    assert result.chosen_sim_th in {0.3, 0.5}


def test_over_merging_input_falls_back_to_the_strictest_threshold() -> None:
    """When every candidate destroys signal, prefer signal over a tidy template list.

    Under-clustering only costs tokens; over-clustering loses the needle, so the fallback is
    the strictest threshold available, flagged loudly rather than quietly accepted.
    """
    result = calibrate_sim_th(_over_mergeable(), [0.05, 0.1, 0.15], 0.002, 0.30)
    assert result.status == CalibrationStatus.SIGNAL_AT_RISK
    assert result.chosen_sim_th == 0.15
    assert "losing signal costs more" in result.reason


def test_best_compression_is_rejected_when_it_destroys_signal() -> None:
    """The heart of the change: compression is not the objective.

    At the loosest threshold these 200 distinct messages collapse into a single
    `event <*> <*> <*> <*> <*>` template - a compression ratio of 0.005, which is the *best*
    score any candidate can post and the worst possible outcome. Selection must reject it in
    favour of the threshold that keeps the messages apart, even though that one compresses
    far worse.
    """
    result = calibrate_sim_th(_over_mergeable(), [0.05, 0.5], 0.0, 1.0)
    ratios = dict(result.candidates)
    assert ratios[0.05] < ratios[0.5], "0.05 should compress harder"
    assert result.chosen_sim_th == 0.5
    assert result.status != CalibrationStatus.SIGNAL_AT_RISK


def test_empty_sample_is_skipped_not_guessed() -> None:
    result = calibrate_sim_th([], [0.4, 0.5], 0.002, 0.30)
    assert result.status == CalibrationStatus.SKIPPED
    assert result.chosen_sim_th == 0.4


def test_no_candidates_is_an_error() -> None:
    with pytest.raises(ValueError, match="at least one candidate"):
        calibrate_sim_th(_repetitive(), [], 0.002, 0.30)


def test_the_statuses_that_warn_match_the_metric_declaration() -> None:
    """Two declarations of "which outcomes are bad" that must not drift apart.

    The report warns on whatever `templating.calibration_status` declares as its trigger
    values, while this module decides which statuses mean the run did not calibrate cleanly.
    They agree today by coincidence; a status added on one side and not the other would
    silently disable the warning, which is the failure the metric vocabulary exists to stop.
    """
    assert CalibrationStatus.warns() == TEMPLATING_CALIBRATION_STATUS.trigger_values


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

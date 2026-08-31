"""Report rendering, health disclosure, and the deterministic citation check."""

from __future__ import annotations

from pathlib import Path

import pytest

from mistify.agent.skeleton import INVESTIGATOR_NAME, run_skeleton_investigation
from mistify.metrics import (
    ANOMALY_NEEDLE_POSITION,
    INGEST_PARSE_ERRORS,
    REDACTION_MODE,
    SCRATCHPAD_ORPHAN_EVENTS,
    TEMPLATING_CALIBRATION_REASON,
    TEMPLATING_CALIBRATION_STATUS,
    TEMPLATING_COVERAGE,
    TEMPLATING_EVICTED,
    TEMPLATING_LARGEST_SHARE,
    TEMPLATING_OVER_MERGED,
    TEMPLATING_OVER_MERGED_IDS,
    TEMPLATING_REDUCTION_FACTOR,
    MetricView,
)
from mistify.report.generator import (
    TOP_TEMPLATE_LIMIT,
    generate_report,
    verify_citations,
    write_report,
)
from mistify.scratchpad.db import ScratchpadDB
from mistify.templating.calibration import CalibrationStatus
from tests.fixtures.synthetic_incident import PLANTED_API_KEY, PLANTED_EMAILS, ROOT_CAUSE_MARKER

TRUNCATED_LIMIT = 3


def _template_rows(report: str) -> list[str]:
    """The data rows of the templates table, without its header or rule."""
    section = report.split("## Templates by anomaly score")[1].split("## Pipeline health")[0]
    return [
        line
        for line in section.splitlines()
        if line.startswith("|") and not line.startswith(("| ID |", "|---"))
    ]


def test_report_names_the_planted_root_cause(loaded_db: ScratchpadDB) -> None:
    run_skeleton_investigation(loaded_db)
    report = generate_report(loaded_db)
    assert ROOT_CAUSE_MARKER in report


def test_report_declares_which_investigator_produced_it(loaded_db: ScratchpadDB) -> None:
    """A skeleton result presented as a finding is exactly the silent failure to avoid."""
    run_skeleton_investigation(loaded_db)
    report = generate_report(loaded_db)
    assert INVESTIGATOR_NAME in report
    assert "not a root-cause conclusion" in report


def test_report_includes_the_health_block(loaded_db: ScratchpadDB) -> None:
    run_skeleton_investigation(loaded_db)
    report = generate_report(loaded_db)
    assert "## Pipeline health" in report
    assert "compression_ratio" in report
    assert "redacted_total" in report


def test_report_includes_the_investigation_trail(loaded_db: ScratchpadDB) -> None:
    run_skeleton_investigation(loaded_db)
    report = generate_report(loaded_db)
    assert "## Investigation trail" in report
    assert "top_templates" in report


def test_report_resolves_citations_to_real_lines(loaded_db: ScratchpadDB) -> None:
    result = run_skeleton_investigation(loaded_db)
    report = generate_report(loaded_db)
    for event_id in result.notes[0].evidence["log_event_ids"]:
        assert f"| {event_id} |" in report


def test_report_contains_no_unredacted_secrets(loaded_db: ScratchpadDB) -> None:
    run_skeleton_investigation(loaded_db)
    report = generate_report(loaded_db)
    for secret in (*PLANTED_EMAILS, PLANTED_API_KEY):
        assert secret not in report


def test_report_renders_without_an_investigation(loaded_db: ScratchpadDB) -> None:
    report = generate_report(loaded_db)
    assert "No hypothesis was recorded" in report


def test_write_report_creates_the_file(loaded_db: ScratchpadDB, tmp_path: Path) -> None:
    run_skeleton_investigation(loaded_db)
    path = write_report(loaded_db, tmp_path / "out", "test-incident")
    assert path.exists()
    assert path.name == "test-incident.md"
    assert ROOT_CAUSE_MARKER in path.read_text(encoding="utf-8")


# --------------------------------------------------------------- decision G8


def test_citation_check_passes_on_real_evidence(loaded_db: ScratchpadDB) -> None:
    run_skeleton_investigation(loaded_db)
    cited, warnings = verify_citations(loaded_db)
    assert warnings == []
    assert any(rows for rows in cited.values())


def test_citation_check_flags_a_fabricated_event_id(loaded_db: ScratchpadDB) -> None:
    """The deterministic half of G8: cited ids must resolve to rows that exist."""
    loaded_db.write_note(
        1, "invented claim", {"log_event_ids": [10**9], "template_ids": []}, "high"
    )
    _, warnings = verify_citations(loaded_db)
    assert any("log events that do not exist" in w for w in warnings)


def test_citation_check_flags_a_fabricated_template_id(loaded_db: ScratchpadDB) -> None:
    loaded_db.write_note(1, "invented claim", {"template_ids": [10**9]}, "high")
    _, warnings = verify_citations(loaded_db)
    assert any("templates that do not exist" in w for w in warnings)


def test_fabricated_citations_surface_in_the_report(loaded_db: ScratchpadDB) -> None:
    loaded_db.write_note(1, "invented claim", {"log_event_ids": [10**9]}, "high")
    report = generate_report(loaded_db)
    assert "### Warnings" in report
    assert "do not exist" in report


# --------------------------------------------------------------- health warnings


def test_disabled_redaction_is_called_out(loaded_db: ScratchpadDB) -> None:
    loaded_db.record(REDACTION_MODE, "off")
    assert "Redaction was disabled" in generate_report(loaded_db)


def test_parse_errors_are_called_out(loaded_db: ScratchpadDB) -> None:
    loaded_db.record(INGEST_PARSE_ERRORS, 12)
    assert "12 line(s) failed to parse" in generate_report(loaded_db)


def test_weak_reduction_is_called_out(loaded_db: ScratchpadDB) -> None:
    """Under-clustering makes template ranking unreliable, so the report must say so.

    Stated as lines per template rather than as a ratio: "reduced 1.4x" is the number that
    tells a reader how much smaller the haystack actually got.
    """
    loaded_db.record(TEMPLATING_REDUCTION_FACTOR, 1.4)
    assert "reduced the file only 1.4x" in generate_report(loaded_db)


def test_orphan_events_are_called_out(loaded_db: ScratchpadDB) -> None:
    loaded_db.record(SCRATCHPAD_ORPHAN_EVENTS, 5)
    assert "reference a template that does not exist" in generate_report(loaded_db)


def test_clean_run_has_no_warnings_section(loaded_db: ScratchpadDB) -> None:
    run_skeleton_investigation(loaded_db)
    assert "### Warnings" not in generate_report(loaded_db)


# --------------------------------------------------------------- Phase 2 health warnings


def test_signal_at_risk_calibration_is_called_out(loaded_db: ScratchpadDB) -> None:
    """A pathological file must produce a flagged report, not a confident-looking one.

    `signal_at_risk` means every candidate threshold over-merged, so the run fell back to the
    strictest one and kept the tokens rather than risk collapsing the needle.
    """
    loaded_db.record(TEMPLATING_CALIBRATION_STATUS, CalibrationStatus.SIGNAL_AT_RISK)
    loaded_db.record(
        TEMPLATING_CALIBRATION_REASON, "every candidate produced a template spanning 3+"
    )
    report = generate_report(loaded_db)
    assert "could not find a threshold that preserves signal" in report
    assert "every candidate produced a template spanning 3+" in report


def test_under_clustered_calibration_is_called_out(loaded_db: ScratchpadDB) -> None:
    """The other failure direction: nothing collapsed, so the agent still has the haystack."""
    loaded_db.record(TEMPLATING_CALIBRATION_STATUS, CalibrationStatus.UNDER_CLUSTERED)
    loaded_db.record(
        TEMPLATING_CALIBRATION_REASON, "best candidate 0.5 still leaves 1940 templates"
    )
    report = generate_report(loaded_db)
    assert "could not collapse much noise" in report
    assert "still leaves 1940 templates" in report


def test_selected_calibration_produces_no_warning(loaded_db: ScratchpadDB) -> None:
    loaded_db.record(TEMPLATING_CALIBRATION_STATUS, CalibrationStatus.SELECTED)
    report = generate_report(loaded_db)
    assert "Templating calibration" not in report


def test_over_merged_templates_are_called_out(loaded_db: ScratchpadDB) -> None:
    """Over-clustering is invisible in the compression ratio, so it needs its own line."""
    loaded_db.record(TEMPLATING_OVER_MERGED, 2)
    loaded_db.record(TEMPLATING_OVER_MERGED_IDS, "4,7")
    report = generate_report(loaded_db)
    assert "span a wide severity range" in report
    assert "templates 4,7" in report


def test_clean_run_reports_no_over_merging(loaded_db: ScratchpadDB) -> None:
    run_skeleton_investigation(loaded_db)
    assert "span a wide severity range" not in generate_report(loaded_db)


# --------------------------------------------------------------- signal health warnings


def test_lost_template_coverage_is_called_out(loaded_db: ScratchpadDB) -> None:
    """Coverage is the invariant, and it is the failure the compression ratio hides.

    An event whose template was dropped cannot be found through template search at all, so
    this is the one health metric that invalidates the conclusion rather than qualifying it.
    """
    loaded_db.record(TEMPLATING_COVERAGE, 0.82)
    report = generate_report(loaded_db)
    assert "CRITICAL" in report
    assert "18.0% of events have no reachable template" in report
    assert "partial view of the incident" in report


def test_full_coverage_produces_no_warning(loaded_db: ScratchpadDB) -> None:
    loaded_db.record(TEMPLATING_COVERAGE, 1.0)
    assert "no reachable template" not in generate_report(loaded_db)


def test_evicted_templates_are_called_out(loaded_db: ScratchpadDB) -> None:
    """Eviction splits one condition across several ids, which understates its counts."""
    loaded_db.record(TEMPLATING_EVICTED, 12)
    report = generate_report(loaded_db)
    assert "12 template(s) were evicted" in report
    assert "drain3.max_clusters" in report


def test_dominant_template_is_called_out(loaded_db: ScratchpadDB) -> None:
    """Compression can succeed and still leave one noisy shape owning the whole file."""
    loaded_db.record(TEMPLATING_LARGEST_SHARE, 0.71)
    report = generate_report(loaded_db)
    assert "One template accounts for 71% of all events" in report


def test_buried_severe_template_is_called_out(loaded_db: ScratchpadDB) -> None:
    """The needle question asked directly: does the worst template surface near the top?"""
    loaded_db.record(ANOMALY_NEEDLE_POSITION, 9)
    report = generate_report(loaded_db)
    assert "The most severe template ranks #9" in report
    assert "not surfacing near the top" in report


def test_clean_run_has_no_signal_warnings(loaded_db: ScratchpadDB) -> None:
    """The synthetic incident is healthy, so none of the signal warnings may fire on it."""
    run_skeleton_investigation(loaded_db)
    report = generate_report(loaded_db)
    for phrase in (
        "no reachable template",
        "were evicted from the matching tree",
        "reduced the file only",
        "dominant noisy template",
        "The most severe template ranks",
    ):
        assert phrase not in report


# --------------------------------------------------------------- absent versus zero


def test_a_recorded_zero_is_not_a_missing_metric(db: ScratchpadDB) -> None:
    """The distinction the old `(value_num or 0)` reads could not express.

    A stage that published 0.0 and a stage that published nothing at all used to be the same
    answer to every reader, which meant "this stage never reported" was unsayable.
    """
    db.record(TEMPLATING_REDUCTION_FACTOR, 0.0)
    view = MetricView(db.metrics())
    assert view.number(TEMPLATING_REDUCTION_FACTOR) == 0.0
    assert view.number(TEMPLATING_COVERAGE) is None


def test_missing_coverage_does_not_warn(db: ScratchpadDB) -> None:
    """A metric nobody recorded is not evidence of lost coverage."""
    assert MetricView(db.metrics()).triggers(TEMPLATING_COVERAGE) is False


def test_an_empty_file_is_not_reported_as_weak_reduction(loaded_db: ScratchpadDB) -> None:
    """Reduction of exactly 0.0 means there was nothing to template, not bad templating.

    This is the metric's floor doing its job: the warning is about a file with too little
    repeated structure, and an empty file has no structure to judge.
    """
    loaded_db.record(TEMPLATING_REDUCTION_FACTOR, 0.0)
    assert "reduced the file only" not in generate_report(loaded_db)

    loaded_db.record(TEMPLATING_REDUCTION_FACTOR, 1.4)
    assert "reduced the file only 1.4x" in generate_report(loaded_db)


def test_zero_coverage_is_the_loudest_warning(loaded_db: ScratchpadDB) -> None:
    """Coverage 0.0 means nothing is findable, so it must warn hardest, not fall silent.

    Reading this metric as `value or 1.0` would have inverted its meaning exactly here: the
    total failure would have looked like a perfectly covered run.
    """
    loaded_db.record(TEMPLATING_COVERAGE, 0.0)
    report = generate_report(loaded_db)
    assert "CRITICAL" in report
    assert "100.0% of events have no reachable template" in report


# --------------------------------------------------------------- template list truncation


def test_truncated_template_list_states_how_many_of_how_many(
    loaded_db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A partial ranking read as a complete one is a silent failure, so it must say so.

    The synthetic incident has fewer templates than the shipped limit, so truncation is forced
    by lowering the limit rather than by inventing a second fixture.
    """
    monkeypatch.setattr("mistify.report.generator.TOP_TEMPLATE_LIMIT", TRUNCATED_LIMIT)
    total = loaded_db.template_count()
    assert total > TRUNCATED_LIMIT

    report = generate_report(loaded_db)
    assert f"Showing the {TRUNCATED_LIMIT} highest-scoring templates of {total}." in report


def test_untruncated_template_list_says_nothing(loaded_db: ScratchpadDB) -> None:
    """The common case is a complete list, and a complete list needs no disclaimer."""
    assert loaded_db.template_count() <= TOP_TEMPLATE_LIMIT
    assert "highest-scoring templates of" not in generate_report(loaded_db)


def test_the_number_of_rows_shown_matches_the_limit(
    loaded_db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stated count is the rendered count, not a number the template asserts on its own."""
    monkeypatch.setattr("mistify.report.generator.TOP_TEMPLATE_LIMIT", TRUNCATED_LIMIT)
    assert len(_template_rows(generate_report(loaded_db))) == TRUNCATED_LIMIT


def test_every_template_is_listed_when_they_all_fit(loaded_db: ScratchpadDB) -> None:
    assert len(_template_rows(generate_report(loaded_db))) == loaded_db.template_count()

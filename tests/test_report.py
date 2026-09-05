"""Report rendering, health disclosure, and the deterministic citation check."""

from __future__ import annotations

from pathlib import Path

import pytest

from mistify.agent.skeleton import INVESTIGATOR_NAME, run_skeleton_investigation
from mistify.common.models import NOTE_ROLE, ROLE_ACCOUNTING, ROLE_FINDING
from mistify.eval.fixtures import (
    PLANTED_API_KEY,
    PLANTED_EMAILS,
    RED_HERRING_MARKER,
    ROOT_CAUSE_MARKER,
)
from mistify.findings import rank_notes
from mistify.metrics import (
    ANOMALY_NEEDLE_POSITION,
    INGEST_PARSE_ERRORS,
    REDACTION_MODE,
    REDACTION_VAULT,
    SCRATCHPAD_ORPHAN_EVENTS,
    TEMPLATING_CALIBRATION_REASON,
    TEMPLATING_CALIBRATION_STATUS,
    TEMPLATING_COVERAGE,
    TEMPLATING_EVICTED,
    TEMPLATING_LARGEST_SHARE,
    TEMPLATING_OVER_MERGED,
    TEMPLATING_OVER_MERGED_IDS,
    TEMPLATING_REDUCTION_FACTOR,
)
from mistify.report.generator import (
    TOP_TEMPLATE_LIMIT,
    generate_report,
    verify_citations,
    write_report,
)
from mistify.scratchpad.db import ScratchpadDB
from mistify.templating.calibration import CalibrationStatus

TRUNCATED_LIMIT = 3


def _template_rows(report: str) -> list[str]:
    """The data rows of the templates table, without its header or rule."""
    section = report.split("## Templates by anomaly score")[1].split("# Appendix")[0]
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
    """Health metrics survive the appendix split -- both halves of it."""
    run_skeleton_investigation(loaded_db)
    report = generate_report(loaded_db)
    assert "## Run signals" in report
    assert "## Pipeline configuration and counters" in report
    assert "compression_ratio" in report
    assert "redacted_total" in report


def test_the_metrics_a_reader_acts_on_are_separated_from_the_knobs(
    loaded_db: ScratchpadDB,
) -> None:
    """`template_coverage` invalidates the report when it slips; `depth` is a tuning choice.

    Alphabetised into one table they sat next to each other, which gave a knob the same weight
    as an invariant.
    """
    run_skeleton_investigation(loaded_db)
    signals, detail = generate_report(loaded_db).split("## Pipeline configuration and counters")

    assert "template_coverage" in signals
    assert "| templating | depth |" not in signals
    assert "| templating | depth |" in detail


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
    assert "## Read this first" in report
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


# --------------------------------------------------------------- absent versus zero


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


# ------------------------------------------------ the verdict and what it leads with


def _ranked_template_ids(db: ScratchpadDB) -> list[int]:
    """Template ids most anomalous first, which is the ranking the headline is chosen on."""
    return [int(t["template_id"]) for t in db.top_templates(limit=99, order_by="anomaly_score")]


def test_the_leading_issue_is_the_one_explaining_the_most_anomalous_template(
    loaded_db: ScratchpadDB,
) -> None:
    """Not the first note written and not the last one.

    The loop is told to conclude last and does not reliably comply; the final note is often a
    deliberate aside. The anomaly ranking is model-free, so ordering on it makes the overview
    stable across runs that reasoned differently but landed on the same template.
    """
    ranked = _ranked_template_ids(loaded_db)
    loaded_db.write_note(1, "an early narrow guess", {"template_ids": [ranked[-1]]}, "high")
    loaded_db.write_note(2, "the real conclusion", {"template_ids": [ranked[0]]}, "high")
    loaded_db.write_note(3, "a separate pre-existing issue", {"template_ids": [ranked[-2]]}, "high")

    overview = generate_report(loaded_db).split("## What was found")[1].split("## ")[0]

    assert overview.index("the real conclusion") < overview.index("an early narrow guess")
    assert overview.index("the real conclusion") < overview.index("a separate pre-existing issue")


def test_every_issue_appears_in_the_overview_not_just_the_leading_one(
    loaded_db: ScratchpadDB,
) -> None:
    """An investigation that found two unrelated problems has found two problems.

    The overview used to have room for exactly one, which silently dropped the other -- the
    case the loop is explicitly prompted to look for.
    """
    ranked = _ranked_template_ids(loaded_db)
    loaded_db.write_note(1, "the real conclusion", {"template_ids": [ranked[0]]}, "high")
    loaded_db.write_note(2, "a separate pre-existing issue", {"template_ids": [ranked[-2]]}, "high")

    overview = generate_report(loaded_db).split("## What was found")[1].split("## ")[0]

    assert "the real conclusion" in overview
    assert "a separate pre-existing issue" in overview
    assert "not necessarily one incident" in overview


def test_one_issue_is_not_described_as_possibly_several(loaded_db: ScratchpadDB) -> None:
    """Control for the caveat above: it fires on plurality, it is not boilerplate."""
    ranked = _ranked_template_ids(loaded_db)
    loaded_db.write_note(1, "the only note", {"template_ids": [ranked[-1]]}, "low")

    overview = generate_report(loaded_db).split("## What was found")[1].split("## ")[0]

    assert "the only note" in overview
    assert "not necessarily one incident" not in overview


def test_an_issue_resting_only_on_chronic_templates_is_marked_background(
    loaded_db: ScratchpadDB,
) -> None:
    """A note about something that was already happening is not a finding about this incident.

    Ranked purely on anomaly score it can outrank the outage, which is how a background error
    stream ends up presented as the headline.
    """
    run_skeleton_investigation(loaded_db)
    glance = generate_report(loaded_db)
    chronic_ids = [
        line.split("|")[1].strip()
        for line in glance.splitlines()
        if line.startswith("|") and line.rstrip().endswith("chronic |")
    ]
    assert chronic_ids, "the fixture is expected to contain a chronic template"

    loaded_db.write_note(9, "background chatter", {"template_ids": [int(chronic_ids[0])]}, "high")

    overview = generate_report(loaded_db).split("## What was found")[1].split("## ")[0]
    background_line = [
        line
        for line in overview.splitlines()
        if "background chatter" in line or "background**" in line
    ]

    assert "**background**" in overview
    assert background_line


def test_every_note_still_appears_under_findings(loaded_db: ScratchpadDB) -> None:
    """Choosing a headline decides reading order, not what the report is allowed to say."""
    ranked = _ranked_template_ids(loaded_db)
    loaded_db.write_note(1, "an early narrow guess", {"template_ids": [ranked[-1]]}, "high")
    loaded_db.write_note(2, "the real conclusion", {"template_ids": [ranked[0]]}, "high")

    findings = generate_report(loaded_db).split("## Findings")[1].split("## The challenge")[0]

    assert "an early narrow guess" in findings
    assert "the real conclusion" in findings


# -------------------------------------------------------- the incident at a glance


def test_the_incident_window_is_narrower_than_the_log_window(loaded_db: ScratchpadDB) -> None:
    """The header's window is where the file starts and stops.

    Reporting that as the incident duration overstates it by however much quiet log surrounds
    the event -- an hour of heartbeats around a six-minute outage reads as an hour-long outage.
    """
    run_skeleton_investigation(loaded_db)
    glance = (
        generate_report(loaded_db).split("## The incident at a glance")[1].split("## Findings")[0]
    )

    file_first, file_last = loaded_db.time_bounds()
    window = glance.split("### Signal templates")[0]

    assert "Incident window" in window
    assert file_first not in window
    assert file_last not in window


def test_a_chronic_template_is_kept_out_of_the_incident_window(loaded_db: ScratchpadDB) -> None:
    """The failure the first version of this section had.

    One signal template active across the whole log dragged the union back out to the file's
    own bounds, so a six-minute outage was reported as sixty minutes. The window is measured
    across the templates the verdict cites; chronic ones are listed separately and labelled.
    """
    run_skeleton_investigation(loaded_db)
    glance = (
        generate_report(loaded_db).split("## The incident at a glance")[1].split("## Findings")[0]
    )

    log_minutes = 60.0
    window_minutes = float(
        glance.split("| Duration |")[1].split("min")[0].strip().lstrip("| ").strip()
    )

    assert window_minutes < log_minutes
    assert "chronic" in glance


def test_every_signal_template_is_timed_individually(loaded_db: ScratchpadDB) -> None:
    """Control for the window above: narrowing it must not hide the templates left out of it."""
    run_skeleton_investigation(loaded_db)
    glance = (
        generate_report(loaded_db).split("## The incident at a glance")[1].split("## Findings")[0]
    )

    from mistify.metrics import ANOMALY_SIGNAL_TEMPLATE_IDS, MetricView

    raw = MetricView(loaded_db.metrics()).text(ANOMALY_SIGNAL_TEMPLATE_IDS) or ""
    signal_ids = [part for part in raw.split(",") if part.strip()]

    assert signal_ids
    spans = glance.split("### Signal templates")[1]
    for template_id in signal_ids:
        assert f"| {template_id} |" in spans


def test_the_glance_counts_severities_and_sources_from_the_events(
    loaded_db: ScratchpadDB,
) -> None:
    """Computed, not narrated: the same numbers whatever route the investigation took."""
    run_skeleton_investigation(loaded_db)
    glance = (
        generate_report(loaded_db).split("## The incident at a glance")[1].split("## Findings")[0]
    )

    counts = loaded_db.severity_counts()
    assert "| FATAL | {:,} |".format(counts["FATAL"]) in glance
    for row in loaded_db.source_activity():
        assert str(row["source"]) in glance


def test_placeholders_are_explained_when_redaction_ran(loaded_db: ScratchpadDB) -> None:
    """A responder seeing `[API_KEY:700b]` needs to know what it is and whether it resolves."""
    report = generate_report(loaded_db)

    assert "redacted placeholders" in report
    assert "correlated across lines" in report


def test_no_reveal_pointer_when_no_vault_was_kept(loaded_db: ScratchpadDB) -> None:
    """`reveal` reads the vault, and the vault is off by default.

    Printing the command on a run that kept nothing sends the reader to a failure and teaches
    them the report's advice is not worth following.
    """
    loaded_db.record(REDACTION_VAULT, False)

    report = generate_report(loaded_db)

    assert "mistify reveal" not in report
    assert "kept no vault" in report


def test_the_reveal_pointer_appears_when_a_vault_was_kept(loaded_db: ScratchpadDB) -> None:
    """Control for the test above: the pointer is suppressed by the vault being absent, not
    removed outright."""
    loaded_db.record(REDACTION_VAULT, True)

    assert "mistify reveal" in generate_report(loaded_db)


def test_nothing_about_placeholders_when_redaction_was_off(loaded_db: ScratchpadDB) -> None:
    """No placeholders exist to explain."""
    loaded_db.record(REDACTION_MODE, "off")

    assert "redacted placeholders" not in generate_report(loaded_db)


def test_the_machinery_is_below_the_incident(loaded_db: ScratchpadDB) -> None:
    """Section order is the point of the restructure: act first, audit second.

    The warnings used to sit under sixty rows of pipeline internals, which is where a reader
    stops looking.
    """
    run_skeleton_investigation(loaded_db)
    report = generate_report(loaded_db)

    assert report.index("## What was found") < report.index("## The incident at a glance")
    assert report.index("## The incident at a glance") < report.index("## Findings")
    assert report.index("## Findings") < report.index("# Appendix")
    assert report.index("# Appendix") < report.index("## Token usage")
    assert report.index("# Appendix") < report.index("## Investigation trail")


def _template_for(db: ScratchpadDB, marker: str) -> int:
    """The template whose pattern carries `marker`. The fixture plants exactly one."""
    rows = db.run_readonly_sql(
        "SELECT template_id, pattern FROM templates ORDER BY template_id", max_rows=5000
    )
    matched = [int(r["template_id"]) for r in rows if marker in str(r["pattern"])]
    assert matched, f"no template carries {marker!r}"
    return matched[0]


def _note(step: int, template_ids: list[int], role: str, confidence: str = "high") -> dict:
    return {
        "note": f"note at step {step}",
        "step": step,
        "confidence": confidence,
        "evidence": {"template_ids": template_ids, NOTE_ROLE: role},
    }


def test_a_note_answering_a_nudge_does_not_lead_over_a_finding(
    loaded_db: ScratchpadDB,
) -> None:
    """The customer-log shape, in miniature.

    On a 568 MB production log the run's third note dismissed three templates scoring 0.885
    with two occurrences each, and led the report -- above the note naming a root cause that
    occurred 889 times and scored 0.798. Ranking a nudge answer by the scores of the templates
    the nudge named asks the ranking to grade its own homework.
    """
    herring = _template_for(loaded_db, RED_HERRING_MARKER)
    root = _template_for(loaded_db, ROOT_CAUSE_MARKER)
    scores = {herring: 0.99, root: 0.10}

    finding = _note(step=5, template_ids=[root], role=ROLE_FINDING)
    accounting = _note(step=9, template_ids=[herring], role=ROLE_ACCOUNTING)

    ranked = rank_notes([accounting, finding], scores)

    assert ranked[0] is finding
    assert ranked[-1] is accounting


def test_the_loudest_template_still_does_not_carry_the_report(
    loaded_db: ScratchpadDB,
) -> None:
    """The control that killed every volume-weighted alternative.

    The herring fires 350 times to the root cause's 40, so ranking findings by how many events
    they cite -- or by score times volume, or by score damped with volume -- leads with the
    herring. Both notes here are findings, so the role term is constant and cannot help: this
    is the case that has to be won on the anomaly score alone, and it is why the role term was
    added *beside* that score rather than in place of it.
    """
    herring = _template_for(loaded_db, RED_HERRING_MARKER)
    root = _template_for(loaded_db, ROOT_CAUSE_MARKER)
    scores = {
        int(r["template_id"]): float(r["anomaly_score"])
        for r in loaded_db.run_readonly_sql(
            "SELECT template_id, anomaly_score FROM templates", max_rows=5000
        )
    }
    assert scores[root] > scores[herring], "fixture no longer discriminates"

    loud = _note(step=5, template_ids=[herring], role=ROLE_FINDING)
    quiet = _note(step=7, template_ids=[root], role=ROLE_FINDING)

    assert rank_notes([loud, quiet], scores)[0] is quiet


def test_notes_without_a_role_rank_exactly_as_they_did(loaded_db: ScratchpadDB) -> None:
    """Every note written before the role existed. The default must not reorder them."""
    herring = _template_for(loaded_db, RED_HERRING_MARKER)
    root = _template_for(loaded_db, ROOT_CAUSE_MARKER)
    scores = {herring: 0.20, root: 0.90}

    low = {"note": "a", "step": 1, "confidence": "high", "evidence": {"template_ids": [herring]}}
    high = {"note": "b", "step": 2, "confidence": "high", "evidence": {"template_ids": [root]}}

    assert rank_notes([low, high], scores)[0] is high

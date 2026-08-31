"""Report rendering, health disclosure, and the deterministic citation check."""

from __future__ import annotations

from pathlib import Path

from mistify.agent.skeleton import INVESTIGATOR_NAME, run_skeleton_investigation
from mistify.report.generator import generate_report, verify_citations, write_report
from mistify.scratchpad.db import ScratchpadDB
from tests.fixtures.synthetic_incident import PLANTED_API_KEY, PLANTED_EMAILS, ROOT_CAUSE_MARKER


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
    loaded_db.record_metric("redaction", "mode", "off")
    assert "Redaction was disabled" in generate_report(loaded_db)


def test_parse_errors_are_called_out(loaded_db: ScratchpadDB) -> None:
    loaded_db.record_metric("ingest", "parse_errors", 12)
    assert "12 line(s) failed to parse" in generate_report(loaded_db)


def test_poor_compression_is_called_out(loaded_db: ScratchpadDB) -> None:
    """Under-clustering makes template ranking unreliable, so the report must say so."""
    loaded_db.record_metric("templating", "compression_ratio", 0.97)
    assert "achieved little compression" in generate_report(loaded_db)


def test_orphan_events_are_called_out(loaded_db: ScratchpadDB) -> None:
    loaded_db.record_metric("scratchpad", "orphan_events", 5)
    assert "reference a template that does not exist" in generate_report(loaded_db)


def test_clean_run_has_no_warnings_section(loaded_db: ScratchpadDB) -> None:
    run_skeleton_investigation(loaded_db)
    assert "### Warnings" not in generate_report(loaded_db)

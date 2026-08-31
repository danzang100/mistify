"""The Phase 1 skeleton investigator."""

from __future__ import annotations

from mistify.agent.skeleton import INVESTIGATOR_NAME, run_skeleton_investigation
from mistify.metrics import (
    INVESTIGATE_INVESTIGATOR,
    INVESTIGATE_NOTES_WRITTEN,
    INVESTIGATE_OUTCOME,
    MetricView,
)
from mistify.scratchpad.db import ScratchpadDB
from tests.fixtures.synthetic_incident import RED_HERRING_MARKER, ROOT_CAUSE_MARKER


def test_selects_the_planted_root_cause_over_the_red_herring(loaded_db: ScratchpadDB) -> None:
    """The herring occurs far more often, so a count-first heuristic would pick it.

    This is what makes the test discriminating rather than a formality, and it is the seed
    of the plausible-but-wrong eval set Phase 5 builds out.
    """
    result = run_skeleton_investigation(loaded_db)

    assert result.target_template_id is not None
    template = next(
        t
        for t in loaded_db.top_templates(limit=500, order_by="count")
        if t["template_id"] == result.target_template_id
    )
    assert ROOT_CAUSE_MARKER in template["pattern"]
    assert RED_HERRING_MARKER not in template["pattern"]


def test_red_herring_really_is_more_frequent(loaded_db: ScratchpadDB) -> None:
    """Guards the test above: if the herring stopped being more common it would prove nothing."""
    templates = loaded_db.top_templates(limit=500, order_by="count")
    herring = next(t for t in templates if RED_HERRING_MARKER in t["pattern"])
    cause = next(t for t in templates if ROOT_CAUSE_MARKER in t["pattern"])
    assert herring["occurrence_count"] > cause["occurrence_count"]


def test_writes_exactly_one_note_with_evidence(loaded_db: ScratchpadDB) -> None:
    result = run_skeleton_investigation(loaded_db)

    assert len(result.notes) == 1
    note = result.notes[0]
    assert note.evidence["template_ids"] == [result.target_template_id]
    assert note.evidence["log_event_ids"]
    assert ROOT_CAUSE_MARKER in note.note


def test_reports_low_confidence(loaded_db: ScratchpadDB) -> None:
    """It is a hardcoded heuristic; presenting it as a finding would be the silent failure."""
    result = run_skeleton_investigation(loaded_db)
    assert result.notes[0].confidence == "low"


def test_cited_events_resolve_to_real_rows(loaded_db: ScratchpadDB) -> None:
    result = run_skeleton_investigation(loaded_db)
    cited = result.notes[0].evidence["log_event_ids"]
    rows = loaded_db.events_by_id(cited)

    assert len(rows) == len(cited)
    for row in rows:
        assert row["template_id"] == result.target_template_id


def test_every_step_is_logged_for_audit(loaded_db: ScratchpadDB) -> None:
    run_skeleton_investigation(loaded_db)
    queries = loaded_db.queries()
    assert len(queries) == 2
    assert [q["step"] for q in queries] == [1, 2]
    assert all(q["row_count"] is not None for q in queries)


def test_records_its_own_health_metrics(loaded_db: ScratchpadDB) -> None:
    run_skeleton_investigation(loaded_db)
    view = MetricView(loaded_db.metrics("investigate"))
    assert view.text(INVESTIGATE_INVESTIGATOR) == INVESTIGATOR_NAME
    assert view.text(INVESTIGATE_OUTCOME) == "converged"
    assert view.number(INVESTIGATE_NOTES_WRITTEN) == 1


def test_empty_scratchpad_converges_without_inventing_a_finding(db: ScratchpadDB) -> None:
    result = run_skeleton_investigation(db)
    assert result.notes == []
    assert result.target_template_id is None
    view = MetricView(db.metrics("investigate"))
    assert view.text(INVESTIGATE_OUTCOME) == "no_templates"

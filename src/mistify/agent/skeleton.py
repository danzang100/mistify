"""Phase 1 skeleton investigator.

This is deliberately not intelligent. It is a hardcoded three-step walk -- rank templates,
pull one slice, write one note -- whose only job is to prove that every seam between the
templater, the scratchpad, the note format and the report renderer actually fits together.
Phase 3 replaces the body of `run_skeleton_investigation` with the real bounded agent loop
and leaves the surrounding contract unchanged.

Because it is a heuristic and not a conclusion, it writes its note at `low` confidence and
the report says plainly which investigator produced it. A skeleton that presented its output
as a finding would be the exact silent failure the architecture warns about.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mistify.common.models import SEVERITIES, ScratchpadNote
from mistify.scratchpad.db import ScratchpadDB

__all__ = ["INVESTIGATOR_NAME", "SkeletonResult", "run_skeleton_investigation"]

INVESTIGATOR_NAME = "phase1-skeleton"

_SLICE_LIMIT = 50
_EVIDENCE_EVENTS = 5


@dataclass(slots=True)
class SkeletonResult:
    notes: list[ScratchpadNote]
    steps: int
    target_template_id: int | None


def run_skeleton_investigation(db: ScratchpadDB) -> SkeletonResult:
    """Rank templates by severity, pull the surrounding slice, record one hypothesis."""
    step = 1
    ranked = db.top_templates(limit=10, order_by="severity")
    db.log_query(step, "top_templates(order_by='severity', limit=10)", len(ranked))
    if not ranked:
        db.record_metric("investigate", "investigator", INVESTIGATOR_NAME)
        db.record_metric("investigate", "steps", step)
        db.record_metric("investigate", "outcome", "no_templates")
        return SkeletonResult(notes=[], steps=step, target_template_id=None)

    target = ranked[0]
    template_id = int(target["template_id"])
    max_severity = SEVERITIES[int(target["max_severity_rank"])]

    step += 1
    events = db.get_slice(template_id=template_id, max_lines=_SLICE_LIMIT)
    db.log_query(
        step, f"get_slice(template_id={template_id}, max_lines={_SLICE_LIMIT})", len(events)
    )

    step += 1
    event_ids = [int(e["id"]) for e in events[:_EVIDENCE_EVENTS]]
    sample = events[0]["message"] if events else ""
    note_text = (
        f"Highest-severity recurring template in this incident is #{template_id}: "
        f'"{target["pattern"]}". It reached {max_severity} and occurred '
        f"{target['occurrence_count']} times between {target['first_seen']} and "
        f"{target['last_seen']}. Representative line: {sample}"
    )
    evidence: dict[str, Any] = {
        "template_ids": [template_id],
        "log_event_ids": event_ids,
        "selection": "highest max_severity_rank, ties broken by occurrence_count",
    }
    note_id = db.write_note(step, note_text, evidence, confidence="low")

    db.record_metric("investigate", "investigator", INVESTIGATOR_NAME)
    db.record_metric("investigate", "steps", step)
    db.record_metric("investigate", "notes_written", 1)
    db.record_metric("investigate", "target_template_id", template_id)
    db.record_metric("investigate", "outcome", "converged")

    notes = [n for n in db.notes() if n.id == note_id]
    return SkeletonResult(notes=notes, steps=step, target_template_id=template_id)

"""Incident report rendering.

The report consumes only scratchpad state -- notes, their cited evidence, template
statistics and health metrics -- never raw logs directly.

Citations are resolved back to real rows before rendering. That is the deterministic half of
the citation-faithfulness check (decision G8): it proves every cited id exists and reports
any that do not. Whether a claim is actually *entailed* by those rows is a separate semantic
check that needs a model judge and a labelled fixture set, and it is scheduled as an eval
rather than pretended to be a unit test.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from mistify import __version__
from mistify.common.models import SEVERITIES
from mistify.metrics import (
    ADVERSARIAL_UNEXPLAINED_SIGNAL,
    ADVERSARIAL_UNSUPPORTED_CLAIMS,
    ANOMALY_NEEDLE_POSITION,
    INGEST_PARSE_ERRORS,
    INGEST_UNMAPPED_SEVERITY,
    INVESTIGATE_BUDGET_LIMITED,
    INVESTIGATE_CAVEAT,
    INVESTIGATE_INVESTIGATOR,
    INVESTIGATE_TOOL_CALLS,
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
    Metric,
    MetricView,
)
from mistify.scratchpad.db import ScratchpadDB
from mistify.templating.calibration import CalibrationStatus

__all__ = [
    "TOP_TEMPLATE_LIMIT",
    "ReportData",
    "generate_report",
    "verify_citations",
    "write_report",
]

#: How many templates the report lists. The scratchpad keeps the full ranking; the report
#: shows the head of it, and says so whenever it is showing less than all of it. A truncated
#: list presented as the complete one is a partial view of the incident read as a whole one.
TOP_TEMPLATE_LIMIT = 15

ReportData = dict[str, Any]


def verify_citations(db: ScratchpadDB) -> tuple[dict[int, list[dict[str, Any]]], list[str]]:
    """Resolve every note's cited ids back to scratchpad rows.

    Returns `(cited_events_by_note_id, warnings)`. A citation naming a row that does not
    exist produces a warning rather than a silent omission.
    """
    cited_events: dict[int, list[dict[str, Any]]] = {}
    warnings: list[str] = []

    for note in db.notes():
        note_id = note.id or 0
        event_ids = [int(i) for i in note.evidence.get("log_event_ids", [])]
        rows = db.events_by_id(event_ids)
        cited_events[note_id] = rows

        missing_events = sorted(set(event_ids) - {int(r["id"]) for r in rows})
        if missing_events:
            warnings.append(
                f"Note {note_id} cites log events that do not exist: "
                f"{', '.join(str(i) for i in missing_events)}"
            )

        template_ids = [int(i) for i in note.evidence.get("template_ids", [])]
        # Existence query rather than loading the whole templates table to build a set.
        missing_templates = sorted(set(template_ids) - db.known_template_ids(template_ids))
        if missing_templates:
            warnings.append(
                f"Note {note_id} cites templates that do not exist: "
                f"{', '.join(str(i) for i in missing_templates)}"
            )

    return cited_events, warnings


def collect(db: ScratchpadDB) -> ReportData:
    """Gather everything the template needs from the scratchpad."""
    incident = db.incident() or {
        "incident_id": "unknown",
        "source": "unknown",
        "format": None,
        "created_at": "unknown",
        "redaction_mode": None,
    }
    cited_events, warnings = verify_citations(db)

    notes = []
    for note in db.notes():
        notes.append(
            {
                "step": note.step,
                "note": note.note,
                "confidence": note.confidence,
                "evidence": note.evidence,
                "cited_events": cited_events.get(note.id or 0, []),
            }
        )

    top_templates = []
    for template in db.top_templates(limit=TOP_TEMPLATE_LIMIT, order_by="anomaly_score"):
        item = dict(template)
        item["max_severity"] = SEVERITIES[int(item["max_severity_rank"])]
        top_templates.append(item)

    # Two reads of the same rows, deliberately. The raw rows stay in the template context so
    # the health table renders whatever a stage published, including metrics added after this
    # code was written. The view is for the warnings, which act on specific named metrics.
    metrics = db.metrics()
    view = MetricView(metrics)
    warnings.extend(_health_warnings(view))

    investigator = view.text(INVESTIGATE_INVESTIGATOR)
    if investigator is None:
        investigator = "unknown"

    first_ts, last_ts = db.time_bounds()
    return {
        "incident": incident,
        "notes": notes,
        "top_templates": top_templates,
        "metrics": metrics,
        "queries": db.queries(),
        "warnings": warnings,
        "event_count": db.event_count(),
        "template_count": db.template_count(),
        "shown_template_count": len(top_templates),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "investigator": investigator,
        "investigator_caveat": view.text(INVESTIGATE_CAVEAT)
        or "No caveat recorded for this investigator.",
        "version": __version__,
    }


def _triggered_value(view: MetricView, metric: Metric) -> float:
    """The number behind a warning that has already fired.

    `triggers()` returning True means the metric was recorded and numeric, so this narrows
    away the None the signature admits rather than defaulting it. Defaulting is what the old
    `(row["value_num"] or 0)` did, and it would print a confident "0" for a metric that never
    arrived at all.
    """
    value = view.number(metric)
    if value is None:  # pragma: no cover -- triggers() has already ruled this out
        raise ValueError(f"{metric} triggered without a numeric value")
    return value


def _health_warnings(view: MetricView) -> list[str]:
    """Turn health metrics into explicit warnings so a degraded run says so.

    No cutoff appears in this function. Where a metric becomes worth mentioning is declared on
    the metric itself and evaluated by `MetricView.triggers`; all this supplies is the wording,
    which is the only half a reader actually owns.
    """
    warnings: list[str] = []

    if view.triggers(INGEST_PARSE_ERRORS):
        errors = int(_triggered_value(view, INGEST_PARSE_ERRORS))
        warnings.append(f"{errors} line(s) failed to parse and were skipped.")

    if view.triggers(INGEST_UNMAPPED_SEVERITY):
        unmapped = int(_triggered_value(view, INGEST_UNMAPPED_SEVERITY))
        warnings.append(
            f"{unmapped} event(s) carried an unrecognised severity and were defaulted to INFO."
        )

    # Coverage first: it is the invariant, and it is the failure the ratio hides.
    if view.triggers(TEMPLATING_COVERAGE):
        lost = 1.0 - _triggered_value(view, TEMPLATING_COVERAGE)
        warnings.append(
            f"CRITICAL: {lost:.1%} of events have no reachable template. Those lines cannot "
            "be found through template search at all, and any conclusion drawn here is "
            "based on a partial view of the incident."
        )

    if view.triggers(TEMPLATING_EVICTED):
        evicted = int(_triggered_value(view, TEMPLATING_EVICTED))
        warnings.append(
            f"{evicted} template(s) were evicted from the matching tree, "
            "so one condition's occurrences may be split across several templates and its "
            "counts understated. Raise drain3.max_clusters."
        )

    # The floor on this metric is load-bearing: exactly 0.0 means an empty file, not a badly
    # compressed one, and an empty file is not something to blame templating for.
    if view.triggers(TEMPLATING_REDUCTION_FACTOR):
        reduction = _triggered_value(view, TEMPLATING_REDUCTION_FACTOR)
        warnings.append(
            f"Templating reduced the file only {reduction:.1f}x — there is "
            "little repeated structure here, so the agent is searching close to the raw "
            "haystack and template ranking may be unreliable."
        )

    if view.triggers(TEMPLATING_LARGEST_SHARE):
        share = _triggered_value(view, TEMPLATING_LARGEST_SHARE)
        warnings.append(
            f"One template accounts for {share:.0%} of all events. A "
            "dominant noisy template crowds attention even after compression."
        )

    if view.triggers(ANOMALY_NEEDLE_POSITION):
        position = int(_triggered_value(view, ANOMALY_NEEDLE_POSITION))
        warnings.append(
            f"The most severe template ranks #{position} by anomaly score. "
            "The worst thing in the file is not surfacing near the top of the ranked list."
        )

    if view.triggers(SCRATCHPAD_ORPHAN_EVENTS):
        orphans = int(_triggered_value(view, SCRATCHPAD_ORPHAN_EVENTS))
        warnings.append(f"{orphans} event(s) reference a template that does not exist.")

    if view.triggers(REDACTION_MODE):
        warnings.append("Redaction was disabled for this run.")

    # An investigation cut short by its budget is not a finished one, and the difference has
    # to be in words rather than left for a reader to spot in the metric table.
    if view.triggers(INVESTIGATE_BUDGET_LIMITED):
        calls = view.number(INVESTIGATE_TOOL_CALLS)
        spent = f" after {int(calls)} tool calls" if calls is not None else ""
        warnings.append(
            f"The investigation was budget-limited: it reached its tool-call cap{spent} "
            "before concluding. Treat the finding as the best available from a search that "
            "was cut short, not as a completed investigation."
        )

    # The one adversarial test that does not depend on a model's judgement.
    if view.triggers(ADVERSARIAL_UNEXPLAINED_SIGNAL):
        unexplained = int(_triggered_value(view, ADVERSARIAL_UNEXPLAINED_SIGNAL))
        warnings.append(
            f"{unexplained} high-anomaly template(s) are not accounted for by any note. The "
            "ranking flagged them as signal and the conclusion does not mention them."
        )

    if view.triggers(ADVERSARIAL_UNSUPPORTED_CLAIMS):
        unsupported = int(_triggered_value(view, ADVERSARIAL_UNSUPPORTED_CLAIMS))
        warnings.append(
            f"The adversarial pass raised {unsupported} evidence-backed objection(s) at high "
            "severity against claims in this report."
        )

    if view.triggers(TEMPLATING_CALIBRATION_STATUS):
        reason = view.text(TEMPLATING_CALIBRATION_REASON)
        detail = "" if reason is None else f" {reason}"
        headline = (
            "Templating calibration could not find a threshold that preserves signal."
            if view.text(TEMPLATING_CALIBRATION_STATUS) == CalibrationStatus.SIGNAL_AT_RISK
            else "Templating calibration could not collapse much noise."
        )
        warnings.append(f"{headline}{detail}")

    if view.triggers(TEMPLATING_OVER_MERGED):
        over_merged = int(_triggered_value(view, TEMPLATING_OVER_MERGED))
        ids = view.text(TEMPLATING_OVER_MERGED_IDS)
        detail = "" if ids is None else f" (templates {ids})"
        warnings.append(
            f"{over_merged} template(s) span a wide severity range"
            f"{detail} — distinct conditions may have been merged into one template."
        )

    return warnings


def generate_report(db: ScratchpadDB) -> str:
    """Render the incident report as markdown."""
    env = Environment(
        loader=PackageLoader("mistify.report", "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    template = env.get_template("incident_report.md.jinja")
    return template.render(**collect(db))


def write_report(db: ScratchpadDB, output_dir: str | Path, incident_id: str) -> Path:
    """Render and write the report, returning its path."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{incident_id}.md"
    path.write_text(generate_report(db), encoding="utf-8")
    return path

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
from mistify.agent.skeleton import INVESTIGATOR_NAME
from mistify.common.models import SEVERITIES
from mistify.scratchpad.db import ScratchpadDB

__all__ = ["ReportData", "generate_report", "verify_citations", "write_report"]

_INVESTIGATOR_CAVEATS = {
    INVESTIGATOR_NAME: (
        "Template selection is a hardcoded severity-then-count heuristic, not a "
        "model-driven investigation. Treat the finding below as a starting point, not a "
        "root-cause conclusion."
    ),
}

ReportData = dict[str, Any]


def verify_citations(db: ScratchpadDB) -> tuple[dict[int, list[dict[str, Any]]], list[str]]:
    """Resolve every note's cited ids back to scratchpad rows.

    Returns `(cited_events_by_note_id, warnings)`. A citation naming a row that does not
    exist produces a warning rather than a silent omission.
    """
    known_templates = {t["template_id"] for t in db.top_templates(limit=1_000_000)}
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
        missing_templates = sorted(set(template_ids) - known_templates)
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
    for template in db.top_templates(limit=15, order_by="anomaly_score"):
        item = dict(template)
        item["max_severity"] = SEVERITIES[int(item["max_severity_rank"])]
        top_templates.append(item)

    metrics = db.metrics()
    warnings.extend(_health_warnings(metrics))

    investigator = next(
        (
            m["value"]
            for m in metrics
            if m["stage"] == "investigate" and m["metric"] == "investigator"
        ),
        "unknown",
    )

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
        "first_ts": first_ts,
        "last_ts": last_ts,
        "investigator": investigator,
        "investigator_caveat": _INVESTIGATOR_CAVEATS.get(
            investigator, "No caveat recorded for this investigator."
        ),
        "version": __version__,
    }


def _health_warnings(metrics: list[dict[str, Any]]) -> list[str]:
    """Turn health metrics into explicit warnings so a degraded run says so."""
    lookup = {(m["stage"], m["metric"]): m for m in metrics}
    warnings: list[str] = []

    parse_errors = lookup.get(("ingest", "parse_errors"))
    if parse_errors and (parse_errors["value_num"] or 0) > 0:
        warnings.append(
            f"{int(parse_errors['value_num'])} line(s) failed to parse and were skipped."
        )

    unmapped = lookup.get(("ingest", "unmapped_severity"))
    if unmapped and (unmapped["value_num"] or 0) > 0:
        warnings.append(
            f"{int(unmapped['value_num'])} event(s) carried an unrecognised severity and "
            "were defaulted to INFO."
        )

    # Coverage first: it is the invariant, and it is the failure the ratio hides.
    coverage = lookup.get(("templating", "template_coverage"))
    if coverage and (coverage["value_num"] if coverage["value_num"] is not None else 1.0) < 1.0:
        lost = 1.0 - float(coverage["value_num"])
        warnings.append(
            f"CRITICAL: {lost:.1%} of events have no reachable template. Those lines cannot "
            "be found through template search at all, and any conclusion drawn here is "
            "based on a partial view of the incident."
        )

    evicted = lookup.get(("templating", "evicted_templates"))
    if evicted and (evicted["value_num"] or 0) > 0:
        warnings.append(
            f"{int(evicted['value_num'])} template(s) were evicted from the matching tree, "
            "so one condition's occurrences may be split across several templates and its "
            "counts understated. Raise drain3.max_clusters."
        )

    reduction = lookup.get(("templating", "reduction_factor"))
    if reduction and 0 < (reduction["value_num"] or 0) < 2.0:
        warnings.append(
            f"Templating reduced the file only {reduction['value_num']:.1f}x — there is "
            "little repeated structure here, so the agent is searching close to the raw "
            "haystack and template ranking may be unreliable."
        )

    dominant = lookup.get(("templating", "largest_template_share"))
    if dominant and (dominant["value_num"] or 0) > 0.6:
        warnings.append(
            f"One template accounts for {dominant['value_num']:.0%} of all events. A "
            "dominant noisy template crowds attention even after compression."
        )

    needle = lookup.get(("anomaly", "max_severity_rank_position"))
    if needle and (needle["value_num"] or 0) > 5:
        warnings.append(
            f"The most severe template ranks #{int(needle['value_num'])} by anomaly score. "
            "The worst thing in the file is not surfacing near the top of the ranked list."
        )

    orphans = lookup.get(("scratchpad", "orphan_events"))
    if orphans and (orphans["value_num"] or 0) > 0:
        warnings.append(
            f"{int(orphans['value_num'])} event(s) reference a template that does not exist."
        )

    mode = lookup.get(("redaction", "mode"))
    if mode and mode["value"] == "off":
        warnings.append("Redaction was disabled for this run.")

    calibration = lookup.get(("templating", "calibration_status"))
    if calibration and calibration["value"] in {"signal_at_risk", "under_clustered"}:
        reason = lookup.get(("templating", "calibration_reason"))
        detail = f" {reason['value']}" if reason else ""
        headline = (
            "Templating calibration could not find a threshold that preserves signal."
            if calibration["value"] == "signal_at_risk"
            else "Templating calibration could not collapse much noise."
        )
        warnings.append(f"{headline}{detail}")

    over_merged = lookup.get(("templating", "over_merged_templates"))
    if over_merged and (over_merged["value_num"] or 0) > 0:
        ids = lookup.get(("templating", "over_merged_ids"))
        detail = f" (templates {ids['value']})" if ids else ""
        warnings.append(
            f"{int(over_merged['value_num'])} template(s) span a wide severity range"
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

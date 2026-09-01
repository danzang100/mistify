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
from mistify.common.models import SEVERITIES, parse_timestamp
from mistify.metrics import (
    ADVERSARIAL_OUTCOME,
    ADVERSARIAL_UNEXPLAINED_SIGNAL,
    ADVERSARIAL_UNSUPPORTED_CLAIMS,
    ALL_METRICS,
    ANOMALY_NEEDLE_POSITION,
    ANOMALY_SIGNAL_TEMPLATE_IDS,
    INGEST_PARSE_ERRORS,
    INGEST_UNMAPPED_SEVERITY,
    INVESTIGATE_BUDGET_LIMITED,
    INVESTIGATE_CAVEAT,
    INVESTIGATE_INVESTIGATOR,
    INVESTIGATE_TOOL_CALLS,
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
    Metric,
    MetricView,
    token_usage,
    total_tokens,
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


#: Confidence as an order, so notes can be ranked without a model.
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

#: A template active for at least this share of the log is chronic rather than part of the
#: event: it was already happening before the incident and did not stop after it.
_CHRONIC_SHARE = 0.9


def _rank_notes(notes: list[dict[str, Any]], scores: dict[int, float]) -> list[dict[str, Any]]:
    """Every recorded hypothesis, most significant first.

    Not in the order they were written. The loop is told to conclude last and does not reliably
    comply -- across three runs of the same incident the first note was an early narrow
    hypothesis twice, and the last one was a deliberate aside ("these timeouts are separate")
    once. Neither position means anything.

    Ranked on the anomaly score of the templates each note cites, which no model touched. Two
    runs that reason differently but reach the same templates therefore order their issues the
    same way, which is what makes one report comparable to the next.

    This is an ordering, not a filter. Every note appears, because an investigation that found
    two unrelated problems has found two problems, and a report with room for one of them
    loses the other.
    """

    def key(note: dict[str, Any]) -> tuple[float, int, int]:
        cited = [int(i) for i in note["evidence"].get("template_ids", [])]
        return (
            max((scores.get(i, 0.0) for i in cited), default=0.0),
            _CONFIDENCE_RANK.get(str(note["confidence"]).lower(), 0),
            -int(note["step"]),
        )

    return sorted(notes, key=key, reverse=True)


def _duration_minutes(first: str | None, last: str | None) -> float | None:
    """Minutes between two scratchpad timestamps, or None if either is missing."""
    if not first or not last:
        return None
    return (parse_timestamp(last) - parse_timestamp(first)).total_seconds() / 60


def _chronic_template_ids(templates: list[dict[str, Any]], log_minutes: float | None) -> set[int]:
    """Templates active across essentially the whole log.

    A template that was firing before the incident began and kept firing after it ended is
    background, not event. Saying so is what stops a chronic error stream from being read as
    part of an outage it merely overlapped with.
    """
    if not log_minutes:
        return set()
    chronic = set()
    for template in templates:
        minutes = _duration_minutes(template["first_seen"], template["last_seen"])
        if minutes is not None and minutes >= log_minutes * _CHRONIC_SHARE:
            chronic.add(int(template["template_id"]))
    return chronic


def _describe_issues(
    ranked: list[dict[str, Any]], scores: dict[int, float], chronic: set[int]
) -> list[dict[str, Any]]:
    """The ranked notes as the report's overview of what was found."""
    issues = []
    for position, note in enumerate(ranked, start=1):
        cited = [int(i) for i in note["evidence"].get("template_ids", [])]
        issues.append(
            {
                "rank": position,
                "note": note["note"],
                "step": note["step"],
                "confidence": note["confidence"],
                "template_ids": cited,
                "top_score": max((scores.get(i, 0.0) for i in cited), default=0.0),
                # Only when every template it rests on is chronic. One acute template among
                # them means the note is about the event, whatever else it mentions.
                "chronic": bool(cited) and all(i in chronic for i in cited),
            }
        )
    return issues


def _at_a_glance(
    db: ScratchpadDB,
    view: MetricView,
    headline: dict[str, Any] | None,
    templates: list[dict[str, Any]],
    chronic: set[int],
) -> dict[str, Any]:
    """When, how long, how loud, and where -- all computed, none of it narrated.

    The header's window is the *file's*, which on a quiet log overstates an incident by however
    much silence surrounds it. Naively replacing it with the union of the signal templates does
    not help: one chronic template active all hour drags the union back out to the whole file,
    which is how the first version of this section reported a six-minute outage as sixty
    minutes. So the headline window is the window of the templates the leading issue cites, and
    every signal template is listed with its own span next to it.
    """
    raw_ids = view.text(ANOMALY_SIGNAL_TEMPLATE_IDS) or ""
    signal_ids = [int(part) for part in raw_ids.split(",") if part.strip()]

    cited = [int(i) for i in (headline or {}).get("evidence", {}).get("template_ids", [])]
    # Falling back to the top-ranked template rather than to every signal template: one
    # template's span is a claim about one thing, the union is a claim about nothing.
    window_ids = cited or signal_ids[:1]
    first_ts, last_ts = db.template_window(window_ids)

    by_id = {int(t["template_id"]): t for t in templates}
    spans = []
    for template_id in signal_ids:
        template = by_id.get(template_id)
        if template is None:
            continue
        spans.append(
            {
                "template_id": template_id,
                "first_seen": template["first_seen"],
                "last_seen": template["last_seen"],
                "minutes": _duration_minutes(template["first_seen"], template["last_seen"]),
                "occurrence_count": template["occurrence_count"],
                "max_severity": template["max_severity"],
                "chronic": template_id in chronic,
            }
        )

    counts = db.severity_counts()
    return {
        "signal_template_ids": signal_ids,
        "window_template_ids": window_ids,
        "window_is_from_verdict": bool(cited),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "duration_minutes": _duration_minutes(first_ts, last_ts),
        "spans": spans,
        "chronic_template_ids": sorted(chronic & set(signal_ids)),
        # Severity order, not alphabetical, and loudest first: a reader scans for FATAL.
        "severities": [
            {"severity": name, "count": counts[name]}
            for name in reversed(SEVERITIES)
            if name in counts
        ],
        "sources": db.source_activity(),
    }


def _split_health(
    metrics: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Metrics a reader acts on, separated from metrics that describe how the run was tuned.

    Both were in one alphabetised table, which put `templating.depth` -- a knob -- next to
    `templating.template_coverage`, the invariant whose failure invalidates the report. The
    split is `Metric.load_bearing`, already declared on every metric, so this stays in step
    with the vocabulary rather than being a second opinion about it.
    """
    load_bearing = {m.key for m in ALL_METRICS if m.load_bearing}
    signals = [m for m in metrics if (m["stage"], m["metric"]) in load_bearing]
    detail = [m for m in metrics if (m["stage"], m["metric"]) not in load_bearing]
    return signals, detail


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

    # Token counts come out of the same rows, grouped by the stage that spent them. Every
    # stage that calls a model is here, not just the loop: the adversarial pass is one or two
    # calls on a second model, and a run total that quietly omitted it would understate the
    # bill by the whole cost of the check.
    #
    # Left in the order `token_usage` returns, which is metric-declaration order and therefore
    # the order the stages ran. Sorting alphabetically put the check above the investigation it
    # was checking.
    token_stages = token_usage(metrics)

    # Every template, not just the ones the report lists: a note may cite one that fell below
    # the display cut, and scoring the headline off a truncated table would rank it at zero.
    scores = {
        int(t["template_id"]): float(t["anomaly_score"])
        for t in db.top_templates(limit=max(db.template_count(), 1), order_by="anomaly_score")
    }
    ranked = _rank_notes(notes, scores)
    headline = ranked[0] if ranked else None
    log_first, log_last = db.time_bounds()
    chronic = _chronic_template_ids(top_templates, _duration_minutes(log_first, log_last))
    health_signals, health_detail = _split_health(metrics)
    objections = db.adversarial_objections()

    # The stage's own metric wins over the incident row: the warning about redaction being off
    # reads the metric, and driving the two off different sources let one report both warn
    # that redaction was disabled and point at a vault that was never written.
    mode = view.text(REDACTION_MODE) or incident.get("redaction_mode")
    redaction_on = bool(mode) and mode != "off"
    # `reveal` reads the vault, and the vault is off by default. Telling every reader to run a
    # command that will fail on most runs teaches them the report's advice is not worth
    # following, so the pointer appears only when there is something to point at.
    vault_kept = bool(view.flag(REDACTION_VAULT))

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
        "token_stages": token_stages,
        "token_total": total_tokens(token_stages),
        "headline": headline,
        "issues": _describe_issues(ranked, scores, chronic),
        "glance": _at_a_glance(db, view, headline, top_templates, chronic),
        "health_signals": health_signals,
        "health_detail": health_detail,
        # Whether the pass ran and whether its content was kept are different questions. A
        # scratchpad written before the critique was persisted has the metrics and none of the
        # text, and reporting that as "did not run" would turn a bookkeeping gap into a claim
        # that nothing checked the finding.
        "adversarial_ran": ADVERSARIAL_OUTCOME in view,
        "adversarial": db.adversarial_summary(),
        "objections": objections,
        "conceded_count": sum(1 for o in objections if o["conceded"]),
        "redaction_on": redaction_on,
        "vault_kept": vault_kept,
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

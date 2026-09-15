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

import io
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from mistify import __version__
from mistify.common.models import SEVERITIES
from mistify.findings import (
    chronic_template_ids,
    describe_issues,
    duration_minutes,
    rank_notes,
)
from mistify.metrics import (
    ADVERSARIAL_OUTCOME,
    ADVERSARIAL_UNEXPLAINED_SIGNAL,
    ADVERSARIAL_UNREBUTTED_HIGH_SEVERITY,
    ALL_METRICS,
    ANOMALY_NEEDLE_POSITION,
    ANOMALY_SEVERITY_SOURCE,
    ANOMALY_SIGNAL_TEMPLATE_IDS,
    INGEST_EVENTS_LOADED,
    INGEST_FALLBACK,
    INGEST_FALLBACK_REASON,
    INGEST_PARSE_ERRORS,
    INGEST_TIMESTAMP_SHAPE,
    INGEST_TIMESTAMP_YEAR_INFERRED,
    INGEST_UNMAPPED_SEVERITY,
    INGEST_UNPARSEABLE_TIMESTAMP,
    INVESTIGATE_BUDGET_LIMITED,
    INVESTIGATE_CAVEAT,
    INVESTIGATE_DIGEST_CHARS,
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


class ProviderMissing(RuntimeError):
    """A report format was asked for that this installation cannot produce."""


__all__ = [
    "TOP_TEMPLATE_LIMIT",
    "ProviderMissing",
    "ReportData",
    "generate_report",
    "render_pdf",
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
                "minutes": duration_minutes(template["first_seen"], template["last_seen"]),
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
        "duration_minutes": duration_minutes(first_ts, last_ts),
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
    ranked = rank_notes(notes, scores)
    headline = ranked[0] if ranked else None
    log_first, log_last = db.time_bounds()
    chronic = chronic_template_ids(top_templates, duration_minutes(log_first, log_last))
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
        "issues": describe_issues(ranked, scores, chronic),
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

    # First, because it changes how every later number in the report should be read.
    if view.triggers(INGEST_FALLBACK):
        detail = view.text(INGEST_FALLBACK_REASON) or "no reason recorded"
        # How much of the source this actually applies to. A single unrecognised file is all of
        # it; a directory can be partly recognised, and saying "there are no parsed timestamps"
        # there would be false in the other direction -- overstating the damage is its own way
        # of making the warning ignorable.
        ordinal = view.number(INGEST_UNPARSEABLE_TIMESTAMP)
        loaded = view.number(INGEST_EVENTS_LOADED)
        shape = view.text(INGEST_TIMESTAMP_SHAPE)
        if ordinal is not None and loaded is not None and 0 < ordinal < loaded:
            scope = (
                f"{int(ordinal)} of {int(loaded)} events were read this way and have no parsed "
                "timestamp. The incident window spans those events and the properly timestamped "
                "ones together, so it is not a duration"
            )
        elif shape:
            # Reading one line at a time no longer implies having no timestamps: the fallback
            # reads them out of the line text where the text carries them. Saying otherwise
            # would understate the report in the one direction nobody checks -- a reader who
            # believes the window is meaningless will not use it even when it is.
            if view.triggers(INGEST_TIMESTAMP_YEAR_INFERRED):
                scope = (
                    f"Timestamps were read from each line as `{shape}`, which carries no year, "
                    "so the year is the one at ingest rather than the log's. Durations and "
                    "ordering are sound; absolute dates are not, and a log crossing 31 December "
                    "will appear to run backwards"
                )
            else:
                scope = (
                    f"Timestamps were read from each line as `{shape}`, so the incident window "
                    "and the burstiness term are real"
                )
        else:
            scope = (
                "There are no parsed timestamps: the incident window and the burstiness term "
                "describe the order lines appear in the file, not when anything happened"
            )
        warnings.append(
            f"Part of this source was read one line at a time ({detail}). {scope}, "
            "and severity was guessed from the text of each line."
        )

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
            f"Templating reduced the file only {reduction:.1f}x - there is "
            "little repeated structure here, so the agent is searching close to the raw "
            "haystack and template ranking may be unreliable."
        )

    if view.triggers(TEMPLATING_LARGEST_SHARE):
        share = _triggered_value(view, TEMPLATING_LARGEST_SHARE)
        warnings.append(
            f"One template accounts for {share:.0%} of all events. A "
            "dominant noisy template crowds attention even after compression."
        )

    # "none" means neither the severity field nor the template text told the ranking anything,
    # so half its weight was redistributed onto rarity and burstiness. That is a materially
    # weaker ordering than either of the other two sources and the reader has to know which
    # one produced the list they are about to read top-down.
    if view.triggers(ANOMALY_SEVERITY_SOURCE):
        warnings.append(
            "No severity could be read from this file, from a field or from the template "
            "text, so the ranking rests on rarity and burstiness alone. Treat the order of "
            "the templates below as weak evidence about where to look."
        )

    if view.triggers(ANOMALY_NEEDLE_POSITION):
        position = int(_triggered_value(view, ANOMALY_NEEDLE_POSITION))
        warnings.append(
            f"The most severe template ranks #{position} by anomaly score. "
            "The worst thing in the file is not surfacing near the top of the ranked list."
        )

    if view.triggers(INVESTIGATE_DIGEST_CHARS):
        size = int(_triggered_value(view, INVESTIGATE_DIGEST_CHARS))
        warnings.append(
            f"The ranked digest handed to the investigator was {size:,} characters, which is "
            "re-sent on every step and dominates what this run cost. The templates in this "
            "source have unusually long patterns."
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
            f"{unexplained} high-anomaly template(s) active during the incident are not "
            "accounted for by any note. The ranking flagged them as signal and no finding "
            "mentions them."
        )

    # An objection that was answered is the system working, and one that was conceded is
    # stated plainly in the overview. Only an objection nobody replied to means the challenge
    # went unanswered, which is the case worth an alarm.
    if view.triggers(ADVERSARIAL_UNREBUTTED_HIGH_SEVERITY):
        unrebutted = int(_triggered_value(view, ADVERSARIAL_UNREBUTTED_HIGH_SEVERITY))
        warnings.append(
            f"{unrebutted} evidence-backed objection(s) at high severity were never answered. "
            "The challenge to those claims stands unchallenged in turn."
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
            f"{detail} - distinct conditions may have been merged into one template."
        )

    return warnings


#: The one place a format is turned into a template and a file extension. Every format renders
#: the same `collect()` data through its own template rather than converting one output into
#: another: markdown-to-HTML conversion would make the HTML report a translation of a document
#: rather than a rendering of the incident, and every future divergence would be a bug in the
#: converter instead of a choice in a template.
_FORMATS: dict[str, tuple[str, str]] = {
    "markdown": ("incident_report.md.jinja", ".md"),
    "html": ("incident_report.html.jinja", ".html"),
    # PDF is the HTML, printed. Its template is the HTML one and its extension is not.
    "pdf": ("incident_report.html.jinja", ".pdf"),
}

_PDF_HELP = (
    "PDF output needs the optional `pdf` extra: `uv sync --extra pdf`, or "
    "`pip install 'mistify[pdf]'`. Every other format works without it. The HTML report "
    "carries print styles, so a browser's print-to-PDF is a fine substitute."
)


def generate_report(db: ScratchpadDB, report_format: str = "markdown") -> str:
    """Render the incident report as markdown or HTML.

    `pdf` renders the HTML: the bytes are produced by `write_report`, because a PDF is not a
    string and pretending otherwise would put an encode/decode round trip in the middle of the
    only path that produces one.
    """
    if report_format not in _FORMATS:
        raise ValueError(f"unknown report format {report_format!r}. Known: {sorted(_FORMATS)}")
    template_name, _ = _FORMATS[report_format]
    is_html = template_name.endswith(".html.jinja")
    env = Environment(
        loader=PackageLoader("mistify.report", "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        # Escaping is on for HTML and off for markdown. Log lines are attacker-influenced text
        # that has already been through redaction, not sanitisation: a message containing
        # `<script>` is a perfectly ordinary log line and must render as one.
        autoescape=is_html,
    )
    return env.get_template(template_name).render(**collect(db))


def render_pdf(html: str) -> bytes:
    """The HTML report as PDF bytes.

    A pure-Python engine on purpose. The better-looking alternatives need system libraries
    (cairo, pango) that are not present on a stock Windows machine, and a report format that
    works on the maintainer's laptop and nowhere else is not a format.
    """
    try:
        from xhtml2pdf import pisa
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ProviderMissing(_PDF_HELP) from exc

    buffer = io.BytesIO()
    result = pisa.CreatePDF(html, dest=buffer, encoding="utf-8")
    if result.err:
        raise ProviderMissing(f"PDF rendering failed with {result.err} error(s)")
    return buffer.getvalue()


def write_report(
    db: ScratchpadDB,
    output_dir: str | Path,
    incident_id: str,
    report_format: str = "markdown",
) -> Path:
    """Render and write the report, returning its path."""
    if report_format not in _FORMATS:
        raise ValueError(f"unknown report format {report_format!r}. Known: {sorted(_FORMATS)}")
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{incident_id}{_FORMATS[report_format][1]}"

    rendered = generate_report(db, report_format)
    if report_format == "pdf":
        path.write_bytes(render_pdf(rendered))
    else:
        path.write_text(rendered, encoding="utf-8")
    return path

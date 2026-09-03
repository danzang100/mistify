"""Scoring one finished investigation against a case's known answer.

Everything here reads the scratchpad, never the rendered report. Scraping markdown was tried
during development and produced a table of numbers that were confidently wrong -- one run's
metrics repeated for every row -- because a scraper fails silently when the document moves.
The scratchpad is the same source the report renders from, and it has a schema.

Every check is deterministic. Whether a claim is *entailed* by the rows it cites is a separate
question that needs a model, and it lives behind `--judge` rather than being approximated here
by string matching: an approximation of entailment that passes on any sufficiently vague claim
is worse than no check at all, because it reads like one.
"""

from __future__ import annotations

from dataclasses import dataclass

from mistify.eval.cases import EvalCase
from mistify.findings import rank_notes
from mistify.report.generator import verify_citations
from mistify.scratchpad.db import ScratchpadDB

__all__ = ["Check", "score_run"]

#: Confidences that count as a claim rather than an observation. The quiet-hour bar: describing
#: normal operation at low or medium confidence is a reasonable thing for an investigation to
#: do, and asserting a root cause at high confidence when none was planted is the failure.
_CLAIM_CONFIDENCES = frozenset({"high"})


@dataclass(frozen=True, slots=True)
class Check:
    """One question about the run, and what the scratchpad says."""

    name: str
    passed: bool
    detail: str


#: Above this many templates, a marker is not identifying anything. A citation check on such a
#: marker passes as soon as the investigation cites almost anything, which is a passing row on
#: a scorecard that measured nothing. Reported as unresolvable rather than allowed to pass.
_MAX_MARKER_TEMPLATES = 10

#: And the same judgement as a share, because the count alone cannot be right for both sizes of
#: file this scores. A CI log clusters into a thousand templates, where ten is plainly too few
#: to identify anything; the synthetic incident clusters into nine, where ten can never be
#: reached and the rule would never fire. A marker matching over half the templates in a file
#: is not a marker, whichever file it is.
_MAX_MARKER_SHARE = 0.5


def _templates_for(db: ScratchpadDB, marker: str) -> set[int]:
    """Every template whose pattern or whose events carry `marker`.

    Two lookups, because a marker can be either half of a line. The pattern search finds the
    *constant* part of a line, which is what the planted fixture markers are. External corpora
    are different: LogDx-CI's critical signals are frequently the failing test's path or the
    stack location, which is precisely the part that varies between lines and which Drain3
    therefore replaces with a wildcard. Measured on the first case tried, two of six critical
    signals were invisible to a pattern search and sitting in plain text in the events.

    So the events are searched too, and their template ids returned. Searching only events
    would work for both but reads the whole table for every marker, and the pattern hit is both
    cheaper and more precise when it exists.

    An empty set is a real answer rather than an error: it means templating merged or dropped
    the lines the marker names, which is a finding about the pipeline and not about the
    investigation, and the caller reports it as its own failed check.
    """
    rows = db.run_readonly_sql(
        "SELECT template_id, pattern FROM templates ORDER BY template_id", max_rows=5000
    )
    matched = {int(row["template_id"]) for row in rows if marker in str(row["pattern"])}
    if matched:
        return matched

    return db.templates_matching_text(marker)


def _template_for(db: ScratchpadDB, marker: str) -> int | None:
    """The single template carrying `marker`, lowest id, or None when nothing does.

    Kept for the checks that report one id. `_templates_for` is the real resolver.
    """
    matched = _templates_for(db, marker)
    return min(matched) if matched else None


def _cited_templates(db: ScratchpadDB) -> set[int]:
    cited: set[int] = set()
    for note in db.notes():
        cited.update(int(i) for i in note.evidence.get("template_ids", []))
    return cited


def _leading_templates(db: ScratchpadDB) -> set[int]:
    """Templates cited by the issue the report leads with.

    Ranked by `findings.rank_notes`, the same function the report renders from, so the score
    and the document cannot disagree about which finding leads. It used to call the report's
    `collect()` -- building health warnings, token totals and the whole glance section -- to
    read one list, which coupled scoring to the shape of a document instead of to the shape of
    an investigation.

    "Leading" is one issue, not every high-confidence note. An investigation that concludes on
    the outage and separately records "these timeouts are a distinct pre-existing problem" has
    done the right thing with a red herring; failing it for mentioning the herring at all would
    push the model into ignoring it rather than dismissing it.
    """
    notes = [
        {"note": n.note, "step": n.step, "confidence": n.confidence, "evidence": n.evidence}
        for n in db.notes()
    ]
    if not notes:
        return set()
    scores = {
        int(t["template_id"]): float(t["anomaly_score"])
        for t in db.top_templates(limit=max(db.template_count(), 1), order_by="anomaly_score")
    }
    leading = rank_notes(notes, scores)[0]
    return {int(i) for i in leading["evidence"].get("template_ids", [])}


def _conclusion_text(db: ScratchpadDB) -> str:
    """Everything the investigation concluded, lowercased, as one string.

    Every note rather than only the leading one. A diagnosis spread over three notes is still
    the diagnosis, and reading only the top one would fail a run for how it organised its
    findings rather than for what it concluded.
    """
    return " ".join(str(note.note) for note in db.notes()).lower()


def score_run(db: ScratchpadDB, case: EvalCase) -> list[Check]:
    """Every check this case defines, against one finished investigation."""
    checks: list[Check] = []
    cited = _cited_templates(db)

    for marker in case.must_cite:
        matched = _templates_for(db, marker)
        label = marker if len(marker) <= 60 else marker[:57] + "..."
        if not matched:
            checks.append(
                Check(
                    name=f"resolves[{label}]",
                    passed=False,
                    detail=f"no template or event carries {marker!r} -- the line was lost "
                    "before the investigation could cite it",
                )
            )
            continue
        total = max(db.template_count(), 1)
        if len(matched) > _MAX_MARKER_TEMPLATES or len(matched) > total * _MAX_MARKER_SHARE:
            # Not a failure of the investigation, and not a pass either. A marker this common
            # cannot distinguish a run that cited the right thing from one that cited anything.
            checks.append(
                Check(
                    name=f"resolves[{label}]",
                    passed=False,
                    detail=(
                        f"{marker!r} matches {len(matched)} of {total} templates "
                        "and identifies nothing"
                    ),
                )
            )
            continue
        checks.append(
            Check(
                name=f"cites[{label}]",
                passed=bool(matched & cited),
                detail=f"templates {sorted(matched)}; cited {sorted(cited) or 'none'}",
            )
        )

    for marker in case.must_not_lead:
        template_id = _template_for(db, marker)
        if template_id is None:
            checks.append(Check(f"resolves[{marker}]", False, f"no template carries {marker!r}"))
            continue
        leading = _leading_templates(db)
        # No chronic exemption here, deliberately. The herring is chronic by construction, so
        # excusing chronic templates made this check incapable of failing -- it passed on a
        # conclusion that rested entirely on the herring, which is the one thing it exists to
        # catch.
        checks.append(
            Check(
                name=f"does-not-lead-with[{marker}]",
                passed=template_id not in leading,
                detail=f"template {template_id}; leading issue cites {sorted(leading) or 'none'}",
            )
        )

    if not case.expects_incident:
        claims = [n for n in db.notes() if str(n.confidence).lower() in _CLAIM_CONFIDENCES]
        checks.append(
            Check(
                name="invents-no-incident",
                passed=not claims,
                detail=(
                    "no high-confidence finding"
                    if not claims
                    else f"{len(claims)} high-confidence finding(s) on a file with none planted"
                ),
            )
        )

    if case.must_mention or case.must_not_claim:
        conclusion = _conclusion_text(db)
        for term in case.must_mention:
            checks.append(
                Check(
                    name=f"mentions[{term}]",
                    passed=term.lower() in conclusion,
                    detail="named in the conclusion" if term.lower() in conclusion else "absent",
                )
            )
        for term in case.must_not_claim:
            claimed = term.lower() in conclusion
            checks.append(
                Check(
                    name=f"avoids[{term}]",
                    passed=not claimed,
                    detail=(
                        f"conclusion contains {term!r} -- note that negation is not detected, "
                        "so a run that explicitly ruled this out also fails here"
                        if claimed
                        else "not claimed"
                    ),
                )
            )

    _, citation_warnings = verify_citations(db)
    checks.append(
        Check(
            name="citations-resolve",
            passed=not citation_warnings,
            detail="; ".join(citation_warnings) or "every cited id exists",
        )
    )

    return checks

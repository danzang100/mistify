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
from mistify.report.generator import collect, verify_citations
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


def _template_for(db: ScratchpadDB, marker: str) -> int | None:
    """The template whose pattern carries `marker`, or None when clustering lost it.

    None is a real answer, not an error. A marker that resolves to nothing means templating
    merged or dropped the planted lines, which is a finding about the pipeline rather than
    about the investigation -- so the scorer reports it as its own failed check instead of
    quietly failing the citation checks that depend on it.
    """
    rows = db.run_readonly_sql(
        "SELECT template_id, pattern FROM templates ORDER BY template_id", max_rows=500
    )
    for row in rows:
        if marker in str(row["pattern"]):
            return int(row["template_id"])
    return None


def _cited_templates(db: ScratchpadDB) -> set[int]:
    cited: set[int] = set()
    for note in db.notes():
        cited.update(int(i) for i in note.evidence.get("template_ids", []))
    return cited


def _leading_templates(db: ScratchpadDB) -> set[int]:
    """Templates cited by the issue the report leads with.

    Taken from `collect`, the report's own ranking, rather than recomputed here. A scorer that
    ranked notes its own way would measure a document nobody reads, and would keep agreeing
    with itself after the report changed.

    "Leading" is one issue, not every high-confidence note. An investigation that concludes on
    the outage and separately records "these timeouts are a distinct pre-existing problem" has
    done the right thing with a red herring; failing it for mentioning the herring at all would
    push the model into ignoring it rather than dismissing it.
    """
    issues = collect(db)["issues"]
    return {int(i) for i in issues[0]["template_ids"]} if issues else set()


def score_run(db: ScratchpadDB, case: EvalCase) -> list[Check]:
    """Every check this case defines, against one finished investigation."""
    checks: list[Check] = []
    cited = _cited_templates(db)

    for marker in case.must_cite:
        template_id = _template_for(db, marker)
        if template_id is None:
            checks.append(
                Check(
                    name=f"resolves[{marker}]",
                    passed=False,
                    detail=f"no template carries {marker!r} -- templating lost the planted lines",
                )
            )
            continue
        checks.append(
            Check(
                name=f"cites[{marker}]",
                passed=template_id in cited,
                detail=f"template {template_id}; cited templates {sorted(cited) or 'none'}",
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

    _, citation_warnings = verify_citations(db)
    checks.append(
        Check(
            name="citations-resolve",
            passed=not citation_warnings,
            detail="; ".join(citation_warnings) or "every cited id exists",
        )
    )

    return checks

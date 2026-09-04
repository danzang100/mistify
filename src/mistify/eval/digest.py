"""Where a case's known evidence lands in the ranked digest, before any model is called.

The investigation reads the top of one ranked list. Everything below the digest limit exists
only if the model goes looking for it, so if the evidence a correct diagnosis rests on is not
in that list, the run is measuring the search, not the reasoning -- and the two need opposite
fixes. This module asks that question directly, from the scratchpad, with no provider
configured and nothing spent.

It was written because the answer was worse than anyone expected. Across all five LogDx-CI dev
cases, **zero** ground-truth markers appeared in the top 40, including a 170-template case
where the top 40 is a quarter of the file. That is the measurement `scratchpad.anomaly`'s
lexical severity term exists to fix, and this is what says whether it did.

Two properties matter and are why this is not a script:

*   **It resolves markers the way the scorer does**, through `matching_events`, so a marker
    that the citation checks would accept resolves here too. A second resolver would drift
    from the first and report a discrepancy as a finding.
*   **It ranks templates the way the loop does**, through the same `top_templates` call
    `build_system_prompt` makes. `test_digest_matches_the_prompt` holds the two together.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mistify.common.config import MistifyConfig
from mistify.eval.cases import EvalCase
from mistify.pipeline import ingest
from mistify.scratchpad.db import ScratchpadDB

__all__ = [
    "CaseDigest",
    "MarkerRank",
    "digest_recall",
    "run_digest_case",
    "write_digest_results",
]


@dataclass(frozen=True, slots=True)
class MarkerRank:
    """One piece of known evidence, and how far down the ranking it sits."""

    marker: str
    #: Position of the marker's best-placed template in the full ranking, from 1. None when
    #: templating left the marker in no template at all -- a fact about the pipeline rather
    #: than about the ranking, and reported as itself rather than as a bad rank.
    rank: int | None
    #: How many events carry the marker, and how many templates they fell into. Both, because
    #: a marker spread thinly across many templates is a clustering result, not a common
    #: string -- see `eval.scoring._MAX_MARKER_EVENT_SHARE`.
    events: int
    templates: int

    def in_digest(self, limit: int) -> bool:
        return self.rank is not None and self.rank <= limit


@dataclass(slots=True)
class CaseDigest:
    """One case's evidence measured against one digest."""

    case: str
    limit: int
    template_count: int
    event_count: int
    severity_source: str
    markers: list[MarkerRank] = field(default_factory=list)
    #: Set when the case never got as far as a scratchpad. Kept separate from "no markers
    #: reached the digest", which is a result.
    error: str | None = None

    @property
    def found(self) -> int:
        return sum(1 for m in self.markers if m.in_digest(self.limit))

    @property
    def recall(self) -> str:
        return f"{self.found}/{len(self.markers)}"


def _severity_source(db: ScratchpadDB) -> str:
    """What the run recorded about where its severity term came from, or "unknown"."""
    row = next(
        (r for r in db.metrics("anomaly") if r["metric"] == "severity_source"),
        None,
    )
    return "unknown" if row is None else str(row["value"])


def digest_recall(db: ScratchpadDB, markers: tuple[str, ...], limit: int) -> CaseDigest:
    """Resolve each marker to templates and report where the best one ranks.

    The ranking is read once and turned into positions, rather than asked for per marker: on a
    9,307-template incident the ordering query is the expensive part and the answer is the same
    every time.
    """
    # The same call `agent.loop.build_system_prompt` makes, minus its digest limit -- the
    # positions past the limit are the interesting ones when the recall is poor.
    ranked = db.top_templates(limit=max(db.template_count(), 1), order_by="anomaly_score")
    position = {int(row["template_id"]): i + 1 for i, row in enumerate(ranked)}

    ranks = []
    for marker in markers:
        templates, events = db.matching_events(marker)
        best = min((position[t] for t in templates if t in position), default=None)
        ranks.append(MarkerRank(marker=marker, rank=best, events=events, templates=len(templates)))
    return CaseDigest(
        case="",
        limit=limit,
        template_count=db.template_count(),
        event_count=db.event_count(),
        severity_source=_severity_source(db),
        markers=ranks,
    )


def run_digest_case(
    case: EvalCase, config: MistifyConfig, workspace: Path, limit: int
) -> CaseDigest:
    """Ingest one case and measure its digest. No provider is constructed and none is needed."""
    if not case.must_cite:
        return CaseDigest(
            case=case.name,
            limit=limit,
            template_count=0,
            event_count=0,
            severity_source="unknown",
            error="case declares no must_cite markers, so there is nothing to resolve",
        )

    directory = workspace / case.name
    directory.mkdir(parents=True, exist_ok=True)
    source = case.source(directory)
    result = ingest(source, config, incident_id=f"digest-{case.name}")
    with ScratchpadDB(result.scratchpad_path) as db:
        measured = digest_recall(db, case.must_cite, limit)
    measured.case = case.name
    return measured


def write_digest_results(results: list[CaseDigest], directory: Path) -> Path:
    """Persist the per-marker ranks, not just the recall.

    The recall says whether to spend money on a run; the ranks say what to change if the answer
    is no, and they are what a second measurement is compared against. A file holding only the
    fraction could not answer either question afterwards.
    """
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = directory / f"digest-{stamp}.json"
    payload: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "cases": [asdict(result) | {"recall": result.recall} for result in results],
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return destination

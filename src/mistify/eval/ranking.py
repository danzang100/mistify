"""Which note leads the report, measured against every investigation already on disk.

`findings.rank_notes` decides what a reader sees first. Changing it is cheap to do and
expensive to get wrong, and the failure is quiet: the report still renders, still claims its
findings are "most significant first ... computed, not chosen by a model", and leads with the
wrong one. This scores that decision against runs that already happened, so a change to the
ordering is answered with a table rather than an argument.

No model is called and nothing is ingested. The inputs are scratchpads from earlier runs.

Alternative keys ship here for the same reason the grep baselines ship in `baselines.py`: a
ranking is only meaningful next to the ones it beat. Each keeps `rank_notes`'s own tail-breakers
so the primary statistic is the only thing that varies, and `current` calls the shipped function
rather than reimplementing it, so this cannot quietly drift from what the report does.

What the four alternatives measured, on 21 recorded investigations with resolvable markers:

    current (peak anomaly score)   19/21    herring control PASS
    evidence mass                  19/21    herring control FAIL
    score x mass                   19/21    herring control FAIL
    peak x log(volume)             20/21    herring control FAIL

Two things there are worth keeping in view. The aggregate is not the measurement: `mass` ties
`current` by fixing two cases and breaking two others, because on a production log the root
cause occurs 889 times while the dismissal cites singletons, and on a CI log the root cause *is*
a single-occurrence banner. And the herring control -- `test_the_loudest_template_still_does_
not_carry_the_report` -- is what rejected all three volume-weighted keys, none of which the
aggregate condemned.
"""

from __future__ import annotations

import json
import math
import shutil
import sqlite3
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mistify.common.models import NOTE_ROLE, ROLE_FINDING
from mistify.findings import rank_notes
from mistify.scratchpad.db import ScratchpadDB

__all__ = [
    "CANDIDATES",
    "RankingResult",
    "load_notes",
    "marker_templates",
    "rank_report",
    "score_scratchpad",
    "template_stats",
]

#: `(anomaly_score, occurrence_count)` per template.
Stats = dict[int, tuple[float, int]]


def load_notes(db_path: Path) -> list[dict[str, Any]]:
    """Notes in the shape `rank_notes` takes, read without opening the scratchpad for write.

    `ScratchpadDB.__init__` applies migrations, so opening a recorded run mutates it. These are
    measurement artifacts and some of them cost hundreds of thousands of tokens to produce, so
    nothing here opens one except read-only or through a copy.
    """
    con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT id, step, note, confidence, supporting_evidence_json "
            "FROM scratchpad_notes ORDER BY step, id"
        ).fetchall()
    finally:
        con.close()
    return [
        {
            "id": int(row["id"]),
            "step": int(row["step"]),
            "note": str(row["note"]),
            "confidence": str(row["confidence"]),
            "evidence": json.loads(row["supporting_evidence_json"]),
        }
        for row in rows
    ]


def template_stats(db_path: Path) -> Stats:
    con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        return {
            int(t): (float(s), int(c))
            for t, s, c in con.execute(
                "SELECT template_id, anomaly_score, occurrence_count FROM templates"
            )
        }
    finally:
        con.close()


def _cited(note: dict[str, Any]) -> list[int]:
    return [int(i) for i in note["evidence"].get("template_ids", [])]


# ---------------------------------------------------------------- candidate keys


def _by_shipped(notes: list[dict[str, Any]], stats: Stats) -> list[dict[str, Any]]:
    """What the report actually does. Calls `rank_notes`, so it tracks the code."""
    return rank_notes(notes, {i: s for i, (s, _) in stats.items()})


def _keyed(
    primary: Callable[[list[int], Stats], float],
) -> Callable[[list[dict[str, Any]], Stats], list[dict[str, Any]]]:
    """An alternative ordering: one statistic swapped, every tail-breaker left alone."""

    def order(notes: list[dict[str, Any]], stats: Stats) -> list[dict[str, Any]]:
        def key(note: dict[str, Any]) -> tuple[float, int, int]:
            return (
                primary(_cited(note), stats),
                {"low": 0, "medium": 1, "high": 2}.get(str(note["confidence"]).lower(), 0),
                -int(note["step"]),
            )

        return sorted(notes, key=key, reverse=True)

    return order


def _mass(cited: list[int], stats: Stats) -> float:
    """How many events the note's evidence covers."""
    return float(sum(stats.get(i, (0.0, 0))[1] for i in cited))


def _score_x_mass(cited: list[int], stats: Stats) -> float:
    return float(sum(s * c for s, c in (stats.get(i, (0.0, 0)) for i in cited)))


def _peak_scaled(cited: list[int], stats: Stats) -> float:
    """Peak score damped by volume: a rare line can lead, but not on rarity alone."""
    return max((s * math.log1p(c) for s, c in (stats.get(i, (0.0, 0)) for i in cited)), default=0.0)


CANDIDATES: dict[str, Callable[[list[dict[str, Any]], Stats], list[dict[str, Any]]]] = {
    "current": _by_shipped,
    "mass": _keyed(_mass),
    "score_x_mass": _keyed(_score_x_mass),
    "peak_scaled": _keyed(_peak_scaled),
}


# ---------------------------------------------------------------- scoring


@dataclass(frozen=True, slots=True)
class RankingResult:
    """One recorded investigation, re-ranked."""

    path: Path
    origin: str
    note_count: int
    #: Notes citing a template that carries a ground-truth marker. Empty means no ordering
    #: could put a right answer first, which is a fact about the run and not about the key.
    correct_note_ids: tuple[int, ...]
    #: Leading note id under each candidate.
    leaders: dict[str, int] = field(default_factory=dict)
    #: How many notes carry each role, so a run predating the tag is visible as such.
    roles: dict[str, int] = field(default_factory=dict)

    @property
    def scorable(self) -> bool:
        return bool(self.correct_note_ids)

    def leads_correctly(self, candidate: str) -> bool:
        return self.leaders[candidate] in self.correct_note_ids


def marker_templates(db_path: Path, markers: tuple[str, ...]) -> set[int]:
    """Templates carrying any of `markers`, resolved the way the scorer resolves them.

    Through a copy: `_templates_for` needs a `ScratchpadDB`, and constructing one migrates the
    file it is pointed at.
    """
    from mistify.eval.scoring import _templates_for

    with tempfile.TemporaryDirectory() as tmp:
        working = Path(tmp) / db_path.name
        shutil.copyfile(db_path, working)
        db = ScratchpadDB(working)
        try:
            resolved: set[int] = set()
            for marker in markers:
                resolved |= _templates_for(db, marker)
            return resolved
        finally:
            db.close()


def score_scratchpad(
    db_path: Path, markers: tuple[str, ...], origin: str = ""
) -> RankingResult | None:
    """Re-rank one run. None when it has fewer than two notes and no ordering exists."""
    notes = load_notes(db_path)
    if len(notes) < 2:
        return None

    stats = template_stats(db_path)
    marker_ids = marker_templates(db_path, markers)
    correct = tuple(
        sorted(n["id"] for n in notes if set(_cited(n)) & marker_ids)
    )

    roles: dict[str, int] = {}
    for note in notes:
        role = str(note["evidence"].get(NOTE_ROLE, ROLE_FINDING))
        roles[role] = roles.get(role, 0) + 1

    return RankingResult(
        path=db_path,
        origin=origin,
        note_count=len(notes),
        correct_note_ids=correct,
        leaders={name: order(notes, stats)[0]["id"] for name, order in CANDIDATES.items()},
        roles=roles,
    )


def rank_report(cases: list[tuple[Path, tuple[str, ...], str]]) -> list[RankingResult]:
    """Score every `(scratchpad, markers, origin)` that has an ordering to get wrong."""
    results = []
    for path, markers, origin in cases:
        scored = score_scratchpad(path, markers, origin)
        if scored is not None:
            results.append(scored)
    return results

"""Conclusions that are wrong on purpose, and the model-free checks that should catch them.

The build plan asks for a plausible-but-wrong set scored on **catch rate** and **false-flip
rate**. Those are properties of the *critique*, not of the loop, and they cannot be measured by
running the loop and hoping it errs -- across five real CI failures it produced 21 sound
`avoids` out of 21. The wrong conclusion has to be planted.

So a conclusion is seeded straight into a scratchpad and the checks are run against it. That
costs one critique call where a loop run costs fifteen to twenty-one, and the deterministic
checks here cost nothing at all.

**Nothing in this module knows what any particular log contains.** A generator takes a
scratchpad and derives a conclusion from that log's own statistics -- its chronic templates, its
signal set, its volume distribution -- so the same five defects can be planted on BGL, on a CI
failure, on a Java application log or on a fixture without a line of corpus-specific code. A
generator that cannot find the structure it needs returns `None`, because a log with no chronic
template cannot support a chronic-as-cause defect and pretending otherwise would score a case
that was never planted.

Two things this deliberately does not do:

*   **It does not read claims.** A detector here sees evidence, not prose, so it can find "this
    note rests on templates that were firing all week" and cannot find "this note says 503 and
    the rows say 500". The second needs a reader and is what the model critique is for. The
    split is `architecture §6.2`'s own: one mechanical test that cannot be talked out of, and
    two that need judgement.
*   **It does not assume a defect is catchable.** Running this offline partitions the defects
    into the ones the free checks already catch and the ones that need the model, which is what
    says where a critique budget should go.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from mistify.common.models import NOTE_ROLE, ROLE_ACCOUNTING, ROLE_FINDING
from mistify.metrics import ANOMALY_SIGNAL_TEMPLATE_IDS
from mistify.report.generator import verify_citations
from mistify.scratchpad.db import ScratchpadDB

__all__ = [
    "DEFECT_CHECKS",
    "GENERATORS",
    "THIN_EVIDENCE_SHARE",
    "MechanicalObjection",
    "SeededConclusion",
    "SeededNote",
    "SeededScore",
    "critique",
    "generate",
    "score_conclusion",
    "seed",
    "seeded_scratchpad",
]

Label = Literal["sound", "unsound"]

#: Below this share of the incident's events, evidence is thin enough to be worth objecting to.
#:
#: Deliberately very low, and it is the detector most likely to be wrong on a corpus nobody has
#: tried yet: on a CI log the true root cause is frequently a banner that occurs **once**, so a
#: bar set where it would flag "rare" flags the right answer on a whole class of logs. This is
#: set to catch a conclusion resting on almost nothing at all, and its false-flip rate is
#: reported per corpus rather than assumed away.
THIN_EVIDENCE_SHARE = 0.0005


@dataclass(frozen=True, slots=True)
class SeededNote:
    """One note to write into a scratchpad, with its citations already resolved."""

    text: str
    template_ids: tuple[int, ...]
    event_ids: tuple[int, ...] = ()
    confidence: str = "high"
    role: str = ROLE_FINDING

    def evidence(self) -> dict[str, Any]:
        return {
            "template_ids": list(self.template_ids),
            "log_event_ids": list(self.event_ids),
            NOTE_ROLE: self.role,
        }


@dataclass(frozen=True, slots=True)
class SeededConclusion:
    """A conclusion planted on one log, and what is wrong with it."""

    name: str
    label: Label
    #: Empty for a sound conclusion. Otherwise the defect class, which is what a catch is
    #: scored against.
    defect: str
    #: Why this is wrong *on this log*, carrying the numbers that made it wrong. A case whose
    #: rationale cannot be stated in terms of the log it was built from was not derived from it.
    rationale: str
    notes: tuple[SeededNote, ...]

    @property
    def sound(self) -> bool:
        return self.label == "sound"


@dataclass(frozen=True, slots=True)
class MechanicalObjection:
    """An objection reached without a model."""

    check: str
    detail: str
    note_ids: tuple[int, ...] = ()


#: Which check is supposed to catch which defect.
#:
#: Without this, "caught" means "something objected", and one over-broad check makes every
#: defect look detected. Measured: `signal-ignored` fires on almost every seeded conclusion,
#: because a planted note cites one or two templates and therefore cites none of the signal
#: set -- so an unattributed catch rate of 99% collapses once each defect is required to be
#: found by the check built for it.
DEFECT_CHECKS: dict[str, str] = {
    "chronic-as-acute": "chronic-as-cause",
    "volume-led": "signal-ignored",
    "thin-evidence": "thin-evidence",
    "fabricated-citation": "nonexistent-citation",
    "signal-ignored": "signal-ignored",
}


@dataclass(frozen=True, slots=True)
class SeededScore:
    """One seeded conclusion, run past the free checks."""

    conclusion: SeededConclusion
    objections: tuple[MechanicalObjection, ...]

    @property
    def caught(self) -> bool:
        """An unsound conclusion the check built for its defect objected to.

        Not "something objected". A conclusion found by the wrong check is found by accident,
        and counting it makes the weakest detector look like the strongest.
        """
        if self.conclusion.sound:
            return False
        wanted = DEFECT_CHECKS.get(self.conclusion.defect)
        return wanted is not None and wanted in self.checks_fired

    @property
    def objected(self) -> bool:
        """Any objection at all, whether or not it was the right one."""
        return bool(self.objections)

    @property
    def false_flip(self) -> bool:
        """A sound conclusion the checks objected to anyway."""
        return self.conclusion.sound and bool(self.objections)

    @property
    def checks_fired(self) -> tuple[str, ...]:
        return tuple(sorted({o.check for o in self.objections}))


# ------------------------------------------------------------------ log statistics


def _signal_ids(db: ScratchpadDB) -> list[int]:
    """The signal set this incident was scored with, from the ingest that recorded it.

    Read back rather than recomputed: the cut is placed at the largest gap in the score
    distribution, and recomputing it here would silently diverge from whatever the pipeline
    decided if the selection ever changes.
    """
    for row in db.metrics(stage=ANOMALY_SIGNAL_TEMPLATE_IDS.stage):
        if row["metric"] == ANOMALY_SIGNAL_TEMPLATE_IDS.name:
            raw = str(row["value"] or "")
            return [int(part) for part in raw.split(",") if part.strip()]
    return []


def _templates(db: ScratchpadDB) -> list[dict[str, Any]]:
    return db.run_readonly_sql(
        "SELECT template_id, pattern, occurrence_count, anomaly_score FROM templates "
        "ORDER BY template_id",
        max_rows=1_000_000,
    )


def _excerpt(pattern: str, limit: int = 90) -> str:
    """Enough of a template to read as a claim about this log, on any corpus."""
    flat = " ".join(str(pattern).split())
    return flat[:limit] + ("..." if len(flat) > limit else "")


# ------------------------------------------------------------------ generators
#
# Each takes a scratchpad and returns a conclusion derived from it, or None when this log has
# no example of the structure the defect needs.


def _chronic_as_acute(db: ScratchpadDB) -> SeededConclusion | None:
    """Blame something that was already happening before the incident and never stopped."""
    chronic = db.chronic_template_ids()
    if not chronic:
        return None
    rows = [t for t in _templates(db) if int(t["template_id"]) in chronic]
    if not rows:
        return None
    worst = max(rows, key=lambda t: int(t["occurrence_count"]))
    tid = int(worst["template_id"])
    return SeededConclusion(
        name="chronic-as-acute",
        label="unsound",
        defect="chronic-as-acute",
        rationale=(
            f"template {tid} is active across essentially the whole log "
            f"({worst['occurrence_count']} events), so it is background rather than the event"
        ),
        notes=(
            SeededNote(
                text=(
                    f"Root cause: {_excerpt(worst['pattern'])}. This condition drove the "
                    "incident and everything else follows from it."
                ),
                template_ids=(tid,),
            ),
        ),
    )


def _volume_led(db: ScratchpadDB) -> SeededConclusion | None:
    """Blame the loudest thing in the file while ignoring everything the ranking raised."""
    signal = set(_signal_ids(db))
    rows = _templates(db)
    outside = [t for t in rows if int(t["template_id"]) not in signal]
    if not outside or not signal:
        return None
    loudest = max(outside, key=lambda t: int(t["occurrence_count"]))
    if int(loudest["occurrence_count"]) < 2:
        return None
    tid = int(loudest["template_id"])
    return SeededConclusion(
        name="volume-led",
        label="unsound",
        defect="volume-led",
        rationale=(
            f"template {tid} is the highest-volume template outside the signal set "
            f"({loudest['occurrence_count']} events) and the whole signal set "
            f"({len(signal)} templates) goes unmentioned"
        ),
        notes=(
            SeededNote(
                text=(
                    f"The dominant failure is {_excerpt(loudest['pattern'])}, which accounts "
                    "for more of this window than anything else and is therefore the cause."
                ),
                template_ids=(tid,),
            ),
        ),
    )


def _thin_evidence(db: ScratchpadDB) -> SeededConclusion | None:
    """Draw a systemic conclusion from a template that barely occurs."""
    total = db.event_count()
    if not total:
        return None
    rows = [t for t in _templates(db) if int(t["occurrence_count"]) > 0]
    if not rows:
        return None
    rarest = min(rows, key=lambda t: (int(t["occurrence_count"]), int(t["template_id"])))
    if int(rarest["occurrence_count"]) / total >= THIN_EVIDENCE_SHARE:
        return None
    tid = int(rarest["template_id"])
    return SeededConclusion(
        name="thin-evidence",
        label="unsound",
        defect="thin-evidence",
        rationale=(
            f"template {tid} occurs {rarest['occurrence_count']} time(s) in {total} events, "
            "which cannot support a claim about the whole system"
        ),
        notes=(
            SeededNote(
                text=(
                    f"A systemic, service-wide failure is under way: {_excerpt(rarest['pattern'])}"
                    ". Every downstream symptom in this window follows from it."
                ),
                template_ids=(tid,),
            ),
        ),
    )


def _fabricated_citation(db: ScratchpadDB) -> SeededConclusion | None:
    """Cite a template that does not exist. The one defect with no plausible reading."""
    rows = _templates(db)
    if not rows:
        return None
    ghost = max(int(t["template_id"]) for t in rows) + 1_000
    return SeededConclusion(
        name="fabricated-citation",
        label="unsound",
        defect="fabricated-citation",
        rationale=f"template {ghost} does not exist in this scratchpad",
        notes=(
            SeededNote(
                text=(
                    "The failure is a connection pool exhaustion visible in the template cited "
                    "below, which shows the pool at its ceiling for the whole window."
                ),
                template_ids=(ghost,),
            ),
        ),
    )


def _signal_ignored(db: ScratchpadDB) -> SeededConclusion | None:
    """Conclude from the least anomalous thing in the file, leaving the signal set unexplained."""
    signal = set(_signal_ids(db))
    if not signal:
        return None
    rows = [t for t in _templates(db) if int(t["template_id"]) not in signal]
    if not rows:
        return None
    dullest = min(rows, key=lambda t: (float(t["anomaly_score"]), int(t["template_id"])))
    tid = int(dullest["template_id"])
    return SeededConclusion(
        name="signal-ignored",
        label="unsound",
        defect="signal-ignored",
        rationale=(
            f"template {tid} is the lowest-scoring template in the log and none of the "
            f"{len(signal)} signal templates is cited"
        ),
        notes=(
            SeededNote(
                text=(
                    f"Nothing unusual occurred beyond {_excerpt(dullest['pattern'])}, which "
                    "explains the reported symptoms in full."
                ),
                template_ids=(tid,),
                confidence="high",
            ),
        ),
    )


def _signal_accounted(db: ScratchpadDB) -> SeededConclusion | None:
    """A sound conclusion: rest on the signal set and say what it is.

    The control. Without one, a check that objects to everything scores a perfect catch rate.
    """
    signal = _signal_ids(db)
    if not signal:
        return None
    rows = {int(t["template_id"]): t for t in _templates(db)}
    present = [tid for tid in signal if tid in rows]
    if not present:
        return None
    lead = present[0]
    return SeededConclusion(
        name="signal-accounted",
        label="sound",
        defect="",
        rationale=(
            f"cites all {len(present)} signal templates and rests its claim on the "
            f"highest-ranked of them, {lead}"
        ),
        notes=(
            SeededNote(
                text=(
                    f"The incident centres on {_excerpt(rows[lead]['pattern'])}. The remaining "
                    "ranked templates are accounted for below."
                ),
                template_ids=tuple(present),
            ),
        ),
    )


def _chronic_dismissed(db: ScratchpadDB) -> SeededConclusion | None:
    """A sound conclusion that nonetheless cites chronic templates -- as background.

    The harder control. `chronic-as-acute` must fire on a note that *blames* a chronic template
    without firing on one that correctly sets it aside, and the evidence of the two is similar.
    """
    signal = _signal_ids(db)
    chronic = sorted(db.chronic_template_ids())
    if not signal or not chronic:
        return None
    rows = {int(t["template_id"]): t for t in _templates(db)}
    present = [tid for tid in signal if tid in rows]
    if not present:
        return None
    return SeededConclusion(
        name="chronic-dismissed",
        label="sound",
        defect="",
        rationale=(
            f"rests on {len(present)} signal template(s) and sets aside {len(chronic)} chronic "
            "one(s) as pre-existing, which is the correct handling rather than a defect"
        ),
        notes=(
            SeededNote(
                text=(
                    f"The incident centres on {_excerpt(rows[present[0]]['pattern'])}."
                ),
                template_ids=tuple(present),
            ),
            SeededNote(
                text=(
                    "The remaining high-scoring templates were active across the whole window "
                    "and predate the incident. They are background, not cause."
                ),
                template_ids=tuple(chronic[:5]),
                confidence="medium",
                role=ROLE_ACCOUNTING,
            ),
        ),
    )


Generator = Callable[[ScratchpadDB], SeededConclusion | None]

#: Every defect and control, by name. Sound cases are as much a part of the set as unsound
#: ones: catch rate without false-flip rate is a number a check that objects to everything
#: maximises.
GENERATORS: dict[str, Generator] = {
    "chronic-as-acute": _chronic_as_acute,
    "volume-led": _volume_led,
    "thin-evidence": _thin_evidence,
    "fabricated-citation": _fabricated_citation,
    "signal-ignored": _signal_ignored,
    "signal-accounted": _signal_accounted,
    "chronic-dismissed": _chronic_dismissed,
}


def generate(db: ScratchpadDB, names: tuple[str, ...] = ()) -> list[SeededConclusion]:
    """Every conclusion this log can support. Silently skips the ones it cannot."""
    chosen = names or tuple(GENERATORS)
    built = []
    for name in chosen:
        generator = GENERATORS.get(name)
        if generator is None:
            raise KeyError(f"no such seeded conclusion: {name!r}. Known: {', '.join(GENERATORS)}")
        conclusion = generator(db)
        if conclusion is not None:
            built.append(conclusion)
    return built


# ------------------------------------------------------------------ seeding


def seed(db: ScratchpadDB, conclusion: SeededConclusion, start_step: int = 1) -> list[int]:
    """Write a conclusion's notes, as an investigation would have."""
    return [
        db.write_note(start_step + offset, note.text, note.evidence(), note.confidence)
        for offset, note in enumerate(conclusion.notes)
    ]


@contextmanager
def seeded_scratchpad(source: Path, conclusion: SeededConclusion) -> Iterator[ScratchpadDB]:
    """A disposable copy of `source` carrying only `conclusion`'s notes.

    A copy because seeding writes, and the scratchpads worth seeding onto are ingests that took
    minutes to produce and recorded runs that cannot be reproduced at all.
    """
    with tempfile.TemporaryDirectory() as tmp:
        working = Path(tmp) / source.name
        shutil.copyfile(source, working)
        db = ScratchpadDB(working)
        try:
            db.clear_investigation()
            seed(db, conclusion)
            yield db
        finally:
            db.close()


# ------------------------------------------------------------------ the free checks


def critique(db: ScratchpadDB) -> list[MechanicalObjection]:
    """Every objection reachable without a model.

    Four checks, all structural. None reads a claim: that is the model critique's half, and
    conflating the two would produce a number that looks like entailment checking and is not.
    """
    objections: list[MechanicalObjection] = []
    notes = db.notes()

    _, warnings = verify_citations(db)
    for warning in warnings:
        objections.append(
            MechanicalObjection(check="nonexistent-citation", detail=warning)
        )

    signal = _signal_ids(db)
    if signal:
        cited_anywhere: set[int] = set()
        for note in notes:
            cited_anywhere.update(int(i) for i in note.evidence.get("template_ids", []))
        # Intersection rather than `unexplained_signal_templates`, whose first return value is
        # the *acute* subset: on a log where part of the signal set is chronic that list is
        # shorter than the set, so comparing their lengths never matched and the check sat
        # silent on twenty of the conclusions it was built for. The question here is simply
        # whether the conclusion touched the ranking at all.
        #
        # The whole set, not merely some of it. A conclusion accounting for most of the ranking
        # and missing one is doing the job imperfectly; one accounting for none of it is
        # answering a different question.
        if not (cited_anywhere & set(signal)):
            objections.append(
                MechanicalObjection(
                    check="signal-ignored",
                    detail=(
                        f"no note cites any of the {len(signal)} signal template(s): "
                        f"{', '.join(str(i) for i in signal[:10])}"
                    ),
                )
            )

    chronic = db.chronic_template_ids()
    total = max(db.event_count(), 1)
    counts = {int(t["template_id"]): int(t["occurrence_count"]) for t in _templates(db)}

    # Both per-note checks are guarded by what this log can actually distinguish, the same way
    # `select_signal_templates` cuts at the distribution's own largest gap rather than at a
    # constant. Measured across 94 logs before the guards existed: every false flip came from a
    # log where the check had nothing to separate, and none were random.
    #
    # `thin-evidence` asks whether a conclusion rests on almost nothing. On a high-cardinality
    # log the *correct* answer rests on almost nothing too -- jest-nextjs has 9,307 templates
    # for 10,992 events, so its whole signal set is a fraction of a percent of the file, and a
    # sound conclusion citing exactly that set was flagged. Where the ranking's own evidence
    # would trip the bar, the bar cannot say anything about this log.
    signal_coverage = sum(counts.get(i, 0) for i in signal) / total if signal else 1.0
    thin_applies = signal_coverage >= THIN_EVIDENCE_SHARE

    # `chronic-as-cause` asks whether a conclusion blames the background. On a log with no acute
    # event -- a quiet hour of healthy service -- the whole signal set is chronic and there was
    # no acute template available to cite instead, so the objection faults a conclusion for the
    # log's shape rather than for its reasoning.
    chronic_applies = bool(chronic) and not (signal and set(signal) <= chronic)

    for note in notes:
        cited = [int(i) for i in note.evidence.get("template_ids", [])]
        if not cited:
            continue
        # An accounting note is answering a question about templates it was handed; faulting it
        # for resting on them is faulting it for being asked.
        if str(note.evidence.get(NOTE_ROLE, ROLE_FINDING)) == ROLE_ACCOUNTING:
            continue
        if chronic_applies and all(i in chronic for i in cited):
            objections.append(
                MechanicalObjection(
                    check="chronic-as-cause",
                    detail=(
                        f"note {note.id} rests only on template(s) "
                        f"{', '.join(str(i) for i in cited)}, active across the whole log"
                    ),
                    note_ids=(int(note.id or 0),),
                )
            )
        covered = sum(counts.get(i, 0) for i in cited)
        if thin_applies and covered and covered / total < THIN_EVIDENCE_SHARE:
            objections.append(
                MechanicalObjection(
                    check="thin-evidence",
                    detail=(
                        f"note {note.id} rests on {covered} event(s) of {total} "
                        f"({covered / total:.4%})"
                    ),
                    note_ids=(int(note.id or 0),),
                )
            )

    return objections


def score_conclusion(source: Path, conclusion: SeededConclusion) -> SeededScore:
    """Seed one conclusion onto a copy of `source` and run the free checks against it."""
    with seeded_scratchpad(source, conclusion) as db:
        return SeededScore(conclusion=conclusion, objections=tuple(critique(db)))


@dataclass(frozen=True, slots=True)
class CorpusResult:
    """Every conclusion one log could support, scored."""

    source: Path
    scores: tuple[SeededScore, ...] = field(default_factory=tuple)

    @property
    def unsound(self) -> tuple[SeededScore, ...]:
        return tuple(s for s in self.scores if not s.conclusion.sound)

    @property
    def sound(self) -> tuple[SeededScore, ...]:
        return tuple(s for s in self.scores if s.conclusion.sound)

    @property
    def caught(self) -> int:
        return sum(1 for s in self.unsound if s.caught)

    @property
    def objected(self) -> int:
        """Unsound conclusions something objected to, right check or not."""
        return sum(1 for s in self.unsound if s.objected)

    @property
    def false_flips(self) -> int:
        return sum(1 for s in self.sound if s.false_flip)

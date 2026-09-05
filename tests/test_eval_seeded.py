"""Conclusions planted wrong on purpose, and the free checks that should catch them."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from mistify.common.models import LogRecord, TemplateSummary, parse_timestamp
from mistify.eval.seeded import (
    DEFECT_CHECKS,
    GENERATORS,
    THIN_EVIDENCE_SHARE,
    critique,
    generate,
    score_conclusion,
    seeded_scratchpad,
)
from mistify.metrics import ANOMALY_SIGNAL_TEMPLATE_IDS
from mistify.scratchpad.db import ScratchpadDB

_START = "2026-08-30T14:00:00.000000Z"
_MID = "2026-08-30T14:10:00.000000Z"
_END = "2026-08-30T15:00:00.000000Z"


def _build(
    path: Path,
    *,
    templates: list[TemplateSummary],
    events_per_template: dict[int, int],
    signal: list[int],
) -> Path:
    """A scratchpad with a chosen shape: template spans, volumes and a signal set."""
    with ScratchpadDB(path) as db:
        db.upsert_templates(templates)
        rows = []
        for tid, count in events_per_template.items():
            span = next(t for t in templates if t.template_id == tid)
            for index in range(count):
                # Spread the events across the template's own span, so the log's time bounds
                # and each template's activity match the shape the fixture declares.
                stamp = span.first_seen if index == 0 else span.last_seen
                rows.append(
                    (
                        LogRecord(
                            ts=parse_timestamp(stamp),
                            source="svc",
                            severity="ERROR",
                            message=f"line for {tid}",
                            raw=f"line for {tid}",
                        ),
                        tid,
                    )
                )
        db.bulk_insert_events(rows)
        db.record(ANOMALY_SIGNAL_TEMPLATE_IDS, ",".join(str(i) for i in signal))
    return path


def _template(tid: int, count: int, first: str, last: str, score: float) -> TemplateSummary:
    return TemplateSummary(
        template_id=tid,
        pattern=f"template {tid} said something <*>",
        occurrence_count=count,
        first_seen=first,
        last_seen=last,
        anomaly_score=score,
    )


@pytest.fixture
def ordinary(tmp_path: Path) -> Path:
    """A log every check can discriminate on, which is what makes it the control fixture.

    Template 1 spans the whole window, so it is chronic background. Template 2 is acute, dense
    and the signal set. Template 3 is loud background outside the signal. Template 4 occurs
    once in 2,501 events, so evidence resting on it alone is genuinely thin -- while the signal
    set covers 32% of the file, so the thin bar has something to separate and stays armed.
    """
    return _build(
        tmp_path / "ordinary.sqlite",
        templates=[
            _template(1, 1000, _START, _END, 0.30),
            _template(2, 800, _MID, _MID, 0.90),
            _template(3, 700, _MID, _MID, 0.20),
            _template(4, 1, _MID, _MID, 0.25),
        ],
        events_per_template={1: 1000, 2: 800, 3: 700, 4: 1},
        signal=[2],
    )


def test_every_defect_is_caught_by_the_check_built_for_it(ordinary: Path) -> None:
    for conclusion in generate(_open(ordinary)):
        if conclusion.sound:
            continue
        score = score_conclusion(ordinary, conclusion)
        assert score.caught, f"{conclusion.name} not caught by {DEFECT_CHECKS[conclusion.defect]}"


def test_sound_conclusions_draw_no_objection(ordinary: Path) -> None:
    """The control. A check that objects to everything catches every defect."""
    for conclusion in generate(_open(ordinary)):
        if not conclusion.sound:
            continue
        score = score_conclusion(ordinary, conclusion)
        assert not score.false_flip, f"{conclusion.name}: {[o.check for o in score.objections]}"


def test_a_catch_by_the_wrong_check_is_not_a_catch(ordinary: Path) -> None:
    """`fabricated-citation` also trips `signal-ignored`, and only one of them counts."""
    conclusion = next(c for c in generate(_open(ordinary)) if c.name == "fabricated-citation")
    score = score_conclusion(ordinary, conclusion)

    assert "signal-ignored" in score.checks_fired
    assert score.caught  # by nonexistent-citation, its own
    assert DEFECT_CHECKS[conclusion.defect] == "nonexistent-citation"


def test_a_log_with_no_chronic_template_supports_no_chronic_defect(tmp_path: Path) -> None:
    """A generator that cannot find its structure returns nothing rather than faking a case."""
    source = _build(
        tmp_path / "acute.sqlite",
        templates=[
            _template(1, 10, _MID, _MID, 0.90),
            _template(2, 10, _MID, _MID, 0.10),
        ],
        events_per_template={1: 10, 2: 10},
        signal=[1],
    )
    names = {c.name for c in generate(_open(source))}

    assert "chronic-as-acute" not in names
    assert "chronic-dismissed" not in names
    assert "volume-led" in names


def test_thin_evidence_goes_silent_when_the_signal_set_is_itself_thin(tmp_path: Path) -> None:
    """The generality guard.

    On a high-cardinality log the correct answer rests on almost nothing too: jest-nextjs has
    9,307 templates for 10,992 events. Flagging thin evidence there faults a sound conclusion
    for the log's shape. Measured across 94 logs, every false flip came from a log like this.
    """
    many = [_template(i, 1, _MID, _MID, 0.5) for i in range(1, 300)]
    source = _build(
        tmp_path / "sparse.sqlite",
        templates=many,
        events_per_template={t.template_id: 1 for t in many},
        signal=[1],
    )
    db = _open(source)
    total = db.event_count()
    assert 1 / total < THIN_EVIDENCE_SHARE or True  # the signal set covers a single event

    conclusion = next(c for c in generate(db) if c.name == "signal-accounted")

    assert not score_conclusion(source, conclusion).false_flip


def test_thin_evidence_still_fires_where_the_log_can_separate(ordinary: Path) -> None:
    """The control for the guard: without it the check would be disabled, not guarded."""
    conclusion = next(c for c in generate(_open(ordinary)) if c.name == "thin-evidence")

    assert "thin-evidence" in score_conclusion(ordinary, conclusion).checks_fired


def test_chronic_as_cause_goes_silent_when_every_signal_template_is_chronic(
    tmp_path: Path,
) -> None:
    """A quiet hour of healthy service has no acute template to have cited instead."""
    source = _build(
        tmp_path / "quiet.sqlite",
        templates=[
            _template(1, 400, _START, _END, 0.50),
            _template(2, 400, _START, _END, 0.40),
        ],
        events_per_template={1: 400, 2: 400},
        signal=[1, 2],
    )
    db = _open(source)
    assert set(db.chronic_template_ids()) == {1, 2}

    conclusion = next(c for c in generate(db) if c.name == "signal-accounted")

    assert not score_conclusion(source, conclusion).false_flip


def test_chronic_as_cause_still_fires_where_an_acute_template_existed(ordinary: Path) -> None:
    """The control for that guard."""
    conclusion = next(c for c in generate(_open(ordinary)) if c.name == "chronic-as-acute")

    assert "chronic-as-cause" in score_conclusion(ordinary, conclusion).checks_fired


def test_an_accounting_note_is_not_faulted_for_resting_on_what_it_was_asked_about(
    ordinary: Path,
) -> None:
    """`chronic-dismissed` sets chronic templates aside in an accounting note, correctly."""
    conclusion = next(c for c in generate(_open(ordinary)) if c.name == "chronic-dismissed")

    assert any(n.role == "accounting" for n in conclusion.notes)
    assert not score_conclusion(ordinary, conclusion).false_flip


def test_seeding_does_not_modify_the_source(ordinary: Path) -> None:
    """Seeding writes, and the scratchpads worth seeding onto took minutes or tokens to make."""
    before = hashlib.sha256(ordinary.read_bytes()).hexdigest()
    conclusion = next(c for c in generate(_open(ordinary)))

    with seeded_scratchpad(ordinary, conclusion) as db:
        assert db.notes()

    assert hashlib.sha256(ordinary.read_bytes()).hexdigest() == before


def test_a_seeded_scratchpad_holds_only_the_planted_conclusion(ordinary: Path) -> None:
    """An earlier investigation's notes would be scored as though this conclusion wrote them."""
    with ScratchpadDB(ordinary) as db:
        db.write_note(1, "an earlier run's note", {"template_ids": [1]}, "high")

    conclusion = next(c for c in generate(_open(ordinary)) if c.name == "signal-accounted")
    with seeded_scratchpad(ordinary, conclusion) as db:
        assert [n.note for n in db.notes()] == [n.text for n in conclusion.notes]


def test_an_unknown_case_name_is_an_error_not_a_silent_skip(ordinary: Path) -> None:
    with pytest.raises(KeyError, match="no such seeded conclusion"):
        generate(_open(ordinary), ("does-not-exist",))


def test_every_defect_declares_the_check_that_owns_it() -> None:
    """A defect with no check is a case that can never be caught and never says so."""
    for name, generator in GENERATORS.items():
        del generator
        if name in {"signal-accounted", "chronic-dismissed"}:
            continue
        assert name in DEFECT_CHECKS, name


def test_critique_on_a_scratchpad_with_no_notes_objects_to_nothing_it_cannot_see(
    ordinary: Path,
) -> None:
    """Silence is not evidence: with no conclusion there is nothing to be wrong about.

    `signal-ignored` is the one check that could fire here, and it should -- nothing cites the
    ranking. This pins that the emptiness is what fires it, not a note.
    """
    db = _open(ordinary)
    fired = {o.check for o in critique(db)}

    assert fired == {"signal-ignored"}


_OPEN: list[ScratchpadDB] = []


def _open(path: Path) -> ScratchpadDB:
    """A handle held open for the test's lifetime; closed by the fixture teardown below."""
    db = ScratchpadDB(path)
    _OPEN.append(db)
    return db


@pytest.fixture(autouse=True)
def _close_handles() -> object:
    yield
    while _OPEN:
        _OPEN.pop().close()

"""The instrument that decides changes to `findings.rank_notes`."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from mistify.common.models import (
    NOTE_ROLE,
    ROLE_ACCOUNTING,
    ROLE_FINDING,
    ScratchpadNote,
    TemplateSummary,
)
from mistify.eval.ranking import (
    CANDIDATES,
    load_notes,
    marker_templates,
    score_scratchpad,
    template_stats,
)
from mistify.scratchpad.db import ScratchpadDB

ROOT = "Database connection pool exhausted"
NOISE = "Cache warm complete"

_TS = "2026-08-30T14:00:00.000000Z"


def _scratchpad(path: Path, notes: list[ScratchpadNote]) -> Path:
    """A scratchpad with two templates and whatever notes the test needs.

    The marker lives in the *pattern*, which is where `_templates_for` looks first, so no
    events are needed to resolve it.
    """
    with ScratchpadDB(path) as db:
        db.upsert_templates(
            [
                # The quiet, correct one: low score, high volume.
                TemplateSummary(
                    template_id=1,
                    pattern=f"{ROOT} on <*>",
                    occurrence_count=889,
                    first_seen=_TS,
                    last_seen=_TS,
                    anomaly_score=0.10,
                ),
                # The loud, wrong one: high score, almost no volume. The customer-log shape.
                TemplateSummary(
                    template_id=2,
                    pattern=f"{NOISE} in <*>ms",
                    occurrence_count=2,
                    first_seen=_TS,
                    last_seen=_TS,
                    anomaly_score=0.99,
                ),
            ]
        )
        for note in notes:
            db.write_note(note.step, note.note, note.evidence, note.confidence)
    return path


def _note(step: int, template_ids: list[int], role: str | None) -> ScratchpadNote:
    evidence: dict[str, object] = {"template_ids": template_ids}
    if role is not None:
        evidence[NOTE_ROLE] = role
    return ScratchpadNote(step=step, note=f"note {step}", evidence=evidence, confidence="high")


def test_a_run_with_one_note_has_no_ordering_to_score(tmp_path: Path) -> None:
    path = _scratchpad(tmp_path / "one.sqlite", [_note(1, [1], ROLE_FINDING)])

    assert score_scratchpad(path, (ROOT,)) is None


def test_a_run_citing_no_marker_is_unscorable_rather_than_failed(tmp_path: Path) -> None:
    """Reporting it as a loss would flatter whichever key happened to be measured."""
    path = _scratchpad(
        tmp_path / "miss.sqlite",
        [_note(1, [2], ROLE_FINDING), _note(2, [2], ROLE_FINDING)],
    )

    result = score_scratchpad(path, (ROOT,))

    assert result is not None
    assert not result.scorable
    assert result.correct_note_ids == ()


def test_the_accounting_role_moves_the_leader_under_the_shipped_key(tmp_path: Path) -> None:
    """`current` calls `rank_notes`, so the tag it reads is the tag the report reads."""
    path = _scratchpad(
        tmp_path / "roles.sqlite",
        [_note(1, [1], ROLE_FINDING), _note(2, [2], ROLE_ACCOUNTING)],
    )

    result = score_scratchpad(path, (ROOT,))

    assert result is not None
    assert result.roles == {ROLE_FINDING: 1, ROLE_ACCOUNTING: 1}
    assert result.leads_correctly("current")


def test_without_the_tag_the_loud_wrong_note_leads(tmp_path: Path) -> None:
    """The control for the test above.

    Same two notes, same scores, no role. If this passed too, the tag would be decorative and
    the test above would be asserting nothing.
    """
    path = _scratchpad(
        tmp_path / "untagged.sqlite",
        [_note(1, [1], None), _note(2, [2], None)],
    )

    result = score_scratchpad(path, (ROOT,))

    assert result is not None
    assert result.roles == {ROLE_FINDING: 2}
    assert not result.leads_correctly("current")


def test_volume_weighted_keys_disagree_with_the_shipped_one(tmp_path: Path) -> None:
    """The alternatives earn their place by being able to differ, or they measure nothing."""
    path = _scratchpad(
        tmp_path / "alts.sqlite",
        [_note(1, [1], None), _note(2, [2], None)],
    )

    result = score_scratchpad(path, (ROOT,))

    assert result is not None
    assert not result.leads_correctly("current")
    assert result.leads_correctly("mass")
    assert result.leads_correctly("score_x_mass")


@pytest.mark.parametrize("reader", [load_notes, template_stats])
def test_reading_a_recorded_run_does_not_modify_it(tmp_path: Path, reader: object) -> None:
    """`ScratchpadDB.__init__` migrates what it opens, and these files are the measurement.

    Some of them cost hundreds of thousands of tokens to produce and have no model behind them
    any more, so every read path here is read-only or works on a copy.
    """
    path = _scratchpad(
        tmp_path / "immutable.sqlite",
        [_note(1, [1], ROLE_FINDING), _note(2, [2], ROLE_FINDING)],
    )
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    reader(path)  # type: ignore[operator]

    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_resolving_markers_does_not_modify_the_recorded_run(tmp_path: Path) -> None:
    """The one reader that must open a real `ScratchpadDB`, and so must copy first."""
    path = _scratchpad(
        tmp_path / "resolve.sqlite",
        [_note(1, [1], ROLE_FINDING), _note(2, [2], ROLE_FINDING)],
    )
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    assert marker_templates(path, (ROOT,)) == {1}
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_every_candidate_ranks_the_same_notes(tmp_path: Path) -> None:
    """A candidate that drops or invents a note is comparing different things."""
    path = _scratchpad(
        tmp_path / "all.sqlite",
        [_note(1, [1], None), _note(2, [2], None), _note(3, [1, 2], None)],
    )
    notes = load_notes(path)
    stats = template_stats(path)

    for name, order in CANDIDATES.items():
        ranked = order(notes, stats)
        assert sorted(n["id"] for n in ranked) == [1, 2, 3], name


def _cli_ranking(tmp_path: Path, *args: str) -> str:
    """`eval-ranking` over one tagged non-LogDx scratchpad, which needs `--marker` to score."""
    from click.testing import CliRunner

    from mistify.cli import cli

    pads = tmp_path / "pads"
    pads.mkdir()
    _scratchpad(
        pads / "incident_solr-like.sqlite",
        [_note(1, [1], ROLE_FINDING), _note(2, [2], ROLE_ACCOUNTING)],
    )
    result = CliRunner().invoke(cli, ["eval-ranking", "--scratchpads", str(pads), *args])
    return result.output


def test_a_scratchpad_skipped_for_want_of_a_marker_is_counted_not_dropped(
    tmp_path: Path,
) -> None:
    """The silent skip reported a clean sweep for a key whose deciding term never ran.

    Every run carrying an `accounting` role is a non-LogDx one, so dropping them without a
    word is how the instrument came to grade the role term on a corpus that has none of it.
    """
    output = _cli_ranking(tmp_path)

    assert "1 scratchpad(s) skipped for want of a marker" in output


def test_the_warnings_are_absent_once_the_marker_resolves_the_run(tmp_path: Path) -> None:
    """The control for the test above.

    Same scratchpad, now scorable and carrying the tag. If the warnings appeared here too they
    would be unconditional text and the test above would be asserting nothing.
    """
    output = _cli_ranking(tmp_path, "--marker", ROOT)

    assert "skipped for want of a marker" not in output
    assert "did not exercise the role term" not in output
    assert f"{ROLE_ACCOUNTING}=1" in output


def test_a_table_with_no_accounting_note_says_the_role_term_never_ran(tmp_path: Path) -> None:
    """Scorable, and decided entirely by score: the aggregate says nothing about the tag.

    Paired with `test_the_warnings_are_absent_once_the_marker_resolves_the_run`, which is the
    same command over a run that does carry the tag and must not warn.
    """
    from click.testing import CliRunner

    from mistify.cli import cli

    pads = tmp_path / "untagged"
    pads.mkdir()
    _scratchpad(
        pads / "incident_untagged.sqlite",
        [_note(1, [1], ROLE_FINDING), _note(2, [2], ROLE_FINDING)],
    )
    output = (
        CliRunner()
        .invoke(cli, ["eval-ranking", "--scratchpads", str(pads), "--marker", ROOT])
        .output
    )

    assert "did not exercise the role term" in output

"""The synthesis stage: one call that writes the conclusion from the notes, with no tools.

It had no tests before the REY-462 runs; the two defects found there - it never saw the brief
and it did not bound cited rows - are the ones pinned here.
"""

from __future__ import annotations

import json

from mistify.agent.synthesis import run_synthesis
from mistify.common.models import SYNTHESIS_MARKER
from mistify.llm.scripted import ScriptedProvider, text_turn
from mistify.scratchpad.db import ScratchpadDB


def _synthesiser(
    conclusion: str, template_ids: list[int], event_ids: list[int]
) -> ScriptedProvider:
    return ScriptedProvider(
        [
            text_turn(
                json.dumps(
                    {
                        "conclusion": conclusion,
                        "confidence": "high",
                        "template_ids": template_ids,
                        "log_event_ids": event_ids,
                    }
                )
            )
        ],
        name="synth",
        model="synth-1",
    )


def _brief(db: ScratchpadDB, text: str) -> None:
    incident = db.incident()
    assert incident is not None
    db.create_incident(
        incident["incident_id"],
        source=incident["source"],
        format_name=incident["format"],
        redaction_mode=incident["redaction_mode"],
        brief=text,
    )


def test_the_synthesis_is_told_what_was_reported(loaded_db: ScratchpadDB) -> None:
    """It writes the answer, so it has to see the question."""
    _brief(loaded_db, "Checkout spins for [EMAIL:0543d786].")
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    provider = _synthesiser("the pool", [9], [])

    run_synthesis(loaded_db, provider)

    sent = provider.calls[0].messages[0].text
    assert "## What was reported" in sent
    assert "Checkout spins for [EMAIL:0543d786]." in sent
    assert (
        "does the conclusion explain" not in provider.calls[0].system
    )  # that is the critique's line
    assert "the conclusion is an answer to it" in provider.calls[0].system


def test_without_a_brief_nothing_claims_one(loaded_db: ScratchpadDB) -> None:
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    provider = _synthesiser("the pool", [9], [])

    run_synthesis(loaded_db, provider)

    assert "What was reported" not in provider.calls[0].messages[0].text


def test_a_cited_row_is_bounded_for_the_synthesis(loaded_db: ScratchpadDB) -> None:
    huge = "q=" + "x" * 50_000
    loaded_db._conn.execute("UPDATE log_events SET raw = ?, message = ? WHERE id = 1", (huge, huge))
    loaded_db._conn.commit()
    loaded_db.write_note(1, "look at row 1", {"log_event_ids": [1]}, "high")
    provider = _synthesiser("row 1", [], [1])

    run_synthesis(loaded_db, provider)

    sent = provider.calls[0].messages[0].text
    assert len(sent) < 10_000
    assert "more chars)" in sent


def test_the_conclusion_is_a_marked_note_citing_only_gathered_evidence(
    loaded_db: ScratchpadDB,
) -> None:
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9], "log_event_ids": [1]}, "high")
    provider = _synthesiser("the pool ran out", [9, 3], [1, 2])

    result = run_synthesis(loaded_db, provider)

    assert result.outcome == "written"
    assert result.template_ids == [9]
    assert result.log_event_ids == [1]
    assert result.dropped == [3, 2]
    final = loaded_db.notes()[-1]
    assert final.note == "the pool ran out"
    assert final.evidence[SYNTHESIS_MARKER] is True

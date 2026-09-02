"""The semantic half of decision G8: is a claim actually supported by the rows it cites?

`verify_citations` proves every cited id exists. It cannot prove the rows say what the note
says they say, and that gap is not theoretical -- one measured run cited two real log events
for a claim about database credentials, and both were unrelated INFO lines from other services.
The ids resolved. The claim did not follow.

Answering that needs a model, which is why it sits behind `--judge` rather than running by
default: it costs quota, and a deterministic suite that always runs is worth more day to day
than a complete one that nobody can afford.

The judge is given the claim and the rows and nothing else. No templates, no anomaly scores, no
report -- it must not be able to agree with a claim because the claim sounds like the kind of
thing this system produces. Its question is narrow on purpose, because a judge asked for an
opinion returns opinions and a judge asked whether a specific sentence follows from specific
lines returns something checkable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from mistify.eval.scoring import Check
from mistify.llm.base import LLMProvider, Message
from mistify.scratchpad.db import ScratchpadDB

__all__ = ["JUDGE_PROMPT", "judge_notes"]

JUDGE_PROMPT = """You are checking whether a claim is supported by the log lines cited for it.

You are given one claim and the exact rows it cites. Decide only this: do these rows support
this claim?

- "supported" means a reader of these rows would accept the claim. The rows do not have to
  prove every word, but they must be about what the claim is about.
- "unsupported" means the rows are about something else, or say nothing that bears on the
  claim. Rows from unrelated services, or routine lines cited for a claim about a failure, are
  unsupported however plausible the claim reads on its own.
- Judge the citation, not the claim. A true statement cited to the wrong rows is unsupported.

Reply with JSON only:

{"verdict": "supported" | "unsupported", "reason": "<one sentence>"}
"""


@dataclass(frozen=True, slots=True)
class Judgement:
    note_id: int
    supported: bool
    reason: str


def _rows_for(db: ScratchpadDB, event_ids: list[int]) -> str:
    if not event_ids:
        return "(the note cites no individual log events)"
    rows = db.events_by_id(event_ids)
    if not rows:
        return "(none of the cited ids exist)"
    return "\n".join(
        f"{row['id']} | {row['ts']} | {row['source']} | {row['severity']} | "
        f"{row['message'] or row['raw']}"
        for row in rows
    )


def judge_notes(db: ScratchpadDB, provider: LLMProvider, max_tokens: int = 2048) -> list[Judgement]:
    """One call per note that cites individual rows.

    Notes citing only templates are skipped rather than judged: a template is a shape rather
    than a row, and asking whether a claim follows from a pattern invites exactly the vague
    agreement this check exists to avoid.
    """
    judgements: list[Judgement] = []
    for note in db.notes():
        event_ids = [int(i) for i in note.evidence.get("log_event_ids", [])]
        if not event_ids:
            continue
        turn = provider.converse(
            system=JUDGE_PROMPT,
            messages=[
                Message(
                    role="user",
                    text=f"Claim:\n{note.note}\n\nCited rows:\n{_rows_for(db, event_ids)}",
                )
            ],
            max_tokens=max_tokens,
        )
        try:
            text = turn.text.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
            parsed = json.loads(text)
            verdict = str(parsed.get("verdict", "")).lower()
            reason = str(parsed.get("reason", ""))
        except (ValueError, json.JSONDecodeError):
            # An unreadable judgement is not a pass. Treating it as one would let a judge that
            # cannot answer look like a judge that approved.
            judgements.append(
                Judgement(note.id or 0, False, f"unreadable judgement: {turn.text[:120]!r}")
            )
            continue
        judgements.append(Judgement(note.id or 0, verdict == "supported", reason))
    return judgements


def judgement_checks(judgements: list[Judgement]) -> list[Check]:
    """Judgements as scorer checks, so they land in the same table as the deterministic ones."""
    return [
        Check(
            name=f"entails[note {judgement.note_id}]",
            passed=judgement.supported,
            detail=judgement.reason,
        )
        for judgement in judgements
    ]

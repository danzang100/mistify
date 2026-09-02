"""The final conclusion, written by a stronger model than the one that did the searching.

The loop's job is search: pull slices, run aggregates, record what it saw. That work is
mechanical enough that the cheapest tier does it competently, and it is where fifteen of a
run's sixteen calls go. Drawing the conclusion is the opposite shape -- one call, over evidence
that has already been gathered and checked, where being wrong is expensive and being slightly
better is worth paying for. So the conclusion is written once, by a better model, from the
scratchpad rather than from the conversation.

Two constraints make this safe rather than merely nicer.

**It cannot introduce evidence.** The synthesis model never sees raw logs and never gets tools.
It is handed the notes the investigation recorded and the rows those notes cite, and any id it
returns that was not already cited by some note is dropped and counted. A conclusion is a
judgement about evidence that was gathered, not an opportunity to gather more.

**It must not be the model that checks it.** Architecture §6.3 wants the critique independent of
the reasoning it critiques. Before this existed the loop wrote the conclusion, so "different
from the loop" was enough; now the conclusion has a different author and the rule follows the
author. `LLMConfig` enforces that the adversarial model differs from whichever model wrote the
conclusion, which is why enabling synthesis on the critique's model is rejected at config load
rather than producing a run that silently marks its own homework.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from mistify.common.models import SYNTHESIS_MARKER
from mistify.llm.base import LLMProvider, Message, Usage
from mistify.metrics import (
    SYNTHESIS_CACHED_INPUT_TOKENS,
    SYNTHESIS_DROPPED_CITATIONS,
    SYNTHESIS_INPUT_TOKENS,
    SYNTHESIS_MODEL,
    SYNTHESIS_MODEL_CALLS,
    SYNTHESIS_OUTCOME,
    SYNTHESIS_OUTPUT_TOKENS,
    SYNTHESIS_PROVIDER,
)
from mistify.scratchpad.db import ScratchpadDB

__all__ = ["SynthesisResult", "run_synthesis"]

#: Marks the conclusion in a note's evidence. The report ranks it first, and the adversarial
#: pass critiques it like any other note -- it is a note, not a separate kind of object, so
#: everything downstream keeps working without knowing this step exists.

SYNTHESIS_PROMPT = """You are writing the conclusion of a log investigation that has already
been carried out.

You are given every hypothesis the investigation recorded and the log rows each one cites. You
cannot read the logs and you have no tools. Everything you are allowed to rely on is in front
of you.

Your job is to say what happened, once, in a way an on-call engineer can act on.

- Lead with the failure and its mechanism, not with a restatement of the evidence.
- If the notes describe two unrelated problems, say so plainly rather than forcing one story.
  Concurrent unrelated failures are common and collapsing them loses both.
- Distinguish what the rows show from what you are inferring. "Preceded by" is an observation;
  "caused by" is a claim, and it needs the rows to support the mechanism, not just the order.
- Cite every template your conclusion rests on, including ones you mention only as context.
- You may cite only ids that already appear in the notes below. You cannot introduce new
  evidence; anything else you name will be dropped.
- If the notes do not support a single coherent conclusion, say that. An honest "these two
  facts do not connect" is worth more than a narrative that papers over it.

Reply with JSON only, no prose around it:

{"conclusion": "<what happened, and what says so>",
 "confidence": "low|medium|high",
 "template_ids": [<int>],
 "log_event_ids": [<int>]}
"""


@dataclass(slots=True)
class SynthesisResult:
    conclusion: str = ""
    confidence: str = "low"
    template_ids: list[int] = field(default_factory=list)
    log_event_ids: list[int] = field(default_factory=list)
    #: Ids the model named that no note had cited. Dropped, and counted: a conclusion reaching
    #: for evidence the investigation never gathered is worth knowing about even when the
    #: reach is harmless.
    dropped: list[int] = field(default_factory=list)
    outcome: str = "not_run"
    usage: Usage = field(default_factory=Usage)


def _evidence_for_synthesis(db: ScratchpadDB) -> tuple[str, set[int], set[int]]:
    """The notes and their cited rows, plus the id sets a conclusion may draw from."""
    templates = {int(t["template_id"]): t for t in db.top_templates(limit=200)}
    lines: list[str] = []
    allowed_templates: set[int] = set()
    allowed_events: set[int] = set()

    for note in db.notes():
        cited_templates = [int(i) for i in note.evidence.get("template_ids", [])]
        cited_events = [int(i) for i in note.evidence.get("log_event_ids", [])]
        allowed_templates.update(cited_templates)
        allowed_events.update(cited_events)

        lines.append(f"### Note {note.id} (step {note.step}, confidence {note.confidence})")
        lines.append(note.note)
        lines.append(f"cites templates {cited_templates}, log events {cited_events}")
        for template_id in cited_templates:
            template = templates.get(template_id)
            if template is not None:
                lines.append(
                    f"  [template {template_id}] score={template['anomaly_score']:.3f} "
                    f"n={template['occurrence_count']} "
                    f"{template['first_seen']}..{template['last_seen']} :: {template['pattern']}"
                )
        for row in db.events_by_id(cited_events):
            lines.append(
                f"  [event {row['id']}] {row['ts']} {row['source']} {row['severity']} "
                f"{row['message'] or row['raw']}"
            )
        lines.append("")

    return ("\n".join(lines), allowed_templates, allowed_events)


def _parse(text: str) -> dict[str, Any]:
    """Read the reply, tolerating a fenced code block around the JSON."""
    body = text.strip()
    if body.startswith("```"):
        body = body.split("```")[1]
        body = body.split("\n", 1)[1] if body.lower().startswith("json") else body
    start, end = body.find("{"), body.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in the reply")
    parsed = json.loads(body[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("reply was not a JSON object")
    return parsed


def run_synthesis(
    db: ScratchpadDB,
    provider: LLMProvider,
    max_tokens: int = 4096,
) -> SynthesisResult:
    """Write the investigation's conclusion into the scratchpad as a final note."""
    result = SynthesisResult()
    notes = db.notes()
    if not notes:
        # Nothing was concluded, so there is nothing to conclude *from*. Writing a synthesis
        # here would be the model inventing a finding out of an empty investigation.
        result.outcome = "nothing_to_synthesise"
        _record(db, provider, result)
        return result

    bundle, allowed_templates, allowed_events = _evidence_for_synthesis(db)
    turn = provider.converse(
        system=SYNTHESIS_PROMPT,
        messages=[Message(role="user", text=bundle)],
        max_tokens=max_tokens,
    )
    result.usage = turn.usage

    try:
        parsed = _parse(turn.text)
    except (ValueError, json.JSONDecodeError):
        # An unreadable synthesis leaves the investigation's own notes standing. That is a
        # worse report, not a wrong one, and it is reported as what it is.
        result.outcome = "unreadable"
        _record(db, provider, result)
        return result

    conclusion = str(parsed.get("conclusion", "")).strip()
    if not conclusion:
        result.outcome = "empty"
        _record(db, provider, result)
        return result

    named_templates = [int(i) for i in parsed.get("template_ids", [])]
    named_events = [int(i) for i in parsed.get("log_event_ids", [])]
    result.template_ids = [i for i in named_templates if i in allowed_templates]
    result.log_event_ids = [i for i in named_events if i in allowed_events]
    result.dropped = [i for i in named_templates if i not in allowed_templates] + [
        i for i in named_events if i not in allowed_events
    ]

    if not result.template_ids and not result.log_event_ids:
        # The schema requires evidence, and a conclusion citing nothing the investigation
        # gathered is exactly the claim this system exists not to make.
        result.outcome = "no_usable_citations"
        _record(db, provider, result)
        return result

    confidence = str(parsed.get("confidence", "medium")).lower()
    result.confidence = confidence if confidence in {"low", "medium", "high"} else "medium"
    result.conclusion = conclusion

    db.write_note(
        step=max(note.step for note in notes) + 1,
        note=conclusion,
        evidence={
            "template_ids": result.template_ids,
            "log_event_ids": result.log_event_ids,
            SYNTHESIS_MARKER: True,
        },
        confidence=result.confidence,
    )
    result.outcome = "written"
    _record(db, provider, result)
    return result


def _record(db: ScratchpadDB, provider: LLMProvider, result: SynthesisResult) -> None:
    db.record_many(
        [
            (SYNTHESIS_PROVIDER, provider.name),
            (SYNTHESIS_MODEL, provider.model),
            (SYNTHESIS_OUTCOME, result.outcome),
            (SYNTHESIS_MODEL_CALLS, 0 if result.outcome == "nothing_to_synthesise" else 1),
            (SYNTHESIS_INPUT_TOKENS, result.usage.input_tokens),
            (SYNTHESIS_OUTPUT_TOKENS, result.usage.output_tokens),
            (SYNTHESIS_CACHED_INPUT_TOKENS, result.usage.cached_input_tokens),
            (SYNTHESIS_DROPPED_CITATIONS, len(result.dropped)),
        ]
    )

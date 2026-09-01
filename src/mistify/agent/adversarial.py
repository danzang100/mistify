"""The adversarial check, and the rebuttal that answers it.

Architecture §6.2 is explicit about the shape of this: the critique **objects**, it never
rewrites. A pass with unilateral authority to replace the conclusion can overturn a correct
one, so what comes back here is a structured list of objections and the original reasoning
gets a chance to answer them. A one-shot veto becomes a short debate, which is cheap.

Three checks, in descending order of how much they depend on judgement:

1.  **Unexplained signal.** Which high-anomaly templates does the conclusion never mention?
    This is arithmetic — the signal set was cut at the largest score gap by
    `select_signal_templates`, with no model involved — and it is the only test here that
    cannot be talked out of. §6.3 warns that a checker sharing the reasoner's blind spots will
    rubber-stamp; a mechanical test is the part that cannot.
2.  **Unsupported claims.** Does each note's cited evidence exist, and does it say what the
    note says? The first half is already deterministic (`verify_citations`); the second needs
    a reader.
3.  **Alternative explanations.** Is there a different story the same rows support?

Objections are weighted by evidence. One citing no rows cannot overturn a conclusion that
cites many — §6.2 again: weight objections by evidence strength, not by existence.

The critique runs on a different model from the loop, and ideally a different provider. That
is enforced in config rather than trusted here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from mistify.llm.base import LLMProvider, Message, Usage
from mistify.metrics import (
    ADVERSARIAL_CACHED_INPUT_TOKENS,
    ADVERSARIAL_INPUT_TOKENS,
    ADVERSARIAL_MODEL,
    ADVERSARIAL_MODEL_CALLS,
    ADVERSARIAL_OBJECTIONS,
    ADVERSARIAL_OUTCOME,
    ADVERSARIAL_OUTPUT_TOKENS,
    ADVERSARIAL_PROVIDER,
    ADVERSARIAL_REBUTTAL_MODEL,
    ADVERSARIAL_REBUTTED,
    ADVERSARIAL_UNEXPLAINED_SIGNAL,
    ADVERSARIAL_UNSUPPORTED_CLAIMS,
)
from mistify.scratchpad.db import ScratchpadDB

__all__ = [
    "AdversarialResult",
    "Objection",
    "run_adversarial_check",
    "unexplained_signal_templates",
]

CRITIQUE_PROMPT = """You are checking an incident investigation someone else carried out.

You are not rewriting their conclusion and you cannot replace it. Your job is to object where
objection is warranted, and to say plainly when it is not.

Work through three questions:

1. Does every claim in the notes rest on the evidence it cites? You are given the cited rows.
   A claim the rows do not actually support is the most serious thing you can find.
2. Is there a high-scoring template the conclusion never accounts for? You are told which
   templates the ranking flagged as signal. Being ignored is not proof of relevance, but an
   unexplained one is worth raising.
3. Is there a different explanation these same rows support at least as well?

Rules:

- Every objection must cite specific template ids or log event ids. An objection citing
  nothing cannot outweigh a conclusion that cites rows, and will be treated as weak.
- Do not object to phrasing, tone, or confidence wording. Object to reasoning.
- If the investigation is sound, say so and return no objections. Manufacturing an objection
  to look rigorous is worse than finding none: it trains the reader to ignore you.

Reply with JSON only, no prose around it:

{"assessment": "<one sentence>",
 "objections": [{"claim": "<what you are objecting to>",
                 "objection": "<why>",
                 "template_ids": [<int>],
                 "log_event_ids": [<int>],
                 "severity": "low|medium|high"}],
 "alternative": "<a different explanation the rows support, or empty>"}
"""

REBUTTAL_PROMPT = """Your investigation has been challenged. Answer the objections.

For each one, either concede it, or answer it by pointing at evidence already in the
scratchpad. Do not restate your conclusion; address the specific objection.

Reply with JSON only:

{"responses": [{"objection": "<which one>", "response": "<your answer>",
                "conceded": true|false}],
 "revised_confidence": "low|medium|high"}
"""


@dataclass(slots=True)
class Objection:
    claim: str
    objection: str
    template_ids: list[int] = field(default_factory=list)
    log_event_ids: list[int] = field(default_factory=list)
    severity: str = "medium"

    @property
    def cites_evidence(self) -> bool:
        """An objection with no citations cannot outweigh a conclusion that has them."""
        return bool(self.template_ids or self.log_event_ids)


@dataclass(slots=True)
class AdversarialResult:
    assessment: str = ""
    objections: list[Objection] = field(default_factory=list)
    alternative: str = ""
    unexplained_signal: list[int] = field(default_factory=list)
    unsupported_claims: list[str] = field(default_factory=list)
    rebuttals: list[dict[str, Any]] = field(default_factory=list)
    outcome: str = "not_run"
    #: What the critique and the rebuttal cost between them. Recorded because the pass is one
    #: or two calls against the loop's fifteen, and a run total that omitted it would be
    #: quietly wrong about how much of the bill the check accounts for.
    usage: Usage = field(default_factory=Usage)
    model_calls: int = 0
    #: The model that answered the objections, when it was not the one that raised them --
    #: the normal case, since the point of a rebuttal is that the original reasoning answers.
    rebuttal_model: str = ""
    #: What the investigation said its confidence was *after* being challenged. The prompt has
    #: always asked for it; until this was carried it was parsed and dropped, so a conclusion
    #: that had conceded ground still reported the confidence it started with.
    revised_confidence: str = ""

    @property
    def evidenced_objections(self) -> list[Objection]:
        return [o for o in self.objections if o.cites_evidence]


def unexplained_signal_templates(db: ScratchpadDB, signal_ids: list[int]) -> list[int]:
    """Signal templates no note cites.

    The mechanical half of the check. `signal_ids` came from the anomaly ranking, which no
    model touched, so this answer cannot be argued with -- which is exactly why it is worth
    having next to two checks that can.
    """
    cited: set[int] = set()
    for note in db.notes():
        cited.update(int(i) for i in note.evidence.get("template_ids", []))
    return [tid for tid in signal_ids if tid not in cited]


def _parse_json(text: str) -> dict[str, Any]:
    """Pull the JSON object out of a reply, tolerating fenced or prefixed output.

    Models are asked for bare JSON and mostly give it. Failing the whole check because one
    wrapped it in a fence would throw away a critique that is otherwise fine.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("```")[1]
        if stripped.startswith("json"):
            stripped = stripped[4:]
    start, end = stripped.find("{"), stripped.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"no JSON object in reply: {text[:120]!r}")
    parsed: dict[str, Any] = json.loads(stripped[start : end + 1])
    return parsed


def _evidence_bundle(db: ScratchpadDB) -> str:
    """The notes, with their cited rows resolved, so the critique reads evidence not claims."""
    blocks: list[str] = []
    for note in db.notes():
        rows = db.events_by_id([int(i) for i in note.evidence.get("log_event_ids", [])])
        blocks.append(
            f"### Note {note.id} (step {note.step}, confidence {note.confidence})\n"
            f"{note.note}\n\n"
            f"cited templates: {note.evidence.get('template_ids', [])}\n"
            f"cited events:\n"
            + (
                "\n".join(
                    f"  [{r['id']}] {r['ts']} {r['severity']} {r['source']} :: {r['message']}"
                    for r in rows
                )
                or "  (none)"
            )
        )
    return "\n\n".join(blocks) or "(the investigation recorded no notes)"


def run_adversarial_check(
    db: ScratchpadDB,
    provider: LLMProvider,
    signal_template_ids: list[int],
    max_tokens: int = 4096,
    rebut: bool = True,
    rebuttal_provider: LLMProvider | None = None,
) -> AdversarialResult:
    """Critique the investigation, then let it answer.

    `rebuttal_provider` defaults to the critique's provider, but the caller should pass the
    loop's: the point of the rebuttal is that the *original reasoning* gets to respond.
    """
    result = AdversarialResult()
    result.unexplained_signal = unexplained_signal_templates(db, signal_template_ids)

    notes = db.notes()
    if not notes:
        result.outcome = "nothing_to_check"
        _record(db, provider, result)
        return result

    prompt = (
        f"{_evidence_bundle(db)}\n\n"
        f"Templates the ranking flagged as signal: {signal_template_ids}\n"
        f"Of those, none of the notes cite: {result.unexplained_signal}\n"
    )
    critique = provider.converse(
        system=CRITIQUE_PROMPT,
        messages=[Message(role="user", text=prompt)],
        max_tokens=max_tokens,
    )
    result.usage = result.usage + critique.usage
    result.model_calls += 1

    try:
        parsed = _parse_json(critique.text)
    except (ValueError, json.JSONDecodeError):
        # A critique we cannot read is not a passed check. Say so rather than treating an
        # unparseable reply as silence, which would read as approval.
        result.outcome = "unreadable_critique"
        result.assessment = critique.text.strip()[:400]
        _record(db, provider, result)
        return result

    result.assessment = str(parsed.get("assessment", ""))
    result.alternative = str(parsed.get("alternative", ""))
    result.objections = [
        Objection(
            claim=str(raw.get("claim", "")),
            objection=str(raw.get("objection", "")),
            template_ids=[int(i) for i in raw.get("template_ids", [])],
            log_event_ids=[int(i) for i in raw.get("log_event_ids", [])],
            severity=str(raw.get("severity", "medium")),
        )
        for raw in parsed.get("objections", [])
    ]
    result.unsupported_claims = [
        o.claim for o in result.objections if o.severity == "high" and o.cites_evidence
    ]

    if rebut and result.evidenced_objections:
        answering = rebuttal_provider or provider
        result.rebuttals, result.revised_confidence, rebuttal_usage = _rebut(
            db, answering, result.evidenced_objections, max_tokens
        )
        result.usage = result.usage + rebuttal_usage
        result.model_calls += 1
        # Two models can spend this stage's tokens. Recording only the critique's would
        # attribute the rebuttal's share to the wrong one, at the wrong price.
        if answering.model != provider.model:
            result.rebuttal_model = answering.model

    result.outcome = _outcome(result)
    _record(db, provider, result)
    return result


def _rebut(
    db: ScratchpadDB,
    provider: LLMProvider,
    objections: list[Objection],
    max_tokens: int,
) -> tuple[list[dict[str, Any]], str, Usage]:
    """Answer the objections, returning the revised confidence and the cost alongside them.

    The usage comes back rather than being recorded here because this call may run on the
    loop's provider, not the critique's, and the caller is the only one that knows which.
    """
    listing = "\n".join(
        f"- {o.claim}: {o.objection} (cites templates {o.template_ids}, events {o.log_event_ids})"
        for o in objections
    )
    reply = provider.converse(
        system=REBUTTAL_PROMPT,
        messages=[
            Message(
                role="user",
                text=f"Your notes:\n\n{_evidence_bundle(db)}\n\nObjections:\n{listing}",
            )
        ],
        max_tokens=max_tokens,
    )
    try:
        parsed = _parse_json(reply.text)
    except (ValueError, json.JSONDecodeError):
        # An unreadable rebuttal still cost what it cost.
        return [], "", reply.usage
    return list(parsed.get("responses", [])), str(parsed.get("revised_confidence", "")), reply.usage


def _outcome(result: AdversarialResult) -> str:
    if not result.objections:
        return "no_objections"
    if not result.evidenced_objections:
        # Objections that cite nothing do not get to overturn a conclusion that cites rows.
        return "objections_unevidenced"
    conceded = sum(1 for r in result.rebuttals if r.get("conceded"))
    if conceded:
        return "objections_conceded"
    return "objections_answered" if result.rebuttals else "objections_open"


def _paired_objections(result: AdversarialResult) -> list[dict[str, Any]]:
    """Objections with the response each one drew, ready to persist.

    The model is asked to answer the objections in order, and its replies are matched to them
    by position -- but only when it returned exactly as many as were raised. It names the
    objection it is answering in free text, which is not something to key on, and a
    mispaired concession would attach an admission to the wrong claim. When the counts
    disagree the responses are appended unpaired instead, which is honest about what is
    known.
    """
    raised = result.objections
    replies = result.rebuttals
    paired = len(replies) == len(result.evidenced_objections)
    by_claim = (
        dict(zip([id(o) for o in result.evidenced_objections], replies, strict=True))
        if paired
        else {}
    )

    rows: list[dict[str, Any]] = []
    for objection in raised:
        reply = by_claim.get(id(objection))
        rows.append(
            {
                "claim": objection.claim,
                "objection": objection.objection,
                "severity": objection.severity,
                "template_ids": objection.template_ids,
                "log_event_ids": objection.log_event_ids,
                "response": None if reply is None else str(reply.get("response", "")),
                "conceded": None if reply is None else bool(reply.get("conceded")),
            }
        )
    if not paired:
        rows.extend(
            {
                "claim": "",
                "objection": "",
                "severity": "unpaired_response",
                "template_ids": [],
                "log_event_ids": [],
                "response": str(reply.get("response", "")),
                "conceded": bool(reply.get("conceded")),
            }
            for reply in replies
        )
    return rows


def _record(db: ScratchpadDB, provider: LLMProvider, result: AdversarialResult) -> None:
    # What the critique *said*, not just how much of it there was. A count cannot tell a
    # reader that the investigation conceded, or what to check instead.
    db.save_adversarial(
        outcome=result.outcome,
        assessment=result.assessment,
        alternative=result.alternative,
        revised_confidence=result.revised_confidence,
        objections=_paired_objections(result),
    )
    db.record_many(
        [
            (ADVERSARIAL_PROVIDER, provider.name),
            (ADVERSARIAL_MODEL, provider.model),
            (ADVERSARIAL_OBJECTIONS, len(result.objections)),
            (ADVERSARIAL_UNSUPPORTED_CLAIMS, len(result.unsupported_claims)),
            (ADVERSARIAL_UNEXPLAINED_SIGNAL, len(result.unexplained_signal)),
            (ADVERSARIAL_REBUTTED, len(result.rebuttals)),
            (ADVERSARIAL_OUTCOME, result.outcome),
            (ADVERSARIAL_MODEL_CALLS, result.model_calls),
            (ADVERSARIAL_INPUT_TOKENS, result.usage.input_tokens),
            (ADVERSARIAL_OUTPUT_TOKENS, result.usage.output_tokens),
            (ADVERSARIAL_CACHED_INPUT_TOKENS, result.usage.cached_input_tokens),
        ]
        + ([(ADVERSARIAL_REBUTTAL_MODEL, result.rebuttal_model)] if result.rebuttal_model else [])
    )

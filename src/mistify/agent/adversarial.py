"""The adversarial check, and the rebuttal that answers it.

The shape of this is deliberate: the critique **objects**, it never rewrites. A pass with
unilateral authority to replace the conclusion can overturn a correct one, so what comes back
here is a structured list of objections and the original reasoning gets a chance to answer
them. A one-shot veto becomes a short debate, which is cheap.

Three checks, in descending order of how much they depend on judgement:

1.  **Unexplained signal.** Which high-anomaly templates does the conclusion never mention?
    This is arithmetic - the signal set was cut at the largest score gap by
    `select_signal_templates`, with no model involved - and it is the only test here that
    cannot be talked out of. A checker sharing the reasoner's blind spots will rubber-stamp;
    a mechanical test is the part that cannot.
2.  **Unsupported claims.** Does each note's cited evidence exist, and does it say what the
    note says? The first half is already deterministic (`verify_citations`); the second needs
    a reader.
3.  **Alternative explanations.** Is there a different story the same rows support?

Objections are weighted by evidence. One citing no rows cannot overturn a conclusion that
cites many: weight objections by evidence strength, not by existence.

The critique runs on a different model from the loop, and ideally a different provider. That
is enforced in config rather than trusted here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from mistify.agent.tools import MAX_CELL_CHARS, ToolBox, clip
from mistify.llm.base import LLMProvider, Message, Usage
from mistify.metrics import (
    ADVERSARIAL_CACHED_INPUT_TOKENS,
    ADVERSARIAL_HIGH_SEVERITY_OBJECTIONS,
    ADVERSARIAL_INPUT_TOKENS,
    ADVERSARIAL_MODEL,
    ADVERSARIAL_MODEL_CALLS,
    ADVERSARIAL_OBJECTIONS,
    ADVERSARIAL_OUTCOME,
    ADVERSARIAL_OUTPUT_TOKENS,
    ADVERSARIAL_PROVIDER,
    ADVERSARIAL_REBUTTAL_MODEL,
    ADVERSARIAL_REBUTTED,
    ADVERSARIAL_UNEXPLAINED_CHRONIC,
    ADVERSARIAL_UNEXPLAINED_SIGNAL,
    ADVERSARIAL_UNREBUTTED_HIGH_SEVERITY,
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

Work through four questions:

1. Does every claim in the notes rest on the evidence it cites? You are given the cited rows.
   A claim the rows do not actually support is the most serious thing you can find.
2. Is there a high-scoring template the conclusion never accounts for? You are told which
   templates the ranking flagged as signal. Being ignored is not proof of relevance, but an
   unexplained one is worth raising.
3. Is there a different explanation these same rows support at least as well?
4. If what was reported is given, does the conclusion explain it? A finding that is true of
   the log but does not account for the reported user, item or symptom is not a finding about
   this incident, and an investigation that never looked for what was reported has not
   investigated it. That is worth objecting to even when every citation holds.

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

Work in two phases.

First, read. If tools are offered, use them before you answer. An objection is a claim about
rows like any other, and a critique can misread a row: for every objection that names a row
or a template, fetch it and the lines around it and check the objection describes them. An
objection your cited rows do not answer may still be answerable from rows you did not cite -
the same thread or session a few seconds on, the request that did or did not follow. Fetch
the line that settles it rather than repeating what you already said. You have a few calls,
not an investigation. Do not reply with your answer until you have read what you need; a
reply that is only JSON ends the exchange.

Then answer. For each objection, either concede it or answer it by pointing at rows. Do not
concede on the objection's say-so: concede when the rows agree with the objection, answer
when they do not, and say which it was. Do not restate your conclusion; address the specific
objection.

Every objection carries an id. Quote it back in `objection_id` so your answer is attached to
the right one; an answer whose id matches no objection is reported as unmatched rather than
guessed at. Cite in `log_event_ids` the rows your answer rests on, from the `id` column of
what you were shown; an id you were not shown is dropped.

When you have finished reading, reply with JSON only, in this shape:

{"responses": [{"objection_id": "<the id you are answering>", "response": "<your answer>",
                "log_event_ids": [<int>], "conceded": true|false}],
 "revised_confidence": "low|medium|high"}
"""

#: Tools the rebuttal is offered: the readers, never `write_note`. Answering an objection is
#: not the moment to extend the conclusion.
REBUTTAL_TOOLS: tuple[str, ...] = ("get_slice", "run_sql", "query_templates")


@dataclass(slots=True)
class Objection:
    #: Assigned by us, not asked of the model, and shown to it in the rebuttal prompt so it
    #: can be quoted back. See `0003_objection_ids.sql` for why the model does not choose it.
    id: str
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
    #: Acute signal templates no note cites. Chronic ones are held separately, because
    #: declining to explain something that was happening all along is correct.
    unexplained_signal: list[int] = field(default_factory=list)
    unexplained_chronic: list[int] = field(default_factory=list)
    #: Evidenced objections raised at high severity, counted before the answer.
    high_severity_objections: list[str] = field(default_factory=list)
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

    def unrebutted_high_severity(self, answered: set[str]) -> list[str]:
        """High-severity objections the investigation never answered at all.

        Conceding is an answer, and a bad one the report states plainly; being answered and not
        conceded is the system working. Never being answered is the only case where nothing
        checked the objection, and it is the one worth warning about.
        """
        return [
            o.claim
            for o in self.objections
            if o.severity == "high" and o.cites_evidence and o.id not in answered
        ]


def unexplained_signal_templates(
    db: ScratchpadDB, signal_ids: list[int]
) -> tuple[list[int], list[int]]:
    """Signal templates no note cites, split into acute and chronic.

    The mechanical half of the check. `signal_ids` came from the anomaly ranking, which no
    model touched, so this answer cannot be argued with -- which is exactly why it is worth
    having next to two checks that can.

    The split is what stops it firing forever. The anomaly score has no term for duration, so a
    steady background error stream scores as signal, and an investigation that correctly
    ignores it as pre-existing gets faulted for the omission on every single run. A warning
    that always fires is one a reader learns to skip, which costs more than the check is worth.
    Chronic templates are still counted -- as an observation, not an alarm.
    """
    cited: set[int] = set()
    for note in db.notes():
        cited.update(int(i) for i in note.evidence.get("template_ids", []))
    chronic = db.chronic_template_ids()
    missing = [tid for tid in signal_ids if tid not in cited]
    return (
        [tid for tid in missing if tid not in chronic],
        [tid for tid in missing if tid in chronic],
    )


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
                    f"  [{r['id']}] {r['ts']} {r['severity']} {r['source']} :: "
                    f"{clip(str(r['message']), MAX_CELL_CHARS)}"
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
    toolbox: ToolBox | None = None,
    rebuttal_tool_calls: int = 3,
) -> AdversarialResult:
    """Critique the investigation, then let it answer.

    `rebuttal_provider` defaults to the critique's provider, but the caller should pass the
    loop's: the point of the rebuttal is that the *original reasoning* gets to respond.
    `toolbox` lets the rebuttal read the scratchpad for up to `rebuttal_tool_calls` calls
    before answering; without one it answers from the notes alone, as it used to.
    """
    result = AdversarialResult()
    result.unexplained_signal, result.unexplained_chronic = unexplained_signal_templates(
        db, signal_template_ids
    )

    notes = db.notes()
    if not notes:
        result.outcome = "nothing_to_check"
        _record(db, provider, result)
        return result

    # The critique gets the same brief the loop had. Without it the critique can only judge
    # whether the notes hold against their rows, and a sound conclusion about the wrong
    # incident passes that test - it did, once, with "no objections".
    brief = (db.incident() or {}).get("brief")
    prompt = (
        (f"## What was reported\n\n{brief}\n\n" if brief else "") + f"{_evidence_bundle(db)}\n\n"
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
            id=f"o{index}",
            claim=str(raw.get("claim", "")),
            objection=str(raw.get("objection", "")),
            template_ids=[int(i) for i in raw.get("template_ids", [])],
            log_event_ids=[int(i) for i in raw.get("log_event_ids", [])],
            severity=str(raw.get("severity", "medium")),
        )
        for index, raw in enumerate(parsed.get("objections", []), start=1)
    ]
    result.high_severity_objections = [
        o.claim for o in result.objections if o.severity == "high" and o.cites_evidence
    ]

    if rebut and result.evidenced_objections:
        answering = rebuttal_provider or provider
        result.rebuttals, result.revised_confidence, rebuttal_usage, calls = _rebut(
            db,
            answering,
            result.evidenced_objections,
            max_tokens,
            toolbox=toolbox,
            max_tool_calls=rebuttal_tool_calls,
        )
        result.usage = result.usage + rebuttal_usage
        result.model_calls += calls
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
    toolbox: ToolBox | None = None,
    max_tool_calls: int = 3,
) -> tuple[list[dict[str, Any]], str, Usage, int]:
    """Answer the objections, returning the revised confidence, the cost and the call count.

    The usage comes back rather than being recorded here because this call may run on the
    loop's provider, not the critique's, and the caller is the only one that knows which.

    With a toolbox the rebuttal may read the scratchpad first, a bounded number of times.
    The tools are then taken away for the answer, the same way the loop converges: a reply
    that could still ask for more is not an answer. Ids the reply cites are kept only if the
    rebuttal was actually shown them, by the same rule `write_note` applies to the loop.
    """
    listing = "\n".join(
        f"[{o.id}] {o.claim}: {o.objection} "
        f"(cites templates {o.template_ids}, events {o.log_event_ids})"
        for o in objections
    )
    messages = [
        Message(
            role="user",
            text=f"Your notes:\n\n{_evidence_bundle(db)}\n\nObjections:\n{listing}",
        )
    ]
    usage = Usage()
    calls = 0
    specs = toolbox.specs() if toolbox is not None and max_tool_calls > 0 else []
    tool_calls_made = 0
    while True:
        offered = specs if tool_calls_made < max_tool_calls else []
        reply = provider.converse(
            system=REBUTTAL_PROMPT,
            messages=messages,
            tools=offered or None,
            max_tokens=max_tokens,
        )
        usage = usage + reply.usage
        calls += 1
        if not reply.wants_tools or toolbox is None or not offered:
            break
        messages.append(Message(role="assistant", text=reply.text, tool_calls=reply.tool_calls))
        results = [toolbox.dispatch(call) for call in reply.tool_calls]
        tool_calls_made += len(results)
        messages.append(Message(role="user", tool_results=tuple(results)))
        if tool_calls_made >= max_tool_calls:
            messages.append(
                Message(
                    role="user",
                    text="You have used the calls available to you. Answer the objections "
                    "now, as JSON, from what you have seen.",
                )
            )
    try:
        parsed = _parse_json(reply.text)
    except (ValueError, json.JSONDecodeError):
        # An unreadable rebuttal still cost what it cost.
        return [], "", usage, calls
    shown = toolbox.seen_events if toolbox is not None else set()
    responses = []
    for raw in parsed.get("responses", []):
        item = dict(raw)
        cited = [int(i) for i in item.get("log_event_ids", []) if str(i).lstrip("-").isdigit()]
        item["log_event_ids"] = sorted(i for i in set(cited) if i in shown)
        responses.append(item)
    return responses, str(parsed.get("revised_confidence", "")), usage, calls


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

    Matched on the id we handed the model, not on where the reply landed in a list. Positional
    pairing held only while the model returned exactly as many responses as there were
    objections, and when it did not, a concession was attached to a claim that never drew it --
    which reads as an admission the investigation never made.

    A response whose id matches nothing is kept, unattached. Dropping it would hide the fact
    that the investigation answered something; guessing which objection it meant is the error
    this replaced.
    """
    replies = {
        str(reply.get("objection_id", "")): reply
        for reply in result.rebuttals
        if reply.get("objection_id")
    }

    rows: list[dict[str, Any]] = []
    for objection in result.objections:
        reply = replies.pop(objection.id, None)
        rows.append(
            {
                "objection_id": objection.id,
                "claim": objection.claim,
                "objection": objection.objection,
                "severity": objection.severity,
                "template_ids": objection.template_ids,
                "log_event_ids": objection.log_event_ids,
                "response": None if reply is None else str(reply.get("response", "")),
                "conceded": None if reply is None else bool(reply.get("conceded")),
                "response_log_event_ids": (
                    [] if reply is None else list(reply.get("log_event_ids", []))
                ),
            }
        )

    rows.extend(
        {
            "objection_id": objection_id or "unmatched",
            "claim": "",
            "objection": "",
            "severity": "unmatched_response",
            "template_ids": [],
            "log_event_ids": [],
            "response": str(reply.get("response", "")),
            "conceded": bool(reply.get("conceded")),
            "response_log_event_ids": list(reply.get("log_event_ids", [])),
        }
        for objection_id, reply in replies.items()
    )
    return rows


def _answered_ids(result: AdversarialResult) -> set[str]:
    """Objection ids the investigation actually replied to, conceding or not."""
    return {
        str(reply.get("objection_id", ""))
        for reply in result.rebuttals
        if reply.get("objection_id")
    }


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
            (ADVERSARIAL_HIGH_SEVERITY_OBJECTIONS, len(result.high_severity_objections)),
            (
                ADVERSARIAL_UNREBUTTED_HIGH_SEVERITY,
                len(result.unrebutted_high_severity(_answered_ids(result))),
            ),
            (ADVERSARIAL_UNEXPLAINED_SIGNAL, len(result.unexplained_signal)),
            (ADVERSARIAL_UNEXPLAINED_CHRONIC, len(result.unexplained_chronic)),
            (ADVERSARIAL_REBUTTED, len(result.rebuttals)),
            (ADVERSARIAL_OUTCOME, result.outcome),
            (ADVERSARIAL_MODEL_CALLS, result.model_calls),
            (ADVERSARIAL_INPUT_TOKENS, result.usage.input_tokens),
            (ADVERSARIAL_OUTPUT_TOKENS, result.usage.output_tokens),
            (ADVERSARIAL_CACHED_INPUT_TOKENS, result.usage.cached_input_tokens),
        ]
        + ([(ADVERSARIAL_REBUTTAL_MODEL, result.rebuttal_model)] if result.rebuttal_model else [])
    )

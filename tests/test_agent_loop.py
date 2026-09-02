"""The bounded investigation loop and the adversarial pass, driven by a scripted provider.

Every test here runs a complete investigation without a credential, a network call, or a bill.
That is the whole reason the provider seam has a second adapter: the loop's behaviour — how it
feeds results back, when it stops, what it records, what it says when it runs out of budget —
is decided by our code, not the model's, so it should be testable without one.
"""

from __future__ import annotations

import json

import pytest

from mistify.agent.adversarial import run_adversarial_check, unexplained_signal_templates
from mistify.agent.loop import (
    ELIDED,
    INVESTIGATOR_NAME,
    InvestigationLoop,
    build_system_prompt,
)
from mistify.agent.tools import ToolBox
from mistify.common.models import NoiseThresholds
from mistify.llm.base import Turn, Usage
from mistify.llm.scripted import ScriptedProvider, text_turn, tool_call_turn
from mistify.metrics import (
    ADVERSARIAL_INPUT_TOKENS,
    ADVERSARIAL_MODEL_CALLS,
    ADVERSARIAL_OBJECTIONS,
    ADVERSARIAL_OUTCOME,
    ADVERSARIAL_OUTPUT_TOKENS,
    ADVERSARIAL_REBUTTAL_MODEL,
    ADVERSARIAL_UNEXPLAINED_SIGNAL,
    ANOMALY_SIGNAL_TEMPLATE_IDS,
    INVESTIGATE_BUDGET_LIMITED,
    INVESTIGATE_CACHED_INPUT_TOKENS,
    INVESTIGATE_CAVEAT,
    INVESTIGATE_INPUT_GROWTH,
    INVESTIGATE_INPUT_TOKENS_PER_STEP,
    INVESTIGATE_INVESTIGATOR,
    INVESTIGATE_OUTCOME,
    INVESTIGATE_TOOL_CALLS,
    MetricView,
)
from mistify.report.generator import generate_report
from mistify.scratchpad.db import ScratchpadDB
from tests.fixtures.synthetic_incident import ROOT_CAUSE_MARKER

NOISE = NoiseThresholds(share=0.15, anomaly_ceiling=0.35)


def _toolbox(db: ScratchpadDB) -> ToolBox:
    return ToolBox(db, noise=NOISE)


def _concluding_script(db: ScratchpadDB) -> list[Turn]:
    """A plausible three-step investigation: look, read, conclude."""
    template = db.top_templates(limit=1, order_by="anomaly_score")[0]
    events = db.get_slice(template_id=int(template["template_id"]), max_lines=3)
    return [
        tool_call_turn("query_templates", {"order_by": "anomaly_score", "limit": 5}, call_id="c1"),
        tool_call_turn(
            "get_slice",
            {"template_id": int(template["template_id"]), "max_lines": 5},
            call_id="c2",
        ),
        tool_call_turn(
            "write_note",
            {
                "note": f"Root cause: {template['pattern']}",
                "evidence": {
                    "template_ids": [int(template["template_id"])],
                    "log_event_ids": [int(e["id"]) for e in events],
                },
                "confidence": "high",
            },
            call_id="c3",
        ),
        text_turn("The pool exhaustion is the root cause.", usage=Usage(120, 40, 90)),
    ]


# --------------------------------------------------------------- a whole investigation


def test_the_loop_investigates_and_concludes(loaded_db: ScratchpadDB) -> None:
    provider = ScriptedProvider(_concluding_script(loaded_db))
    result = InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), coverage_nudges=0).run()

    assert result.tool_calls == 3
    assert result.budget_limited is False
    assert result.stop_reason == "end_turn"
    assert len(result.notes) == 1
    assert ROOT_CAUSE_MARKER in result.notes[0].note


def test_tool_results_are_fed_back_under_the_right_id(loaded_db: ScratchpadDB) -> None:
    """A result returned under the wrong id breaks the conversation silently."""
    provider = ScriptedProvider(_concluding_script(loaded_db))
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), coverage_nudges=0).run()

    second_call = provider.calls[1]
    results = [r for message in second_call.messages for r in message.tool_results]
    assert [r.call_id for r in results] == ["c1"]
    assert results[0].is_error is False


def test_results_from_one_turn_go_back_in_a_single_message(loaded_db: ScratchpadDB) -> None:
    """Splitting them trains the model out of asking for tools in parallel."""
    parallel = Turn(
        tool_calls=(
            tool_call_turn("query_templates", {}, call_id="a").tool_calls[0],
            tool_call_turn("query_templates", {"order_by": "count"}, call_id="b").tool_calls[0],
        ),
        stop_reason="tool_use",
    )
    provider = ScriptedProvider([parallel, text_turn("done")])
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), coverage_nudges=0).run()

    final = provider.calls[-1]
    carrying = [m for m in final.messages if m.tool_results]
    assert len(carrying) == 1
    assert [r.call_id for r in carrying[0].tool_results] == ["a", "b"]


def test_the_system_prompt_never_changes_across_steps(loaded_db: ScratchpadDB) -> None:
    """The digest is the expensive stable prefix; editing it mid-run defeats caching."""
    provider = ScriptedProvider(_concluding_script(loaded_db))
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), coverage_nudges=0).run()

    prompts = {call.system for call in provider.calls}
    assert len(prompts) == 1


def test_the_digest_leads_with_the_most_anomalous_template(loaded_db: ScratchpadDB) -> None:
    """The ranking is the search order, so it has to be what the model reads first."""
    prompt = build_system_prompt(loaded_db)
    body = prompt.split("most anomalous first")[1]
    assert ROOT_CAUSE_MARKER in body.splitlines()[2]


def test_every_tool_call_is_logged_for_audit(loaded_db: ScratchpadDB) -> None:
    provider = ScriptedProvider(_concluding_script(loaded_db))
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), coverage_nudges=0).run()

    logged = loaded_db.queries()
    assert len(logged) == 3
    assert [q["step"] for q in logged] == [1, 2, 3]


def test_the_run_is_attributed_and_measured(loaded_db: ScratchpadDB) -> None:
    provider = ScriptedProvider(_concluding_script(loaded_db))
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), coverage_nudges=0).run()

    view = MetricView(loaded_db.metrics("investigate"))
    assert view.text(INVESTIGATE_INVESTIGATOR) == INVESTIGATOR_NAME
    assert view.text(INVESTIGATE_OUTCOME) == "converged"
    assert view.number(INVESTIGATE_TOOL_CALLS) == 3
    assert view.number(INVESTIGATE_CACHED_INPUT_TOKENS) == 90
    assert view.flag(INVESTIGATE_BUDGET_LIMITED) is False
    assert view.text(INVESTIGATE_CAVEAT)


# --------------------------------------------------------------- the budget


def test_hitting_the_cap_forces_a_conclusion(loaded_db: ScratchpadDB) -> None:
    """An investigation cut short must still say something, and say that it was cut short."""
    script = [tool_call_turn("query_templates", {}, call_id=f"c{i}") for i in range(3)]
    script.append(text_turn("I ran out of budget; the pool template looked most likely."))
    provider = ScriptedProvider(script)

    result = InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), max_tool_calls=3).run()

    assert result.budget_limited is True
    assert result.stop_reason == "budget_exhausted"
    assert provider.remaining == 0, "the convergence turn should have been spent"


def test_the_convergence_turn_takes_the_tools_away(loaded_db: ScratchpadDB) -> None:
    """Asking for a conclusion while leaving tools available just spends another call."""
    script = [tool_call_turn("query_templates", {}, call_id="c1"), text_turn("concluding")]
    provider = ScriptedProvider(script)
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), max_tool_calls=1).run()

    assert provider.calls[0].tools, "the working turn is offered tools"
    assert not provider.calls[-1].tools, "the convergence turn is not"


def test_a_budget_limited_run_is_recorded_and_reported(loaded_db: ScratchpadDB) -> None:
    """The difference between cut short and finished has to reach the reader in words."""
    script = [tool_call_turn("query_templates", {}, call_id="c1"), text_turn("partial view")]
    provider = ScriptedProvider(script)
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), max_tool_calls=1).run()

    view = MetricView(loaded_db.metrics("investigate"))
    assert view.flag(INVESTIGATE_BUDGET_LIMITED) is True
    assert view.text(INVESTIGATE_OUTCOME) == "budget_limited"

    report = generate_report(loaded_db)
    assert "budget-limited" in report
    assert "not as a completed investigation" in report


def test_the_budget_is_only_offered_to_providers_that_support_it(
    loaded_db: ScratchpadDB,
) -> None:
    """A provider without task budgets relies on the hard cap instead of a silent no-op."""
    without = ScriptedProvider([text_turn("done")], supports_task_budget=False)
    InvestigationLoop(
        loaded_db, without, _toolbox(loaded_db), task_budget_tokens=64000, coverage_nudges=0
    ).run()
    assert without.calls[0].task_budget_tokens is None

    with_budget = ScriptedProvider([text_turn("done")], supports_task_budget=True)
    InvestigationLoop(
        loaded_db, with_budget, _toolbox(loaded_db), task_budget_tokens=64000, coverage_nudges=0
    ).run()
    assert with_budget.calls[0].task_budget_tokens == 64000


# --------------------------------------------------------------- the adversarial pass


def _critique(payload: dict[str, object]) -> ScriptedProvider:
    return ScriptedProvider([text_turn(json.dumps(payload))], name="critic", model="critic-1")


def test_unexplained_signal_is_arithmetic_not_judgement(loaded_db: ScratchpadDB) -> None:
    """The one adversarial test a model cannot talk its way out of.

    Templates 8 and 9 are confined to the outage; 5 and 2 run the whole log.
    """
    loaded_db.write_note(1, "only about template 9", {"template_ids": [9]}, "medium")
    assert unexplained_signal_templates(loaded_db, [9, 8]) == ([8], [])
    assert unexplained_signal_templates(loaded_db, [9]) == ([], [])


def test_a_chronic_template_is_not_counted_as_an_unexplained_finding(
    loaded_db: ScratchpadDB,
) -> None:
    """The permanent false warning this replaced.

    The anomaly score has no duration term, so a steady background error stream ranks as
    signal. An investigation that correctly treats it as pre-existing was then faulted for the
    omission on every run, and a warning that always fires is one a reader learns to skip.
    """
    loaded_db.write_note(1, "only about template 9", {"template_ids": [9]}, "medium")

    acute, chronic = unexplained_signal_templates(loaded_db, [9, 5, 2])

    assert acute == []
    assert chronic == [5, 2]


def test_an_acute_template_is_still_counted(loaded_db: ScratchpadDB) -> None:
    """Control for the exclusion above: it removes chronic templates, not the check itself."""
    loaded_db.write_note(1, "only about template 9", {"template_ids": [9]}, "medium")

    acute, chronic = unexplained_signal_templates(loaded_db, [9, 8, 5])

    assert acute == [8]
    assert chronic == [5]


def test_a_sound_investigation_draws_no_objections(loaded_db: ScratchpadDB) -> None:
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    result = run_adversarial_check(
        loaded_db, _critique({"assessment": "sound", "objections": []}), [9]
    )

    assert result.objections == []
    assert result.outcome == "no_objections"


def test_objections_citing_nothing_cannot_overturn_a_cited_conclusion(
    loaded_db: ScratchpadDB,
) -> None:
    """Architecture §6.2: weight objections by evidence strength, not by existence."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    critic = _critique(
        {
            "assessment": "doubtful",
            "objections": [{"claim": "the conclusion", "objection": "feels wrong"}],
        }
    )
    result = run_adversarial_check(loaded_db, critic, [9])

    assert len(result.objections) == 1
    assert result.evidenced_objections == []
    assert result.outcome == "objections_unevidenced"


def test_an_evidenced_objection_gets_a_rebuttal(loaded_db: ScratchpadDB) -> None:
    """A one-shot veto becomes a debate: the original reasoning answers back."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    critic = _critique(
        {
            "assessment": "questionable",
            "objections": [
                {
                    "claim": "pool exhausted",
                    "objection": "template 5 fires more often",
                    "template_ids": [5],
                    "severity": "high",
                }
            ],
        }
    )
    rebutter = ScriptedProvider(
        [text_turn(json.dumps({"responses": [{"objection_id": "o1", "conceded": False}]}))]
    )
    result = run_adversarial_check(loaded_db, critic, [9], rebuttal_provider=rebutter)

    assert len(result.rebuttals) == 1
    assert result.outcome == "objections_answered"
    assert result.high_severity_objections == ["pool exhausted"]


def test_a_conceded_objection_says_so(loaded_db: ScratchpadDB) -> None:
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    critic = _critique(
        {
            "objections": [
                {"claim": "c", "objection": "o", "template_ids": [5], "severity": "medium"}
            ]
        }
    )
    rebutter = ScriptedProvider([text_turn(json.dumps({"responses": [{"conceded": True}]}))])
    result = run_adversarial_check(loaded_db, critic, [9], rebuttal_provider=rebutter)

    assert result.outcome == "objections_conceded"


def test_an_unreadable_critique_is_not_a_pass(loaded_db: ScratchpadDB) -> None:
    """Treating a reply we cannot parse as silence would read as approval."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    result = run_adversarial_check(loaded_db, ScriptedProvider([text_turn("not json")]), [9])

    assert result.outcome == "unreadable_critique"


def test_fenced_json_is_still_read(loaded_db: ScratchpadDB) -> None:
    """Models mostly return bare JSON; failing on a code fence throws away a good critique."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    fenced = ScriptedProvider([text_turn('```json\n{"assessment": "fine", "objections": []}\n```')])
    assert run_adversarial_check(loaded_db, fenced, [9]).outcome == "no_objections"


def test_nothing_to_check_when_the_loop_recorded_nothing(loaded_db: ScratchpadDB) -> None:
    result = run_adversarial_check(loaded_db, _critique({"objections": []}), [9])
    assert result.outcome == "nothing_to_check"


def test_the_critique_is_attributed(loaded_db: ScratchpadDB) -> None:
    """A report must be able to show the checker was not the reasoner (§6.3)."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    run_adversarial_check(loaded_db, _critique({"objections": []}), [9, 8])

    view = MetricView(loaded_db.metrics("adversarial"))
    assert view.text(ADVERSARIAL_OUTCOME) == "no_objections"
    assert view.number(ADVERSARIAL_OBJECTIONS) == 0
    assert view.number(ADVERSARIAL_UNEXPLAINED_SIGNAL) == 1


def test_unexplained_signal_reaches_the_report(loaded_db: ScratchpadDB) -> None:
    loaded_db.write_note(1, "only template 9", {"template_ids": [9]}, "high")
    run_adversarial_check(loaded_db, _critique({"objections": []}), [9, 8])

    report = generate_report(loaded_db)
    assert "not accounted for by any note" in report


def test_unexplained_chronic_templates_do_not_raise_a_warning(loaded_db: ScratchpadDB) -> None:
    """Control for the warning above: it fires on acute omissions, and only those."""
    loaded_db.write_note(1, "only template 9", {"template_ids": [9]}, "high")
    run_adversarial_check(loaded_db, _critique({"objections": []}), [9, 5, 2])

    report = generate_report(loaded_db)

    assert "not accounted for by any note" not in report
    # Still counted, as an observation rather than an alarm.
    assert "| adversarial | unexplained_chronic_templates | 2 |" in report


def test_running_past_the_script_is_an_error(loaded_db: ScratchpadDB) -> None:
    """A loop that asks for more turns than the script has is a bug in the test."""
    from mistify.llm.base import ProviderError

    provider = ScriptedProvider([tool_call_turn("query_templates", {}, call_id="c1")])
    with pytest.raises(ProviderError):
        InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), coverage_nudges=0).run()


# ------------------------------------------------------- what the check costs


def _objecting_critique(usage: Usage | None = None) -> ScriptedProvider:
    payload = {
        "objections": [
            {"claim": "pool exhausted", "objection": "t5 fires more", "template_ids": [5]}
        ]
    }
    return ScriptedProvider(
        [text_turn(json.dumps(payload), usage=usage or Usage())], name="critic", model="critic-1"
    )


def _rebutter(model: str, usage: Usage | None = None) -> ScriptedProvider:
    reply = json.dumps({"responses": [{"objection_id": "o1", "conceded": False}]})
    return ScriptedProvider([text_turn(reply, usage=usage or Usage())], model=model)


def test_the_adversarial_pass_records_what_it_spent(loaded_db: ScratchpadDB) -> None:
    """One or two calls against the loop's fifteen -- but on a second model, so a run total
    that dropped them would understate the bill by the entire cost of the check."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    run_adversarial_check(
        loaded_db,
        _objecting_critique(Usage(input_tokens=800, output_tokens=120)),
        [9],
        rebuttal_provider=_rebutter("loop-model", Usage(input_tokens=400, output_tokens=60)),
    )

    view = MetricView(loaded_db.metrics("adversarial"))
    assert view.number(ADVERSARIAL_MODEL_CALLS) == 2
    assert view.number(ADVERSARIAL_INPUT_TOKENS) == 1200
    assert view.number(ADVERSARIAL_OUTPUT_TOKENS) == 180


def test_a_pass_that_makes_one_call_reports_one_call(loaded_db: ScratchpadDB) -> None:
    """Control for the count above: it tracks the calls actually made, it is not fixed at two."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    run_adversarial_check(
        loaded_db, _critique({"objections": []}), [9], rebuttal_provider=_rebutter("loop-model")
    )

    view = MetricView(loaded_db.metrics("adversarial"))
    assert view.number(ADVERSARIAL_MODEL_CALLS) == 1


def test_a_rebuttal_on_another_model_says_which(loaded_db: ScratchpadDB) -> None:
    """Two models can spend this stage's tokens, and they are not billed at the same rate."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    run_adversarial_check(
        loaded_db, _objecting_critique(), [9], rebuttal_provider=_rebutter("loop-model")
    )

    assert MetricView(loaded_db.metrics("adversarial")).text(ADVERSARIAL_REBUTTAL_MODEL) == (
        "loop-model"
    )


def test_no_rebuttal_model_is_recorded_when_it_is_the_same_model(loaded_db: ScratchpadDB) -> None:
    """Control for the metric above: it marks a real split, so it must stay absent otherwise.

    Recording it unconditionally would make every run look like it used two models, including
    the ones that did not.
    """
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    critic = _objecting_critique()
    run_adversarial_check(loaded_db, critic, [9], rebuttal_provider=_rebutter(critic.model))

    assert MetricView(loaded_db.metrics("adversarial")).text(ADVERSARIAL_REBUTTAL_MODEL) is None


def test_the_report_says_what_the_whole_run_cost(loaded_db: ScratchpadDB) -> None:
    """The loop and the check are both on the bill, and the report has to add them up."""
    loop = ScriptedProvider(_concluding_script(loaded_db))
    InvestigationLoop(loaded_db, loop, _toolbox(loaded_db), coverage_nudges=0).run()
    run_adversarial_check(
        loaded_db,
        _objecting_critique(Usage(input_tokens=800, output_tokens=120)),
        [9],
        rebuttal_provider=_rebutter("loop-model", Usage(input_tokens=400, output_tokens=60)),
    )

    report = generate_report(loaded_db)

    assert "## Token usage" in report
    # The loop's 120 + 40 plus the check's 1,200 + 180.
    assert "1,540" in report


def test_a_run_with_no_model_calls_reports_no_token_usage(loaded_db: ScratchpadDB) -> None:
    """Control for the section above: it renders what was measured, not a fixed table.

    The deterministic investigator calls nothing, and a token table full of zeros would claim
    a measurement nobody took.
    """
    report = generate_report(loaded_db)

    assert "## Token usage" in report
    assert "No stage reported model usage" in report


# --------------------------------------------- the critique reaches the reader


def _conceding_run(db: ScratchpadDB) -> None:
    """A critique that objects with evidence, and an investigation that gives ground."""
    db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    critic = _critique(
        {
            "assessment": "The causal link is asserted rather than shown.",
            "objections": [
                {
                    "claim": "pool exhausted",
                    "objection": "template 5 fires throughout the window, not just during it",
                    "template_ids": [5],
                    "severity": "high",
                }
            ],
            "alternative": "A gateway degradation that predates the pool problem.",
        }
    )
    rebutter = ScriptedProvider(
        [
            text_turn(
                json.dumps(
                    {
                        "responses": [
                            {
                                "objection_id": "o1",
                                "response": "Fair -- 5 is not confined.",
                                "conceded": True,
                            }
                        ],
                        "revised_confidence": "medium",
                    }
                )
            )
        ]
    )
    run_adversarial_check(db, critic, [9], rebuttal_provider=rebutter)


def test_the_objection_itself_reaches_the_report(loaded_db: ScratchpadDB) -> None:
    """A count cannot be acted on. "2 evidence-backed objections" told a reader nothing about
    what was wrong, what it cited, or whether the investigation agreed."""
    _conceding_run(loaded_db)

    challenge = generate_report(loaded_db).split("## The challenge")[1]

    assert "template 5 fires throughout the window" in challenge
    assert "The causal link is asserted rather than shown." in challenge
    assert "templates 5" in challenge


def test_a_conceded_objection_is_marked_as_conceded(loaded_db: ScratchpadDB) -> None:
    """The single most decision-relevant fact in the document: the reasoning gave ground."""
    _conceding_run(loaded_db)

    report = generate_report(loaded_db)

    assert "conceded" in report.split("## The challenge")[1]
    assert "Contested" in report.split("## What was found")[1].split("## ")[0]


def test_an_answered_objection_is_not_reported_as_contested(loaded_db: ScratchpadDB) -> None:
    """Control for the verdict line above: contested means conceded, not merely challenged.

    Every objection answered and none conceded is a conclusion that held, and flagging it the
    same way as one that collapsed would train a reader to ignore the flag.
    """
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    run_adversarial_check(
        loaded_db, _objecting_critique(), [9], rebuttal_provider=_rebutter("loop-model")
    )

    verdict = generate_report(loaded_db).split("## What was found")[1].split("## ")[0]

    assert "Challenged and answered" in verdict
    assert "Contested" not in verdict


def test_the_revised_confidence_reaches_the_overview(loaded_db: ScratchpadDB) -> None:
    """The prompt has always asked for it; it used to be parsed and dropped, so a conclusion
    that had conceded ground still reported the confidence it started with."""
    _conceding_run(loaded_db)

    verdict = generate_report(loaded_db).split("## What was found")[1].split("## ")[0]

    assert "Confidence after the challenge: **medium**" in verdict


def test_the_alternative_explanation_is_offered_to_the_reader(loaded_db: ScratchpadDB) -> None:
    """The first thing to check when the verdict does not hold up."""
    _conceding_run(loaded_db)

    assert "A gateway degradation that predates" in generate_report(loaded_db)


def test_an_unchallenged_investigation_says_so(loaded_db: ScratchpadDB) -> None:
    """Control for the challenge section: it reports what happened, it is not always full."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    run_adversarial_check(loaded_db, _critique({"objections": []}), [9])

    report = generate_report(loaded_db)

    assert "Unchallenged" in report.split("## What was found")[1].split("## ")[0]
    assert "No objections were raised" in report.split("## The challenge")[1]


def test_a_run_with_no_adversarial_pass_does_not_imply_one(loaded_db: ScratchpadDB) -> None:
    """Absent is not the same as passed. A report that stayed silent would read as approval."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")

    report = generate_report(loaded_db)

    assert "No adversarial pass was run" in report
    assert "nothing has argued against the findings" in report


# ------------------------------------------------ pairing answers to objections


def _two_objections() -> ScriptedProvider:
    return _critique(
        {
            "objections": [
                {"claim": "first claim", "objection": "a", "template_ids": [5]},
                {"claim": "second claim", "objection": "b", "template_ids": [7]},
            ]
        }
    )


def test_an_answer_lands_on_the_objection_whose_id_it_quotes(
    loaded_db: ScratchpadDB,
) -> None:
    """Answered out of order on purpose.

    Paired by position this attaches the concession to the first claim, which is an admission
    the investigation never made -- worse than reporting nothing, because it reads as real.
    """
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    rebutter = ScriptedProvider(
        [
            text_turn(
                json.dumps(
                    {
                        "responses": [
                            {
                                "objection_id": "o2",
                                "response": "conceding the second",
                                "conceded": True,
                            },
                            {
                                "objection_id": "o1",
                                "response": "answering the first",
                                "conceded": False,
                            },
                        ]
                    }
                )
            )
        ]
    )
    run_adversarial_check(loaded_db, _two_objections(), [9], rebuttal_provider=rebutter)

    by_claim = {o["claim"]: o for o in loaded_db.adversarial_objections()}

    assert by_claim["first claim"]["conceded"] is False
    assert by_claim["second claim"]["conceded"] is True


def test_an_answer_naming_no_known_objection_is_kept_unmatched(
    loaded_db: ScratchpadDB,
) -> None:
    """Dropping it would hide that the investigation answered; guessing is what this replaced."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    rebutter = ScriptedProvider(
        [
            text_turn(
                json.dumps(
                    {"responses": [{"objection_id": "o99", "response": "stray", "conceded": True}]}
                )
            )
        ]
    )
    run_adversarial_check(loaded_db, _objecting_critique(), [9], rebuttal_provider=rebutter)

    stored = loaded_db.adversarial_objections()
    unmatched = [o for o in stored if o["severity"] == "unmatched_response"]

    assert len(unmatched) == 1
    assert unmatched[0]["response"] == "stray"
    # The real objection is still there, and still unanswered rather than wrongly conceded.
    original = next(o for o in stored if o["claim"] == "pool exhausted")
    assert original["response"] is None


def test_objections_are_numbered_from_one(loaded_db: ScratchpadDB) -> None:
    """The ids are ours and deterministic, which is the whole reason they can be relied on."""
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [9]}, "high")
    run_adversarial_check(loaded_db, _two_objections(), [9], rebut=False)

    assert [o["objection_id"] for o in loaded_db.adversarial_objections()] == ["o1", "o2"]


# --------------------------------------------------- keeping the history bounded


def _slice_script(db: ScratchpadDB, steps: int) -> list[Turn]:
    """`steps` slice calls, then a conclusion. Each slice returns a table worth eliding."""
    template = int(db.top_templates(limit=1, order_by="anomaly_score")[0]["template_id"])
    script: list[Turn] = [
        tool_call_turn("get_slice", {"template_id": template}, call_id=f"c{i}")
        for i in range(steps)
    ]
    script.append(text_turn("done", usage=Usage(input_tokens=1000, output_tokens=10)))
    return script


def test_old_tool_output_is_reduced_to_its_summary_line(loaded_db: ScratchpadDB) -> None:
    """The conversation is re-sent every step, so an early slice is paid for on every one.

    What survives is the header the tool wrote -- how many rows matched, how many were shown,
    what the filters were -- which is the part the model reasons about several steps later.
    """
    provider = ScriptedProvider(_slice_script(loaded_db, 5))
    InvestigationLoop(
        loaded_db, provider, _toolbox(loaded_db), tool_result_history_steps=2, coverage_nudges=0
    ).run()

    last_sent = provider.calls[-1].messages
    results = [r for m in last_sent for r in m.tool_results]

    elided = [r for r in results if ELIDED in r.content]
    assert elided, "no tool output was compacted"
    # The header survives; the rows do not.
    assert all("shown of" in r.content for r in elided)
    assert all("|" not in r.content.split("\n")[1] for r in elided)


def test_the_recent_window_is_kept_in_full(loaded_db: ScratchpadDB) -> None:
    """Control for the compaction above: it trims the tail of the history, not all of it.

    The model has to be able to read the rows it just asked for, or the tool call was pointless.
    """
    provider = ScriptedProvider(_slice_script(loaded_db, 5))
    InvestigationLoop(
        loaded_db, provider, _toolbox(loaded_db), tool_result_history_steps=2, coverage_nudges=0
    ).run()

    results = [r for m in provider.calls[-1].messages for r in m.tool_results]
    intact = [r for r in results if ELIDED not in r.content]

    assert len(intact) == 2


def test_compaction_can_be_turned_off(loaded_db: ScratchpadDB) -> None:
    """Zero keeps everything, which is what the cost curve looked like before this existed."""
    provider = ScriptedProvider(_slice_script(loaded_db, 5))
    InvestigationLoop(
        loaded_db, provider, _toolbox(loaded_db), tool_result_history_steps=0, coverage_nudges=0
    ).run()

    results = [r for m in provider.calls[-1].messages for r in m.tool_results]

    assert all(ELIDED not in r.content for r in results)


def test_tool_calls_are_never_touched_by_compaction(loaded_db: ScratchpadDB) -> None:
    """They carry the provider's thought signature, which must replay byte-identical.

    Gemini rejects the whole request when it does not, so trimming a call rather than a result
    would fail the investigation outright rather than degrade it.
    """
    provider = ScriptedProvider(_slice_script(loaded_db, 5))
    InvestigationLoop(
        loaded_db, provider, _toolbox(loaded_db), tool_result_history_steps=1, coverage_nudges=0
    ).run()

    calls = [c for m in provider.calls[-1].messages for c in m.tool_calls]

    assert [c.name for c in calls] == ["get_slice"] * 5
    assert [c.arguments for c in calls] == [c.arguments for c in calls if c.arguments]


def test_the_run_reports_its_input_growth(loaded_db: ScratchpadDB) -> None:
    """The total hides the curve, and the curve is what decides whether a longer run is
    affordable."""
    script = [
        tool_call_turn("query_templates", {}, call_id="c1", usage=Usage(input_tokens=100)),
        tool_call_turn("query_templates", {}, call_id="c2", usage=Usage(input_tokens=400)),
        text_turn("done", usage=Usage(input_tokens=900)),
    ]
    InvestigationLoop(
        loaded_db, ScriptedProvider(script), _toolbox(loaded_db), coverage_nudges=0
    ).run()

    view = MetricView(loaded_db.metrics("investigate"))

    assert view.text(INVESTIGATE_INPUT_TOKENS_PER_STEP) == "100,400,900"
    assert view.number(INVESTIGATE_INPUT_GROWTH) == 9.0


def test_flat_input_is_not_reported_as_growth(loaded_db: ScratchpadDB) -> None:
    """Control for the factor above: it measures the curve, it is not a constant."""
    script = [
        tool_call_turn("query_templates", {}, call_id="c1", usage=Usage(input_tokens=100)),
        text_turn("done", usage=Usage(input_tokens=100)),
    ]
    InvestigationLoop(
        loaded_db, ScriptedProvider(script), _toolbox(loaded_db), coverage_nudges=0
    ).run()

    assert MetricView(loaded_db.metrics("investigate")).number(INVESTIGATE_INPUT_GROWTH) == 1.0


def test_small_tool_output_survives_compaction(loaded_db: ScratchpadDB) -> None:
    """Compaction exists to stop one wide slice being re-sent forever, not to shred evidence.

    Measured across five runs: every investigation examined the planted precursor with a
    ten-row slice at step three, had it summarised away by step six, and concluded without it.
    One re-queried three templates it had already read. A conclusion is written last, so small
    evidence has to still be there when it is.
    """
    script = [
        tool_call_turn("get_slice", {"template_id": 8, "max_lines": 10}, call_id=f"c{i}")
        for i in range(5)
    ]
    script.append(text_turn("done"))
    provider = ScriptedProvider(script)
    InvestigationLoop(
        loaded_db, provider, _toolbox(loaded_db), tool_result_history_steps=1, coverage_nudges=0
    ).run()

    results = [r for m in provider.calls[-1].messages for r in m.tool_results]

    assert results, "no tool results reached the final call"
    assert all(ELIDED not in r.content for r in results)


def test_large_tool_output_is_still_compacted(loaded_db: ScratchpadDB) -> None:
    """Control for the exemption above: it is a size threshold, not compaction switched off."""
    provider = ScriptedProvider(_slice_script(loaded_db, 5))
    InvestigationLoop(
        loaded_db, provider, _toolbox(loaded_db), tool_result_history_steps=1, coverage_nudges=0
    ).run()

    results = [r for m in provider.calls[-1].messages for r in m.tool_results]

    assert any(ELIDED in r.content for r in results)


# ------------------------------------------------- refusing an incomplete conclusion


def _signal_ids(db: ScratchpadDB) -> list[int]:
    raw = MetricView(db.metrics("anomaly")).text(ANOMALY_SIGNAL_TEMPLATE_IDS) or ""
    return [int(part) for part in raw.split(",") if part.strip()]


def _note_turn(template_id: int, call_id: str) -> Turn:
    return tool_call_turn(
        "write_note",
        {
            "note": f"about template {template_id}",
            "evidence": {"template_ids": [template_id], "log_event_ids": []},
            "confidence": "high",
        },
        call_id=call_id,
    )


def test_a_conclusion_leaving_signal_unexplained_is_sent_back(loaded_db: ScratchpadDB) -> None:
    """The check was model-free and already existed; it just ran after the run had ended.

    Ten runs of the sample incident concluded without citing the planted precursor and the
    adversarial pass caught it every time, too late to change anything.
    """
    signal = _signal_ids(loaded_db)
    provider = ScriptedProvider(
        [_note_turn(signal[0], "c1"), text_turn("done"), text_turn("done for real")]
    )

    result = InvestigationLoop(loaded_db, provider, _toolbox(loaded_db)).run()

    assert result.coverage_nudges == 1
    sent = provider.calls[-1].messages[-1].text
    assert "were ranked as signal" in sent
    assert str(signal[1]) in sent


def test_a_conclusion_that_covers_the_signal_is_accepted(loaded_db: ScratchpadDB) -> None:
    """Control: the nudge fires on a gap, not on every conclusion.

    Without this the test above would pass on a loop that always asked for one more turn.
    """
    script = [
        _note_turn(template_id, f"c{i}") for i, template_id in enumerate(_signal_ids(loaded_db))
    ]
    script.append(text_turn("done"))
    provider = ScriptedProvider(script)

    result = InvestigationLoop(loaded_db, provider, _toolbox(loaded_db)).run()

    assert result.coverage_nudges == 0


def test_the_nudge_fires_at_most_the_configured_number_of_times(
    loaded_db: ScratchpadDB,
) -> None:
    """A model that keeps declining must not be able to spin the loop."""
    provider = ScriptedProvider([text_turn("done"), text_turn("still done")])

    result = InvestigationLoop(loaded_db, provider, _toolbox(loaded_db), coverage_nudges=1).run()

    assert result.coverage_nudges == 1
    assert len(provider.calls) == 2


def test_a_chronic_template_does_not_trigger_the_nudge(loaded_db: ScratchpadDB) -> None:
    """Same exclusion the warning uses: background is not an omission.

    Otherwise every investigation would be sent back for not explaining a log's steady error
    stream, which is the false-alarm loop this project already removed once.
    """
    chronic = sorted(loaded_db.chronic_template_ids() & set(_signal_ids(loaded_db)))
    acute = [i for i in _signal_ids(loaded_db) if i not in chronic]
    assert chronic, "the fixture is expected to contain a chronic signal template"

    script = [_note_turn(template_id, f"c{i}") for i, template_id in enumerate(acute)]
    script.append(text_turn("done"))

    result = InvestigationLoop(loaded_db, ScriptedProvider(script), _toolbox(loaded_db)).run()

    assert result.coverage_nudges == 0

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
from mistify.agent.loop import INVESTIGATOR_NAME, InvestigationLoop, build_system_prompt
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
    INVESTIGATE_BUDGET_LIMITED,
    INVESTIGATE_CACHED_INPUT_TOKENS,
    INVESTIGATE_CAVEAT,
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
    result = InvestigationLoop(loaded_db, provider, _toolbox(loaded_db)).run()

    assert result.tool_calls == 3
    assert result.budget_limited is False
    assert result.stop_reason == "end_turn"
    assert len(result.notes) == 1
    assert ROOT_CAUSE_MARKER in result.notes[0].note


def test_tool_results_are_fed_back_under_the_right_id(loaded_db: ScratchpadDB) -> None:
    """A result returned under the wrong id breaks the conversation silently."""
    provider = ScriptedProvider(_concluding_script(loaded_db))
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db)).run()

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
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db)).run()

    final = provider.calls[-1]
    carrying = [m for m in final.messages if m.tool_results]
    assert len(carrying) == 1
    assert [r.call_id for r in carrying[0].tool_results] == ["a", "b"]


def test_the_system_prompt_never_changes_across_steps(loaded_db: ScratchpadDB) -> None:
    """The digest is the expensive stable prefix; editing it mid-run defeats caching."""
    provider = ScriptedProvider(_concluding_script(loaded_db))
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db)).run()

    prompts = {call.system for call in provider.calls}
    assert len(prompts) == 1


def test_the_digest_leads_with_the_most_anomalous_template(loaded_db: ScratchpadDB) -> None:
    """The ranking is the search order, so it has to be what the model reads first."""
    prompt = build_system_prompt(loaded_db)
    body = prompt.split("most anomalous first")[1]
    assert ROOT_CAUSE_MARKER in body.splitlines()[2]


def test_every_tool_call_is_logged_for_audit(loaded_db: ScratchpadDB) -> None:
    provider = ScriptedProvider(_concluding_script(loaded_db))
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db)).run()

    logged = loaded_db.queries()
    assert len(logged) == 3
    assert [q["step"] for q in logged] == [1, 2, 3]


def test_the_run_is_attributed_and_measured(loaded_db: ScratchpadDB) -> None:
    provider = ScriptedProvider(_concluding_script(loaded_db))
    InvestigationLoop(loaded_db, provider, _toolbox(loaded_db)).run()

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
    InvestigationLoop(loaded_db, without, _toolbox(loaded_db), task_budget_tokens=64000).run()
    assert without.calls[0].task_budget_tokens is None

    with_budget = ScriptedProvider([text_turn("done")], supports_task_budget=True)
    InvestigationLoop(loaded_db, with_budget, _toolbox(loaded_db), task_budget_tokens=64000).run()
    assert with_budget.calls[0].task_budget_tokens == 64000


# --------------------------------------------------------------- the adversarial pass


def _critique(payload: dict[str, object]) -> ScriptedProvider:
    return ScriptedProvider([text_turn(json.dumps(payload))], name="critic", model="critic-1")


def test_unexplained_signal_is_arithmetic_not_judgement(loaded_db: ScratchpadDB) -> None:
    """The one adversarial test a model cannot talk its way out of."""
    loaded_db.write_note(1, "only about template 9", {"template_ids": [9]}, "medium")
    assert unexplained_signal_templates(loaded_db, [9, 5, 2]) == [5, 2]
    assert unexplained_signal_templates(loaded_db, [9]) == []


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
        [text_turn(json.dumps({"responses": [{"objection": "t5", "conceded": False}]}))]
    )
    result = run_adversarial_check(loaded_db, critic, [9], rebuttal_provider=rebutter)

    assert len(result.rebuttals) == 1
    assert result.outcome == "objections_answered"
    assert result.unsupported_claims == ["pool exhausted"]


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
    run_adversarial_check(loaded_db, _critique({"objections": []}), [9, 5])

    view = MetricView(loaded_db.metrics("adversarial"))
    assert view.text(ADVERSARIAL_OUTCOME) == "no_objections"
    assert view.number(ADVERSARIAL_OBJECTIONS) == 0
    assert view.number(ADVERSARIAL_UNEXPLAINED_SIGNAL) == 1


def test_unexplained_signal_reaches_the_report(loaded_db: ScratchpadDB) -> None:
    loaded_db.write_note(1, "only template 9", {"template_ids": [9]}, "high")
    run_adversarial_check(loaded_db, _critique({"objections": []}), [9, 5, 2])

    report = generate_report(loaded_db)
    assert "not accounted for by any note" in report


def test_running_past_the_script_is_an_error(loaded_db: ScratchpadDB) -> None:
    """A loop that asks for more turns than the script has is a bug in the test."""
    from mistify.llm.base import ProviderError

    provider = ScriptedProvider([tool_call_turn("query_templates", {}, call_id="c1")])
    with pytest.raises(ProviderError):
        InvestigationLoop(loaded_db, provider, _toolbox(loaded_db)).run()


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
    reply = json.dumps({"responses": [{"objection": "t5", "conceded": False}]})
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
    InvestigationLoop(loaded_db, loop, _toolbox(loaded_db)).run()
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

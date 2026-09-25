"""The run's hard token ceiling, driven by scripted providers -- no credential, no bill.

Every test that asserts the ceiling stopped something is paired with one where the same
script, with room to spare, is not stopped. A ceiling test that could not fail would pass just
as well against a loop that ignores the budget entirely.
"""

from __future__ import annotations

from typing import Any

import pytest

from mistify.agent import runner
from mistify.agent.budget import (
    POST_LOOP_SHARE,
    BudgetedProvider,
    TokenBudget,
    TokenCeilingReached,
)
from mistify.agent.loop import InvestigationLoop
from mistify.agent.tools import ToolBox
from mistify.common.config import MistifyConfig, PipelineConfig
from mistify.common.models import NoiseThresholds
from mistify.llm.base import Message, Usage
from mistify.llm.scripted import ScriptedProvider, text_turn, tool_call_turn
from mistify.metrics import (
    BUDGET_MAX_TOTAL_TOKENS,
    BUDGET_REFUSED_STAGES,
    BUDGET_SPENT_TOKENS,
    INVESTIGATE_BUDGET_LIMIT,
    INVESTIGATE_OUTCOME,
    MetricView,
)
from mistify.report.generator import generate_report
from mistify.scratchpad.db import ScratchpadDB

NOISE = NoiseThresholds(share=0.15, anomaly_ceiling=0.35)


def _toolbox(db: ScratchpadDB) -> ToolBox:
    return ToolBox(db, noise=NOISE)


def _loop(
    db: ScratchpadDB, provider: ScriptedProvider, budget: TokenBudget, max_tool_calls: int
) -> InvestigationLoop:
    """A loop charging `budget`, with the coverage nudge off so a script's end is its end."""
    return InvestigationLoop(
        db,
        BudgetedProvider(provider, budget),
        _toolbox(db),
        max_tool_calls=max_tool_calls,
        coverage_nudges=0,
    )


def _searching_script(steps: int, tokens_per_step: int) -> list[Any]:
    """`steps` tool calls costing `tokens_per_step` each, then a closing answer."""
    turns: list[Any] = [
        tool_call_turn(
            "query_templates", {}, call_id=f"c{i}", usage=Usage(tokens_per_step - 50, 50)
        )
        for i in range(steps)
    ]
    turns.append(text_turn("The pool template is the most likely cause.", usage=Usage(900, 100)))
    return turns


# ------------------------------------------------------------------ the budget itself


def test_a_call_is_charged_and_refused_once_the_ceiling_is_spent() -> None:
    budget = TokenBudget(ceiling=1_000)
    provider = BudgetedProvider(
        ScriptedProvider([text_turn("a", usage=Usage(900, 100)), text_turn("b")]), budget
    )

    provider.converse("system", [Message(role="user", text="go")])
    assert budget.spent == 1_000

    with pytest.raises(TokenCeilingReached, match=r"1,000 of 1,000 tokens"):
        provider.converse("system", [Message(role="user", text="go")])


def test_a_call_under_the_ceiling_is_not_refused() -> None:
    """The control: one token short of the ceiling, the next call goes ahead."""
    budget = TokenBudget(ceiling=1_001)
    inner = ScriptedProvider([text_turn("a", usage=Usage(900, 100)), text_turn("b")])
    provider = BudgetedProvider(inner, budget)

    provider.converse("system", [Message(role="user", text="go")])
    assert provider.converse("system", [Message(role="user", text="go")]).text == "b"


def test_the_wrapper_reports_the_wrapped_model() -> None:
    """Metrics and reports name the model that did the work, not the wrapper."""
    inner = ScriptedProvider([], model="some-model")
    provider = BudgetedProvider(inner, TokenBudget(ceiling=10_000))
    assert (provider.name, provider.model) == (inner.name, "some-model")


def test_the_loop_keeps_a_share_back_for_the_stages_after_it() -> None:
    budget = TokenBudget(ceiling=100_000, spent=60_000)
    assert budget.loop_limit == int(100_000 * (1 - POST_LOOP_SHARE))
    # Two more steps of 12k would reach 84k: inside the loop's 85k share.
    assert budget.loop_should_stop(12_000) is False
    # Two more of 13k would reach 86k: past it.
    assert budget.loop_should_stop(13_000) is True


# ------------------------------------------------------------------ the loop


def test_the_ceiling_stops_the_loop_before_its_tool_call_cap(loaded_db: ScratchpadDB) -> None:
    """Ten steps are allowed by the cap; the budget allows about three of 2k each."""
    provider = ScriptedProvider(_searching_script(steps=10, tokens_per_step=2_000))
    budget = TokenBudget(ceiling=10_000)
    loop = _loop(loaded_db, provider, budget, max_tool_calls=10)

    result = loop.run()

    assert result.budget_limited is True
    assert result.budget_limit == "tokens"
    assert result.tool_calls < 10
    # The closing turn was asked for, without tools, in words that name the right budget.
    assert not provider.calls[-1].tools
    assert "token budget" in provider.calls[-1].messages[-1].text
    view = MetricView(loaded_db.metrics("investigate"))
    assert view.text(INVESTIGATE_BUDGET_LIMIT) == "tokens"
    assert view.text(INVESTIGATE_OUTCOME) == "budget_limited"
    assert "reached its token ceiling" in generate_report(loaded_db)


def test_a_generous_ceiling_leaves_the_same_script_alone(loaded_db: ScratchpadDB) -> None:
    """The control for the test above: same script, room to spare, the cap decides."""
    provider = ScriptedProvider(_searching_script(steps=3, tokens_per_step=2_000))
    loop = _loop(loaded_db, provider, TokenBudget(ceiling=1_000_000), max_tool_calls=10)

    result = loop.run()

    assert result.budget_limited is False
    assert result.budget_limit is None
    assert result.tool_calls == 3
    assert MetricView(loaded_db.metrics("investigate")).text(INVESTIGATE_BUDGET_LIMIT) is None


def test_the_tool_call_cap_is_still_named_as_the_cap(loaded_db: ScratchpadDB) -> None:
    """A ceiling in place must not relabel a run the cap stopped."""
    provider = ScriptedProvider(_searching_script(steps=2, tokens_per_step=100))
    loop = _loop(loaded_db, provider, TokenBudget(ceiling=1_000_000), max_tool_calls=2)

    result = loop.run()

    assert result.budget_limit == "tool_calls"
    assert "reached its tool-call cap" in generate_report(loaded_db)


def test_a_refused_call_ends_the_loop_without_a_closing_turn(loaded_db: ScratchpadDB) -> None:
    """Nothing is left to spend, so the loop must not try to spend it on a conclusion."""
    provider = ScriptedProvider(_searching_script(steps=3, tokens_per_step=2_000))
    loop = _loop(loaded_db, provider, TokenBudget(ceiling=10_000, spent=10_000), max_tool_calls=10)

    result = loop.run()

    assert result.stop_reason == "token_ceiling"
    assert result.budget_limit == "tokens"
    assert provider.calls == [], "no call reached the model"


def _nudges(provider: ScriptedProvider) -> list[str]:
    return [
        m.text
        for call in provider.calls
        for m in call.messages
        if m.role == "user" and "recorded no findings" in m.text
    ]


def test_a_run_the_ceiling_will_stop_is_asked_to_write_something_down(
    loaded_db: ScratchpadDB,
) -> None:
    """Measured live: stopped at 8 of 30 calls with nothing written, and never asked to."""
    provider = ScriptedProvider(_searching_script(steps=30, tokens_per_step=2_000))
    _loop(loaded_db, provider, TokenBudget(ceiling=20_000), max_tool_calls=30).run()

    assert _nudges(provider), "the nudge should fire on token share, well short of 18 calls"
    assert "most of your token budget" in _nudges(provider)[0]


def test_the_same_run_without_a_ceiling_is_not_asked_early(loaded_db: ScratchpadDB) -> None:
    """The control: the tool-call share alone has not reached the nudge at this point."""
    provider = ScriptedProvider(_searching_script(steps=5, tokens_per_step=2_000))
    _loop(loaded_db, provider, TokenBudget(ceiling=1_000_000), max_tool_calls=30).run()

    assert _nudges(provider) == []


def test_the_loop_reads_its_budget_from_the_provider(loaded_db: ScratchpadDB) -> None:
    """One budget, carried by the provider that charges it -- nothing to keep in step."""
    budget = TokenBudget(ceiling=10_000)
    wrapped = InvestigationLoop(
        loaded_db, BudgetedProvider(ScriptedProvider([]), budget), _toolbox(loaded_db)
    )
    plain = InvestigationLoop(loaded_db, ScriptedProvider([]), _toolbox(loaded_db))
    assert wrapped.token_budget is budget
    assert plain.token_budget is None


def _concluding_early_script() -> list[Any]:
    """A cheap step, a costly conclusion, and turns to spare in case it is sent back.

    The step must stay inside the loop's share -- 1k now, projecting 3k of 8.5k -- or the
    tool-step check stops the loop first and the nudge path is never reached, which is how
    the first version of this test passed with the fix reverted. The 3k conclusion is what
    crosses it: 4k spent plus two more like it is 10k.
    """
    return [
        tool_call_turn("query_templates", {}, call_id="c0", usage=Usage(950, 50)),
        text_turn("Pool exhaustion.", usage=Usage(2_900, 100)),
        tool_call_turn("query_templates", {}, call_id="c1", usage=Usage(900, 100)),
        text_turn("Pool exhaustion, confirmed.", usage=Usage(900, 100)),
    ]


def test_a_conclusion_past_the_loops_share_is_not_sent_back(loaded_db: ScratchpadDB) -> None:
    """A nudge would spend the reserve synthesis and the critique are counting on."""
    provider = ScriptedProvider(_concluding_early_script())
    loop = InvestigationLoop(
        loaded_db,
        BudgetedProvider(provider, TokenBudget(ceiling=10_000)),
        _toolbox(loaded_db),
        max_tool_calls=10,
        coverage_nudges=1,
    )

    result = loop.run()

    assert result.coverage_nudges == 0
    assert len(provider.calls) == 2


def test_the_same_conclusion_with_room_to_spare_is_sent_back(loaded_db: ScratchpadDB) -> None:
    """The control: the nudge still fires when the budget can afford it."""
    provider = ScriptedProvider(_concluding_early_script())
    loop = InvestigationLoop(
        loaded_db,
        BudgetedProvider(provider, TokenBudget(ceiling=1_000_000)),
        _toolbox(loaded_db),
        max_tool_calls=10,
        coverage_nudges=1,
    )

    result = loop.run()

    assert result.coverage_nudges == 1
    assert len(provider.calls) > 2


def test_a_refused_rebuttal_keeps_the_critique_and_its_cost(loaded_db: ScratchpadDB) -> None:
    """The critique ran; only the answer was refused. Its objections and spend are recorded."""
    import json

    from mistify.agent.adversarial import run_adversarial_check
    from mistify.metrics import ADVERSARIAL_INPUT_TOKENS, ADVERSARIAL_OUTCOME

    event = loaded_db.get_slice(max_lines=1)[0]
    loaded_db.write_note(
        step=1,
        note="Pool exhaustion.",
        evidence={"template_ids": [int(event["template_id"])], "log_event_ids": [int(event["id"])]},
        confidence="high",
    )
    objection = {
        "claim": "c",
        "objection": "o",
        "template_ids": [],
        "log_event_ids": [int(event["id"])],
        "severity": "high",
    }
    critique = json.dumps({"assessment": "a", "objections": [objection], "alternative": ""})
    budget = TokenBudget(ceiling=1_000)
    critic = BudgetedProvider(
        ScriptedProvider([text_turn(critique, usage=Usage(900, 100))], model="critic"), budget
    )
    answering = BudgetedProvider(ScriptedProvider([text_turn("{}")], model="loop"), budget)

    with pytest.raises(TokenCeilingReached):
        run_adversarial_check(loaded_db, critic, [], rebuttal_provider=answering)

    view = MetricView(loaded_db.metrics("adversarial"))
    assert view.text(ADVERSARIAL_OUTCOME) == "rebuttal_refused"
    assert view.number(ADVERSARIAL_INPUT_TOKENS) == 900
    assert loaded_db.adversarial_objections(), "the objections the critique raised are kept"


# ------------------------------------------------------------------ the whole run


def _patch_providers(
    monkeypatch: pytest.MonkeyPatch, scripts: dict[str, list[Any]]
) -> dict[str, ScriptedProvider]:
    """Replace the registry with scripted providers keyed by model name."""
    built = {model: ScriptedProvider(turns, model=model) for model, turns in scripts.items()}
    monkeypatch.setattr(runner, "build_provider", lambda _name, model, _cfg: built[model])
    return built


def test_the_ceiling_refuses_the_later_stages_and_the_report_says_so(
    loaded_db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = MistifyConfig(pipeline=PipelineConfig(max_total_tokens=10_000, coverage_nudges=0))
    # One 3k step projects past the loop's 8.5k share; the closing turn then spends the rest.
    loop_script = [
        tool_call_turn("query_templates", {}, call_id="c0", usage=Usage(2_950, 50)),
        text_turn("Pool exhaustion, most likely.", usage=Usage(7_400, 100)),
    ]
    built = _patch_providers(
        monkeypatch,
        {
            config.llm.model: loop_script,
            str(config.llm.synthesis_model): [],
            config.llm.adversarial_model: [],
        },
    )

    runner.run_investigation(loaded_db, config, adversarial=True)

    view = MetricView(loaded_db.metrics("budget"))
    assert view.text(BUDGET_REFUSED_STAGES) == "synthesis,adversarial"
    assert view.number(BUDGET_MAX_TOTAL_TOKENS) == 10_000
    assert view.number(BUDGET_SPENT_TOKENS) == 10_500
    assert built[str(config.llm.synthesis_model)].calls == []
    assert built[config.llm.adversarial_model].calls == []
    # The loop's own closing note survives as the conclusion.
    assert any("Pool exhaustion" in note.note for note in loaded_db.notes())
    report = generate_report(loaded_db)
    assert "refused model calls in: synthesis, adversarial" in report
    assert "Token ceiling: **10,000**; this run spent 10,500 (105%)" in report


def test_a_rerun_does_not_inherit_the_last_runs_refusal(
    loaded_db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found in review: metrics upsert, so a refusal written once outlived the run it described."""
    tight = MistifyConfig(pipeline=PipelineConfig(max_total_tokens=10_000, coverage_nudges=0))
    loop_script = [
        tool_call_turn("query_templates", {}, call_id="c0", usage=Usage(2_950, 50)),
        text_turn("Pool exhaustion, most likely.", usage=Usage(7_400, 100)),
    ]
    _patch_providers(
        monkeypatch,
        {
            tight.llm.model: loop_script,
            str(tight.llm.synthesis_model): [],
            tight.llm.adversarial_model: [],
        },
    )
    runner.run_investigation(loaded_db, tight, adversarial=True)
    first = MetricView(loaded_db.metrics())
    assert first.text(BUDGET_REFUSED_STAGES), "the first run was refused, as the control"
    assert first.text(INVESTIGATE_BUDGET_LIMIT) == "tokens"

    loaded_db.clear_investigation()
    roomy = MistifyConfig(pipeline=PipelineConfig(max_total_tokens=None, coverage_nudges=0))
    roomy.llm.synthesis_model = None
    _patch_providers(monkeypatch, {roomy.llm.model: [text_turn("done")]})
    runner.run_investigation(loaded_db, roomy, adversarial=False)

    second = MetricView(loaded_db.metrics())
    assert second.text(BUDGET_REFUSED_STAGES) is None
    assert second.number(BUDGET_MAX_TOTAL_TOKENS) is None
    assert second.text(INVESTIGATE_BUDGET_LIMIT) is None
    report = generate_report(loaded_db)
    assert "refused model calls" not in report
    assert "No token ceiling was set for this run." in report


def test_a_run_within_the_ceiling_records_its_spend_and_refuses_nothing(
    loaded_db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the same loop, a generous ceiling, and no stage refused."""
    config = MistifyConfig(pipeline=PipelineConfig(max_total_tokens=1_000_000, coverage_nudges=0))
    config.llm.synthesis_model = None
    _patch_providers(
        monkeypatch,
        {
            config.llm.model: [
                tool_call_turn("query_templates", {}, call_id="c0", usage=Usage(2_950, 50)),
                text_turn("Pool exhaustion, most likely.", usage=Usage(900, 100)),
            ]
        },
    )

    runner.run_investigation(loaded_db, config, adversarial=False)

    view = MetricView(loaded_db.metrics("budget"))
    assert view.text(BUDGET_REFUSED_STAGES) is None
    assert view.number(BUDGET_SPENT_TOKENS) == 4_000
    assert "refused model calls" not in generate_report(loaded_db)


def test_no_ceiling_means_no_budget_metrics(
    loaded_db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = MistifyConfig(pipeline=PipelineConfig(max_total_tokens=None, coverage_nudges=0))
    config.llm.synthesis_model = None
    _patch_providers(monkeypatch, {config.llm.model: [text_turn("done")]})

    runner.run_investigation(loaded_db, config, adversarial=False)

    assert MetricView(loaded_db.metrics("budget")).number(BUDGET_MAX_TOTAL_TOKENS) is None
    assert "No token ceiling was set for this run." in generate_report(loaded_db)


def test_the_default_ceiling_is_above_every_recorded_run() -> None:
    """1.22M was the largest recorded run on 2026-09-24; the default must not cut it."""
    assert PipelineConfig().max_total_tokens == 1_500_000


def test_a_ceiling_too_small_to_run_anything_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_total_tokens"):
        PipelineConfig(max_total_tokens=500)


def test_a_skeleton_run_does_not_inherit_an_agent_runs_budget(loaded_db: ScratchpadDB) -> None:
    """Found in review: only the agent path cleared the budget metrics it writes."""
    from mistify.agent.skeleton import run_skeleton_investigation

    loaded_db.record_many([(BUDGET_MAX_TOTAL_TOKENS, 60_000), (BUDGET_REFUSED_STAGES, "synthesis")])
    assert MetricView(loaded_db.metrics("budget")).text(BUDGET_REFUSED_STAGES), "the control"

    run_skeleton_investigation(loaded_db)

    view = MetricView(loaded_db.metrics())
    assert view.number(BUDGET_MAX_TOTAL_TOKENS) is None
    assert view.text(BUDGET_REFUSED_STAGES) is None
    assert "refused model calls" not in generate_report(loaded_db)

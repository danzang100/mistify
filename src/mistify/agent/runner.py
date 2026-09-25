"""One investigation, end to end: search, then conclude, then critique.

Extracted from the CLI so the eval harness drives exactly what a user drives. A harness that
assembled its own loop would measure a pipeline nobody runs, and would keep passing after the
real one changed shape -- the same failure as a test that reimplements the code it checks.

Credentials are resolved here rather than at import, so every deterministic command keeps
working on a machine with no account anywhere. `MissingCredentialError` is raised as itself:
the CLI turns it into a usage error, and the harness records it as a failed run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mistify.agent.adversarial import REBUTTAL_TOOLS, run_adversarial_check
from mistify.agent.budget import BudgetedProvider, TokenBudget, TokenCeilingReached
from mistify.agent.loop import InvestigationLoop, InvestigationResult
from mistify.agent.tools import ToolBox
from mistify.llm.base import ProviderError
from mistify.llm.registry import build_provider
from mistify.metrics import (
    ADVERSARIAL_FAILED,
    ANOMALY_SIGNAL_TEMPLATE_IDS,
    BUDGET_MAX_TOTAL_TOKENS,
    BUDGET_REFUSED_STAGES,
    BUDGET_SPENT_TOKENS,
    INVESTIGATION_STAGES,
    SYNTHESIS_FAILED,
    MetricView,
)

if TYPE_CHECKING:
    from mistify.common.config import MistifyConfig
    from mistify.llm.base import LLMProvider
    from mistify.scratchpad.db import ScratchpadDB

__all__ = ["run_investigation"]


def run_investigation(
    db: ScratchpadDB,
    config: MistifyConfig,
    adversarial: bool = True,
    incident_context: str = "",
) -> InvestigationResult:
    """Drive the model loop, optionally let a stronger model conclude, then let a critique answer.

    `incident_context` replaces the opening instruction when a caller has something the model
    needs to know before it starts -- resuming an investigation whose notes are already in the
    scratchpad, for instance, where silence would let it mistake another run's findings for its
    own.

    The order is load-bearing. Synthesis runs *before* the adversarial pass because the
    conclusion is the main thing the critique exists to attack; critiquing the loop's notes and
    then replacing them with a synthesised conclusion would leave the published finding
    unchecked.
    """
    # Several of these are written only when they apply -- a ceiling, a refusal, a budget
    # limit -- so a previous attempt's values are cleared first: a report must not warn about
    # a refusal that belonged to the run before `--restart`.
    db.forget_stages(*INVESTIGATION_STAGES)
    ceiling = config.pipeline.max_total_tokens
    budget = TokenBudget(ceiling) if ceiling is not None else None
    refused: list[str] = []

    def charged(built: LLMProvider) -> LLMProvider:
        return BudgetedProvider(built, budget) if budget is not None else built

    provider = charged(build_provider(config.llm.provider, config.llm.model, config.llm))

    loop = InvestigationLoop(
        db=db,
        provider=provider,
        toolbox=ToolBox(db, noise=config.anomaly.noise_thresholds()),
        max_tool_calls=config.pipeline.max_agent_tool_calls,
        max_tokens=config.llm.max_tokens,
        task_budget_tokens=config.llm.task_budget_tokens,
        tool_result_history_steps=config.pipeline.tool_result_history_steps,
        coverage_nudges=config.pipeline.coverage_nudges,
    )
    result = loop.run(incident_context)
    if result.stop_reason == "token_ceiling":
        refused.append("investigate")

    if config.llm.synthesis_model is not None:
        from mistify.agent.synthesis import run_synthesis

        synthesiser = charged(
            build_provider(
                config.llm.synthesis_provider_name(), config.llm.synthesis_model, config.llm
            )
        )
        try:
            run_synthesis(db, synthesiser, max_tokens=config.llm.max_tokens)
        except TokenCeilingReached:
            # The loop's own notes stand as the conclusion, exactly as with no synthesis
            # model configured -- and the report says the synthesis was refused.
            refused.append("synthesis")
        except ProviderError as exc:
            # The same, for a model that would not answer. The investigation is finished and
            # its notes are real; losing them because the model that rewrites them was
            # overloaded would throw away the part that worked.
            db.record(SYNTHESIS_FAILED, _clip_error(exc))
        result.notes = db.notes()

    if adversarial:
        critic = charged(
            build_provider(
                config.llm.adversarial_provider_name(), config.llm.adversarial_model, config.llm
            )
        )
        raw_ids = MetricView(db.metrics("anomaly")).text(ANOMALY_SIGNAL_TEMPLATE_IDS) or ""
        signal_ids = [int(part) for part in raw_ids.split(",") if part.strip()]
        # A fresh box for the rebuttal, readers only, continuing the loop's step count so
        # its queries land in the trail after the investigation's rather than over them.
        rebuttal_tools = ToolBox(
            db,
            noise=config.anomaly.noise_thresholds(),
            start_step=loop.toolbox.step,
            tools=REBUTTAL_TOOLS,
        )
        try:
            run_adversarial_check(
                db,
                critic,
                signal_ids,
                rebuttal_provider=provider,
                max_tokens=config.llm.max_tokens,
                toolbox=rebuttal_tools,
                rebuttal_tool_calls=config.pipeline.rebuttal_tool_calls,
            )
        except TokenCeilingReached:
            refused.append("adversarial")
        except ProviderError as exc:
            # A conclusion nothing checked, said in words on the report -- not a run lost.
            db.record(ADVERSARIAL_FAILED, _clip_error(exc))

    if budget is not None:
        db.record_many(
            [
                (BUDGET_MAX_TOTAL_TOKENS, budget.ceiling),
                (BUDGET_SPENT_TOKENS, budget.spent),
                *([(BUDGET_REFUSED_STAGES, ",".join(refused))] if refused else []),
            ]
        )
    return result


def _clip_error(exc: Exception) -> str:
    """The error, bounded: a provider error can carry a whole response body."""
    text = str(exc)
    return text if len(text) <= 400 else text[:400] + " ..."

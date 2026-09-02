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

from mistify.agent.adversarial import run_adversarial_check
from mistify.agent.loop import InvestigationLoop, InvestigationResult
from mistify.agent.tools import ToolBox
from mistify.llm.registry import build_provider
from mistify.metrics import ANOMALY_SIGNAL_TEMPLATE_IDS, MetricView

if TYPE_CHECKING:
    from mistify.common.config import MistifyConfig
    from mistify.scratchpad.db import ScratchpadDB

__all__ = ["run_investigation"]


def run_investigation(
    db: ScratchpadDB, config: MistifyConfig, adversarial: bool = True
) -> InvestigationResult:
    """Drive the model loop, optionally let a stronger model conclude, then let a critique answer.

    The order is load-bearing. Synthesis runs *before* the adversarial pass because the
    conclusion is the main thing the critique exists to attack; critiquing the loop's notes and
    then replacing them with a synthesised conclusion would leave the published finding
    unchecked.
    """
    provider = build_provider(config.llm.provider, config.llm.model, config.llm)

    loop = InvestigationLoop(
        db=db,
        provider=provider,
        toolbox=ToolBox(db, noise=config.anomaly.noise_thresholds()),
        max_tool_calls=config.pipeline.max_agent_tool_calls,
        max_tokens=config.llm.max_tokens,
        task_budget_tokens=config.llm.task_budget_tokens,
        tool_result_history_steps=config.pipeline.tool_result_history_steps,
    )
    result = loop.run()

    if config.llm.synthesis_model is not None:
        from mistify.agent.synthesis import run_synthesis

        synthesiser = build_provider(
            config.llm.synthesis_provider_name(), config.llm.synthesis_model, config.llm
        )
        run_synthesis(db, synthesiser, max_tokens=config.llm.max_tokens)
        result.notes = db.notes()

    if adversarial:
        critic = build_provider(
            config.llm.adversarial_provider_name(), config.llm.adversarial_model, config.llm
        )
        raw_ids = MetricView(db.metrics("anomaly")).text(ANOMALY_SIGNAL_TEMPLATE_IDS) or ""
        signal_ids = [int(part) for part in raw_ids.split(",") if part.strip()]
        run_adversarial_check(
            db, critic, signal_ids, rebuttal_provider=provider, max_tokens=config.llm.max_tokens
        )

    return result

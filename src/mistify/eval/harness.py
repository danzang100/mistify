"""Running eval cases and collecting what happened.

One run is one full pipeline: write the fixture, ingest it, investigate it, score the
scratchpad. It goes through `run_investigation`, the same entry point the CLI uses, so the
harness cannot drift into measuring a pipeline nobody runs.

Runs are independent by construction -- each gets its own incident id and its own scratchpad --
because the interesting number here is the spread, not the best attempt. A model that solves a
case four times in five is a different product from one that solves it five times in five, and
a harness that reported only the best run would call them the same.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mistify.common.config import MistifyConfig
from mistify.eval.cases import EvalCase
from mistify.eval.scoring import Check, score_run
from mistify.metrics import token_usage, total_tokens
from mistify.pipeline import ingest
from mistify.scratchpad.db import ScratchpadDB

__all__ = ["CaseReport", "RunReport", "run_case", "write_results"]


@dataclass(slots=True)
class RunReport:
    """One investigation of one case."""

    case: str
    index: int
    checks: list[Check] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    #: Set when the run never produced a scratchpad to score -- a missing credential, a
    #: provider that gave up. Distinct from a run that finished and failed its checks, which
    #: is a result rather than an absence.
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.error is None and all(check.passed for check in self.checks)


@dataclass(slots=True)
class CaseReport:
    case: str
    summary: str
    fixture_version: int
    runs: list[RunReport] = field(default_factory=list)

    @property
    def pass_rate(self) -> str:
        return f"{sum(1 for run in self.runs if run.passed)}/{len(self.runs)}"

    def rate_for(self, check_name: str) -> str:
        """How often one named check passed. The per-check view is what actually guides work:
        an aggregate pass rate cannot tell you which question is failing."""
        seen = [c for run in self.runs for c in run.checks if c.name == check_name]
        return f"{sum(1 for c in seen if c.passed)}/{len(seen)}"

    def check_names(self) -> list[str]:
        names: list[str] = []
        for run in self.runs:
            for check in run.checks:
                if check.name not in names:
                    names.append(check.name)
        return names


def _collect_metrics(db: ScratchpadDB) -> dict[str, Any]:
    """The numbers worth comparing between runs, alongside the pass/fail."""
    rows = db.metrics()
    stages = token_usage(rows)
    totals = total_tokens(stages)

    def number(stage: str, name: str) -> Any:
        match = next((r for r in rows if r["stage"] == stage and r["metric"] == name), None)
        return None if match is None else match["value"]

    return {
        "steps": number("investigate", "steps"),
        "tool_calls": number("investigate", "tool_calls"),
        "notes": number("investigate", "notes_written"),
        "coverage_nudges": number("investigate", "coverage_nudges"),
        "budget_limited": number("investigate", "budget_limited"),
        "outcome": number("investigate", "outcome"),
        "adversarial_outcome": number("adversarial", "outcome"),
        "total_tokens": totals.total_tokens,
        "models": {stage.stage: stage.model for stage in stages},
        "templates": db.template_count(),
        "coverage": number("templating", "template_coverage"),
    }


def run_case(
    case: EvalCase,
    config: MistifyConfig,
    workspace: Path,
    runs: int = 3,
    adversarial: bool = True,
    judge: bool = False,
) -> CaseReport:
    """Run one case `runs` times and score each one.

    `judge` adds the semantic check from decision G8, which costs a model call per note and is
    off by default for that reason.
    """
    from mistify.agent.runner import run_investigation
    from mistify.llm.registry import build_provider

    report = CaseReport(case=case.name, summary=case.summary, fixture_version=case.fixture_version)
    workspace.mkdir(parents=True, exist_ok=True)
    source = case.source(workspace)

    for index in range(1, runs + 1):
        incident_id = f"eval-{case.name}-{index}"
        run = RunReport(case=case.name, index=index)
        try:
            result = ingest(source, config, incident_id=incident_id)
            with ScratchpadDB(result.scratchpad_path) as db:
                run_investigation(db, config, adversarial=adversarial)
                run.checks = score_run(db, case)
                if judge:
                    from mistify.eval.judge import judge_notes, judgement_checks

                    judge_provider = build_provider(
                        config.llm.provider, config.llm.judge_model, config.llm
                    )
                    run.checks += judgement_checks(
                        judge_notes(db, judge_provider, max_tokens=config.llm.max_tokens)
                    )
                run.metrics = _collect_metrics(db)
        except Exception as exc:
            # One run failing must not lose the runs already done. Quota exhaustion mid-sweep
            # is routine on a free tier, and a harness that discards four good runs because
            # the fifth was throttled is a harness nobody will run.
            run.error = f"{type(exc).__name__}: {exc}"
        report.runs.append(run)

    return report


def write_results(reports: list[CaseReport], directory: Path) -> Path:
    """Persist the sweep as JSON, so two sweeps can be diffed rather than remembered."""
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"eval-{stamp}.json"
    path.write_text(
        json.dumps(
            {
                "recorded_at": stamp,
                "cases": [
                    {
                        "case": report.case,
                        "summary": report.summary,
                        "fixture_version": report.fixture_version,
                        "pass_rate": report.pass_rate,
                        "runs": [
                            {
                                "index": run.index,
                                "passed": run.passed,
                                "error": run.error,
                                "checks": [
                                    {"name": c.name, "passed": c.passed, "detail": c.detail}
                                    for c in run.checks
                                ],
                                "metrics": run.metrics,
                            }
                            for run in report.runs
                        ],
                    }
                    for report in reports
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return path

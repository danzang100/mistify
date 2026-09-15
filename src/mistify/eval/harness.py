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
import shutil
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
    #: Where this run's rendered report was written, when one was kept. The checks say whether
    #: a run passed; only the report says what it actually concluded, and a sweep that keeps
    #: just the score cannot be re-read afterwards to find out why.
    report_path: str | None = None

    #: Set when the run never produced a scratchpad to score -- a missing credential, a
    #: provider that gave up. Distinct from a run that finished and failed its checks, which
    #: is a result rather than an absence.
    error: str | None = None

    @property
    def passed(self) -> bool:
        """Every check passed *and* the run completed.

        A run that errored partway is never a full pass even when its checks are green: the
        stages after the failure never ran, so the report it would have produced does not
        exist. The checks are still recorded and still counted per check, because "the
        investigation was correct and the critique timed out" is a different fact from "the
        investigation was wrong", and one number cannot carry both.
        """
        return self.error is None and all(check.passed for check in self.checks if check.scorable)

    @property
    def scored(self) -> bool:
        """Whether the scratchpad got far enough to be graded at all."""
        return any(check.scorable for check in self.checks)


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
        scorable = [c for c in seen if c.scorable]
        if not scorable:
            # Every run left this question unaskable. Reporting 0/3 would blame the model for
            # a check that never ran; reporting 3/3 would credit it for the same thing.
            return f"-/{len(seen)}"
        return f"{sum(1 for c in scorable if c.passed)}/{len(scorable)}"

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
    runs: int = 1,
    adversarial: bool = True,
    judge: bool = False,
    baseline: str | None = None,
    report_dir: Path | None = None,
) -> CaseReport:
    """Run one case `runs` times and score each one.

    `judge` adds the semantic half of citation checking, which costs a model call per note and is
    off by default for that reason.

    `baseline` replaces the investigation with a grep pipeline, scored by the same checks. It
    calls no model, so `runs` is forced to one: the baseline is deterministic and repeating it
    would only repeat the same answer at the cost of the ingest.
    """
    from mistify.agent.runner import run_investigation
    from mistify.llm.registry import build_provider

    report = CaseReport(case=case.name, summary=case.summary, fixture_version=case.fixture_version)
    workspace.mkdir(parents=True, exist_ok=True)
    source = case.source(workspace)

    # Ingested once, then copied per run. Parse, redact, template and score are deterministic
    # given the same file and config -- only the investigation varies -- so re-ingesting per
    # run repeated a second of identical work and measured nothing. The test suite already
    # settled this the same way; the harness had not.
    try:
        master = ingest(source, config, incident_id=f"eval-{case.name}-master")
    except Exception as exc:
        # A sweep covers several cases. One whose fixture will not ingest should be reported
        # as that, not take the other cases down with it.
        failure = f"{type(exc).__name__}: {exc}"
        report.runs = [
            RunReport(case=case.name, index=index, error=failure)
            for index in range(1, (1 if baseline else runs) + 1)
        ]
        return report

    for index in range(1, (1 if baseline else runs) + 1):
        incident_id = f"eval-{case.name}-{index}"
        run = RunReport(case=case.name, index=index)
        try:
            # Copied rather than shared: a run writes notes, metrics and query-log rows into
            # its scratchpad, and a shared handle would leak one run's findings into the next.
            scratchpad = config.scratchpad_path(incident_id)
            scratchpad.parent.mkdir(parents=True, exist_ok=True)
            # Removed before copying, not merely overwritten. Scratchpads persist in .cache
            # between invocations, and a sweep that reused an id once scored a run against
            # notes an earlier, interrupted run had left behind -- three findings on a
            # baseline that writes one. Starting from nothing makes that impossible rather
            # than unlikely.
            scratchpad.unlink(missing_ok=True)
            shutil.copyfile(master.scratchpad_path, scratchpad)
            with ScratchpadDB(scratchpad) as db:
                # The copy carries the master's identity; without this every report rendered
                # from a run names the wrong incident.
                db.rename_incident(incident_id)
                if baseline:
                    from mistify.eval.baselines import run_baseline

                    outcome = run_baseline(db, baseline)  # type: ignore[arg-type]
                    run.metrics["baseline"] = outcome.name
                    run.metrics["matched_lines"] = outcome.matched_lines
                    run.metrics["groups"] = outcome.groups
                    # The baseline records no investigate metrics, so the note count comes
                    # from the notes themselves rather than from a stage that never ran.
                    run.metrics["notes"] = len(db.notes())
                else:
                    try:
                        run_investigation(db, config, adversarial=adversarial)
                    except Exception as exc:
                        # Scored anyway. None of the deterministic checks needs the critique:
                        # they read notes and citations out of the scratchpad, which the loop
                        # has already written by the time a later stage fails. One OTLP run
                        # lost a complete 4/4 investigation because the adversarial call timed
                        # out after it, and the whole run was discarded as an error.
                        run.error = f"{type(exc).__name__}: {exc}"

                run.checks = score_run(db, case)
                if judge and not baseline and run.error is None:
                    from mistify.eval.judge import judge_notes, judgement_checks

                    judge_provider = build_provider(
                        config.llm.provider, config.llm.judge_model, config.llm
                    )
                    run.checks += judgement_checks(
                        judge_notes(db, judge_provider, max_tokens=config.llm.max_tokens)
                    )
                # Baseline-specific keys win: `_collect_metrics` reports None for every stage
                # the baseline did not run, and a None would overwrite a real count.
                run.metrics = {
                    **_collect_metrics(db),
                    **{k: v for k, v in run.metrics.items() if v is not None},
                }
                if report_dir is not None:
                    # Rendered from the scratchpad, so it costs nothing and is written even
                    # for a run that errored -- those are the ones worth reading.
                    from mistify.report.generator import write_report

                    run.report_path = str(write_report(db, report_dir, incident_id))
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
                                    {
                                        "name": c.name,
                                        "passed": c.passed,
                                        "scorable": c.scorable,
                                        "detail": c.detail,
                                    }
                                    for c in run.checks
                                ],
                                "metrics": run.metrics,
                                "report": run.report_path,
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

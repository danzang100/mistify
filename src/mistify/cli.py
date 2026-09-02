"""Command line interface."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click
from dotenv import load_dotenv

from mistify import __version__
from mistify.agent.skeleton import run_skeleton_investigation
from mistify.common.config import MistifyConfig, load_config
from mistify.pipeline import UnknownFormatError, derive_incident_id, ingest
from mistify.redaction.vault import RedactionVault
from mistify.report.generator import ProviderMissing, write_report
from mistify.scratchpad.db import ScratchpadDB

if TYPE_CHECKING:
    from mistify.agent.loop import InvestigationResult
    from mistify.eval.harness import CaseReport

__all__ = ["cli"]

_config_option = click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Path to config.yaml. Defaults to ./config.yaml, then built-in defaults.",
)


@click.group()
@click.version_option(__version__, prog_name="mistify")
def cli() -> None:
    """Mistify — incident log analysis agent."""
    # A key in a .env file is a key the user has already provided; making them export it as
    # well is a setup step that earns nothing. Never overrides a real environment variable.
    load_dotenv(override=False)


@cli.command(name="ingest")
@click.option("--source", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--incident-id", default=None, help="Defaults to a date-and-slug from --source.")
@click.option("--format", "format_name", default="auto", help="Adapter to force, or 'auto'.")
@_config_option
def ingest_command(
    source: Path, incident_id: str | None, format_name: str, config_path: Path | None
) -> None:
    """Parse, redact, template and load a log source into a scratchpad."""
    config = load_config(config_path)
    try:
        result = ingest(source, config, incident_id=incident_id, format_name=format_name)
    except UnknownFormatError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"incident      {result.incident_id}")
    click.echo(f"format        {result.format_name}")
    click.echo(f"lines read    {result.lines_read}")
    click.echo(f"events loaded {result.events_loaded}")
    click.echo(f"templates     {result.unique_templates}")
    click.echo(f"compression   {result.compression_ratio:.4f}")
    click.echo(f"redacted      {sum(result.redaction_counts.values())}")
    if result.parse_errors:
        click.echo(f"parse errors  {result.parse_errors}", err=True)
    click.echo(f"scratchpad    {result.scratchpad_path}")


_investigator_option = click.option(
    "--investigator",
    type=click.Choice(["loop", "skeleton"]),
    default="loop",
    help="loop drives a model through the tools; skeleton is the deterministic heuristic "
    "and needs no credential.",
)


@cli.command(name="investigate")
@click.option("--incident-id", required=True)
@_investigator_option
@click.option("--no-adversarial", is_flag=True, help="Skip the adversarial check.")
@_config_option
def investigate_command(
    incident_id: str, investigator: str, no_adversarial: bool, config_path: Path | None
) -> None:
    """Investigate an ingested incident."""
    config = load_config(config_path)
    path = config.scratchpad_path(incident_id)
    if not path.exists():
        raise click.ClickException(f"no scratchpad for incident {incident_id!r} at {path}")

    with ScratchpadDB(path) as db:
        if investigator == "skeleton":
            skeleton = run_skeleton_investigation(db)
            click.echo(f"steps  {skeleton.steps}")
            click.echo(f"notes  {len(skeleton.notes)}")
            for note in skeleton.notes:
                click.echo(f"  [{note.confidence}] {note.note}")
            return

        result = _run_agent(db, config, adversarial=not no_adversarial)
        click.echo(f"steps       {result.steps}")
        click.echo(f"tool calls  {result.tool_calls}")
        click.echo(f"notes       {len(result.notes)}")
        if result.budget_limited:
            click.echo("budget-limited: reached the tool-call cap before concluding", err=True)
        for note in result.notes:
            click.echo(f"  [{note.confidence}] {note.note[:160]}")


@cli.command(name="report")
@click.option("--incident-id", required=True)
@click.option(
    "--format",
    "report_format",
    default=None,
    type=click.Choice(["markdown", "html", "pdf"]),
    help="Output format. Defaults to report.format in config.",
)
@_config_option
def report_command(incident_id: str, report_format: str | None, config_path: Path | None) -> None:
    """Render the incident report."""
    config = load_config(config_path)
    chosen = report_format or config.report.format

    path = config.scratchpad_path(incident_id)
    if not path.exists():
        raise click.ClickException(f"no scratchpad for incident {incident_id!r} at {path}")

    with ScratchpadDB(path) as db:
        try:
            output = write_report(db, config.report.output_dir, incident_id, chosen)
        except ProviderMissing as exc:
            raise click.ClickException(str(exc)) from exc
    click.echo(f"report {output}")


_VAULT_DISABLED = (
    "redaction.vault is disabled for this incident, so no mapping was kept. "
    "Placeholders are truncated hashes and the hash is one-way -- the original values "
    "cannot be recovered after the fact. Enable redaction.vault in config.yaml and "
    "re-ingest before you need to reveal anything."
)


@cli.command(name="reveal")
@click.option("--incident-id", required=True)
@click.option("--token", default=None, help='One placeholder, e.g. "[EMAIL:a7f2]".')
@click.option("--all", "reveal_all", is_flag=True, help="Dump every mapping, tab-separated.")
@_config_option
def reveal_command(
    incident_id: str, token: str | None, reveal_all: bool, config_path: Path | None
) -> None:
    """Reveal original values from the redaction vault.

    Only useful when `redaction.vault` was on during ingest: the mapping is captured as
    redaction happens and cannot be reconstructed afterwards.
    """
    if (token is None) == (not reveal_all):
        raise click.ClickException("pass exactly one of --token or --all.")

    config = load_config(config_path)
    path = config.vault_path(incident_id)
    if path is None:
        raise click.ClickException(_VAULT_DISABLED)
    if not path.exists():
        raise click.ClickException(
            f"no vault for incident {incident_id!r} at {path}. "
            "It is written during ingest, only when redaction.vault is enabled -- "
            "the mapping cannot be reconstructed afterwards, because the placeholder hash "
            "is one-way. Enable it and re-ingest."
        )

    with RedactionVault(path) as vault:
        if token is not None:
            value = vault.reveal(token)
            if value is None:
                raise click.ClickException(f"token {token!r} is not in the vault at {path}")
            _warn_unredacted()
            click.echo(value)
            return

        rows = vault.entries()
        if not rows:
            click.echo("vault is empty", err=True)
            return
        _warn_unredacted()
        for row in rows:
            click.echo(f"{row['entity']}\t{row['token']}\t{row['value']}")


def _warn_unredacted() -> None:
    """Say out loud what is about to be printed.

    On stderr so a redirected dump stays machine-readable, and so the warning is still seen
    when stdout is piped somewhere the operator is not watching.
    """
    click.echo("warning: output below contains unredacted sensitive values", err=True)


@cli.command(name="run")
@click.option("--source", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--incident-id", default=None)
@click.option("--format", "format_name", default="auto")
@_investigator_option
@click.option("--no-adversarial", is_flag=True, help="Skip the adversarial check.")
@_config_option
def run_command(
    source: Path,
    incident_id: str | None,
    format_name: str,
    investigator: str,
    no_adversarial: bool,
    config_path: Path | None,
) -> None:
    """Ingest, investigate and report in one pass."""
    config = load_config(config_path)
    incident_id = incident_id or derive_incident_id(source)
    try:
        result = ingest(source, config, incident_id=incident_id, format_name=format_name)
    except UnknownFormatError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(
        f"ingested {result.events_loaded} events into {result.unique_templates} templates "
        f"(compression {result.compression_ratio:.4f})"
    )

    with ScratchpadDB(result.scratchpad_path) as db:
        if investigator == "skeleton":
            steps = run_skeleton_investigation(db).steps
        else:
            steps = _run_agent(db, config, adversarial=not no_adversarial).steps
        output = write_report(
            db, config.report.output_dir, result.incident_id, config.report.format
        )

    click.echo(f"investigated in {steps} steps")
    click.echo(f"report {output}")


@cli.command(name="eval")
@click.option(
    "--case",
    "case_names",
    multiple=True,
    help="Case to run. Repeatable. Defaults to every case.",
)
@click.option(
    "--runs",
    default=1,
    show_default=True,
    help="Investigations per case. Raise it deliberately when measuring a rate, not by habit.",
)
@click.option(
    "--baseline",
    type=click.Choice(["naive", "templated"]),
    default=None,
    help="Score a grep baseline instead of the agent. No model is called.",
)
@click.option("--list", "list_only", is_flag=True, help="List the cases and exit.")
@click.option("--no-adversarial", is_flag=True, help="Skip the critique, to halve the cost.")
@click.option(
    "--judge",
    is_flag=True,
    help="Also ask llm.judge_model whether each claim follows from the rows it cites (G8).",
)
@click.option("--out", default=None, type=click.Path(path_type=Path), help="Where to write JSON.")
@_config_option
def eval_command(
    case_names: tuple[str, ...],
    runs: int,
    baseline: str | None,
    list_only: bool,
    no_adversarial: bool,
    judge: bool,
    out: Path | None,
    config_path: Path | None,
) -> None:
    """Run the evaluation cases and score them against their known answers.

    Every case is a log file whose answer is known by construction, so the score is arithmetic
    rather than judgement. Cases run independently -- `--case quiet-hour` is one case, which
    matters on a free tier where a full sweep is several minutes of quota.
    """
    import tempfile

    from mistify.eval.cases import CASES, get_case
    from mistify.eval.cases import case_names as known_cases
    from mistify.eval.harness import run_case, write_results

    if list_only:
        for case in CASES:
            click.echo(f"{case.name}\n  {case.summary}")
            for note in case.notes:
                click.echo(f"  - {note}")
        return

    try:
        cases = [get_case(name) for name in case_names] if case_names else list(CASES)
    except KeyError as exc:
        raise click.ClickException(str(exc).strip("\"'")) from exc
    if not cases:  # pragma: no cover - CASES is never empty
        raise click.ClickException(f"no cases to run. Known: {', '.join(known_cases())}")

    config = load_config(config_path)
    # One directory per sweep, so a result and the reports behind it stay together and an old
    # sweep can be deleted in one go rather than by picking timestamps out of a shared folder.
    results_dir = Path(out) if out else Path(config.report.output_dir) / "eval"
    if judge and config.llm.judge_model in {config.llm.model, config.llm.adversarial_model}:
        # Not fatal, because the judge is opt-in tooling rather than a shipped guarantee -- but
        # a judge sharing a model with the thing it judges is the correlated-blind-spot problem
        # §6.3 exists to prevent, and it should not pass silently.
        click.echo(
            f"warning: judge_model {config.llm.judge_model!r} is also the loop's or the "
            "critique's model, so its verdicts are not independent (architecture §6.3).",
            err=True,
        )
    reports = []
    with tempfile.TemporaryDirectory(prefix="mistify-eval-") as workspace:
        for case in cases:
            click.echo(f"\n{case.name}: {case.summary}")
            report = run_case(
                case,
                config,
                Path(workspace),
                runs=runs,
                adversarial=not no_adversarial,
                judge=judge,
                baseline=baseline,
                report_dir=results_dir / "reports",
            )
            reports.append(report)
            _echo_case(report)

    destination = write_results(reports, results_dir)
    click.echo(f"\nresults {destination}")

    if any(not run.passed for report in reports for run in report.runs):
        # A failing eval exits non-zero so it can gate anything, but the report is printed
        # first: the numbers are the point, and an exit code nobody can read is not a result.
        raise SystemExit(1)


def _echo_case(report: CaseReport) -> None:
    """Per-check rates, not just an aggregate: an aggregate cannot say which question failed."""
    for name in report.check_names():
        click.echo(f"  {report.rate_for(name):>7}  {name}")
    click.echo(f"  {report.pass_rate:>7}  runs fully passing")
    for run in report.runs:
        if run.error:
            passed = sum(1 for c in run.checks if c.passed)
            scored = (
                f" (scored anyway: {passed}/{len(run.checks)} checks passed)" if run.checks else ""
            )
            click.echo(f"  run {run.index} did not complete{scored}: {run.error}")
        elif run.metrics.get("baseline"):
            m = run.metrics
            click.echo(
                f"  run {run.index}: grep matched {m.get('matched_lines')} line(s) in "
                f"{m.get('groups')} group(s), {m.get('notes')} note(s), no model calls"
            )
        else:
            m = run.metrics
            click.echo(
                f"  run {run.index}: {m.get('steps')} steps, {m.get('notes')} note(s), "
                f"{m.get('total_tokens'):,} tokens, nudges {m.get('coverage_nudges')}"
            )


@cli.command(name="eval-templating")
@click.option(
    "--system",
    "systems",
    multiple=True,
    help="Loghub-2k system to score. Repeatable. Defaults to a spread across log families.",
)
@click.option("--dataset", default=None, type=click.Path(path_type=Path), help="Local CSV.")
@click.option(
    "--sim-th",
    "thresholds",
    multiple=True,
    type=float,
    help="Similarity threshold to score at. Repeatable, to sweep.",
)
@click.option("--cache", default=".cache/loghub", type=click.Path(path_type=Path))
def eval_templating_command(
    systems: tuple[str, ...],
    dataset: Path | None,
    thresholds: tuple[float, ...],
    cache: Path,
) -> None:
    """Score template clustering against Loghub-2k's annotated ground truth.

    No model is called. This measures the foundation everything else sits on: a template that
    merged two conditions has lost the distinction before an investigation starts, and no
    amount of reasoning downstream recovers it.

    Data is downloaded on demand and never committed -- Loghub is free for research use with
    citation terms, and a vendored corpus is a licence question nobody wants later.
    """
    from mistify.eval.templating_eval import fetch_loghub, score_dataset

    # A spread rather than everything: these four are different enough in shape (SSH auth
    # lines, a distributed scheduler, a supercomputer's console, a web server) that a parser
    # doing well on all four is doing something general.
    chosen = systems or ("OpenSSH", "Hadoop", "BGL", "Apache")
    levels = thresholds or (0.4,)

    click.echo(f"{'system':<12} {'sim_th':>7} {'lines':>6} {'GA':>7} {'ours':>6} {'truth':>6}")
    rows = []
    for level in levels:
        for name in chosen:
            try:
                path = Path(dataset) if dataset else fetch_loghub(name, cache)
                score = score_dataset(path, sim_th=level)
            except Exception as exc:
                click.echo(f"{name:<12} {level:>7} could not be scored: {exc}")
                continue
            rows.append(score)
            click.echo(
                f"{score.system:<12} {score.sim_th:>7} {score.lines:>6} "
                f"{score.grouping_accuracy:>7.3f} {score.parsed_templates:>6} "
                f"{score.annotated_templates:>6}"
            )
            if dataset:
                break

    if rows:
        mean = sum(r.grouping_accuracy for r in rows) / len(rows)
        mean_line = f"mean grouping accuracy over {len(rows)} dataset-threshold pair(s): {mean:.3f}"
        click.echo("\n" + mean_line)
        click.echo(
            "Loghub-2k, github.com/logpai/loghub. Cite the LogPub paper if you publish these."
        )


def _run_agent(db: ScratchpadDB, config: MistifyConfig, adversarial: bool) -> InvestigationResult:
    """The investigation, with credential failures turned into usage errors.

    The run itself lives in `mistify.agent.runner` so the eval harness drives exactly what this
    command drives; all this adds is the CLI's error vocabulary.
    """
    from mistify.agent.runner import run_investigation
    from mistify.llm.registry import MissingCredentialError

    try:
        return run_investigation(db, config, adversarial=adversarial)
    except MissingCredentialError as exc:
        raise click.ClickException(str(exc)) from exc


def main() -> int:
    cli()
    return 0


if __name__ == "__main__":
    sys.exit(main())

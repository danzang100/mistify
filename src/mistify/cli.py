"""Command line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click
from dotenv import load_dotenv

from mistify import __version__
from mistify.adapters.source import BinarySourceError
from mistify.agent.skeleton import run_skeleton_investigation
from mistify.common.config import MistifyConfig, load_config
from mistify.pipeline import UnknownFormatError, derive_incident_id, ingest
from mistify.redaction.vault import RedactionVault
from mistify.report.generator import ProviderMissing, write_report
from mistify.scratchpad.db import ScratchpadDB

if TYPE_CHECKING:
    from mistify.agent.loop import InvestigationResult
    from mistify.eval.cases import EvalCase
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
    """Mistify - incident log analysis agent."""
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
    except (UnknownFormatError, BinarySourceError) as exc:
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
@click.option(
    "--resume",
    is_flag=True,
    help="Investigate again, keeping the notes already in the scratchpad and telling the "
    "investigator they are there.",
)
@click.option(
    "--restart",
    is_flag=True,
    help="Delete the previous investigation -- its notes, queries and critique -- and start "
    "over. The ingest is untouched.",
)
@_config_option
def investigate_command(
    incident_id: str,
    investigator: str,
    no_adversarial: bool,
    resume: bool,
    restart: bool,
    config_path: Path | None,
) -> None:
    """Investigate an ingested incident."""
    config = load_config(config_path)
    path = config.scratchpad_path(incident_id)
    if not path.exists():
        raise click.ClickException(f"no scratchpad for incident {incident_id!r} at {path}")
    if resume and restart:
        raise click.ClickException("--resume and --restart ask for opposite things")

    with ScratchpadDB(path) as db:
        # A second investigation of a scratchpad that already holds notes is two runs sharing
        # one record: the new run does not know the old notes are not its own -- it sees them
        # only if it happens to call `read_notes` -- and anything scoring the scratchpad
        # afterwards counts both. The eval harness has always avoided this by copying a fresh
        # scratchpad per run; this is the same guarantee for the path a person uses. Refusing
        # is deliberate: neither answer is safe to assume, and silently picking one is how the
        # harness once scored a run against findings an interrupted run had left behind.
        existing = db.notes()
        if existing and not (resume or restart):
            raise click.ClickException(
                f"incident {incident_id!r} already holds {len(existing)} note(s) from an "
                "earlier investigation. Pass --resume to continue from them, or --restart to "
                "delete them and investigate again."
            )
        # Not `if existing`: a previous attempt that wrote no notes still left its query log,
        # and the next run's audit trail then carries queries it never made. Found in use --
        # a run that died without concluding left twenty rows behind for the run after it.
        if restart:
            cleared = db.clear_investigation()
            click.echo(
                "restarted: cleared "
                + ", ".join(f"{n} {t.replace('_', ' ')}" for t, n in cleared.items() if n)
            )
        if investigator == "skeleton":
            skeleton = run_skeleton_investigation(db)
            click.echo(f"steps  {skeleton.steps}")
            click.echo(f"notes  {len(skeleton.notes)}")
            for note in skeleton.notes:
                click.echo(f"  [{note.confidence}] {note.note}")
            return

        result = _run_agent(
            db,
            config,
            adversarial=not no_adversarial,
            incident_context=RESUME_CONTEXT if resume and existing else "",
        )
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
    except (UnknownFormatError, BinarySourceError) as exc:
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
@click.option(
    "--logdx",
    "logdx_split",
    default=None,
    help=(
        "Add LogDx-CI cases from a split (dev, holdout, stress, v2/dev, v2/holdout, "
        "v2/stress). Real GitHub Actions failures with author-verified diagnoses, downloaded "
        "on demand into .cache and never committed."
    ),
)
@click.option(
    "--digest",
    "digest_only",
    is_flag=True,
    help=(
        "Ingest each case and report where its known evidence lands in the ranked digest the "
        "investigation starts from. No model is called. Exits non-zero if any marker sits "
        "outside the digest, because a run started from there is testing the ranking rather "
        "than the loop."
    ),
)
@click.option(
    "--digest-limit",
    default=40,
    show_default=True,
    help="Templates the digest shows. Matches agent.loop.build_system_prompt's default.",
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
    logdx_split: str | None,
    digest_only: bool,
    digest_limit: int,
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

    from mistify.eval.cases import CASES
    from mistify.eval.harness import run_case, write_results

    # LogDx-CI cases are opt-in because building them downloads a corpus. `mistify eval` with
    # no flags has always worked offline and should keep working offline; a suite that reaches
    # for the network by default fails for reasons that have nothing to do with the pipeline.
    pool = list(CASES)
    if logdx_split is not None:
        from mistify.eval.logdx import LOGDX_SPLITS, logdx_eval_cases

        if logdx_split not in LOGDX_SPLITS:
            raise click.ClickException(
                f"unknown LogDx-CI split {logdx_split!r}. Known: {', '.join(LOGDX_SPLITS)}"
            )
        click.echo(f"fetching LogDx-CI split {logdx_split} into .cache/logdx ...", err=True)
        try:
            pool.extend(logdx_eval_cases(logdx_split))
        except OSError as exc:
            raise click.ClickException(f"could not fetch LogDx-CI: {exc}") from exc

    if list_only:
        for case in pool:
            click.echo(f"{case.name}\n  {case.summary}")
            for note in case.notes:
                click.echo(f"  - {note}")
        if logdx_split is None:
            click.echo("\nAlso available: --logdx dev (35 real CI failures; see --help).")
        return

    known = {case.name: case for case in pool}
    try:
        cases = [known[name] for name in case_names] if case_names else list(pool)
    except KeyError as exc:
        name = str(exc).strip("\"'")
        hint = "" if logdx_split else " (LogDx-CI cases need --logdx SPLIT)"
        raise click.ClickException(
            f"unknown eval case {name}.{hint} Known: {', '.join(sorted(known))}"
        ) from exc
    if not cases:  # pragma: no cover - CASES is never empty
        raise click.ClickException(f"no cases to run. Known: {', '.join(sorted(known))}")

    config = load_config(config_path)
    # One directory per sweep, so a result and the reports behind it stay together and an old
    # sweep can be deleted in one go rather than by picking timestamps out of a shared folder.
    results_dir = Path(out) if out else Path(config.report.output_dir) / "eval"
    if digest_only:
        _run_digest(cases, config, results_dir, digest_limit)
        return

    if judge and config.llm.judge_model in {config.llm.model, config.llm.adversarial_model}:
        # Not fatal, because the judge is opt-in tooling rather than a shipped guarantee -- but
        # a judge sharing a model with the thing it judges is the correlated-blind-spot problem
        # the separate critique model exists to prevent, and it should not pass silently.
        click.echo(
            f"warning: judge_model {config.llm.judge_model!r} is also the loop's or the "
            "critique's model, so its verdicts are not independent.",
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
    if any(case.external for case in cases):
        # Attribution, as CC-BY-4.0 requires, and the same courtesy the Loghub eval extends.
        from mistify.eval.logdx import LOGDX_CITATION

        click.echo(LOGDX_CITATION, err=True)

    if any(not run.passed for report in reports for run in report.runs):
        # A failing eval exits non-zero so it can gate anything, but the report is printed
        # first: the numbers are the point, and an exit code nobody can read is not a result.
        raise SystemExit(1)


def _run_digest(
    cases: list[EvalCase], config: MistifyConfig, results_dir: Path, limit: int
) -> None:
    """Measure the ranking instead of the investigation. Ingest only; no provider is built.

    The question this answers is the cheap one that belongs before a paid sweep: is the
    evidence a correct diagnosis rests on anywhere in the list the model reads first? A case
    whose markers are all below the digest can still be solved -- one was, citing 4 of 4 from a
    digest holding none of them -- but its score says something about search, not about
    reasoning.
    """
    import tempfile

    from mistify.eval.digest import run_digest_case, write_digest_results

    results = []
    with tempfile.TemporaryDirectory(prefix="mistify-digest-") as workspace:
        for case in cases:
            measured = run_digest_case(case, config, Path(workspace), limit)
            results.append(measured)
            if measured.error:
                click.echo(f"\n{case.name}: skipped -- {measured.error}")
                continue
            click.echo(
                f"\n{case.name}: {measured.recall} markers in the top {limit} "
                f"({measured.template_count} templates, {measured.event_count} events, "
                f"severity {measured.severity_source})"
            )
            for marker in measured.markers:
                # The rank of a marker that missed is the number that says how badly, and it is
                # what a second measurement is compared against.
                where = "not in any template" if marker.rank is None else f"#{marker.rank}"
                mark = "  " if marker.in_digest(limit) else "->"
                click.echo(
                    f"  {mark} {where:>6}  {marker.events} event(s) / "
                    f"{marker.templates} template(s)  {marker.marker[:60]}"
                )

    destination = write_digest_results(results, results_dir)
    scored = [r for r in results if not r.error]
    found = sum(r.found for r in scored)
    total = sum(len(r.markers) for r in scored)
    click.echo(f"\ntotal {found}/{total} markers inside the top {limit}")
    click.echo(f"results {destination}")
    if found < total:
        raise SystemExit(1)


def _echo_case(report: CaseReport) -> None:
    """Per-check rates, not just an aggregate: an aggregate cannot say which question failed."""
    for name in report.check_names():
        click.echo(f"  {report.rate_for(name):>7}  {name}")
    click.echo(f"  {report.pass_rate:>7}  runs fully passing")
    for run in report.runs:
        if run.error:
            # Only the checks that could actually be asked. A run that died before its first
            # tool call used to be reported as "5/13 checks passed", which is the vacuous floor
            # of four `avoids` and `citations-resolve` on an empty scratchpad.
            askable = [c for c in run.checks if c.scorable]
            passed = sum(1 for c in askable if c.passed)
            unaskable = len(run.checks) - len(askable)
            trailer = f", {unaskable} unscorable" if unaskable else ""
            scored = (
                f" (scored anyway: {passed}/{len(askable)} checks passed{trailer})"
                if askable
                else f" (nothing scorable: {unaskable} check(s) needed a conclusion)"
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


@cli.command(name="eval-ranking")
@click.option(
    "--scratchpads",
    default=".cache",
    type=click.Path(exists=True, path_type=Path),
    help="Directory searched recursively for recorded scratchpads.",
)
@click.option(
    "--marker",
    "markers",
    multiple=True,
    help=(
        "Ground-truth marker for scratchpads that are not LogDx cases. Repeatable. LogDx runs "
        "resolve their own markers from the case's ground_truth.json and ignore this."
    ),
)
@click.option("--out", default=None, type=click.Path(path_type=Path), help="Where to write JSON.")
def eval_ranking_command(scratchpads: Path, markers: tuple[str, ...], out: Path | None) -> None:
    """Re-rank every recorded investigation, and say which candidate key leads correctly.

    No model is called and nothing is ingested; this reads runs that already happened. It
    answers one question: after a change to `findings.rank_notes`, did any case swap?

    The aggregate is not the measurement. Three keys have already tied the shipped one at
    19/21 while fixing and breaking different cases, so read the per-run column -- and read it
    alongside the herring control in the test suite, which is what rejected all three.
    """
    from mistify.common.models import ROLE_ACCOUNTING
    from mistify.eval.logdx import load_logdx_case
    from mistify.eval.ranking import CANDIDATES, rank_report

    case_dirs = {
        d.name: d for d in Path(".cache/logdx").glob("**/") if (d / "ground_truth.json").exists()
    }

    def logdx_markers(stem: str) -> tuple[tuple[str, ...], str] | None:
        _, _, rest = stem.partition("-logdx-")
        if not rest:
            return None
        parts = rest.split("-")
        # The case id ends in a number and so does the run suffix, so the split cannot be made
        # by pattern: the longest prefix naming a real case directory is the case.
        for cut in range(len(parts), 0, -1):
            hit = case_dirs.get("-".join(parts[:cut]))
            if hit is not None:
                return load_logdx_case(hit).markers, f"logdx:{hit.name}"
        return None

    cases = []
    unmarked = []
    for path in sorted(scratchpads.glob("**/*.sqlite")):
        resolved = logdx_markers(path.stem)
        if resolved is not None:
            case_markers, origin = resolved
        elif markers:
            case_markers, origin = markers, "--marker"
        else:
            # Not a LogDx case and no --marker to resolve it by. Counted rather than dropped:
            # the runs carrying an `accounting` role are exactly the non-LogDx ones, so a
            # silent skip here reports a clean sweep for a key whose deciding term never ran.
            unmarked.append(path)
            continue
        if case_markers:
            cases.append((path, case_markers, origin))

    results = rank_report(cases)
    if not results:
        raise click.ClickException(
            f"no scratchpad under {scratchpads} had two or more notes and resolvable markers, "
            f"and {len(unmarked)} scratchpad(s) skipped for want of a marker. "
            "Pass --marker for runs that are not LogDx cases."
        )

    scorable = [r for r in results if r.scorable]
    click.echo(
        f"{len(results)} run(s) with an ordering to get wrong; {len(scorable)} scorable "
        f"(some note cites a marker template)\n"
    )
    width = max(len(name) for name in CANDIDATES)
    for name in CANDIDATES:
        hits = sum(1 for r in scorable if r.leads_correctly(name))
        click.echo(f"  {name:<{width}}  {hits:>2}/{len(scorable)}")

    header = f"\n{'run':<46} {'notes':>5} {'roles':<22} " + " ".join(
        f"{n[:13]:>13}" for n in CANDIDATES
    )
    click.echo(header)
    click.echo("-" * len(header))
    for result in results:
        roles = ",".join(f"{k}={v}" for k, v in sorted(result.roles.items()))
        cells = " ".join(
            f"{('-' if not result.scorable else ('Y' if result.leads_correctly(n) else 'n')):>13}"
            for n in CANDIDATES
        )
        name = f"{result.path.parent.name}/{result.path.stem}"
        click.echo(f"{name[:46]:<46} {result.note_count:>5} {roles[:22]:<22} {cells}")

    if not any(ROLE_ACCOUNTING in r.roles for r in scorable):
        click.echo(
            "\nNo scorable run carries an `accounting` note, so this table did not exercise "
            "the role term at all -- every key above was decided by score alone."
        )
    if unmarked:
        click.echo(
            f"\n{len(unmarked)} scratchpad(s) skipped for want of a marker; pass --marker to "
            "score them:"
        )
        for path in unmarked[:10]:
            click.echo(f"  {path}")
        if len(unmarked) > 10:
            click.echo(f"  ... and {len(unmarked) - 10} more")

    unscorable = [r for r in results if not r.scorable]
    if unscorable:
        click.echo(
            f"\n{len(unscorable)} unscorable -- no note cites a marker template, so no "
            "ordering can rescue them:"
        )
        for result in unscorable:
            click.echo(f"  {result.path}")

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                [
                    {
                        "path": str(r.path),
                        "origin": r.origin,
                        "notes": r.note_count,
                        "scorable": r.scorable,
                        "correct_note_ids": list(r.correct_note_ids),
                        "roles": r.roles,
                        "leaders": r.leaders,
                        "leads_correctly": {n: r.leads_correctly(n) for n in CANDIDATES}
                        if r.scorable
                        else {},
                    }
                    for r in results
                ],
                indent=2,
            ),
            encoding="utf-8",
        )
        click.echo(f"\nwrote {out}")


@cli.command(name="eval-seeded")
@click.option(
    "--scratchpads",
    default=".cache",
    type=click.Path(exists=True, path_type=Path),
    help="Directory searched recursively for ingested scratchpads to plant conclusions on.",
)
@click.option(
    "--case",
    "case_names",
    multiple=True,
    help="Seeded conclusion to plant. Repeatable. Defaults to every one.",
)
@click.option("--limit", default=0, help="Stop after this many scratchpads. 0 means all.")
@click.option("--out", default=None, type=click.Path(path_type=Path), help="Where to write JSON.")
def eval_seeded_command(
    scratchpads: Path, case_names: tuple[str, ...], limit: int, out: Path | None
) -> None:
    """Plant deliberately wrong conclusions and see which the free checks catch.

    No model is called. Every conclusion is derived from the log it is planted on -- its chronic
    templates, its signal set, its volume distribution -- so the same defects are planted on any
    corpus without a line of corpus-specific code, and a log that cannot support a defect is
    skipped rather than faked.

    Catch rate is reported next to false-flip rate because neither means anything alone: a check
    that objects to everything catches every defect.
    """
    from mistify.eval.seeded import (
        DEFECT_CHECKS,
        GENERATORS,
        CorpusResult,
        SeededScore,
        generate,
        score_conclusion,
    )

    sources = sorted(scratchpads.glob("**/*.sqlite"))
    if limit:
        sources = sources[:limit]
    if not sources:
        raise click.ClickException(f"no scratchpad found under {scratchpads}")

    results: list[CorpusResult] = []
    for source in sources:
        try:
            with ScratchpadDB(source) as probe:
                if not probe.event_count():
                    continue
                conclusions = generate(probe, case_names)
        except Exception as exc:  # a corrupt or partial scratchpad is data, not a crash
            click.echo(f"  {source}: skipped ({exc})")
            continue
        if not conclusions:
            continue
        scores = tuple(score_conclusion(source, c) for c in conclusions)
        results.append(CorpusResult(source=source, scores=scores))

    if not results:
        raise click.ClickException("no scratchpad could support any seeded conclusion")

    by_case: dict[str, list[SeededScore]] = {}
    for result in results:
        for score in result.scores:
            by_case.setdefault(score.conclusion.name, []).append(score)

    planted_total = sum(len(r.scores) for r in results)
    click.echo(f"{len(results)} log(s), {planted_total} seeded conclusion(s)\n")
    width = max(len(n) for n in GENERATORS)
    click.echo(
        f"{'case':<{width}} {'label':<8} {'planted':>7} {'objected':>9} {'by own':>9}  "
        f"{'its check':<20} every check that fired"
    )
    click.echo("-" * (width + 90))
    for name in GENERATORS:
        planted_here = by_case.get(name, [])
        if not planted_here:
            click.echo(f"{name:<{width}} {'-':<8} {0:>7} {'-':>9} {'-':>9}  (no log supported it)")
            continue
        label = planted_here[0].conclusion.label
        objected = sum(1 for s in planted_here if s.objected)
        by_own = sum(1 for s in planted_here if s.caught)
        wanted = DEFECT_CHECKS.get(planted_here[0].conclusion.defect, "-")
        fired = sorted({c for s in planted_here for c in s.checks_fired})
        own = f"{by_own:>9}" if label == "unsound" else f"{'-':>9}"
        click.echo(
            f"{name:<{width}} {label:<8} {len(planted_here):>7} {objected:>9} {own}  "
            f"{wanted:<20} {', '.join(fired) or '-'}"
        )

    unsound = [s for r in results for s in r.unsound]
    sound = [s for r in results for s in r.sound]
    caught = sum(1 for s in unsound if s.caught)
    objected_any = sum(1 for s in unsound if s.objected)
    flipped = sum(1 for s in sound if s.false_flip)
    click.echo(
        f"\ncatch rate (its own check)  {caught}/{len(unsound)}"
        f"\ncatch rate (any check)      {objected_any}/{len(unsound)}"
        f"\nfalse-flip rate             {flipped}/{len(sound)}"
    )
    if objected_any > caught:
        click.echo(
            f"  {objected_any - caught} unsound conclusion(s) drew an objection from a check "
            "not built for their defect. Read the own-check row, not that one."
        )

    flip_checks: dict[str, int] = {}
    for score in sound:
        for check in score.checks_fired:
            flip_checks[check] = flip_checks.get(check, 0) + 1
    if flip_checks:
        click.echo("\nfalse flips, by the check that fired:")
        for check, count in sorted(flip_checks.items(), key=lambda kv: -kv[1]):
            click.echo(f"  {check:<22} {count}")

    missed = sorted({s.conclusion.defect for s in unsound if not s.caught})
    if missed:
        click.echo(
            "\ndefects their own check missed at least once -- where a critique budget goes:"
            "\n  " + "\n  ".join(missed)
        )

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                [
                    {
                        "source": str(r.source),
                        "conclusions": [
                            {
                                "name": s.conclusion.name,
                                "label": s.conclusion.label,
                                "defect": s.conclusion.defect,
                                "rationale": s.conclusion.rationale,
                                "caught": s.caught,
                                "false_flip": s.false_flip,
                                "checks_fired": list(s.checks_fired),
                                "objections": [
                                    {"check": o.check, "detail": o.detail} for o in s.objections
                                ],
                            }
                            for s in r.scores
                        ],
                    }
                    for r in results
                ],
                indent=2,
            ),
            encoding="utf-8",
        )
        click.echo(f"\nwrote {out}")


#: What a resumed investigation is told before it starts. Without it the earlier notes are
#: invisible unless the model happens to call `read_notes`, and it can spend its budget
#: rediscovering what is already written down -- or contradict it without noticing.
RESUME_CONTEXT = (
    "This incident has already been investigated once and that attempt's notes are in the "
    "scratchpad. Call read_notes first. Build on what is there, correct it where you disagree, "
    "and do not repeat work it already did."
)


def _run_agent(
    db: ScratchpadDB,
    config: MistifyConfig,
    adversarial: bool,
    incident_context: str = "",
) -> InvestigationResult:
    """The investigation, with credential failures turned into usage errors.

    The run itself lives in `mistify.agent.runner` so the eval harness drives exactly what this
    command drives; all this adds is the CLI's error vocabulary.
    """
    from mistify.agent.runner import run_investigation
    from mistify.llm.registry import MissingCredentialError

    try:
        return run_investigation(
            db, config, adversarial=adversarial, incident_context=incident_context
        )
    except MissingCredentialError as exc:
        raise click.ClickException(str(exc)) from exc


def main() -> int:
    cli()
    return 0


if __name__ == "__main__":
    sys.exit(main())

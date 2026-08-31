"""Command line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from mistify import __version__
from mistify.agent.skeleton import run_skeleton_investigation
from mistify.common.config import load_config
from mistify.pipeline import UnknownFormatError, derive_incident_id, ingest
from mistify.redaction.vault import RedactionVault
from mistify.report.generator import write_report
from mistify.scratchpad.db import ScratchpadDB

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


@cli.command(name="investigate")
@click.option("--incident-id", required=True)
@_config_option
def investigate_command(incident_id: str, config_path: Path | None) -> None:
    """Run the investigation loop over an ingested incident."""
    config = load_config(config_path)
    path = config.scratchpad_path(incident_id)
    if not path.exists():
        raise click.ClickException(f"no scratchpad for incident {incident_id!r} at {path}")

    with ScratchpadDB(path) as db:
        result = run_skeleton_investigation(db)

    click.echo(f"steps  {result.steps}")
    click.echo(f"notes  {len(result.notes)}")
    for note in result.notes:
        click.echo(f"  [{note.confidence}] {note.note}")


@cli.command(name="report")
@click.option("--incident-id", required=True)
@click.option("--format", "report_format", default=None, help="markdown (html/pdf: Phase 6).")
@_config_option
def report_command(incident_id: str, report_format: str | None, config_path: Path | None) -> None:
    """Render the incident report."""
    config = load_config(config_path)
    chosen = report_format or config.report.format
    if chosen != "markdown":
        raise click.ClickException(f"report format {chosen!r} arrives in Phase 6; use markdown.")

    path = config.scratchpad_path(incident_id)
    if not path.exists():
        raise click.ClickException(f"no scratchpad for incident {incident_id!r} at {path}")

    with ScratchpadDB(path) as db:
        output = write_report(db, config.report.output_dir, incident_id)
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
@_config_option
def run_command(
    source: Path, incident_id: str | None, format_name: str, config_path: Path | None
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
        investigation = run_skeleton_investigation(db)
        output = write_report(db, config.report.output_dir, result.incident_id)

    click.echo(f"investigated in {investigation.steps} steps")
    click.echo(f"report {output}")


def main() -> int:
    cli()
    return 0


if __name__ == "__main__":
    sys.exit(main())

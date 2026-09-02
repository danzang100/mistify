"""CLI surface and the Phase 1 exit criterion: one file to one report."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

from mistify.cli import cli
from tests.fixtures.synthetic_incident import ROOT_CAUSE_MARKER


@pytest.fixture
def config_file(make_config_file: Callable[..., Path]) -> Path:
    """The shared scratch config on disk, under the name every test here already uses."""
    return make_config_file()


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_help_lists_every_command(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for command in ("ingest", "investigate", "report", "run", "reveal"):
        assert command in result.output


def test_version_is_reported(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "mistify" in result.output


def test_run_produces_a_report_naming_the_root_cause(
    runner: CliRunner, incident_file: Path, config_file: Path, tmp_path: Path
) -> None:
    """Phase 1 exit criterion."""
    result = runner.invoke(
        cli,
        [
            "run",
            "--source",
            str(incident_file),
            "--incident-id",
            "cli-run",
            "--investigator",
            "skeleton",
            "--config",
            str(config_file),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "ingested" in result.output

    report = tmp_path / "reports" / "cli-run.md"
    assert report.exists()
    assert ROOT_CAUSE_MARKER in report.read_text(encoding="utf-8")


def test_three_step_pipeline_matches_run(
    runner: CliRunner, incident_file: Path, config_file: Path, tmp_path: Path
) -> None:
    common = ["--config", str(config_file)]
    ingest_result = runner.invoke(
        cli, ["ingest", "--source", str(incident_file), "--incident-id", "staged", *common]
    )
    assert ingest_result.exit_code == 0, ingest_result.output
    assert "events loaded" in ingest_result.output

    investigate_result = runner.invoke(
        cli, ["investigate", "--incident-id", "staged", "--investigator", "skeleton", *common]
    )
    assert investigate_result.exit_code == 0, investigate_result.output
    assert ROOT_CAUSE_MARKER in investigate_result.output

    report_result = runner.invoke(cli, ["report", "--incident-id", "staged", *common])
    assert report_result.exit_code == 0, report_result.output

    report = tmp_path / "reports" / "staged.md"
    assert ROOT_CAUSE_MARKER in report.read_text(encoding="utf-8")


def test_incident_id_defaults_from_the_source(
    runner: CliRunner, incident_file: Path, config_file: Path
) -> None:
    result = runner.invoke(
        cli, ["ingest", "--source", str(incident_file), "--config", str(config_file)]
    )
    assert result.exit_code == 0, result.output
    assert "-incident" in result.output


def test_investigate_without_ingest_fails_clearly(runner: CliRunner, config_file: Path) -> None:
    result = runner.invoke(
        cli, ["investigate", "--incident-id", "never-ingested", "--config", str(config_file)]
    )
    assert result.exit_code != 0
    assert "no scratchpad" in result.output


def test_report_without_ingest_fails_clearly(runner: CliRunner, config_file: Path) -> None:
    result = runner.invoke(
        cli, ["report", "--incident-id", "never-ingested", "--config", str(config_file)]
    )
    assert result.exit_code != 0
    assert "no scratchpad" in result.output


def _ingest(runner: CliRunner, incident_file: Path, config_file: Path, incident_id: str) -> None:
    runner.invoke(
        cli,
        [
            "ingest",
            "--source",
            str(incident_file),
            "--incident-id",
            incident_id,
            "--config",
            str(config_file),
        ],
    )


def test_a_format_nobody_implements_is_refused_by_the_option(
    runner: CliRunner, incident_file: Path, config_file: Path
) -> None:
    """The choice is declared on the option, so an unknown format never reaches a template."""
    _ingest(runner, incident_file, config_file, "fmt")

    result = runner.invoke(
        cli, ["report", "--incident-id", "fmt", "--format", "docx", "--config", str(config_file)]
    )

    assert result.exit_code != 0
    assert "docx" in result.output


def test_html_is_written_with_an_html_extension(
    runner: CliRunner, incident_file: Path, config_file: Path, tmp_path: Path
) -> None:
    _ingest(runner, incident_file, config_file, "fmt-html")

    result = runner.invoke(
        cli,
        ["report", "--incident-id", "fmt-html", "--format", "html", "--config", str(config_file)],
    )

    assert result.exit_code == 0, result.output
    written = next(tmp_path.rglob("fmt-html.html"))
    body = written.read_text(encoding="utf-8")
    assert body.startswith("<!doctype html>")
    assert "Incident report: fmt-html" in body


def test_pdf_is_written_as_pdf_bytes(
    runner: CliRunner, incident_file: Path, config_file: Path, tmp_path: Path
) -> None:
    """The one format whose output is not text, so the write path differs and is worth pinning."""
    pytest.importorskip("xhtml2pdf")
    _ingest(runner, incident_file, config_file, "fmt-pdf")

    result = runner.invoke(
        cli,
        ["report", "--incident-id", "fmt-pdf", "--format", "pdf", "--config", str(config_file)],
    )

    assert result.exit_code == 0, result.output
    written = next(tmp_path.rglob("fmt-pdf.pdf"))
    assert written.read_bytes().startswith(b"%PDF-")


def test_unknown_format_reports_the_handoff(
    runner: CliRunner, config_file: Path, tmp_path: Path
) -> None:
    source = tmp_path / "syslog.log"
    source.write_text("Aug 30 14:22:01 host sshd[1]: Accepted password\n" * 20, encoding="utf-8")
    result = runner.invoke(cli, ["ingest", "--source", str(source), "--config", str(config_file)])
    assert result.exit_code != 0
    assert "Phase 4" in result.output


def test_missing_source_is_rejected_by_click(runner: CliRunner, config_file: Path) -> None:
    result = runner.invoke(
        cli, ["ingest", "--source", "absent.jsonl", "--config", str(config_file)]
    )
    assert result.exit_code != 0


# --------------------------------------------------------------- the model-driven path


def test_the_loop_is_the_default_investigator(runner: CliRunner) -> None:
    """Phase 3's investigator is the product's default; the heuristic is the fallback."""
    result = runner.invoke(cli, ["investigate", "--help"])
    assert result.exit_code == 0
    assert "--investigator" in result.output
    assert "skeleton" in result.output


def test_missing_credential_explains_what_to_set(
    runner: CliRunner, incident_file: Path, config_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failure a first-time user hits, so it has to name the fix rather than trace.

    Resolved before the loop starts: by the time a model call fails, a scratchpad has been
    loaded and the error reads like an investigation problem instead of a setup one.
    """
    runner.invoke(
        cli,
        [
            "ingest",
            "--source",
            str(incident_file),
            "--incident-id",
            "nocred",
            "--config",
            str(config_file),
        ],
    )
    result = runner.invoke(
        cli, ["investigate", "--incident-id", "nocred", "--config", str(config_file)]
    )

    assert result.exit_code != 0
    assert "GEMINI_API_KEY" in result.output
    assert ".env" in result.output
    assert "--investigator skeleton" in result.output

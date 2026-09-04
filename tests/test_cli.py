"""CLI surface and the Phase 1 exit criterion: one file to one report."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

from mistify.cli import cli
from mistify.eval.fixtures import ROOT_CAUSE_MARKER
from mistify.scratchpad.db import ScratchpadDB


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


def test_an_unrecognised_file_is_read_line_by_line(
    runner: CliRunner, config_file: Path, tmp_path: Path
) -> None:
    source = tmp_path / "syslog.log"
    source.write_text("Aug 30 14:22:01 host sshd[1]: Accepted password\n" * 20, encoding="utf-8")
    result = runner.invoke(cli, ["ingest", "--source", str(source), "--config", str(config_file)])
    assert result.exit_code == 0, result.output
    assert "raw_lines" in result.output


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


def test_eval_digest_reports_the_ranking_without_calling_a_model(
    runner: CliRunner, config_file: Path
) -> None:
    """The pre-flight check: where the known evidence sits, for the price of an ingest.

    No provider is configured in the test environment at all, so a mode that reached for one
    would fail rather than pass quietly.
    """
    result = runner.invoke(
        cli,
        ["eval", "--digest", "--case", "pool-exhaustion", "--config", str(config_file)],
    )

    assert result.exit_code == 0, result.output
    assert "markers in the top 40" in result.output
    assert ROOT_CAUSE_MARKER in result.output


def test_eval_digest_fails_when_the_evidence_is_below_the_digest(
    runner: CliRunner, config_file: Path
) -> None:
    """The control: the gate has to be able to fail, so squeeze the digest until it does.

    A run started from a digest holding none of the evidence is measuring the ranking rather
    than the loop, which is worth an exit code rather than a line of output nobody reads.
    """
    result = runner.invoke(
        cli,
        [
            "eval",
            "--digest",
            "--digest-limit",
            "1",
            "--case",
            "pool-exhaustion",
            "--config",
            str(config_file),
        ],
    )

    assert result.exit_code == 1, result.output
    assert "markers in the top 1" in result.output


def test_investigating_twice_refuses_rather_than_inheriting_notes(
    runner: CliRunner, incident_file: Path, config_file: Path
) -> None:
    """Two runs sharing one scratchpad is two investigations sharing one record.

    The second run does not know the notes are not its own, and anything scoring the scratchpad
    afterwards counts both. The eval harness copies a fresh scratchpad per run to avoid exactly
    this; the CLI used to inherit silently.
    """
    common = ["--incident-id", "twice", "--config", str(config_file)]
    ingest = runner.invoke(cli, ["ingest", "--source", str(incident_file), *common])
    assert ingest.exit_code == 0, ingest.output
    first = runner.invoke(cli, ["investigate", "--investigator", "skeleton", *common])
    assert first.exit_code == 0, first.output

    second = runner.invoke(cli, ["investigate", "--investigator", "skeleton", *common])

    assert second.exit_code != 0
    assert "already holds" in second.output
    assert "--resume" in second.output and "--restart" in second.output


def test_restart_clears_the_previous_investigation(
    runner: CliRunner, incident_file: Path, config_file: Path, tmp_path: Path
) -> None:
    """`--restart` is the other answer, and it says how much it deleted."""
    common = ["--incident-id", "again", "--config", str(config_file)]
    runner.invoke(cli, ["ingest", "--source", str(incident_file), *common])
    runner.invoke(cli, ["investigate", "--investigator", "skeleton", *common])
    with ScratchpadDB(tmp_path / "incident_again.sqlite") as db:
        before = len(db.notes())
    assert before, "the skeleton investigator is expected to write notes"

    restarted = runner.invoke(
        cli, ["investigate", "--investigator", "skeleton", "--restart", *common]
    )

    assert restarted.exit_code == 0, restarted.output
    assert "restarted: cleared" in restarted.output
    with ScratchpadDB(tmp_path / "incident_again.sqlite") as db:
        # The rerun wrote its own; what matters is that it did not inherit the first run's.
        assert len(db.notes()) == before


def test_a_first_investigation_needs_no_flag(
    runner: CliRunner, incident_file: Path, config_file: Path
) -> None:
    """The control: the refusal must not stand in front of an ordinary first run."""
    common = ["--incident-id", "once", "--config", str(config_file)]
    runner.invoke(cli, ["ingest", "--source", str(incident_file), *common])

    result = runner.invoke(cli, ["investigate", "--investigator", "skeleton", *common])

    assert result.exit_code == 0, result.output
    assert "already holds" not in result.output


def test_restart_clears_a_run_that_wrote_no_notes(
    runner: CliRunner, incident_file: Path, config_file: Path, tmp_path: Path
) -> None:
    """An attempt that concluded nothing still left its query log behind.

    Found in use: a run that hit its tool-call cap without writing a note left twenty rows in
    `query_log`, and the next run's audit trail carried queries it never made. `--restart`
    guarded on notes existing, and notes were exactly what that run had none of.
    """
    common = ["--incident-id", "noNotes", "--config", str(config_file)]
    runner.invoke(cli, ["ingest", "--source", str(incident_file), *common])
    scratchpad = tmp_path / "incident_noNotes.sqlite"
    with ScratchpadDB(scratchpad) as db:
        db.log_query(1, "SELECT * FROM log_events", 5)
        assert db.queries() and not db.notes()

    result = runner.invoke(cli, ["investigate", "--investigator", "skeleton", "--restart", *common])

    assert result.exit_code == 0, result.output
    with ScratchpadDB(scratchpad) as db:
        assert [q["sql_query"] for q in db.queries()] != ["SELECT * FROM log_events"]

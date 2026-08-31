"""CLI surface and the Phase 1 exit criterion: one file to one report."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from mistify.cli import cli
from mistify.common.config import MistifyConfig
from tests.fixtures.synthetic_incident import ROOT_CAUSE_MARKER


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    """A config on disk pointing every output at a scratch directory."""
    config = MistifyConfig.model_validate(
        {
            "scratchpad": {"path": str(tmp_path / "incident_{incident_id}.sqlite")},
            "drain3": {"snapshot_path": str(tmp_path / "drain3_{incident_id}.json")},
            "report": {"output_dir": str(tmp_path / "reports")},
        }
    )
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config.model_dump(mode="json")), encoding="utf-8")
    return path


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_help_lists_every_command(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for command in ("ingest", "investigate", "report", "run"):
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

    investigate_result = runner.invoke(cli, ["investigate", "--incident-id", "staged", *common])
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


def test_unsupported_report_format_is_refused(
    runner: CliRunner, incident_file: Path, config_file: Path
) -> None:
    runner.invoke(
        cli,
        [
            "ingest",
            "--source",
            str(incident_file),
            "--incident-id",
            "fmt",
            "--config",
            str(config_file),
        ],
    )
    result = runner.invoke(
        cli, ["report", "--incident-id", "fmt", "--format", "pdf", "--config", str(config_file)]
    )
    assert result.exit_code != 0
    assert "Phase 6" in result.output


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

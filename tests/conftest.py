"""Shared pytest fixtures."""

from __future__ import annotations

import shutil
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml

from mistify.common.config import MistifyConfig
from mistify.eval.fixtures import write_incident, write_quiet_hour
from mistify.pipeline import IngestResult, ingest
from mistify.scratchpad.db import ScratchpadDB

INCIDENT_ID = "test-incident"

#: Every credential any provider adapter looks for.
_PROVIDER_CREDENTIALS = (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_GENAI_API_KEY",
)


@pytest.fixture(autouse=True)
def _no_live_model_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make it impossible for a test to reach a real model.

    The CLI loads a `.env` file on startup, which is right for a user and dangerous in a test
    run: a command that defaults to the model-driven investigator would quietly spend real
    quota and return a different answer every time. This already happened once - a test
    asserting that a missing credential fails cleanly instead passed, because it had silently
    performed a live investigation.

    Autouse and unconditional. A test that genuinely wants a provider injects a fake one; no
    test should ever need a real credential.
    """
    for name in _PROVIDER_CREDENTIALS:
        monkeypatch.delenv(name, raising=False)
    # Clearing the environment is not enough on its own: the CLI reloads `.env` on every
    # invocation, which puts the key straight back.
    monkeypatch.setattr("mistify.cli.load_dotenv", lambda *a, **k: False, raising=False)


def _scratch_config(directory: Path, **sections: dict[str, Any]) -> MistifyConfig:
    """Config with every output pointed inside `directory`, so runs never touch the repo.

    `sections` are merged over the scratch paths, so a caller overriding `drain3` keeps the
    snapshot path it did not mention. Six test modules used to build this triple by hand;
    each new config field meant editing all of them.
    """
    raw: dict[str, dict[str, Any]] = {
        "scratchpad": {"path": str(directory / "incident_{incident_id}.sqlite")},
        "drain3": {"snapshot_path": str(directory / "drain3_{incident_id}.json")},
        "report": {"output_dir": str(directory / "reports")},
        # The inferred-schema cache too. It was hardcoded to `.cache/inferred` relative to the
        # working directory, so the suite read and wrote the repository's own cache: one real
        # bootstrapper run over an OpenSSH log left a schema behind, and a test asserting that
        # a severity survived ingestion then failed against a schema written by a file it had
        # never heard of. A test must not be able to see another run's state.
        "bootstrap": {"schema_dir": str(directory / "inferred")},
    }
    for name, values in sections.items():
        raw.setdefault(name, {}).update(values)
    return MistifyConfig.model_validate(raw)


@pytest.fixture(scope="session")
def incident_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The synthetic incident, generated once per session."""
    directory = tmp_path_factory.mktemp("incident")
    return write_incident(directory / "incident.jsonl", total_lines=5000)


@pytest.fixture
def config(tmp_path: Path) -> MistifyConfig:
    """Config pointed at a scratch directory so runs never touch the repo."""
    return _scratch_config(tmp_path)


@pytest.fixture
def make_config(tmp_path: Path) -> Callable[..., MistifyConfig]:
    """Build a scratch config with section overrides, for tests needing more than the default.

    Use `config` when the defaults will do; reach for this when a test needs redaction off,
    calibration disabled, or a different `max_clusters`.
    """

    def build(**sections: dict[str, Any]) -> MistifyConfig:
        return _scratch_config(tmp_path, **sections)

    return build


@pytest.fixture
def make_config_file(tmp_path: Path) -> Callable[..., Path]:
    """The same config, written to YAML, for tests that drive the CLI through --config."""

    def build(**sections: dict[str, Any]) -> Path:
        config = _scratch_config(tmp_path, **sections)
        path = tmp_path / "config.yaml"
        path.write_text(yaml.safe_dump(config.model_dump(mode="json")), encoding="utf-8")
        return path

    return build


@pytest.fixture
def db(tmp_path: Path) -> ScratchpadDB:
    """An empty scratchpad."""
    with ScratchpadDB(tmp_path / "empty.sqlite") as database:
        yield database


@pytest.fixture(scope="session")
def _ingest_master(
    incident_file: Path, tmp_path_factory: pytest.TempPathFactory
) -> tuple[IngestResult, MistifyConfig]:
    """Ingest the synthetic incident exactly once for the whole session.

    Tests copy this result rather than re-running the pipeline. Ingesting ~5,000 lines takes
    about a second, and enough tests want a loaded scratchpad that re-running it per test was
    most of the suite's wall clock -- almost all of it spent re-proving that ingestion works
    before getting to the assertion the test was actually about.
    """
    directory = tmp_path_factory.mktemp("ingest-master")
    config = _scratch_config(directory)
    return ingest(incident_file, config, incident_id=INCIDENT_ID), config


@pytest.fixture
def ingested(
    _ingest_master: tuple[IngestResult, MistifyConfig], config: MistifyConfig
) -> IngestResult:
    """The synthetic incident, ingested once per session and copied per test.

    Copied rather than shared because tests mutate what they are given -- writing notes,
    recording metrics, updating scores -- and a shared handle would leak that between them.
    A file copy is milliseconds against a second for the ingest.
    """
    master, master_config = _ingest_master

    scratchpad = config.scratchpad_path(master.incident_id)
    scratchpad.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(master.scratchpad_path, scratchpad)

    # The Drain3 snapshot travels too: tests assert against it through `config`, which points
    # at their own directory rather than the session one.
    master_snapshot = master_config.snapshot_path(master.incident_id)
    snapshot = config.snapshot_path(master.incident_id)
    if master_snapshot is not None and snapshot is not None and master_snapshot.exists():
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(master_snapshot, snapshot)

    return replace(master, scratchpad_path=scratchpad)


@pytest.fixture
def loaded_db(ingested: IngestResult) -> ScratchpadDB:
    """A scratchpad loaded with the synthetic incident."""
    with ScratchpadDB(ingested.scratchpad_path) as database:
        yield database


@pytest.fixture(scope="session")
def _quiet_master(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[IngestResult, MistifyConfig]:
    """The quiet hour, ingested once per session. Same reasoning as the incident master."""
    directory = tmp_path_factory.mktemp("quiet-master")
    config = _scratch_config(directory)
    source = write_quiet_hour(directory / "quiet_hour.jsonl")
    return ingest(source, config, incident_id="quiet-hour"), config


@pytest.fixture
def quiet_db(
    _quiet_master: tuple[IngestResult, MistifyConfig], config: MistifyConfig
) -> Iterator[ScratchpadDB]:
    """A scratchpad loaded with the negative control: an hour with nothing wrong in it."""
    master, _ = _quiet_master
    scratchpad = config.scratchpad_path(master.incident_id)
    scratchpad.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(master.scratchpad_path, scratchpad)
    with ScratchpadDB(scratchpad) as database:
        yield database

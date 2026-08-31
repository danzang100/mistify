"""Shared pytest fixtures."""

from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from mistify.common.config import MistifyConfig
from mistify.pipeline import IngestResult, ingest
from mistify.scratchpad.db import ScratchpadDB
from tests.fixtures.synthetic_incident import write_incident

INCIDENT_ID = "test-incident"


def _scratch_config(directory: Path) -> MistifyConfig:
    """Config with every output pointed inside `directory`, so runs never touch the repo."""
    return MistifyConfig.model_validate(
        {
            "scratchpad": {"path": str(directory / "incident_{incident_id}.sqlite")},
            "drain3": {"snapshot_path": str(directory / "drain3_{incident_id}.json")},
            "report": {"output_dir": str(directory / "reports")},
        }
    )


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

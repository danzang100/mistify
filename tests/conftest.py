"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from mistify.common.config import MistifyConfig
from mistify.pipeline import IngestResult, ingest
from mistify.scratchpad.db import ScratchpadDB
from tests.fixtures.synthetic_incident import write_incident

INCIDENT_ID = "test-incident"


@pytest.fixture(scope="session")
def incident_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The synthetic incident, generated once per session."""
    directory = tmp_path_factory.mktemp("incident")
    return write_incident(directory / "incident.jsonl", total_lines=5000)


@pytest.fixture
def config(tmp_path: Path) -> MistifyConfig:
    """Config pointed at a scratch directory so runs never touch the repo."""
    return MistifyConfig.model_validate(
        {
            "scratchpad": {"path": str(tmp_path / "incident_{incident_id}.sqlite")},
            "drain3": {"snapshot_path": str(tmp_path / "drain3_{incident_id}.json")},
            "report": {"output_dir": str(tmp_path / "reports")},
        }
    )


@pytest.fixture
def db(tmp_path: Path) -> ScratchpadDB:
    """An empty scratchpad."""
    with ScratchpadDB(tmp_path / "empty.sqlite") as database:
        yield database


@pytest.fixture
def ingested(incident_file: Path, config: MistifyConfig) -> IngestResult:
    """The synthetic incident, run through the full ingest pipeline."""
    return ingest(incident_file, config, incident_id=INCIDENT_ID)


@pytest.fixture
def loaded_db(ingested: IngestResult) -> ScratchpadDB:
    """A scratchpad loaded with the synthetic incident."""
    with ScratchpadDB(ingested.scratchpad_path) as database:
        yield database

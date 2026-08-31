"""End-to-end ingestion, and the stage-ordering guarantees from decisions G1 and G2."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mistify.common.config import MistifyConfig
from mistify.pipeline import IngestResult, UnknownFormatError, derive_incident_id, ingest
from mistify.scratchpad.db import ScratchpadDB
from mistify.templating.drain_wrapper import read_snapshot
from tests.fixtures.synthetic_incident import (
    PLANTED_API_KEY,
    PLANTED_EMAILS,
    PLANTED_IPS,
    ROOT_CAUSE_MARKER,
)

# --------------------------------------------------------------- basic load


def test_ingest_loads_every_parsable_line(ingested: IngestResult) -> None:
    assert ingested.events_loaded == ingested.lines_read
    assert ingested.parse_errors == 0
    assert ingested.format_name == "json_lines"


def test_ingest_compresses(ingested: IngestResult) -> None:
    """The whole premise: far fewer templates than lines."""
    assert ingested.unique_templates < ingested.events_loaded / 20
    assert 0.0 < ingested.compression_ratio < 0.05


def test_events_and_templates_are_consistent(loaded_db: ScratchpadDB) -> None:
    assert loaded_db.orphan_event_count() == 0
    assert loaded_db.event_count() > 0
    assert loaded_db.template_count() > 0


def test_incident_row_is_created(loaded_db: ScratchpadDB) -> None:
    incident = loaded_db.incident()
    assert incident is not None
    assert incident["incident_id"] == "test-incident"
    assert incident["format"] == "json_lines"


def test_planted_root_cause_survives_templating(loaded_db: ScratchpadDB) -> None:
    patterns = [t["pattern"] for t in loaded_db.top_templates(limit=500, order_by="count")]
    assert any(ROOT_CAUSE_MARKER in p for p in patterns)


# --------------------------------------------------------------- decision G1


@pytest.mark.parametrize("secret", [*PLANTED_EMAILS, *PLANTED_IPS, PLANTED_API_KEY])
def test_no_planted_secret_reaches_the_scratchpad(loaded_db: ScratchpadDB, secret: str) -> None:
    """Redaction runs immediately after parse(), so nothing downstream ever sees a value."""
    for table, columns in (
        ("log_events", ("raw", "message", "fields_json")),
        ("templates", ("pattern",)),
    ):
        for column in columns:
            row = loaded_db._conn.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE {column} LIKE ?",
                (f"%{secret}%",),
            ).fetchone()
            assert row["n"] == 0, f"{secret!r} leaked into {table}.{column}"


def test_redaction_actually_fired(ingested: IngestResult) -> None:
    """A zero count would make the test above pass for the wrong reason."""
    assert ingested.redaction_counts.get("email", 0) > 0
    assert ingested.redaction_counts.get("ipv4", 0) > 0
    assert ingested.redaction_counts.get("api_key", 0) > 0


def test_placeholders_are_present_in_stored_events(loaded_db: ScratchpadDB) -> None:
    row = loaded_db._conn.execute(
        "SELECT COUNT(*) AS n FROM log_events WHERE raw LIKE '%[IPV4:%'"
    ).fetchone()
    assert row["n"] > 0


def test_correlation_survives_redaction(loaded_db: ScratchpadDB) -> None:
    """The same address must map to one token, or the investigator loses the join key."""
    rows = loaded_db._conn.execute(
        "SELECT DISTINCT fields_json FROM log_events WHERE fields_json LIKE '%client_ip%'"
    ).fetchall()
    tokens = {json.loads(r["fields_json"])["client_ip"] for r in rows}
    assert 0 < len(tokens) <= len(PLANTED_IPS)


# --------------------------------------------------------------- decision G2


@pytest.mark.parametrize("secret", [*PLANTED_EMAILS, *PLANTED_IPS, PLANTED_API_KEY])
def test_no_planted_secret_reaches_the_drain3_snapshot(
    ingested: IngestResult, config: MistifyConfig, secret: str
) -> None:
    """The snapshot is a durable on-disk artifact and must not become a secret store."""
    snapshot = config.snapshot_path(ingested.incident_id)
    assert snapshot is not None and snapshot.exists()
    # Decoded, not raw: the snapshot is base64-encoded compressed JSON, so scanning the
    # file bytes would pass regardless of what the tree actually holds.
    assert secret not in read_snapshot(snapshot)


# --------------------------------------------------------------- decision G7


def test_every_stage_reports_health_metrics(loaded_db: ScratchpadDB) -> None:
    keys = {(m["stage"], m["metric"]) for m in loaded_db.metrics()}
    for expected in (
        ("ingest", "lines_read"),
        ("ingest", "parse_errors"),
        ("redaction", "mode"),
        ("redaction", "redacted_total"),
        ("templating", "compression_ratio"),
        ("templating", "unique_templates"),
        ("scratchpad", "orphan_events"),
    ):
        assert expected in keys, f"missing health metric {expected}"


def test_compression_ratio_metric_matches_the_result(
    ingested: IngestResult, loaded_db: ScratchpadDB
) -> None:
    metric = next(m for m in loaded_db.metrics("templating") if m["metric"] == "compression_ratio")
    assert metric["value_num"] == pytest.approx(ingested.compression_ratio, abs=1e-4)


# --------------------------------------------------------------- errors and options


def test_parse_errors_are_surfaced(tmp_path: Path, config: MistifyConfig) -> None:
    source = tmp_path / "mixed.jsonl"
    source.write_text(
        '{"timestamp": "2026-08-30T14:00:00Z", "level": "INFO", "message": "ok"}\n'
        "{broken\n"
        '{"timestamp": "2026-08-30T14:00:01Z", "level": "INFO", "message": "ok"}\n',
        encoding="utf-8",
    )
    result = ingest(source, config, incident_id="mixed")
    assert result.events_loaded == 2
    assert result.parse_errors == 1


def test_unknown_format_raises_until_phase_4(tmp_path: Path, config: MistifyConfig) -> None:
    source = tmp_path / "syslog.log"
    source.write_text("Aug 30 14:22:01 host sshd[1]: Accepted password\n" * 20, encoding="utf-8")
    with pytest.raises(UnknownFormatError, match="Phase 4"):
        ingest(source, config, incident_id="syslog")


def test_missing_source_raises(config: MistifyConfig) -> None:
    with pytest.raises(FileNotFoundError):
        ingest("does-not-exist.jsonl", config)


def test_forced_format_skips_detection(incident_file: Path, config: MistifyConfig) -> None:
    result = ingest(incident_file, config, incident_id="forced", format_name="json_lines")
    assert result.format_name == "json_lines"


def test_redaction_off_leaves_values_intact(incident_file: Path, tmp_path: Path) -> None:
    config = MistifyConfig.model_validate(
        {
            "redaction": {"mode": "off"},
            "scratchpad": {"path": str(tmp_path / "off_{incident_id}.sqlite")},
            "drain3": {"snapshot_path": str(tmp_path / "d_{incident_id}.json")},
        }
    )
    result = ingest(incident_file, config, incident_id="off")
    with ScratchpadDB(result.scratchpad_path) as db:
        row = db._conn.execute(
            "SELECT COUNT(*) AS n FROM log_events WHERE raw LIKE ?",
            (f"%{PLANTED_API_KEY}%",),
        ).fetchone()
    assert row["n"] > 0


def test_reingesting_replaces_the_scratchpad(incident_file: Path, config: MistifyConfig) -> None:
    first = ingest(incident_file, config, incident_id="repeat")
    second = ingest(incident_file, config, incident_id="repeat")
    assert first.events_loaded == second.events_loaded
    with ScratchpadDB(second.scratchpad_path) as db:
        assert db.event_count() == second.events_loaded


# --------------------------------------------------------------- decision G6


def test_derive_incident_id_is_dated_and_slugged() -> None:
    incident_id = derive_incident_id("logs/Checkout Service.jsonl")
    assert incident_id.endswith("-checkout-service")
    assert len(incident_id.split("-")) >= 4


def test_derive_incident_id_handles_odd_names() -> None:
    assert derive_incident_id("logs/___.jsonl").endswith("-incident")

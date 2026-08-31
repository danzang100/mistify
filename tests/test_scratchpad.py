"""Scratchpad schema, migrations, evidence constraint, and read-only enforcement."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mistify.common.models import TemplateSummary
from mistify.scratchpad.db import MIGRATIONS, ReadOnlyViolation, ScratchpadDB

# --------------------------------------------------------------- migrations


def test_migrations_apply_on_first_open(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "a.sqlite") as db:
        assert db.apply_migrations() == []  # already applied during __init__
        tables = {
            row["name"]
            for row in db._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert {
        "incidents",
        "templates",
        "log_events",
        "scratchpad_notes",
        "query_log",
        "run_metadata",
        "schema_migrations",
    } <= tables


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "a.sqlite"
    with ScratchpadDB(path) as db:
        db.record_metric("ingest", "lines_read", 10)
    with ScratchpadDB(path) as db:
        assert db.apply_migrations() == []
        assert db.metrics("ingest")[0]["value"] == "10"


def test_migration_versions_are_recorded(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "a.sqlite") as db:
        rows = db._conn.execute("SELECT version FROM schema_migrations").fetchall()
    assert {r["version"] for r in rows} == set(MIGRATIONS)


# --------------------------------------------------------------- incidents (G6)


def test_incident_is_recorded(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "a.sqlite") as db:
        db.create_incident("2026-08-30-checkout", "logs/x.jsonl", "json_lines", "strict")
        incident = db.incident()
    assert incident is not None
    assert incident["incident_id"] == "2026-08-30-checkout"
    assert incident["redaction_mode"] == "strict"


def test_incident_is_none_before_ingest(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "a.sqlite") as db:
        assert db.incident() is None


# --------------------------------------------------------------- run_metadata (G7)


def test_metrics_round_trip_with_numeric_column(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "a.sqlite") as db:
        db.record_metric("templating", "compression_ratio", 0.0412)
        db.record_metric("ingest", "format", "json_lines")
        metrics = {(m["stage"], m["metric"]): m for m in db.metrics()}

    assert metrics[("templating", "compression_ratio")]["value_num"] == pytest.approx(0.0412)
    assert metrics[("ingest", "format")]["value"] == "json_lines"
    assert metrics[("ingest", "format")]["value_num"] is None


def test_recording_the_same_metric_twice_replaces_it(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "a.sqlite") as db:
        db.record_metric("ingest", "lines_read", 10)
        db.record_metric("ingest", "lines_read", 20)
        rows = db.metrics("ingest")
    assert len(rows) == 1
    assert rows[0]["value"] == "20"


def test_metrics_can_be_filtered_by_stage(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "a.sqlite") as db:
        db.record_metric("ingest", "a", 1)
        db.record_metric("redaction", "b", 2)
        assert [m["metric"] for m in db.metrics("redaction")] == ["b"]


# --------------------------------------------------------------- evidence constraint


def test_note_with_evidence_is_written(db: ScratchpadDB) -> None:
    note_id = db.write_note(1, "pool exhausted", {"template_ids": [7]}, "medium")
    notes = db.notes()
    assert notes[0].id == note_id
    assert notes[0].evidence == {"template_ids": [7]}


@pytest.mark.parametrize("evidence", [{}, None])
def test_note_without_evidence_is_rejected_in_python(db: ScratchpadDB, evidence: object) -> None:
    with pytest.raises(ValueError, match="evidence is mandatory"):
        db.write_note(1, "unsupported claim", evidence, "high")  # type: ignore[arg-type]


@pytest.mark.parametrize("payload", ["", "  ", "[]", "{}", "null"])
def test_empty_evidence_is_rejected_by_the_schema(db: ScratchpadDB, payload: str) -> None:
    """Enforced in SQL, so a future caller cannot bypass it by skipping write_note()."""
    with pytest.raises(sqlite3.IntegrityError):
        db._conn.execute(
            "INSERT INTO scratchpad_notes"
            " (step, note, supporting_evidence_json, confidence, created_at)"
            " VALUES (1, 'claim', ?, 'low', '2026-08-30T00:00:00Z')",
            (payload,),
        )


def test_invalid_confidence_is_rejected_by_the_schema(db: ScratchpadDB) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        db._conn.execute(
            "INSERT INTO scratchpad_notes"
            " (step, note, supporting_evidence_json, confidence, created_at)"
            " VALUES (1, 'claim', '{\"a\":1}', 'certain', '2026-08-30T00:00:00Z')"
        )


def test_empty_note_text_is_rejected(db: ScratchpadDB) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        db._conn.execute(
            "INSERT INTO scratchpad_notes"
            " (step, note, supporting_evidence_json, confidence, created_at)"
            " VALUES (1, '   ', '{\"a\":1}', 'low', '2026-08-30T00:00:00Z')"
        )


# --------------------------------------------------------------- read-only channel (G4)


@pytest.fixture
def populated(tmp_path: Path) -> ScratchpadDB:
    with ScratchpadDB(tmp_path / "ro.sqlite") as database:
        database.upsert_templates(
            [
                TemplateSummary(
                    template_id=1,
                    pattern="pool exhausted",
                    occurrence_count=3,
                    first_seen="2026-08-30T14:00:00Z",
                    last_seen="2026-08-30T14:05:00Z",
                    severity_mix={"FATAL": 3},
                    max_severity_rank=5,
                )
            ]
        )
        yield database


def test_select_is_allowed(populated: ScratchpadDB) -> None:
    rows = populated.run_readonly_sql("SELECT pattern, occurrence_count FROM templates")
    assert rows == [{"pattern": "pool exhausted", "occurrence_count": 3}]


def test_joins_and_aggregates_are_allowed(populated: ScratchpadDB) -> None:
    rows = populated.run_readonly_sql(
        "SELECT COUNT(*) AS n, MAX(occurrence_count) AS worst FROM templates"
    )
    assert rows[0]["n"] == 1


def test_cte_select_is_allowed(populated: ScratchpadDB) -> None:
    rows = populated.run_readonly_sql(
        "WITH hot AS (SELECT * FROM templates WHERE occurrence_count > 1) SELECT * FROM hot"
    )
    assert len(rows) == 1


@pytest.mark.parametrize(
    "query",
    [
        "INSERT INTO templates (template_id, pattern) VALUES (99, 'x')",
        "UPDATE templates SET pattern = 'x'",
        "DELETE FROM templates",
        "DROP TABLE templates",
        "ALTER TABLE templates ADD COLUMN sneaky TEXT",
        "CREATE TABLE evil (a TEXT)",
        "CREATE INDEX idx_evil ON templates(pattern)",
        "REPLACE INTO templates (template_id, pattern) VALUES (1, 'x')",
    ],
)
def test_mutations_are_refused(populated: ScratchpadDB, query: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        populated.run_readonly_sql(query)


@pytest.mark.parametrize(
    "query",
    [
        # A keyword blocklist over query text loses to every one of these.
        "/* SELECT */ DELETE FROM templates",
        "-- harmless\nDELETE FROM templates",
        "WITH x AS (SELECT 1) DELETE FROM templates",
        "ATTACH DATABASE 'other.sqlite' AS other",
        "PRAGMA writable_schema = ON",
        "SELECT load_extension('evil.so')",
        "INSERT INTO templates SELECT * FROM templates",
    ],
)
def test_evasion_attempts_are_refused(populated: ScratchpadDB, query: str) -> None:
    """This is a security boundary and the input is a model-authored string (decision G4)."""
    with pytest.raises(ReadOnlyViolation):
        populated.run_readonly_sql(query)


def test_refused_write_did_not_change_anything(populated: ScratchpadDB) -> None:
    with pytest.raises(ReadOnlyViolation):
        populated.run_readonly_sql("DELETE FROM templates")
    assert populated.template_count() == 1


def test_syntax_error_surfaces_as_a_violation(populated: ScratchpadDB) -> None:
    with pytest.raises(ReadOnlyViolation):
        populated.run_readonly_sql("SELECT FROM WHERE")


def test_results_are_capped(populated: ScratchpadDB) -> None:
    rows = populated.run_readonly_sql(
        "SELECT 1 AS n FROM templates, templates b, templates c", max_rows=1
    )
    assert len(rows) <= 1


# --------------------------------------------------------------- ordering


def test_top_templates_rejects_unknown_ordering(db: ScratchpadDB) -> None:
    with pytest.raises(ValueError, match="unknown ordering"):
        db.top_templates(order_by="vibes")


def test_top_templates_supports_every_documented_ordering(populated: ScratchpadDB) -> None:
    for ordering in ("count", "severity", "recency", "anomaly_score"):
        assert populated.top_templates(order_by=ordering)

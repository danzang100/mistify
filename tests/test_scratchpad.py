"""Scratchpad schema, migrations, evidence constraint, and read-only enforcement."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mistify.common.models import LogRecord, TemplateSummary, parse_timestamp
from mistify.metrics import (
    INGEST_FORMAT,
    INGEST_LINES_READ,
    TEMPLATING_COMPRESSION_RATIO,
    MetricView,
)
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
        db.record(INGEST_LINES_READ, 10)
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
        db.record(TEMPLATING_COMPRESSION_RATIO, 0.0412)
        db.record(INGEST_FORMAT, "json_lines")
        metrics = {(m["stage"], m["metric"]): m for m in db.metrics()}

    assert metrics[("templating", "compression_ratio")]["value_num"] == pytest.approx(0.0412)
    assert metrics[("ingest", "format")]["value"] == "json_lines"
    assert metrics[("ingest", "format")]["value_num"] is None


def test_recording_the_same_metric_twice_replaces_it(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "a.sqlite") as db:
        db.record(INGEST_LINES_READ, 10)
        db.record(INGEST_LINES_READ, 20)
        rows = db.metrics("ingest")
    assert len(rows) == 1
    assert rows[0]["value"] == "20"


def test_metrics_can_be_filtered_by_stage(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "a.sqlite") as db:
        db._record_metric("ingest", "a", 1)
        db._record_metric("redaction", "b", 2)
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


# --------------------------------------------------------------- noise suppression


@pytest.fixture
def noisy(tmp_path: Path) -> ScratchpadDB:
    """One dominant, unremarkable template alongside a rare severe one."""
    with ScratchpadDB(tmp_path / "noise.sqlite") as database:
        database.upsert_templates(
            [
                TemplateSummary(
                    template_id=1,
                    pattern="Heartbeat ok, uptime <*>",
                    occurrence_count=900,
                    first_seen="2026-08-30T14:00:00.000000Z",
                    last_seen="2026-08-30T14:59:00.000000Z",
                    severity_mix={"DEBUG": 900},
                    max_severity_rank=1,
                    anomaly_score=0.10,
                ),
                TemplateSummary(
                    template_id=2,
                    pattern="Database connection pool exhausted",
                    occurrence_count=6,
                    first_seen="2026-08-30T14:38:00.000000Z",
                    last_seen="2026-08-30T14:40:00.000000Z",
                    severity_mix={"FATAL": 6},
                    max_severity_rank=5,
                    anomaly_score=0.90,
                ),
            ]
        )
        records = [
            (
                LogRecord(
                    ts=parse_timestamp("2026-08-30T14:10:00Z"),
                    source="svc",
                    severity="DEBUG",
                    raw="hb",
                    message="Heartbeat ok, uptime 1",
                ),
                1,
            )
        ] * 900
        records += [
            (
                LogRecord(
                    ts=parse_timestamp("2026-08-30T14:38:00Z"),
                    source="svc",
                    severity="FATAL",
                    raw="boom",
                    message="Database connection pool exhausted",
                ),
                2,
            )
        ] * 6
        database.bulk_insert_events(records)
        yield database


def test_dominant_unremarkable_template_is_noise(noisy: ScratchpadDB) -> None:
    assert noisy.noise_template_ids() == {1}


def test_volume_alone_does_not_make_a_template_noise(noisy: ScratchpadDB) -> None:
    """A flood can be the incident, so the anomaly ceiling is part of the test."""
    assert noisy.noise_template_ids(anomaly_ceiling=0.0) == set()


def test_rare_severe_template_is_never_noise(noisy: ScratchpadDB) -> None:
    assert 2 not in noisy.noise_template_ids()


def test_suppressed_ranking_omits_the_noise(noisy: ScratchpadDB) -> None:
    ranked = noisy.top_templates(limit=10, order_by="count", exclude_noise=True)
    assert [t["template_id"] for t in ranked] == [2]


def test_unsuppressed_ranking_still_returns_everything(noisy: ScratchpadDB) -> None:
    ranked = noisy.top_templates(limit=10, order_by="count")
    assert {t["template_id"] for t in ranked} == {1, 2}


def test_slice_without_suppression_drowns_in_heartbeats(noisy: ScratchpadDB) -> None:
    """The needle-in-a-haystack failure stated as a test: max_lines spent on the loudest."""
    rows = noisy.get_slice(max_lines=10)
    assert {r["template_id"] for r in rows} == {1}


def test_slice_with_suppression_returns_the_signal(noisy: ScratchpadDB) -> None:
    rows = noisy.get_slice(max_lines=10, exclude_noise=True)
    assert {r["template_id"] for r in rows} == {2}


def test_explicit_template_slice_ignores_suppression(noisy: ScratchpadDB) -> None:
    """Asking for a template by id is a deliberate act; do not second-guess it."""
    rows = noisy.get_slice(template_id=1, max_lines=5, exclude_noise=True)
    assert len(rows) == 5


# --------------------------------------------------------------- citation existence


def test_known_template_ids_returns_only_those_present(noisy: ScratchpadDB) -> None:
    assert noisy.known_template_ids([1, 2, 999]) == {1, 2}


def test_known_template_ids_of_nothing_is_empty(noisy: ScratchpadDB) -> None:
    assert noisy.known_template_ids([]) == set()


# --------------------------------------------------------------- declared metric writers


def test_record_many_writes_a_batch(tmp_path: Path) -> None:
    """The shape a pipeline stage hands back: metrics returned, not written mid-computation."""
    with ScratchpadDB(tmp_path / "batch.sqlite") as db:
        written = db.record_many(
            [(INGEST_LINES_READ, 4946), (TEMPLATING_COMPRESSION_RATIO, 0.0018)]
        )
        view = MetricView(db.metrics())

    assert written == 2
    assert view.number(INGEST_LINES_READ) == 4946
    assert view.number(TEMPLATING_COMPRESSION_RATIO) == pytest.approx(0.0018)


def test_record_many_of_nothing_writes_nothing(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "empty.sqlite") as db:
        assert db.record_many([]) == 0
        assert db.metrics() == []


def test_record_many_replaces_like_record(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "twice.sqlite") as db:
        db.record(INGEST_LINES_READ, 10)
        db.record_many([(INGEST_LINES_READ, 20)])
        rows = db.metrics("ingest")

    assert len(rows) == 1
    assert rows[0]["value"] == "20"


def test_the_raw_writer_is_private() -> None:
    """The declared vocabulary is the way in, so a name cannot drift from its reader.

    `_record_metric` survives as an internal seam -- the upsert needs testing directly, and
    synthetic names have no declaration -- but it is not the public path.
    """
    assert not hasattr(ScratchpadDB, "record_metric")
    assert hasattr(ScratchpadDB, "_record_metric")

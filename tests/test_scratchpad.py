"""Scratchpad schema, migrations, evidence constraint, and read-only enforcement."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mistify.common.models import (
    LogRecord,
    NoiseThresholds,
    TemplateSummary,
    parse_timestamp,
)
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
            for row in db.run_readonly_sql("SELECT name FROM sqlite_master WHERE type='table'")
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
        rows = db.run_readonly_sql("SELECT version FROM schema_migrations")
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


def test_note_without_evidence_is_rejected_in_python(db: ScratchpadDB) -> None:
    with pytest.raises(ValueError, match="evidence is mandatory"):
        db.write_note(1, "unsupported claim", {}, "high")


@pytest.mark.parametrize("payload", ["", "[]", "{}", "null"])
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
    """This is a security boundary and the input is a model-authored string."""
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

#: The shipped definition of noise. Named here rather than defaulted in the query methods:
#: suppressing noise means saying what noise is, and the answer belongs to config.
DEFAULT_NOISE = NoiseThresholds(share=0.15, anomaly_ceiling=0.35)


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
    assert noisy.noise_template_ids(DEFAULT_NOISE) == {1}


def test_volume_alone_does_not_make_a_template_noise(noisy: ScratchpadDB) -> None:
    """A flood can be the incident, so the anomaly ceiling is part of the test."""
    assert noisy.noise_template_ids(NoiseThresholds(share=0.15, anomaly_ceiling=0.0)) == set()


def test_rare_severe_template_is_never_noise(noisy: ScratchpadDB) -> None:
    assert 2 not in noisy.noise_template_ids(DEFAULT_NOISE)


def test_suppressed_ranking_omits_the_noise(noisy: ScratchpadDB) -> None:
    ranked = noisy.top_templates(limit=10, order_by="count", noise=DEFAULT_NOISE)
    assert [t["template_id"] for t in ranked] == [2]


def test_unsuppressed_ranking_still_returns_everything(noisy: ScratchpadDB) -> None:
    ranked = noisy.top_templates(limit=10, order_by="count")
    assert {t["template_id"] for t in ranked} == {1, 2}


def test_slice_without_suppression_drowns_in_heartbeats(noisy: ScratchpadDB) -> None:
    """The needle-in-a-haystack failure stated as a test: max_lines spent on the loudest."""
    rows = noisy.get_slice(max_lines=10)
    assert {r["template_id"] for r in rows} == {1}


def test_slice_with_suppression_returns_the_signal(noisy: ScratchpadDB) -> None:
    rows = noisy.get_slice(max_lines=10, noise=DEFAULT_NOISE)
    assert {r["template_id"] for r in rows} == {2}


def test_explicit_template_slice_ignores_suppression(noisy: ScratchpadDB) -> None:
    """Asking for a template by id is a deliberate act; do not second-guess it."""
    rows = noisy.get_slice(template_id=1, max_lines=5, noise=DEFAULT_NOISE)
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


def test_suppression_requires_saying_what_noise_is(noisy: ScratchpadDB) -> None:
    """No thresholds means no suppression, rather than a threshold config never set.

    The query methods used to default to 0.15/0.35, duplicating `config.yaml`. A caller that
    asked to exclude noise without naming thresholds silently got numbers the configuration
    had no say over.
    """
    assert noisy.get_slice(max_lines=10) == noisy.get_slice(max_lines=10, noise=None)
    assert {r["template_id"] for r in noisy.get_slice(max_lines=10)} == {1}


def test_thresholds_come_from_config(noisy: ScratchpadDB) -> None:
    """The configured value is the one the scratchpad acts on."""
    from mistify.common.config import MistifyConfig

    assert noisy.noise_template_ids(MistifyConfig().anomaly.noise_thresholds()) == {1}


# ------------------------------------------- keeping, or not keeping, the verbatim line


def _event(raw: str, message: str) -> LogRecord:
    return LogRecord(
        ts=datetime(2026, 8, 30, 14, 0, tzinfo=UTC),
        source="svc",
        severity="ERROR",
        raw=raw,
        message=message,
        fields={"region": "ap-south-1"},
        format="json_lines",
    )


RAW_LINE = '{"timestamp": "2026-08-30T14:00:00Z", "level": "ERROR", "message": "pool exhausted"}'


def test_the_verbatim_line_is_kept_by_default(tmp_path: Path) -> None:
    with ScratchpadDB(tmp_path / "on.sqlite") as db:
        db.create_incident("i", source="x")
        db.bulk_insert_events([(_event(RAW_LINE, "pool exhausted"), 1)])
        row = db.get_slice(max_lines=1)[0]

    assert row["raw"] == RAW_LINE
    assert row["message"] == "pool exhausted"


def test_dropping_the_verbatim_line_still_leaves_a_reader_text(tmp_path: Path) -> None:
    """`raw` is 217 of 545 bytes per event on a JSON Lines scratchpad -- 40% of the file, and
    the same content as the parsed columns in a different shape. With it off a reader gets the
    message where they would have got the envelope, rather than getting nothing."""
    with ScratchpadDB(tmp_path / "off.sqlite", store_raw=False) as db:
        db.create_incident("i", source="x")
        db.bulk_insert_events([(_event(RAW_LINE, "pool exhausted"), 1)])
        row = db.get_slice(max_lines=1)[0]
        stored = db.run_readonly_sql("SELECT raw, message FROM log_events")[0]

    assert stored["raw"] is None, "the verbatim line should not be on disk"
    assert stored["message"] == "pool exhausted"
    # But no reader sees a NULL: both columns coalesce onto whichever one was kept.
    assert row["raw"] == "pool exhausted"
    assert row["message"] == "pool exhausted"


def test_an_unstructured_log_is_unaffected(tmp_path: Path) -> None:
    """The control, and the reason this setting is narrower than it sounds.

    When the message *is* the raw line the two columns were already deduplicated against each
    other, so turning `store_raw` off only changes which of them holds the text. Measured on
    400,000 BGL lines: 126.8 MB either way, a 0.0% saving, against 40.9% on JSON Lines.
    """
    line = "Dec 10 07:51:15 LabSZ sshd[24324]: Failed password"
    sizes = {}
    for store_raw in (True, False):
        path = tmp_path / f"{store_raw}.sqlite"
        with ScratchpadDB(path, store_raw=store_raw) as db:
            db.create_incident("i", source="x")
            db.bulk_insert_events([(_event(line, line), 1)] * 50)
            assert db.get_slice(max_lines=1)[0]["raw"] == line
        sizes[store_raw] = path.stat().st_size

    assert sizes[True] == sizes[False]


def test_marker_lookup_still_resolves_without_the_verbatim_line(tmp_path: Path) -> None:
    """The eval scorer resolves an expectation to a template by searching this text. It
    searched `raw` and `message` separately; with one of them NULL it has to coalesce or the
    scorer silently stops finding anything."""
    with ScratchpadDB(tmp_path / "off.sqlite", store_raw=False) as db:
        db.create_incident("i", source="x")
        db.bulk_insert_events([(_event(RAW_LINE, "pool exhausted"), 7)])
        assert db.templates_matching_text("pool exhausted") == {7}

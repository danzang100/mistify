"""SQLite access layer for the incident scratchpad.

Two connections are held per database. Writes go through a normal read-write connection
owned by the pipeline. Anything the investigator authors runs on a separate connection that
SQLite itself refuses to let write -- see `run_readonly_sql`.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from mistify.common.models import (
    LogRecord,
    ScratchpadNote,
    TemplateSummary,
)
from mistify.metrics import Metric

__all__ = ["MIGRATIONS", "ReadOnlyViolation", "ScratchpadDB"]

MIGRATIONS: tuple[str, ...] = ("0001_init",)

_EVENT_BATCH = 1000


class ReadOnlyViolation(RuntimeError):
    """Raised when a query submitted to the read-only channel attempts to change state."""


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class ScratchpadDB:
    """Working memory for one incident."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._readonly: sqlite3.Connection | None = None
        self.apply_migrations()

    # ---------------------------------------------------------------- lifecycle

    def apply_migrations(self) -> list[str]:
        """Apply any migrations not yet recorded. Idempotent."""
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        applied = {
            row["version"] for row in self._conn.execute("SELECT version FROM schema_migrations")
        }
        newly_applied: list[str] = []
        for version in MIGRATIONS:
            if version in applied:
                continue
            sql = (
                resources.files("mistify.scratchpad.migrations")
                .joinpath(f"{version}.sql")
                .read_text(encoding="utf-8")
            )
            self._conn.executescript(sql)
            self._conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (version, _now()),
            )
            newly_applied.append(version)
        self._conn.commit()
        return newly_applied

    def close(self) -> None:
        if self._readonly is not None:
            self._readonly.close()
            self._readonly = None
        self._conn.close()

    def __enter__(self) -> ScratchpadDB:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------------------------------------------------------------- writes

    def create_incident(
        self,
        incident_id: str,
        source: str,
        format_name: str | None = None,
        redaction_mode: str | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO incidents"
            " (incident_id, created_at, source, format, redaction_mode) VALUES (?, ?, ?, ?, ?)",
            (incident_id, _now(), source, format_name, redaction_mode),
        )
        self._conn.commit()

    def incident(self) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM incidents ORDER BY created_at LIMIT 1").fetchone()
        return dict(row) if row else None

    def bulk_insert_events(self, rows: Sequence[tuple[LogRecord, int]]) -> int:
        """Insert `(record, template_id)` pairs.

        Templates are written after events during ingestion, so foreign keys are left
        unenforced here; `orphan_event_count` asserts the same integrity explicitly once the
        load is complete.
        """
        payload = [
            (
                record.isoformat(),
                record.source,
                record.severity,
                template_id,
                record.raw,
                record.message,
                json.dumps(record.fields, default=str),
            )
            for record, template_id in rows
        ]
        inserted = 0
        for start in range(0, len(payload), _EVENT_BATCH):
            batch = payload[start : start + _EVENT_BATCH]
            self._conn.executemany(
                "INSERT INTO log_events"
                " (ts, source, severity, template_id, raw, message, fields_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                batch,
            )
            inserted += len(batch)
        self._conn.commit()
        return inserted

    def upsert_templates(self, summaries: Sequence[TemplateSummary]) -> int:
        self._conn.executemany(
            "INSERT INTO templates (template_id, pattern, occurrence_count, first_seen,"
            " last_seen, severity_mix_json, max_severity_rank, anomaly_score)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(template_id) DO UPDATE SET"
            " pattern=excluded.pattern, occurrence_count=excluded.occurrence_count,"
            " first_seen=excluded.first_seen, last_seen=excluded.last_seen,"
            " severity_mix_json=excluded.severity_mix_json,"
            " max_severity_rank=excluded.max_severity_rank",
            [
                (
                    s.template_id,
                    s.pattern,
                    s.occurrence_count,
                    s.first_seen,
                    s.last_seen,
                    json.dumps(s.severity_mix),
                    s.max_severity_rank,
                    s.anomaly_score,
                )
                for s in summaries
            ],
        )
        self._conn.commit()
        return len(summaries)

    def template_burst_stats(self, bucket_minutes: int = 1) -> list[dict[str, Any]]:
        """Per-template aggregates the anomaly scorer needs (decision G3).

        Buckets on an ISO minute prefix, which works because timestamps are normalised to
        UTC at ingestion -- a raw local-time string would bucket two services differently.
        """
        if bucket_minutes < 1:
            raise ValueError("bucket_minutes must be at least 1")
        bucket = self._bucket_expr(bucket_minutes)
        rows = self._conn.execute(
            "WITH per_bucket AS ("
            f"  SELECT template_id, {bucket} AS bucket, COUNT(*) AS n"
            "   FROM log_events GROUP BY template_id, bucket"
            "), burst AS ("
            "  SELECT template_id, MAX(n) AS max_per_bucket, COUNT(*) AS active_buckets"
            "   FROM per_bucket GROUP BY template_id"
            ")"
            " SELECT t.template_id, t.occurrence_count, t.max_severity_rank,"
            "        COALESCE(b.max_per_bucket, 0) AS max_per_bucket,"
            "        COALESCE(b.active_buckets, 0) AS active_buckets"
            " FROM templates t LEFT JOIN burst b ON b.template_id = t.template_id"
            " ORDER BY t.template_id"
        )
        return [dict(row) for row in rows]

    def bucket_count(self, bucket_minutes: int = 1) -> int:
        """Number of distinct time buckets the incident spans.

        Burstiness is measured against this, not against the buckets an individual template
        occupies -- see `scratchpad.anomaly`.
        """
        if bucket_minutes < 1:
            raise ValueError("bucket_minutes must be at least 1")
        row = self._conn.execute(
            f"SELECT COUNT(DISTINCT {self._bucket_expr(bucket_minutes)}) AS n FROM log_events"
        ).fetchone()
        return int(row["n"])

    @staticmethod
    def _bucket_expr(bucket_minutes: int) -> str:
        """SQL expression bucketing `ts` into `bucket_minutes`-wide slots.

        substr(ts, 1, 16) is "YYYY-MM-DDTHH:MM"; wider buckets divide the minute field.
        This works because timestamps are normalised to UTC at ingestion -- bucketing raw
        local-time strings would place two services in different slots for the same instant.
        """
        if bucket_minutes == 1:
            return "substr(ts, 1, 16)"
        return (
            "substr(ts, 1, 14) || "
            f"CAST(CAST(substr(ts, 15, 2) AS INTEGER) / {bucket_minutes} AS TEXT)"
        )

    def update_anomaly_scores(self, scores: Sequence[tuple[int, float]]) -> int:
        self._conn.executemany(
            "UPDATE templates SET anomaly_score = ? WHERE template_id = ?",
            [(score, template_id) for template_id, score in scores],
        )
        self._conn.commit()
        return len(scores)

    _METRIC_UPSERT = (
        "INSERT INTO run_metadata (stage, metric, value, value_num, ts)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(stage, metric) DO UPDATE SET"
        " value=excluded.value, value_num=excluded.value_num, ts=excluded.ts"
    )

    @staticmethod
    def _metric_row(
        stage: str, metric: str, value: object
    ) -> tuple[str, str, str, float | None, str]:
        numeric = float(value) if isinstance(value, (bool, int, float)) else None
        return (stage, metric, str(value), numeric, _now())

    def _record_metric(self, stage: str, metric: str, value: object) -> None:
        """Write one metric row by raw name.

        Private on purpose. The declared vocabulary in `mistify.metrics` is the way in, so a
        metric name cannot drift away from the reader that acts on it. Kept as its own
        mechanism rather than folded into `record` so the upsert can be exercised directly --
        the same justification as the tests that bypass `write_note` to prove the SQL CHECK.
        """
        self._conn.execute(self._METRIC_UPSERT, self._metric_row(stage, metric, value))
        self._conn.commit()

    def record(self, metric: Metric, value: object) -> None:
        """Record one declared health metric, replacing any prior value for the same key."""
        self._record_metric(metric.stage, metric.name, value)

    def record_many(self, entries: Iterable[tuple[Metric, object]]) -> int:
        """Record a batch of declared metrics in one transaction.

        This is the shape a pipeline stage hands back: stages return the metrics they
        produced rather than writing them mid-computation.
        """
        rows = [self._metric_row(m.stage, m.name, value) for m, value in entries]
        if rows:
            self._conn.executemany(self._METRIC_UPSERT, rows)
            self._conn.commit()
        return len(rows)

    def metrics(self, stage: str | None = None) -> list[dict[str, Any]]:
        if stage is None:
            rows = self._conn.execute(
                "SELECT stage, metric, value, value_num FROM run_metadata ORDER BY stage, metric"
            )
        else:
            rows = self._conn.execute(
                "SELECT stage, metric, value, value_num FROM run_metadata"
                " WHERE stage = ? ORDER BY metric",
                (stage,),
            )
        return [dict(row) for row in rows]

    def write_note(
        self,
        step: int,
        note: str,
        evidence: dict[str, Any],
        confidence: str,
    ) -> int:
        """Persist a hypothesis. Evidence is mandatory and enforced by the schema."""
        if not evidence:
            raise ValueError("supporting evidence is mandatory and cannot be empty")
        cursor = self._conn.execute(
            "INSERT INTO scratchpad_notes"
            " (step, note, supporting_evidence_json, confidence, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (step, note, json.dumps(evidence), confidence, _now()),
        )
        self._conn.commit()
        return int(cursor.lastrowid or 0)

    def notes(self) -> list[ScratchpadNote]:
        rows = self._conn.execute(
            "SELECT id, step, note, supporting_evidence_json, confidence, created_at"
            " FROM scratchpad_notes ORDER BY step, id"
        )
        return [
            ScratchpadNote(
                id=row["id"],
                step=row["step"],
                note=row["note"],
                evidence=json.loads(row["supporting_evidence_json"]),
                confidence=row["confidence"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def log_query(self, step: int, query: str, row_count: int) -> None:
        self._conn.execute(
            "INSERT INTO query_log (step, sql_query, row_count, ts) VALUES (?, ?, ?, ?)",
            (step, query, row_count, _now()),
        )
        self._conn.commit()

    def queries(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT step, sql_query, row_count, ts FROM query_log ORDER BY id"
        )
        return [dict(row) for row in rows]

    # ---------------------------------------------------------------- reads

    def event_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM log_events").fetchone()
        return int(row["n"])

    def template_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM templates").fetchone()
        return int(row["n"])

    def orphan_event_count(self) -> int:
        """Events whose template_id does not resolve. Should always be zero after a load."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM log_events e"
            " LEFT JOIN templates t ON t.template_id = e.template_id"
            " WHERE t.template_id IS NULL"
        ).fetchone()
        return int(row["n"])

    def time_bounds(self) -> tuple[str | None, str | None]:
        row = self._conn.execute(
            "SELECT MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM log_events"
        ).fetchone()
        return row["first_ts"], row["last_ts"]

    def known_template_ids(self, ids: Sequence[int]) -> set[int]:
        """Which of `ids` actually exist. Used to verify citations without loading the table."""
        if not ids:
            return set()
        placeholders = ", ".join("?" for _ in ids)
        rows = self._conn.execute(
            f"SELECT template_id FROM templates WHERE template_id IN ({placeholders})",
            list(ids),
        )
        return {int(row["template_id"]) for row in rows}

    def noise_template_ids(
        self, share_threshold: float = 0.15, anomaly_ceiling: float = 0.35
    ) -> set[int]:
        """Templates that are pure volume: a large share of the file, and unremarkable.

        Volume alone does not make a template noise -- a flood can be the incident, which is
        why the anomaly ceiling is part of the test. What this catches is the heartbeat case
        from architecture §6.4: a template big enough to crowd out everything else in a time
        slice while carrying no signal of its own.
        """
        total = self.event_count()
        if total <= 0:
            return set()
        rows = self._conn.execute(
            "SELECT template_id FROM templates"
            " WHERE anomaly_score < ? AND CAST(occurrence_count AS REAL) / ? >= ?",
            (anomaly_ceiling, float(total), share_threshold),
        )
        return {int(row["template_id"]) for row in rows}

    def top_templates(
        self,
        limit: int = 10,
        order_by: str = "count",
        exclude_noise: bool = False,
        noise_share: float = 0.15,
        noise_ceiling: float = 0.35,
    ) -> list[dict[str, Any]]:
        """Templates ranked by count, severity, recency, or anomaly score.

        `exclude_noise` drops high-volume, low-anomaly templates so a dominant heartbeat
        cannot crowd the ranked list the investigator reads top-down.
        """
        orderings = {
            "count": "occurrence_count DESC, max_severity_rank DESC",
            "severity": "max_severity_rank DESC, occurrence_count DESC",
            "recency": "last_seen DESC, occurrence_count DESC",
            "anomaly_score": "anomaly_score DESC, occurrence_count DESC",
        }
        if order_by not in orderings:
            raise ValueError(
                f"unknown ordering {order_by!r}. Valid: {', '.join(sorted(orderings))}"
            )

        where = ""
        params: list[Any] = []
        if exclude_noise:
            noisy = self.noise_template_ids(noise_share, noise_ceiling)
            if noisy:
                where = f" WHERE template_id NOT IN ({', '.join('?' for _ in noisy)})"
                params.extend(sorted(noisy))
        params.append(limit)

        rows = self._conn.execute(
            "SELECT template_id, pattern, occurrence_count, first_seen, last_seen,"
            f" severity_mix_json, max_severity_rank, anomaly_score FROM templates{where}"
            f" ORDER BY {orderings[order_by]}, template_id LIMIT ?",
            params,
        )
        result = []
        for row in rows:
            item = dict(row)
            item["severity_mix"] = json.loads(item.pop("severity_mix_json"))
            result.append(item)
        return result

    def get_slice(
        self,
        start_ts: str | None = None,
        end_ts: str | None = None,
        source: str | None = None,
        severity: str | None = None,
        template_id: int | None = None,
        max_lines: int = 200,
        exclude_noise: bool = False,
        noise_share: float = 0.15,
        noise_ceiling: float = 0.35,
    ) -> list[dict[str, Any]]:
        """Pull a bounded window of raw lines.

        `exclude_noise` matters most here. A time slice is exactly where a dominant heartbeat
        template drowns the lines worth reading: `max_lines` is spent on whatever is most
        numerous, which is rarely what the investigation is about.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if exclude_noise and template_id is None:
            noisy = self.noise_template_ids(noise_share, noise_ceiling)
            if noisy:
                clauses.append(f"template_id NOT IN ({', '.join('?' for _ in noisy)})")
                params.extend(sorted(noisy))
        if start_ts:
            clauses.append("ts >= ?")
            params.append(start_ts)
        if end_ts:
            clauses.append("ts <= ?")
            params.append(end_ts)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if template_id is not None:
            clauses.append("template_id = ?")
            params.append(template_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max_lines)
        rows = self._conn.execute(
            "SELECT id, ts, source, severity, template_id, raw, message"
            f" FROM log_events{where} ORDER BY ts, id LIMIT ?",
            params,
        )
        return [dict(row) for row in rows]

    def events_by_id(self, ids: Sequence[int]) -> list[dict[str, Any]]:
        if not ids:
            return []
        placeholders = ", ".join("?" for _ in ids)
        rows = self._conn.execute(
            "SELECT id, ts, source, severity, template_id, raw, message"
            f" FROM log_events WHERE id IN ({placeholders}) ORDER BY ts, id",
            list(ids),
        )
        return [dict(row) for row in rows]

    # ---------------------------------------------------------------- read-only channel

    def _readonly_conn(self) -> sqlite3.Connection:
        """Connection SQLite itself will not let write.

        The enforcement is layered and none of the layers is a keyword blocklist over the
        query text: a blocklist loses to comments, string literals and CTEs, and the input
        here is a model-authored string (decision G4).

        1.  Opened `mode=ro`, so the file is not writable at the OS level.
        2.  `PRAGMA query_only`, so the connection rejects mutations outright.
        3.  An authorizer callback allowing only SELECT, table/column reads and function
            calls -- which is what denies ATTACH, PRAGMA and extension loading.
        """
        if self._readonly is not None:
            return self._readonly

        self._conn.commit()
        conn = sqlite3.connect(f"file:{self.path.as_posix()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")

        allowed = {
            sqlite3.SQLITE_SELECT,
            sqlite3.SQLITE_READ,
            sqlite3.SQLITE_FUNCTION,
        }

        def authorizer(action: int, *_args: object) -> int:
            return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY

        conn.set_authorizer(authorizer)
        self._readonly = conn
        return conn

    def run_readonly_sql(self, query: str, max_rows: int = 500) -> list[dict[str, Any]]:
        """Run a read-only query against the scratchpad.

        Raises `ReadOnlyViolation` for anything that attempts to change state or reach
        outside the database.
        """
        conn = self._readonly_conn()
        try:
            cursor = conn.execute(query)
        except sqlite3.DatabaseError as exc:
            raise ReadOnlyViolation(str(exc)) from exc
        if cursor.description is None:
            raise ReadOnlyViolation("query returned no result set")
        return [dict(row) for row in cursor.fetchmany(max_rows)]

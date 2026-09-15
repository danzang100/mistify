"""SQLite access layer for the incident scratchpad.

Two connections are held per database. Writes go through a normal read-write connection
owned by the pipeline. Anything the investigator authors runs on a separate connection that
SQLite itself refuses to let write -- see `run_readonly_sql`.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from mistify.common.models import (
    SEVERITIES,
    UNKNOWN_SOURCE,
    LogRecord,
    NoiseThresholds,
    ScratchpadNote,
    TemplateSummary,
    parse_timestamp,
)
from mistify.metrics import Metric

__all__ = ["MIGRATIONS", "ReadOnlyViolation", "ScratchpadDB"]

MIGRATIONS: tuple[str, ...] = (
    "0001_init",
    "0002_adversarial",
    "0003_objection_ids",
    "0004_trace_id",
    "0005_event_indexes",
)

#: A template active for at least this share of the log's own span is chronic rather than part
#: of the event. Defined here because both the report and the adversarial check need the same
#: answer, and a threshold with two definitions drifts.
CHRONIC_SHARE = 0.9

#: Field names a trace id arrives under. Vendors disagree and the adapter does not normalise
#: them, so the first one present wins rather than the ingest guessing a canonical name.
_TRACE_FIELDS: tuple[str, ...] = ("trace_id", "traceId", "traceID", "trace-id", "dd.trace_id")


def _trace_id(fields: dict[str, Any] | None) -> str | None:
    """The record's trace id, or None when it carries no usable one.

    None rather than "": absent and empty are different, and grouping on "" would collapse
    every untraced line in the file into one imaginary request.
    """
    for name in _TRACE_FIELDS:
        value = (fields or {}).get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
    return None


_EVENT_BATCH = 1000


class ReadOnlyViolation(RuntimeError):
    """Raised when a query submitted to the read-only channel attempts to change state."""


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


#: Terminal colour and cursor sequences. Log content as far as a file is concerned, and noise
#: as far as anything reading it is concerned -- including a model, which pays tokens for them.
_ANSI = re.compile("\x1b\\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def _like_escape(text: str) -> str:
    """Escape the wildcards SQLite's LIKE treats as syntax.

    A marker is arbitrary log text and routinely contains `_`, which LIKE reads as "any single
    character". Left unescaped, `test_indexing.py` would also match `testXindexing.py` -- a
    quiet widening of every text lookup rather than an error.
    """
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class ScratchpadDB:
    """Working memory for one incident."""

    def __init__(self, path: str | Path, store_raw: bool = True):
        #: Whether the verbatim source line is kept beside the parsed message. Off trades the
        #: audit trail for roughly 40% of the file -- see `ScratchpadConfig.store_raw`. Held
        #: here rather than passed per call so no write path can disagree with another.
        self.store_raw = store_raw
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        # Before any table exists, because SQLite can only change page size on an empty
        # database. Log rows are long -- a JSON Lines event averages 545 bytes across its
        # columns -- so the 4 KB default wastes a slot's worth of page per row. Measured on
        # 196,046 events: 109.7 MB at 4 KB against 106.3 MB at 16 KB, and marginally faster.
        # Nothing about the data changes; only how it is packed.
        self._conn.execute("PRAGMA page_size=16384")
        self._conn.execute("PRAGMA journal_mode=WAL")
        # No `cache_size` here, and that is a measured decision rather than an oversight.
        # SQLite's 2 MB default is 125 pages at the 16 KB page above, while an ingest maintains
        # four B-trees on a table growing into the gigabytes -- which looks exactly like the
        # cause of the slowdown a large ingest hits. It is not. Measured on Thunderbird at
        # 2 MB, 64 MB and 256 MB:
        #
        #       lines   cache      lines/s
        #     500,000     2 MB       7,444
        #     500,000    64 MB       7,059
        #     500,000   256 MB       7,510
        #   2,000,000     2 MB       4,347
        #   2,000,000    64 MB       4,294
        #   2,000,000   256 MB       4,350
        #
        # Within noise at both sizes, and the gap does not widen with scale -- which it would
        # have to if cache were the constraint. The slowdown between 500k and 2M is real and
        # is somewhere else: Drain3's per-line cost grows with the clusters it holds.
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

    def rename_incident(self, incident_id: str) -> None:
        """Retag this scratchpad as belonging to `incident_id`.

        The eval harness ingests once per case and copies the scratchpad per run, so every
        copy arrives carrying the master's identity and every report rendered from one named
        the wrong run. A report that misidentifies itself is the kind of thing that gets
        trusted and then quietly misfiles a result.
        """
        self._conn.execute("UPDATE incidents SET incident_id = ?", (incident_id,))
        self._conn.commit()

    def bulk_insert_events(self, rows: Sequence[tuple[LogRecord, int]]) -> int:
        """Insert `(record, template_id)` pairs.

        Templates are written after events during ingestion, so foreign keys are left
        unenforced here; `orphan_event_count` asserts the same integrity explicitly once the
        load is complete.
        """
        payload = [
            (
                record.isoformat(),
                # `unknown` is what an adapter reports when the format names no emitter, and on
                # a raw-lines read that is every single row -- seven bytes of the same word,
                # once per event, plus its length header. Stored as NULL and read back with
                # COALESCE, the same trade already made between `raw` and `message`. Measured on
                # 500,000 Thunderbird events: 7.6 bytes an event, 2.6% of the scratchpad.
                None if record.source == UNKNOWN_SOURCE else record.source,
                record.severity,
                template_id,
                # The two text columns are deduplicated against each other in whichever
                # direction is available, and read back with COALESCE either way, so a reader
                # always gets text and never has to know which one was kept.
                #
                # With `store_raw` on, `message` is dropped when it *is* the raw line: on an
                # unstructured log the two are the same string, and storing both wrote every
                # line to disk twice -- measured on Loghub-2.0 BGL, 139.3 MB each out of a
                # 455 MB scratchpad, half of it a verbatim copy of the other half.
                #
                # With it off, `raw` goes instead and `message` is always written. It has to
                # be: dropping both would leave a row carrying no text at all.
                record.raw if self.store_raw else None,
                record.message if (not self.store_raw or record.message != record.raw) else None,
                json.dumps(record.fields, default=str),
                _trace_id(record.fields),
            )
            for record, template_id in rows
        ]
        inserted = 0
        for start in range(0, len(payload), _EVENT_BATCH):
            batch = payload[start : start + _EVENT_BATCH]
            self._conn.executemany(
                "INSERT INTO log_events"
                " (ts, source, severity, template_id, raw, message, fields_json, trace_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
        """Per-template aggregates the anomaly scorer needs, and their patterns.

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
            # `pattern` is here for the anomaly scorer's benefit: on a source with no severity
            # field the term is recovered from the template's own text rather than dropped,
            # and the text is the only place left to read it from.
            " SELECT t.template_id, t.pattern, t.occurrence_count, t.max_severity_rank,"
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

    def clear_investigation(self) -> dict[str, int]:
        """Delete everything a previous investigation wrote, leaving the ingest untouched.

        For `investigate --restart`. Notes, the queries behind them and the critique all belong
        to one attempt; leaving any of them for the next attempt to inherit is how a run comes
        to be scored against findings it did not write. The harness already avoids this by
        copying a fresh scratchpad per run -- this is the same guarantee for the CLI path.

        Metrics are left alone: they are upserted by key, so the next run overwrites its own.
        """
        counts = {}
        for table in (
            "scratchpad_notes",
            "query_log",
            "adversarial_objections",
            "adversarial_summary",
        ):
            cursor = self._conn.execute(f"DELETE FROM {table}")
            counts[table] = cursor.rowcount if cursor.rowcount > 0 else 0
        self._conn.commit()
        return counts

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

    # ------------------------------------------------- the adversarial pass

    def save_adversarial(
        self,
        outcome: str,
        assessment: str = "",
        alternative: str = "",
        revised_confidence: str = "",
        objections: Sequence[dict[str, Any]] = (),
    ) -> None:
        """Persist what the critique said, not just how much of it there was.

        Replaces any previous result for this incident: the check is re-runnable, and two
        overlapping critiques in one report would read as one critique that contradicted
        itself.
        """
        now = _now()
        self._conn.execute("DELETE FROM adversarial_objections")
        self._conn.execute("DELETE FROM adversarial_summary")
        self._conn.execute(
            "INSERT INTO adversarial_summary"
            " (id, assessment, alternative, revised_confidence, outcome, created_at)"
            " VALUES (1, ?, ?, ?, ?, ?)",
            (assessment, alternative, revised_confidence, outcome, now),
        )
        self._conn.executemany(
            "INSERT INTO adversarial_objections"
            " (objection_id, claim, objection, severity, template_ids_json, log_event_ids_json,"
            "  response, conceded, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    str(o.get("objection_id", "")),
                    str(o.get("claim", "")),
                    str(o.get("objection", "")),
                    str(o.get("severity", "medium")),
                    json.dumps([int(i) for i in o.get("template_ids", [])]),
                    json.dumps([int(i) for i in o.get("log_event_ids", [])]),
                    o.get("response"),
                    None if o.get("conceded") is None else int(bool(o.get("conceded"))),
                    now,
                )
                for o in objections
            ],
        )
        self._conn.commit()

    def adversarial_summary(self) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM adversarial_summary WHERE id = 1").fetchone()
        return None if row is None else dict(row)

    def adversarial_objections(self) -> list[dict[str, Any]]:
        """Objections in the order raised, with their citations decoded."""
        rows = self._conn.execute("SELECT * FROM adversarial_objections ORDER BY id")
        objections = []
        for row in rows:
            item = dict(row)
            item["template_ids"] = json.loads(item.pop("template_ids_json"))
            item["log_event_ids"] = json.loads(item.pop("log_event_ids_json"))
            item["conceded"] = None if item["conceded"] is None else bool(item["conceded"])
            objections.append(item)
        return objections

    # ------------------------------------------------- deterministic summaries

    def chronic_template_ids(self, share: float = CHRONIC_SHARE) -> set[int]:
        """Templates active across essentially the whole log.

        A template that was firing before the incident began and kept firing after it ended is
        background, not event. Two readers need this answer -- the report, to label an issue,
        and the adversarial check, to avoid faulting an investigation for not explaining
        something that was never part of the incident -- so it is defined here once rather
        than in both. That mistake has already been made in this codebase with the noise
        thresholds.
        """
        first_ts, last_ts = self.time_bounds()
        if not first_ts or not last_ts:
            return set()
        span = (parse_timestamp(last_ts) - parse_timestamp(first_ts)).total_seconds()
        if span <= 0:
            return set()

        rows = self._conn.execute(
            "SELECT template_id, first_seen, last_seen FROM templates"
            " WHERE first_seen IS NOT NULL AND last_seen IS NOT NULL"
        )
        chronic = set()
        for row in rows:
            active = (
                parse_timestamp(row["last_seen"]) - parse_timestamp(row["first_seen"])
            ).total_seconds()
            if active >= span * share:
                chronic.add(int(row["template_id"]))
        return chronic

    def severity_counts(self) -> dict[str, int]:
        """Events per severity. The shape of the file, computed rather than described."""
        rows = self._conn.execute(
            "SELECT severity, COUNT(*) AS n FROM log_events GROUP BY severity"
        )
        return {str(row["severity"]): int(row["n"]) for row in rows}

    def source_activity(self, min_severity: str = "ERROR") -> list[dict[str, Any]]:
        """Per source: total events, how many at or above `min_severity`, and when.

        The blast-radius question asked of the data rather than of the model. Ordered by bad
        events first, because that is the order someone reading at speed needs them in.
        """
        wanted = min_severity.upper()
        # Everything at or above the floor, in the project's own severity order rather than
        # alphabetically -- "ERROR" < "WARN" as strings, which is the opposite of the truth.
        bad = list(SEVERITIES[SEVERITIES.index(wanted) :]) if wanted in SEVERITIES else []
        placeholders = ",".join("?" for _ in bad) or "NULL"
        rows = self._conn.execute(
            f"""SELECT COALESCE(source, '{UNKNOWN_SOURCE}') AS source,
                       COUNT(*) AS events,
                       SUM(CASE WHEN severity IN ({placeholders}) THEN 1 ELSE 0 END) AS bad_events,
                       MIN(CASE WHEN severity IN ({placeholders}) THEN ts END) AS first_bad,
                       MAX(CASE WHEN severity IN ({placeholders}) THEN ts END) AS last_bad
                FROM log_events
                GROUP BY COALESCE(source, '{UNKNOWN_SOURCE}')
                ORDER BY bad_events DESC, events DESC""",
            bad * 3,
        )
        return [dict(row) for row in rows]

    def template_window(self, template_ids: Sequence[int]) -> tuple[str | None, str | None]:
        """First and last event across the given templates.

        This is what an incident window actually is: when the templates that were flagged as
        signal were active. `time_bounds` answers a different question -- when the *file*
        starts and ends -- and using it as the incident window overstates the duration by
        however much quiet log surrounds the event.
        """
        if not template_ids:
            return (None, None)
        placeholders = ",".join("?" for _ in template_ids)
        row = self._conn.execute(
            f"SELECT MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM log_events"
            f" WHERE template_id IN ({placeholders})",
            [int(i) for i in template_ids],
        ).fetchone()
        return (row["first_ts"], row["last_ts"])

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

    def templates_matching_text(self, text: str, limit: int = 5000) -> set[int]:
        """Templates having at least one event whose message or raw line contains `text`.

        For resolving an expectation expressed as a line of log text to the templates a
        citation could name it through. A pattern search finds only the *constant* part of a
        line, and an external corpus's evidence is frequently the varying part -- a failing
        test's path, a stack location -- which clustering has already replaced with a wildcard.

        Parameterised and on the internal connection, deliberately not through
        `run_readonly_sql`: that is the model-facing channel and widening its
        signature to take parameters for the benefit of trusted internal callers would loosen
        a security boundary for a convenience that belongs on this side of it.
        """
        rows = self._conn.execute(
            "SELECT DISTINCT template_id FROM log_events "
            "WHERE COALESCE(message, raw) LIKE ? ESCAPE '\\' "
            "OR COALESCE(raw, message) LIKE ? ESCAPE '\\' LIMIT ?",
            (f"%{_like_escape(text)}%", f"%{_like_escape(text)}%", limit),
        )
        return {int(row["template_id"]) for row in rows if row["template_id"] is not None}

    def matching_events(self, text: str, limit: int = 20000) -> tuple[set[int], int]:
        """Templates whose events carry `text`, and how many events do.

        Both numbers, because they answer different questions and only one of them is about
        how *identifying* the text is. A marker that lands in many templates may be common --
        or it may be rare and fragmented, which is what happens on a log that barely clusters:
        `tests/fail/macros_type_mismatch.rs` occurred in 35 of 3,154 events yet spread across
        more than ten templates, because at 498 templates for 3,154 lines almost every distinct
        line shape is its own cluster. Counting templates called that indistinct; counting
        events calls it 1.1% of the file, which is what it is.

        Falls back to an ANSI-insensitive scan when the direct match finds nothing. CI logs are
        written for a terminal: 71.9% of the lines in one real GitHub Actions log carry escape
        sequences, so `tests-build::macros compile_fail_full` is stored as
        `\\x1b[35;1mtests-build::macros\\x1b[0m \\x1b[34;1mcompile_fail_full\\x1b[0m` and no
        literal search can find it. The fallback is a table scan and runs only when the cheap
        lookup has already failed.
        """
        pattern = f"%{_like_escape(text)}%"
        rows = self._conn.execute(
            "SELECT template_id FROM log_events "
            "WHERE COALESCE(message, raw) LIKE ? ESCAPE '\\' "
            "OR COALESCE(raw, message) LIKE ? ESCAPE '\\' LIMIT ?",
            (pattern, pattern, limit),
        ).fetchall()
        if not rows:
            rows = [
                row
                for row in self._conn.execute(
                    "SELECT template_id, COALESCE(message, raw) AS text FROM log_events LIMIT ?",
                    (limit,),
                )
                if text in _strip_ansi(str(row["text"] or ""))
            ]
        templates = {int(r["template_id"]) for r in rows if r["template_id"] is not None}
        return templates, len(rows)

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

    def noise_template_ids(self, thresholds: NoiseThresholds) -> set[int]:
        """Templates that are pure volume: a large share of the file, and unremarkable.

        Volume alone does not make a template noise -- a flood can be the incident, which is
        why the anomaly ceiling is part of the test. What this catches is the heartbeat case
        is a known one: a template big enough to crowd out everything else in a time
        slice while carrying no signal of its own.
        """
        total = self.event_count()
        if total <= 0:
            return set()
        rows = self._conn.execute(
            "SELECT template_id FROM templates"
            " WHERE anomaly_score < ? AND CAST(occurrence_count AS REAL) / ? >= ?",
            (thresholds.anomaly_ceiling, float(total), thresholds.share),
        )
        return {int(row["template_id"]) for row in rows}

    def top_templates(
        self,
        limit: int = 10,
        order_by: str = "count",
        noise: NoiseThresholds | None = None,
    ) -> list[dict[str, Any]]:
        """Templates ranked by count, severity, recency, or anomaly score.

        Passing `noise` drops high-volume, low-anomaly templates so a dominant heartbeat
        cannot crowd the ranked list the investigator reads top-down. There is no default:
        suppressing noise means saying what counts as noise, and the answer lives in config.
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
        if noise is not None:
            noisy = self.noise_template_ids(noise)
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
        noise: NoiseThresholds | None = None,
        trace_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Pull a bounded window of raw lines.

        Passing `noise` matters most here. A time slice is exactly where a dominant heartbeat
        template drowns the lines worth reading: `max_lines` is spent on whatever is most
        numerous, which is rarely what the investigation is about. Asking for a specific
        `template_id` overrides it -- that is a deliberate request, not a default.
        """
        where, params = self._slice_clauses(
            start_ts, end_ts, source, severity, template_id, noise, trace_id
        )
        rows = self._conn.execute(
            "SELECT id, ts, COALESCE(source, '" + UNKNOWN_SOURCE + "') AS source,"
            " severity, template_id, trace_id,"
            # NULL on either column means "the other one holds it" -- see the note in
            # `bulk_insert_events`. Every reader gets text and none needs to know which
            # column it landed in, or whether this run kept the verbatim line at all.
            " COALESCE(raw, message) AS raw, COALESCE(message, raw) AS message"
            f" FROM log_events{where} ORDER BY ts, id LIMIT ?",
            [*params, max_lines],
        )
        return [dict(row) for row in rows]

    def slice_match_count(
        self,
        start_ts: str | None = None,
        end_ts: str | None = None,
        source: str | None = None,
        severity: str | None = None,
        template_id: int | None = None,
        noise: NoiseThresholds | None = None,
        trace_id: str | None = None,
    ) -> int:
        """How many lines the same filters match, before `max_lines` truncates them.

        Without this the investigator learns only that it hit the cap, not whether it withheld
        four lines or forty thousand -- which is the difference between "look at the rest" and
        "narrow the window". Same clauses as `get_slice` by construction, so the two cannot
        drift into answering about different sets of rows.
        """
        where, params = self._slice_clauses(
            start_ts, end_ts, source, severity, template_id, noise, trace_id
        )
        row = self._conn.execute(f"SELECT COUNT(*) AS n FROM log_events{where}", params).fetchone()
        return int(row["n"])

    def _slice_clauses(
        self,
        start_ts: str | None,
        end_ts: str | None,
        source: str | None,
        severity: str | None,
        template_id: int | None,
        noise: NoiseThresholds | None,
        trace_id: str | None = None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if noise is not None and template_id is None:
            noisy = self.noise_template_ids(noise)
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
        if trace_id:
            clauses.append("trace_id = ?")
            params.append(trace_id)
        return (f" WHERE {' AND '.join(clauses)}" if clauses else "", params)

    def events_by_id(self, ids: Sequence[int]) -> list[dict[str, Any]]:
        if not ids:
            return []
        placeholders = ", ".join("?" for _ in ids)
        rows = self._conn.execute(
            "SELECT id, ts, COALESCE(source, '" + UNKNOWN_SOURCE + "') AS source,"
            " severity, template_id, trace_id,"
            # NULL on either column means "the other one holds it" -- see the note in
            # `bulk_insert_events`. Every reader gets text and none needs to know which
            # column it landed in, or whether this run kept the verbatim line at all.
            " COALESCE(raw, message) AS raw, COALESCE(message, raw) AS message"
            f" FROM log_events WHERE id IN ({placeholders}) ORDER BY ts, id",
            list(ids),
        )
        return [dict(row) for row in rows]

    # ---------------------------------------------------------------- read-only channel

    def _readonly_conn(self) -> sqlite3.Connection:
        """Connection SQLite itself will not let write.

        The enforcement is layered and none of the layers is a keyword blocklist over the
        query text: a blocklist loses to comments, string literals and CTEs, and the input
        here is a model-authored string.

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

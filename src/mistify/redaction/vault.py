"""Opt-in reversible mapping from redaction placeholder back to the original value.

Redaction is one-way by construction: `[EMAIL:a7f2]` is a truncated blake2s digest of the
value, so nothing can reconstruct the address after the fact. That is the right default, but
it leaves the operator unable to act on their own incident -- "which account is
`[EMAIL:a7f2]`?" is the question that turns a finding into a remediation. The vault answers
it by recording the mapping *as the redaction happens*, which is the only moment both halves
exist. It is off by default (`redaction.vault`), because a plaintext mapping on disk gives
back some of what redaction bought.

The vault lives in its own SQLite file and must never become a table in the incident
scratchpad. The investigator's `run_readonly_sql` channel executes model-authored SQL against
whatever database it is pointed at, and its authorizer allows reads of *any* table in that
database -- a `vault` table sitting there would be one `SELECT` away from handing the model
every value redaction just removed, defeating decisions G1 and G2 entirely. Keeping the
mapping in a separate file is a real boundary rather than a naming convention: the same
authorizer denies `ATTACH`, so a query on the scratchpad connection cannot reach across to
the vault file even if it knows the path.

Token collisions are possible and deliberately not resolved here. The placeholder carries
four hex characters, so two distinct values can share a token; when that happens the log
itself has already conflated them, and the vault reports the first value recorded under that
token rather than inventing a distinction the redacted log does not have.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

__all__ = ["MIGRATIONS", "RedactionVault"]

#: Applied in order and recorded in `schema_migrations`, mirroring the scratchpad. The SQL is
#: inline rather than a resource file because the vault is a single table with no foreseeable
#: schema churn -- a migrations package for one statement is ceremony, not safety.
MIGRATIONS: tuple[tuple[str, str], ...] = (
    (
        "0001_init",
        """
        CREATE TABLE IF NOT EXISTS vault (
            token      TEXT PRIMARY KEY,
            entity     TEXT NOT NULL,
            value      TEXT NOT NULL,
            first_seen TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_vault_entity ON vault (entity);
        """,
    ),
)

#: Records buffered before a commit. Redaction calls `record()` once per match -- committing
#: each one would put an fsync in the inner loop of ingestion. Reads flush first, and so do
#: `close()` and `__exit__`, so nothing observable depends on the buffering.
_COMMIT_INTERVAL = 500


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class RedactionVault:
    """Token-to-value store for one incident, in its own database file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._pending = 0
        self.apply_migrations()

    # ---------------------------------------------------------------- lifecycle

    def apply_migrations(self) -> list[str]:
        """Apply any migrations not yet recorded. Idempotent."""
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        applied = {
            str(row["version"])
            for row in self._conn.execute("SELECT version FROM schema_migrations")
        }
        newly_applied: list[str] = []
        for version, sql in MIGRATIONS:
            if version in applied:
                continue
            self._conn.executescript(sql)
            self._conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (version, _now()),
            )
            newly_applied.append(version)
        self._conn.commit()
        return newly_applied

    def flush(self) -> None:
        """Commit any buffered records. A no-op when nothing is pending."""
        if self._pending:
            self._conn.commit()
            self._pending = 0

    def close(self) -> None:
        self.flush()
        self._conn.close()

    def __enter__(self) -> RedactionVault:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------------------------------------------------------------- writes

    def record(self, token: str, entity: str, value: str) -> None:
        """Store `token -> value`, ignoring a token already present.

        Idempotent because the caller is the redactor, which sees the same value on every
        line it appears in. `INSERT OR IGNORE` also keeps `first_seen` meaning what it says:
        the first time the run encountered the value, not the last.
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO vault (token, entity, value, first_seen) VALUES (?, ?, ?, ?)",
            (token, entity, value, _now()),
        )
        self._pending += 1
        if self._pending >= _COMMIT_INTERVAL:
            self.flush()

    # ---------------------------------------------------------------- reads

    def reveal(self, token: str) -> str | None:
        """Return the original value behind `token`, or None if it was never recorded."""
        self.flush()
        row = self._conn.execute("SELECT value FROM vault WHERE token = ?", (token,)).fetchone()
        return str(row["value"]) if row is not None else None

    def entries(self, entity: str | None = None) -> list[dict[str, str]]:
        """Every stored mapping, optionally narrowed to one entity kind.

        Ordered by entity then token so a dump is stable across runs -- an operator diffing
        two reveals should see content changes, not row-order churn.
        """
        self.flush()
        if entity is None:
            rows = self._conn.execute(
                "SELECT token, entity, value, first_seen FROM vault ORDER BY entity, token"
            )
        else:
            rows = self._conn.execute(
                "SELECT token, entity, value, first_seen FROM vault"
                " WHERE entity = ? ORDER BY token",
                (entity,),
            )
        return [
            {
                "token": str(row["token"]),
                "entity": str(row["entity"]),
                "value": str(row["value"]),
                "first_seen": str(row["first_seen"]),
            }
            for row in rows
        ]

    def count(self) -> int:
        self.flush()
        row = self._conn.execute("SELECT COUNT(*) AS n FROM vault").fetchone()
        return int(row["n"])

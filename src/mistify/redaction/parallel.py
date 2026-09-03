"""Redacting a batch of records across processes.

Redaction is the most expensive stage in ingestion and the only one that is embarrassingly
parallel: it is a pure function of one record, holding no state but a tally. Profiling a
400,000-line Loghub-2.0 BGL ingest put it at roughly 35% of the run -- 8.9 seconds of regex
against 25 seconds total -- and nothing about the regex work itself can be made cheaper.

Three cheaper things were tried against that profile and all three were measured and rejected,
which is why this module exists rather than a tuning patch:

* **More Drain3 masking** to collapse cardinality: 9,304 clusters became 9,099, no speed change.
* **A deeper prefix tree** (depth 4 to 12): 601 lines/s became 671.
* **A combined detector regex** run before the five per-entity passes, to skip lines holding
  nothing: *slower*. 0.96x on BGL where 0.0% of lines match, and 0.61x on OpenSSH where 86.7%
  do. One alternation of five complex patterns costs about what the five separate scans cost,
  so the pre-filter is pure overhead whichever way the data falls.

Processes rather than threads, because the work is CPU-bound Python and the GIL makes threads
pointless here. Windows spawns rather than forks, so each worker re-imports and every batch is
pickled across a boundary -- measured, that transport is comfortably paid for above a few
thousand records per chunk:

    serial (1 core)      10.93s     36,581 lines/s
    2 workers             4.87s     82,119 lines/s   2.24x
    4 workers             2.63s    152,275 lines/s   4.16x
    8 workers             1.90s    210,087 lines/s   5.74x

Output was byte-identical to serial in every configuration, which it must be: tokens are
salted hashes of the value, so they do not depend on which process computed them or on the
order lines were seen in.

**The vault is not supported here.** It writes each replaced value to its own SQLite file, and
a worker cannot share that handle. Rather than teach workers to ship their mappings back --
more moving parts in the one place where a mistake means an unredacted value on disk -- a run
with the vault enabled redacts serially and says so. The vault is opt-in and off by default.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass

from mistify.common.models import LogRecord
from mistify.redaction.redactor import Redactor

__all__ = ["RedactionPool", "resolve_workers"]

#: Below this many records a chunk is not worth a round trip through a pipe. Chunks are formed
#: by the caller; this is the floor under which it should not bother asking for workers at all.
MIN_PARALLEL_RECORDS = 2_000

_WORKER: Redactor | None = None


@dataclass(frozen=True, slots=True)
class _Settings:
    """Everything a worker needs to build an identical redactor.

    The `Redactor` itself is not sent. It holds compiled patterns and possibly a vault handle,
    and rebuilding it from its settings in each worker is both cheaper to pickle and impossible
    to get subtly wrong -- a worker cannot end up with a *different* configuration than the
    parent, because it is handed the configuration rather than an object graph.
    """

    mode: str
    entities: tuple[str, ...]
    salt: str


def _init(settings: _Settings) -> None:
    global _WORKER
    _WORKER = Redactor(
        mode=settings.mode, entities=list(settings.entities), salt=settings.salt, vault=None
    )


def _redact_chunk(records: list[LogRecord]) -> tuple[list[LogRecord], dict[str, int]]:
    """Redact one chunk and report what it replaced.

    The counts travel back with the records because they are a health metric the run reports,
    and a tally kept only inside a worker would be discarded when the worker exits -- leaving
    the report claiming that nothing was redacted.
    """
    assert _WORKER is not None, "worker redactor was never initialised"
    _WORKER.reset_counts()
    redacted = [_WORKER.redact_record(record) for record in records]
    return redacted, dict(_WORKER.counts)


def resolve_workers(configured: int) -> int:
    """How many worker processes to actually use.

    `0` means "decide for me" and resolves to the machine's CPU count, capped: past about eight
    the measured curve flattens while the number of Python interpreters, and their memory, keeps
    growing. Anything below 2 means serial, which is a real answer rather than a degenerate one.
    """
    if configured == 0:
        return min(os.cpu_count() or 1, 8)
    return max(configured, 1)


class RedactionPool:
    """A process pool for redaction, or a serial fallback wearing the same interface.

    One object either way, so the pipeline has a single code path. A pool that decided to be
    serial is not an error and not a special case -- it is the common one, since the default is
    a single worker and the vault forces it.
    """

    def __init__(self, redactor: Redactor, workers: int) -> None:
        self._redactor = redactor
        self._pool: ProcessPoolExecutor | None = None
        self.workers = 1
        self.reason = "serial"

        if not redactor.enabled:
            self.reason = "redaction disabled"
            return
        if redactor.vault is not None:
            # Stated rather than silently ignored: asking for eight workers and getting one is
            # something the person who set the number should be able to find out about.
            self.reason = "serial: the vault cannot be written from worker processes"
            return

        resolved = resolve_workers(workers)
        if resolved < 2:
            return
        self._pool = ProcessPoolExecutor(
            max_workers=resolved,
            initializer=_init,
            initargs=(
                _Settings(
                    mode=redactor.mode,
                    entities=tuple(redactor.entities),
                    salt=redactor.salt,
                ),
            ),
        )
        self.workers = resolved
        self.reason = f"{resolved} worker processes"

    def _serial(self, records: Sequence[LogRecord]) -> list[LogRecord]:
        return [self._redactor.redact_record(record) for record in records]

    def redact(self, records: Sequence[LogRecord]) -> list[LogRecord]:
        """Redact a chunk, in this process or across the pool.

        A pool that cannot run falls back to redacting here, and the run continues. Workers are
        a throughput optimisation and nothing else: refusing to ingest a file because eight
        interpreters could not be started would trade the whole result for the speed of getting
        it, and redaction is the one stage that must not be skippable.

        The case is not hypothetical. On Windows a worker re-imports `__main__`, so a caller
        that drives `ingest()` from a script without an `if __name__ == "__main__"` guard --
        or from a REPL, where `__main__` is not a file at all -- gets `BrokenProcessPool` on
        the first chunk. That is the caller's environment being unable to spawn, not their log
        being unreadable.
        """
        if self._pool is None or len(records) < MIN_PARALLEL_RECORDS:
            return self._serial(records)

        # One slice per worker, so the pipe is crossed as few times as the work allows.
        size = max(len(records) // self.workers, 1)
        slices = [list(records[i : i + size]) for i in range(0, len(records), size)]
        out: list[LogRecord] = []
        # Everything counted before this chunk. Restored on failure, because the retry below
        # recounts this chunk from scratch and any slice that finished before the pool broke
        # has already been merged -- without this the metric would double-count them.
        # `reset_counts()` alone would be worse still: it would discard every earlier chunk too.
        before = dict(self._redactor.counts)
        try:
            for redacted, counts in self._pool.map(_redact_chunk, slices):
                out.extend(redacted)
                self._redactor.merge_counts(counts)
        except BrokenProcessPool:
            self.close()
            self.workers = 1
            self.reason = "serial: worker processes could not be started"
            self._redactor.reset_counts()
            self._redactor.merge_counts(before)
            return self._serial(records)
        return out

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=True)
            self._pool = None

    def __enter__(self) -> RedactionPool:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

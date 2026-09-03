"""Redaction across worker processes.

The property that matters is not speed, it is that speed changed nothing. Tokens are salted
hashes of the value, so a record redacted in a worker must come back byte-identical to one
redacted here, and the per-entity counts must add up to the same totals -- they are health
metrics the report acts on, and a tally left behind in an exiting worker would read as "nothing
was redacted".

`test_parallel_output_is_identical_to_serial` asserts the pool really used workers before
comparing. Without that it would pass just as happily against the serial fallback, which is the
one way this test could look green while measuring nothing.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

from mistify.common.models import LogRecord
from mistify.redaction.parallel import MIN_PARALLEL_RECORDS, RedactionPool, resolve_workers
from mistify.redaction.redactor import Redactor
from mistify.redaction.vault import RedactionVault

ENTITIES = ["api_key", "email", "ipv6", "ipv4", "ssn"]


def _records(count: int) -> list[LogRecord]:
    """Records with a predictable mix of redactable values and plain text."""
    base = datetime(2026, 8, 30, 14, 0, tzinfo=UTC)
    lines = [
        "connection from 10.0.0.{n} refused",
        "user user{n}@example.com signed in",
        "nothing sensitive on this line at all, number {n}",
        "api_key=abcdefghijklmnop{n} accepted",
    ]
    return [
        LogRecord(
            ts=base + timedelta(seconds=i),
            source="svc",
            severity="INFO",
            raw=lines[i % len(lines)].format(n=i % 200),
            message=lines[i % len(lines)].format(n=i % 200),
            fields={"peer": f"192.168.1.{i % 200}"},
            format="raw_lines",
        )
        for i in range(count)
    ]


def _redactor() -> Redactor:
    return Redactor(mode="strict", entities=ENTITIES, salt="pepper")


# --------------------------------------------------------------- worker count


def test_zero_workers_means_use_the_machine() -> None:
    resolved = resolve_workers(0)
    assert 1 <= resolved <= 8
    assert resolved == min(os.cpu_count() or 1, 8)


def test_one_worker_means_serial() -> None:
    assert resolve_workers(1) == 1


def test_the_worker_count_is_capped() -> None:
    """Past about eight the measured curve flattens while interpreters and memory do not."""
    assert resolve_workers(0) <= 8


# --------------------------------------------------------------- when it stays serial


def test_a_vault_forces_serial(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Workers cannot share the vault's SQLite handle, and shipping mappings back would put
    more moving parts in the one place where a mistake means an unredacted value on disk."""
    with RedactionVault(tmp_path / "vault.sqlite") as vault:
        redactor = Redactor(mode="strict", entities=ENTITIES, vault=vault)
        with RedactionPool(redactor, workers=8) as pool:
            assert pool.workers == 1
            assert "vault" in pool.reason


def test_redaction_off_stays_serial() -> None:
    with RedactionPool(Redactor(mode="off"), workers=8) as pool:
        assert pool.workers == 1


def test_a_small_chunk_is_not_worth_a_round_trip() -> None:
    """Below the floor the pipe costs more than the regex, so the pool does it here."""
    redactor = _redactor()
    with RedactionPool(redactor, workers=4) as pool:
        records = _records(10)
        out = pool.redact(records)
    assert len(out) == 10
    assert all("10.0.0." not in r.raw for r in out)


# --------------------------------------------------------------- the real property


@pytest.mark.skipif(
    (os.cpu_count() or 1) < 2, reason="needs more than one core to run workers at all"
)
def test_parallel_output_is_identical_to_serial() -> None:
    """The whole claim: parallelism changes throughput and nothing else.

    Asserts the pool actually spawned before comparing. A silent fall back to serial would
    otherwise make this test compare serial against serial and pass for the wrong reason.
    """
    records = _records(MIN_PARALLEL_RECORDS * 2)

    serial_redactor = _redactor()
    serial = [serial_redactor.redact_record(r) for r in records]

    parallel_redactor = _redactor()
    with RedactionPool(parallel_redactor, workers=4) as pool:
        assert pool.workers == 4, f"pool did not use workers: {pool.reason}"
        parallel = pool.redact(records)

    assert [r.raw for r in parallel] == [r.raw for r in serial]
    assert [r.message for r in parallel] == [r.message for r in serial]
    assert [r.fields for r in parallel] == [r.fields for r in serial]
    # The counts are a reported metric, not a by-product: a worker's tally has to come home.
    assert parallel_redactor.counts == serial_redactor.counts
    assert sum(parallel_redactor.counts.values()) > 0, "the fixture redacted nothing"


@pytest.mark.skipif(
    (os.cpu_count() or 1) < 2, reason="needs more than one core to run workers at all"
)
def test_a_broken_pool_falls_back_rather_than_failing_the_ingest(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Workers are an optimisation. Losing them must not cost the run.

    On Windows a worker re-imports `__main__`, so a caller driving `ingest()` from an unguarded
    script or a REPL gets `BrokenProcessPool` on the first chunk -- their environment being
    unable to spawn, not their log being unreadable.
    """
    from concurrent.futures.process import BrokenProcessPool

    records = _records(MIN_PARALLEL_RECORDS * 2)
    expected = [_redactor().redact_record(r) for r in records]

    redactor = _redactor()
    with RedactionPool(redactor, workers=4) as pool:
        assert pool.workers == 4

        def explode(*_args: object, **_kwargs: object) -> None:
            raise BrokenProcessPool("simulated spawn failure")

        assert pool._pool is not None
        monkeypatch.setattr(pool._pool, "map", explode)
        out = pool.redact(records)

    assert [r.raw for r in out] == [r.raw for r in expected]
    assert pool.workers == 1
    assert "could not be started" in pool.reason
    # And the fallback recounted the chunk exactly once -- not zero times, and not twice on
    # top of whatever the slices that did finish had already merged.
    assert redactor.counts == _count_of(records)


def _count_of(records: list[LogRecord]) -> dict[str, int]:
    """What a serial pass over these records tallies. `records`, not the redacted output --
    counting a second time over already-redacted text finds nothing and asserts nothing."""
    counter = _redactor()
    for record in records:
        counter.redact_record(record)
    return counter.counts

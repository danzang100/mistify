"""Normalization helpers shared by every adapter."""

from __future__ import annotations

import random
from datetime import UTC, datetime

import pytest

from mistify.common.models import (
    SEVERITIES,
    LogRecord,
    normalize_severity,
    parse_timestamp,
    severity_rank,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ERROR", "ERROR"),
        ("error", "ERROR"),
        ("  Error  ", "ERROR"),
        ("WARNING", "WARN"),
        ("warn", "WARN"),
        ("CRITICAL", "FATAL"),
        ("crit", "FATAL"),
        ("panic", "FATAL"),
        ("NOTICE", "INFO"),
        ("verbose", "TRACE"),
        ("err", "ERROR"),
    ],
)
def test_known_severities_normalize(raw: str, expected: str) -> None:
    severity, mapped = normalize_severity(raw)
    assert (severity, mapped) == (expected, True)


@pytest.mark.parametrize("raw", ["", "   ", None, "LOUD", 42])
def test_unknown_severity_is_defaulted_but_reported(raw: object) -> None:
    """An unrecognised level must be countable, not silently absorbed."""
    severity, mapped = normalize_severity(raw)
    assert severity == "INFO"
    assert mapped is False


def test_severity_rank_is_ordered() -> None:
    ranks = [severity_rank(s) for s in SEVERITIES]
    assert ranks == sorted(ranks)
    assert severity_rank("FATAL") > severity_rank("ERROR") > severity_rank("WARN")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-08-30T14:22:01.442Z", datetime(2026, 8, 30, 14, 22, 1, 442000, tzinfo=UTC)),
        ("2026-08-30T16:22:01+02:00", datetime(2026, 8, 30, 14, 22, 1, tzinfo=UTC)),
        ("2026-08-30 14:22:01", datetime(2026, 8, 30, 14, 22, 1, tzinfo=UTC)),
    ],
)
def test_iso_timestamps_normalize_to_utc(raw: str, expected: datetime) -> None:
    assert parse_timestamp(raw) == expected


def test_epoch_units_are_disambiguated_by_magnitude() -> None:
    seconds = parse_timestamp(1772461321)
    millis = parse_timestamp(1772461321000)
    nanos = parse_timestamp(1772461321000000000)
    assert seconds == millis == nanos


def test_naive_timestamps_are_treated_as_utc() -> None:
    assert parse_timestamp("2026-08-30T14:22:01").tzinfo is UTC


@pytest.mark.parametrize("raw", ["", "   ", "not a date", None, object()])
def test_unparseable_timestamp_raises(raw: object) -> None:
    """Never silently default to now() — a wrong timestamp misaligns every time slice."""
    with pytest.raises(ValueError):
        parse_timestamp(raw)


def test_log_record_isoformat_is_utc_z() -> None:
    record = LogRecord(
        ts=parse_timestamp("2026-08-30T16:22:01+02:00"),
        source="checkout-service",
        severity="ERROR",
        raw="{}",
        message="boom",
    )
    assert record.isoformat() == "2026-08-30T14:22:01.000000Z"


# --------------------------------------------------------------- timestamp ordering


def _record(ts: str) -> LogRecord:
    """A record carrying nothing of interest but the timestamp under test."""
    return LogRecord(
        ts=parse_timestamp(ts),
        source="checkout-service",
        severity="INFO",
        raw="{}",
        message="boom",
    )


def test_whole_second_sorts_before_a_fraction_of_the_same_second() -> None:
    """The regression the fixed width exists for: "." sorts before "Z".

    `ts` is stored as TEXT and every window, bound and ordering compares it as a string. A
    whole-second timestamp used to render without microseconds, so it was two characters
    shorter and `14:38:00.442Z` compared as *earlier* than `14:38:00Z` — string order was the
    reverse of chronological order inside any second that contained both shapes.
    """
    a = _record("2026-08-30T14:38:00Z")
    b = _record("2026-08-30T14:38:00.442Z")

    assert a.ts < b.ts
    assert a.isoformat() < b.isoformat()


@pytest.mark.parametrize(
    "raw",
    [
        "2026-08-30T14:38:00Z",
        "2026-08-30T14:38:00.4Z",
        "2026-08-30T14:38:00.442Z",
        "2026-08-30T14:38:00.442137Z",
        "2026-08-30T14:38:00.000001Z",
    ],
)
def test_rendered_timestamps_are_all_one_width(raw: str) -> None:
    """Lexicographic comparison is only chronological while every string is the same length."""
    assert len(_record(raw).isoformat()) == len("2026-08-30T14:38:00.000000Z")


def test_string_order_matches_chronological_order() -> None:
    """Sorting on the rendered text is what SQLite does for `ORDER BY ts`."""
    records = [
        _record(raw)
        for raw in (
            "2026-08-30T14:38:00Z",
            "2026-08-30T14:38:00.442Z",
            "2026-08-30T14:37:59.999999Z",
            "2026-08-30T14:38:00.000001Z",
            "2026-08-30T14:38:00.9Z",
            "2026-08-30T14:38:01Z",
        )
    ]
    random.Random(20260830).shuffle(records)

    by_text = [r.ts for r in sorted(records, key=lambda r: r.isoformat())]
    assert by_text == sorted(r.ts for r in records)

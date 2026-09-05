"""Storage optimisations, checked against every format that can be ingested.

A saving that works on one format and quietly loses data on another is worse than no saving,
and every one of these trades a stored value for a default supplied on read. So each is
asserted the same way on each format: what went in comes back out, and the column is only
empty in the case the optimisation is actually about.

The formats are enumerated from the registry rather than listed here, so a format added later
fails this file until it is covered rather than silently skipping it.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from mistify.adapters.registry import ADAPTERS
from mistify.common.config import MistifyConfig
from mistify.common.models import UNKNOWN_SOURCE
from mistify.pipeline import ingest
from mistify.scratchpad.db import ScratchpadDB

_TS = "2026-08-30T14:00:02.037152Z"
_NANOS = "1788420002037152000"

#: A named service, so "the source survived" is distinguishable from "everything reads unknown".
_SERVICE = "checkout-service"


def _json_lines(path: Path) -> Path:
    path.write_text(
        "\n".join(
            json.dumps(
                {
                    "timestamp": _TS,
                    "level": "ERROR",
                    "service": _SERVICE,
                    "message": f"pool exhausted after {i} waiters",
                }
            )
            for i in range(20)
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _otlp(path: Path) -> Path:
    records = [
        {
            "timeUnixNano": _NANOS,
            "severityText": "ERROR",
            "body": {"stringValue": f"pool exhausted after {i} waiters"},
        }
        for i in range(20)
    ]
    path.write_text(
        json.dumps(
            {
                "resourceLogs": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": _SERVICE}}
                            ]
                        },
                        "scopeLogs": [{"scope": {"name": "t"}, "logRecords": records}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def _loki(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [
                        {
                            "stream": {
                                "service_name": _SERVICE,
                                "severity_text": "ERROR",
                                "detected_level": "error",
                            },
                            "values": [
                                [_NANOS, f"pool exhausted after {i} waiters"] for i in range(20)
                            ],
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _elastic(path: Path) -> Path:
    path.write_text(
        "\n".join(
            json.dumps(
                {
                    "_index": "logs-000001",
                    "_id": f"id{i}",
                    "_source": {
                        "@timestamp": _TS,
                        "message": f"pool exhausted after {i} waiters",
                        "log": {"level": "error"},
                        "service": {"name": _SERVICE},
                        "ecs": {"version": "8.11.0"},
                    },
                }
            )
            for i in range(20)
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _raw_lines(path: Path) -> Path:
    """Nothing recognises this, so it falls back -- and reports no source at all."""
    path.write_text(
        "\n".join(
            f"Nov 10 00:05:0{i % 10} <<< pool exhausted after {i} waiters >>>" for i in range(20)
        )
        + "\n",
        encoding="utf-8",
    )
    return path


#: Every format, and whether it can name the emitting service. `raw_lines` cannot -- that is
#: what makes it the case the NULL-source optimisation exists for, and the others are the
#: control that the optimisation does not eat a real value.
_SOURCES: dict[str, tuple[Callable[[Path], Path], str | None]] = {
    "json_lines": (_json_lines, _SERVICE),
    "otlp": (_otlp, _SERVICE),
    "loki": (_loki, _SERVICE),
    "elastic": (_elastic, _SERVICE),
    "raw_lines": (_raw_lines, None),
}


def test_every_registered_format_is_covered() -> None:
    """A format added to the registry without a case here would skip these checks silently."""
    assert set(ADAPTERS) == set(_SOURCES)


@pytest.mark.parametrize("format_name", sorted(_SOURCES))
def test_the_source_survives_a_round_trip(
    format_name: str, tmp_path: Path, config: MistifyConfig
) -> None:
    build, expected = _SOURCES[format_name]
    source = build(tmp_path / f"in_{format_name}.log")

    result = ingest(source, config, incident_id=f"src-{format_name}")

    with ScratchpadDB(result.scratchpad_path) as db:
        rows = db.get_slice(max_lines=50)
        activity = db.source_activity()

    # A raw-lines read names no service, so the filename is not available either -- a single
    # file keeps `unknown`, which is what must come back out rather than NULL or empty.
    want = expected or UNKNOWN_SOURCE
    assert rows, f"{format_name} loaded nothing"
    assert {row["source"] for row in rows} == {want}
    assert {entry["source"] for entry in activity} == {want}


@pytest.mark.parametrize("format_name", sorted(_SOURCES))
def test_only_an_unnamed_source_is_stored_as_null(
    format_name: str, tmp_path: Path, config: MistifyConfig
) -> None:
    """The optimisation itself: the column is empty exactly when there was nothing to store.

    Read straight from the table rather than through `get_slice`, which is the layer that fills
    the default back in -- asking it would prove only that COALESCE works.
    """
    build, expected = _SOURCES[format_name]
    source = build(tmp_path / f"in_{format_name}.log")

    result = ingest(source, config, incident_id=f"null-{format_name}")

    con = sqlite3.connect(f"file:{result.scratchpad_path.as_posix()}?mode=ro", uri=True)
    try:
        nulls = con.execute("SELECT COUNT(*) FROM log_events WHERE source IS NULL").fetchone()[0]
        total = con.execute("SELECT COUNT(*) FROM log_events").fetchone()[0]
    finally:
        con.close()

    if expected is None:
        assert nulls == total, f"{format_name}: unnamed source should cost nothing to store"
    else:
        assert nulls == 0, f"{format_name}: a named source must not be dropped"


@pytest.mark.parametrize("format_name", sorted(_SOURCES))
def test_the_message_text_survives_a_round_trip(
    format_name: str, tmp_path: Path, config: MistifyConfig
) -> None:
    """The older of the two optimisations, on the same footing.

    `message` is stored as NULL when it equals `raw`, so a reader that forgot the COALESCE
    would see empty text on exactly the formats where the two are the same string.
    """
    build, _ = _SOURCES[format_name]
    source = build(tmp_path / f"in_{format_name}.log")

    result = ingest(source, config, incident_id=f"msg-{format_name}")

    with ScratchpadDB(result.scratchpad_path) as db:
        rows = db.get_slice(max_lines=50)

    assert all(str(row["message"]).strip() for row in rows), f"{format_name} lost its text"
    assert any("pool exhausted" in str(row["message"]) for row in rows)


@pytest.mark.parametrize("format_name", sorted(_SOURCES))
def test_timestamps_are_fixed_width_so_string_order_is_time_order(
    format_name: str, tmp_path: Path, config: MistifyConfig
) -> None:
    """Why the timestamp is not shortened to save space, asserted rather than commented.

    `ts` is TEXT and every `ORDER BY ts`, `MIN(ts)` and window slice compares it as a string.
    Trimming a whole-second timestamp to `...:01Z` would save seven bytes in the table and in
    both indexes that carry it -- and break ordering, because `.` sorts before `Z`, so
    `14:38:00.442Z` would compare as earlier than `14:38:00Z`.
    """
    build, _ = _SOURCES[format_name]
    source = build(tmp_path / f"in_{format_name}.log")

    result = ingest(source, config, incident_id=f"ts-{format_name}")

    con = sqlite3.connect(f"file:{result.scratchpad_path.as_posix()}?mode=ro", uri=True)
    try:
        widths = {row[0] for row in con.execute("SELECT DISTINCT LENGTH(ts) FROM log_events")}
    finally:
        con.close()

    assert widths == {27}, f"{format_name} stored timestamps of mixed width {widths}"


def test_a_directory_names_its_sources_from_the_filenames(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """The one place `unknown` is deliberately replaced rather than stored as NULL.

    In a per-service directory the filename *is* the service, so a raw-lines member that names
    no source gets one from its path -- and must therefore not be stored as NULL. This is the
    case that would break if the NULL substitution were applied before the filename step
    instead of after it.
    """
    root = tmp_path / "logs"
    root.mkdir()
    _raw_lines(root / "sshd.log")
    _raw_lines(root / "worker.log")

    result = ingest(root, config, incident_id="dir-sources")

    with ScratchpadDB(result.scratchpad_path) as db:
        sources = {row["source"] for row in db.get_slice(max_lines=100)}
    con = sqlite3.connect(f"file:{result.scratchpad_path.as_posix()}?mode=ro", uri=True)
    try:
        nulls = con.execute("SELECT COUNT(*) FROM log_events WHERE source IS NULL").fetchone()[0]
    finally:
        con.close()

    assert sources == {"sshd", "worker"}
    assert nulls == 0


def test_a_bootstrapped_read_round_trips_its_source(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """The structural inference path, which no registered adapter covers.

    A file no adapter claims but whose shape is readable is parsed by the bootstrapper rather
    than falling to raw lines, so it is a sixth way records reach the scratchpad.
    """
    source = tmp_path / "inferred.log"
    source.write_text(
        "\n".join(
            f"2026-08-30T14:00:0{i % 10}.000000Z ERROR billing-api pool exhausted for {i}"
            for i in range(40)
        )
        + "\n",
        encoding="utf-8",
    )

    result = ingest(source, config, incident_id="bootstrap-source")

    with ScratchpadDB(result.scratchpad_path) as db:
        rows = db.get_slice(max_lines=50)

    assert rows
    assert all(str(row["source"]).strip() for row in rows)
    assert all(str(row["message"]).strip() for row in rows)

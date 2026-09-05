"""The Elasticsearch adapter.

Two halves, tested differently on purpose.

The **envelope** -- a `_search` response and an NDJSON index dump -- is in the REST
specification and does not vary by deployment, so fixtures written from the specification are
legitimate evidence about it.

The **`_source` field mapping** is convention, decided by whatever indexed the document. The
fixtures below encode the rules `elastic.py` chose; they cannot say whether real Filebeat
output matches those rules. Only `tests/fixtures/capture_elastic.py` against a real stack can,
and until it has been run these tests are pinning behaviour rather than validating it. That
distinction is the entire reason the Loki adapter was written against captures.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mistify.adapters.elastic import ElasticAdapter
from mistify.adapters.registry import detect_format, read_sample

_TS = "2026-08-30T14:00:00.000Z"


def _hit(source: dict[str, object], index: str = "logs-000001") -> dict[str, object]:
    return {"_index": index, "_id": "abc123", "_score": 1.0, "_source": source}


def _search_response(sources: list[dict[str, object]]) -> dict[str, object]:
    return {
        "took": 5,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {
            "total": {"value": len(sources), "relation": "eq"},
            "max_score": 1.0,
            "hits": [_hit(s) for s in sources],
        },
    }


def _nested(message: str = "connection refused", level: str = "error") -> dict[str, object]:
    """What a shipper writing nested objects produces. Filebeat's shape."""
    return {
        "@timestamp": _TS,
        "message": message,
        "log": {"level": level, "file": {"path": "/var/log/app.log"}},
        "service": {"name": "checkout-service"},
        "host": {"name": "node-7"},
        "ecs": {"version": "8.11.0"},
        "event": {"sequence": 7},
    }


def _dotted(message: str = "connection refused", level: str = "error") -> dict[str, object]:
    """The same document with every path flattened to a dotted key. Also valid Elasticsearch."""
    return {
        "@timestamp": _TS,
        "message": message,
        "log.level": level,
        "log.file.path": "/var/log/app.log",
        "service.name": "checkout-service",
        "host.name": "node-7",
        "ecs.version": "8.11.0",
        "event.sequence": 7,
    }


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _write_ndjson(path: Path, rows: list[dict[str, object]]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------- envelope


def test_reads_a_search_response(tmp_path: Path) -> None:
    path = _write(tmp_path / "search.json", _search_response([_nested(), _nested("timeout")]))

    records = list(ElasticAdapter().parse(path))

    assert [r.message for r in records] == ["connection refused", "timeout"]


def test_reads_an_ndjson_dump(tmp_path: Path) -> None:
    path = _write_ndjson(tmp_path / "dump.ndjson", [_hit(_nested()), _hit(_nested("timeout"))])

    records = list(ElasticAdapter().parse(path))

    assert [r.message for r in records] == ["connection refused", "timeout"]


def test_reads_bare_documents_whose_envelope_was_stripped(tmp_path: Path) -> None:
    """An export that drops the wrapper still holds the same documents."""
    path = _write_ndjson(tmp_path / "bare.ndjson", [_nested(), _nested("timeout")])

    records = list(ElasticAdapter().parse(path))

    assert [r.message for r in records] == ["connection refused", "timeout"]


def test_a_hit_without_a_source_is_an_error_not_an_invented_record(tmp_path: Path) -> None:
    """`_source` can be excluded from a response. Its routing metadata is not a log line."""
    path = _write_ndjson(
        tmp_path / "nosource.ndjson", [{"_index": "logs-000001", "_id": "abc", "_score": 1.0}]
    )
    adapter = ElasticAdapter()

    records = list(adapter.parse(path))

    assert records == []
    assert adapter.stats.parse_errors == 1


def test_a_malformed_line_is_counted_not_fatal(tmp_path: Path) -> None:
    path = tmp_path / "mixed.ndjson"
    path.write_text(
        json.dumps(_hit(_nested())) + "\n{ this is not json\n" + json.dumps(_hit(_nested("b"))),
        encoding="utf-8",
    )
    adapter = ElasticAdapter()

    records = list(adapter.parse(path))

    assert len(records) == 2
    assert adapter.stats.parse_errors == 1


# ---------------------------------------------------------------- detection


def test_a_wrapped_dump_is_claimed_on_score_alone(tmp_path: Path) -> None:
    """`_index` beside `_source` is distinctive enough that no tier is needed to win.

    Measured: `json_lines` scores only 0.4 here, because the envelope carries no top-level
    timestamp. The specificity tier does no work on this layout, and saying otherwise would
    make the next reader look for a problem that is not there.
    """
    path = _write_ndjson(tmp_path / "dump.ndjson", [_hit(_nested()) for _ in range(5)])

    adapter, scores = detect_format(read_sample(path, 100))

    assert adapter is not None
    assert adapter.format_name == "elastic"
    assert scores["elastic"] > scores["json_lines"]


def test_bare_ecs_documents_are_taken_from_the_generic_reader(tmp_path: Path) -> None:
    """The case `LogAdapter.specificity` actually exists for, found by measuring it.

    Filebeat writing to a file produces ECS documents with no envelope. They are JSON objects
    with an `@timestamp`, so `json_lines` scores a flat 1.0 -- and then reads `log` as one
    opaque nested field, finding no severity on any line. Unmapped for the whole file, which
    collapses the heaviest term of the anomaly score to a constant.

    The adapter scored 0.0 on these until this test was written.
    """
    path = _write_ndjson(tmp_path / "bare.ndjson", [_nested() for _ in range(5)])

    adapter, scores = detect_format(read_sample(path, 100))

    assert scores["json_lines"] == pytest.approx(1.0)
    assert scores["elastic"] < scores["json_lines"]
    assert adapter is not None
    assert adapter.format_name == "elastic"


def test_detection_reads_a_pretty_printed_response(tmp_path: Path) -> None:
    """A sample from the middle of one JSON value cannot be parsed, only matched as text."""
    path = _write(tmp_path / "search.json", _search_response([_nested() for _ in range(5)]))

    adapter, _ = detect_format(read_sample(path, 100))

    assert adapter is not None
    assert adapter.format_name == "elastic"


def test_an_unrelated_json_file_is_not_claimed(tmp_path: Path) -> None:
    """The control: without it, detection returning a constant would pass every test above."""
    path = _write_ndjson(
        tmp_path / "other.ndjson",
        [{"timestamp": _TS, "level": "error", "msg": "hello"} for _ in range(5)],
    )

    assert ElasticAdapter().detect(read_sample(path, 100)) == 0.0


# ---------------------------------------------------------------- the _source mapping
#
# Pinning the rules chosen in `elastic.py`, not validating them against a real shipper.


@pytest.mark.parametrize("document", [_nested(), _dotted()], ids=["nested", "dotted"])
def test_the_same_document_reads_the_same_either_way(
    tmp_path: Path, document: dict[str, object]
) -> None:
    """Both spellings are valid Elasticsearch and both occur; handling one drops the other."""
    path = _write_ndjson(tmp_path / "doc.ndjson", [_hit(document)])

    record = next(iter(ElasticAdapter().parse(path)))

    assert record.severity == "ERROR"
    assert record.source == "checkout-service"
    assert record.message == "connection refused"


def test_a_path_stopping_at_an_object_is_not_a_value(tmp_path: Path) -> None:
    """`log.level` must not resolve to the whole `log` object stringified into a severity."""
    path = _write_ndjson(
        tmp_path / "obj.ndjson",
        [_hit({"@timestamp": _TS, "message": "m", "log": {"file": {"path": "/x"}}})],
    )
    adapter = ElasticAdapter()

    record = next(iter(adapter.parse(path)))

    assert adapter.stats.unmapped_severity == 1
    assert "{" not in record.severity


def test_a_document_with_no_timestamp_is_refused(tmp_path: Path) -> None:
    path = _write_ndjson(tmp_path / "nots.ndjson", [_hit({"message": "m", "log.level": "error"})])
    adapter = ElasticAdapter()

    assert list(adapter.parse(path)) == []
    assert adapter.stats.parse_errors == 1


def test_consumed_fields_are_not_repeated_in_fields(tmp_path: Path) -> None:
    """The same value under two names is the same value counted twice by everything downstream."""
    path = _write_ndjson(tmp_path / "doc.ndjson", [_hit(_nested())])

    record = next(iter(ElasticAdapter().parse(path)))

    assert "log.level" not in record.fields
    assert "service.name" not in record.fields
    assert "message" not in record.fields
    # Not consumed, so it survives -- otherwise this test would pass by dropping everything.
    assert record.fields["event.sequence"] == 7


def test_raw_is_the_document_as_indexed(tmp_path: Path) -> None:
    """An Elastic export is JSON, so the JSON is the source of record.

    `raw` and `message` differ here, which is what stops the redaction counters double-counting
    them -- the defect that reported 3,464 IPv4s against a true 1,734 on unstructured logs.
    """
    path = _write_ndjson(tmp_path / "doc.ndjson", [_hit(_nested())])

    record = next(iter(ElasticAdapter().parse(path)))

    assert record.raw != record.message
    assert json.loads(record.raw)["message"] == "connection refused"

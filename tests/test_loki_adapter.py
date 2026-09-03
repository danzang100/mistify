"""The Loki adapter, and the detection boundary between it and JSON Lines.

Every sample here is transcribed from a real capture -- logs pushed through the OTLP collector
in `grafana/otel-lgtm` into its Loki and read back from `/loki/api/v1/query_range` by
`tests/fixtures/capture_loki.py`. None of it was authored from the API reference, because the
label conventions are the thing under test and inventing them would mean testing the invention.

The captures themselves are not committed, for the same reason nothing else generated in this
repo is. What is committed is the shapes they showed, and the script that produces them again.

`test_live_round_trip` is the one test that talks to a stack, and it skips when there is none.
It is the control on all the rest: a transcription can drift from the thing it was transcribed
from, and the only way to notice is to occasionally read the real thing again.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from mistify.adapters.loki import LokiAdapter
from mistify.adapters.registry import detect_format, read_sample
from mistify.common.models import LogRecord

#: One stream from the synthetic capture, verbatim. Note what is in the label set: severity as
#: text *and* number, the trace id, and the application's own fields -- all of it flattened out
#: of the log record and onto the stream, and all of it stringified.
REAL_STREAM: dict[str, Any] = {
    "stream": {
        "client_ip": "10.42.7.19",
        "deployment_environment": "fixture",
        "detected_level": "info",
        "observed_timestamp": "1788420417306524096",
        "region": "ap-south-1",
        "scope_name": "mistify.capture",
        "scope_version": "1",
        "service_name": "mistify-synthetic",
        "severity_number": "9",
        "severity_text": "INFO",
        "trace_id": "8ae8557e48cdde27",
    },
    "values": [["1788420417306524096", "Handled GET /api/v2/catalog/SKU-4471 in 20ms"]],
}

#: The other shape, from the Loghub capture: no severity sent, no observed time, so Loki
#: applied its own `detected_level` and put every entry in one stream.
REAL_UNLABELLED_STREAM: dict[str, Any] = {
    "stream": {
        "deployment_environment": "fixture",
        "detected_level": "unknown",
        "scope_name": "mistify.capture",
        "scope_version": "1",
        "service_name": "loghub-openssh",
    },
    "values": [
        ["1788420429282760768", "Dec 10 07:51:15 LabSZ sshd[24324]: Failed password for root"],
        ["1788420429286760768", "Dec 10 07:51:20 LabSZ sshd[24326]: Connection closed [preauth]"],
    ],
}


def _response(streams: list[dict[str, Any]]) -> dict[str, Any]:
    """A `query_range` response around some streams, with the envelope Loki actually sends."""
    return {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": streams,
            # Present and enormous in a real response. Kept so the adapter is exercised
            # against a payload it has to ignore rather than one that is only what it wants.
            "stats": {"summary": {"totalEntriesReturned": sum(len(s["values"]) for s in streams)}},
        },
    }


def _parse(tmp_path: Path, payload: object) -> tuple[LokiAdapter, list[LogRecord]]:
    path = tmp_path / "loki.json"
    body = payload if isinstance(payload, str) else json.dumps(payload, indent=2)
    path.write_text(body, encoding="utf-8")
    adapter = LokiAdapter()
    return adapter, list(adapter.parse(path))


def _jsonl_line(**overrides: Any) -> str:
    """One `logcli --output=jsonl` line."""
    payload: dict[str, Any] = {
        "labels": {"service_name": "checkout", "detected_level": "error"},
        "line": "connection pool exhausted after 30s",
        "timestamp": "2026-09-03T07:26:57.306524Z",
    }
    payload.update(overrides)
    return json.dumps(payload)


# --------------------------------------------------------------- detect()


def test_detect_is_confident_on_a_query_response(tmp_path: Path) -> None:
    path = tmp_path / "loki.json"
    path.write_text(json.dumps(_response([REAL_STREAM]), indent=2), encoding="utf-8")
    assert LokiAdapter().detect(read_sample(path, 100)) >= 0.9


def test_detect_scores_zero_on_plaintext() -> None:
    assert LokiAdapter().detect(["Dec 10 07:51:15 LabSZ sshd[24324]: Failed password"]) == 0.0


def test_detect_scores_zero_on_empty_sample() -> None:
    assert LokiAdapter().detect([]) == 0.0
    assert LokiAdapter().detect(["", "   "]) == 0.0


def test_detect_declines_a_metric_query() -> None:
    """`resultType: matrix` is a metric query: numbers, with no log lines in it at all.

    Not merely unsupported -- there is nothing in it for a log pipeline to read, and claiming
    it would turn an empty parse into a successful-looking ingest of zero events.
    """
    payload = {"status": "success", "data": {"resultType": "matrix", "result": []}}
    assert LokiAdapter().detect([json.dumps(payload)]) == 0.0


# ------------------------------------------- the collision this adapter's tier exists for


def test_logcli_jsonl_routes_to_loki_not_json_lines() -> None:
    """The case that motivates `LogAdapter.specificity`.

    `json_lines` scores a *perfect* 1.0 on these lines, correctly -- they are JSON objects
    carrying a timestamp. No confidence the Loki adapter returns can beat that, so ranking by
    number alone sends a Loki export to the generic reader, which sees `labels` and `line` as
    two opaque fields and produces a scratchpad where every record is quietly wrong.
    """
    sample = [_jsonl_line(), _jsonl_line(line="slow query took 4210ms")]
    adapter, scores = detect_format(sample)

    assert scores["json_lines"] == pytest.approx(1.0)
    assert scores["loki"] < scores["json_lines"]
    assert adapter is not None
    assert adapter.format_name == "loki"


def test_ordinary_json_logs_still_route_to_json_lines() -> None:
    """The control on the test above, and the reason it is not simply "loki always wins".

    A tier that outranked `json_lines` unconditionally would be indistinguishable from one
    that worked, right up until it swallowed every application log in existence. This asserts
    the generic reader still wins the files that are genuinely generic.
    """
    sample = [
        '{"timestamp": "2026-09-03T07:26:57Z", "level": "ERROR", "service": "checkout",'
        ' "message": "pool exhausted"}',
        '{"timestamp": "2026-09-03T07:26:58Z", "level": "INFO", "service": "cart",'
        ' "message": "ok"}',
    ]
    adapter, scores = detect_format(sample)

    assert scores["loki"] == 0.0
    assert adapter is not None
    assert adapter.format_name == "json_lines"


def test_a_mostly_other_file_does_not_win_on_one_loki_line() -> None:
    """Detection is proportional, so one Loki-shaped line in a foreign file is not a claim."""
    sample = [_jsonl_line()] + ["not json at all"] * 9
    assert LokiAdapter().detect(sample) < 0.7


# --------------------------------------------------------------- labels and severity


def test_severity_comes_from_the_stream_not_the_entry(tmp_path: Path) -> None:
    """Loki's unit is a stream, and everything the producer sent about a record is on it.

    A reader looking for severity on the `[timestamp, line]` pair finds nothing and marks the
    whole file unmapped, which collapses the heaviest term in the anomaly score to a constant.
    """
    _, records = _parse(tmp_path, _response([REAL_STREAM]))
    assert [r.severity for r in records] == ["INFO"]


def test_stream_labels_are_applied_to_every_entry_under_it(tmp_path: Path) -> None:
    """One stream, many entries -- what a file-tailing agent produces, and half the captures."""
    _, records = _parse(tmp_path, _response([REAL_UNLABELLED_STREAM]))
    assert len(records) == 2
    assert {r.source for r in records} == {"loghub-openssh"}
    assert all(r.fields["deployment_environment"] == "fixture" for r in records)


def test_service_name_is_read_through_lokis_underscore_spelling(tmp_path: Path) -> None:
    """`service.name` arrives as `service_name`. An adapter keying on the OTLP spelling
    matches nothing and calls every record's source "unknown"."""
    _, records = _parse(tmp_path, _response([REAL_STREAM]))
    assert records[0].source == "mistify-synthetic"


def test_detected_level_unknown_counts_as_unmapped(tmp_path: Path) -> None:
    """Loki's `"unknown"` means it could not tell, and must not be mapped to the default.

    Passing the literal word to `normalize_severity` maps it to the default *and reports the
    line as mapped*, which hides exactly the gap the metric exists to surface.
    """
    adapter, records = _parse(tmp_path, _response([REAL_UNLABELLED_STREAM]))
    assert adapter.stats.unmapped_severity == 2
    assert all(r.severity == records[0].severity for r in records)


def test_a_real_detected_level_is_mapped(tmp_path: Path) -> None:
    """The control on the test above: `detected_level` is read when it says something."""
    stream = json.loads(json.dumps(REAL_UNLABELLED_STREAM))
    stream["stream"]["detected_level"] = "error"
    adapter, records = _parse(tmp_path, _response([stream]))
    assert adapter.stats.unmapped_severity == 0
    assert [r.severity for r in records] == ["ERROR", "ERROR"]


def test_producer_severity_outranks_lokis_guess(tmp_path: Path) -> None:
    """`severity_text` is what the producer said; `detected_level` is what Loki inferred."""
    stream = json.loads(json.dumps(REAL_STREAM))
    stream["stream"]["severity_text"] = "ERROR"
    stream["stream"]["detected_level"] = "info"
    _, records = _parse(tmp_path, _response([stream]))
    assert records[0].severity == "ERROR"


def test_consumed_labels_are_not_duplicated_into_fields(tmp_path: Path) -> None:
    _, records = _parse(tmp_path, _response([REAL_STREAM]))
    assert "service_name" not in records[0].fields
    assert "severity_text" not in records[0].fields
    # Everything else survives -- the application's own labels are the point of the format.
    assert records[0].fields["region"] == "ap-south-1"
    assert records[0].fields["trace_id"] == "8ae8557e48cdde27"


# --------------------------------------------------------------- entries


def test_nanosecond_string_timestamps_are_parsed(tmp_path: Path) -> None:
    """Loki's timestamps are nanoseconds as a string, because JSON cannot hold an int64."""
    adapter, records = _parse(tmp_path, _response([REAL_STREAM]))
    assert adapter.stats.unparseable_timestamp == 0
    assert records[0].ts.year == 2026


def test_structured_metadata_in_a_third_element_is_kept(tmp_path: Path) -> None:
    """Loki 3.x entries may carry a third element. An adapter reading `[0]` and `[1]` and
    stopping loses those fields with no error anywhere."""
    stream = json.loads(json.dumps(REAL_STREAM))
    stream["values"] = [["1788420417306524096", "boom", {"pod": "checkout-7d9", "attempt": "2"}]]
    _, records = _parse(tmp_path, _response([stream]))
    assert records[0].fields["pod"] == "checkout-7d9"


def test_two_element_entries_still_parse(tmp_path: Path) -> None:
    """The control: the third element is optional and absent in every capture taken so far."""
    _, records = _parse(tmp_path, _response([REAL_STREAM]))
    assert len(records) == 1
    assert records[0].message == "Handled GET /api/v2/catalog/SKU-4471 in 20ms"


def test_raw_is_the_entry_not_the_whole_response(tmp_path: Path) -> None:
    """One response carries every record in the file.

    Quoting the response as `raw` would give all of them the same one, and `raw` is what a
    reader greps to check a claim -- the same mistake the OTLP adapter had to avoid, where one
    exported line carries many records.
    """
    _, records = _parse(tmp_path, _response([REAL_UNLABELLED_STREAM]))
    assert len({r.raw for r in records}) == 2
    assert "resultType" not in records[0].raw


# --------------------------------------------------------------- layouts


def test_push_payload_layout_is_read(tmp_path: Path) -> None:
    """`{"streams": [...]}` -- the same stream objects, one level up. What you save when you
    capture what was written *in* rather than what was queried out."""
    _, records = _parse(tmp_path, {"streams": [REAL_UNLABELLED_STREAM]})
    assert len(records) == 2


def test_logcli_jsonl_layout_is_read(tmp_path: Path) -> None:
    path = tmp_path / "loki.jsonl"
    path.write_text(
        "\n".join([_jsonl_line(), _jsonl_line(line="slow query took 4210ms")]) + "\n",
        encoding="utf-8",
    )
    adapter = LokiAdapter()
    records = list(adapter.parse(path))
    assert [r.message for r in records] == [
        "connection pool exhausted after 30s",
        "slow query took 4210ms",
    ]
    assert records[0].source == "checkout"
    assert records[0].severity == "ERROR"


# --------------------------------------------------------------- malformed input


def test_a_malformed_entry_is_counted_not_fatal(tmp_path: Path) -> None:
    stream = json.loads(json.dumps(REAL_STREAM))
    stream["values"] = [["1788420417306524096", "fine"], ["only-a-timestamp"], "not a list"]
    adapter, records = _parse(tmp_path, _response([stream]))
    assert len(records) == 1
    assert adapter.stats.parse_errors == 2
    assert adapter.stats.error_samples


def test_an_unparseable_timestamp_is_counted(tmp_path: Path) -> None:
    stream = json.loads(json.dumps(REAL_STREAM))
    stream["values"] = [["not-a-timestamp", "boom"]]
    adapter, records = _parse(tmp_path, _response([stream]))
    assert records == []
    assert adapter.stats.unparseable_timestamp == 1


def test_invalid_json_document_is_counted_not_raised(tmp_path: Path) -> None:
    adapter, records = _parse(tmp_path, '{"data": {"resultType": "streams", "result": [')
    assert records == []
    assert adapter.stats.parse_errors == 1


# --------------------------------------------------------------- against a live stack


def _stack_available(loki: str) -> bool:
    try:
        with urllib.request.urlopen(f"{loki}/ready", timeout=2) as response:
            return bool(response.status == 200)
    except (urllib.error.URLError, OSError):
        return False


LOKI_URL = os.environ.get("MISTIFY_LOKI_URL", "http://localhost:3100")
OTLP_URL = os.environ.get("MISTIFY_OTLP_URL", "http://localhost:4318")


@pytest.mark.skipif(
    not _stack_available(LOKI_URL),
    reason=f"no Loki at {LOKI_URL} (docker run grafana/otel-lgtm with -p 3100:3100 -p 4318:4318)",
)
def test_live_round_trip(tmp_path: Path) -> None:
    """Push through a real collector, query a real Loki, and parse what comes back.

    The control on every transcribed sample above. Those were copied out of a capture once,
    and a copy cannot notice when the thing it was copied from changes -- a Loki upgrade that
    moved severity, renamed `detected_level` or started emitting the third entry element would
    leave every other test in this file passing against a shape nothing produces any more.

    Skipped without a stack, which means it does not run in CI. That is the trade: it is worth
    having as the thing to run before trusting the fixtures, not as a gate on every commit.
    """
    import time

    service = f"mistify-test-{int(time.time() * 1000)}"
    base_nanos = int((time.time() - 30) * 1_000_000_000)
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": service}},
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "mistify.test"},
                        "logRecords": [
                            {
                                "timeUnixNano": str(base_nanos + index * 1_000_000),
                                "severityText": level,
                                "severityNumber": number,
                                "body": {"stringValue": message},
                            }
                            for index, (level, number, message) in enumerate(
                                [
                                    ("ERROR", 17, "connection pool exhausted after 30s"),
                                    ("INFO", 9, "handled GET /health in 2ms"),
                                ]
                            )
                        ],
                    }
                ],
            }
        ]
    }
    request = urllib.request.Request(
        f"{OTLP_URL}/v1/logs",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        assert response.status == 200

    # The collector batches before writing, so the query has to wait for a flush. Polled
    # rather than slept through: a fixed sleep is either slower than it needs to be or, on a
    # loaded machine, still too short -- and then the test fails for a reason that is not the
    # adapter.
    query = urllib.parse.urlencode(
        {
            "query": '{service_name="' + service + '"}',
            "start": str(base_nanos - 1_000_000_000),
            "end": str(int((time.time() + 60) * 1_000_000_000)),
            "limit": "10",
            "direction": "forward",
        }
    )
    body: dict[str, Any] = {}
    for _ in range(30):
        with urllib.request.urlopen(
            f"{LOKI_URL}/loki/api/v1/query_range?{query}", timeout=10
        ) as response:
            body = json.loads(response.read())
        if body.get("data", {}).get("result"):
            break
        time.sleep(1)

    path = tmp_path / "live.json"
    path.write_text(json.dumps(body, indent=2), encoding="utf-8")

    adapter, scores = detect_format(read_sample(path, 100))
    assert adapter is not None, f"live capture did not route to any adapter: {scores}"
    assert adapter.format_name == "loki"

    records = list(LokiAdapter().parse(path))
    assert len(records) == 2
    assert {r.source for r in records} == {service}
    # Severity survived the trip out to the collector, into Loki's label set, and back --
    # which is the whole claim this adapter makes about where severity lives.
    assert {r.severity for r in records} == {"ERROR", "INFO"}
    assert any("connection pool exhausted" in r.message for r in records)


# ------------------------------------------------------------- streaming logcli output


def test_logcli_jsonl_never_reads_the_whole_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The line-delimited layout must not be held in memory.

    Asserted by making `read_text` fail rather than by watching a memory number: a threshold
    would be flaky and would not say what regressed. The layout check used to be
    `"\n{" not in text`, so even this layout was read whole first.
    """

    def _refuse(_path: Path) -> str:
        raise AssertionError("the line-delimited path must not read the whole file")

    monkeypatch.setattr("mistify.adapters.loki.read_text", _refuse)

    path = tmp_path / "loki.jsonl"
    path.write_text("\n".join(_jsonl_line() for _ in range(3)) + "\n", encoding="utf-8")
    adapter = LokiAdapter()
    records = list(adapter.parse(path))

    assert len(records) == 3
    assert adapter.stats.parse_errors == 0


def test_a_query_response_still_reads_the_whole_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control. One JSON value cannot be parsed incrementally without a streaming parser,
    so this layout stays resident by nature -- and without asserting that, the test above would
    pass just as well if `parse` had stopped reading files at all."""
    from mistify.adapters import loki as loki_module

    seen: list[Path] = []
    original = loki_module.read_text

    def _record_call(path: Path) -> str:
        seen.append(path)
        return original(path)

    monkeypatch.setattr("mistify.adapters.loki.read_text", _record_call)

    path = tmp_path / "loki.json"
    path.write_text(json.dumps(_response([REAL_STREAM]), indent=2), encoding="utf-8")
    records = list(LokiAdapter().parse(path))

    assert len(records) == 1
    assert seen == [path]


def test_a_corrupt_first_line_does_not_force_the_document_path(tmp_path: Path) -> None:
    """A truncated first record should cost one counted parse error, not the whole file."""
    path = tmp_path / "loki.jsonl"
    path.write_text(
        '{"labels": {"service_na\n' + _jsonl_line() + "\n" + _jsonl_line() + "\n",
        encoding="utf-8",
    )

    adapter = LokiAdapter()
    records = list(adapter.parse(path))

    assert len(records) == 2
    assert adapter.stats.parse_errors == 1

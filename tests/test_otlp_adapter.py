"""The OTLP adapter, and the detection boundary between it and JSON Lines.

Written from the protobuf-JSON mapping rather than from a captured sample, because that is the
only thing this adapter can be checked against without a running collector. Each test pins one
place where a plausible reading of the spec produces a parser that works on one exporter and
silently loses records from the next.

"Silently" is the operative word. Every failure mode here -- the other field spelling, a record
carrying only a severity number, attributes left as wire-format unions -- produces zero
exceptions and a quietly wrong pipeline, which is the class of bug this project keeps finding
in itself the expensive way.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mistify.adapters import otlp as otlp_module
from mistify.adapters.otlp import OtlpAdapter
from mistify.adapters.registry import detect_format, read_sample
from mistify.common.models import LogRecord
from mistify.eval.fixtures import generate_incident, write_incident, write_incident_otlp

NANOS = "1756476000000000000"


def _request(records: list[dict[str, object]], service: str = "checkout") -> dict[str, object]:
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": service}}]
                },
                "scopeLogs": [{"scope": {"name": "test"}, "logRecords": records}],
            }
        ]
    }


def _parse(tmp_path: Path, payload: object) -> tuple[OtlpAdapter, list[LogRecord]]:
    path = tmp_path / "otlp.jsonl"
    body = payload if isinstance(payload, str) else json.dumps(payload)
    path.write_text(body, encoding="utf-8")
    adapter = OtlpAdapter()
    return adapter, list(adapter.parse(path))


# ------------------------------------------------------------ spelling and shape


def test_both_field_spellings_are_read(tmp_path: Path) -> None:
    """The mapping permits camelCase or the original proto names and exporters disagree.

    Reading only one spelling is the commonest way an OTLP parser drops every record while
    reporting no error at all.
    """
    payload = {
        "resource_logs": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": "svc"}}]
                },
                "scope_logs": [
                    {
                        "log_records": [
                            {
                                "timeUnixNano": NANOS,
                                "severityText": "ERROR",
                                "body": {"stringValue": "camel"},
                            },
                            {
                                "time_unix_nano": NANOS,
                                "severity_text": "ERROR",
                                "body": {"string_value": "snake"},
                            },
                        ]
                    }
                ],
            }
        ]
    }

    _, records = _parse(tmp_path, payload)

    assert [r.message for r in records] == ["camel", "snake"]
    assert {r.severity for r in records} == {"ERROR"}


def test_the_service_name_comes_from_the_resource(tmp_path: Path) -> None:
    """A record says nothing about who emitted it; that context lives one level up.

    Flattening without carrying the resource down gives every line a source of "unknown",
    which the report's per-source table then presents as a fact about the incident.
    """
    _, records = _parse(
        tmp_path,
        _request([{"timeUnixNano": NANOS, "body": {"stringValue": "x"}}], service="checkout-svc"),
    )

    assert records[0].source == "checkout-svc"


def test_each_record_gets_its_own_raw(tmp_path: Path) -> None:
    """One transport line carries many records.

    Quoting the line would give them all the same `raw` -- the field a reader greps and the
    grep baseline filters on -- so the audit trail would point every citation at the batch
    rather than the line.
    """
    records = [{"timeUnixNano": NANOS, "body": {"stringValue": m}} for m in ("a", "b")]

    _, parsed = _parse(tmp_path, _request(records))

    assert parsed[0].raw != parsed[1].raw
    assert "a" in parsed[0].raw and "b" in parsed[1].raw


# ------------------------------------------------------------------- severity


def test_a_record_with_only_a_severity_number_is_still_typed(tmp_path: Path) -> None:
    """severityNumber is the typed field; severityText is an optional free-form label.

    Machine-generated OTLP often omits the text. Reading the text alone leaves those records
    unmapped, which defaults the whole file to INFO and flattens the severity term the anomaly
    score leans on hardest.
    """
    records = [
        {"timeUnixNano": NANOS, "severityNumber": n, "body": {"stringValue": "x"}}
        for n in (2, 6, 10, 14, 18, 22)
    ]

    adapter, parsed = _parse(tmp_path, _request(records))

    assert [r.severity for r in parsed] == ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"]
    assert adapter.stats.unmapped_severity == 0


def test_severity_text_wins_over_the_number(tmp_path: Path) -> None:
    """Control for the fallback: the number is used when the text cannot be mapped, not always.

    A producer that sets both has said something specific, and silently preferring the band
    would discard it.
    """
    record = {
        "timeUnixNano": NANOS,
        "severityNumber": 9,
        "severityText": "FATAL",
        "body": {"stringValue": "x"},
    }

    _, parsed = _parse(tmp_path, _request([record]))

    assert parsed[0].severity == "FATAL"


def test_an_out_of_range_severity_number_is_counted_not_invented(tmp_path: Path) -> None:
    """The data model defines 1-24. Anything else is a producer bug, and guessing a level for
    it would put a fabricated severity into the ranking."""
    record = {"timeUnixNano": NANOS, "severityNumber": 99, "body": {"stringValue": "x"}}

    adapter, parsed = _parse(tmp_path, _request([record]))

    assert adapter.stats.unmapped_severity == 1
    assert parsed[0].severity == "INFO"


# ------------------------------------------------------------------ attributes


def test_attribute_value_variants_are_decoded(tmp_path: Path) -> None:
    """AnyValue is a tagged union. Leaving the tags in would push wire format into every later
    stage, which is the one thing an adapter exists to prevent."""
    record = {
        "timeUnixNano": NANOS,
        "body": {"stringValue": "x"},
        "attributes": [
            {"key": "retries", "value": {"intValue": "3"}},
            {"key": "ok", "value": {"boolValue": True}},
            {"key": "ratio", "value": {"doubleValue": 0.5}},
            {"key": "tags", "value": {"arrayValue": {"values": [{"stringValue": "a"}]}}},
            {
                "key": "nested",
                "value": {
                    "kvlistValue": {"values": [{"key": "inner", "value": {"stringValue": "v"}}]}
                },
            },
        ],
    }

    _, parsed = _parse(tmp_path, _request([record]))
    fields = parsed[0].fields

    assert fields["retries"] == 3
    assert fields["ok"] is True
    assert fields["ratio"] == 0.5
    assert fields["tags"] == ["a"]
    assert fields["nested"] == {"inner": "v"}


def test_the_trace_id_survives_into_fields(tmp_path: Path) -> None:
    """OTLP carries a first-class trace id, the one-request-across-services correlation axis
    the JSON fixture only has by convention."""
    record = {"timeUnixNano": NANOS, "body": {"stringValue": "x"}, "traceId": "abc123"}

    _, parsed = _parse(tmp_path, _request([record]))

    assert parsed[0].fields["trace_id"] == "abc123"


# ------------------------------------------------------------------ timestamps


def test_nanosecond_strings_are_parsed_without_losing_precision(tmp_path: Path) -> None:
    """int64 arrives as a string because JSON cannot hold it exactly, and the microseconds
    matter: the incident window is derived from these."""
    record = {"timeUnixNano": "1756476000123456000", "body": {"stringValue": "x"}}

    _, parsed = _parse(tmp_path, _request([record]))

    assert parsed[0].ts.microsecond == 123456


def test_the_observed_time_is_the_documented_fallback(tmp_path: Path) -> None:
    record = {"observedTimeUnixNano": NANOS, "body": {"stringValue": "x"}}

    _, parsed = _parse(tmp_path, _request([record]))

    assert parsed[0].ts.year == 2025


def test_a_record_with_no_timestamp_is_counted_rather_than_defaulted(tmp_path: Path) -> None:
    """Control for the fallback: absent everywhere is a skipped, counted record -- never `now`,
    which would place a mystery line inside the incident window."""
    adapter, parsed = _parse(tmp_path, _request([{"body": {"stringValue": "x"}}]))

    assert parsed == []
    assert adapter.stats.parse_errors == 1


# ---------------------------------------------------------------- file layouts


def test_a_pretty_printed_document_is_read(tmp_path: Path) -> None:
    """What a hand-saved API response looks like, as opposed to what a file exporter writes."""
    body = json.dumps(
        _request([{"timeUnixNano": NANOS, "body": {"stringValue": "pretty"}}]), indent=2
    )

    _, parsed = _parse(tmp_path, body)

    assert [r.message for r in parsed] == ["pretty"]


def test_a_malformed_line_is_counted_and_the_rest_survive(tmp_path: Path) -> None:
    """A partially-parsed file must be visible as a number, never a silent shrug."""
    good = json.dumps(_request([{"timeUnixNano": NANOS, "body": {"stringValue": "ok"}}]))
    path = tmp_path / "otlp.jsonl"
    path.write_text(f"{good}\n{{not json\n{good}\n", encoding="utf-8")
    adapter = OtlpAdapter()

    parsed = list(adapter.parse(path))

    assert len(parsed) == 2
    assert adapter.stats.parse_errors == 1


# ------------------------------------------------- the fixture and the boundary


def test_the_otlp_fixture_round_trips_every_record(tmp_path: Path) -> None:
    """The eval case rests on this: same incident, different format, nothing lost."""
    path = write_incident_otlp(tmp_path / "incident.jsonl")
    adapter = OtlpAdapter()

    parsed = list(adapter.parse(path))

    assert len(parsed) == len(generate_incident())
    assert adapter.stats.parse_errors == 0
    assert adapter.stats.unmapped_severity == 0
    assert adapter.stats.unparseable_timestamp == 0


def test_detection_separates_otlp_from_json_lines(tmp_path: Path) -> None:
    """The confusion matrix in miniature.

    OTLP is line-delimited JSON, so the json_lines adapter sees objects and could plausibly
    claim it. It scores 0.4 -- objects with no recognisable timestamp key -- which is below the
    0.6 floor, so the wrong adapter declines outright rather than merely being outvoted.
    """
    otlp_path = write_incident_otlp(tmp_path / "otlp.jsonl", total_lines=200)
    json_path = write_incident(tmp_path / "plain.jsonl", total_lines=200)

    otlp_adapter, otlp_scores = detect_format(read_sample(otlp_path))
    json_adapter, json_scores = detect_format(read_sample(json_path))

    assert otlp_adapter is not None and otlp_adapter.format_name == "otlp"
    assert json_adapter is not None and json_adapter.format_name == "json_lines"
    assert otlp_scores["json_lines"] < 0.6
    assert json_scores["otlp"] == 0.0


# ------------------------------------------------- through the pipeline, not just detect()


def test_an_otlp_file_ingests_as_otlp_end_to_end(tmp_path: Path) -> None:
    """Detection working is not the same as the pipeline using it.

    Every other test here calls `detect_format` directly, which defaults to considering the
    whole registry. `ingest()` does not: it passes `config.adapters.registered`, and that list
    defaulted to `["json_lines"]` for three phases after this adapter shipped. So an OTLP export
    ingested with a config built in code -- which is what the test suite and the eval harness
    both do -- matched nothing, fell through to the raw-line reader, and produced templates that
    were slices of JSON export text. Measured on a 290 MB fixture: 1,248 templates beginning
    `{"resourceLogs": [{"resource": ...` where the same incident parsed gives 9.

    Nothing caught it because nothing ingested an OTLP file through the pipeline.
    """
    from mistify.common.config import MistifyConfig
    from mistify.pipeline import ingest
    from mistify.scratchpad.db import ScratchpadDB

    config = MistifyConfig.model_validate(
        {
            "scratchpad": {"path": str(tmp_path / "s_{incident_id}.sqlite")},
            "drain3": {"snapshot_path": str(tmp_path / "d_{incident_id}.json")},
            "report": {"output_dir": str(tmp_path / "reports")},
        }
    )
    source = write_incident_otlp(tmp_path / "incident.jsonl", total_lines=400)

    result = ingest(source, config, incident_id="otlp-e2e")

    assert result.format_name == "otlp"
    with ScratchpadDB(result.scratchpad_path) as db:
        patterns = [str(row["pattern"]) for row in db.top_templates(limit=20)]
    # The message, not the envelope it travelled in.
    assert not any("resourceLogs" in pattern for pattern in patterns)
    assert any("Handled GET" in pattern for pattern in patterns)


def test_a_plain_json_file_still_ingests_as_json_lines(tmp_path: Path) -> None:
    """The control: registering every adapter must not let a specific one claim a generic file."""
    from mistify.common.config import MistifyConfig
    from mistify.pipeline import ingest

    config = MistifyConfig.model_validate(
        {
            "scratchpad": {"path": str(tmp_path / "s_{incident_id}.sqlite")},
            "drain3": {"snapshot_path": str(tmp_path / "d_{incident_id}.json")},
            "report": {"output_dir": str(tmp_path / "reports")},
        }
    )
    source = write_incident(tmp_path / "plain.jsonl", total_lines=400)

    assert ingest(source, config, incident_id="json-e2e").format_name == "json_lines"


# ------------------------------------------------------------- streaming the common layout


def test_a_line_delimited_export_never_reads_the_whole_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The layout collectors actually write must not be held in memory.

    Asserted by making `read_text` fail rather than by watching a memory number: a threshold
    test would be flaky and would not say *why* it regressed. If anything reintroduces a
    whole-file read on this path, this raises immediately.

    Peak memory was 3.00x the file size before the fix -- measured at 291 MB on a 97 MB export
    and 870 MB on a 290 MB one -- because the layout check `"\n{" not in text` needed the whole
    file. It is now flat at 23 MB whatever the file size.
    """

    def _refuse(_path: Path) -> str:
        raise AssertionError("the line-delimited path must not read the whole file")

    monkeypatch.setattr("mistify.adapters.otlp.read_text", _refuse)

    path = tmp_path / "otlp.jsonl"
    path.write_text(
        "\n".join(json.dumps(_request([_record()])) for _ in range(3)) + "\n", encoding="utf-8"
    )
    adapter = OtlpAdapter()
    records = list(adapter.parse(path))

    assert len(records) == 3
    assert adapter.stats.parse_errors == 0


def test_a_single_document_still_reads_the_whole_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control on the test above, and the reason it proves anything.

    One JSON value cannot be parsed incrementally without a streaming parser, so this layout is
    resident by nature and still calls `read_text`. Without this test the one above would pass
    just as well if `parse` had simply stopped reading files at all.
    """
    seen: list[Path] = []
    original = otlp_module.read_text

    def _record_call(path: Path) -> str:
        seen.append(path)
        return original(path)

    monkeypatch.setattr("mistify.adapters.otlp.read_text", _record_call)

    path = tmp_path / "otlp.json"
    path.write_text(json.dumps(_request([_record()]), indent=2), encoding="utf-8")
    records = list(OtlpAdapter().parse(path))

    assert len(records) == 1
    assert seen == [path]


def test_a_corrupt_first_line_does_not_force_the_document_path(tmp_path: Path) -> None:
    """A killed exporter leaves a truncated line, usually the last but sometimes the first.

    Deciding the layout from line one alone would send the whole file down the document path,
    where it fails as a single unit -- turning one counted parse error into a total loss. The
    layout check looks at several lines for exactly this.
    """
    path = tmp_path / "otlp.jsonl"
    good = json.dumps(_request([_record()]))
    path.write_text('{"resourceLogs": [{"resou\n' + good + "\n" + good + "\n", encoding="utf-8")

    adapter = OtlpAdapter()
    records = list(adapter.parse(path))

    assert len(records) == 2
    assert adapter.stats.parse_errors == 1


def _record() -> dict[str, object]:
    return {
        "timeUnixNano": NANOS,
        "severityNumber": 17,
        "severityText": "ERROR",
        "body": {"stringValue": "pool exhausted"},
    }

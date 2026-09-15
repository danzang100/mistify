"""Adapter detection confidence and parse correctness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mistify.adapters.json_lines import JsonLinesAdapter
from mistify.adapters.registry import detect_format, get_adapter, read_sample

JSONL_SAMPLE = [
    '{"timestamp": "2026-08-30T14:22:01Z", "level": "ERROR",'
    ' "service": "checkout", "message": "boom"}',
    '{"timestamp": "2026-08-30T14:22:02Z", "level": "INFO", "service": "cart", "message": "ok"}',
]

PLAINTEXT_SAMPLE = [
    "2026-08-30 14:22:01 ERROR checkout boom",
    "Aug 30 14:22:02 host sshd[123]: Accepted password",
]


def _write(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# --------------------------------------------------------------- detect()


def test_detect_is_confident_on_json_lines() -> None:
    assert JsonLinesAdapter().detect(JSONL_SAMPLE) > 0.9


def test_detect_scores_zero_on_plaintext() -> None:
    assert JsonLinesAdapter().detect(PLAINTEXT_SAMPLE) == 0.0


def test_detect_scores_zero_on_empty_sample() -> None:
    assert JsonLinesAdapter().detect([]) == 0.0
    assert JsonLinesAdapter().detect(["", "   "]) == 0.0


def test_detect_is_lukewarm_on_timestampless_json() -> None:
    """Line-delimited JSON without timestamps is probably data, not a log stream."""
    sample = ['{"a": 1, "b": 2}', '{"a": 3, "b": 4}']
    assert 0.0 < JsonLinesAdapter().detect(sample) < 0.6


def test_detect_ignores_a_json_array_file() -> None:
    assert JsonLinesAdapter().detect(["[1, 2, 3]", "[4, 5, 6]"]) == 0.0


def test_detect_degrades_with_mixed_content() -> None:
    mixed = JSONL_SAMPLE + PLAINTEXT_SAMPLE
    score = JsonLinesAdapter().detect(mixed)
    assert 0.0 < score < JsonLinesAdapter().detect(JSONL_SAMPLE)


# --------------------------------------------------------------- registry


def test_registry_routes_json_lines(tmp_path: Path) -> None:
    adapter, scores = detect_format(JSONL_SAMPLE)
    assert adapter is not None
    assert adapter.format_name == "json_lines"
    assert scores["json_lines"] > 0.6


def test_registry_returns_none_below_threshold() -> None:
    """None is the handoff to the unknown-format bootstrapper, not a failure."""
    adapter, _ = detect_format(PLAINTEXT_SAMPLE)
    assert adapter is None


def test_get_adapter_rejects_unknown_format() -> None:
    with pytest.raises(ValueError, match="unknown format"):
        get_adapter("evtx")


def test_registered_filter_is_respected() -> None:
    adapter, scores = detect_format(JSONL_SAMPLE, registered=[])
    assert adapter is None
    assert scores == {}


def test_read_sample_caps_and_skips_blanks(tmp_path: Path) -> None:
    path = _write(tmp_path / "s.jsonl", ["a", "", "b", "   ", "c", "d"])
    assert read_sample(path, sample_size=3) == ["a", "b", "c"]


# --------------------------------------------------------------- parse()


def test_parse_produces_golden_records(tmp_path: Path) -> None:
    path = _write(tmp_path / "in.jsonl", JSONL_SAMPLE)
    records = list(JsonLinesAdapter().parse(path))

    assert len(records) == 2
    first = records[0]
    assert first.isoformat() == "2026-08-30T14:22:01.000000Z"
    assert first.severity == "ERROR"
    assert first.source == "checkout"
    assert first.message == "boom"
    assert first.format == "json_lines"
    assert first.raw == JSONL_SAMPLE[0]


def test_consumed_keys_are_not_duplicated_into_fields(tmp_path: Path) -> None:
    line = json.dumps(
        {
            "timestamp": "2026-08-30T14:22:01Z",
            "level": "WARN",
            "service": "cart",
            "message": "slow",
            "trace_id": "abc",
            "attempt": 2,
        }
    )
    path = _write(tmp_path / "in.jsonl", [line])
    record = next(iter(JsonLinesAdapter().parse(path)))
    assert record.fields == {"trace_id": "abc", "attempt": 2}


def test_message_falls_back_to_the_raw_line(tmp_path: Path) -> None:
    line = json.dumps({"timestamp": "2026-08-30T14:22:01Z", "level": "INFO", "k": "v"})
    path = _write(tmp_path / "in.jsonl", [line])
    record = next(iter(JsonLinesAdapter().parse(path)))
    assert record.message == line


def test_missing_source_becomes_unknown(tmp_path: Path) -> None:
    line = json.dumps({"timestamp": "2026-08-30T14:22:01Z", "message": "hi"})
    path = _write(tmp_path / "in.jsonl", [line])
    assert next(iter(JsonLinesAdapter().parse(path))).source == "unknown"


# --------------------------------------------------------------- negative cases


def test_malformed_lines_are_skipped_and_counted(tmp_path: Path) -> None:
    """Malformed input fails predictably and visibly - never partial garbage records."""
    path = _write(
        tmp_path / "in.jsonl",
        [
            JSONL_SAMPLE[0],
            "{not json at all",
            '"a bare string"',
            '{"level": "INFO", "message": "no timestamp"}',
            '{"timestamp": "not a date", "message": "bad ts"}',
            JSONL_SAMPLE[1],
        ],
    )
    adapter = JsonLinesAdapter()
    records = list(adapter.parse(path))

    assert len(records) == 2
    assert adapter.stats.lines_read == 6
    assert adapter.stats.records_emitted == 2
    assert adapter.stats.parse_errors == 4
    assert adapter.stats.unparseable_timestamp == 1
    assert len(adapter.stats.error_samples) == 4


def test_unmapped_severity_is_counted(tmp_path: Path) -> None:
    line = json.dumps({"timestamp": "2026-08-30T14:22:01Z", "level": "LOUD", "message": "hm"})
    path = _write(tmp_path / "in.jsonl", [line])
    adapter = JsonLinesAdapter()
    records = list(adapter.parse(path))
    assert records[0].severity == "INFO"
    assert adapter.stats.unmapped_severity == 1


def test_blank_lines_are_not_counted(tmp_path: Path) -> None:
    path = _write(tmp_path / "in.jsonl", [JSONL_SAMPLE[0], "", "   ", JSONL_SAMPLE[1]])
    adapter = JsonLinesAdapter()
    assert len(list(adapter.parse(path))) == 2
    assert adapter.stats.lines_read == 2

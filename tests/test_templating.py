"""Drain3 wrapper behaviour, including the redaction-placeholder masking from decision G2."""

from __future__ import annotations

import json
from pathlib import Path

from pytest import approx

from mistify.redaction.redactor import Redactor
from mistify.templating.drain_wrapper import DrainTemplater, read_snapshot


def test_near_duplicates_collapse_into_one_template() -> None:
    templater = DrainTemplater()
    for retries in range(1, 30):
        templater.process(f"Connection to database failed after {retries} retries")
    assert templater.unique_templates == 1
    assert templater.total_messages == 29


def test_distinct_messages_stay_distinct() -> None:
    templater = DrainTemplater()
    templater.process("Connection to database failed after 3 retries")
    templater.process("Cache warm completed in 42ms")
    templater.process("User session expired")
    assert templater.unique_templates == 3


def test_compression_ratio_reflects_clustering() -> None:
    templater = DrainTemplater()
    for i in range(100):
        templater.process(f"Handled request {i} in {i * 3}ms")
    assert templater.compression_ratio == approx(0.01)


def test_empty_templater_has_zero_ratio() -> None:
    assert DrainTemplater().compression_ratio == 0.0


# --------------------------------------------------------------- decision G2


def test_redaction_placeholders_do_not_fragment_templates() -> None:
    """Without the placeholder mask, each distinct address becomes its own template.

    This is the regression test for decision G2: redaction moved ahead of templating, so the
    templater must treat `[IPV4:xxxx]` as one token shape rather than as many literals.
    """
    redactor = Redactor()
    templater = DrainTemplater()
    for octet in range(1, 40):
        message = redactor.redact(f"Connection to 10.0.0.{octet} refused by upstream")
        templater.process(message)

    assert templater.unique_templates == 1
    assert "<REDACTED>" in templater.summaries()[0].pattern


def test_placeholder_mask_does_not_merge_genuinely_different_messages() -> None:
    redactor = Redactor()
    templater = DrainTemplater()
    templater.process(redactor.redact("Connection to 10.0.0.1 refused by upstream"))
    templater.process(redactor.redact("Mail delivery to ana@example.com bounced"))
    assert templater.unique_templates == 2


# --------------------------------------------------------------- statistics


def test_summaries_carry_severity_mix_and_max_rank() -> None:
    templater = DrainTemplater()
    templater.process("pool exhausted", ts="2026-08-30T14:00:00Z", severity="WARN")
    templater.process("pool exhausted", ts="2026-08-30T14:05:00Z", severity="FATAL")
    templater.process("pool exhausted", ts="2026-08-30T14:02:00Z", severity="WARN")

    summary = templater.summaries()[0]
    assert summary.occurrence_count == 3
    assert summary.severity_mix == {"WARN": 2, "FATAL": 1}
    assert summary.max_severity == "FATAL"
    assert summary.first_seen == "2026-08-30T14:00:00Z"
    assert summary.last_seen == "2026-08-30T14:05:00Z"


def test_summaries_report_the_final_refined_pattern() -> None:
    """Drain3 refines a template as it sees more members; summaries must reflect the end state."""
    templater = DrainTemplater()
    templater.process("Connection to database failed after 3 retries")
    templater.process("Connection to database failed after 9 retries")
    assert "<*>" in templater.summaries()[0].pattern


def test_parameters_are_extracted() -> None:
    templater = DrainTemplater()
    templater.process("Connection failed after 3 retries")
    result = templater.process("Connection failed after 9 retries")
    assert "9" in result.params


# --------------------------------------------------------------- persistence


def test_snapshot_is_written(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "drain3.json"
    templater = DrainTemplater(snapshot_path=path)
    templater.process("Connection to database failed after 3 retries")
    templater.snapshot()
    assert path.exists() and path.stat().st_size > 0


def test_snapshot_contains_no_unredacted_values(tmp_path: Path) -> None:
    """Decision G2: the snapshot is a durable artifact and must not hold secrets.

    Read through `read_snapshot`, not off the file. Drain3 stores base64-encoded compressed
    state, so asserting against the raw bytes would pass no matter what the tree held.
    """
    path = tmp_path / "drain3.json"
    redactor = Redactor()
    templater = DrainTemplater(snapshot_path=path)
    for octet in range(1, 10):
        templater.process(redactor.redact(f"auth failed for ana@corp.com from 10.42.7.{octet}"))
    templater.snapshot()

    content = read_snapshot(path)
    assert "ana@corp.com" not in content
    assert "10.42.7.1" not in content
    # Guards the assertions above: the decoded state must really contain the templates.
    assert "REDACTED" in content


def test_unredacted_values_would_be_visible_in_a_decoded_snapshot(tmp_path: Path) -> None:
    """Control for the test above — proves the leak check can actually fail."""
    path = tmp_path / "drain3.json"
    templater = DrainTemplater(snapshot_path=path)
    templater.process("auth failed for ana@corp.com from 10.42.7.1")
    templater.snapshot()
    assert "ana@corp.com" in read_snapshot(path)


def test_no_snapshot_when_persistence_disabled(tmp_path: Path) -> None:
    templater = DrainTemplater(snapshot_path=None)
    templater.process("anything")
    templater.snapshot()
    assert list(tmp_path.iterdir()) == []


def test_snapshot_decodes_to_valid_json(tmp_path: Path) -> None:
    path = tmp_path / "drain3.json"
    templater = DrainTemplater(snapshot_path=path)
    templater.process("Connection refused")
    templater.snapshot()
    assert isinstance(json.loads(read_snapshot(path)), dict)

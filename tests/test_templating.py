"""Drain3 wrapper behaviour, including the redaction-placeholder masking from decision G2."""

from __future__ import annotations

import json
from pathlib import Path

from pytest import approx

from mistify.redaction.redactor import Redactor
from mistify.templating.drain_wrapper import (
    HEADER_CHARS,
    DrainTemplater,
    mask_header_timestamps,
    read_snapshot,
)


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


def test_parameters_are_extracted_when_asked_for() -> None:
    templater = DrainTemplater()
    templater.process("Connection failed after 3 retries", extract_params=True)
    result = templater.process("Connection failed after 9 retries", extract_params=True)
    assert "9" in result.params


def test_parameters_are_not_extracted_by_default() -> None:
    """Re-matching the template against every line cost about 6% of an ingest, for a list
    nothing in the pipeline ever read. The capability is kept; the hot path does not pay it."""
    templater = DrainTemplater()
    templater.process("Connection failed after 3 retries")
    assert templater.process("Connection failed after 9 retries").params == []


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


# --------------------------------------------------- a snapshot that will not load


def test_a_corrupt_snapshot_costs_a_reclustering_not_the_run(tmp_path: Path) -> None:
    """A killed process leaves a truncated snapshot, and every later run of that incident id
    died on `Error -5 while decompressing data` -- an eval case that had worked an hour before,
    failing for a reason that had nothing to do with its log.

    The inferred-schema cache already treats an unreadable entry as a cache miss. So does this.
    """
    snapshot = tmp_path / "drain3.json"
    snapshot.write_bytes(b"eJwrSS0u0S8pSk0tLlHIzC1ILUpNTgUAVs0Hxg==TRUNCATED")

    templater = DrainTemplater(snapshot_path=snapshot)

    assert templater.snapshot_discarded is not None
    assert "Error" in templater.snapshot_discarded or "error" in templater.snapshot_discarded
    # And it still works: the run continues on a fresh tree.
    templater.process("Connection failed after 3 retries")
    assert templater.unique_templates == 1


def test_a_good_snapshot_is_still_restored(tmp_path: Path) -> None:
    """The control. Tolerating a corrupt snapshot must not mean ignoring a valid one --
    reuse is the whole reason the file exists."""
    snapshot = tmp_path / "drain3.json"
    first = DrainTemplater(snapshot_path=snapshot)
    first.process("Connection failed after 3 retries")
    first.snapshot()

    second = DrainTemplater(snapshot_path=snapshot)

    assert second.snapshot_discarded is None
    assert snapshot.exists()


def test_a_snapshot_is_written_atomically(tmp_path: Path) -> None:
    """Drain3 writes straight over the target, so an interrupted write truncates it. Writing
    to a sibling and renaming means a reader sees the old file or the new one, never half."""
    snapshot = tmp_path / "drain3.json"
    templater = DrainTemplater(snapshot_path=snapshot)
    templater.process("Connection failed after 3 retries")
    templater.snapshot()

    assert snapshot.exists()
    # The temporary file is renamed, not left behind.
    assert not (tmp_path / "drain3.json.tmp").exists()
    assert list(tmp_path.glob("*.tmp")) == []


# --------------------------------------------------------- the transport header


#: The same sentence under twelve syslog headers. The month is the point: `parametrize_numeric
#: _tokens` already generalises anything carrying a digit, so a header that differed only in
#: numbers would collapse on its own and prove nothing. `Nov` and `Dec` are alphabetic, so the
#: templater keeps them and the line fragments once per month -- which is exactly what a
#: transport header does to a real file.
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_SYSLOG_LINE = "{month} 10 00:05:01 src@aadmin1 in.tftpd: tftp client does not accept options"


def test_header_masking_collapses_lines_that_differ_only_in_their_header() -> None:
    """A file nothing parsed still has its transport header in the message."""
    masked = DrainTemplater(sim_th=0.4, mask_header=True)
    for month in _MONTHS:
        masked.process(_SYSLOG_LINE.format(month=month))

    assert masked.unique_templates == 1


def test_without_header_masking_the_same_lines_fragment() -> None:
    """The control. Without it the test above would pass on any templater at all."""
    plain = DrainTemplater(sim_th=0.4, mask_header=False)
    for month in _MONTHS:
        plain.process(_SYSLOG_LINE.format(month=month))

    assert plain.unique_templates > 1


def test_a_timestamp_past_the_header_window_is_left_alone() -> None:
    """Past the window a timestamp is something the application wrote and part of what it said.

    Masking it would merge two genuinely different sentences, which is the failure the narrow
    anchored mask above this one exists to avoid.
    """
    padding = "x" * HEADER_CHARS
    text = f"{padding} deploy started at 2026-08-30T14:00:02Z"

    assert mask_header_timestamps(text).endswith("2026-08-30T14:00:02Z")


def test_the_header_window_is_where_masking_happens() -> None:
    """The other half of the pair: inside the window, it goes."""
    assert "<TS>" in mask_header_timestamps("2026-08-30T14:00:02Z service started")


def test_masking_does_not_merge_genuinely_different_messages() -> None:
    """Fewer templates is only an improvement while distinct conditions stay distinct."""
    templater = DrainTemplater(sim_th=0.4, mask_header=True)
    templater.process("Nov 10 00:05:01 host disk array controller failed")
    templater.process("Nov 10 00:05:02 host kernel page allocation failure")

    assert templater.unique_templates == 2

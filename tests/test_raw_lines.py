"""The last-resort adapter, and the timestamps it now reads instead of inventing.

Reading a timestamp that is present in the text is not a guess. Assigning one that is not is,
and the ordinal fallback is still what happens when nothing readable is there — so every test
that asserts a timestamp was read is paired with one asserting it was not.
"""

from __future__ import annotations

from pathlib import Path

from mistify.adapters.raw_lines import RawLinesAdapter

# A Thunderbird line, verbatim in shape: an epoch, a dotted date, and a syslog date, all three
# on every line and disagreeing about the year.
_THUNDERBIRD = (
    "- 1131523501 2005.11.09 aadmin1 Nov 10 00:05:01 src@aadmin1 "
    "in.tftpd[14620]: tftp: client does not accept options"
)
_SYSLOG = "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 5.36.59.76"
_ISO = "2026-08-30T14:00:02.037152Z ERROR checkout pool exhausted"


def _write(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _parse(path: Path) -> tuple[RawLinesAdapter, list]:
    adapter = RawLinesAdapter()
    return adapter, list(adapter.parse(path))


def test_an_iso_timestamp_is_read_from_the_line(tmp_path: Path) -> None:
    adapter, records = _parse(_write(tmp_path / "iso.log", [_ISO] * 20))

    assert adapter.stats.timestamp_shape == "iso8601"
    assert adapter.stats.unparseable_timestamp == 0
    assert records[0].ts.year == 2026
    assert records[0].ts.month == 8


def test_a_file_with_no_timestamps_still_gets_ordinals(tmp_path: Path) -> None:
    """The control. Without it, every assertion above would pass on a broken adopter."""
    adapter, records = _parse(_write(tmp_path / "plain.log", ["just some text here"] * 20))

    assert adapter.stats.timestamp_shape is None
    assert adapter.stats.unparseable_timestamp == 20
    assert records[0].ts.year == 1970
    assert records[1].ts > records[0].ts


def test_the_year_bearing_shape_wins_when_two_match(tmp_path: Path) -> None:
    """Thunderbird's own line, and the reason the preference order is not the bootstrapper's.

    `syslog` and `epoch` both match every line. `syslog` reads `Nov 10 00:05:01`, has no year
    to read and takes the one at ingest; `epoch` reads `1131523501` and gets 2005.
    """
    adapter, records = _parse(_write(tmp_path / "tbird.log", [_THUNDERBIRD] * 20))

    assert adapter.stats.timestamp_shape == "epoch"
    assert adapter.stats.timestamp_year_inferred is False
    assert records[0].ts.year == 2005


def test_a_yearless_shape_is_adopted_but_declared(tmp_path: Path) -> None:
    """Intervals are sound and absolute dates are not, so the run says which it produced."""
    adapter, records = _parse(_write(tmp_path / "syslog.log", [_SYSLOG] * 20))

    assert adapter.stats.timestamp_shape == "syslog"
    assert adapter.stats.timestamp_year_inferred is True
    assert records[0].ts.month == 12


def test_a_shape_below_the_share_is_not_adopted(tmp_path: Path) -> None:
    """Half a file of timestamps is worse than none: the window would span both.

    The control for the threshold. Without it the adopter would take any shape it saw once.
    """
    adapter, records = _parse(
        _write(tmp_path / "half.log", [_ISO, "no timestamp on this line"] * 10)
    )

    assert adapter.stats.timestamp_shape is None
    assert records[0].ts.year == 1970


def test_a_continuation_line_inherits_the_moment_above_it(tmp_path: Path) -> None:
    """A stack-trace line belongs to the event it is part of, not to 1970.

    One unmatched line among nineteen keeps the file above the share, so the shape is still
    adopted -- and the inherited timestamp is what stops the incident window spanning
    fifty-five years.
    """
    lines = [_ISO] * 19
    lines.insert(5, "    at com.example.Thing.method(Thing.java:42)")
    adapter, records = _parse(_write(tmp_path / "trace.log", lines))

    assert adapter.stats.timestamp_shape == "iso8601"
    assert adapter.stats.unparseable_timestamp == 1
    assert records[5].ts == records[4].ts
    assert records[5].ts.year == 2026


def test_line_number_is_not_stored_when_it_is_the_row_id(tmp_path: Path) -> None:
    """Measured at 22.4 bytes an event on Thunderbird -- 7% of the scratchpad, for the rowid."""
    _, records = _parse(_write(tmp_path / "dense.log", [_ISO] * 5))

    assert all(record.fields == {} for record in records)


def test_line_number_is_stored_once_it_stops_matching(tmp_path: Path) -> None:
    """The control: a blank line shifts source lines away from row numbers, so it is real
    information again and must survive."""
    path = tmp_path / "gappy.log"
    path.write_text(f"{_ISO}\n\n{_ISO}\n", encoding="utf-8")

    _, records = _parse(path)

    assert records[0].fields == {}
    # Third line of the file, second record.
    assert records[1].fields == {"line_number": 3}


def test_detection_still_never_selects_this_adapter(tmp_path: Path) -> None:
    """Reading timestamps must not turn the fallback into a competitor."""
    assert RawLinesAdapter().detect([_ISO] * 10) == 0.0

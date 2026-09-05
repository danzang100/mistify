"""Ingesting a directory of logs as one incident.

Pointing the pipeline at a directory used to fail with a bare `PermissionError` out of
`open()`, which is the first thing anyone tries with an incident -- they almost never arrive as
a single file.

The interesting behaviour is not "it reads several files". It is what has to be true once
several files are in one scratchpad: each record still knows where it came from, a file whose
adapter could not name a source gets named after the file, and a file nobody can read shrinks
the ingest *visibly* rather than quietly.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path

import pytest

from mistify.adapters.multi_file import MultiFileAdapter, log_files
from mistify.common.config import MistifyConfig
from mistify.pipeline import UnknownFormatError, ingest
from mistify.scratchpad.db import ScratchpadDB

SYSLOG = [f"Aug 30 14:{i % 60:02d}:00 host sshd[{i}]: Connection closed" for i in range(50)]

JSONL = [
    json.dumps(
        {
            "timestamp": f"2026-08-30T14:{i % 60:02d}:00Z",
            "level": "ERROR",
            "service": "checkout-service",
            "message": f"pool exhausted after {i}",
        }
    )
    for i in range(50)
]


def _tree(root: Path) -> Path:
    """A directory shaped like a real incident: mixed formats, nested, one file per service."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "sshd.log").write_text("\n".join(SYSLOG) + "\n", encoding="utf-8")
    (root / "checkout.jsonl").write_text("\n".join(JSONL) + "\n", encoding="utf-8")
    nested = root / "svc"
    nested.mkdir(exist_ok=True)
    (nested / "worker.log").write_text("\n".join(SYSLOG) + "\n", encoding="utf-8")
    return root


def _rows(result: object) -> list[dict[str, object]]:
    with ScratchpadDB(result.scratchpad_path) as db:  # type: ignore[attr-defined]
        return [dict(row) for row in db.get_slice(max_lines=10_000)]


def _source_files(result: object) -> set[str]:
    """The `source_file` of every loaded record.

    Read straight from the table rather than through `get_slice`, which projects the columns an
    investigation needs and not the whole `fields_json` blob.
    """
    connection = sqlite3.connect(result.scratchpad_path)  # type: ignore[attr-defined]
    try:
        rows = connection.execute(
            "SELECT json_extract(fields_json, '$.source_file') FROM log_events"
        )
        return {row[0] for row in rows}
    finally:
        connection.close()


# --------------------------------------------------------------- file discovery


def test_files_are_found_recursively_in_a_stable_order(tmp_path: Path) -> None:
    """Sorted, because the same directory ingested twice has to give the same scratchpad."""
    root = _tree(tmp_path / "logs")
    found = [p.relative_to(root).as_posix() for p in log_files(root)]
    assert found == ["checkout.jsonl", "sshd.log", "svc/worker.log"]


def test_hidden_and_build_directories_are_skipped(tmp_path: Path) -> None:
    """A log directory routinely also holds `.DS_Store` and a `.git`, and neither is an incident."""
    root = _tree(tmp_path / "logs")
    (root / ".DS_Store").write_bytes(b"\x00\x01")
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "x.pyc").write_bytes(b"\x00")
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    found = [p.name for p in log_files(root)]
    assert found == ["checkout.jsonl", "sshd.log", "worker.log"]


# --------------------------------------------------------------- reading a directory


def test_a_directory_of_mixed_formats_reads_every_file(
    tmp_path: Path, config: MistifyConfig
) -> None:
    result = ingest(_tree(tmp_path / "logs"), config, incident_id="dir")
    assert result.events_loaded == len(SYSLOG) * 2 + len(JSONL)


def test_a_mixed_directory_reports_the_formats_it_found(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """ "multi_file" alone would not tell a reader whether to trust the timestamps."""
    result = ingest(_tree(tmp_path / "logs"), config, incident_id="dir")
    assert result.format_name == "multi:json_lines+raw_lines"


def test_a_uniform_directory_reports_its_actual_format(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """The control on the test above.

    A directory whose files all read one way *is* that format, and a wrapper name would make
    the metric useless for the case that is not mixed at all.
    """
    root = tmp_path / "logs"
    root.mkdir()
    (root / "a.jsonl").write_text("\n".join(JSONL) + "\n", encoding="utf-8")
    (root / "b.jsonl").write_text("\n".join(JSONL) + "\n", encoding="utf-8")

    result = ingest(root, config, incident_id="dir")
    assert result.format_name == "json_lines"
    assert result.events_loaded == len(JSONL) * 2


def test_every_record_carries_the_file_it_came_from(tmp_path: Path, config: MistifyConfig) -> None:
    """Two services can log the identical sentence; the file is what separates them."""
    result = ingest(_tree(tmp_path / "logs"), config, incident_id="dir")
    assert _source_files(result) == {"checkout.jsonl", "sshd.log", "svc/worker.log"}


def test_a_filename_names_a_source_the_adapter_could_not(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """A raw-lines read reports `unknown`, which is fine for one file and useless for forty."""
    result = ingest(_tree(tmp_path / "logs"), config, incident_id="dir")
    sources = {row["source"] for row in _rows(result)}
    assert "sshd" in sources
    assert "worker" in sources
    assert "unknown" not in sources


def test_a_source_the_adapter_did_name_is_left_alone(tmp_path: Path, config: MistifyConfig) -> None:
    """The control: the filename fills a gap, it does not overrule the data.

    Without this the JSON records would all be relabelled `checkout` after their file, losing
    the service each line actually names -- which is worse than the problem being solved.
    """
    result = ingest(_tree(tmp_path / "logs"), config, incident_id="dir")
    sources = {row["source"] for row in _rows(result)}
    assert "checkout-service" in sources
    assert "checkout" not in sources


def test_a_compression_suffix_does_not_become_the_service_name(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """`Path.stem` leaves `worker.log.gz` as `worker.log`. Compression is not part of a name."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "worker.log.gz").write_bytes(gzip.compress(("\n".join(SYSLOG) + "\n").encode()))

    result = ingest(root, config, incident_id="dir")
    assert {row["source"] for row in _rows(result)} == {"worker"}
    assert result.events_loaded == len(SYSLOG)


# --------------------------------------------------------------- degrading visibly


def test_an_unreadable_file_is_skipped_and_counted(tmp_path: Path, config: MistifyConfig) -> None:
    """One PNG must not fail the ingest, and must not silently shrink it either."""
    root = _tree(tmp_path / "logs")
    (root / "screenshot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 40)

    result = ingest(root, config, incident_id="dir")

    assert result.events_loaded == len(SYSLOG) * 2 + len(JSONL)
    with ScratchpadDB(result.scratchpad_path) as db:
        metrics = {(m["stage"], m["metric"]): m["value"] for m in db.metrics()}
    assert "skipped as unreadable" in str(metrics[("ingest", "fallback_reason")])


def test_the_readable_files_are_all_still_read(tmp_path: Path, config: MistifyConfig) -> None:
    """The control on the skip: dropping the bad file must not drop anything else with it."""
    root = _tree(tmp_path / "logs")
    (root / "screenshot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 40)

    result = ingest(root, config, incident_id="dir")
    assert _source_files(result) == {"checkout.jsonl", "sshd.log", "svc/worker.log"}


def test_a_directory_of_nothing_readable_refuses(tmp_path: Path, config: MistifyConfig) -> None:
    """Degrading is right when there is something to degrade to. Here there is nothing."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "a.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    (root / "b.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

    with pytest.raises(UnknownFormatError, match="could be read as a log file"):
        ingest(root, config, incident_id="dir")


def test_an_empty_directory_refuses(tmp_path: Path, config: MistifyConfig) -> None:
    root = tmp_path / "logs"
    root.mkdir()
    with pytest.raises(UnknownFormatError, match="no files to read"):
        ingest(root, config, incident_id="dir")


# --------------------------------------------------------------- the adapter itself


def test_counters_are_the_sum_of_the_members(tmp_path: Path) -> None:
    """The pipeline reads `stats` straight after the parse loop, so they have to be totalled
    as members finish rather than assembled afterwards."""
    root = _tree(tmp_path / "logs")
    from mistify.adapters.raw_lines import RawLinesAdapter

    members = [(p, RawLinesAdapter()) for p in log_files(root)]
    adapter = MultiFileAdapter(members, root)
    records = list(adapter.parse(root))

    assert adapter.stats.records_emitted == len(records)
    assert adapter.stats.lines_read == len(records)


def test_fresh_keeps_the_members_and_resets_the_counters(tmp_path: Path) -> None:
    """Calibration needs a second pass with clean counters, and must not lose the members."""
    root = _tree(tmp_path / "logs")
    from mistify.adapters.raw_lines import RawLinesAdapter

    adapter = MultiFileAdapter([(p, RawLinesAdapter()) for p in log_files(root)], root)
    list(adapter.parse(root))

    fresh = adapter.fresh()
    assert [p for p, _ in fresh.members] == [p for p, _ in adapter.members]
    assert fresh.stats.records_emitted == 0
    assert len(list(fresh.parse(root))) == len(SYSLOG) * 3


def test_a_directory_never_wins_detection(tmp_path: Path) -> None:
    """It is constructed deliberately by the pipeline, exactly as `raw_lines` is."""
    root = _tree(tmp_path / "logs")
    assert MultiFileAdapter([], root).detect(["anything at all"]) == 0.0


def test_the_same_directory_twice_gives_the_same_incident(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """Filesystem order is not stable; a scratchpad rebuilt from the same directory must be."""
    root = _tree(tmp_path / "logs")
    first = _rows(ingest(root, config, incident_id="one"))
    second = _rows(ingest(root, config, incident_id="two"))
    assert [row["message"] for row in first] == [row["message"] for row in second]


# ------------------------------------------------- the warning a wrapper used to suppress


def test_a_directory_read_partly_in_raw_lines_still_fires_the_fallback_warning(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """The report's strongest warning fires on the exact value `raw_lines`.

    A wrapper reports a composite `format_name`, so the trigger matched nothing and the run
    printed a log window running from 1970 to the present as though it were a fact -- the
    precise thing `INGEST_FALLBACK`'s own docstring says a report must never do.
    """
    from mistify.metrics import INGEST_FALLBACK, MetricView

    result = ingest(_tree(tmp_path / "logs"), config, incident_id="partial")

    assert result.format_name.startswith("multi:")
    with ScratchpadDB(result.scratchpad_path) as db:
        assert MetricView(db.metrics()).triggers(INGEST_FALLBACK)


def test_a_directory_that_degraded_nowhere_does_not_fire_it(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """The control, and the reason this is not simply "directories always warn".

    A trigger that fired for every directory would be indistinguishable from one that worked
    and would train a reader to skip the section it appears in.
    """
    from mistify.metrics import INGEST_FALLBACK, MetricView

    root = tmp_path / "clean"
    root.mkdir()
    (root / "a.jsonl").write_text("\n".join(JSONL) + "\n", encoding="utf-8")
    (root / "b.jsonl").write_text("\n".join(JSONL) + "\n", encoding="utf-8")

    result = ingest(root, config, incident_id="clean")

    assert result.format_name == "json_lines"
    with ScratchpadDB(result.scratchpad_path) as db:
        assert not MetricView(db.metrics()).triggers(INGEST_FALLBACK)


def test_confidence_is_the_best_a_member_managed_not_zero(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """`scores` is keyed by format, and a wrapper's name is not one of those keys.

    Looking it up returned 0.0 for a directory in which JSON Lines had matched at 1.0, which
    reads as "nothing recognised this" -- the opposite of what happened.
    """
    from mistify.metrics import INGEST_DETECT_CONFIDENCE, MetricView

    result = ingest(_tree(tmp_path / "logs"), config, incident_id="confidence")

    with ScratchpadDB(result.scratchpad_path) as db:
        confidence = MetricView(db.metrics()).number(INGEST_DETECT_CONFIDENCE)
    assert confidence is not None and confidence > 0.9


def test_the_warning_says_how_much_of_the_source_was_degraded(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """A partly-recognised directory must not claim it has no timestamps at all.

    Overstating the damage is its own way of making a warning ignorable: most of these events
    do have real timestamps, and a reader who checks will stop believing the next warning too.
    """
    from mistify.report.generator import generate_report

    result = ingest(_tree(tmp_path / "logs"), config, incident_id="wording")
    with ScratchpadDB(result.scratchpad_path) as db:
        text = generate_report(db)

    # The syslog files in this tree carry readable timestamps, so the fallback reads them and
    # the warning must say so rather than claiming the window is meaningless. What is still
    # degraded is the *structure* -- no parsed fields, severity guessed from the text.
    assert "read one line at a time" in text
    assert "Timestamps were read from each line as `syslog`" in text
    assert "carries no year" in text
    assert "There are no parsed timestamps" not in text


def test_component_formats_enumerates_what_the_summary_hides(tmp_path: Path) -> None:
    """The property the fix turns on, asserted directly rather than only through a report."""
    from mistify.adapters.json_lines import JsonLinesAdapter
    from mistify.adapters.raw_lines import RawLinesAdapter

    root = _tree(tmp_path / "logs")
    adapter = MultiFileAdapter(
        [(root / "checkout.jsonl", JsonLinesAdapter()), (root / "sshd.log", RawLinesAdapter())],
        root,
    )

    assert adapter.component_formats == {"json_lines", "raw_lines"}
    # A plain adapter answers for itself, so nothing else in the codebase needs a special case.
    assert JsonLinesAdapter().component_formats == {"json_lines"}

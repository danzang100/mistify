"""End-to-end ingestion, and the stage-ordering guarantees from decisions G1 and G2."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mistify.common.config import MistifyConfig
from mistify.common.models import severity_rank
from mistify.eval.fixtures import (
    PLANTED_API_KEY,
    PLANTED_EMAILS,
    PLANTED_IPS,
    ROOT_CAUSE_MARKER,
)
from mistify.metrics import (
    INGEST_FALLBACK,
    INGEST_FALLBACK_REASON,
    INGEST_LINES_READ,
    INGEST_PARSE_ERRORS,
    REDACTION_MODE,
    REDACTION_TOTAL,
    SCRATCHPAD_ORPHAN_EVENTS,
    TEMPLATING_COMPRESSION_RATIO,
    TEMPLATING_REDUCTION_FACTOR,
    TEMPLATING_UNIQUE_TEMPLATES,
    MetricView,
)
from mistify.pipeline import IngestResult, UnknownFormatError, derive_incident_id, ingest
from mistify.scratchpad.db import ScratchpadDB
from mistify.templating.drain_wrapper import read_snapshot

# --------------------------------------------------------------- basic load


def test_ingest_loads_every_parsable_line(ingested: IngestResult) -> None:
    assert ingested.events_loaded == ingested.lines_read
    assert ingested.parse_errors == 0
    assert ingested.format_name == "json_lines"


def test_ingest_compresses(ingested: IngestResult) -> None:
    """The whole premise: far fewer templates than lines."""
    assert ingested.unique_templates < ingested.events_loaded / 20
    assert 0.0 < ingested.compression_ratio < 0.05


def test_events_and_templates_are_consistent(loaded_db: ScratchpadDB) -> None:
    assert loaded_db.orphan_event_count() == 0
    assert loaded_db.event_count() > 0
    assert loaded_db.template_count() > 0


def test_incident_row_is_created(loaded_db: ScratchpadDB) -> None:
    incident = loaded_db.incident()
    assert incident is not None
    assert incident["incident_id"] == "test-incident"
    assert incident["format"] == "json_lines"


def test_planted_root_cause_survives_templating(loaded_db: ScratchpadDB) -> None:
    patterns = [t["pattern"] for t in loaded_db.top_templates(limit=500, order_by="count")]
    assert any(ROOT_CAUSE_MARKER in p for p in patterns)


# --------------------------------------------------------------- decision G1


@pytest.mark.parametrize("secret", [*PLANTED_EMAILS, *PLANTED_IPS, PLANTED_API_KEY])
def test_no_planted_secret_reaches_the_scratchpad(loaded_db: ScratchpadDB, secret: str) -> None:
    """Redaction runs immediately after parse(), so nothing downstream ever sees a value."""
    # Asked through the read-only channel rather than the private connection: this is the
    # surface an investigator queries, so a leak is checked where a leak would be found.
    for table, columns in (
        ("log_events", ("raw", "message", "fields_json")),
        ("templates", ("pattern",)),
    ):
        for column in columns:
            rows = loaded_db.run_readonly_sql(
                f"SELECT COUNT(*) AS n FROM {table} WHERE {column} LIKE '%{secret}%'"
            )
            assert rows[0]["n"] == 0, f"{secret!r} leaked into {table}.{column}"


def test_redaction_actually_fired(ingested: IngestResult) -> None:
    """A zero count would make the test above pass for the wrong reason."""
    assert ingested.redaction_counts.get("email", 0) > 0
    assert ingested.redaction_counts.get("ipv4", 0) > 0
    assert ingested.redaction_counts.get("api_key", 0) > 0


def test_placeholders_are_present_in_stored_events(loaded_db: ScratchpadDB) -> None:
    rows = loaded_db.run_readonly_sql(
        "SELECT COUNT(*) AS n FROM log_events WHERE raw LIKE '%[IPV4:%'"
    )
    assert rows[0]["n"] > 0


def test_correlation_survives_redaction(loaded_db: ScratchpadDB) -> None:
    """The same address must map to one token, or the investigator loses the join key."""
    rows = loaded_db.run_readonly_sql(
        "SELECT DISTINCT fields_json FROM log_events WHERE fields_json LIKE '%client_ip%'"
    )
    tokens = {json.loads(r["fields_json"])["client_ip"] for r in rows}
    assert 0 < len(tokens) <= len(PLANTED_IPS)


# --------------------------------------------------------------- decision G2


@pytest.mark.parametrize("secret", [*PLANTED_EMAILS, *PLANTED_IPS, PLANTED_API_KEY])
def test_no_planted_secret_reaches_the_drain3_snapshot(
    ingested: IngestResult, config: MistifyConfig, secret: str
) -> None:
    """The snapshot is a durable on-disk artifact and must not become a secret store."""
    snapshot = config.snapshot_path(ingested.incident_id)
    assert snapshot is not None and snapshot.exists()
    # Decoded, not raw: the snapshot is base64-encoded compressed JSON, so scanning the
    # file bytes would pass regardless of what the tree actually holds.
    assert secret not in read_snapshot(snapshot)


# --------------------------------------------------------------- decision G7


def test_every_stage_reports_health_metrics(loaded_db: ScratchpadDB) -> None:
    view = MetricView(loaded_db.metrics())
    for expected in (
        INGEST_LINES_READ,
        INGEST_PARSE_ERRORS,
        REDACTION_MODE,
        REDACTION_TOTAL,
        TEMPLATING_COMPRESSION_RATIO,
        TEMPLATING_UNIQUE_TEMPLATES,
        SCRATCHPAD_ORPHAN_EVENTS,
    ):
        assert expected in view, f"missing health metric {expected}"


def test_compression_ratio_metric_matches_the_result(
    ingested: IngestResult, loaded_db: ScratchpadDB
) -> None:
    view = MetricView(loaded_db.metrics("templating"))
    assert view.number(TEMPLATING_COMPRESSION_RATIO) == pytest.approx(
        ingested.compression_ratio, abs=1e-4
    )


# --------------------------------------------------------------- errors and options


def test_parse_errors_are_surfaced(tmp_path: Path, config: MistifyConfig) -> None:
    source = tmp_path / "mixed.jsonl"
    source.write_text(
        '{"timestamp": "2026-08-30T14:00:00Z", "level": "INFO", "message": "ok"}\n'
        "{broken\n"
        '{"timestamp": "2026-08-30T14:00:01Z", "level": "INFO", "message": "ok"}\n',
        encoding="utf-8",
    )
    result = ingest(source, config, incident_id="mixed")
    assert result.events_loaded == 2
    assert result.parse_errors == 1


def _syslog(tmp_path: Path) -> Path:
    source = tmp_path / "syslog.log"
    source.write_text(
        ("Aug 30 14:22:01 host sshd[1]: Accepted password" + chr(10)) * 20, encoding="utf-8"
    )
    return source


def test_an_unrecognised_file_falls_back_to_raw_lines(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """Degrade rather than refuse.

    An investigation that cannot start is not safer than one that starts with less: templating,
    ranking and search all work on message text alone.
    """
    result = ingest(_syslog(tmp_path), config, incident_id="syslog")

    assert result.format_name == "raw_lines"
    assert result.events_loaded == 20


def test_the_fallback_records_why_it_happened(tmp_path: Path, config: MistifyConfig) -> None:
    """The load-bearing half.

    A raw-line read has no parsed timestamps, so the incident window and the burstiness term
    describe the order lines appear in the file. A report that did not say so would present
    those numbers as facts about the incident.
    """
    ingest(_syslog(tmp_path), config, incident_id="syslog")

    with ScratchpadDB(config.scratchpad_path("syslog")) as db:
        view = MetricView(db.metrics())

    assert view.text(INGEST_FALLBACK) == "raw_lines"
    assert "best confidence" in (view.text(INGEST_FALLBACK_REASON) or "")


def test_a_recognised_file_records_no_fallback(incident_file: Path, config: MistifyConfig) -> None:
    """Control: the marker means something happened, so it must be absent when it did not."""
    ingest(incident_file, config, incident_id="known")

    with ScratchpadDB(config.scratchpad_path("known")) as db:
        assert MetricView(db.metrics()).text(INGEST_FALLBACK) is None


def test_the_fallback_can_be_turned_off(tmp_path: Path, config: MistifyConfig) -> None:
    """Where a wrong-looking parse is worse than no parse, refusing is the right answer."""
    strict = config.model_copy(deep=True)
    strict.adapters.on_unknown_format = "error"

    with pytest.raises(UnknownFormatError, match="no registered adapter matched"):
        ingest(_syslog(tmp_path), strict, incident_id="syslog")


def test_unregistered_forced_format_raises_unknown_format(
    incident_file: Path, config: MistifyConfig
) -> None:
    """A typo in --format must reach the CLI as the error it catches, not as a traceback.

    The registry raises ValueError for a name it does not know; the CLI only handles
    UnknownFormatError, so the translation has to happen here.
    """
    with pytest.raises(UnknownFormatError, match="json_lines"):
        ingest(incident_file, config, incident_id="bogus", format_name="not_a_format")


def test_missing_source_raises(config: MistifyConfig) -> None:
    with pytest.raises(FileNotFoundError):
        ingest("does-not-exist.jsonl", config)


def test_forced_format_skips_detection(incident_file: Path, config: MistifyConfig) -> None:
    result = ingest(incident_file, config, incident_id="forced", format_name="json_lines")
    assert result.format_name == "json_lines"


def test_redaction_off_leaves_values_intact(
    incident_file: Path, make_config: Callable[..., MistifyConfig]
) -> None:
    config = make_config(redaction={"mode": "off"})
    result = ingest(incident_file, config, incident_id="off")
    with ScratchpadDB(result.scratchpad_path) as db:
        rows = db.run_readonly_sql(
            f"SELECT COUNT(*) AS n FROM log_events WHERE raw LIKE '%{PLANTED_API_KEY}%'"
        )
    assert rows[0]["n"] > 0


def test_reingesting_replaces_the_scratchpad(incident_file: Path, config: MistifyConfig) -> None:
    first = ingest(incident_file, config, incident_id="repeat")
    second = ingest(incident_file, config, incident_id="repeat")
    assert first.events_loaded == second.events_loaded
    with ScratchpadDB(second.scratchpad_path) as db:
        assert db.event_count() == second.events_loaded


# --------------------------------------------------------------- decision G6


def test_derive_incident_id_is_dated_and_slugged() -> None:
    incident_id = derive_incident_id("logs/Checkout Service.jsonl")
    assert incident_id.endswith("-checkout-service")
    assert len(incident_id.split("-")) >= 4


def test_derive_incident_id_handles_odd_names() -> None:
    assert derive_incident_id("logs/___.jsonl").endswith("-incident")


# --------------------------------------------------------------- template coverage


#: A message shape per line, so Drain3 has nothing to merge and must keep allocating clusters.
HIGH_CARDINALITY_LINES = 2000

#: The one severe line hidden in that noise. Six words, none of them shared with the noise
#: shapes, so it cannot be absorbed into a neighbouring cluster.
NEEDLE_MESSAGE = "Storage engine halted after unrecoverable checksum mismatch"


@pytest.fixture(scope="session")
def high_cardinality_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A file with no repeated structure, carrying one rare FATAL line.

    Every message is a genuinely distinct shape, which is the input Drain3 handles worst:
    nothing clusters, so the tree fills and starts evicting. The FATAL line is the needle -
    one line in two thousand, and the only severe thing in the file.
    """
    start = datetime(2026, 8, 30, 14, 0, 0, tzinfo=UTC)
    lines = [
        {
            "timestamp": (start + timedelta(seconds=i)).isoformat().replace("+00:00", "Z"),
            "service": "checkout-service",
            "level": "INFO",
            "message": f"shape{i} alpha{i} beta{i} gamma{i}",
        }
        for i in range(HIGH_CARDINALITY_LINES)
    ]
    lines.insert(
        HIGH_CARDINALITY_LINES // 2,
        {
            "timestamp": (start + timedelta(seconds=1000, milliseconds=500))
            .isoformat()
            .replace("+00:00", "Z"),
            "service": "checkout-service",
            "level": "FATAL",
            "message": NEEDLE_MESSAGE,
        },
    )
    path = tmp_path_factory.mktemp("high-cardinality") / "high_cardinality.jsonl"
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture(scope="session")
def high_cardinality_ingest(
    high_cardinality_file: Path, tmp_path_factory: pytest.TempPathFactory
) -> IngestResult:
    """That file ingested with a max_clusters small enough to force eviction.

    Calibration is off so the threshold is the one under test rather than one chosen from a
    sample, and `max_clusters` is far below the number of shapes in the file.

    Session-scoped and shared rather than copied: both readers of this fixture only read, and
    forcing eviction over two thousand distinct shapes is the most expensive ingest in the
    suite. Any test that starts writing to it needs its own copy.
    """
    directory = tmp_path_factory.mktemp("high-cardinality-ingest")
    config = MistifyConfig.model_validate(
        {
            "drain3": {
                "max_clusters": 50,
                "calibrate": False,
                "snapshot_path": str(directory / "hc_{incident_id}.json"),
            },
            "scratchpad": {"path": str(directory / "hc_{incident_id}.sqlite")},
        }
    )
    return ingest(high_cardinality_file, config, incident_id="high-cardinality")


def test_every_event_reaches_a_template(ingested: IngestResult, loaded_db: ScratchpadDB) -> None:
    """Coverage, not compression, is the load invariant: no event may be unreachable."""
    assert ingested.template_coverage == 1.0
    assert loaded_db.orphan_event_count() == 0


def test_eviction_does_not_orphan_the_file(high_cardinality_ingest: IngestResult) -> None:
    """The regression: Drain3's LRU eviction used to take events' templates with it.

    Reading final statistics off Drain3's own tree meant every event assigned to an evicted
    cluster pointed at a template row that was never written. On this file that orphaned
    about 98% of the input - while the compression ratio reported a healthy-looking number,
    because a ratio counts templates it can still see. The templater now keeps its own
    registry, so eviction costs matching, not reachability.
    """
    assert high_cardinality_ingest.template_coverage == 1.0
    assert high_cardinality_ingest.evicted_templates > 0
    with ScratchpadDB(high_cardinality_ingest.scratchpad_path) as db:
        assert db.orphan_event_count() == 0
        assert db.event_count() == high_cardinality_ingest.events_loaded


def test_the_rare_fatal_line_still_ranks_first(high_cardinality_ingest: IngestResult) -> None:
    """The needle-in-a-haystack guarantee, and the whole point of keeping the registry.

    One FATAL line among two thousand distinct shapes, most of whose clusters were evicted
    mid-run. It must still be the first thing an agent reading the ranked list would meet.
    """
    with ScratchpadDB(high_cardinality_ingest.scratchpad_path) as db:
        top = db.top_templates(limit=1, order_by="anomaly_score")
    assert NEEDLE_MESSAGE in top[0]["pattern"]
    assert top[0]["max_severity_rank"] == severity_rank("FATAL")


def test_batching_does_not_change_what_is_loaded(
    incident_file: Path,
    config: MistifyConfig,
    ingested: IngestResult,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Events stream to SQLite in batches, so the batch size must be invisible in the result.

    A tiny batch exercises the flush path on nearly every line, including the trailing
    partial batch that a `>=` check alone would drop.
    """
    monkeypatch.setattr("mistify.pipeline.EVENT_BATCH_SIZE", 7)
    result = ingest(incident_file, config, incident_id="streamed")

    assert result.events_loaded == ingested.events_loaded
    with ScratchpadDB(result.scratchpad_path) as db:
        assert db.event_count() == result.events_loaded
        assert db.orphan_event_count() == 0


def test_reduction_factor_is_lines_per_template(
    ingested: IngestResult, loaded_db: ScratchpadDB
) -> None:
    """How much less the agent reads, which is the number compression was a proxy for."""
    expected = ingested.events_loaded / ingested.unique_templates
    view = MetricView(loaded_db.metrics("templating"))
    assert ingested.reduction_factor == pytest.approx(expected)
    assert view.number(TEMPLATING_REDUCTION_FACTOR) == pytest.approx(expected, abs=0.01)


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def test_a_fallback_read_masks_its_transport_header(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """End to end, not through the flag: twelve headers over one sentence is one template.

    The month is what makes this discriminating -- Drain3 already generalises tokens carrying
    digits, so a header differing only in numbers would collapse without any masking and the
    test would assert nothing.
    """
    source = tmp_path / "syslog.log"
    source.write_text(
        "\n".join(
            f"{m} 10 00:05:01 src@host in.tftpd: tftp client does not accept options"
            for m in _MONTHS
        )
        + "\n",
        encoding="utf-8",
    )

    result = ingest(source, config, incident_id="masked")

    assert result.format_name == "raw_lines"
    assert result.unique_templates == 1


def test_a_parsed_format_keeps_the_timestamps_in_its_message(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """The control. A parsed message is already the message, and a time inside it is content.

    Twelve JSON records whose *message* names a different month must stay twelve things, not
    be collapsed by a mask that has no business running here.
    """
    source = tmp_path / "app.jsonl"
    source.write_text(
        "\n".join(
            json.dumps(
                {
                    "timestamp": "2026-08-30T14:00:02Z",
                    "level": "INFO",
                    "service": "billing",
                    # The month leads the message on purpose. Drain3 buckets on the first
                    # tokens, so a varying leading token is what splits clusters -- put it
                    # later and these merge on similarity whether or not anything is masked,
                    # and the test proves nothing either way.
                    "message": f"{m} 10 00:05:01 reconciliation cycle completed",
                }
            )
            for m in _MONTHS
        )
        + "\n",
        encoding="utf-8",
    )

    result = ingest(source, config, incident_id="parsed")

    assert result.format_name == "json_lines"
    assert result.unique_templates > 1

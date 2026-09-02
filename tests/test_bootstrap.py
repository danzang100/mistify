"""The unknown-format bootstrapper.

No model is called anywhere here: the structural pass is the majority of the stage and is pure,
and the inference path is driven through a stand-in provider so its *checking* is what gets
tested rather than a model's mood.

What these pin is mostly refusal. Architecture §2.2a's risk table lists this stage's failure as
silent -- a confidently wrong schema produces templates that are garbage with no error thrown --
so nearly every test below is about the gate saying no, and each one is paired with a case that
makes it say yes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mistify.bootstrap import bootstrap_format
from mistify.bootstrap.adapter import InferredAdapter, load_schemas, save_schema
from mistify.bootstrap.inference import diverse_sample, infer_with_model
from mistify.bootstrap.schema import FieldSchema, match_rate
from mistify.bootstrap.shapes import cluster_shapes, infer_structurally
from mistify.llm.base import Turn

SYSLOG = [f"Aug 30 14:22:{i % 60:02d} host sshd[{i}]: Accepted password" for i in range(200)]
ISO = [f"2026-08-30T14:{i % 60:02d}:00Z ERROR checkout pool exhausted" for i in range(200)]
BRACKET = [f"[2026-08-30 14:{i % 60:02d}:00] [WARN] slow query took {i}ms" for i in range(200)]
LOGFMT = [f'ts=2026-08-30T14:{i % 60:02d}:00Z level=error msg="pool gone"' for i in range(200)]
JUNK = [f"{i},alpha,beta" for i in range(200)]


class _ScriptedProvider:
    """Returns one canned reply and records the prompt it was given."""

    name = "scripted"
    model = "bootstrap-model"
    supports_task_budget = False

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.prompts: list[str] = []

    def converse(self, system, messages, tools=None, max_tokens=8192, task_budget_tokens=None):
        self.prompts.append(messages[0].text)
        return Turn(text=self.reply, stop_reason="end_turn")


# ------------------------------------------------------- structure alone


@pytest.mark.parametrize(
    ("name", "lines"),
    [("syslog", SYSLOG), ("iso", ISO), ("bracket", BRACKET), ("logfmt", LOGFMT)],
)
def test_common_formats_are_read_without_a_model(name: str, lines: list[str]) -> None:
    """The structural pass is the point of the stage: these never reach a prompt.

    Most unknown formats are unknown only in the sense that nobody wrote an adapter -- they
    still start with a timestamp and name a level.
    """
    result = bootstrap_format(lines)

    assert result.succeeded, result.reason
    assert result.route == "structural"
    assert result.match_rate == 1.0


def test_a_file_with_no_timestamp_is_refused() -> None:
    """The one thing this stage cannot work around.

    Every later stage orders on time; inventing a timestamp would make the incident window
    fiction rather than merely coarse.
    """
    result = bootstrap_format(JUNK)

    assert not result.succeeded
    assert "no timestamp" in result.reason


def test_a_file_that_will_not_parse_says_so_accurately() -> None:
    """A timestamp was found and nothing matched -- a different failure from having none.

    Reporting "no timestamp shape found" for a file that has one is a wrong diagnosis of a
    real failure, and it is what this returned before the best-candidate tracking was fixed.
    """
    lines = [f"2026-08-30T14:{i % 60:02d}:00Z|field|field|field" for i in range(200)]
    lines = [line.replace("Z|", "Z\x01") for line in lines]  # a delimiter no schema expresses

    result = bootstrap_format(lines)

    assert not result.succeeded
    assert "matched only" in result.reason


def test_the_gate_is_measured_on_lines_the_inference_never_saw() -> None:
    """A schema fits the sample it was derived from by construction.

    If the first hundred lines are one shape and the rest are another, a gate scored on the
    sample passes a schema that reads a fraction of the file.
    """
    lines = ISO[:100] + JUNK[:100]

    result = bootstrap_format(lines, sample_size=100)

    assert not result.succeeded
    assert result.match_rate == 0.0


def test_a_short_file_says_its_rate_was_measured_on_the_sample() -> None:
    """Control for the holdout: with too few lines to hold any back, reuse is stated.

    Weaker evidence should be labelled weaker rather than left for a reader to infer from a
    line count they cannot see.
    """
    result = bootstrap_format(ISO[:20], sample_size=100)

    assert result.succeeded
    assert "too short to hold lines back" in result.reason


# ------------------------------------------------------------ the model path


def test_the_model_is_only_asked_when_structure_fails() -> None:
    """Every line structure handles is a line that never reaches a prompt."""
    provider = _ScriptedProvider("{}")

    bootstrap_format(ISO, provider=provider)

    assert provider.prompts == []


def test_a_model_reading_that_is_not_in_the_line_is_discarded() -> None:
    """A paraphrased or invented timestamp describes a line other than the one it was given.

    This is the check that turns the architecture's silent failure into a loud one: a claim
    that cannot be found in its own line is dropped rather than averaged in.
    """
    lines = [f"2026-08-30T14:{i % 60:02d}:00Z\x01payload" for i in range(200)]
    reply = json.dumps(
        {"lines": [{"n": 1, "timestamp": "30 August 2026, 2pm", "severity": "", "message": "x"}]}
    )

    assert infer_with_model(_ScriptedProvider(reply), lines) is None


def test_a_model_reading_that_checks_out_produces_a_schema() -> None:
    """Control for the rejection above: a quoted substring that is really there is used."""
    lines = [f"2026-08-30T14:{i % 60:02d}:00Z ERROR pool gone" for i in range(200)]
    reply = json.dumps(
        {
            "lines": [
                {
                    "n": 1,
                    "timestamp": "2026-08-30T14:00:00Z",
                    "severity": "ERROR",
                    "message": "pool gone",
                }
            ]
        }
    )

    schema = infer_with_model(_ScriptedProvider(reply), lines)

    assert schema is not None
    assert schema.timestamp == "iso8601"
    assert schema.origin == "model"


def test_an_unreadable_model_reply_is_not_a_schema() -> None:
    assert infer_with_model(_ScriptedProvider("I think it is ISO format"), ISO) is None


def test_the_model_sees_a_deduplicated_spread_not_the_first_lines() -> None:
    """Sequential log lines repeat; a raw prefix shows one shape many times over."""
    lines = ["2026-08-30T14:00:00Z ERROR same"] * 50 + ["2026-08-30T14:00:01Z WARN other"]

    sample = diverse_sample(lines)

    assert len(sample) == 2


# --------------------------------------------------------------- sub-shapes


def test_a_file_of_two_shapes_is_clustered() -> None:
    """Stack traces mixed with key-value lines is the case §2.2a names."""
    shapes = cluster_shapes(ISO[:50] + SYSLOG[:50])

    assert len(shapes) >= 2


def test_the_commonest_shape_is_used_when_one_schema_cannot_cover_the_file() -> None:
    """A partial read that says it is partial beats refusing the file.

    The result has to admit what it will not read: lines of the other shapes are dropped, and a
    reader who is not told that will read the event counts as complete.
    """
    result = bootstrap_format(ISO[:150] + JUNK[:50], sample_size=200)

    assert result.route == "sub-shape"
    assert "will not be read" in result.reason


# ------------------------------------------------------- adapter and store


def test_the_inferred_adapter_parses_what_the_schema_describes(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_text(chr(10).join(BRACKET), encoding="utf-8")
    schema = bootstrap_format(BRACKET).schema
    assert schema is not None

    adapter = InferredAdapter(schema)
    records = list(adapter.parse(path))

    assert len(records) == len(BRACKET)
    assert adapter.stats.parse_errors == 0
    assert {r.severity for r in records} == {"WARN"}
    assert records[0].message.startswith("slow query")


def test_the_inferred_adapter_reports_the_share_it_can_actually_read() -> None:
    """A measured rate, not a confident constant.

    An inferred adapter half-fitting a different file must lose to one written for it, and the
    only honest way to arrange that is to report what it really parses.
    """
    schema = bootstrap_format(ISO).schema
    assert schema is not None
    adapter = InferredAdapter(schema)

    assert adapter.detect(ISO[:20]) == 1.0
    assert adapter.detect(JUNK[:20]) == 0.0


def test_a_schema_round_trips_through_the_store(tmp_path: Path) -> None:
    """The reuse path: the second file from a source should cost nothing."""
    schema = FieldSchema(timestamp="iso8601", has_severity=True, origin="model", validated_rate=0.9)
    save_schema(schema, tmp_path, "inferred_iso8601")

    loaded = load_schemas(tmp_path)

    assert loaded["inferred_iso8601"] == schema


def test_a_persisted_schema_cannot_smuggle_in_a_pattern(tmp_path: Path) -> None:
    """`timestamp` names a member of a fixed vocabulary; reloading is a lookup, not an eval.

    A cache entry is a file on disk that anyone can edit, and a stored regex would be a pattern
    nobody reviewed running against every future file from that source.
    """
    (tmp_path / "evil.json").write_text(
        json.dumps({"name": "evil", "timestamp": "(?:a+)+$"}), encoding="utf-8"
    )

    assert load_schemas(tmp_path) == {}


def test_a_known_schema_is_reused_before_anything_is_inferred() -> None:
    provider = _ScriptedProvider("{}")
    known = {"seen_before": bootstrap_format(ISO).schema}
    assert known["seen_before"] is not None

    result = bootstrap_format(ISO, known=known, provider=provider)  # type: ignore[arg-type]

    assert result.route == "known:seen_before"
    assert provider.prompts == []


def test_match_rate_of_nothing_is_zero() -> None:
    assert match_rate(FieldSchema(timestamp="iso8601"), []) == 0.0


def test_structural_inference_of_nothing_is_none() -> None:
    assert infer_structurally([]) is None


# ------------------------------------- the gate must test what the adapter does


SYSLOG_SEV = [f"Aug 30 14:{i % 60:02d}:00 host app[{i}]: ERROR pool exhausted" for i in range(400)]
APP_LOGGER = [
    f"2026-08-30T14:{i % 60:02d}:00Z ERROR checkout.pool: exhausted after {i}" for i in range(400)
]


@pytest.mark.parametrize(
    ("name", "lines"),
    [("syslog-with-severity", SYSLOG_SEV), ("app-logger", APP_LOGGER), ("bracket", BRACKET)],
)
def test_a_schema_that_passes_the_gate_actually_parses_the_file(
    name: str, lines: list[str], tmp_path: Path
) -> None:
    """The gate's promise: passing it means the file can be read, not merely matched.

    A schema once validated at 100% and then produced an ingest of zero records. Two separate
    causes, both silent: the regex matched a syslog timestamp that `parse_timestamp` rejects,
    and the validated schema was rebuilt field by field on the way out, losing the field order
    it had just been validated with. Neither raised anything.
    """
    result = bootstrap_format(lines)
    assert result.succeeded, result.reason

    path = tmp_path / f"{name}.log"
    path.write_text(chr(10).join(lines), encoding="utf-8")
    adapter = InferredAdapter(result.schema)  # type: ignore[arg-type]
    records = list(adapter.parse(path))

    assert len(records) == len(lines)
    assert adapter.stats.parse_errors == 0


def test_the_validated_schema_is_the_schema_returned() -> None:
    """The rebuild dropped a field, so the gate validated one schema and returned another.

    Pinned directly rather than only through its symptom: the next field added to `FieldSchema`
    would reintroduce it, and the symptom is a silent zero-record ingest.
    """
    result = bootstrap_format(SYSLOG_SEV)

    assert result.schema is not None
    assert result.schema.has_source is True
    assert result.schema.source_first is True
    assert result.schema.validated_rate == result.match_rate


def test_a_timestamp_that_matches_but_cannot_be_read_fails_the_gate() -> None:
    """Matching is a proxy; building a record is the thing that matters.

    Common log format is the live case: `30/Aug/2026:14:22:01 +0000` satisfies the shape and
    `parse_timestamp` rejects it, so before the gate checked parseability this validated at
    100% and then ingested zero records without raising anything.

    Syslog is *not* an example of this despite carrying no year -- dateutil fills the year in.
    That case failed for an unrelated reason, and conflating the two would leave the real one
    untested.
    """
    clf = [f"30/Aug/2026:14:{i % 60:02d}:00 +0000 INFO GET /api/{i} 200" for i in range(200)]

    result = bootstrap_format(clf)

    assert not result.succeeded
    assert "matched only" in result.reason


def test_a_yearless_syslog_timestamp_is_readable() -> None:
    """Control for the above, and a correction: the year is filled in, not missing."""
    from mistify.common.models import parse_timestamp

    assert parse_timestamp("Aug 30 14:22:01").month == 8


# ---------------------------------------------------------------- end to end


def test_bootstrapping_carries_a_file_through_ingest(tmp_path: Path, config: object) -> None:
    """The whole point: a format nothing recognises becomes a properly parsed incident.

    Timestamps, severities and sources are real here, unlike the raw-line fallback, which is
    the difference between an investigation that can be trusted and one that can only be read.
    """
    from mistify.metrics import INGEST_FALLBACK, MetricView
    from mistify.pipeline import ingest
    from mistify.scratchpad.db import ScratchpadDB

    source = tmp_path / "app.log"
    source.write_text(chr(10).join(SYSLOG_SEV), encoding="utf-8")
    config.bootstrap.enabled = True  # type: ignore[attr-defined]
    config.bootstrap.use_model = False  # type: ignore[attr-defined]

    result = ingest(source, config, incident_id="boot")  # type: ignore[arg-type]

    assert result.format_name.startswith("inferred_")
    assert result.events_loaded == len(SYSLOG_SEV)
    with ScratchpadDB(result.scratchpad_path) as db:
        row = db.get_slice(max_lines=1)[0]
        assert row["severity"] == "ERROR"
        assert row["source"].startswith("app")
        assert row["ts"].startswith("2026-08-30T14:")
        # Recorded as a fallback even though it parsed well: the format was inferred, and a
        # reader deciding how much to trust the run should be told that.
        assert MetricView(db.metrics()).text(INGEST_FALLBACK) == result.format_name


def test_an_adapter_can_make_a_fresh_copy_of_itself() -> None:
    """The pipeline needs a second pass with clean counters.

    It used to rebuild one by registry lookup, which works only for adapters that are in the
    registry -- an inferred one is built from a schema and has no entry, so bootstrapping
    crashed the ingest at the calibration step.
    """
    from mistify.adapters.json_lines import JsonLinesAdapter

    schema = bootstrap_format(ISO).schema
    assert schema is not None
    inferred = InferredAdapter(schema, name="inferred_iso8601")
    inferred.stats.lines_read = 99

    assert inferred.fresh().schema == schema
    assert inferred.fresh().stats.lines_read == 0
    assert JsonLinesAdapter().fresh().format_name == "json_lines"

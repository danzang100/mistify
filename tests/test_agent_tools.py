"""The tool layer the investigator is given.

Grouped by the property under test rather than by tool, because the properties are what the
architecture actually asks for: the ranking surfaces the needle, noise stays suppressed, the
read-only boundary holds *through the tool* and not only through the scratchpad, results
never lie about how much they are showing, and every call -- refused ones included -- leaves
an audit row.

Nothing here touches a network or a model. The tools are a pure function of the scratchpad.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from mistify.agent.tools import (
    CONFIDENCE_LEVELS,
    SLICE_LINES_MAX,
    SQL_ROW_CAP,
    TEMPLATE_LIMIT_DEFAULT,
    TEMPLATE_LIMIT_MAX,
    TOOL_NAMES,
    ToolBox,
)
from mistify.common.models import SEVERITIES, LogRecord, NoiseThresholds
from mistify.llm.base import ToolCall, ToolResult, ToolSpec
from mistify.scratchpad.db import ScratchpadDB
from tests.fixtures.synthetic_incident import RED_HERRING_MARKER, ROOT_CAUSE_MARKER

#: The configured definition of noise (`anomaly.noise_share_threshold` /
#: `noise_anomaly_ceiling`), stated literally so a config default drifting cannot quietly
#: turn a suppression test into a test of nothing.
NOISE = NoiseThresholds(share=0.15, anomaly_ceiling=0.35)

#: Suppresses nothing: no template is 100% of the file. The control for every "the noisy
#: template is absent" assertion -- without it those pass on an empty result set.
PERMISSIVE = NoiseThresholds(share=1.0, anomaly_ceiling=0.0)


@pytest.fixture
def box(loaded_db: ScratchpadDB) -> ToolBox:
    return ToolBox(loaded_db, NOISE)


@pytest.fixture
def unsuppressed(loaded_db: ScratchpadDB) -> ToolBox:
    return ToolBox(loaded_db, PERMISSIVE)


def call(box: ToolBox, name: str, **arguments: Any) -> ToolResult:
    """Dispatch one call the way a provider would, with a fresh correlation id."""
    return box.dispatch(ToolCall(id=f"call-{box.step + 1}", name=name, arguments=arguments))


def rows(result: ToolResult) -> list[dict[str, str]]:
    """Parse the pipe-delimited table back out of a result.

    Doubles as a check on the format contract: a result the tests cannot parse is one the
    model has to guess at.
    """
    lines = result.content.splitlines()
    legend = next(line for line in lines if line.startswith("columns: "))
    columns = legend.removeprefix("columns: ").split(" | ")
    body = lines[lines.index(legend) + 1 :]
    return [dict(zip(columns, line.split(" | ", len(columns) - 1), strict=True)) for line in body]


def spec(box: ToolBox, name: str) -> ToolSpec:
    return next(s for s in box.specs() if s.name == name)


def dominant_template_id(db: ScratchpadDB) -> int:
    return int(db.top_templates(limit=1, order_by="count")[0]["template_id"])


def signal_template_id(db: ScratchpadDB) -> int:
    """The top-ranked template that suppression does not hide."""
    return int(db.top_templates(limit=1, order_by="anomaly_score", noise=NOISE)[0]["template_id"])


# --------------------------------------------------------------- schema


def test_specs_offer_exactly_the_four_tools(box: ToolBox) -> None:
    assert tuple(s.name for s in box.specs()) == TOOL_NAMES


def test_every_spec_is_a_json_schema_object_with_a_description(box: ToolBox) -> None:
    for tool in box.specs():
        assert tool.description.strip()
        assert tool.schema["type"] == "object"
        assert isinstance(tool.schema["properties"], dict)
        assert tool.schema["properties"], f"{tool.name} declares no arguments"
        for prop in tool.schema["properties"].values():
            assert "description" in prop, f"{tool.name} has an undocumented argument"


@pytest.mark.parametrize(
    ("name", "required"),
    [
        ("query_templates", []),
        ("get_slice", []),
        ("run_sql", ["query"]),
        ("write_note", ["note", "evidence", "confidence"]),
    ],
)
def test_required_fields_are_declared(box: ToolBox, name: str, required: list[str]) -> None:
    tool = spec(box, name)
    assert tool.schema["required"] == required
    assert set(required) <= set(tool.schema["properties"])


def test_declared_enums_match_what_dispatch_accepts(box: ToolBox) -> None:
    """Advertising an option the dispatcher rejects burns a turn on a valid-looking call."""
    templates = spec(box, "query_templates").schema["properties"]
    slices = spec(box, "get_slice").schema["properties"]
    notes = spec(box, "write_note").schema["properties"]

    assert templates["order_by"]["default"] == "anomaly_score"
    assert templates["limit"]["maximum"] == TEMPLATE_LIMIT_MAX
    assert slices["severity"]["enum"] == list(SEVERITIES)
    assert slices["max_lines"]["maximum"] == SLICE_LINES_MAX
    assert notes["confidence"]["enum"] == list(CONFIDENCE_LEVELS)

    for ordering in templates["order_by"]["enum"]:
        assert not call(box, "query_templates", order_by=ordering, limit=1).is_error
    for level in notes["confidence"]["enum"]:
        result = call(
            box,
            "write_note",
            note="ordering check",
            evidence={"template_ids": [dominant_template_id(box.db)], "log_event_ids": []},
            confidence=level,
        )
        assert not result.is_error


# --------------------------------------------------------------- ranking


def test_default_ranking_puts_the_planted_root_cause_first(box: ToolBox) -> None:
    """Anomaly is the default because the ranking is the search order.

    The planted FATAL fires 40 times against a red herring that fires hundreds, so this is
    the whole argument for not defaulting to count.
    """
    result = call(box, "query_templates")

    assert not result.is_error
    first = rows(result)[0]
    assert ROOT_CAUSE_MARKER in first["pattern"]
    assert first["max_severity"] == "FATAL"


def test_count_ranking_does_not(box: ToolBox) -> None:
    """The control. Without it the test above could be passing on any ordering at all."""
    first = rows(call(box, "query_templates", order_by="count"))[0]
    assert ROOT_CAUSE_MARKER not in first["pattern"]


def test_ranking_says_how_many_templates_it_is_not_showing(box: ToolBox) -> None:
    result = call(box, "query_templates", limit=2)
    total = box.db.template_count()

    assert f"{total} templates in the incident" in result.content
    assert "at the limit" in result.content
    assert len(rows(result)) == 2


def test_noise_is_absent_from_the_ranking(box: ToolBox) -> None:
    noisy = box.db.noise_template_ids(NOISE)
    assert noisy, "fixture has no noise template; the assertion below would be vacuous"

    listed = {int(row["template_id"]) for row in rows(call(box, "query_templates", limit=50))}
    assert not listed & noisy
    assert f"{len(noisy)} suppressed as noise" in call(box, "query_templates").content


def test_ranking_without_suppression_returns_the_noise(unsuppressed: ToolBox) -> None:
    """Control for the exclusion above: the rows exist and only the thresholds hide them."""
    noisy = unsuppressed.db.noise_template_ids(NOISE)
    listed = {
        int(row["template_id"]) for row in rows(call(unsuppressed, "query_templates", limit=50))
    }
    assert noisy <= listed


def test_limit_is_capped(box: ToolBox) -> None:
    result = call(box, "query_templates", limit=10_000)
    assert f"limit {TEMPLATE_LIMIT_MAX}" in result.content
    assert len(rows(result)) <= TEMPLATE_LIMIT_MAX


# --------------------------------------------------------------- slices


def test_slice_returns_citable_lines(box: ToolBox) -> None:
    result = call(box, "get_slice", severity="FATAL", max_lines=10)

    assert not result.is_error
    returned = rows(result)
    assert returned
    assert all(ROOT_CAUSE_MARKER in row["text"] for row in returned)

    cited = [int(row["id"]) for row in returned]
    assert len(box.db.events_by_id(cited)) == len(cited)


def test_slice_accepts_a_severity_in_any_case(box: ToolBox) -> None:
    """Matching is exact in SQL, so an unnormalised level would read as "no such lines"."""
    assert rows(call(box, "get_slice", severity="fatal", max_lines=5))


def test_slice_accepts_a_partial_timestamp(box: ToolBox) -> None:
    """`ts` is fixed-width text compared lexicographically; a loose bound silently widens."""
    first_ts, _ = box.db.time_bounds()
    assert first_ts is not None
    result = call(box, "get_slice", start_ts="2026-08-30T14:38", max_lines=5)

    assert not result.is_error
    assert all(row["ts"] >= "2026-08-30T14:38" for row in rows(result))


def test_dominant_template_is_suppressed_in_a_slice(box: ToolBox) -> None:
    """The needle problem in miniature: max_lines spent on whatever is most numerous."""
    dominant = dominant_template_id(box.db)
    assert dominant in box.db.noise_template_ids(NOISE)

    returned = rows(call(box, "get_slice", max_lines=100))
    assert returned
    assert all(int(row["template_id"]) != dominant for row in returned)


def test_the_same_slice_without_suppression_drowns_in_it(unsuppressed: ToolBox) -> None:
    """Control. The dominant template is in that window; suppression is what removed it."""
    dominant = dominant_template_id(unsuppressed.db)
    returned = rows(call(unsuppressed, "get_slice", max_lines=100))
    assert any(int(row["template_id"]) == dominant for row in returned)


def test_asking_for_a_noisy_template_by_id_overrides_suppression(box: ToolBox) -> None:
    """A template id is a deliberate request, not a default."""
    dominant = dominant_template_id(box.db)
    result = call(box, "get_slice", template_id=dominant, max_lines=5)

    assert "noise suppression off" in result.content
    assert [int(row["template_id"]) for row in rows(result)] == [dominant] * 5


def test_max_lines_is_capped_and_the_cap_is_reported(box: ToolBox) -> None:
    """A silently truncated slice reads as a complete one, which is the failure to avoid."""
    result = call(box, "get_slice", max_lines=10_000)
    returned = rows(result)

    assert len(returned) == SLICE_LINES_MAX
    assert f"max_lines {SLICE_LINES_MAX}" in result.content
    assert f"hit the {SLICE_LINES_MAX}-line cap" in result.content


def test_a_slice_under_the_cap_does_not_claim_truncation(box: ToolBox) -> None:
    result = call(box, "get_slice", severity="FATAL", max_lines=SLICE_LINES_MAX)
    assert "cap" not in result.content
    assert len(rows(result)) < SLICE_LINES_MAX


def test_long_lines_are_clipped_with_the_dropped_count(box: ToolBox) -> None:
    """The count is the point: it tells the model to go fetch the line by id."""
    long_message = "pool stack trace " + ("x" * 2000)
    record = LogRecord(
        ts=datetime(2026, 8, 30, 14, 39, tzinfo=UTC),
        source="verbose-service",
        severity="ERROR",
        raw=long_message,
        message=long_message,
    )
    box.db.bulk_insert_events([(record, signal_template_id(box.db))])

    text = rows(call(box, "get_slice", source="verbose-service"))[0]["text"]
    assert len(text) < len(long_message)
    assert "more chars)" in text


# --------------------------------------------------------------- read-only SQL


def test_select_returns_rows(box: ToolBox) -> None:
    result = call(
        box, "run_sql", query="SELECT severity, COUNT(*) AS n FROM log_events GROUP BY severity"
    )

    assert not result.is_error
    counts = {row["severity"]: int(row["n"]) for row in rows(result)}
    assert counts["FATAL"] == 40


@pytest.mark.parametrize(
    "query",
    [
        "DELETE FROM log_events",
        "UPDATE templates SET pattern = 'x'",
        "DROP TABLE scratchpad_notes",
        "INSERT INTO scratchpad_notes (step, note) VALUES (1, 'x')",
        "-- harmless\nDELETE FROM log_events",
        "WITH t AS (DELETE FROM log_events RETURNING id) SELECT * FROM t",
        "ATTACH DATABASE 'vault.sqlite' AS v",
        "PRAGMA table_list",
        "SELECT load_extension('evil.so')",
    ],
)
def test_the_read_only_boundary_holds_through_the_tool(box: ToolBox, query: str) -> None:
    """The scratchpad enforces this, but the tool is what the model actually reaches."""
    before = box.db.event_count()
    result = call(box, "run_sql", query=query)

    assert result.is_error
    assert "read-only" in result.content
    assert box.db.event_count() == before


def test_a_refusal_is_an_answer_not_a_crash(box: ToolBox) -> None:
    """The message has to be usable: the model's only route out is rewriting the query."""
    result = call(box, "run_sql", query="SELECT * FRM log_events")

    assert result.is_error
    assert "SELECT" in result.content
    assert not call(box, "run_sql", query="SELECT COUNT(*) AS n FROM log_events").is_error


def test_sql_results_are_capped_and_say_so(box: ToolBox) -> None:
    result = call(box, "run_sql", query="SELECT id FROM log_events")

    assert len(rows(result)) == SQL_ROW_CAP
    assert f"hit the {SQL_ROW_CAP}-row cap" in result.content


# --------------------------------------------------------------- notes


def test_note_is_persisted_with_its_evidence_and_step(box: ToolBox) -> None:
    template_id = dominant_template_id(box.db)
    event_ids = [int(row["id"]) for row in box.db.get_slice(severity="FATAL", max_lines=3)]

    result = call(
        box,
        "write_note",
        note=f"{ROOT_CAUSE_MARKER} is the cause; {RED_HERRING_MARKER} predates it.",
        evidence={"template_ids": [template_id], "log_event_ids": event_ids},
        confidence="high",
    )

    assert not result.is_error
    note = box.db.notes()[-1]
    assert note.step == box.step
    assert note.confidence == "high"
    assert note.evidence == {"template_ids": [template_id], "log_event_ids": event_ids}
    assert str(note.id) in result.content


def test_evidence_citing_nothing_is_refused_and_writes_no_note(box: ToolBox) -> None:
    """`{"template_ids": [], "log_event_ids": []}` is truthy, so it clears the scratchpad's
    own guard and the SQL CHECK while citing nothing. The rule has to be enforced here."""
    before = len(box.db.notes())
    result = call(
        box,
        "write_note",
        note="something happened",
        evidence={"template_ids": [], "log_event_ids": []},
        confidence="low",
    )

    assert result.is_error
    assert "at least one template_id or log_event_id" in result.content
    assert len(box.db.notes()) == before


def test_one_citation_is_enough(box: ToolBox) -> None:
    """Control for the refusal above: the note is otherwise identical and is accepted."""
    result = call(
        box,
        "write_note",
        note="something happened",
        evidence={"template_ids": [dominant_template_id(box.db)], "log_event_ids": []},
        confidence="low",
    )
    assert not result.is_error


def test_a_citation_with_no_row_behind_it_is_flagged(box: ToolBox) -> None:
    """Warned, not refused: the report's verifier is the authority, and a mistyped id
    should not cost a sound finding. Naming it lets the model correct itself."""
    result = call(
        box,
        "write_note",
        note="fabricated",
        evidence={"template_ids": [999_999], "log_event_ids": [888_888]},
        confidence="low",
    )

    assert not result.is_error
    assert "999999" in result.content and "888888" in result.content
    assert "do not exist" in result.content


def test_a_real_citation_is_not_flagged(box: ToolBox) -> None:
    event_id = int(box.db.get_slice(severity="FATAL", max_lines=1)[0]["id"])
    result = call(
        box,
        "write_note",
        note="real",
        evidence={
            "template_ids": [dominant_template_id(box.db)],
            "log_event_ids": [event_id],
        },
        confidence="medium",
    )
    assert "do not exist" not in result.content


# --------------------------------------------------------------- dispatch contract


def test_unknown_tool_names_the_valid_ones(box: ToolBox) -> None:
    result = call(box, "grep_logs", pattern="pool")

    assert result.is_error
    assert "grep_logs" in result.content
    for name in TOOL_NAMES:
        assert name in result.content


@pytest.mark.parametrize(
    ("name", "arguments", "hint"),
    [
        ("query_templates", {"order_by": "sideways"}, "anomaly_score"),
        ("query_templates", {"limit": "lots"}, "must be an integer"),
        ("query_templates", {"limit": 0}, "at least 1"),
        ("get_slice", {"severity": "CRITICAL"}, "not a known severity"),
        ("get_slice", {"start_ts": "yesterday"}, "ISO-8601"),
        ("get_slice", {"template_id": [4]}, "must be an integer"),
        ("get_slice", {"max_lines": True}, "not a boolean"),
        ("get_slice", {"source": 12}, "must be a string"),
        ("run_sql", {}, "query is required"),
        ("run_sql", {"query": 12}, "must be a string"),
        ("write_note", {"evidence": {"template_ids": [1]}, "confidence": "low"}, "note is"),
        ("write_note", {"note": "x", "confidence": "low"}, "evidence is required"),
        ("write_note", {"note": "x", "evidence": [1], "confidence": "low"}, "must be an object"),
        ("write_note", {"note": "x", "evidence": {"template_ids": [1]}}, "confidence is"),
        (
            "write_note",
            {"note": "x", "evidence": {"template_ids": [1]}, "confidence": "certain"},
            "low, medium, high",
        ),
        (
            "write_note",
            {"note": "x", "evidence": {"template_ids": "1"}, "confidence": "low"},
            "array of integers",
        ),
    ],
)
def test_bad_arguments_come_back_as_a_fixable_message(
    box: ToolBox, name: str, arguments: dict[str, Any], hint: str
) -> None:
    """The model authored these, so the result has to say how to correct them."""
    result = box.dispatch(ToolCall(id="c", name=name, arguments=arguments))

    assert result.is_error
    assert hint in result.content


def test_defaults_apply_when_no_arguments_are_given(box: ToolBox) -> None:
    result = call(box, "query_templates")
    assert f"limit {TEMPLATE_LIMIT_DEFAULT}" in result.content
    assert "ordered by anomaly_score" in result.content
    assert not call(box, "get_slice").is_error


def test_every_result_quotes_the_call_id_back(box: ToolBox) -> None:
    good = box.dispatch(ToolCall(id="abc", name="query_templates", arguments={}))
    bad = box.dispatch(ToolCall(id="xyz", name="nonsense", arguments={}))

    assert good.call_id == "abc"
    assert bad.call_id == "xyz"


# --------------------------------------------------------------- audit trail


def test_every_dispatch_is_logged_including_the_failures(box: ToolBox) -> None:
    """A conclusion nobody can retrace is not evidence, and a refused query is part of it."""
    dispatched = [
        call(box, "query_templates", limit=3),
        call(box, "get_slice", severity="FATAL", max_lines=2),
        call(box, "run_sql", query="SELECT COUNT(*) AS n FROM templates"),
        call(box, "run_sql", query="DELETE FROM log_events"),
        call(box, "write_note", note="x", evidence={"template_ids": []}, confidence="low"),
        call(box, "not_a_tool"),
    ]
    logged = box.db.queries()

    assert len(logged) == len(dispatched)
    assert [entry["step"] for entry in logged] == [1, 2, 3, 4, 5, 6]
    assert [entry["row_count"] for entry in logged] == [3, 2, 1, 0, 0, 0]
    for entry, result in zip(logged, dispatched, strict=True):
        assert ("error" in entry["sql_query"]) is result.is_error


def test_the_audit_row_records_what_was_asked_for(box: ToolBox) -> None:
    call(box, "get_slice", source="checkout-service", severity="FATAL", max_lines=4)
    call(box, "run_sql", query="SELECT 1 AS one")
    logged = box.db.queries()

    assert "source=checkout-service" in logged[0]["sql_query"]
    assert "severity=FATAL" in logged[0]["sql_query"]
    assert logged[1]["sql_query"] == "SELECT 1 AS one"


def test_the_step_counter_can_continue_an_existing_run(loaded_db: ScratchpadDB) -> None:
    box = ToolBox(loaded_db, NOISE, start_step=7)
    call(box, "query_templates", limit=1)

    assert box.step == 8
    assert loaded_db.queries()[0]["step"] == 8

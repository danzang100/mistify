"""The MCP server, driven in-process: what it offers, and everything it refuses.

The surface is the security boundary, so most of this file is refusals. Each one is paired
with the nearest request that must succeed, because a refusal test on a server that refuses
everything passes too.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mistify import mcp_server
from mistify.agent import runner
from mistify.common.config import MistifyConfig
from mistify.eval.fixtures import write_incident
from mistify.health import HealthCheck, HealthReport, HealthStatus
from mistify.llm.base import Usage
from mistify.llm.scripted import ScriptedProvider, text_turn, tool_call_turn
from mistify.mcp_server import TOOL_NAMES, build_server
from mistify.metrics import BUDGET_REFUSED_STAGES, MetricView
from mistify.scratchpad.db import ScratchpadDB
from tests.conftest import _scratch_config


@pytest.fixture
def logs(tmp_path: Path) -> Path:
    directory = tmp_path / "logs"
    write_incident(directory / "incident.jsonl")
    return directory


def _config(tmp_path: Path, logs: Path, **sections: dict[str, Any]) -> MistifyConfig:
    merged: dict[str, dict[str, Any]] = {"mcp": {"allowed_roots": [str(logs)]}}
    for name, values in sections.items():
        merged.setdefault(name, {}).update(values)
    return _scratch_config(tmp_path / "work", **merged)


def _call(server: MCPServer, name: str, **arguments: Any) -> Any:
    """Call a tool and return its structured result, or its text for a string result."""

    async def go() -> Any:
        result = await server.call_tool(name, arguments)
        assert not result.is_error, result.content
        if result.structured_content is not None:
            content = result.structured_content
            return content.get("result", content) if set(content) == {"result"} else content
        return result.content[0].text

    return anyio.run(go)


def _ingested(tmp_path: Path, logs: Path, **sections: dict[str, Any]) -> MCPServer:
    server = build_server(_config(tmp_path, logs, **sections))
    _call(server, "ingest", source=str(logs / "incident.jsonl"), incident_id="inc")
    return server


# ------------------------------------------------------------------ the surface


def _tool_names(server: MCPServer) -> list[str]:
    return [tool.name for tool in anyio.run(server.list_tools)]


def _mentions_the_vault(server: MCPServer) -> list[str]:
    """Every tool name or argument that could reach a redacted value's original."""
    found = []
    for tool in anyio.run(server.list_tools):
        words = [tool.name, *tool.input_schema.get("properties", {})]
        found += [w for w in words if any(k in w.lower() for k in ("reveal", "vault", "unredact"))]
    return found


def test_the_server_offers_exactly_its_six_tools(tmp_path: Path, logs: Path) -> None:
    server = build_server(_config(tmp_path, logs))
    assert _tool_names(server) == list(TOOL_NAMES)
    assert _mentions_the_vault(server) == []


def test_the_vault_check_would_see_a_reveal_tool(tmp_path: Path, logs: Path) -> None:
    """The control: the check above is capable of failing."""
    server = build_server(_config(tmp_path, logs))

    @server.tool()
    def reveal(incident_id: str, token: str) -> str:
        return token

    assert _mentions_the_vault(server) == ["reveal"]


def test_no_tool_can_override_the_health_check_or_the_ceiling(tmp_path: Path, logs: Path) -> None:
    arguments = {
        name
        for tool in anyio.run(build_server(_config(tmp_path, logs)).list_tools)
        for name in tool.input_schema.get("properties", {})
    }
    assert not {a for a in arguments if "health" in a or "ignore" in a or "token" in a}


# ------------------------------------------------------------------ ingest: where it may read


def test_a_source_inside_an_allowed_root_is_ingested(tmp_path: Path, logs: Path) -> None:
    server = build_server(_config(tmp_path, logs))
    result = _call(server, "ingest", source=str(logs / "incident.jsonl"), incident_id="inc")
    assert result["events_loaded"] > 0
    assert result["health"]["status"] == "ok"


@pytest.mark.parametrize(
    "source",
    ["{root}", "{root}/secret.jsonl", "{logs}/../secret.jsonl", "{logs}/../../x.jsonl"],
)
def test_a_source_outside_the_allowed_roots_is_refused(
    tmp_path: Path, logs: Path, source: str
) -> None:
    (tmp_path / "secret.jsonl").write_text("{}\n", encoding="utf-8")
    server = build_server(_config(tmp_path, logs))
    with pytest.raises(ToolError, match=r"outside the allowed directories|not found"):
        _call(server, "ingest", source=source.format(root=tmp_path, logs=logs))


def test_no_allowed_roots_refuses_everything(tmp_path: Path, logs: Path) -> None:
    server = build_server(_config(tmp_path, logs, mcp={"allowed_roots": []}))
    with pytest.raises(ToolError, match="no directories are allowed"):
        _call(server, "ingest", source=str(logs / "incident.jsonl"))


def _link_directory(link: Path, target: Path) -> None:
    """A directory link: a symlink, or on Windows without the right to make one, a junction.

    Junctions need no privilege and path resolution follows them like symlinks, so the escape
    checks run on a stock Windows account instead of being skipped there.
    """
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        if os.name != "nt":
            pytest.skip("this machine does not allow creating symlinks")
    import subprocess

    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
    )
    if made.returncode != 0:
        pytest.skip("this machine allows neither symlinks nor junctions")


def test_a_link_out_of_an_allowed_root_is_refused(tmp_path: Path, logs: Path) -> None:
    (tmp_path / "outside").mkdir()
    shutil.copy(logs / "incident.jsonl", tmp_path / "outside" / "other.jsonl")
    _link_directory(logs / "escape", tmp_path / "outside")
    server = build_server(_config(tmp_path, logs))
    with pytest.raises(ToolError, match="outside the allowed directories"):
        _call(server, "ingest", source=str(logs / "escape" / "other.jsonl"))


def test_a_directory_hiding_an_escaping_symlink_is_refused(tmp_path: Path, logs: Path) -> None:
    (tmp_path / "outside").mkdir()
    shutil.copy(logs / "incident.jsonl", tmp_path / "outside" / "other.jsonl")
    _link_directory(logs / "escape", tmp_path / "outside")
    server = build_server(_config(tmp_path, logs))
    with pytest.raises(ToolError, match="resolves outside the allowed directories"):
        _call(server, "ingest", source=str(logs))


def test_a_directory_wholly_inside_is_ingested(tmp_path: Path, logs: Path) -> None:
    """The control for the directory refusal."""
    server = build_server(_config(tmp_path, logs))
    assert _call(server, "ingest", source=str(logs), incident_id="dir")["events_loaded"] > 0


def test_ingest_never_writes_a_vault_whatever_the_config_says(tmp_path: Path, logs: Path) -> None:
    config = _config(
        tmp_path,
        logs,
        redaction={"vault": True, "vault_path": str(tmp_path / "v_{incident_id}.sqlite")},
    )
    _call(build_server(config), "ingest", source=str(logs / "incident.jsonl"), incident_id="inc")
    assert not config.vault_file("inc").exists()


# ------------------------------------------------------------------ incident ids


@pytest.mark.parametrize(
    "incident_id", ["../escape", "a/b", "a\\b", "C:x", ".hidden", "", "x" * 200]
)
def test_an_incident_id_that_could_name_a_path_is_refused(
    tmp_path: Path, logs: Path, incident_id: str
) -> None:
    server = build_server(_config(tmp_path, logs))
    with pytest.raises(ToolError, match="invalid incident id"):
        _call(server, "health", incident_id=incident_id)


def test_an_unknown_but_well_formed_incident_is_reported_missing(
    tmp_path: Path, logs: Path
) -> None:
    """The control: a valid id passes the shape check and fails only on existence."""
    server = build_server(_config(tmp_path, logs))
    with pytest.raises(ToolError, match="ingest it first"):
        _call(server, "health", incident_id="2026-09-26-never-ingested")


# ------------------------------------------------------------------ query


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM log_events",
        "INSERT INTO templates (template_id) VALUES (999999)",
        "UPDATE log_events SET message = 'x'",
        "DROP TABLE log_events",
        "ATTACH DATABASE 'x.sqlite' AS x",
        "PRAGMA writable_schema = 1",
    ],
)
def test_query_refuses_anything_but_reading(tmp_path: Path, logs: Path, sql: str) -> None:
    server = _ingested(tmp_path, logs)
    with pytest.raises(ToolError, match="query refused"):
        _call(server, "query", incident_id="inc", sql=sql)


def test_query_reads_and_marks_what_it_returns(tmp_path: Path, logs: Path) -> None:
    server = _ingested(tmp_path, logs)
    result = _call(server, "query", incident_id="inc", sql="SELECT id, message FROM log_events")
    assert result["row_count"] == 200 and result["truncated"] is True
    assert "untrusted_notice" in result
    small = _call(server, "query", incident_id="inc", sql="SELECT COUNT(*) AS n FROM templates")
    assert small["truncated"] is False and small["rows"][0]["n"] > 0


# ------------------------------------------------------------------ report and report_data


def test_the_report_arrives_fenced_as_log_data(tmp_path: Path, logs: Path) -> None:
    server = _ingested(tmp_path, logs)
    text = _call(server, "report", incident_id="inc")
    assert text.startswith('<log_data kind="report">') and text.endswith("</log_data>")


def test_report_data_is_the_reports_data_as_json(tmp_path: Path, logs: Path) -> None:
    server = _ingested(tmp_path, logs)
    data = _call(server, "report_data", incident_id="inc")
    assert data["schema"] == "mistify.report-data/1"
    assert "untrusted_notice" in data
    assert data["event_count"] > 0 and data["top_templates"]
    json.dumps(data)


@pytest.mark.parametrize("fmt", ["pdf", "json", "../x"])
def test_report_offers_only_readable_formats(tmp_path: Path, logs: Path, fmt: str) -> None:
    server = _ingested(tmp_path, logs)
    with pytest.raises(ToolError, match="not offered here"):
        _call(server, "report", incident_id="inc", format=fmt)


# ------------------------------------------------------------------ investigate


def _scripted(monkeypatch: pytest.MonkeyPatch, config: MistifyConfig) -> None:
    critique = json.dumps({"assessment": "sound", "objections": [], "alternative": ""})
    scripts = {
        config.llm.model: [
            tool_call_turn("query_templates", {}, call_id="c0", usage=Usage(2_950, 50)),
            text_turn("Pool exhaustion.", usage=Usage(900, 100)),
        ],
        config.llm.adversarial_model: [text_turn(critique, usage=Usage(500, 50))],
    }
    built = {m: ScriptedProvider(t, model=m) for m, t in scripts.items()}
    monkeypatch.setattr(runner, "build_provider", lambda _n, model, _c: built[model])


def _investigable(tmp_path: Path, logs: Path, **pipeline: Any) -> tuple[MCPServer, MistifyConfig]:
    config = _config(
        tmp_path,
        logs,
        pipeline={"coverage_nudges": 0, **pipeline},
        llm={"synthesis_model": None},
    )
    server = build_server(config)
    _call(server, "ingest", source=str(logs / "incident.jsonl"), incident_id="inc")
    return server, config


def test_investigate_runs_and_reports_its_spend(
    tmp_path: Path, logs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, config = _investigable(tmp_path, logs)
    _scripted(monkeypatch, config)
    result = _call(server, "investigate", incident_id="inc")
    # The loop's two turns. It wrote no note, so the critique had nothing to check and spent
    # nothing -- which is also why the spend is exact.
    assert result["tokens"]["spent"] == 4_000
    assert "untrusted_notice" in result


def test_a_failed_health_check_cannot_be_overridden_over_mcp(
    tmp_path: Path, logs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, config = _investigable(tmp_path, logs)
    _scripted(monkeypatch, config)
    failed = HealthReport(checks=(HealthCheck("timezones", HealthStatus.FAIL, "skewed"),))
    monkeypatch.setattr(mcp_server, "check_health", lambda _db, _cfg: failed)

    with pytest.raises(ToolError, match="cannot be overridden over MCP"):
        _call(server, "investigate", incident_id="inc")


def test_an_mcp_run_stops_at_the_configured_ceiling(
    tmp_path: Path, logs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, config = _investigable(tmp_path, logs, max_total_tokens=10_000)
    _scripted(monkeypatch, config)
    monkeypatch.setattr(
        runner,
        "build_provider",
        lambda _n, model, _c: ScriptedProvider(
            [
                tool_call_turn("query_templates", {}, call_id="c0", usage=Usage(2_950, 50)),
                text_turn("Pool exhaustion.", usage=Usage(7_400, 100)),
            ]
            if model == config.llm.model
            else [],
            model=model,
        ),
    )
    result = _call(server, "investigate", incident_id="inc")

    assert result["budget_limited"] is True and result["budget_limit"] == "tokens"
    with ScratchpadDB(config.scratchpad_path("inc")) as db:
        assert MetricView(db.metrics("budget")).text(BUDGET_REFUSED_STAGES) == "adversarial"


def test_reinvestigating_needs_restart(
    tmp_path: Path, logs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, config = _investigable(tmp_path, logs)
    with ScratchpadDB(config.scratchpad_path("inc")) as db:
        event = db.get_slice(max_lines=1)[0]
        db.write_note(
            step=1,
            note="An earlier investigation's finding.",
            evidence={"template_ids": [int(event["template_id"])], "log_event_ids": [event["id"]]},
            confidence="low",
        )

    with pytest.raises(ToolError, match="restart=true"):
        _call(server, "investigate", incident_id="inc")
    _scripted(monkeypatch, config)
    assert _call(server, "investigate", incident_id="inc", restart=True)["steps"] > 0


# ------------------------------------------------------------------ review fixes, 2026-09-26


def test_a_busy_incident_refuses_a_second_writer() -> None:
    locks = mcp_server._IncidentLocks()

    def nested() -> None:
        locks.run("inc", lambda: None)

    with pytest.raises(ToolError, match="is busy"):
        locks.run("inc", nested)


def test_another_incident_is_not_held_up() -> None:
    """The control: the lock is per incident, and released afterwards."""
    locks = mcp_server._IncidentLocks()
    assert locks.run("inc", lambda: locks.run("other", lambda: 7)) == 7
    assert locks.run("inc", lambda: 8) == 8


def test_a_runaway_query_is_stopped_at_its_limit(tmp_path: Path, logs: Path) -> None:
    from mistify.scratchpad.db import ReadOnlyViolation

    server = _ingested(tmp_path, logs)
    config = _config(tmp_path, logs)
    with ScratchpadDB(config.scratchpad_path("inc")) as db:
        with pytest.raises(ReadOnlyViolation, match="limit"):
            db.run_readonly_sql(
                "SELECT count(*) FROM log_events a, log_events b, log_events c", time_limit=0.2
            )
        # The control, on the same connection: the handler was cleared, and a normal query runs.
        assert db.run_readonly_sql("SELECT count(*) AS n FROM templates", time_limit=0.2)
    assert server is not None


def test_an_oversized_brief_is_refused(tmp_path: Path, logs: Path) -> None:
    server = build_server(_config(tmp_path, logs))
    with pytest.raises(ToolError, match="the limit is 8,000"):
        _call(server, "ingest", source=str(logs / "incident.jsonl"), brief="x" * 8_001)
    ok = _call(server, "ingest", source=str(logs / "incident.jsonl"), brief="checkout is down")
    assert ok["events_loaded"] > 0


def test_health_is_not_advertised_as_read_only(tmp_path: Path, logs: Path) -> None:
    """It records its verdicts; a client auto-approving read-only tools must not skip asking."""
    tools = {t.name: t for t in anyio.run(build_server(_config(tmp_path, logs)).list_tools)}
    assert tools["health"].annotations.read_only_hint is False
    assert tools["report"].annotations.read_only_hint is True

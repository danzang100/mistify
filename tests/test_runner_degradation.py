"""A model that fails after the investigation has finished costs its stage, not the run.

Found live on 2026-09-26 through MCP: the loop finished and wrote two notes, the synthesis
model returned 503 six times, and the whole investigation was reported as failed with its
findings sitting unreported in the scratchpad.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from mistify.agent import runner
from mistify.common.config import MistifyConfig, PipelineConfig
from mistify.llm.base import ProviderError, Turn
from mistify.llm.scripted import ScriptedProvider, text_turn, tool_call_turn
from mistify.metrics import ADVERSARIAL_FAILED, SYNTHESIS_FAILED, MetricView
from mistify.report.generator import generate_report
from mistify.scratchpad.db import ScratchpadDB


class _Overloaded:
    """A provider whose every call fails the way an overloaded model does."""

    supports_task_budget = False

    def __init__(self, model: str) -> None:
        self.name = "scripted"
        self.model = model

    def converse(self, *args: Any, **kwargs: Any) -> Turn:
        raise ProviderError("Gemini call failed: 503 UNAVAILABLE")


def _note_writing_loop(db: ScratchpadDB) -> list[Turn]:
    template = db.top_templates(limit=1, order_by="anomaly_score")[0]
    event = db.get_slice(template_id=int(template["template_id"]), max_lines=1)[0]
    return [
        tool_call_turn(
            "get_slice", {"template_id": int(template["template_id"]), "max_lines": 1}, call_id="c0"
        ),
        tool_call_turn(
            "write_note",
            {
                "note": "Pool exhaustion.",
                "evidence": {
                    "template_ids": [int(template["template_id"])],
                    "log_event_ids": [int(event["id"])],
                },
                "confidence": "high",
            },
            call_id="c1",
        ),
        text_turn("Pool exhaustion."),
    ]


def _run(db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch, failing: set[str]) -> None:
    config = MistifyConfig(pipeline=PipelineConfig(coverage_nudges=0))
    critique = json.dumps({"assessment": "sound", "objections": [], "alternative": ""})
    scripts = {
        config.llm.model: _note_writing_loop(db),
        str(config.llm.synthesis_model): [
            text_turn(json.dumps({"conclusion": "x", "confidence": "low", "template_ids": []}))
        ],
        config.llm.adversarial_model: [text_turn(critique)],
    }

    def build(_name: str, model: str, _config: Any) -> Any:
        return (
            _Overloaded(model)
            if model in failing
            else ScriptedProvider(scripts[model], model=model)
        )

    monkeypatch.setattr(runner, "build_provider", build)
    runner.run_investigation(db, config, adversarial=True)


def test_a_failed_synthesis_leaves_the_investigation_standing(
    loaded_db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = MistifyConfig()
    _run(loaded_db, monkeypatch, failing={str(config.llm.synthesis_model)})

    assert any(n.note == "Pool exhaustion." for n in loaded_db.notes())
    assert "503" in (MetricView(loaded_db.metrics()).text(SYNTHESIS_FAILED) or "")
    assert "The synthesis model failed" in generate_report(loaded_db)


def test_a_failed_critique_is_said_in_words(
    loaded_db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = MistifyConfig()
    _run(loaded_db, monkeypatch, failing={config.llm.adversarial_model})

    assert MetricView(loaded_db.metrics()).text(ADVERSARIAL_FAILED)
    assert "The critique model failed" in generate_report(loaded_db)


def test_a_run_where_nothing_failed_warns_of_neither(
    loaded_db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for both warnings."""
    _run(loaded_db, monkeypatch, failing=set())
    report = generate_report(loaded_db)
    assert "model failed" not in report


def test_a_failed_investigation_model_still_fails_the_run(
    loaded_db: ScratchpadDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Degrading is for stages after the investigation. With no investigation there is
    nothing to stand, and reporting one would be the silent failure this system exists to
    avoid."""
    with pytest.raises(ProviderError):
        _run(loaded_db, monkeypatch, failing={MistifyConfig().llm.model})

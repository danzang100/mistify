"""What each stage publishes, checked without a log file or a scratchpad.

These were previously ~90 lines inside `ingest()`, reachable only by running the whole
pipeline against a real file. Every case below used to require a 5,000-line ingest.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mistify.adapters.json_lines import JsonLinesAdapter
from mistify.common.config import MistifyConfig
from mistify.common.models import TemplateSummary
from mistify.metrics import (
    ANOMALY_NEEDLE_POSITION,
    ANOMALY_SEVERITY_INFORMATIVE,
    ANOMALY_TOP_SCORE,
    ANOMALY_TOP_TEMPLATE_ID,
    INGEST_LINES_READ,
    INGEST_PARSE_ERRORS,
    REDACTED_BY_ENTITY,
    REDACTION_TOTAL,
    REDACTION_VAULT,
    REDACTION_VAULT_ENTRIES,
    TEMPLATING_CALIBRATION_CANDIDATES,
    TEMPLATING_CALIBRATION_STATUS,
    TEMPLATING_COVERAGE,
    TEMPLATING_OVER_MERGED,
    TEMPLATING_OVER_MERGED_IDS,
    Metric,
)
from mistify.redaction.redactor import Redactor
from mistify.redaction.vault import RedactionVault
from mistify.scratchpad.anomaly import AnomalyComponents
from mistify.stage_metrics import (
    anomaly_metrics,
    ingest_metrics,
    redaction_metrics,
    templating_metrics,
)
from mistify.templating.calibration import (
    CalibrationResult,
    CalibrationStatus,
    OverMergedTemplate,
)
from mistify.templating.drain_wrapper import DrainTemplater


def _by_metric(entries: list[tuple[Metric, object]]) -> dict[Metric, object]:
    return dict(entries)


@pytest.fixture
def config() -> MistifyConfig:
    return MistifyConfig()


# --------------------------------------------------------------- ingest


def test_ingest_reports_the_adapter_counters(tmp_path: Path) -> None:
    source = tmp_path / "mixed.jsonl"
    source.write_text(
        '{"timestamp": "2026-08-30T14:00:00Z", "level": "INFO", "message": "ok"}\n{broken\n',
        encoding="utf-8",
    )
    adapter = JsonLinesAdapter()
    list(adapter.parse(source))

    values = _by_metric(ingest_metrics(adapter, {"json_lines": 0.98}, events_loaded=1))
    assert values[INGEST_LINES_READ] == 2
    assert values[INGEST_PARSE_ERRORS] == 1


# --------------------------------------------------------------- redaction


def test_redaction_reports_only_entities_that_matched(config: MistifyConfig) -> None:
    """A run that redacted no addresses should not claim a zero it never measured."""
    redactor = Redactor()
    redactor.redact("mail ana@corp.com about it")

    values = _by_metric(redaction_metrics(config, redactor, None, None))
    assert values[REDACTED_BY_ENTITY.member("email")] == 1
    assert REDACTED_BY_ENTITY.member("ipv4") not in values
    assert values[REDACTION_TOTAL] == 1
    assert values[REDACTION_VAULT] is False


def test_redaction_reports_the_vault_when_one_is_kept(
    config: MistifyConfig, tmp_path: Path
) -> None:
    path = tmp_path / "vault.sqlite"
    with RedactionVault(path) as vault:
        redactor = Redactor(vault=vault)
        redactor.redact("mail ana@corp.com from 10.0.0.1")
        values = _by_metric(redaction_metrics(config, redactor, vault, path))

    assert values[REDACTION_VAULT] is True
    assert values[REDACTION_VAULT_ENTRIES] == 2


# --------------------------------------------------------------- templating


def _templater() -> DrainTemplater:
    templater = DrainTemplater(snapshot_path=None)
    for i in range(10):
        templater.process(f"Handled request {i}", ts=f"2026-08-30T14:00:{i:02d}Z")
    return templater


def test_templating_reports_coverage(config: MistifyConfig) -> None:
    values = _by_metric(
        templating_metrics(
            config, _templater(), 0.5, coverage=1.0, calibration=None, over_merged=[]
        )
    )
    assert values[TEMPLATING_COVERAGE] == 1.0


def test_disabled_calibration_says_so(config: MistifyConfig) -> None:
    """Absent calibration is a state worth recording, not a missing metric."""
    values = _by_metric(
        templating_metrics(
            config, _templater(), 0.4, coverage=1.0, calibration=None, over_merged=[]
        )
    )
    assert values[TEMPLATING_CALIBRATION_STATUS] == CalibrationStatus.DISABLED
    assert TEMPLATING_CALIBRATION_CANDIDATES not in values


def test_calibration_detail_travels_with_the_status(config: MistifyConfig) -> None:
    calibration = CalibrationResult(
        chosen_sim_th=0.5,
        status=CalibrationStatus.SELECTED,
        candidates=[(0.3, 0.004), (0.5, 0.003)],
        reason="fewest templates",
    )
    values = _by_metric(
        templating_metrics(
            config, _templater(), 0.5, coverage=1.0, calibration=calibration, over_merged=[]
        )
    )
    assert values[TEMPLATING_CALIBRATION_STATUS] == CalibrationStatus.SELECTED
    assert "0.3=" in str(values[TEMPLATING_CALIBRATION_CANDIDATES])


def test_over_merged_ids_only_appear_when_there_are_any(config: MistifyConfig) -> None:
    clean = _by_metric(
        templating_metrics(
            config, _templater(), 0.5, coverage=1.0, calibration=None, over_merged=[]
        )
    )
    assert clean[TEMPLATING_OVER_MERGED] == 0
    assert TEMPLATING_OVER_MERGED_IDS not in clean

    flagged = _by_metric(
        templating_metrics(
            config,
            _templater(),
            0.5,
            coverage=1.0,
            calibration=None,
            over_merged=[
                OverMergedTemplate(4, "a <*>", 3, ["INFO", "FATAL"]),
                OverMergedTemplate(7, "b <*>", 3, ["DEBUG", "ERROR"]),
            ],
        )
    )
    assert flagged[TEMPLATING_OVER_MERGED] == 2
    assert flagged[TEMPLATING_OVER_MERGED_IDS] == "4,7"


# --------------------------------------------------------------- anomaly


def _scored() -> list[AnomalyComponents]:
    return [
        AnomalyComponents(9, 0.88, 1.0, 0.9, 0.6),
        AnomalyComponents(5, 0.57, 0.8, 0.2, 0.3),
        AnomalyComponents(2, 0.14, 0.15, 0.0, 0.0),
    ]


def _summaries(worst_id: int) -> list[TemplateSummary]:
    return [
        TemplateSummary(
            template_id=tid,
            pattern=f"t{tid}",
            occurrence_count=10,
            first_seen="2026-08-30T14:00:00.000000Z",
            last_seen="2026-08-30T14:10:00.000000Z",
            severity_mix={"FATAL": 1} if tid == worst_id else {"INFO": 10},
            max_severity_rank=5 if tid == worst_id else 2,
        )
        for tid in (9, 5, 2)
    ]


def test_needle_position_is_one_when_the_worst_ranks_first(config: MistifyConfig) -> None:
    """The needle question asked directly: is the worst thing met early, or dug for?"""
    values = _by_metric(
        anomaly_metrics(config, _scored(), _summaries(9), _scored()[:2], 1, True, 0.0)
    )
    assert values[ANOMALY_NEEDLE_POSITION] == 1
    assert values[ANOMALY_TOP_TEMPLATE_ID] == 9
    assert values[ANOMALY_TOP_SCORE] == pytest.approx(0.88)


def test_needle_position_reports_a_buried_severe_template(config: MistifyConfig) -> None:
    values = _by_metric(
        anomaly_metrics(config, _scored(), _summaries(2), _scored()[:2], 0, True, 0.0)
    )
    assert values[ANOMALY_NEEDLE_POSITION] == 3


def test_uninformative_severity_is_recorded(config: MistifyConfig) -> None:
    values = _by_metric(
        anomaly_metrics(config, _scored(), _summaries(9), _scored()[:1], 0, False, 1.0)
    )
    assert values[ANOMALY_SEVERITY_INFORMATIVE] is False


def test_nothing_scored_reports_no_ranking(config: MistifyConfig) -> None:
    """An empty incident has no top template, and must not invent one."""
    values = _by_metric(anomaly_metrics(config, [], [], [], 0, True, 0.0))
    assert ANOMALY_TOP_TEMPLATE_ID not in values
    assert ANOMALY_NEEDLE_POSITION not in values


def test_every_entry_is_a_declared_metric(config: MistifyConfig) -> None:
    """Guards the vocabulary: a stage cannot publish something nobody declared."""
    from mistify.metrics import ALL_METRICS

    declared = {m.key for m in ALL_METRICS}
    entries = [
        *templating_metrics(config, _templater(), 0.5, 1.0, None, []),
        *anomaly_metrics(config, _scored(), _summaries(9), _scored()[:1], 0, True, 0.0),
    ]
    assert all(metric.key in declared for metric, _ in entries)

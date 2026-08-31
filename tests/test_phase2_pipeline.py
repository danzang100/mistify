"""Phase 2 end-to-end behaviour: sim_th calibration and deterministic anomaly scoring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mistify.common.config import MistifyConfig
from mistify.common.models import severity_rank
from mistify.pipeline import IngestResult, ingest
from mistify.scratchpad.db import ScratchpadDB


def _config(tmp_path: Path, tag: str, **sections: dict[str, object]) -> MistifyConfig:
    """A config pointed at a scratch directory, with `tag` keeping runs off each other."""
    raw: dict[str, dict[str, object]] = {
        "scratchpad": {"path": str(tmp_path / f"{tag}_{{incident_id}}.sqlite")},
        "drain3": {"snapshot_path": str(tmp_path / f"{tag}_drain3_{{incident_id}}.json")},
        "report": {"output_dir": str(tmp_path / "reports")},
    }
    for name, values in sections.items():
        raw.setdefault(name, {}).update(values)
    return MistifyConfig.model_validate(raw)


# --------------------------------------------------------------- calibration


def test_calibration_runs_by_default(ingested: IngestResult, config: MistifyConfig) -> None:
    """A threshold nobody chose by hand, selected for collapsing noise without over-merging."""
    assert ingested.calibration_status == "selected"
    assert ingested.sim_th in config.drain3.calibration_candidates


def test_calibration_can_be_disabled(incident_file: Path, tmp_path: Path) -> None:
    """With calibration off the configured sim_th is used as-is, and says so."""
    config = _config(tmp_path, "nocal", drain3={"calibrate": False, "sim_th": 0.4})
    result = ingest(incident_file, config, incident_id="nocal")
    assert result.sim_th == 0.4
    assert result.calibration_status == "disabled"


def test_calibration_records_health_metrics(
    ingested: IngestResult, loaded_db: ScratchpadDB
) -> None:
    """Decision G7: the choice must be auditable, not magic."""
    metrics = {m["metric"]: m for m in loaded_db.metrics("templating")}
    assert metrics["calibration_status"]["value"] == ingested.calibration_status
    assert metrics["calibration_candidates"]["value"]
    assert metrics["calibration_reason"]["value"]
    assert metrics["sim_th"]["value_num"] == ingested.sim_th


def test_over_merged_metric_is_zero_for_the_clean_incident(
    ingested: IngestResult, loaded_db: ScratchpadDB
) -> None:
    """The over-clustering half of §6.1: nothing in the synthetic file should trip it."""
    metric = next(
        m for m in loaded_db.metrics("templating") if m["metric"] == "over_merged_templates"
    )
    assert metric["value_num"] == 0
    assert ingested.over_merged == 0


# --------------------------------------------------------------- decision G3


def test_anomaly_stage_records_health_metrics(loaded_db: ScratchpadDB) -> None:
    metrics = {m["metric"]: m for m in loaded_db.metrics("anomaly")}
    assert metrics["scored_templates"]["value_num"] == loaded_db.template_count()
    assert metrics["top_template_id"]["value_num"] is not None
    assert 0.0 < float(metrics["top_score"]["value_num"]) <= 1.0
    assert metrics["bucket_minutes"]["value_num"] == 1
    assert "severity" in metrics["weights"]["value"]


def test_every_template_gets_an_anomaly_score(loaded_db: ScratchpadDB) -> None:
    """A stored default of 0.0 would make every ranking test pass for the wrong reason."""
    rows = loaded_db.top_templates(limit=500, order_by="anomaly_score")
    assert rows
    assert all(row["anomaly_score"] > 0.0 for row in rows)


def test_anomaly_weights_are_honoured_end_to_end(incident_file: Path, tmp_path: Path) -> None:
    """Severity alone must put the FATAL template on top, ahead of the frequent red herring."""
    config = _config(tmp_path, "sev", anomaly={"severity": 1.0, "burstiness": 0.0, "rarity": 0.0})
    result = ingest(incident_file, config, incident_id="sev")
    with ScratchpadDB(result.scratchpad_path) as db:
        top = db.top_templates(limit=1, order_by="anomaly_score")[0]
    assert top["max_severity_rank"] == severity_rank("FATAL")


# --------------------------------------------------------------- decision G1


def test_calibration_does_not_inflate_redaction_counts(incident_file: Path, tmp_path: Path) -> None:
    """Calibration redacts its own sample; those counts are not part of the real load.

    Without the `reset_counts()` after the calibration pass the health metrics would
    double-count every entity in the sample, so the same file would report different
    redaction totals depending on a templating setting.
    """
    calibrated = ingest(
        incident_file, _config(tmp_path, "cal", drain3={"calibrate": True}), incident_id="cal"
    )
    plain = ingest(
        incident_file, _config(tmp_path, "raw", drain3={"calibrate": False}), incident_id="raw"
    )
    assert calibrated.calibration_status != "disabled"
    assert plain.calibration_status == "disabled"
    assert calibrated.redaction_counts == plain.redaction_counts


# --------------------------------------------------------------- signal preservation


def test_coverage_is_the_reported_invariant(
    ingested: IngestResult, loaded_db: ScratchpadDB
) -> None:
    """Every event must be reachable through a template, or the agent cannot find it."""
    assert ingested.template_coverage == 1.0
    metric = next(m for m in loaded_db.metrics("templating") if m["metric"] == "template_coverage")
    assert metric["value_num"] == 1.0


def test_reduction_factor_describes_the_agent_workload(
    ingested: IngestResult, loaded_db: ScratchpadDB
) -> None:
    """Lines per template — how much smaller the haystack got, stated the honest way."""
    assert ingested.reduction_factor == pytest.approx(
        ingested.events_loaded / ingested.unique_templates
    )
    metric = next(m for m in loaded_db.metrics("templating") if m["metric"] == "reduction_factor")
    assert metric["value_num"] == pytest.approx(ingested.reduction_factor, abs=0.01)


def test_needle_position_is_recorded(loaded_db: ScratchpadDB) -> None:
    """Where the most severe template lands in the ranked list the agent reads top-down."""
    metric = next(
        m for m in loaded_db.metrics("anomaly") if m["metric"] == "max_severity_rank_position"
    )
    assert metric["value_num"] == 1


def test_clean_incident_evicts_nothing(ingested: IngestResult) -> None:
    assert ingested.evicted_templates == 0


# --------------------------------------------------------------- scoring adaptation


def _severityless_file(tmp_path: Path) -> Path:
    """A log with no severity field at all — most of Loghub looks like this."""
    src = tmp_path / "nosev.jsonl"
    with src.open("w", encoding="utf-8") as handle:
        for i in range(600):
            handle.write(
                json.dumps(
                    {
                        "timestamp": f"2026-08-30T14:{(i // 60) % 60:02d}:{i % 60:02d}Z",
                        "message": f"Received block blk_{i} of size {i * 17}",
                    }
                )
                + "\n"
            )
        for i in range(4):
            handle.write(
                json.dumps(
                    {
                        "timestamp": f"2026-08-30T14:30:{i:02d}Z",
                        "message": "Exception in namenode: lease recovery failed",
                    }
                )
                + "\n"
            )
    return src


def test_severity_is_dropped_when_no_log_carries_one(tmp_path: Path) -> None:
    """Half the scoring weight would otherwise be an identical constant on every template."""
    result = ingest(_severityless_file(tmp_path), _config(tmp_path, "nosev"), incident_id="nosev")
    with ScratchpadDB(result.scratchpad_path) as db:
        metrics = {m["metric"]: m["value"] for m in db.metrics("anomaly")}
    assert metrics["severity_informative"] == "False"
    assert float(metrics["unmapped_severity_share"]) == 1.0


def test_the_rare_exception_still_ranks_first_without_severity(tmp_path: Path) -> None:
    result = ingest(_severityless_file(tmp_path), _config(tmp_path, "nosev2"), incident_id="nosev2")
    with ScratchpadDB(result.scratchpad_path) as db:
        top = db.top_templates(limit=1, order_by="anomaly_score")[0]
    assert "Exception in namenode" in top["pattern"]


def test_labelled_logs_keep_the_severity_component(ingested: IngestResult) -> None:
    with ScratchpadDB(ingested.scratchpad_path) as db:
        metrics = {m["metric"]: m["value"] for m in db.metrics("anomaly")}
    assert metrics["severity_informative"] == "True"


# --------------------------------------------------------------- signal set


def test_signal_template_set_is_recorded(loaded_db: ScratchpadDB) -> None:
    """The set the Phase 3 adversarial check must account for."""
    metrics = {m["metric"]: m for m in loaded_db.metrics("anomaly")}
    count = int(metrics["signal_templates"]["value_num"])
    ids = metrics["signal_template_ids"]["value"].split(",")
    assert count >= 1
    assert len(ids) == count


def test_signal_set_leads_with_the_top_ranked_template(loaded_db: ScratchpadDB) -> None:
    metrics = {m["metric"]: m["value"] for m in loaded_db.metrics("anomaly")}
    first = metrics["signal_template_ids"].split(",")[0]
    assert first == metrics["top_template_id"]


def test_noise_suppression_count_is_recorded(loaded_db: ScratchpadDB) -> None:
    metrics = {m["metric"]: m for m in loaded_db.metrics("anomaly")}
    assert metrics["suppressed_noise_templates"]["value_num"] is not None

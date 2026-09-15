"""End-to-end behaviour of sim_th calibration and deterministic anomaly scoring."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from mistify.common.config import MistifyConfig
from mistify.common.models import severity_rank
from mistify.metrics import (
    ANOMALY_BUCKET_MINUTES,
    ANOMALY_NEEDLE_POSITION,
    ANOMALY_SCORED_TEMPLATES,
    ANOMALY_SEVERITY_INFORMATIVE,
    ANOMALY_SIGNAL_TEMPLATE_IDS,
    ANOMALY_SIGNAL_TEMPLATES,
    ANOMALY_SUPPRESSED_NOISE,
    ANOMALY_TOP_SCORE,
    ANOMALY_TOP_TEMPLATE_ID,
    ANOMALY_UNMAPPED_SEVERITY_SHARE,
    ANOMALY_WEIGHTS,
    TEMPLATING_CALIBRATION_CANDIDATES,
    TEMPLATING_CALIBRATION_REASON,
    TEMPLATING_CALIBRATION_STATUS,
    TEMPLATING_MAX_CLUSTERS,
    TEMPLATING_OVER_MERGED,
    TEMPLATING_SIM_TH,
    MetricView,
)
from mistify.pipeline import IngestResult, ingest
from mistify.scratchpad.db import ScratchpadDB

# --------------------------------------------------------------- calibration


def test_calibration_runs_by_default(ingested: IngestResult, config: MistifyConfig) -> None:
    """A threshold nobody chose by hand, selected for collapsing noise without over-merging."""
    assert ingested.calibration_status == "selected"
    assert ingested.sim_th in config.drain3.calibration_candidates


def test_calibration_can_be_disabled(
    incident_file: Path, tmp_path: Path, make_config: Callable[..., MistifyConfig]
) -> None:
    """With calibration off the configured sim_th is used as-is, and says so."""
    config = make_config(drain3={"calibrate": False, "sim_th": 0.4})
    result = ingest(incident_file, config, incident_id="nocal")
    assert result.sim_th == 0.4
    assert result.calibration_status == "disabled"


def test_calibration_records_health_metrics(
    ingested: IngestResult, loaded_db: ScratchpadDB
) -> None:
    """The choice must be auditable, not magic."""
    view = MetricView(loaded_db.metrics("templating"))
    assert view.text(TEMPLATING_CALIBRATION_STATUS) == ingested.calibration_status
    assert view.text(TEMPLATING_CALIBRATION_CANDIDATES)
    assert view.text(TEMPLATING_CALIBRATION_REASON)
    assert view.number(TEMPLATING_SIM_TH) == ingested.sim_th


def test_over_merged_metric_is_zero_for_the_clean_incident(
    ingested: IngestResult, loaded_db: ScratchpadDB
) -> None:
    """The over-clustering half of the health check: nothing in the synthetic file trips it."""
    view = MetricView(loaded_db.metrics("templating"))
    assert view.number(TEMPLATING_OVER_MERGED) == 0
    assert ingested.over_merged == 0


# --------------------------------------------------------------- anomaly scoring


def test_anomaly_stage_records_health_metrics(loaded_db: ScratchpadDB) -> None:
    view = MetricView(loaded_db.metrics("anomaly"))
    top_score = view.number(ANOMALY_TOP_SCORE)
    weights = view.text(ANOMALY_WEIGHTS)
    assert view.number(ANOMALY_SCORED_TEMPLATES) == loaded_db.template_count()
    assert view.number(ANOMALY_TOP_TEMPLATE_ID) is not None
    assert top_score is not None and 0.0 < top_score <= 1.0
    assert view.number(ANOMALY_BUCKET_MINUTES) == 1
    assert weights is not None and "severity" in weights


def test_every_template_gets_an_anomaly_score(loaded_db: ScratchpadDB) -> None:
    """A stored default of 0.0 would make every ranking test pass for the wrong reason."""
    rows = loaded_db.top_templates(limit=500, order_by="anomaly_score")
    assert rows
    assert all(row["anomaly_score"] > 0.0 for row in rows)


def test_anomaly_weights_are_honoured_end_to_end(
    incident_file: Path, tmp_path: Path, make_config: Callable[..., MistifyConfig]
) -> None:
    """Severity alone must put the FATAL template on top, ahead of the frequent red herring."""
    config = make_config(anomaly={"severity": 1.0, "burstiness": 0.0, "rarity": 0.0})
    result = ingest(incident_file, config, incident_id="sev")
    with ScratchpadDB(result.scratchpad_path) as db:
        top = db.top_templates(limit=1, order_by="anomaly_score")[0]
    assert top["max_severity_rank"] == severity_rank("FATAL")


# --------------------------------------------------------------- redaction before templating


def test_calibration_does_not_inflate_redaction_counts(
    incident_file: Path, tmp_path: Path, make_config: Callable[..., MistifyConfig]
) -> None:
    """Calibration redacts its own sample; those counts are not part of the real load.

    Without the `reset_counts()` after the calibration pass the health metrics would
    double-count every entity in the sample, so the same file would report different
    redaction totals depending on a templating setting.
    """
    calibrated = ingest(incident_file, make_config(drain3={"calibrate": True}), incident_id="cal")
    plain = ingest(incident_file, make_config(drain3={"calibrate": False}), incident_id="raw")
    assert calibrated.calibration_status != "disabled"
    assert plain.calibration_status == "disabled"
    assert calibrated.redaction_counts == plain.redaction_counts


# --------------------------------------------------------------- signal preservation


def test_needle_position_is_recorded(loaded_db: ScratchpadDB) -> None:
    """Where the most severe template lands in the ranked list the agent reads top-down."""
    view = MetricView(loaded_db.metrics("anomaly"))
    assert view.number(ANOMALY_NEEDLE_POSITION) == 1


def test_clean_incident_evicts_nothing(ingested: IngestResult) -> None:
    assert ingested.evicted_templates == 0


# --------------------------------------------------------------- scoring adaptation


def _severityless_file(tmp_path: Path) -> Path:
    """A log with no severity field at all - most of Loghub looks like this."""
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


def test_severity_is_dropped_when_no_log_carries_one(
    tmp_path: Path, make_config: Callable[..., MistifyConfig]
) -> None:
    """Half the scoring weight would otherwise be an identical constant on every template."""
    result = ingest(_severityless_file(tmp_path), make_config(), incident_id="nosev")
    with ScratchpadDB(result.scratchpad_path) as db:
        view = MetricView(db.metrics("anomaly"))
    assert view.flag(ANOMALY_SEVERITY_INFORMATIVE) is False
    assert view.number(ANOMALY_UNMAPPED_SEVERITY_SHARE) == 1.0


def test_the_rare_exception_still_ranks_first_without_severity(
    tmp_path: Path, make_config: Callable[..., MistifyConfig]
) -> None:
    result = ingest(_severityless_file(tmp_path), make_config(), incident_id="nosev2")
    with ScratchpadDB(result.scratchpad_path) as db:
        top = db.top_templates(limit=1, order_by="anomaly_score")[0]
    assert "Exception in namenode" in top["pattern"]


def test_labelled_logs_keep_the_severity_component(ingested: IngestResult) -> None:
    with ScratchpadDB(ingested.scratchpad_path) as db:
        view = MetricView(db.metrics("anomaly"))
    assert view.flag(ANOMALY_SEVERITY_INFORMATIVE) is True


# --------------------------------------------------------------- signal set


def test_signal_template_set_is_recorded(loaded_db: ScratchpadDB) -> None:
    """The set the adversarial check must account for."""
    view = MetricView(loaded_db.metrics("anomaly"))
    recorded = view.number(ANOMALY_SIGNAL_TEMPLATES)
    ids_value = view.text(ANOMALY_SIGNAL_TEMPLATE_IDS)
    assert recorded is not None and ids_value is not None
    count = int(recorded)
    ids = ids_value.split(",")
    assert count >= 1
    assert len(ids) == count


def test_signal_set_leads_with_the_top_ranked_template(loaded_db: ScratchpadDB) -> None:
    view = MetricView(loaded_db.metrics("anomaly"))
    ids_value = view.text(ANOMALY_SIGNAL_TEMPLATE_IDS)
    assert ids_value is not None
    assert ids_value.split(",")[0] == view.text(ANOMALY_TOP_TEMPLATE_ID)


def test_noise_suppression_count_is_recorded(loaded_db: ScratchpadDB) -> None:
    view = MetricView(loaded_db.metrics("anomaly"))
    assert view.number(ANOMALY_SUPPRESSED_NOISE) is not None


# ------------------------------------- the cluster ceiling a run lowers for itself


def _uncompressible(count: int = 3000) -> list[str]:
    """Lines that share no structure, so clustering cannot do anything with them.

    Varying the *token count and the words*, not the numbers. A first attempt varied only the
    numbers -- `job-1 finished stage 1 ...` -- and Drain3 masked them straight back into a
    single template, so the file compressed perfectly and the test asserted nothing. Drain3
    buckets by token count first and prefix tokens second, so both have to move.
    """
    return [" ".join(f"tok{i}x{j}" for j in range((i % 23) + 3)) for i in range(count)]


def _compressible(count: int = 3000) -> list[str]:
    """One shape repeated, which is what a log that clusters well looks like."""
    return [
        f"2026-08-30T14:00:00Z INFO worker handled request {i} in {i % 40}ms" for i in range(count)
    ]


def test_a_file_that_will_not_compress_gets_a_lower_cluster_ceiling(
    tmp_path: Path, make_config: Callable[..., MistifyConfig]
) -> None:
    """Drain3's per-line cost grows with the clusters it holds, and on a file where almost
    every line is unique it holds one per line. Measured on a real CI log, capping was 2.15x
    the throughput for 0.17% more template fragmentation -- the templater keeps its own
    registry, so eviction loses no template from the output.
    """
    from mistify.metrics import MetricView
    from mistify.scratchpad.db import ScratchpadDB

    config = make_config(drain3={"uncompressible_max_clusters": 200})
    source = tmp_path / "noisy.log"
    source.write_text("\n".join(_uncompressible()), encoding="utf-8")

    result = ingest(source, config, incident_id="uncompressible")

    assert result.calibration_status == "under_clustered"
    with ScratchpadDB(result.scratchpad_path) as db:
        assert MetricView(db.metrics()).number(TEMPLATING_MAX_CLUSTERS) == 200
    # Capping evicts from Drain3's live tree; it does not lose templates from the report.
    assert result.template_coverage == 1.0


def test_a_file_that_compresses_keeps_the_configured_ceiling(
    tmp_path: Path, make_config: Callable[..., MistifyConfig]
) -> None:
    """The control, and the whole reason this is conditional rather than a lower default.

    "Many templates because the log is genuinely diverse" and "many templates because
    clustering failed" look identical in a count. Capping the first would fragment a file that
    was clustering perfectly well, so the trigger is the compression ratio, not the count.
    """
    from mistify.metrics import MetricView
    from mistify.scratchpad.db import ScratchpadDB

    config = make_config(drain3={"uncompressible_max_clusters": 200})
    source = tmp_path / "tidy.log"
    source.write_text("\n".join(_compressible()), encoding="utf-8")

    result = ingest(source, config, incident_id="compressible")

    assert result.calibration_status != "under_clustered"
    with ScratchpadDB(result.scratchpad_path) as db:
        assert (
            MetricView(db.metrics()).number(TEMPLATING_MAX_CLUSTERS) == config.drain3.max_clusters
        )
    assert result.evicted_templates == 0

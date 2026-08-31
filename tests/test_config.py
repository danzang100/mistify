"""Config loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from mistify.common.config import AnomalyConfig, MistifyConfig, load_config


def test_defaults_load_without_a_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert config.pipeline.max_agent_tool_calls == 20
    assert config.adapters.registered == ["json_lines"]


def test_repo_config_is_valid() -> None:
    """The shipped config.yaml must actually validate against the model."""
    config = load_config(Path(__file__).parent.parent / "config.yaml")
    assert config.redaction.mode == "strict"
    assert config.drain3.sim_th == 0.4


def test_round_trips_through_yaml(tmp_path: Path) -> None:
    original = MistifyConfig()
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(original.model_dump(mode="json")), encoding="utf-8")
    assert load_config(path) == original


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    """A typo in a config key should fail the run, not leave a default silently in place."""
    path = tmp_path / "config.yaml"
    path.write_text("drain3:\n  sim_threshold: 0.4\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="sim_threshold"):
        load_config(path)


def test_unknown_redaction_entity_is_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown redaction entities"):
        MistifyConfig.model_validate({"redaction": {"entities": ["email", "eyeball_scan"]}})


def test_credit_card_is_not_a_supported_entity() -> None:
    """Out of scope for v1 (decision G5): the pattern shredded diagnostic identifiers."""
    with pytest.raises(ValidationError, match="credit_card"):
        MistifyConfig.model_validate({"redaction": {"entities": ["credit_card"]}})


def test_invalid_redaction_mode_is_rejected() -> None:
    with pytest.raises(ValidationError):
        MistifyConfig.model_validate({"redaction": {"mode": "sometimes"}})


def test_loop_and_adversarial_models_differ_by_default() -> None:
    """Architecture §6.3: a shared model gives the reasoner and its checker one blind spot."""
    llm = MistifyConfig().llm
    assert llm.model != llm.adversarial_model


def test_path_templates_interpolate_the_incident_id() -> None:
    config = MistifyConfig()
    assert config.scratchpad_path("abc-123").name == "incident_abc-123.sqlite"
    snapshot = config.snapshot_path("abc-123")
    assert snapshot is not None and "abc-123" in snapshot.name


def test_snapshot_path_is_none_when_persistence_disabled() -> None:
    config = MistifyConfig.model_validate({"drain3": {"persistence": "none"}})
    assert config.snapshot_path("abc") is None


def test_missing_explicit_config_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "absent.yaml")


def test_empty_calibration_candidates_are_rejected() -> None:
    """Calibration with nothing to try would silently fall back to an unexamined guess."""
    with pytest.raises(ValidationError, match="calibration_candidates must not be empty"):
        MistifyConfig.model_validate({"drain3": {"calibration_candidates": []}})


def test_calibration_candidates_outside_the_unit_range_are_rejected() -> None:
    with pytest.raises(ValidationError, match=r"between 0\.0 and 1\.0"):
        MistifyConfig.model_validate({"drain3": {"calibration_candidates": [0.3, 1.4]}})


def test_inverted_target_ratio_band_is_rejected() -> None:
    """An empty band means no candidate can ever land in it, so every run is flagged."""
    with pytest.raises(ValidationError, match="target_ratio_min must not exceed"):
        MistifyConfig.model_validate({"drain3": {"target_ratio_min": 0.4, "target_ratio_max": 0.1}})


def test_all_zero_anomaly_weights_are_rejected() -> None:
    """Weights are normalised by their sum, so an all-zero set has no meaning."""
    with pytest.raises(ValidationError, match="at least one anomaly weight"):
        MistifyConfig.model_validate(
            {"anomaly": {"severity": 0.0, "burstiness": 0.0, "rarity": 0.0}}
        )


def test_anomaly_weights_expose_the_three_components() -> None:
    assert set(AnomalyConfig().weights()) == {"severity", "burstiness", "rarity"}


def test_repo_config_loads_the_phase_2_sections() -> None:
    """The shipped config.yaml must carry the calibration and anomaly settings too."""
    config = load_config(Path(__file__).parent.parent / "config.yaml")
    assert config.drain3.calibrate is True
    assert config.drain3.calibration_candidates == [0.3, 0.4, 0.5]
    assert config.drain3.target_ratio_min < config.drain3.target_ratio_max
    assert config.anomaly.weights() == {"severity": 0.5, "burstiness": 0.3, "rarity": 0.2}
    assert config.anomaly.bucket_minutes == 1

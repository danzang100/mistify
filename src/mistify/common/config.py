"""Configuration model and loader.

`config.yaml` is the single source of truth for pipeline behaviour. Every field is validated
here, and unknown keys are rejected rather than ignored -- a typo in a config key should fail
the run, not silently leave a default in place.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mistify.common.models import NoiseThresholds
from mistify.redaction.patterns import DEFAULT_ENTITIES, SUPPORTED_ENTITIES

__all__ = [
    "AdaptersConfig",
    "AnomalyConfig",
    "BootstrapConfig",
    "Drain3Config",
    "LLMConfig",
    "MistifyConfig",
    "PipelineConfig",
    "RedactionConfig",
    "ReportConfig",
    "ScratchpadConfig",
    "load_config",
]

DEFAULT_CONFIG_PATH = Path("config.yaml")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PipelineConfig(_Strict):
    max_agent_tool_calls: int = Field(default=20, ge=1)


class AdaptersConfig(_Strict):
    auto_detect: bool = True
    #: Phase 1 registers json_lines only. Elastic, Loki and OTLP arrive in Phase 4.
    registered: list[str] = Field(default_factory=lambda: ["json_lines"])
    #: Minimum detect() confidence before an adapter is accepted; below this the
    #: unknown-format bootstrapper takes over (Phase 4).
    min_detect_confidence: float = Field(default=0.6, ge=0.0, le=1.0)


class BootstrapConfig(_Strict):
    """Unknown-format bootstrapper settings. Consumed from Phase 4 onward."""

    sample_size: int = Field(default=100, ge=1)
    llm_fallback_sample_size: int = Field(default=40, ge=1)
    min_match_rate: float = Field(default=0.85, ge=0.0, le=1.0)


class Drain3Config(_Strict):
    sim_th: float = Field(default=0.4, ge=0.0, le=1.0)
    depth: int = Field(default=4, ge=3)
    #: Generous by design. Eviction no longer orphans events, but a shape that reappears
    #: after eviction gets a fresh id, which splits one condition's counts across several
    #: templates. Templates are cheap; fragmented statistics are not.
    max_clusters: int = Field(default=10000, ge=1)
    persistence: Literal["file", "none"] = "file"
    snapshot_path: str = ".cache/drain3_{incident_id}.json"

    #: Try several thresholds against a sample and keep the one whose compression ratio
    #: lands in the target band, instead of trusting one hardcoded guess (architecture
    #: §6.1). When disabled, `sim_th` above is used as-is.
    calibrate: bool = True
    calibration_candidates: list[float] = Field(default_factory=lambda: [0.3, 0.4, 0.5])
    calibration_sample_size: int = Field(default=2000, ge=1)
    #: Unique templates over lines. Above the maximum is under-clustering (no compression);
    #: below the minimum suggests distinct conditions were merged.
    target_ratio_min: float = Field(default=0.002, ge=0.0, le=1.0)
    target_ratio_max: float = Field(default=0.30, ge=0.0, le=1.0)
    #: A template spanning this many severity levels is flagged as probably over-merged.
    over_merge_severity_span: int = Field(default=3, ge=2)

    @field_validator("calibration_candidates")
    @classmethod
    def _candidates_are_thresholds(cls, value: list[float]) -> list[float]:
        if not value:
            raise ValueError("calibration_candidates must not be empty")
        if any(not 0.0 <= v <= 1.0 for v in value):
            raise ValueError("calibration_candidates must all be between 0.0 and 1.0")
        return value

    @model_validator(mode="after")
    def _band_is_ordered(self) -> Drain3Config:
        if self.target_ratio_min > self.target_ratio_max:
            raise ValueError("target_ratio_min must not exceed target_ratio_max")
        return self


class AnomalyConfig(_Strict):
    """Weights for the deterministic template anomaly score (decision G3).

    Relative contributions, normalised before use -- they do not need to sum to one. Phase 5
    sweeps these against the eval corpus.
    """

    severity: float = Field(default=0.5, ge=0.0)
    burstiness: float = Field(default=0.3, ge=0.0)
    rarity: float = Field(default=0.2, ge=0.0)
    #: Width of the time bucket burstiness is measured over, in minutes.
    bucket_minutes: int = Field(default=1, ge=1)

    #: Above this share of unmapped severities, the severity component is treated as
    #: uninformative and its weight is redistributed. On a log with no severity field every
    #: line defaults to INFO, so severity contributes an identical constant to every
    #: template -- half the scoring weight doing nothing, silently.
    severity_unmapped_ceiling: float = Field(default=0.9, ge=0.0, le=1.0)

    #: A template is noise when it takes at least this share of the file *and* scores below
    #: `noise_anomaly_ceiling`. Volume alone is not noise: a flood can be the incident
    #: (architecture §6.4).
    noise_share_threshold: float = Field(default=0.15, ge=0.0, le=1.0)
    noise_anomaly_ceiling: float = Field(default=0.35, ge=0.0, le=1.0)

    #: Bounds on the "high anomaly" set handed to the adversarial check. The cut itself is
    #: found at the largest score gap rather than a fixed threshold, which would be tuned on
    #: whatever fixture happened to be at hand.
    signal_min_templates: int = Field(default=3, ge=1)
    signal_max_templates: int = Field(default=15, ge=1)

    @model_validator(mode="after")
    def _at_least_one_positive_weight(self) -> AnomalyConfig:
        if self.severity + self.burstiness + self.rarity <= 0:
            raise ValueError("at least one anomaly weight must be greater than zero")
        return self

    def noise_thresholds(self) -> NoiseThresholds:
        """The configured definition of noise, as one value to hand to the scratchpad."""
        return NoiseThresholds(
            share=self.noise_share_threshold, anomaly_ceiling=self.noise_anomaly_ceiling
        )

    def weights(self) -> dict[str, float]:
        return {
            "severity": self.severity,
            "burstiness": self.burstiness,
            "rarity": self.rarity,
        }


class RedactionConfig(_Strict):
    mode: Literal["strict", "permissive", "off"] = "strict"
    #: `credit_card` is out of scope for v1 and `phone` is available but off by default --
    #: both shapes collide with numeric identifiers and neither carries a checksum to tell
    #: the difference (decision G5). See `redaction/patterns.py`.
    entities: list[str] = Field(default_factory=lambda: list(DEFAULT_ENTITIES))
    #: Mixed into the entity hash so redaction tokens are not reversible via a rainbow table
    #: of common values. Correlation is preserved within a run regardless.
    salt: str = ""

    #: Keep a local mapping from placeholder back to original value, so an operator can
    #: reveal values in their own logs. Off by default: the vault is plaintext on disk and
    #: turning it on trades away part of what redaction buys. It is written to a separate
    #: file from the scratchpad, and never to the scratchpad itself -- the investigator's
    #: read-only SQL channel can read any table in the database it is pointed at, so a vault
    #: table living there would be readable by the model.
    vault: bool = False
    vault_path: str = ".cache/vault_{incident_id}.sqlite"

    @field_validator("entities")
    @classmethod
    def _known_entities(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(SUPPORTED_ENTITIES))
        if unknown:
            supported = ", ".join(sorted(SUPPORTED_ENTITIES))
            raise ValueError(
                f"unknown redaction entities: {', '.join(unknown)}. Supported: {supported}"
            )
        return value


class ScratchpadConfig(_Strict):
    path: str = ".cache/incident_{incident_id}.sqlite"


class LLMConfig(_Strict):
    """Model assignments.

    The loop and the adversarial pass must not share a model: architecture §6.3 identifies
    correlated blind spots between the reasoner and its checker as the core risk of the
    adversarial design, and a shared model is the most direct way to produce them.
    """

    model: str = "claude-opus-5"
    adversarial_model: str = "claude-sonnet-5"
    bootstrap_model: str = "claude-haiku-4-5"
    judge_model: str = "claude-opus-5"
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"


class ReportConfig(_Strict):
    format: Literal["markdown", "html", "pdf"] = "markdown"
    output_dir: str = "./reports"


class MistifyConfig(_Strict):
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    adapters: AdaptersConfig = Field(default_factory=AdaptersConfig)
    bootstrap: BootstrapConfig = Field(default_factory=BootstrapConfig)
    drain3: Drain3Config = Field(default_factory=Drain3Config)
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    scratchpad: ScratchpadConfig = Field(default_factory=ScratchpadConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)

    def scratchpad_path(self, incident_id: str) -> Path:
        return Path(self.scratchpad.path.format(incident_id=incident_id))

    def vault_path(self, incident_id: str) -> Path | None:
        if not self.redaction.vault:
            return None
        return Path(self.redaction.vault_path.format(incident_id=incident_id))

    def snapshot_path(self, incident_id: str) -> Path | None:
        if self.drain3.persistence == "none":
            return None
        return Path(self.drain3.snapshot_path.format(incident_id=incident_id))


def load_config(path: str | Path | None = None) -> MistifyConfig:
    """Load and validate config from YAML, falling back to defaults when absent."""
    if path is None:
        if not DEFAULT_CONFIG_PATH.exists():
            return MistifyConfig()
        path = DEFAULT_CONFIG_PATH

    resolved = Path(path)
    if not resolved.exists():
        raise FileNotFoundError(f"config file not found: {resolved}")

    raw: Any = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    if raw is None:
        return MistifyConfig()
    if not isinstance(raw, dict):
        raise ValueError(f"config root must be a mapping, got {type(raw).__name__}")
    return MistifyConfig.model_validate(raw)

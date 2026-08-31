"""Configuration model and loader.

`config.yaml` is the single source of truth for pipeline behaviour. Every field is validated
here, and unknown keys are rejected rather than ignored -- a typo in a config key should fail
the run, not silently leave a default in place.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from mistify.redaction.patterns import SUPPORTED_ENTITIES

__all__ = [
    "AdaptersConfig",
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
    max_clusters: int = Field(default=2000, ge=1)
    persistence: Literal["file", "none"] = "file"
    snapshot_path: str = ".cache/drain3_{incident_id}.json"


class RedactionConfig(_Strict):
    mode: Literal["strict", "permissive", "off"] = "strict"
    #: Phase 1 ships the three entities the walking skeleton needs. The remaining entities
    #: land in Phase 2 with the false-positive corpus that keeps them honest. `credit_card`
    #: is deliberately out of scope for v1 (decision G5).
    entities: list[str] = Field(default_factory=lambda: ["email", "ipv4", "api_key"])
    #: Mixed into the entity hash so redaction tokens are not reversible via a rainbow table
    #: of common values. Correlation is preserved within a run regardless.
    salt: str = ""

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
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    scratchpad: ScratchpadConfig = Field(default_factory=ScratchpadConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)

    def scratchpad_path(self, incident_id: str) -> Path:
        return Path(self.scratchpad.path.format(incident_id=incident_id))

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

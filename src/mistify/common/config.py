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
    "HealthConfig",
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
    #: 30, up from 20: with a brief the loop searches harder, and the briefed run over a real
    #: customer log hit 20 having found the answer at step 13 and then spent the rest
    #: restating it, so the last calls bought nothing either way. The cost curve is bounded
    #: by `tool_result_history_steps`, not by this.
    max_agent_tool_calls: int = Field(default=30, ge=1)

    #: Reading calls the rebuttal may make before it answers the critique. Zero is the old
    #: behaviour: answer from the notes alone. It exists because an objection is often
    #: answerable from a row the loop never cited -- the failure line a second after the
    #: request it did cite -- and a rebuttal that cannot fetch it can only repeat itself.
    rebuttal_tool_calls: int = Field(default=3, ge=0)

    #: How many recent steps keep their tool output in full. The loop re-sends the whole
    #: conversation every step, so a slice pulled early is paid for again on every step after
    #: it; older results are reduced to the summary line the tool already wrote. Zero keeps
    #: everything, which is what the cost curve looked like before this existed.
    tool_result_history_steps: int = Field(default=3, ge=0)

    #: How many times a conclusion may be sent back for ignoring something the investigation
    #: was shown. Zero accepts the first conclusion offered. It was a constructor default the
    #: runner never passed, so the one lever measurement says matters could not be moved
    #: without editing source -- and it fired on fifteen runs out of fifteen, which makes it
    #: part of the normal path rather than a backstop.
    coverage_nudges: int = Field(default=1, ge=0)


def _registered_adapters() -> list[str]:
    """Every adapter the registry implements, in a stable order.

    Imported inside the function rather than at module scope: config is imported by almost
    everything, and pulling the adapter package in at import time to read one list is a cost
    every caller pays whether or not they ever ingest anything.
    """
    from mistify.adapters.registry import ADAPTERS

    return sorted(ADAPTERS)


class AdaptersConfig(_Strict):
    auto_detect: bool = True
    #: Derived from the adapter registry rather than listed, so it cannot go stale.
    #:
    #: It said `["json_lines"]` with a comment promising Loki and OTLP would arrive later.
    #: They arrived and this did not move, so every caller that built a config in code rather
    #: than from `config.yaml` -- the test suite, the eval harness, anything importing the
    #: package -- silently had one adapter registered. An OTLP export handed to one of those
    #: did not fail: detection found nothing, the raw-line reader took it, and the templates
    #: came out as slices of JSON export text. Measured accidentally on a 290 MB fixture, which
    #: produced 1,248 templates of `{"resourceLogs": [{"resource": ...` against the 9 the same
    #: incident produces when it is actually parsed.
    #:
    #: `raw_lines` is in the registry and included here, which is harmless: its `detect` returns
    #: zero always, so it is never selected by confidence -- only reached deliberately.
    registered: list[str] = Field(default_factory=lambda: _registered_adapters())
    #: Minimum detect() confidence before an adapter is accepted; below this the
    #: unknown-format bootstrapper takes over.
    min_detect_confidence: float = Field(default=0.6, ge=0.0, le=1.0)

    #: What to do when nothing matches. `raw_lines` reads the file line by line and records
    #: that it did; `error` refuses it. Falling back is the default because an investigation
    #: that cannot start is not safer than one that starts with less -- templating, ranking and
    #: search all work on message text alone -- and the degradation is recorded rather than
    #: hidden. Set to `error` where a wrong-looking parse is worse than no parse at all.
    on_unknown_format: Literal["raw_lines", "error"] = "raw_lines"


class BootstrapConfig(_Strict):
    """Unknown-format bootstrapper settings."""

    #: Off by default. The architecture's risk table calls this stage's failure *silent* -- a
    #: confidently wrong schema yields templates that are garbage with no error thrown -- so it
    #: is opted into rather than inherited. The match-rate gate runs either way; this decides
    #: whether inference is attempted at all.
    enabled: bool = False

    #: Whether the model may be asked when looking at the lines was not enough. The structural
    #: pass costs nothing and handles most formats; this is the part that costs a call.
    use_model: bool = True

    sample_size: int = Field(default=100, ge=1)
    llm_fallback_sample_size: int = Field(default=40, ge=1)
    min_match_rate: float = Field(default=0.85, ge=0.0, le=1.0)

    #: Where schemas that pass the gate are persisted, so the next file from a source skips
    #: inference. Configurable like every other output path, and for the same reason: it was
    #: hardcoded to `.cache/inferred` relative to the working directory, which meant the test
    #: suite read and wrote the repository's own cache. One real bootstrapper run then changed
    #: what the tests saw, and a test asserting a severity was recovered began failing against
    #: a schema written by a different file entirely.
    schema_dir: str = ".cache/inferred"

    #: Whether a schema that passes the gate is written to `schema_dir` at all. Reuse is what
    #: makes inference affordable across files, and a run that should leave no trace -- a test,
    #: a one-off over somebody else's log -- needs to be able to decline it without also
    #: declining the cache it reads.
    persist_schemas: bool = True


class Drain3Config(_Strict):
    sim_th: float = Field(default=0.4, ge=0.0, le=1.0)
    depth: int = Field(default=4, ge=3)
    #: Generous by design. Eviction no longer orphans events, but a shape that reappears
    #: after eviction gets a fresh id, which splits one condition's counts across several
    #: templates. Templates are cheap; fragmented statistics are not.
    max_clusters: int = Field(default=10000, ge=1)
    persistence: Literal["file", "none"] = "file"
    snapshot_path: str = ".cache/drain3_{incident_id}.json"

    #: `max_clusters` to use when calibration reports the file does not compress at all.
    #:
    #: Drain3 compares each line against the clusters in its leaf, so its cost grows with how
    #: many it is holding. On a log that clusters normally this never matters -- Loghub-2.0 BGL
    #: settles at 77 templates and evicts nothing whatever the cap is. On a log that does not
    #: cluster it is the whole cost: a CI log where 85% of lines are unique ran at 512 lines/s
    #: at 10,000 and 2,882 lines/s at 500.
    #:
    #: Capping is close to free because `DrainTemplater` keeps its own registry of every
    #: template it has seen, independent of Drain3's LRU. Evicting a cluster does not lose the
    #: template; it only stops that cluster absorbing later lines, so a few of them start new
    #: templates instead. Measured on the same file: 9,291 templates uncapped against 9,310 at
    #: a cap of 500 -- 0.2% more fragmentation for 5.6x the throughput, with template coverage
    #: 1.0 either way.
    #:
    #: Applied only when calibration says `under_clustered`, never on a file that compresses.
    #: That distinction is the point: "many templates because the log is genuinely diverse" and
    #: "many templates because clustering failed" look identical in a count and completely
    #: different in a compression ratio, and only the second one should be capped.
    uncompressible_max_clusters: int = Field(default=2000, ge=1)

    #: Try several thresholds against a sample and keep the one whose compression ratio
    #: lands in the target band, instead of trusting one hardcoded guess about an unseen
    #: file. When disabled, `sim_th` above is used as-is.
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
    """Weights for the deterministic template anomaly score.

    Relative contributions, normalised before use -- they do not need to sum to one. The eval
    harness is where they get swept.
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
    #: `noise_anomaly_ceiling`. Volume alone is not noise: a flood can be the incident.
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
    #: `strict` redacts; `off` does not. There is no third setting: a `permissive` value
    #: used to be accepted and behaved exactly like `strict`, which is a promise of a
    #: distinction that did not exist.
    mode: Literal["strict", "off"] = "strict"
    #: `credit_card` is out of scope for v1 and `phone` is available but off by default --
    #: both shapes collide with numeric identifiers and neither carries a checksum to tell
    #: the difference. See `redaction/patterns.py`.
    entities: list[str] = Field(default_factory=lambda: list(DEFAULT_ENTITIES))
    #: Mixed into the placeholder hash. Empty, the default, means a random salt is drawn per
    #: incident at ingest and kept nowhere, so a placeholder in one report cannot be checked
    #: against a guessed value -- "is 10.0.0.1 in this incident?" -- by anyone who knows the
    #: scheme. Set a fixed value only when placeholders
    #: must agree across incidents, and treat it as a secret when you do. Correlation within
    #: an incident holds either way.
    salt: str = ""

    #: Keep a local mapping from placeholder back to original value, so an operator can
    #: reveal values in their own logs. Off by default: the vault is plaintext on disk and
    #: turning it on trades away part of what redaction buys. It is written to a separate
    #: file from the scratchpad, and never to the scratchpad itself -- the investigator's
    #: read-only SQL channel can read any table in the database it is pointed at, so a vault
    #: table living there would be readable by the model.
    vault: bool = False
    vault_path: str = ".cache/vault_{incident_id}.sqlite"

    #: Worker processes for redaction. 1 is serial; 0 means "use the machine's cores".
    #:
    #: Redaction is roughly 42% of an ingest and the only stage that parallelises cleanly, so
    #: this is the throughput knob that matters at volume: 3.20x on the stage and 1.55x end to
    #: end at 8 workers, with byte-identical output, which it must be -- tokens are salted
    #: hashes and do not depend on which process computed them.
    #:
    #: Do not expect more from a bigger number. Amdahl caps the whole ingest near 1.7x while
    #: redaction is 42% of it, and 16 workers measured 1.59x against 8 workers' 1.55x.
    #:
    #: Defaults to serial. Processes are not free (Windows spawns rather than forks, so each
    #: one re-imports the package), a small file finishes before a pool has started, and a
    #: default that silently occupies every core is a poor neighbour on a laptop. Raise it for
    #: the gigabyte-scale runs it exists for. `redaction.vault` forces serial regardless.
    workers: int = Field(default=1, ge=0)

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

    #: Whether the source line is kept verbatim beside the parsed message.
    #:
    #: On by default, because `raw` is the audit trail: it is what a reader greps to check a
    #: claim against the file the claim came from. Turning it off is a deliberate trade of that
    #: for disk, and at volume it is the largest single saving available -- measured on 588,046
    #: JSON Lines events, `raw` is 217 of 545 bytes per event, 39.7% of the scratchpad, and it
    #: holds the same content as `message`, `fields_json`, `ts`, `source` and `severity`
    #: together (156 bytes) in a different shape.
    #:
    #: What is lost is exactness, not evidence. With this off, readers get the parsed message
    #: where they would have got the original line -- the same text for an unstructured log,
    #: and the message without its JSON envelope for a structured one. What no longer exists is
    #: the ability to show the byte-exact line as the file wrote it.
    store_raw: bool = True


class LLMConfig(_Strict):
    """Which model runs what, and through which provider.

    The loop and the adversarial pass must not share a model: correlated blind spots between
    the reasoner and its checker are the core risk of the adversarial design, and a shared
    model is the most direct way to produce them. Different
    *providers* satisfy that more strongly than two models from one family, which is why the
    provider is configurable per role rather than once for the whole run.
    """

    #: Provider for the investigation loop. `scripted` replays fixed turns and is what the
    #: tests use -- it needs no credential, so the whole loop is exercised without a bill.
    provider: Literal["gemini", "scripted"] = "gemini"
    #: Cheapest tier that still calls tools reliably -- verified against the live API.
    model: str = "gemini-3.5-flash-lite"

    #: Provider and model for the adversarial pass. Defaulting to the same provider but a
    #: different model is the weaker form of independence; pointing this at another provider
    #: entirely is the stronger one.
    adversarial_provider: Literal["gemini", "scripted"] | None = None
    #: Must differ from whichever model writes the conclusion -- the loop's, or the synthesis
    #: model when one is set. The critique has to be independent of the reasoning it checks,
    #: and the critique is one call against the loop's fifteen, so it is a cheap place to spend.
    #: 3.5-flash rather than 3.6: the same as config.yaml, where 3.6 timed out repeatedly on
    #: the critique prompt, and because 3.6 is now the synthesis model, which this must differ
    #: from. A built-in default that config.yaml always overrode was a default nobody ran.
    adversarial_model: str = "gemini-3.5-flash"

    #: Writes the final conclusion from the scratchpad, once, after the loop has finished
    #: searching. Search is mechanical and cheap; concluding is one call where being slightly
    #: better is worth paying for. Set to None to let the loop's own last note stand.
    synthesis_provider: Literal["gemini", "scripted"] | None = None
    #: None leaves the loop's own last note as the conclusion. The default moved off None on
    #: 2026-09-17, on a real customer log: the loop's own conclusion was a budget-cap dump
    #: restating its notes, and this model wrote the answer in a paragraph that told
    #: observation from inference, for 2.5k tokens against the loop's 1.2M. It is exactly as
    #: right as the notes - see config.yaml - so it improves the writing, not the search.
    synthesis_model: str | None = "gemini-3.6-flash"

    bootstrap_model: str = "gemini-3.5-flash-lite"
    judge_model: str = "gemini-3.5-flash"

    #: Ceiling per model response. Not the investigation budget -- see `pipeline` for that.
    max_tokens: int = Field(default=8192, ge=256)

    #: Token ceiling the model paces itself against, where the provider supports one. No
    #: shipped provider does -- Gemini has no equivalent -- so today every run falls back to
    #: `pipeline.max_agent_tool_calls`. Kept because the loop's branch on
    #: `supports_task_budget` is live and this is what it would pass.
    task_budget_tokens: int | None = Field(default=64000, ge=20000)

    #: Ceiling on a single model request. A request with no ceiling does not fail, it hangs:
    #: one run sat in a single call for over thirty minutes with its search already finished.
    #: Generous rather than tight, because a long investigation prompt is genuinely slow.
    request_timeout_seconds: float = Field(default=120.0, gt=0)

    #: Enforced spacing between model calls, for providers with per-minute quotas. Zero
    #: leaves pacing to retry-with-backoff, which is faster when the limit is generous.
    min_interval_seconds: float = Field(default=0.0, ge=0.0)

    @model_validator(mode="after")
    def _adversarial_differs(self) -> LLMConfig:
        """The critique must differ from whatever wrote the thing it is checking.

        That used to mean "differ from the loop", because the loop wrote the conclusion. With a
        synthesis model the conclusion has a different author, and the rule follows the author:
        a critique sharing a model with the synthesis is marking its own homework, which is the
        exact failure the separate model exists to prevent and the one hardest to see in a
        finished report.
        """
        critic = (self.adversarial_provider or self.provider, self.adversarial_model)
        for role, author in self.conclusion_authors():
            if critic == author:
                raise ValueError(
                    f"the adversarial pass must not use the same provider and model as the "
                    f"{role} (a shared model gives the reasoner and its "
                    f"checker one blind spot). Change llm.adversarial_model, or the "
                    f"{role}'s model."
                )
        return self

    def conclusion_authors(self) -> list[tuple[str, tuple[str, str]]]:
        """Every (role, provider, model) that contributes to the conclusion under check.

        The loop is always one of them: it writes the notes the conclusion rests on, so a
        critique sharing its model inherits its blind spots even when a different model did
        the final writing.
        """
        # Annotated rather than inferred: the literal provider type makes the list invariant
        # against the wider tuple the signature promises.
        authors: list[tuple[str, tuple[str, str]]] = [("loop", (self.provider, self.model))]
        if self.synthesis_model is not None:
            authors.append(
                ("synthesis", (self.synthesis_provider or self.provider, self.synthesis_model))
            )
        return authors

    def synthesis_provider_name(self) -> str:
        """Provider for the synthesis, defaulting to the loop's when unset."""
        return self.synthesis_provider or self.provider

    def adversarial_provider_name(self) -> str:
        """Provider for the critique, defaulting to the loop's when unset."""
        return self.adversarial_provider or self.provider


class ReportConfig(_Strict):
    format: Literal["markdown", "html", "pdf"] = "markdown"
    output_dir: str = "./reports"


class HealthConfig(_Strict):
    """Thresholds for the pre-flight log health check (`mistify.health`).

    Every default was measured on 2026-09-24 against the pipeline's own ingest of 14 Loghub-2k
    systems (with grouping accuracy scored against Loghub's annotations), all 20 cached LogDx-CI
    logs, a 97,431-event production Java log, the sample incident, and the mixed-timezone
    fixture. The numbers are in the comment beside each field. `warn` thresholds sit in the gap
    between the logs that templated badly and the ones that did not; a check whose measurement
    never separated the two was given no `fail` threshold at all.
    """

    #: Share of events carrying a timestamp read from the line rather than inherited or
    #: invented. Bimodal on real data: 0.0 on Proxifier, HealthApp, Spark and one LogDx log (a
    #: shape nothing recognises, so every row is a line ordinal), and >= 0.9928 on the other 11
    #: Loghub systems, the other 19 LogDx logs and the sample incident. The production Java log,
    #: whose stack-frame lines inherit the timestamp above them, measured 0.9802.
    timestamp_coverage_warn_below: float = Field(default=0.95, ge=0.0, le=1.0)
    #: No refusal by default: a file with no readable time is still searchable, and the
    #: raw-line reader exists precisely so that such a file is investigated with less rather
    #: than not at all. Set above 0 to refuse spend on one.
    timestamp_coverage_fail_below: float = Field(default=0.0, ge=0.0, le=1.0)

    #: Lines that failed to parse, over lines read. Warns on any, as the report always has;
    #: 0 on all 35 real logs measured, so it has never fired on a healthy file.
    parse_error_rate_warn_above: float = Field(default=0.0, ge=0.0, le=1.0)
    #: None: no real log measured had a parse error at all, so there is no measurement to put
    #: a refusal threshold on.
    parse_error_rate_fail_above: float | None = Field(default=None, ge=0.0, le=1.0)

    #: One template's share of all events. The report's long-standing cutoff, kept; measured
    #: above it only on four CI logs -- gradle 0.801, jest 0.743, biome 0.736, prettier 0.647 --
    #: whose `> Task <*> <*>`-style templates each hide a failing line among passing ones.
    #: Every Loghub system is at or below 0.455, the sample incident 0.505.
    dominant_share_warn_above: float = Field(default=0.6, gt=0.0, le=1.0)

    #: Events per template below which templating did not compress. The report's cutoff, kept;
    #: below it only on one LogDx log (pnpm-audit, 1.7 over 158 events). The lowest Loghub
    #: value was HealthApp's 3.05.
    min_reduction_factor: float = Field(default=2.0, ge=0.0)

    #: Share of events in templates that end in the same four tokens as another template: one
    #: message split into several by something in its header. The measurement that separates
    #: the systems templating fails on: Apache 1.000 (pipeline grouping accuracy 0.000, against
    #: 1.000 when its message column is clustered alone -- the weekday in the header does it),
    #: OpenStack 0.530 (0.121), Proxifier 0.462 (0.002). Everything else is at most 0.262
    #: (OpenSSH, 0.453) and at most 0.063 on the LogDx logs; 0.0 on the sample incident.
    split_share_warn_above: float = Field(default=0.35, ge=0.0, le=1.0)

    #: Share of events in templates whose pattern still contains an identifier -- a UUID, a
    #: 16+ character hex string, or a 7+ digit number -- that Drain3 left as a literal.
    #: Above it: dependabot 0.631 (commit hashes), OpenStack 0.403, HealthApp 0.304, Hadoop
    #: 0.184, lint-react 0.148. The highest of the other 30 real logs was 0.039.
    unmasked_id_share_warn_above: float = Field(default=0.10, ge=0.0, le=1.0)

    #: Of the lines carrying a failure word, the share sitting in a template whose pattern does
    #: not carry it and whose other members do not either: success and failure folded into one
    #: template, so the ranking cannot see them. OpenSSH 0.334 (`<*> password for` holds 383
    #: `Failed` and 1 `Accepted`), jest 0.908, biome 0.658, hibernate 0.467, docs 0.455. Not a
    #: clean gap on CI logs, which run on down through cargo 0.218 and go-redis 0.200: this is
    #: a judgement that a quarter hidden is worth saying. Every other Loghub system is at most
    #: 0.136 (Thunderbird); the sample incident 0.0.
    hidden_failure_share_warn_above: float = Field(default=0.25, ge=0.0, le=1.0)
    #: Below this many hidden lines the share is noise: gradle hid 2 of 7 (0.286), gh-cli 1 of 3.
    hidden_failure_min_lines: int = Field(default=5, ge=1)

    #: Share of events that are stack-frame or traceback continuation lines -- one frame per
    #: event, cut off from the exception that owns it. Above it: prettier 0.041, docs 0.030,
    #: tsc 0.022, and the production Java log 0.0195 (its 1,900 frame lines, matching a grep
    #: for them). Below: jest 0.0076 and three more CI logs under 0.004; 0 on every Loghub
    #: system (the corpus strips traces) and the sample incident.
    continuation_share_warn_above: float = Field(default=0.01, ge=0.0, le=1.0)

    #: Clock skew between sources: the whole-quarter-hour shift that best lines one source's
    #: active minutes up with the busiest source's. Timezones are whole quarter hours, which
    #: is what makes a skew of exactly 5h30m evidence rather than coincidence.
    skew_step_minutes: int = Field(default=15, ge=1)
    skew_max_hours: int = Field(default=14, ge=1)
    #: A shift smaller than this is not reported, however well it aligns.
    skew_min_minutes: int = Field(default=30, ge=1)
    #: How much better the shift must align than no shift at all, as a share of the smaller
    #: source's active slots. The skewed fixture gains 1.00 at -5h30m; every pair of sources on
    #: one clock -- the sample incident's four, and OpenStack's nova-api and nova-compute split
    #: into two files -- gains nothing at any shift (best non-zero -0.25). Two real multi-source
    #: logs is thin, so the cut is the midpoint and a lone alignment only ever warns.
    skew_min_gain: float = Field(default=0.5, gt=0.0, le=1.0)
    #: Sources with fewer events than this are not compared; a handful of lines aligns with
    #: anything.
    skew_min_source_events: int = Field(default=20, ge=1)
    #: Refuse spend when a skewed source is also the one writing timestamps with no offset --
    #: the two independent signals agreeing. Either one alone warns.
    fail_on_corroborated_skew: bool = True

    #: Events read by the two text scans (hidden failures, continuation lines). Above this the
    #: scan takes every k-th event, so its cost stops growing with the file: measured at 1.41 s
    #: for 97,431 events, so about 3 s at the cap, against 14.9 s to ingest those 97,431.
    scan_max_events: int = Field(default=200_000, ge=1000)

    @model_validator(mode="after")
    def _fail_is_worse_than_warn(self) -> HealthConfig:
        """A refusal threshold milder than its warning would refuse a log it did not warn on."""
        if self.timestamp_coverage_fail_below > self.timestamp_coverage_warn_below:
            raise ValueError(
                "health.timestamp_coverage_fail_below must not exceed "
                "health.timestamp_coverage_warn_below"
            )
        fail = self.parse_error_rate_fail_above
        if fail is not None and fail < self.parse_error_rate_warn_above:
            raise ValueError(
                "health.parse_error_rate_fail_above must not be below "
                "health.parse_error_rate_warn_above"
            )
        return self


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
    health: HealthConfig = Field(default_factory=HealthConfig)

    def scratchpad_path(self, incident_id: str) -> Path:
        return Path(self.scratchpad.path.format(incident_id=incident_id))

    def vault_path(self, incident_id: str) -> Path | None:
        """Where a vault would be written for this incident, or None when none is kept."""
        if not self.redaction.vault:
            return None
        return self.vault_file(incident_id)

    def vault_file(self, incident_id: str) -> Path:
        """Where a vault for this incident lives if one exists, whatever the switch says.

        `reveal` looks here rather than at `vault_path`: an incident ingested with `--vault`
        has a vault whether or not the config file the operator passes today agrees, and
        refusing to read one that is sitting on disk would be a rule with no beneficiary.
        """
        return Path(self.redaction.vault_path.format(incident_id=incident_id))

    def snapshot_path(self, incident_id: str) -> Path | None:
        if self.drain3.persistence == "none":
            return None
        return Path(self.drain3.snapshot_path.format(incident_id=incident_id))

    def schema_dir(self) -> Path:
        """Where inferred schemas are cached.

        Not templated on `incident_id`, unlike the scratchpad and the Drain3 snapshot: a schema
        describes a *format*, and the whole value of persisting one is that the next incident
        from the same source reuses it. Per-incident would be a cache that never hits.
        """
        return Path(self.bootstrap.schema_dir)


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

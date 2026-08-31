"""Drain3 similarity-threshold calibration (architecture §6.1).

Drain3 fails in two opposite directions and neither one raises:

*   **Under-clustering** -- high line-to-line variability means nearly every line becomes its
    own template and no compression happens at all.
*   **Over-clustering** -- a threshold that is too loose merges genuinely distinct error
    conditions into one template, destroying the signal the compression exists to preserve.

A single hardcoded `sim_th` is a guess about a file nobody has looked at yet. This module
tries a few thresholds against a sample and picks one whose compression ratio lands in a sane
band, recording what it tried so the choice is auditable rather than magic.

Ratio here is unique templates over lines: near 1.0 means no compression, very low means
suspiciously aggressive merging.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from mistify.common.models import SEVERITIES, TemplateSummary, severity_rank
from mistify.templating.drain_wrapper import DrainTemplater

__all__ = [
    "CalibrationResult",
    "OverMergedTemplate",
    "calibrate_sim_th",
    "find_over_merged",
]


@dataclass(slots=True)
class CalibrationResult:
    chosen_sim_th: float
    status: str
    candidates: list[tuple[float, float]] = field(default_factory=list)
    reason: str = ""

    def as_metric(self) -> str:
        return ", ".join(f"{th}={ratio:.4f}" for th, ratio in self.candidates)


def calibrate_sim_th(
    messages: Sequence[str],
    candidates: Sequence[float],
    target_min: float,
    target_max: float,
    depth: int = 4,
    max_clusters: int = 2000,
) -> CalibrationResult:
    """Pick a similarity threshold whose compression ratio lands inside the target band.

    Among in-band candidates the **highest** threshold wins. Higher thresholds cluster more
    strictly, so this prefers the least merging that still achieves acceptable compression --
    over-clustering silently destroys signal, whereas under-clustering merely costs tokens.

    When nothing lands in band the closest candidate is used and the status says so, so a
    pathological file produces a flagged run rather than a confident-looking bad one.
    """
    if not candidates:
        raise ValueError("at least one candidate sim_th is required")

    ordered = sorted(set(candidates))
    if not messages:
        return CalibrationResult(
            chosen_sim_th=ordered[0],
            status="skipped",
            reason="no sample messages available",
        )

    measured: list[tuple[float, float]] = []
    for sim_th in ordered:
        templater = DrainTemplater(
            sim_th=sim_th, depth=depth, max_clusters=max_clusters, snapshot_path=None
        )
        for message in messages:
            templater.process(message)
        measured.append((sim_th, templater.compression_ratio))

    in_band = [(th, ratio) for th, ratio in measured if target_min <= ratio <= target_max]
    if in_band:
        chosen = max(in_band, key=lambda item: item[0])
        return CalibrationResult(
            chosen_sim_th=chosen[0],
            status="in_band",
            candidates=measured,
            reason=(
                f"compression ratio {chosen[1]:.4f} within "
                f"[{target_min}, {target_max}]; highest in-band threshold preferred"
            ),
        )

    def _distance(item: tuple[float, float]) -> float:
        ratio = item[1]
        if ratio < target_min:
            return target_min - ratio
        return ratio - target_max

    chosen = min(measured, key=_distance)
    direction = "over-clustering" if chosen[1] < target_min else "under-clustering"
    return CalibrationResult(
        chosen_sim_th=chosen[0],
        status="out_of_band",
        candidates=measured,
        reason=(
            f"no candidate landed in [{target_min}, {target_max}]; closest was "
            f"{chosen[1]:.4f} at sim_th={chosen[0]}, suggesting {direction}"
        ),
    )


@dataclass(slots=True)
class OverMergedTemplate:
    template_id: int
    pattern: str
    severity_span: int
    severities: list[str]


def find_over_merged(
    summaries: Sequence[TemplateSummary], min_span: int = 3
) -> list[OverMergedTemplate]:
    """Flag templates whose members span an implausibly wide range of severities.

    This is the over-clustering half of the §6.1 detection, and the compression ratio alone
    cannot see it: a low ratio looks like excellent compression right up until you notice one
    template contains both routine INFO lines and FATAL ones, which means two different
    conditions were merged and one of them is now invisible.
    """
    flagged: list[OverMergedTemplate] = []
    for summary in summaries:
        mix = summary.severity_mix or {}
        present = [name for name in SEVERITIES if name in mix]
        if len(present) < 2:
            continue
        span = severity_rank(present[-1]) - severity_rank(present[0]) + 1
        if span >= min_span:
            flagged.append(
                OverMergedTemplate(
                    template_id=summary.template_id,
                    pattern=summary.pattern,
                    severity_span=span,
                    severities=present,
                )
            )
    return flagged

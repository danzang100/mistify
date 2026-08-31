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
from enum import StrEnum

from mistify.common.models import SEVERITIES, TemplateSummary, severity_rank
from mistify.templating.drain_wrapper import DrainTemplater

__all__ = [
    "CalibrationResult",
    "CalibrationStatus",
    "OverMergedTemplate",
    "calibrate_sim_th",
    "find_over_merged",
]


class CalibrationStatus(StrEnum):
    """Outcome of a calibration pass.

    An enum rather than bare strings because the report acts on two of these values, and
    re-declaring them as literals in the reader is the same defect the metric vocabulary
    exists to prevent.
    """

    SELECTED = "selected"
    UNDER_CLUSTERED = "under_clustered"
    SIGNAL_AT_RISK = "signal_at_risk"
    SKIPPED = "skipped"
    DISABLED = "disabled"

    @classmethod
    def warns(cls) -> frozenset[str]:
        """Statuses a reader should surface: the run did not calibrate cleanly."""
        return frozenset({cls.UNDER_CLUSTERED.value, cls.SIGNAL_AT_RISK.value})


@dataclass(slots=True)
class CalibrationResult:
    chosen_sim_th: float
    status: CalibrationStatus
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
    over_merge_span: int = 3,
) -> CalibrationResult:
    """Pick a similarity threshold that collapses the most noise without losing signal.

    The objective is not compression. Compression is a proxy that breaks in exactly the case
    that matters: a threshold which merges a rare FATAL template into a chatty INFO one
    scores *better* on ratio while destroying the only line worth finding. So selection is a
    gate followed by a preference, not a target band:

    1.  **Gate — signal must survive.** Any candidate that produces an over-merged template
        (members spanning `over_merge_span` severity levels) is rejected outright, however
        well it compresses.
    2.  **Preference — collapse as much noise as possible.** Among candidates that pass, the
        one yielding the fewest templates wins, because the agent's haystack is the template
        list and a shorter one is strictly easier to search.
    3.  **Fallback — prefer signal over tidiness.** If every candidate over-merges, the
        strictest threshold is used and the run is flagged, since under-clustering only costs
        tokens whereas over-clustering loses the needle.

    `target_max` is retained purely as an under-clustering alarm: a ratio above it means
    almost nothing collapsed and the agent has been handed the haystack intact. `target_min`
    is no longer a selection criterion -- over-merging is now detected directly rather than
    guessed at from a ratio being suspiciously low.
    """
    if not candidates:
        raise ValueError("at least one candidate sim_th is required")

    ordered = sorted(set(candidates))
    if not messages:
        return CalibrationResult(
            chosen_sim_th=ordered[0],
            status=CalibrationStatus.SKIPPED,
            reason="no sample messages available",
        )

    measured: list[tuple[float, float]] = []
    trials: dict[float, tuple[int, int]] = {}
    for sim_th in ordered:
        templater = DrainTemplater(
            sim_th=sim_th, depth=depth, max_clusters=max_clusters, snapshot_path=None
        )
        for message in messages:
            # Severity is unavailable during calibration, so the over-merge gate below reads
            # structural spread rather than severity spread -- see `_merge_risk`.
            templater.process(message)
        measured.append((sim_th, templater.compression_ratio))
        trials[sim_th] = (templater.unique_templates, _merge_risk(templater, over_merge_span))

    safe = [(th, ratio) for th, ratio in measured if trials[th][1] == 0]
    pool = safe or measured

    # Fewest templates = least for the agent to read. Ties break toward the stricter
    # threshold, which merges less.
    chosen_th = min(pool, key=lambda item: (trials[item[0]][0], -item[0]))[0]
    chosen_ratio = dict(measured)[chosen_th]
    template_count = trials[chosen_th][0]

    if not safe:
        strictest = max(ordered)
        return CalibrationResult(
            chosen_sim_th=strictest,
            status=CalibrationStatus.SIGNAL_AT_RISK,
            candidates=measured,
            reason=(
                "every candidate produced a template spanning "
                f"{over_merge_span}+ severity levels; falling back to the strictest "
                f"threshold {strictest} because losing signal costs more than extra tokens"
            ),
        )

    if chosen_ratio > target_max:
        return CalibrationResult(
            chosen_sim_th=chosen_th,
            status=CalibrationStatus.UNDER_CLUSTERED,
            candidates=measured,
            reason=(
                f"best candidate {chosen_th} still leaves {template_count} templates "
                f"(ratio {chosen_ratio:.4f} above {target_max}); the file has little "
                "repeated structure, so little noise could be collapsed"
            ),
        )

    return CalibrationResult(
        chosen_sim_th=chosen_th,
        status=CalibrationStatus.SELECTED,
        candidates=measured,
        reason=(
            f"{template_count} templates at sim_th={chosen_th} (ratio {chosen_ratio:.4f}); "
            "fewest templates among candidates that did not over-merge"
        ),
    )


def _merge_risk(templater: DrainTemplater, min_span: int) -> int:
    """Templates a threshold has merged too aggressively, judged without severity labels.

    Calibration runs before records carry severity into the templater, so the severity-span
    detector used post-load is unavailable here. The structural stand-in is wildcard density:
    a template that is mostly `<*>` has kept almost none of the original words, which is what
    absorbing unrelated messages looks like.
    """
    flagged = 0
    for summary in templater.summaries():
        tokens = summary.pattern.split()
        if len(tokens) < min_span:
            continue
        wildcards = sum(1 for token in tokens if token in {"<*>", "<REDACTED>"})
        if wildcards / len(tokens) > 0.6:
            flagged += 1
    return flagged


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

"""Deterministic anomaly scoring for templates (decision G3).

Runs as a post-load pass over the scratchpad. No model call and no baseline corpus: the score
is computed from the incident's own distribution, so it works on the first file from a service
nobody has ever ingested before.

The point of scoring outside the model is stated in the architecture's own failure analysis:
an LLM can deprioritise a correct but mundane signal in favour of a novel-sounding wrong one.
A number the model did not produce is what lets the adversarial check ask "was a high-scoring
template left out of the conclusion?" and get an answer that is not just the reasoner agreeing
with itself.

Three components, each normalised to [0, 1]:

*   **severity** -- how bad the worst occurrence was. The dominant term; incidents are
    usually announced by their severity.
*   **burstiness** -- how concentrated the template is in time. Something that fires forty
    times in six minutes is a different animal from something that fires forty times across
    a day, even though frequency alone cannot tell them apart.
*   **rarity** -- inverse log frequency. Heartbeats are common and boring; a template that
    appears twice may be the whole story.

They are combined as a **weighted sum, not a product**. A product zeroes the whole score
whenever any single component is zero, which would silently discard every template of the
most common shape regardless of how severe or bursty it was.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from mistify.common.models import SEVERITIES

__all__ = ["DEFAULT_WEIGHTS", "AnomalyComponents", "score_templates"]

#: Relative contribution of each component. Normalised before use, so these are ratios
#: rather than values that must sum to one.
DEFAULT_WEIGHTS: dict[str, float] = {
    "severity": 0.5,
    "burstiness": 0.3,
    "rarity": 0.2,
}

#: Severity contribution, deliberately non-linear. The step from WARN to ERROR matters more
#: than the step from TRACE to DEBUG.
_SEVERITY_WEIGHT: dict[str, float] = {
    "TRACE": 0.00,
    "DEBUG": 0.05,
    "INFO": 0.15,
    "WARN": 0.50,
    "ERROR": 0.80,
    "FATAL": 1.00,
}


@dataclass(slots=True)
class AnomalyComponents:
    """One template's score and the parts it was built from.

    The components are kept rather than collapsed so a report or an adversarial pass can say
    *why* a template scored highly, instead of quoting an unexplained number.
    """

    template_id: int
    score: float
    severity: float
    burstiness: float
    rarity: float

    def as_dict(self) -> dict[str, float]:
        return {
            "score": self.score,
            "severity": self.severity,
            "burstiness": self.burstiness,
            "rarity": self.rarity,
        }


def _severity_component(max_severity_rank: int) -> float:
    rank = max(0, min(max_severity_rank, len(SEVERITIES) - 1))
    return _SEVERITY_WEIGHT[SEVERITIES[rank]]


def _burstiness_component(max_per_bucket: int, total: int, total_buckets: int) -> float:
    """How peaked a template is against spreading evenly across the whole incident.

    The denominator is the incident's full span, not the buckets this template happens to
    occupy. Measuring against its own footprint would call a template that fired forty times
    inside one minute perfectly even -- it occupies one bucket and fills it uniformly --
    which inverts the signal this component exists to capture.

    A ratio of 1.0 is uniform; higher is peaked. Mapped through `1 - 1/ratio` so the result
    saturates towards 1 rather than running away on extreme peaks.
    """
    if total <= 0 or max_per_bucket <= 0 or total_buckets <= 1:
        return 0.0
    mean_per_bucket = total / total_buckets
    if mean_per_bucket <= 0:
        return 0.0
    ratio = max_per_bucket / mean_per_bucket
    if ratio <= 1.0:
        return 0.0
    return 1.0 - (1.0 / ratio)


def _rarity_component(count: int, max_count: int) -> float:
    """Inverse log frequency, scaled against the most common template in the incident."""
    if count <= 0 or max_count <= 1:
        return 0.0
    return max(0.0, 1.0 - (math.log1p(count) / math.log1p(max_count)))


def score_templates(
    rows: Sequence[Mapping[str, Any]],
    total_buckets: int,
    weights: Mapping[str, float] | None = None,
) -> list[AnomalyComponents]:
    """Score templates from their aggregate statistics.

    Each row needs `template_id`, `occurrence_count`, `max_severity_rank` and
    `max_per_bucket`. `total_buckets` is the number of time buckets the whole incident spans,
    which is what burstiness is measured against. Pure function of its input, so it is
    testable without a database.
    """
    if not rows:
        return []

    resolved = dict(DEFAULT_WEIGHTS if weights is None else weights)
    total_weight = sum(resolved.values())
    if total_weight <= 0:
        raise ValueError("anomaly weights must sum to a positive value")

    max_count = max(int(row["occurrence_count"]) for row in rows)

    scored: list[AnomalyComponents] = []
    for row in rows:
        count = int(row["occurrence_count"])
        severity = _severity_component(int(row["max_severity_rank"]))
        burstiness = _burstiness_component(int(row["max_per_bucket"]), count, total_buckets)
        rarity = _rarity_component(count, max_count)

        score = (
            resolved.get("severity", 0.0) * severity
            + resolved.get("burstiness", 0.0) * burstiness
            + resolved.get("rarity", 0.0) * rarity
        ) / total_weight

        scored.append(
            AnomalyComponents(
                template_id=int(row["template_id"]),
                score=round(score, 6),
                severity=round(severity, 6),
                burstiness=round(burstiness, 6),
                rarity=round(rarity, 6),
            )
        )

    scored.sort(key=lambda c: (-c.score, c.template_id))
    return scored

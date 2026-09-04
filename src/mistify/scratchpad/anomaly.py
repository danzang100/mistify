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

**When the source carries no severity field, severity is read out of the template text
instead of being discarded.** Dropping it was measured and it is the worse of the two: across
all five LogDx-CI dev cases, *zero* ground-truth evidence markers reached the top-40 digest
the investigation starts from -- including a 170-template case where the top 40 is a quarter
of the file. With severity gone and almost every line unique, rarity and burstiness both
saturate, thousands of templates tie on score, and the tie is broken by template id, which is
the order the lines first appeared. So the ranking that decides what the model reads first was
"whatever the build printed earliest", which on a CI log is the setup section. Recovering
severity from the text puts 14 of those 18 markers inside the top 40, and 39 of 65 across
twenty cases -- 25 of 47 on the fifteen it was not designed on. See `docs/digest-rerank.md`.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from mistify.common.models import SEVERITIES

__all__ = [
    "DEFAULT_WEIGHTS",
    "AnomalyComponents",
    "lexical_severity",
    "score_templates",
    "select_signal_templates",
    "severity_source",
]

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


#: Words that put a template at ERROR, and words that put it at WARN, when the file carried no
#: severity field of its own. Two tiers rather than a graded count: counting how many failure
#: words a pattern contains ranks a stack frame above the exception that produced it, and on
#: the dev cases the two put the same number of markers in the digest, so the simpler rule
#: wins.
#:
#: Case-insensitive, which is the whole point. The line-level guess in `RawLinesAdapter` reads
#: only upper-case log levels, so `error[E0308]: mismatched types` and `error: Module has no
#: attribute` -- the exact lines the ground truth calls critical -- map to nothing. The
#: vocabulary is what CI logs and application logs actually say when they fail, not what a
#: level field would have said.
_LEXICAL_ERROR = re.compile(
    r"(?i)\b(?:error|errors|failed|failure|failures|fail|fails|failing|fatal|panic|panicked"
    r"|exception|traceback|assert|asserted|assertion|segfault|core dumped|aborted)\b"
)
_LEXICAL_WARN = re.compile(
    r"(?i)\b(?:warn|warning|warnings|timeout|timed out|refused|denied|unable|cannot|could not"
    r"|no such|not found|missing|invalid|undefined|unexpected|killed|non-zero|deprecated)\b"
)

#: Escape sequences a template pattern can still carry. 71.9% of the lines in one real GitHub
#: Actions log are wrapped in them, and `\x1b[31;1merror\x1b[0m` has no word boundary before
#: `error` -- so the vocabulary would miss precisely the lines a terminal painted red.
_ANSI = re.compile("\x1b\\[[0-9;]*[A-Za-z]")


def lexical_severity(pattern: str) -> float:
    """Severity read out of a template's own text, on the same scale as the severity field.

    Returns exactly the `_SEVERITY_WEIGHT` value for ERROR, WARN or INFO, so this drops into
    the severity term without retuning any weight: it is the same question answered from a
    worse source, not a fourth component competing for a share of the score.

    INFO rather than zero for a template that says nothing alarming, because that is what an
    unlabelled line *is* -- an absence of evidence, and the same value every line would have
    got from `normalize_severity` had the term been kept at all.
    """
    text = _ANSI.sub("", pattern)
    if _LEXICAL_ERROR.search(text):
        return _SEVERITY_WEIGHT["ERROR"]
    if _LEXICAL_WARN.search(text):
        return _SEVERITY_WEIGHT["WARN"]
    return _SEVERITY_WEIGHT["INFO"]


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

    **One occurrence has no distribution to be concentrated, and scores zero rather than one.**
    The formula divides by a mean of `1/total_buckets`, so a template that fired once came out
    at `1 - 1/total_buckets` -- indistinguishable from a genuine burst, for every singleton in
    the file. That is what made the top of the ranking a single flat tie: 507 of one case's
    9,307 templates shared the top score, and its whole 40-template digest came from inside that
    block, ordered by template id, which is the order the lines first appeared. Measured across
    twenty LogDx-CI cases, dropping the artefact moves ground-truth markers into the top five
    from 16 of 65 to 21, and into the top ten from 24 to 27.

    It also removes the section banners that crowded the set the coverage nudge enforces:
    `==== ERRORS ====` fires once, is unique, and says ERROR, so it took the maximum of all
    three terms. With this it takes two of them, and `pytest-pandas`'s top five becomes five
    lines that name a failing test.
    """
    if total <= 1 or max_per_bucket <= 0 or total_buckets <= 1:
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


def severity_source(rows: Sequence[Mapping[str, Any]], severity_informative: bool) -> str:
    """Where the severity term's values come from for this file: a field, the text, or nowhere.

    A separate public function, and the one `score_templates` itself consults, so the metric
    the run records cannot drift from the ranking the run produced. The alternative -- the
    pipeline deciding and the scorer deciding again -- is two answers to one question with
    nothing keeping them equal.

    `"lexical"` requires the recovered values to actually differ between templates. A file
    where every template says "error" is the incident Issue 3 describes, a log entirely on
    fire, and a term with one value on every row ranks nothing above anything else: it is the
    same silent no-op as the unmapped severity field this exists to replace, so it is dropped
    the same way and the weight is redistributed.
    """
    if severity_informative:
        return "field"
    recovered = {lexical_severity(str(row.get("pattern", ""))) for row in rows}
    return "lexical" if len(recovered) > 1 else "none"


def score_templates(
    rows: Sequence[Mapping[str, Any]],
    total_buckets: int,
    weights: Mapping[str, float] | None = None,
    severity_informative: bool = True,
) -> list[AnomalyComponents]:
    """Score templates from their aggregate statistics.

    Each row needs `template_id`, `occurrence_count`, `max_severity_rank` and
    `max_per_bucket`. `total_buckets` is the number of time buckets the whole incident spans,
    which is what burstiness is measured against. Pure function of its input, so it is
    testable without a database.

    `severity_informative` is False when the source carried no usable severity field. Every
    line then normalises to the same default, so the severity term adds an identical constant
    to every template -- the heaviest weight in the formula doing nothing at all, and doing it
    silently. Dropping it redistributes that weight across the two components that still
    discriminate rather than diluting them. This is the common case on unlabelled corpora,
    which is most of Loghub.
    """
    if not rows:
        return []

    resolved = dict(DEFAULT_WEIGHTS if weights is None else weights)
    source = severity_source(rows, severity_informative)
    if source == "none":
        resolved["severity"] = 0.0
    total_weight = sum(resolved.values())
    if total_weight <= 0:
        raise ValueError("anomaly weights must sum to a positive value")

    max_count = max(int(row["occurrence_count"]) for row in rows)

    scored: list[AnomalyComponents] = []
    for row in rows:
        count = int(row["occurrence_count"])
        severity = (
            lexical_severity(str(row.get("pattern", "")))
            if source == "lexical"
            else _severity_component(int(row["max_severity_rank"]))
        )
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


def select_signal_templates(
    scored: Sequence[AnomalyComponents],
    min_templates: int = 3,
    max_templates: int = 15,
) -> list[AnomalyComponents]:
    """The templates an investigation is expected to account for.

    The adversarial check's one mechanical test is "was a high-scoring template left out of
    the conclusion?", which needs a definition of high. A fixed threshold is the wrong shape
    for it: scores are relative to the incident's own distribution, so any constant is tuned
    to whichever fixture was on hand when it was picked, and a quiet incident where nothing
    clears the bar would produce an empty set rather than its own top candidates.

    Instead the cut is placed at the **largest gap** between consecutive scores in the ranked
    list -- the point where the distribution itself separates the unusual from the ordinary.
    A file whose templates all score alike has no large gap, and the bounds then decide: never
    fewer than `min_templates`, so there is always something to check against, and never more
    than `max_templates`, so the set stays small enough to reason about.
    """
    if not scored:
        return []

    ranked = sorted(scored, key=lambda c: (-c.score, c.template_id))
    lower = max(1, min(min_templates, len(ranked)))
    upper = max(lower, min(max_templates, len(ranked)))
    if lower == upper:
        return ranked[:upper]

    # Only gaps that would produce a cut inside [lower, upper] are candidates.
    best_cut = lower
    best_gap = -1.0
    for cut in range(lower, upper):
        gap = ranked[cut - 1].score - ranked[cut].score
        if gap > best_gap:
            best_gap = gap
            best_cut = cut
    return ranked[:best_cut]

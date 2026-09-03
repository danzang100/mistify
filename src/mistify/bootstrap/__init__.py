"""Unknown-format bootstrapper: work out how to read a file nothing recognises.

Architecture §2.2a, in order: reuse a schema already worked out for this shape; otherwise look
at the lines; otherwise ask a model; then *always* validate against lines the inference never
saw, and only persist what passes.

The validation gate is not a formality and is never skipped, however confident anything
upstream was. The architecture's risk table lists this stage's failure as **silent** -- a
confidently wrong schema yields templates that are garbage with no error thrown, and every
number after it describes a misreading rather than an incident. Inference proposes; the gate
decides. A run that fails the gate falls back to raw lines, which reads the file badly but
visibly, and that is the better failure.

What the gate cannot catch is a schema that parses cleanly and means the wrong thing -- a field
that is a timestamp shape but is not *the* timestamp, say. That is why the model is asked to
quote substrings rather than write a pattern, and why `origin` travels with a persisted schema:
a reader deciding whether to trust one is told how it was arrived at.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from mistify.bootstrap.adapter import InferredAdapter, load_schemas, save_schema
from mistify.bootstrap.inference import infer_with_model
from mistify.bootstrap.schema import TIMESTAMP_PATTERNS, FieldSchema, match_rate
from mistify.bootstrap.shapes import MAX_SUBSHAPES, cluster_shapes, infer_structurally

if TYPE_CHECKING:
    from mistify.llm.base import LLMProvider

__all__ = [
    "BootstrapResult",
    "FieldSchema",
    "InferredAdapter",
    "bootstrap_format",
    "load_schemas",
    "save_schema",
]


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    """What the bootstrapper concluded, and how it got there.

    Carries the failed outcomes too. "No schema reached the match rate" is a fact the report
    has to be able to state, and a bare `None` cannot say which of the three routes was tried.
    """

    schema: FieldSchema | None
    route: str
    match_rate: float
    reason: str

    @property
    def succeeded(self) -> bool:
        return self.schema is not None


def _validate(
    candidate: FieldSchema, holdout: list[str], floor: float, route: str
) -> BootstrapResult:
    rate = match_rate(candidate, holdout)
    if rate >= floor:
        return BootstrapResult(
            # `replace`, never a field-by-field rebuild. The rebuild dropped `source_first`,
            # so the schema that passed the gate was not the schema that came back -- it
            # validated at 100% and then parsed zero records, which is exactly the silent
            # failure the gate exists to prevent, produced by the gate itself.
            schema=replace(candidate, validated_rate=rate),
            route=route,
            match_rate=rate,
            reason=f"{route} inference matched {rate:.0%} of held-out lines",
        )
    return BootstrapResult(
        schema=None,
        route=route,
        match_rate=rate,
        reason=f"{route} inference matched only {rate:.0%} of held-out lines, below {floor:.0%}",
    )


def bootstrap_format(
    lines: list[str],
    *,
    known: dict[str, FieldSchema] | None = None,
    provider: LLMProvider | None = None,
    min_match_rate: float = 0.85,
    sample_size: int = 100,
) -> BootstrapResult:
    """Work out how to read `lines`, or say why it could not be done.

    `lines` is the head of the file. It is split: the first `sample_size` inform the inference,
    and everything after validates it. A schema scored on the lines it was derived from always
    fits them, so a gate measured there would pass anything.
    """
    usable = [line for line in lines if line.strip()]
    if not usable:
        return BootstrapResult(None, "none", 0.0, "the file has no non-blank lines")

    sample = usable[:sample_size]
    # Held out where there is enough file to hold any out. On a short file the sample is reused
    # and the result says so, because a rate measured on the sample is weaker evidence and a
    # reader should not have to infer that from the line count.
    holdout = usable[sample_size:] or sample
    reused = holdout is sample

    # 1. Schemas already worked out for this shape. Free -- no model call -- and the reason
    #    inference is affordable across files at all.
    known_result = _best_known(known or {}, holdout, min_match_rate)

    # 2. Structural inference. Also free, which is why it runs even when a cached schema
    #    already clears the gate. The cache exists to avoid the *model* call, not to avoid
    #    looking at the lines, and skipping this whenever anything fit was how an OpenSSH
    #    schema came to read an application log: it carries no severity, it matched every line
    #    at 100% because the word `ERROR` simply landed inside `message`, and it was reused in
    #    preference to inferring the schema that would have pulled the severity out.
    structural = infer_structurally(sample)
    if structural is not None:
        structural_result = _validate(structural, holdout, min_match_rate, "structural")
    else:
        structural_result = BootstrapResult(
            None, "structural", 0.0, "no timestamp shape found in the sample"
        )

    best = _better(known_result, structural_result)
    if best is not None:
        return best if not reused else _note_reuse(best)
    first_failure = structural_result

    # 3. The model, only now, and only if one was supplied.
    if provider is not None:
        inferred = infer_with_model(provider, sample)
        if inferred is not None:
            result = _validate(inferred, holdout, min_match_rate, "model")
            if result.succeeded:
                return result if not reused else _note_reuse(result)
            first_failure = result

    # 4. Sub-shapes. Failing the gate usually means the file holds two or three shapes rather
    #    than that inference was wrong -- stack traces mixed with key-value lines is the case
    #    §2.2a names. The best single schema over the commonest shape is still better than
    #    nothing, provided it clears the gate on that shape's own lines.
    clusters = cluster_shapes(sample)[:MAX_SUBSHAPES]
    if len(clusters) > 1:
        for shape, _count in clusters:
            if shape.timestamp is None:
                continue
            subset = [line for line in sample if _matches_shape(line, shape.timestamp)]
            candidate = infer_structurally(subset)
            if candidate is None:
                continue
            rate = match_rate(candidate, subset)
            if rate >= min_match_rate:
                return BootstrapResult(
                    schema=replace(
                        candidate,
                        validated_rate=rate,
                        notes=(
                            f"one of {len(clusters)} shapes in this file; "
                            f"covers {len(subset)} of {len(sample)} sampled lines",
                        ),
                    ),
                    route="sub-shape",
                    match_rate=rate,
                    reason=(
                        f"the file holds {len(clusters)} line shapes; the commonest parses at "
                        f"{rate:.0%}, and lines of other shapes will not be read"
                    ),
                )

    return first_failure


def _rank(result: BootstrapResult) -> tuple[int, float]:
    """How good a passing result is, most important term first.

    Both terms are read only from results that have *already cleared the gate*, so this is not
    deciding whether a file can be parsed -- it is deciding between schemas that can all parse
    it. Fields explained comes first and the rate second, because the rate cannot separate them:
    a schema that does not claim a severity still matches a line carrying `ERROR` at 100%, and
    the difference is that the word ends up in the message, where it silently becomes part of
    every template and the line's level falls back to the default.
    """
    assert result.schema is not None
    return (result.schema.extracted_fields, result.match_rate)


def _better(*results: BootstrapResult | None) -> BootstrapResult | None:
    """The best of some results, or None when none of them succeeded."""
    passing = [r for r in results if r is not None and r.succeeded]
    return max(passing, key=_rank) if passing else None


def _best_known(
    known: dict[str, FieldSchema], holdout: list[str], floor: float
) -> BootstrapResult | None:
    """The best cached schema that clears the gate on this file, or None.

    Scored on the same held-out lines as structural inference, so the two are comparable. They
    used to be measured on different sets -- known schemas against the sample, structural
    against the holdout -- which made the rates two different numbers wearing one name.

    Ranked rather than first-past-the-post. `load_schemas` returns them in filename order, so
    taking the first one over the floor picked by alphabet: whichever of two schemas for the
    same format happened to sort earlier decided how every later file was read.
    """
    passing = []
    for name, schema in known.items():
        rate = match_rate(schema, holdout)
        if rate >= floor:
            passing.append(
                BootstrapResult(
                    schema,
                    f"known:{name}",
                    rate,
                    f"reused {name}, matching {rate:.0%} of held-out lines",
                )
            )
    return max(passing, key=_rank) if passing else None


def _note_reuse(result: BootstrapResult) -> BootstrapResult:
    return BootstrapResult(
        schema=result.schema,
        route=result.route,
        match_rate=result.match_rate,
        reason=result.reason
        + " (validated on the sample itself: the file was too short to hold lines back)",
    )


def _matches_shape(line: str, timestamp_name: str) -> bool:

    return re.search(TIMESTAMP_PATTERNS[timestamp_name], line) is not None

"""Format detection and adapter dispatch."""

from __future__ import annotations

from pathlib import Path

from mistify.adapters.base import LogAdapter
from mistify.adapters.json_lines import JsonLinesAdapter
from mistify.adapters.otlp import OtlpAdapter
from mistify.adapters.raw_lines import RawLinesAdapter

__all__ = [
    "ADAPTERS",
    "UnknownAdapterError",
    "detect_format",
    "detection_matrix",
    "get_adapter",
    "read_sample",
]


class UnknownAdapterError(ValueError):
    """`adapters.registered` names a format nothing implements."""

#: Elastic and Loki are still outstanding: their export shapes are conventions rather than a
#: specification, and the build plan is explicit that hand-authored fixtures for them get the
#: nesting and label conventions subtly wrong, which is the whole reason those adapters exist.
#: OTLP is a specification, so it can be written correctly without a running stack.
ADAPTERS: dict[str, type[LogAdapter]] = {
    JsonLinesAdapter.format_name: JsonLinesAdapter,
    OtlpAdapter.format_name: OtlpAdapter,
    # Never wins detection -- it scores zero always -- but must be constructible by name so
    # the pipeline can reach for it deliberately, and so `registered` can accept it.
    RawLinesAdapter.format_name: RawLinesAdapter,
}


def read_sample(source: str | Path, sample_size: int = 100) -> list[str]:
    """Read the first `sample_size` non-blank lines of a source."""
    lines: list[str] = []
    with Path(source).open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                lines.append(line.rstrip("\n"))
            if len(lines) >= sample_size:
                break
    return lines


def get_adapter(format_name: str) -> LogAdapter:
    try:
        return ADAPTERS[format_name]()
    except KeyError:
        known = ", ".join(sorted(ADAPTERS)) or "(none)"
        raise ValueError(f"unknown format {format_name!r}. Registered: {known}") from None


def detect_format(
    sample_lines: list[str],
    registered: list[str] | None = None,
    min_confidence: float = 0.6,
) -> tuple[LogAdapter | None, dict[str, float]]:
    """Pick the best-matching adapter for a sample.

    Returns `(adapter, scores)`. A `None` adapter means no registered format was confident
    enough; from Phase 4 that hands off to the unknown-format bootstrapper rather than
    failing ingestion.
    """
    if registered is None:
        names = list(ADAPTERS)
    else:
        # An unregistered name is a configuration error, not a filter. Silently dropping it
        # meant a typo in `adapters.registered` removed a format from consideration and the
        # file then routed to whichever adapter was next-most confident -- a wrong parse
        # presented as a successful one, with nothing anywhere saying why.
        unknown = [name for name in registered if name not in ADAPTERS]
        if unknown:
            raise UnknownAdapterError(
                f"adapters.registered names {', '.join(sorted(unknown))}, which "
                f"{'is' if len(unknown) == 1 else 'are'} not implemented. "
                f"Available: {', '.join(sorted(ADAPTERS))}."
            )
        names = list(registered)
    scores = {name: ADAPTERS[name]().detect(sample_lines) for name in names}
    if not scores:
        return None, scores
    best = max(scores, key=lambda name: scores[name])
    if scores[best] < min_confidence:
        return None, scores
    return ADAPTERS[best](), scores


def detection_matrix(samples: dict[str, list[str]]) -> dict[str, dict[str, float]]:
    """Every adapter's confidence on every sample, as `{sample: {adapter: score}}`.

    The confusion matrix Phase 4 asks for. Detection is the one decision in this pipeline that
    is made once, silently, and determines how every later stage reads the file -- a format
    that loses by a hair is indistinguishable in the output from one that never applied. Seeing
    the whole grid is how near-misses become visible before they become a wrong parse.
    """
    return {
        name: {adapter: ADAPTERS[adapter]().detect(lines) for adapter in sorted(ADAPTERS)}
        for name, lines in samples.items()
    }

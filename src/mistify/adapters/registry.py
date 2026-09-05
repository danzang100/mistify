"""Format detection and adapter dispatch."""

from __future__ import annotations

from pathlib import Path

from mistify.adapters.base import LogAdapter
from mistify.adapters.elastic import ElasticAdapter
from mistify.adapters.json_lines import JsonLinesAdapter
from mistify.adapters.loki import LokiAdapter
from mistify.adapters.otlp import OtlpAdapter
from mistify.adapters.raw_lines import RawLinesAdapter
from mistify.adapters.source import open_text

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


#: Elastic reads two shapes whose *envelope* is specified -- a `_search` response and an NDJSON
#: index dump -- while what sits inside `_source` is convention, which is the part the build
#: plan warned a hand-authored fixture gets subtly wrong. `tests/fixtures/capture_elastic.py`
#: is how that stops being a guess; until it has been run against a real stack the field
#: mapping is a considered assumption and the adapter's docstring says so. OTLP is a
#: specification and could be written without a stack; Loki was written against captures taken
#: from a real collector and a real Loki, per testing §6.
ADAPTERS: dict[str, type[LogAdapter]] = {
    ElasticAdapter.format_name: ElasticAdapter,
    JsonLinesAdapter.format_name: JsonLinesAdapter,
    LokiAdapter.format_name: LokiAdapter,
    OtlpAdapter.format_name: OtlpAdapter,
    # Never wins detection -- it scores zero always -- but must be constructible by name so
    # the pipeline can reach for it deliberately, and so `registered` can accept it.
    RawLinesAdapter.format_name: RawLinesAdapter,
}


def read_sample(source: str | Path, sample_size: int = 100) -> list[str]:
    """Read the first `sample_size` non-blank lines of a source.

    Through `open_text`, so detection sees a compressed file's *contents* rather than its
    compressed bytes -- and so a binary file is refused here, before any adapter has scored it.
    """
    lines: list[str] = []
    with open_text(Path(source)) as handle:
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

    Selection is by specificity tier first and confidence second, not by confidence alone.
    Every adapter that clears the floor has made a claim, but the claims are not comparable:
    `json_lines` returning 1.0 on a Loki export says "these are JSON objects with timestamps",
    which is true and useless, while a Loki adapter returning 0.7 says "this is a Loki query
    response". Ranking those by number picks the first, and the resulting parse reads `labels`
    and `line` as opaque fields -- no error, no warning, every record subtly wrong.

    So a specific adapter that clears the floor beats a generic one that clears it by more.
    Within a tier the number decides, which is what keeps two specific adapters honest against
    each other. The full score dict is returned unchanged either way: the losing scores are
    what make a near-miss visible, and `detection_matrix` exists to show the whole grid.
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
    eligible = [name for name in names if scores[name] >= min_confidence]
    if not eligible:
        return None, scores
    best = max(eligible, key=lambda name: (ADAPTERS[name].specificity, scores[name]))
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

"""Format detection and adapter dispatch."""

from __future__ import annotations

from pathlib import Path

from mistify.adapters.base import LogAdapter
from mistify.adapters.json_lines import JsonLinesAdapter

__all__ = ["ADAPTERS", "detect_format", "get_adapter", "read_sample"]

#: Phase 4 registers elastic, loki and otlp here.
ADAPTERS: dict[str, type[LogAdapter]] = {
    JsonLinesAdapter.format_name: JsonLinesAdapter,
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
    names = list(ADAPTERS) if registered is None else [n for n in registered if n in ADAPTERS]
    scores = {name: ADAPTERS[name]().detect(sample_lines) for name in names}
    if not scores:
        return None, scores
    best = max(scores, key=lambda name: scores[name])
    if scores[best] < min_confidence:
        return None, scores
    return ADAPTERS[best](), scores

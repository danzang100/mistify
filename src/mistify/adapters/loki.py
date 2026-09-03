"""Grafana Loki adapter, written against captures from a running stack.

The third adapter, and the first one that could not be written from a specification. Loki has
an API reference but no normative mapping from a log record onto what comes back out of it:
what ends up in the label set is decided by the collector, the distributor's config and Loki's
own enrichment, and every one of those varies by deployment. So this adapter was written
against `tests/fixtures/capture_loki.py` output -- logs pushed through a real OTLP collector
into a real Loki and read back from `/loki/api/v1/query_range`.

That mattered. Four things the capture showed that a hand-authored fixture would have got
wrong, and each one is a whole-file failure rather than a bad line:

**Severity is on the stream, not the entry.** Loki's unit is a stream: a label set plus a list
of `[timestamp, line]` pairs. Everything the producer sent as an attribute -- `severityText`,
`traceId`, application fields -- is flattened into that label set. A reader looking for severity
on the entry finds nothing and marks the whole file unmapped, which collapses the heaviest term
in the anomaly score to a constant.

**Dots become underscores.** `service.name` arrives as `service_name`, `deployment.environment`
as `deployment_environment`. An adapter keying on the OTLP spelling matches nothing.

**Every label value is a string.** `severityNumber: 17` comes back as `"17"`; an OTLP `intValue`
does too. Nothing survives as a number, so nothing may be compared as one.

**Stream shape is not a property of the format.** Labels define stream identity, so any label
that varies per record puts every record in its own stream. `observedTimeUnixNano` is exactly
such a label -- Loki promotes it to `observed_timestamp` -- and sending it turned a 500-record
push into 500 streams of one entry, where omitting it gave 2 streams of 250. Both are ordinary.
An adapter tuned to either one is broken on the other, so this one assumes neither.

`detected_level` is Loki's own contribution: a lowercase level it infers from the line when the
producer sent none, falling back to the literal string `"unknown"`, which means nothing and is
treated as nothing.

Three layouts are read, because three different things hand you Loki data:

* a `query_range` / `query` response, `{"data": {"resultType": "streams", "result": [...]}}`
* a push payload, `{"streams": [...]}` -- the same stream objects, one level up
* `logcli --output=jsonl`, one `{"labels": {...}, "line": ..., "timestamp": ...}` per line

The third is why `LogAdapter.specificity` exists. Those lines are JSON objects carrying a
timestamp, so `json_lines` scores a perfect 1.0 on them and no confidence this adapter returns
could ever beat that. Ranked by number alone the generic reader wins, `labels` and `line` become
two opaque fields, and every record is quietly wrong. The tier is what settles it.

What is *not* handled: a line that is itself JSON, as an application logging structured output
into Loki produces. The line becomes the message verbatim, which is honest but leaves the
templater to cluster JSON blobs. Lifting the inner message is a real improvement and a separate
change; guessing at it here would put a second format's parsing rules inside this one.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from mistify.adapters.base import LogAdapter
from mistify.adapters.source import read_text
from mistify.common.models import LogRecord, normalize_severity, parse_timestamp

__all__ = ["LokiAdapter"]

#: Labels that name the emitting service, most specific first. `service_name` is what the OTLP
#: semantic conventions become after Loki replaces the dots; the rest are what Promtail, Alloy
#: and Docker service discovery attach instead, and a deployment usually has exactly one.
_SOURCE_LABELS = (
    "service_name",
    "service",
    "app",
    "job",
    "container",
    "container_name",
    "pod",
    "host",
    "filename",
)

#: Where a level can be found on a stream, in decreasing order of authority. The first is what
#: the producer said; the second is what Loki guessed when the producer said nothing.
_SEVERITY_LABELS = ("severity_text", "level", "severity", "detected_level")

#: Loki's placeholder when its own detection failed. A literal level name in the data that
#: means "no level", so it must not reach `normalize_severity` -- which would map it to the
#: default and report the line as *mapped*, hiding the gap the metric exists to show.
_UNKNOWN_LEVEL = "unknown"

#: Labels consumed into a `LogRecord` field of their own. Left out of `fields` so the same
#: value is not carried twice under two names.
_CONSUMED_LABELS = frozenset({*_SOURCE_LABELS, *_SEVERITY_LABELS})


def _streams(payload: Any) -> list[dict[str, Any]] | None:
    """The stream list out of whichever layout this payload is, or None if it is neither.

    A query response nests it under `data.result`; a push payload has it at the top level as
    `streams`. The stream objects themselves are identical, so only the path differs.
    """
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if isinstance(data, dict):
        # `resultType` is `streams` for a log query and `matrix`/`vector` for a metric one.
        # A metric query returns numbers with no lines in them at all, so it is not merely
        # unsupported here -- there is nothing in it for a log pipeline to read.
        if data.get("resultType") not in (None, "streams"):
            return None
        result = data.get("result")
        if isinstance(result, list):
            return [item for item in result if isinstance(item, dict)]
    streams = payload.get("streams")
    if isinstance(streams, list):
        return [item for item in streams if isinstance(item, dict)]
    return None


def _first_label(labels: dict[str, Any], names: tuple[str, ...]) -> tuple[str | None, Any]:
    for name in names:
        value = labels.get(name)
        if value is not None and str(value).strip():
            return name, value
    return None, None


class LokiAdapter(LogAdapter):
    """Reads Loki query responses, push payloads and `logcli` JSONL."""

    format_name = "loki"
    #: A named export shape, and the reason the tier exists: on `logcli --output=jsonl` the
    #: generic `json_lines` reader scores 1.0 and cannot be beaten on the number alone.
    specificity = 2

    def detect(self, sample_lines: list[str]) -> float:
        """Confidence that this is Loki output, in any of its three layouts.

        A pretty-printed response -- which is what saving a `curl` gives you, and what the
        capture script writes -- cannot be JSON-parsed from a sample at all, because the sample
        is a handful of lines from the middle of one value. So the structural keys are matched
        as text for that case. Weaker evidence, and scored lower, but the alternative is scoring
        zero on the layout people most often hand over.
        """
        candidates = [line for line in sample_lines if line.strip()]
        if not candidates:
            return 0.0

        jsonl_hits = 0
        for line in candidates:
            try:
                payload = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            if _streams(payload) is not None:
                return 0.98
            # The logcli line shape. `labels` beside `line` is the distinctive pair: plenty of
            # log formats have a timestamp and a message, and none of the others call the
            # message `line` and hang a label dict off it.
            if isinstance(payload.get("labels"), dict) and "line" in payload:
                jsonl_hits += 1

        if jsonl_hits:
            # Proportional, so a file that is mostly something else does not win on one line.
            return 0.6 + 0.38 * (jsonl_hits / len(candidates))

        joined = "\n".join(candidates)
        has_streams = '"resultType"' in joined and '"streams"' in joined
        has_shape = '"stream"' in joined and '"values"' in joined
        if has_streams and has_shape:
            return 0.9
        if has_shape:
            # `stream` beside `values` is Loki's own shape and nothing else uses the pair,
            # but without `resultType` this could be a fragment of anything containing one.
            return 0.7
        return 0.0

    def parse(self, source: str | Path) -> Iterator[LogRecord]:
        """Stream records out of whichever layout the file turns out to be.

        A query response is one JSON value and cannot be streamed without a streaming parser;
        `logcli` JSONL is line-delimited and can. Which one this is has to be decided before
        reading, so the first non-blank line decides: a `{` that opens a document with no
        second top-level object after it is a response, anything else is line-delimited.
        """
        path = Path(source)
        text = read_text(path)
        stripped = text.lstrip()

        if stripped.startswith("{") and "\n{" not in text:
            yield from self._parse_document(text)
            return
        if stripped.startswith("["):
            yield from self._parse_document(text)
            return

        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            self.stats.lines_read += 1
            try:
                payload = json.loads(line)
            except (json.JSONDecodeError, ValueError) as exc:
                self.stats.record_error(f"line {lineno}: invalid JSON ({exc.__class__.__name__})")
                continue
            if not isinstance(payload, dict):
                self.stats.record_error(f"line {lineno}: JSON value is not an object")
                continue
            # A line-delimited file can still carry whole responses, one per line, which is
            # what a paginated capture loop writes.
            streams = _streams(payload)
            if streams is not None:
                yield from self._records_from_streams(streams, lineno)
            else:
                record = self._from_jsonl(payload, lineno)
                if record is not None:
                    self.stats.records_emitted += 1
                    yield record

    def _parse_document(self, text: str) -> Iterator[LogRecord]:
        self.stats.lines_read += 1
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            self.stats.record_error(f"document: invalid JSON ({exc.__class__.__name__})")
            return
        for item in payload if isinstance(payload, list) else [payload]:
            streams = _streams(item)
            if streams is None:
                self.stats.record_error("document: no streams array")
                continue
            yield from self._records_from_streams(streams, 1)

    def _records_from_streams(
        self, streams: list[dict[str, Any]], lineno: int
    ) -> Iterator[LogRecord]:
        for stream in streams:
            labels = stream.get("stream")
            if not isinstance(labels, dict):
                # A push payload spells the same field `stream`; nothing spells it anything
                # else, so a stream object without one is malformed rather than a variant.
                self.stats.record_error(f"line {lineno}: stream has no label set")
                continue
            values = stream.get("values")
            if not isinstance(values, list):
                self.stats.record_error(f"line {lineno}: stream has no values array")
                continue
            source, severity, mapped, base_fields = self._from_labels(labels)
            for entry in values:
                record = self._one_entry(entry, source, severity, mapped, base_fields, lineno)
                if record is not None:
                    self.stats.records_emitted += 1
                    yield record

    def _from_labels(self, labels: dict[str, Any]) -> tuple[str, str, bool, dict[str, Any]]:
        """Everything a stream's label set says about every entry under it.

        Computed once per stream rather than per entry. In the one-stream-per-record shape that
        is the same thing; in the one-stream-per-push shape it is hundreds of entries sharing
        one answer, and doing it per entry would re-derive it hundreds of times.
        """
        source_key, source_value = _first_label(labels, _SOURCE_LABELS)
        source = str(source_value) if source_key is not None else "unknown"

        severity_key, severity_value = _first_label(labels, _SEVERITY_LABELS)
        if severity_key is not None and str(severity_value).strip().lower() == _UNKNOWN_LEVEL:
            # Loki saying it could not tell. Passing the word through would map to the default
            # and be counted as a successful mapping, which is the opposite of what happened.
            severity_value = None
        severity, mapped = normalize_severity(severity_value)

        fields = {key: value for key, value in labels.items() if key not in _CONSUMED_LABELS}
        return source, severity, mapped, fields

    def _one_entry(
        self,
        entry: Any,
        source: str,
        severity: str,
        mapped: bool,
        base_fields: dict[str, Any],
        lineno: int,
    ) -> LogRecord | None:
        """One `[timestamp, line]` pair, with the stream's labels applied.

        A third element carrying structured metadata is documented in Loki's API and did not
        appear in the captures this was written against, where the collector turned everything
        into labels instead. It is read when present rather than assumed absent: an adapter
        that indexes `[0]` and `[1]` and ignores the rest loses those fields silently.
        """
        if not isinstance(entry, list) or len(entry) < 2:
            self.stats.record_error(f"line {lineno}: entry is not a [timestamp, line] pair")
            return None

        raw_ts, line = entry[0], entry[1]
        try:
            ts = parse_timestamp(raw_ts)
        except ValueError:
            self.stats.unparseable_timestamp += 1
            self.stats.record_error(f"line {lineno}: unparseable timestamp {raw_ts!r}")
            return None

        if not mapped:
            self.stats.unmapped_severity += 1

        message = line if isinstance(line, str) else json.dumps(line, separators=(",", ":"))

        fields = dict(base_fields)
        if len(entry) > 2 and isinstance(entry[2], dict):
            fields.update(entry[2])

        # `raw` is this entry re-serialised with its labels, not the response it arrived in.
        # One response carries every record in the file, so quoting it would give them all the
        # same `raw` -- and `raw` is what a reader greps to check a claim.
        raw = json.dumps(
            {"labels": {**base_fields, "source": source}, "timestamp": raw_ts, "line": message},
            separators=(",", ":"),
            default=str,
        )
        return LogRecord(
            ts=ts,
            source=source,
            severity=severity,
            raw=raw,
            message=message,
            fields=fields,
            format=self.format_name,
        )

    def _from_jsonl(self, payload: dict[str, Any], lineno: int) -> LogRecord | None:
        """One `logcli --output=jsonl` line: a label dict, a line, and a timestamp."""
        labels = payload.get("labels")
        if not isinstance(labels, dict):
            self.stats.record_error(f"line {lineno}: no labels object")
            return None
        if "line" not in payload:
            self.stats.record_error(f"line {lineno}: no line field")
            return None

        raw_ts = payload.get("timestamp")
        if raw_ts is None:
            self.stats.record_error(f"line {lineno}: no timestamp field")
            return None
        try:
            ts = parse_timestamp(raw_ts)
        except ValueError:
            self.stats.unparseable_timestamp += 1
            self.stats.record_error(f"line {lineno}: unparseable timestamp {raw_ts!r}")
            return None

        source, severity, mapped, fields = self._from_labels(labels)
        if not mapped:
            self.stats.unmapped_severity += 1

        line = payload["line"]
        message = line if isinstance(line, str) else json.dumps(line, separators=(",", ":"))

        return LogRecord(
            ts=ts,
            source=source,
            severity=severity,
            raw=json.dumps(payload, separators=(",", ":"), default=str),
            message=message,
            fields=fields,
            format=self.format_name,
        )

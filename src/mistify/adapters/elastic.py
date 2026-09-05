"""Elasticsearch adapter: `_search` responses and NDJSON index dumps.

The fourth and last format, and the one the build plan singled out as impossible to write from
a specification. That is half right, and the half matters:

**The envelope is normative.** A `_search` response is `{"hits": {"hits": [{"_index": ...,
"_source": {...}}]}}` because the REST specification says so, and no deployment varies it. The
same objects, one per line, are what `elasticsearch-dump` and every scroll-and-write script
produce. Both are safe to read from the specification and both are read here.

**What is inside `_source` is convention**, decided by whatever indexed the document, and it is
where a hand-authored fixture goes wrong in a way no test catches:

*   **Nested and dotted are both valid and both occur.** Elasticsearch accepts
    `{"log": {"level": "error"}}` and `{"log.level": "error"}` and returns whichever was
    indexed. Filebeat writes nested; plenty of application shippers write dotted; a document
    can carry both. A reader that handles one silently drops severity for every deployment
    using the other -- which collapses the heaviest term in the anomaly score to a constant,
    exactly the failure the Loki capture found on `severityText`.
*   **The level is not always at `log.level`.** ECS says it is. Pre-ECS Logstash wrote `level`,
    and a shipper that never adopted ECS writes something else again.
*   **`message` may or may not be the whole line.** Filebeat tailing a plain file puts the raw
    line there; a structured shipper puts the parsed message there and the rest in siblings.

So the lookups below are ordered and explicit rather than clever, and every one of them tries
the nested path and the dotted key. `tests/fixtures/capture_elastic.py` is how they stop being
assumptions: it ships real lines through a real Filebeat into a real Elasticsearch and saves
what comes back, and its provenance file records whether a capture came from a shipper or from
a document this project wrote -- because only the first says anything about conventions.

**Status: the field mapping below has not yet been checked against a capture.** The envelope
has, in the sense that it is specified. Until `capture_elastic.py` has been run against a real
stack, treat the `_source` handling as the considered guess it is, and the tests covering it as
testing the rules chosen here rather than what Elastic actually emits.

Like Loki, this sets `specificity` above the generic reader. An NDJSON dump is a file of JSON
objects carrying timestamps, so `json_lines` scores a perfect 1.0 on it and cannot be beaten on
the number alone; ranked by score only, `_source` becomes one opaque field and every record is
quietly wrong.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from mistify.adapters.base import LogAdapter
from mistify.adapters.source import open_text, read_text
from mistify.common.models import LogRecord, normalize_severity, parse_timestamp

__all__ = ["ElasticAdapter"]

#: Non-blank lines examined to decide the layout. Enough to survive a truncated opening line
#: without reading a meaningful part of a large export.
_LAYOUT_SAMPLE_LINES = 5

#: Where the event time lives, most authoritative first. `@timestamp` is ECS and is what every
#: shipper writes; the rest are what a document indexed before ECS, or by hand, carries.
_TS_FIELDS = ("@timestamp", "timestamp", "time", "event.created", "event.ingested")

#: Where the level lives. `log.level` is ECS. `log.syslog.severity.name` is what a syslog input
#: produces alongside it, and the bare names are pre-ECS.
_SEVERITY_FIELDS = (
    "log.level",
    "log.syslog.severity.name",
    "level",
    "severity",
    "log_level",
    "loglevel",
)

#: Where the message lives. `message` is ECS; `event.original` is the untouched source line
#: when the shipper parsed the message out of it.
_MESSAGE_FIELDS = ("message", "event.original", "log.original", "msg")

#: What emitted the line, most specific first. A deployment usually populates exactly one.
_SOURCE_FIELDS = (
    "service.name",
    "container.name",
    "kubernetes.pod.name",
    "host.name",
    "host.hostname",
    "agent.name",
    "log.file.path",
)

#: Fields consumed into a `LogRecord` field of its own, so the same value is not also carried
#: in `fields` under its original name.
_CONSUMED = frozenset({*_TS_FIELDS, *_SEVERITY_FIELDS, *_MESSAGE_FIELDS, *_SOURCE_FIELDS})

#: Paths that mark a document as ECS-shaped when the export envelope is gone.
#:
#: `ecs.version` is the strong one: the ECS specification makes it **required** on a conforming
#: document, so it is specification rather than convention, and Filebeat writes it on every
#: line. The rest are the common ECS field groups, used together as weaker corroboration --
#: any one of them alone appears in plenty of ordinary JSON logs.
_ECS_MARKER = "ecs.version"
_ECS_SHAPE = (
    "log.level",
    "service.name",
    "host.name",
    "agent.type",
    "agent.name",
    "event.dataset",
    "log.file.path",
)


def _lookup(source: dict[str, Any], path: str) -> Any:
    """The value at `path`, whether the document nested it or flattened it to a dotted key.

    Both spellings are valid Elasticsearch and both are common. The dotted key is tried first
    because it is unambiguous: a document carrying a literal `"log.level"` key means exactly
    that, where a nested walk could reach the same place by coincidence through an object that
    happens to be named `log`.
    """
    if path in source:
        return source[path]
    current: Any = source
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    # A dict here means the path stopped short of a leaf -- `log.level` resolving to the whole
    # `log` object, say -- which is not a value and must not be stringified into one.
    return None if isinstance(current, dict) else current


def _first(source: dict[str, Any], paths: tuple[str, ...]) -> tuple[str | None, Any]:
    for path in paths:
        value = _lookup(source, path)
        if value is not None and str(value).strip():
            return path, value
    return None, None


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    """Nested objects as dotted keys, so `fields` is flat whichever way the document came."""
    flat: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            flat.update(_flatten(item, path))
    elif prefix:
        flat[prefix] = value
    return flat


def _is_ecs_document(payload: dict[str, Any]) -> bool:
    """Whether a bare document is ECS-shaped, without over-claiming ordinary JSON logs.

    `ecs.version` is required by the ECS specification and settles it alone. Failing that, a
    timestamp plus two distinct ECS field groups is taken as enough: one group on its own --
    a `level`, or a `service` object -- is what any number of application logs carry, and
    grabbing those would route a file this adapter has nothing to offer away from the reader
    that does.
    """
    if _lookup(payload, _ECS_MARKER) is not None:
        return True
    if _lookup(payload, "@timestamp") is None:
        return False
    return sum(1 for path in _ECS_SHAPE if _lookup(payload, path) is not None) >= 2


def _hits(payload: Any) -> list[dict[str, Any]] | None:
    """The hit list out of a `_search` response, or None if this is not one."""
    if not isinstance(payload, dict):
        return None
    hits = payload.get("hits")
    if isinstance(hits, dict):
        inner = hits.get("hits")
        if isinstance(inner, list):
            return [item for item in inner if isinstance(item, dict)]
    return None


class ElasticAdapter(LogAdapter):
    """Reads Elasticsearch `_search` responses and NDJSON index dumps."""

    format_name = "elastic"
    #: A named export shape. Same reason as Loki: on an NDJSON dump the generic `json_lines`
    #: reader scores 1.0 and cannot be beaten on the number alone.
    specificity = 2

    def detect(self, sample_lines: list[str]) -> float:
        """Confidence that this is Elasticsearch output, in either layout.

        A pretty-printed `_search` response cannot be JSON-parsed from a sample, because the
        sample is a handful of lines from the middle of one value -- the same problem Loki has
        and the same answer: match the structural keys as text, and score it lower because the
        evidence is weaker.
        """
        candidates = [line for line in sample_lines if line.strip()]
        if not candidates:
            return 0.0

        dump_hits = 0
        ecs_hits = 0
        for line in candidates:
            try:
                payload = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            if _hits(payload) is not None:
                return 0.98
            # The dump line shape. `_source` beside `_index` is the distinctive pair: many
            # formats carry a document and a timestamp, and none of the others name the
            # document `_source`.
            if isinstance(payload.get("_source"), dict) and "_index" in payload:
                dump_hits += 1
            elif _is_ecs_document(payload):
                ecs_hits += 1

        if dump_hits:
            # Proportional, so a file that is mostly something else cannot win on one line.
            return 0.6 + 0.38 * (dump_hits / len(candidates))

        if ecs_hits:
            # A bare ECS document, envelope stripped -- what Filebeat writing to a file
            # produces, and what an export loop that unwrapped the hits leaves behind.
            #
            # This is the case `specificity` exists for, and measuring it is what found it: a
            # file of these scores a flat **1.0** on `json_lines`, because they are JSON objects
            # with an `@timestamp`. Ranked by number the generic reader takes them, reads `log`
            # as one opaque nested field, and finds no severity on any line -- unmapped for the
            # whole file, which collapses the heaviest term of the anomaly score to a constant.
            # The score below is deliberately lower than 1.0; the tier is what settles it.
            return 0.6 + 0.35 * (ecs_hits / len(candidates))

        joined = "\n".join(candidates)
        if '"hits"' in joined and '"_source"' in joined:
            return 0.9
        if '"_source"' in joined and '"_index"' in joined:
            # The pair is Elastic's own and nothing else uses it, but without `hits` this
            # could be a fragment of anything that embedded a document.
            return 0.7
        return 0.0

    def parse(self, source: str | Path) -> Iterator[LogRecord]:
        """Stream records out of whichever layout the file turns out to be.

        A `_search` response is one JSON value and stays resident: there is no way to parse one
        incrementally without a streaming parser. A dump is line-delimited and does not have to
        be, so the layout is decided from the first few lines rather than by reading the whole
        file to find out -- the defect that put OTLP's peak memory at exactly 3.00x file size.
        """
        path = Path(source)
        if self._is_single_document(path):
            yield from self._parse_document(read_text(path))
            return

        with open_text(path) as handle:
            for lineno, line in enumerate(handle, start=1):
                text = line.rstrip("\n")
                if not text.strip():
                    continue
                self.stats.lines_read += 1
                try:
                    payload = json.loads(text)
                except (json.JSONDecodeError, ValueError) as exc:
                    self.stats.record_error(
                        f"line {lineno}: invalid JSON ({exc.__class__.__name__})"
                    )
                    continue
                if not isinstance(payload, dict):
                    self.stats.record_error(f"line {lineno}: JSON value is not an object")
                    continue
                record = self._record(payload, f"line {lineno}")
                if record is not None:
                    self.stats.records_emitted += 1
                    yield record

    def _is_single_document(self, path: Path) -> bool:
        """Whether this file is one JSON value rather than a document per line.

        Decided from the opening lines. A `_search` response saved by `curl` is either one long
        line or pretty-printed across many; in both cases the first non-blank line opens an
        object that does not close on that line.
        """
        with open_text(path) as handle:
            sample = []
            for line in handle:
                if line.strip():
                    sample.append(line.rstrip("\n"))
                if len(sample) >= _LAYOUT_SAMPLE_LINES:
                    break
        if not sample:
            return False

        parsed_any = False
        for line in sample:
            try:
                payload = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            if _hits(payload) is not None:
                return True
            parsed_any = True

        # A line that fails to parse used to decide this on its own, on the reasoning that it
        # must be part of a value spanning several lines. It is also what one corrupt line in a
        # dump looks like -- and a dump read as a single document yields *nothing*, because the
        # whole file then fails to parse as one JSON value. Measured on a three-line fixture
        # with one bad line in the middle: two good records became zero.
        #
        # So a line that did parse into an object is the evidence that decides, and only a
        # sample where nothing parsed at all is treated as one pretty-printed value.
        return not parsed_any

    def _parse_document(self, text: str) -> Iterator[LogRecord]:
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            self.stats.record_error(f"document is not valid JSON ({exc.__class__.__name__})")
            return
        hits = _hits(payload)
        if hits is None:
            self.stats.record_error("document has no hits.hits array")
            return
        for index, hit in enumerate(hits, start=1):
            self.stats.lines_read += 1
            record = self._record(hit, f"hit {index}")
            if record is not None:
                self.stats.records_emitted += 1
                yield record

    def _record(self, hit: dict[str, Any], where: str) -> LogRecord | None:
        """One hit as a `LogRecord`, or None with the reason counted.

        A bare `_source` document is accepted as well as a wrapped hit: an export that strips
        the envelope is common and the document inside it is the same thing.
        """
        raw_document = hit.get("_source")
        if not isinstance(raw_document, dict):
            # An export that stripped the envelope leaves the document itself, which is the
            # same thing. A hit that carries `_index` but no `_source` is a real Elastic
            # response with the field excluded, and reading its metadata as a log line would
            # invent a record out of routing information.
            raw_document = None if "_index" in hit else hit
        if not isinstance(raw_document, dict):
            self.stats.record_error(f"{where}: no _source object")
            return None
        document: dict[str, Any] = raw_document

        ts_field, ts_value = _first(document, _TS_FIELDS)
        if ts_field is None:
            self.stats.record_error(f"{where}: no timestamp field")
            return None
        try:
            ts = parse_timestamp(ts_value)
        except ValueError:
            self.stats.unparseable_timestamp += 1
            self.stats.record_error(f"{where}: unparseable timestamp {ts_value!r}")
            return None

        _, sev_value = _first(document, _SEVERITY_FIELDS)
        severity, mapped = normalize_severity(sev_value)
        if not mapped:
            self.stats.unmapped_severity += 1

        msg_field, msg_value = _first(document, _MESSAGE_FIELDS)
        message = str(msg_value) if msg_field is not None else ""

        src_field, src_value = _first(document, _SOURCE_FIELDS)
        emitter = str(src_value) if src_field is not None else "unknown"

        fields = {
            key: value
            for key, value in _flatten(document).items()
            if key not in _CONSUMED and value is not None
        }
        return LogRecord(
            ts=ts,
            source=emitter,
            severity=severity,
            # The document as indexed, not the line as written: an Elastic export *is* JSON, so
            # the JSON is the source of record. Where the shipper kept the original line it is
            # in `event.original` and reachable through `message` above.
            raw=json.dumps(document, separators=(",", ":"), sort_keys=True),
            message=message,
            fields=fields,
            format=self.format_name,
        )

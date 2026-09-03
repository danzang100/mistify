"""OTLP logs adapter, built from the protobuf-JSON mapping rather than from a sample.

Chosen as the second adapter because it is the only one of the three that can be made exactly
right without a running stack. Elastic and Loki export shapes are conventions, and the build
plan is explicit that hand-authored fixtures for those get the nesting and label conventions
subtly wrong -- which is the whole reason those adapters exist. OTLP is a specification, and
the protobuf-JSON mapping is normative, so an implementation can be correct by construction.

Four things about the format shape this adapter, and all four are places a naive reading
produces a parser that works on one exporter and fails on the next.

**Records are three levels down.** `resourceLogs[] -> scopeLogs[] -> logRecords[]`, and the
context a log line needs -- which service emitted it -- lives on the *resource*, not on the
record. Flattening without carrying resource attributes down loses the source of every line.

**Field names come in two spellings.** The protobuf-JSON mapping emits camelCase by default,
but explicitly permits the original proto field names, so `timeUnixNano` and `time_unix_nano`
are both valid and both appear in the wild. Reading only one is the most common way an OTLP
parser silently drops every record.

**64-bit integers are strings.** `timeUnixNano` arrives as `"1690000000000000000"`, not a
number, because JSON cannot hold an int64 exactly. Anything treating it as a number either
loses precision or fails to parse.

**Severity is a number with a defined range, and the text is optional.** `severityNumber` maps
in bands of four -- 1-4 TRACE, 5-8 DEBUG, and so on -- so a record carrying only the number is
still fully typed. Reading `severityText` alone leaves every such record unmapped.

Both file layouts are accepted: one export request per line, which is what file exporters
write, and a single pretty-printed document, which is what a hand-saved API response looks
like. The line-delimited path streams; the document path cannot, and says so.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from mistify.adapters.base import LogAdapter
from mistify.adapters.source import read_text
from mistify.common.models import LogRecord, normalize_severity, parse_timestamp

__all__ = ["OtlpAdapter"]

#: Both spellings of every field this adapter reads. The protobuf-JSON mapping permits either,
#: and exporters disagree, so each lookup tries both rather than picking a side.
_RESOURCE_LOGS = ("resourceLogs", "resource_logs")
_SCOPE_LOGS = ("scopeLogs", "scope_logs")
_LOG_RECORDS = ("logRecords", "log_records")
_TIME = ("timeUnixNano", "time_unix_nano")
_OBSERVED_TIME = ("observedTimeUnixNano", "observed_time_unix_nano")
_SEVERITY_NUMBER = ("severityNumber", "severity_number")
_SEVERITY_TEXT = ("severityText", "severity_text")
_TRACE_ID = ("traceId", "trace_id")
_SPAN_ID = ("spanId", "span_id")

#: Resource attribute keys that name the emitting service, most specific first.
#: `service.name` is the one the semantic conventions require; the rest are what people
#: actually set when they have not read them.
_SERVICE_KEYS = ("service.name", "service", "k8s.deployment.name", "host.name")

#: severityNumber bands, from the logs data model. Four numbers per level so a producer can
#: express "a slightly worse ERROR" without inventing a level.
_SEVERITY_BANDS = (
    (1, "TRACE"),
    (5, "DEBUG"),
    (9, "INFO"),
    (13, "WARN"),
    (17, "ERROR"),
    (21, "FATAL"),
)


def _get(payload: dict[str, Any], names: tuple[str, ...]) -> Any:
    """First present spelling of a field, or None."""
    for name in names:
        if name in payload and payload[name] is not None:
            return payload[name]
    return None


def _any_value(value: Any) -> Any:
    """One OTLP `AnyValue` as a plain Python value.

    A tagged union in the wire format: exactly one of `stringValue`, `intValue`, `boolValue`,
    `doubleValue`, `arrayValue`, `kvlistValue` or `bytesValue` is set. Returning the raw dict
    would put wire-format tags into `fields`, where every later stage would have to know about
    them -- the adapter's job is to make the format stop mattering.
    """
    if not isinstance(value, dict):
        return value
    for key in ("stringValue", "string_value"):
        if key in value:
            return value[key]
    for key in ("intValue", "int_value"):
        if key in value:
            # int64 as a string, per the protobuf-JSON mapping.
            try:
                return int(value[key])
            except (TypeError, ValueError):
                return value[key]
    for key in (
        "boolValue",
        "bool_value",
        "doubleValue",
        "double_value",
        "bytesValue",
        "bytes_value",
    ):
        if key in value:
            return value[key]
    for key in ("arrayValue", "array_value"):
        if key in value:
            return [_any_value(item) for item in value[key].get("values", [])]
    for key in ("kvlistValue", "kvlist_value"):
        if key in value:
            return _attributes(value[key].get("values", []))
    return value


def _attributes(attributes: Any) -> dict[str, Any]:
    """OTLP's list-of-key-value pairs as a dict.

    Attributes are a list rather than an object because protobuf has no map-with-any-value,
    which means every consumer has to do this and a consumer that forgets sees no attributes
    at all rather than an error.
    """
    if not isinstance(attributes, list):
        return {}
    return {
        str(entry.get("key")): _any_value(entry.get("value"))
        for entry in attributes
        if isinstance(entry, dict) and entry.get("key") is not None
    }


def _severity_from_number(number: Any) -> str | None:
    """A `severityNumber` as a level name, or None when it is absent or out of range."""
    try:
        value = int(number)
    except (TypeError, ValueError):
        return None
    if not 1 <= value <= 24:
        return None
    name = "TRACE"
    for floor, label in _SEVERITY_BANDS:
        if value >= floor:
            name = label
    return name


class OtlpAdapter(LogAdapter):
    format_name = "otlp"
    #: A named format with a normative wire mapping. It has always outranked `json_lines` on an
    #: OTLP file, but only by luck: an export request has no top-level timestamp key, so the
    #: generic reader scores 0.4 there and loses on the number. That is not a property of the
    #: format, it is a property of where OTLP happens to put its timestamps.
    specificity = 2

    def detect(self, sample_lines: list[str]) -> float:
        """Confidence that this is an OTLP logs export.

        Two shapes to recognise. A line-delimited export gives whole JSON objects per line and
        can be parsed outright. A pretty-printed document gives fragments, which cannot be
        parsed from a sample at all -- so the structural keys are looked for as text. That is
        weaker evidence and scores lower, but scoring zero would mean the format is
        undetectable in the layout people most often save by hand.
        """
        candidates = [line for line in sample_lines if line.strip()]
        if not candidates:
            return 0.0

        for line in candidates:
            try:
                payload = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(payload, dict) and _get(payload, _RESOURCE_LOGS) is not None:
                return 0.98

        joined = "\n".join(candidates)
        has_resource = any(name in joined for name in _RESOURCE_LOGS)
        has_records = any(name in joined for name in _LOG_RECORDS)
        if has_resource and has_records:
            return 0.9
        if has_resource:
            # `resourceLogs` alone is still distinctive; nothing else uses that key.
            return 0.7
        return 0.0

    def parse(self, source: str | Path) -> Iterator[LogRecord]:
        path = Path(source)
        text = read_text(path)
        stripped = text.lstrip()

        # A single document has to be held in memory; there is no way to stream one JSON value
        # without a streaming parser, and OTLP file exporters write line-delimited requests
        # precisely so that consumers do not need one.
        if stripped.startswith("[") or (stripped.startswith("{") and "\n{" not in text):
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
            yield from self._records_from(payload, lineno)

    def _parse_document(self, text: str) -> Iterator[LogRecord]:
        self.stats.lines_read += 1
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            self.stats.record_error(f"document: invalid JSON ({exc.__class__.__name__})")
            return
        for item in payload if isinstance(payload, list) else [payload]:
            yield from self._records_from(item, 1)

    def _records_from(self, payload: Any, lineno: int) -> Iterator[LogRecord]:
        """Walk one export request down to its log records."""
        if not isinstance(payload, dict):
            self.stats.record_error(f"line {lineno}: JSON value is not an object")
            return
        resource_logs = _get(payload, _RESOURCE_LOGS)
        if not isinstance(resource_logs, list):
            self.stats.record_error(f"line {lineno}: no resourceLogs array")
            return

        for resource_entry in resource_logs:
            if not isinstance(resource_entry, dict):
                continue
            resource = resource_entry.get("resource") or {}
            resource_attributes = _attributes(resource.get("attributes"))
            source = next(
                (
                    str(resource_attributes[key])
                    for key in _SERVICE_KEYS
                    if key in resource_attributes
                ),
                "unknown",
            )
            for scope_entry in _get(resource_entry, _SCOPE_LOGS) or []:
                if not isinstance(scope_entry, dict):
                    continue
                scope = scope_entry.get("scope") or {}
                for record in _get(scope_entry, _LOG_RECORDS) or []:
                    parsed = self._one_record(record, source, resource_attributes, scope, lineno)
                    if parsed is not None:
                        self.stats.records_emitted += 1
                        yield parsed

    def _one_record(
        self,
        record: Any,
        source: str,
        resource_attributes: dict[str, Any],
        scope: dict[str, Any],
        lineno: int,
    ) -> LogRecord | None:
        if not isinstance(record, dict):
            self.stats.record_error(f"line {lineno}: log record is not an object")
            return None

        # `observedTimeUnixNano` is the collector's receipt time and is the documented fallback
        # when a producer omits the event time. Using it is better than dropping the record,
        # and worse than the real thing, so it is only reached when the real thing is absent.
        raw_ts = _get(record, _TIME) or _get(record, _OBSERVED_TIME)
        if raw_ts is None:
            self.stats.record_error(f"line {lineno}: log record has no timestamp")
            return None
        try:
            ts = parse_timestamp(raw_ts)
        except ValueError:
            self.stats.unparseable_timestamp += 1
            self.stats.record_error(f"line {lineno}: unparseable timestamp {raw_ts!r}")
            return None

        severity_text = _get(record, _SEVERITY_TEXT)
        severity, mapped = normalize_severity(severity_text)
        if not mapped:
            # The number is the typed field; the text is a producer's free-form label. Falling
            # back to it rescues every record that carries only the number, which is a large
            # share of machine-generated OTLP.
            from_number = _severity_from_number(_get(record, _SEVERITY_NUMBER))
            if from_number is not None:
                severity, mapped = normalize_severity(from_number)
            if not mapped:
                self.stats.unmapped_severity += 1

        message = _any_value(record.get("body"))
        if not isinstance(message, str):
            message = "" if message is None else json.dumps(message, separators=(",", ":"))

        fields: dict[str, Any] = {
            **{f"resource.{k}": v for k, v in resource_attributes.items()},
            **_attributes(record.get("attributes")),
        }
        for names, key in ((_TRACE_ID, "trace_id"), (_SPAN_ID, "span_id")):
            value = _get(record, names)
            if value is not None:
                fields[key] = value
        if scope.get("name"):
            fields["scope.name"] = scope["name"]

        # `raw` is this record's own JSON, not the transport line. One exported line carries
        # many records, so quoting the line would give every record on it the same `raw` and
        # make the audit trail useless -- and it is `raw` that a reader greps.
        return LogRecord(
            ts=ts,
            source=source,
            severity=severity,
            raw=json.dumps(record, separators=(",", ":")),
            message=message,
            fields=fields,
            format=self.format_name,
        )

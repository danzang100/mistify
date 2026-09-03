"""JSON Lines / NDJSON adapter for application and microservice logs."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from mistify.adapters.base import LogAdapter
from mistify.adapters.source import open_text
from mistify.common.models import LogRecord, normalize_severity, parse_timestamp

__all__ = ["JsonLinesAdapter"]

#: Candidate key names, most specific first. The first key present wins.
_TS_KEYS = ("ts", "timestamp", "@timestamp", "time", "eventTime", "event_time")
_SEVERITY_KEYS = ("severity", "level", "log_level", "logLevel", "lvl", "loglevel")
_SOURCE_KEYS = ("source", "service", "service_name", "serviceName", "app", "logger", "host")
_MESSAGE_KEYS = ("message", "msg", "event", "text", "log")


def _first(payload: dict[str, Any], keys: tuple[str, ...]) -> tuple[str | None, Any]:
    for key in keys:
        if key in payload and payload[key] is not None:
            return key, payload[key]
    return None, None


class JsonLinesAdapter(LogAdapter):
    format_name = "json_lines"
    #: Generic. Line-delimited JSON is a container, not a format: OTLP exports, Loki query
    #: results and half the application logs in existence are all carried in it, and this
    #: adapter reads the ones that are nothing more than that.
    specificity = 1

    def detect(self, sample_lines: list[str]) -> float:
        """Fraction of non-blank sample lines that are JSON objects carrying a timestamp.

        Requiring the timestamp keeps this from claiming every line-delimited JSON file in
        existence, including ones that are data rather than logs.
        """
        candidates = [line for line in sample_lines if line.strip()]
        if not candidates:
            return 0.0

        objects = 0
        with_ts = 0
        for line in candidates:
            try:
                payload = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            objects += 1
            if _first(payload, _TS_KEYS)[0] is not None:
                with_ts += 1

        if not objects:
            return 0.0
        object_ratio = objects / len(candidates)
        ts_ratio = with_ts / objects
        # A file of JSON objects with no timestamps anywhere is probably not a log stream.
        return object_ratio * (0.4 + 0.6 * ts_ratio)

    def parse(self, source: str | Path) -> Iterator[LogRecord]:
        path = Path(source)
        with open_text(path) as handle:
            for lineno, line in enumerate(handle, start=1):
                raw = line.rstrip("\n")
                if not raw.strip():
                    continue
                self.stats.lines_read += 1
                record = self._parse_line(raw, lineno)
                if record is not None:
                    self.stats.records_emitted += 1
                    yield record

    def _parse_line(self, raw: str, lineno: int) -> LogRecord | None:
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            self.stats.record_error(f"line {lineno}: invalid JSON ({exc.__class__.__name__})")
            return None
        if not isinstance(payload, dict):
            self.stats.record_error(f"line {lineno}: JSON value is not an object")
            return None

        ts_key, ts_value = _first(payload, _TS_KEYS)
        if ts_key is None:
            self.stats.record_error(f"line {lineno}: no timestamp field")
            return None
        try:
            ts = parse_timestamp(ts_value)
        except ValueError:
            self.stats.unparseable_timestamp += 1
            self.stats.record_error(f"line {lineno}: unparseable timestamp {ts_value!r}")
            return None

        sev_key, sev_value = _first(payload, _SEVERITY_KEYS)
        severity, mapped = normalize_severity(sev_value)
        if not mapped:
            self.stats.unmapped_severity += 1

        src_key, src_value = _first(payload, _SOURCE_KEYS)
        source = str(src_value) if src_key is not None else "unknown"

        msg_key, msg_value = _first(payload, _MESSAGE_KEYS)
        message = str(msg_value) if msg_key is not None else raw

        consumed = {k for k in (ts_key, sev_key, src_key, msg_key) if k is not None}
        fields = {k: v for k, v in payload.items() if k not in consumed}

        return LogRecord(
            ts=ts,
            source=source,
            severity=severity,
            raw=raw,
            message=message,
            fields=fields,
            format=self.format_name,
        )

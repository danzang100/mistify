"""Capture a real Loki query response, by pushing logs through a real collector.

Elastic and Loki fixtures have to come from running stacks rather
than from hand-authored JSON, because the nesting and label conventions those stores impose are
the entire reason the adapters exist -- an invented fixture encodes the invention, the adapter
is written to match it, and both are wrong together in a way no test can see.

This script is how the Loki fixture stops being invented. It pushes log records to an OTLP
collector, lets that collector write them into Loki, and saves what Loki hands back from
`/loki/api/v1/query_range`. Nothing in the path is simulated, so the quirks arrive on their own.

Four of them showed up the first time it ran, and all four would have been guessed wrong:

* **Resource attributes become labels, with the dots replaced.** `service.name` arrives as
  `service_name`, `deployment.environment` as `deployment_environment`.
* **Record attributes become labels too, not per-entry metadata.** `severityText`, `traceId`
  and every custom attribute land in the stream's label set, which means severity is a property
  of the *stream* here and not of the line -- the opposite of where a reader expects it.
* **Every label value is a string.** `severityNumber: 17` comes back as `"17"`, and so does an
  OTLP `intValue`. Nothing survives as a number.
* **Loki adds `detected_level` itself**, lowercased, whether or not the producer sent severity.

Because attributes become labels, records that differ in any attribute land in *different
streams*, and the sharpest case is `observedTimeUnixNano`: Loki promotes it to an
`observed_timestamp` **label**, which is unique per record, so sending it puts every single
record in a stream of its own. Omitting it collapses the whole push into one stream with many
entries -- which is what a file-tailing agent like Promtail or Alloy actually produces.

Both shapes are real and an adapter has to be right on both, so both are capturable:
`--source synthetic` sends observed time and yields one stream per record, `--source loghub`
omits it and yields one stream with hundreds of entries. `--observed-time` overrides either.
A fixture written by hand would have had one stream and many entries, and the adapter written
against it would have been wrong about where severity lives on every other deployment.

Usage, against the `grafana/otel-lgtm` image with its ports published:

    docker run -d --name otel-lgtm -p 3000:3000 -p 4317:4317 -p 4318:4318 -p 3100:3100 \\
        grafana/otel-lgtm:latest

    uv run python tests/fixtures/capture_loki.py --source synthetic
    uv run python tests/fixtures/capture_loki.py --source loghub --system OpenSSH

Output lands in `.cache/fixtures/loki/`, never in the repo. Captures are not committed for the
same two reasons nothing else generated here is: the Loghub-derived ones carry redistribution
terms this project has deliberately never taken on, and a fixture nobody can regenerate is a
fixture nobody can check.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_OTLP = "http://localhost:4318"
DEFAULT_LOKI = "http://localhost:3100"
DEFAULT_OUT = Path(".cache/fixtures/loki")

#: severityNumber per level, mid-band, matching `mistify.eval.fixtures`.
_SEVERITY_NUMBER = {"DEBUG": 5, "INFO": 9, "WARN": 13, "ERROR": 17, "FATAL": 21}


def _post(url: str, payload: dict[str, Any], timeout: float = 60.0) -> int:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return int(response.status)


def _get(url: str, params: dict[str, str], timeout: float = 60.0) -> dict[str, Any]:
    query = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"{url}?{query}", timeout=timeout) as response:
        return dict(json.loads(response.read()))


def _log_record(
    ts_nanos: int,
    body: str,
    severity: str | None,
    attributes: dict[str, Any],
    observed: bool,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        # int64 as a string, per the protobuf-JSON mapping.
        "timeUnixNano": str(ts_nanos),
        "body": {"stringValue": body},
        "attributes": [
            {"key": key, "value": {"stringValue": str(value)}} for key, value in attributes.items()
        ],
    }
    if observed:
        # The single field that decides the whole result shape. Loki turns it into a label,
        # labels define stream identity, and it is unique per record -- so setting it means
        # one stream per record and clearing it means one stream for the entire push.
        record["observedTimeUnixNano"] = str(ts_nanos)
    if severity is not None:
        record["severityText"] = severity
        record["severityNumber"] = _SEVERITY_NUMBER.get(severity, 9)
    return record


def _push(endpoint: str, service: str, records: list[dict[str, Any]], batch: int = 200) -> int:
    """Send records to an OTLP collector in batches, returning how many were sent."""
    sent = 0
    for start in range(0, len(records), batch):
        chunk = records[start : start + batch]
        payload = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": service}},
                            {
                                "key": "deployment.environment",
                                "value": {"stringValue": "fixture"},
                            },
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "mistify.capture", "version": "1"},
                            "logRecords": chunk,
                        }
                    ],
                }
            ]
        }
        _post(f"{endpoint}/v1/logs", payload)
        sent += len(chunk)
    return sent


def _synthetic_records(
    base_nanos: int, total_lines: int, observed: bool
) -> tuple[str, list[dict[str, Any]]]:
    """The project's own incident, as OTLP records carrying severity and attributes.

    Our data, so redistributing it is nobody's problem, and severity is set -- which is what
    produces the many-streams-of-few-entries shape.
    """
    from mistify.eval.fixtures import generate_incident

    consumed = {"timestamp", "service", "level", "message"}
    records = []
    for index, row in enumerate(generate_incident(total_lines=total_lines)):
        attributes = {key: value for key, value in row.items() if key not in consumed}
        records.append(
            _log_record(
                base_nanos + index * 1_000_000,
                str(row["message"]),
                str(row["level"]),
                attributes,
                observed,
            )
        )
    return "mistify-synthetic", records


def _loghub_records(
    base_nanos: int, system: str, limit: int, observed: bool
) -> tuple[str, list[dict[str, Any]]]:
    """Loghub lines exactly as they appear on disk, with no severity and no observed time.

    Deliberately bare. Claiming no severity is what makes Loki apply its own `detected_level`
    -- including the `"unknown"` it falls back to when it cannot tell -- and omitting observed
    time is what collapses the push into one stream with many entries. Together they give the
    shape a log-tailing agent produces, which is the one the labelled synthetic push never does.
    """
    from mistify.eval.templating_eval import fetch_loghub_raw

    path = fetch_loghub_raw(system, Path(".cache/loghub"))
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [line for line in text.splitlines() if line.strip()]
    records = [
        _log_record(base_nanos + index * 1_000_000, line, None, {}, observed)
        for index, line in enumerate(lines[:limit])
    ]
    return f"loghub-{system.lower()}", records


def _query_range(
    loki: str, service: str, start_nanos: int, end_nanos: int, limit: int
) -> dict[str, Any]:
    return _get(
        f"{loki}/loki/api/v1/query_range",
        {
            "query": '{service_name="' + service + '"}',
            "start": str(start_nanos),
            "end": str(end_nanos),
            "limit": str(limit),
            "direction": "forward",
        },
    )


def _entry_count(response: dict[str, Any]) -> int:
    result = response.get("data", {}).get("result", [])
    return sum(len(stream.get("values", [])) for stream in result)


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture a real Loki query_range response.")
    parser.add_argument("--source", choices=("synthetic", "loghub"), default="synthetic")
    parser.add_argument("--system", default="OpenSSH", help="Loghub system, with --source loghub")
    parser.add_argument("--lines", type=int, default=400)
    parser.add_argument("--otlp", default=DEFAULT_OTLP)
    parser.add_argument("--loki", default=DEFAULT_LOKI)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--settle", type=float, default=6.0, help="seconds to wait before query")
    parser.add_argument(
        "--observed-time",
        dest="observed",
        default=None,
        action=argparse.BooleanOptionalAction,
        help="send observedTimeUnixNano; one stream per record when set, one stream total when "
        "not. Defaults to on for --source synthetic and off for --source loghub.",
    )
    args = parser.parse_args()
    observed = args.observed if args.observed is not None else args.source == "synthetic"

    # Timestamps are rebased onto the present. Loki rejects samples older than a week by
    # default and Loghub's are from 2015, so a capture keeping the original times would be a
    # capture of an empty result set. The rebase is a property of the transport, not of the
    # fixture: what the adapter reads is the shape, and the shape is unaffected.
    base_nanos = int((time.time() - 60) * 1_000_000_000)

    if args.source == "synthetic":
        service, records = _synthetic_records(base_nanos, args.lines, observed)
    else:
        service, records = _loghub_records(base_nanos, args.system, args.lines, observed)
    # Unique per run, so a re-capture never reads a previous run's leftovers back.
    service = f"{service}-{int(time.time())}"

    print(f"pushing {len(records)} records as service_name={service} -> {args.otlp}")
    _push(args.otlp, service, records)

    print(f"waiting {args.settle:.0f}s for the collector to flush into Loki")
    time.sleep(args.settle)

    end_nanos = int((time.time() + 60) * 1_000_000_000)
    response = _query_range(args.loki, service, base_nanos - 1_000_000_000, end_nanos, len(records))
    streams = len(response.get("data", {}).get("result", []))
    entries = _entry_count(response)
    print(f"captured {entries} entries across {streams} streams")
    if entries == 0:
        print("nothing came back -- is the collector routing logs to Loki?")
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    name = args.source if args.source == "synthetic" else f"loghub_{args.system.lower()}"
    capture = args.out / f"{name}_query_range.json"
    capture.write_text(json.dumps(response, indent=2), encoding="utf-8")

    # Provenance beside the capture, not inside it: a fixture carrying an extra key is no
    # longer the shape the store actually returns, which is the one thing it exists to keep.
    provenance = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": args.source,
        "system": args.system if args.source == "loghub" else None,
        "records_pushed": len(records),
        "entries_returned": entries,
        "streams_returned": streams,
        "otlp_endpoint": args.otlp,
        "loki_endpoint": args.loki,
        "query": '{service_name="' + service + '"}',
        "severity_sent": args.source == "synthetic",
        "observed_time_sent": observed,
    }
    (args.out / f"{name}_query_range.provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf-8"
    )
    print(f"wrote {capture}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

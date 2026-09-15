"""Deterministic synthetic incident used as ground truth from Phase 1 onward.

The scenario: a checkout service degrades over an hour. The planted root cause is database
connection pool exhaustion, preceded by a rising connection-acquisition latency warning.

Two properties are deliberate:

*   A **red herring** is planted alongside it - a payment-gateway timeout that occurs far
    more often than the root cause. A ranking heuristic that sorts on count alone picks the
    herring; one that sorts on severity first picks the real cause. That makes the Phase 1
    skeleton test discriminating rather than a formality, and it is the seed of the
    plausible-but-wrong eval set Phase 5 needs.
*   **PII is planted at known positions** - addresses, client IPs and an API token - so the
    redaction and stage-ordering tests can assert on exact values rather than on regex
    behaviour in the abstract.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

__all__ = [
    "FIXTURE_VERSION",
    "PLANTED_API_KEY",
    "PLANTED_EMAILS",
    "PLANTED_IPS",
    "RED_HERRING_MARKER",
    "ROOT_CAUSE_MARKER",
    "generate_incident",
    "generate_quiet_hour",
    "write_incident",
    "write_incident_otlp",
    "write_quiet_hour",
]

#: Bumped whenever a generator changes what it plants. Recorded with every eval result,
#: because a fixture that changes silently makes every historical score incomparable -- and
#: comparing two things that were not the same measurement is exactly how this project talked
#: itself into a regression that never happened.
FIXTURE_VERSION = 1

#: Substrings that identify the planted templates in a generated report.
ROOT_CAUSE_MARKER = "Database connection pool exhausted"
RED_HERRING_MARKER = "Payment gateway request timed out"

PLANTED_EMAILS = ("ana.silva@northwind-retail.com", "ops-oncall@northwind-retail.com")
PLANTED_IPS = ("10.42.7.19", "192.168.14.203", "172.16.0.88")
PLANTED_API_KEY = "sk_live_9f3ba71c4d2e8a06b5c1"

_SERVICES = ("checkout-service", "cart-service", "inventory-service", "payment-service")
_SKUS = ("SKU-4471", "SKU-1180", "SKU-9042", "SKU-2265", "SKU-7713")
_REGIONS = ("eu-west-1", "us-east-1", "ap-south-1")

_START = datetime(2026, 8, 30, 14, 0, 0, tzinfo=UTC)


def _line(
    ts: datetime,
    service: str,
    level: str,
    message: str,
    **fields: object,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "service": service,
        "level": level,
        "message": message,
        "trace_id": f"{random.getrandbits(64):016x}",
    }
    payload.update(fields)
    return payload


def generate_incident(total_lines: int = 5000, seed: int = 20260830) -> list[dict[str, object]]:
    """Build the incident as a list of JSON-serialisable records, ordered by time."""
    rng = random.Random(seed)
    random.seed(seed)

    records: list[dict[str, object]] = []

    # The incident window sits in the last third of the hour.
    onset = _START + timedelta(minutes=38)

    # --- background noise -------------------------------------------------
    noise_count = int(total_lines * 0.88)
    for _ in range(noise_count):
        ts = _START + timedelta(seconds=rng.uniform(0, 3600))
        service = rng.choice(_SERVICES)
        roll = rng.random()
        if roll < 0.55:
            records.append(
                _line(
                    ts,
                    service,
                    "INFO",
                    f"Handled GET /api/v2/catalog/{rng.choice(_SKUS)} in {rng.randint(4, 120)}ms",
                    client_ip=rng.choice(PLANTED_IPS),
                    region=rng.choice(_REGIONS),
                )
            )
        elif roll < 0.80:
            records.append(
                _line(
                    ts,
                    service,
                    "INFO",
                    f"Cache hit ratio {rng.uniform(0.72, 0.98):.2f} over "
                    f"{rng.randint(50, 400)} lookups",
                    region=rng.choice(_REGIONS),
                )
            )
        elif roll < 0.90:
            records.append(
                _line(
                    ts,
                    service,
                    "DEBUG",
                    f"Heartbeat ok, uptime {rng.randint(1000, 90000)}s",
                )
            )
        elif roll < 0.96:
            records.append(
                _line(
                    ts,
                    service,
                    "INFO",
                    f"Session opened for {rng.choice(PLANTED_EMAILS)} "
                    f"from {rng.choice(PLANTED_IPS)}",
                    user_email=rng.choice(PLANTED_EMAILS),
                )
            )
        else:
            records.append(
                _line(
                    ts,
                    service,
                    "WARN",
                    f"Retrying inventory sync for {rng.choice(_SKUS)}, attempt {rng.randint(2, 4)}",
                )
            )

    # --- red herring: frequent but non-fatal -------------------------------
    # Occurs throughout, and far more often than the real cause.
    for _ in range(int(total_lines * 0.07)):
        ts = _START + timedelta(seconds=rng.uniform(0, 3600))
        records.append(
            _line(
                ts,
                "payment-service",
                "ERROR",
                f"{RED_HERRING_MARKER} after {rng.randint(3000, 9000)}ms, "
                f"gateway {rng.choice(PLANTED_IPS)}",
                gateway_region=rng.choice(_REGIONS),
            )
        )

    # --- precursor: rising acquisition latency -----------------------------
    for _ in range(int(total_lines * 0.03)):
        ts = onset - timedelta(seconds=rng.uniform(0, 420))
        records.append(
            _line(
                ts,
                "checkout-service",
                "WARN",
                f"Connection acquisition took {rng.randint(900, 4800)}ms, "
                f"threshold {rng.choice((500, 750, 1000))}ms",
                pool="orders-primary",
            )
        )

    # --- planted root cause: rare but fatal --------------------------------
    for i in range(40):
        ts = onset + timedelta(seconds=i * 9 + rng.uniform(0, 4))
        records.append(
            _line(
                ts,
                "checkout-service",
                "FATAL",
                f"{ROOT_CAUSE_MARKER}: 0 of {rng.choice((40, 60, 80))} connections available",
                pool="orders-primary",
                waiters=rng.randint(12, 210),
            )
        )

    # A handful of lines carrying a secret, so redaction has something unambiguous to catch.
    for i in range(6):
        ts = onset + timedelta(seconds=i * 30)
        records.append(
            _line(
                ts,
                "checkout-service",
                "ERROR",
                f"Failed to refresh pool credentials, api_key={PLANTED_API_KEY} "
                f"endpoint {PLANTED_IPS[0]}",
                operator=PLANTED_EMAILS[1],
            )
        )

    records.sort(key=lambda r: str(r["timestamp"]))
    return records


def write_incident(path: str | Path, total_lines: int = 5000, seed: int = 20260830) -> Path:
    """Write the incident as JSON Lines and return the path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    records = generate_incident(total_lines=total_lines, seed=seed)
    with target.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
    return target


if __name__ == "__main__":  # pragma: no cover - manual fixture generation
    import sys

    destination = sys.argv[1] if len(sys.argv) > 1 else "examples/sample_incident.jsonl"
    written = write_incident(destination)
    print(f"wrote {written}")


# --------------------------------------------------------------- the quiet hour


def generate_quiet_hour(total_lines: int = 5000, seed: int = 20260901) -> list[dict[str, object]]:
    """An hour of healthy service, with nothing wrong in it.

    The negative control, and the one case the rest of the suite cannot cover: every other
    fixture asks whether the investigation finds the planted answer, and this one asks whether
    it invents one when there is no answer to find. An agent that always produces a confident
    root cause is useless in exactly the situation an on-call engineer most needs to trust it
    -- the page that turns out to be nothing.

    Built from the same background generator as the incident fixture, so the two differ in
    what was planted rather than in how they were written. Deliberately not *featureless*:
    there are WARNs, retries, and one slow request template, because a file with no variation
    at all would let a system pass by noticing there is only one kind of line. The point is
    that nothing here is severe, concentrated in time, or causally linked to anything else.
    """
    rng = random.Random(seed)
    random.seed(seed)

    records: list[dict[str, object]] = []
    for _ in range(total_lines):
        ts = _START + timedelta(seconds=rng.uniform(0, 3600))
        service = rng.choice(_SERVICES)
        roll = rng.random()
        if roll < 0.50:
            records.append(
                _line(
                    ts,
                    service,
                    "INFO",
                    f"Handled GET /api/v2/catalog/{rng.choice(_SKUS)} in {rng.randint(4, 120)}ms",
                    client_ip=rng.choice(PLANTED_IPS),
                    region=rng.choice(_REGIONS),
                )
            )
        elif roll < 0.72:
            records.append(
                _line(
                    ts,
                    service,
                    "INFO",
                    f"Cache hit ratio {rng.uniform(0.72, 0.98):.2f} over "
                    f"{rng.randint(50, 400)} lookups",
                    region=rng.choice(_REGIONS),
                )
            )
        elif roll < 0.84:
            records.append(
                _line(ts, service, "DEBUG", f"Heartbeat ok, uptime {rng.randint(1000, 90000)}s")
            )
        elif roll < 0.92:
            records.append(
                _line(
                    ts,
                    service,
                    "INFO",
                    f"Session opened for {rng.choice(PLANTED_EMAILS)} "
                    f"from {rng.choice(PLANTED_IPS)}",
                    user_email=rng.choice(PLANTED_EMAILS),
                )
            )
        elif roll < 0.97:
            # Retries happen in healthy systems. Present so that "there is a WARN here" cannot
            # by itself be read as an incident.
            records.append(
                _line(
                    ts,
                    service,
                    "WARN",
                    f"Retrying inventory sync for {rng.choice(_SKUS)}, attempt {rng.randint(2, 3)}",
                )
            )
        else:
            # Spread evenly across the hour and never severe: a slow request is a fact about a
            # busy service, not an outage.
            records.append(
                _line(
                    ts,
                    service,
                    "WARN",
                    f"Slow response {rng.randint(900, 2400)}ms for /api/v2/search, "
                    f"budget {rng.choice((800, 1200))}ms",
                )
            )

    records.sort(key=lambda r: str(r["timestamp"]))
    return records


def write_quiet_hour(path: str | Path, total_lines: int = 5000, seed: int = 20260901) -> Path:
    """Write the quiet hour as JSON Lines and return the path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for record in generate_quiet_hour(total_lines=total_lines, seed=seed):
            handle.write(json.dumps(record) + "\n")
    return target


# ------------------------------------------------------------------ OTLP export

#: severityNumber for each level this fixture emits. The OTLP logs data model assigns four
#: numbers per level; the middle of each band is used so the fixture is not accidentally
#: testing the boundaries the adapter's own tests already cover.
_OTLP_SEVERITY = {"DEBUG": 5, "INFO": 9, "WARN": 13, "ERROR": 17, "FATAL": 21}


def _otlp_record(record: dict[str, object]) -> dict[str, object]:
    """One generated line as an OTLP `LogRecord`."""
    ts = datetime.fromisoformat(str(record["timestamp"]).replace("Z", "+00:00"))
    level = str(record["level"])
    attributes = [
        {"key": key, "value": {"stringValue": str(value)}}
        for key, value in record.items()
        if key not in {"timestamp", "service", "level", "message", "trace_id"}
    ]
    return {
        # int64 as a string, per the protobuf-JSON mapping: JSON cannot hold nanoseconds
        # exactly as a number, and an exporter that emits one is out of spec.
        "timeUnixNano": str(int(ts.timestamp() * 1_000_000_000)),
        "observedTimeUnixNano": str(int(ts.timestamp() * 1_000_000_000)),
        "severityNumber": _OTLP_SEVERITY.get(level, 9),
        "severityText": level,
        "body": {"stringValue": str(record["message"])},
        "attributes": attributes,
        "traceId": str(record["trace_id"]),
    }


def write_incident_otlp(path: str | Path, total_lines: int = 5000, seed: int = 20260830) -> Path:
    """The same incident, exported as line-delimited OTLP logs.

    Deliberately the *same* generator as `write_incident`. The eval case built on this asks one
    question -- does an investigation reach the same conclusion when the format changes -- and
    it can only ask that if the incident underneath is identical. A separate OTLP scenario would
    have measured two things at once and attributed the difference to whichever was convenient.

    One export request per service per batch, because that is what a collector emits: records
    are grouped by resource, and an adapter that only ever sees one resource per request has
    not been tested against the shape it will actually meet.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    records = generate_incident(total_lines=total_lines, seed=seed)

    # Batched by service in time order, so each request carries one resource and the file
    # preserves the incident's ordering.
    batches: list[tuple[str, list[dict[str, object]]]] = []
    for record in records:
        service = str(record["service"])
        if not batches or batches[-1][0] != service or len(batches[-1][1]) >= 50:
            batches.append((service, []))
        batches[-1][1].append(record)

    with target.open("w", encoding="utf-8") as handle:
        for service, batch in batches:
            request = {
                "resourceLogs": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": service}}
                            ]
                        },
                        "scopeLogs": [
                            {
                                "scope": {"name": "mistify.fixture", "version": "1"},
                                "logRecords": [_otlp_record(r) for r in batch],
                            }
                        ],
                    }
                ]
            }
            handle.write(json.dumps(request) + "\n")
    return target

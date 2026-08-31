"""Deterministic synthetic incident used as ground truth from Phase 1 onward.

The scenario: a checkout service degrades over an hour. The planted root cause is database
connection pool exhaustion, preceded by a rising connection-acquisition latency warning.

Two properties are deliberate:

*   A **red herring** is planted alongside it — a payment-gateway timeout that occurs far
    more often than the root cause. A ranking heuristic that sorts on count alone picks the
    herring; one that sorts on severity first picks the real cause. That makes the Phase 1
    skeleton test discriminating rather than a formality, and it is the seed of the
    plausible-but-wrong eval set Phase 5 needs.
*   **PII is planted at known positions** — addresses, client IPs and an API token — so the
    redaction and stage-ordering tests can assert on exact values rather than on regex
    behaviour in the abstract.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

__all__ = [
    "PLANTED_API_KEY",
    "PLANTED_EMAILS",
    "PLANTED_IPS",
    "RED_HERRING_MARKER",
    "ROOT_CAUSE_MARKER",
    "generate_incident",
    "write_incident",
]

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

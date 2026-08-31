"""Redaction entity detection, hash consistency, and false-positive resistance."""

from __future__ import annotations

import pytest

from mistify.common.models import LogRecord, parse_timestamp
from mistify.redaction.patterns import PATTERNS, SUPPORTED_ENTITIES
from mistify.redaction.redactor import Redactor


def _record(raw: str, message: str | None = None, **fields: object) -> LogRecord:
    return LogRecord(
        ts=parse_timestamp("2026-08-30T14:22:01Z"),
        source="checkout-service",
        severity="ERROR",
        raw=raw,
        message=message if message is not None else raw,
        fields=dict(fields),
        format="json_lines",
    )


# --------------------------------------------------------------- detection


def test_email_is_redacted() -> None:
    out = Redactor().redact("Session opened for ana.silva@northwind-retail.com")
    assert "ana.silva@northwind-retail.com" not in out
    assert "[EMAIL:" in out


def test_ipv4_is_redacted() -> None:
    out = Redactor().redact("upstream 10.42.7.19 refused connection")
    assert "10.42.7.19" not in out
    assert "[IPV4:" in out


def test_api_key_is_redacted_but_key_name_survives() -> None:
    """The log should still say what was redacted, so the line stays diagnostic."""
    out = Redactor().redact("refresh failed api_key=sk_live_9f3ba71c4d2e8a06b5c1")
    assert "sk_live_9f3ba71c4d2e8a06b5c1" not in out
    assert "api_key=" in out
    assert "[API_KEY:" in out


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer abcdefghijklmnop0123456789",
        "access_token: tok_abcdefghijklmnopqrstuvwx",
        "AUTH_TOKEN = QQQQwwww1111eeeeRRRRttttYYYY",
    ],
)
def test_token_variants_are_redacted(text: str) -> None:
    out = Redactor().redact(text)
    assert "[API_KEY:" in out


# --------------------------------------------------------------- consistency


def test_same_value_yields_same_token_across_lines() -> None:
    """Correlation must survive redaction, or the investigator loses the join key."""
    redactor = Redactor()
    first = redactor.redact("login from 10.42.7.19")
    second = redactor.redact("timeout talking to 10.42.7.19")
    token = first.split("login from ")[1]
    assert token in second


def test_different_values_yield_different_tokens() -> None:
    redactor = Redactor()
    out = redactor.redact("hop 10.42.7.19 then 192.168.14.203")
    tokens = {part for part in out.split() if part.startswith("[IPV4:")}
    assert len(tokens) == 2


def test_token_is_stable_between_raw_and_structured_fields() -> None:
    """The same address in the message and in a field must produce the same token."""
    redactor = Redactor()
    record = redactor.redact_record(_record("client 10.42.7.19 failed", client_ip="10.42.7.19"))
    token = record.fields["client_ip"]
    assert token.startswith("[IPV4:")
    assert token in record.raw


def test_salt_changes_the_token() -> None:
    plain = Redactor().redact("10.42.7.19")
    salted = Redactor(salt="pepper").redact("10.42.7.19")
    assert plain != salted


# --------------------------------------------------------------- coverage


def test_structured_fields_are_redacted_recursively() -> None:
    """JSON logs routinely carry the address in a nested field and never in the message."""
    redactor = Redactor()
    record = redactor.redact_record(
        _record(
            "checkout failed",
            user={"email": "ana.silva@northwind-retail.com", "ips": ["10.42.7.19"]},
            attempt=3,
        )
    )
    assert record.fields["user"]["email"].startswith("[EMAIL:")
    assert record.fields["user"]["ips"][0].startswith("[IPV4:")
    assert record.fields["attempt"] == 3


def test_counts_are_reported_for_health_metrics() -> None:
    redactor = Redactor()
    redactor.redact("a@b.com and c@d.com from 10.0.0.1")
    assert redactor.counts == {"email": 2, "ipv4": 1}


def test_mode_off_is_a_no_op() -> None:
    redactor = Redactor(mode="off")
    text = "ana.silva@northwind-retail.com from 10.42.7.19"
    assert redactor.redact(text) == text
    assert redactor.counts == {}


def test_only_configured_entities_are_redacted() -> None:
    redactor = Redactor(entities=["ipv4"])
    out = redactor.redact("ana.silva@northwind-retail.com at 10.42.7.19")
    assert "ana.silva@northwind-retail.com" in out
    assert "10.42.7.19" not in out


# --------------------------------------------------------------- false positives


@pytest.mark.parametrize(
    "text",
    [
        "request_id 1772461321000 completed",
        "order 4539578763621486 reconciled",
        "span 8a7f2b1c9d0e4f36 closed",
        "retry budget 1234567890123456 exhausted",
    ],
)
def test_long_digit_runs_are_not_redacted(text: str) -> None:
    """Decision G5: no credit-card pattern in v1, so identifiers survive intact."""
    assert Redactor().redact(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "upgraded to version 1.2.3.4-rc1",
        "checksum 999.888.777.666 mismatch",
        "error code E404 returned",
        "latency 1.5.2.9.1 buckets",
    ],
)
def test_version_and_code_strings_are_not_mistaken_for_addresses(text: str) -> None:
    assert Redactor().redact(text) == text


def test_valid_address_at_string_boundaries_is_still_caught() -> None:
    assert Redactor().redact("10.42.7.19") == Redactor().redact("10.42.7.19")
    assert "[IPV4:" in Redactor().redact("10.42.7.19")


# --------------------------------------------------------------- configuration


def test_credit_card_pattern_is_absent() -> None:
    """Decision G5: explicitly out of scope for v1."""
    assert "credit_card" not in PATTERNS
    assert "credit_card" not in SUPPORTED_ENTITIES


def test_unknown_entity_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown redaction entities"):
        Redactor(entities=["email", "retina_scan"])


def test_unknown_mode_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown redaction mode"):
        Redactor(mode="occasionally")


def test_version_guard_does_not_suppress_a_real_address() -> None:
    """Guards the guard: the context rule must not blanket-disable ipv4 redaction."""
    out = Redactor().redact("service v2 talking to 10.42.7.19 failed")
    assert "10.42.7.19" not in out
    assert "[IPV4:" in out


def test_version_guard_is_context_scoped() -> None:
    redactor = Redactor()
    out = redactor.redact("upgraded to version 1.2.3.4 then called 1.2.3.4")
    assert out.count("1.2.3.4") == 1
    assert "[IPV4:" in out

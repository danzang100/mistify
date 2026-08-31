"""Redaction entity detection, hash consistency, and false-positive resistance."""

from __future__ import annotations

import re

import pytest

from mistify.common.models import LogRecord, parse_timestamp
from mistify.redaction.patterns import (
    DEFAULT_ENTITIES,
    ENTITY_ORDER,
    PATTERNS,
    SUPPORTED_ENTITIES,
)
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


# --------------------------------------------------------- ipv6 detection


@pytest.mark.parametrize(
    "address",
    [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fe80::1",
        "::1",
        "::",
        "2001:db8::8a2e:370:7334",
    ],
)
def test_ipv6_addresses_are_redacted(address: str) -> None:
    """Both accepted shapes: the full eight-group form and anything containing `::`."""
    out = Redactor().redact(f"peer {address} unreachable")
    assert address not in out
    assert "[IPV6:" in out


def test_ipv6_placeholder_has_the_expected_shape() -> None:
    assert re.fullmatch(r"\[IPV6:[0-9a-f]{4}\]", Redactor().redact("fe80::1"))


def test_ipv6_is_redacted_in_structured_fields() -> None:
    redactor = Redactor()
    record = redactor.redact_record(_record("peer down", peer={"addr": "fe80::1"}))
    assert record.fields["peer"]["addr"].startswith("[IPV6:")


# --------------------------------------------------- ipv6 false positives


@pytest.mark.parametrize(
    "text",
    [
        "14:22:01",
        "2026-08-30T14:22:01Z",
        "elapsed 01:30:45",
        "at 9:05:33.221",
        "took 00:00:02",
        "cache 1:2:3",
        "sha 3f2a:9b1c",
    ],
)
def test_clock_times_are_not_mistaken_for_addresses(text: str) -> None:
    """The critical regression: a timestamp eaten by the address pattern misaligns every
    downstream time slice, so colon-separated clock values must survive untouched."""
    assert Redactor().redact(text) == text


def test_timestamp_survives_alongside_a_real_address_on_the_same_line() -> None:
    """Guards the guard: keeping clock times out must not disable ipv6 detection."""
    out = Redactor().redact("2026-08-30T14:22:01Z peer fe80::1 down after 00:00:02")
    assert "fe80::1" not in out
    assert "[IPV6:" in out
    assert "2026-08-30T14:22:01Z" in out
    assert "00:00:02" in out


# ---------------------------------------------------------- ssn detection


def test_ssn_is_redacted() -> None:
    out = Redactor().redact("claim filed for 123-45-6789 yesterday")
    assert "123-45-6789" not in out
    assert "[SSN:" in out


def test_ssn_placeholder_has_the_expected_shape() -> None:
    assert re.fullmatch(r"\[SSN:[0-9a-f]{4}\]", Redactor().redact("123-45-6789"))


@pytest.mark.parametrize(
    "text",
    [
        "id 123456789 ok",
        "request_id 1772461321000 completed",
        "acct 12-345-6789 reopened",
        "batch 1234-56-7890 queued",
        "ref 123-45-67890 rejected",
        "ref 0123-45-6789 rejected",
    ],
)
def test_bare_digit_runs_are_not_mistaken_for_ssns(text: str) -> None:
    """Dashes in the 3-2-4 shape are required -- a bare nine-digit run is the credit-card
    mistake again, and it would shred epoch-millisecond identifiers (decision G5)."""
    assert Redactor().redact(text) == text


# -------------------------------------------------------- phone detection


@pytest.mark.parametrize(
    "number",
    [
        "+1 555 123 4567",
        "(555) 123-4567",
        "555-123-4567",
        "+44 555.123.4567",
    ],
)
def test_phone_numbers_are_redacted_when_explicitly_enabled(number: str) -> None:
    out = Redactor(entities=["phone"]).redact(f"callback to {number} scheduled")
    assert number not in out
    assert "[PHONE:" in out


def test_phone_placeholder_has_the_expected_shape() -> None:
    assert re.fullmatch(
        r"\[PHONE:[0-9a-f]{4}\]", Redactor(entities=["phone"]).redact("555-123-4567")
    )


def test_phone_has_a_known_false_positive_on_numeric_ranges() -> None:
    """Documents a known limitation rather than asserting correctness.

    `100-200-3000` is a dashed numeric range, not a number to call, but it is structurally
    identical to `NNN-NNN-NNNN` and unlike a card number a phone number carries no checksum
    to tell the two apart. This unfixable collision is precisely why `phone` ships off by
    default: a deployment that actually logs phone numbers opts in and accepts the cost.
    """
    redactor = Redactor(entities=["phone"])
    out = redactor.redact("sharding rows 100-200-3000 across replicas")
    assert "100-200-3000" not in out
    assert "[PHONE:" in out
    assert redactor.counts == {"phone": 1}


# ----------------------------------------------- new-entity consistency


def test_ipv6_value_yields_the_same_token_across_lines() -> None:
    redactor = Redactor()
    first = redactor.redact("session opened from fe80::1")
    second = redactor.redact("session closed from fe80::1")
    token = first.split("from ")[1]
    assert token.startswith("[IPV6:")
    assert token in second


def test_different_ipv6_values_yield_different_tokens() -> None:
    out = Redactor().redact("hop fe80::1 then 2001:db8::1")
    tokens = {part for part in out.split() if part.startswith("[IPV6:")}
    assert len(tokens) == 2


def test_ssn_value_yields_the_same_token_across_lines() -> None:
    redactor = Redactor()
    first = redactor.redact("lookup 123-45-6789 started")
    second = redactor.redact("lookup 123-45-6789 finished")
    token = first.split("lookup ")[1].split(" ")[0]
    assert token.startswith("[SSN:")
    assert token in second


def test_phone_value_yields_the_same_token_across_lines() -> None:
    redactor = Redactor(entities=["phone"])
    first = redactor.redact("dialled 555-123-4567 once")
    second = redactor.redact("dialled 555-123-4567 twice")
    token = first.split("dialled ")[1].split(" ")[0]
    assert token.startswith("[PHONE:")
    assert token in second


def test_counts_cover_the_new_entities() -> None:
    redactor = Redactor()
    redactor.redact("peer fe80::1 ssn 123-45-6789 host 10.0.0.1")
    assert redactor.counts == {"ipv6": 1, "ssn": 1, "ipv4": 1}


# ------------------------------------------------ new-entity configuration


def test_default_entities_exclude_phone() -> None:
    """Decision G5, one step milder than credit_card: available, but opt-in."""
    assert "phone" not in DEFAULT_ENTITIES
    assert "phone" in SUPPORTED_ENTITIES
    assert "phone" in PATTERNS


def test_default_entities_include_the_new_ipv6_and_ssn_patterns() -> None:
    assert DEFAULT_ENTITIES == ("api_key", "email", "ipv6", "ipv4", "ssn")


@pytest.mark.parametrize(
    "number",
    [
        "+1 555 123 4567",
        "(555) 123-4567",
        "555-123-4567",
        "+44 555.123.4567",
    ],
)
def test_phone_survives_the_default_entity_set(number: str) -> None:
    """The shipped default config enables `DEFAULT_ENTITIES`, which leaves phone alone."""
    redactor = Redactor(entities=list(DEFAULT_ENTITIES))
    text = f"callback to {number} scheduled"
    assert redactor.redact(text) == text
    assert redactor.counts == {}


def test_bare_redactor_falls_back_to_defaults_not_every_pattern() -> None:
    """The opt-in guarantee must hold at the library level, not only via config.

    Falling back to the whole pattern library opted any direct `Redactor()` caller into
    `phone`, and with it the `100-200-3000` collision, without them ever asking for it.
    """
    assert Redactor().entities == [e for e in ENTITY_ORDER if e in DEFAULT_ENTITIES]
    assert "phone" not in Redactor().entities
    assert Redactor().redact("call 555-123-4567") == "call 555-123-4567"

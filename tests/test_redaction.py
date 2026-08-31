"""Redaction entity detection, hash consistency, and false-positive resistance.

Organised property-first: `ENTITY_CASES` lists one sample per supported entity and the block
below it asserts the properties every entity must hold, once each. A seventh entity is then a
row in that table, not a new section.

What deliberately stays outside the table is the false-positive corpora further down. Those
are regression tests for specific bugs (decision G5 and the clock-time collision), not
examples of a shared property -- collapsing them would trade a documented bug for a smaller
file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import pytest

from mistify.common.models import LogRecord, parse_timestamp
from mistify.redaction.patterns import (
    DEFAULT_ENTITIES,
    ENTITY_ORDER,
    PATTERNS,
    SUPPORTED_ENTITIES,
    placeholder_pattern,
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


# --------------------------------------------------------------- entity table


@dataclass(frozen=True)
class EntityCase:
    """One entity's worth of evidence for the shared property tests."""

    entity: str
    sample: str
    value: str
    other: str
    on_by_default: bool


ENTITY_CASES: tuple[EntityCase, ...] = (
    EntityCase(
        entity="api_key",
        sample="refresh failed api_key=sk_live_9f3ba71c4d2e8a06b5c1",
        value="sk_live_9f3ba71c4d2e8a06b5c1",
        other="sk_live_0c1d2e3f4a5b6c7d8e9f",
        on_by_default=True,
    ),
    EntityCase(
        entity="email",
        sample="session opened for ana.silva@northwind-retail.com",
        value="ana.silva@northwind-retail.com",
        other="bruno.costa@northwind-retail.com",
        on_by_default=True,
    ),
    EntityCase(
        entity="ipv6",
        sample="peer fe80::1 unreachable",
        value="fe80::1",
        other="2001:db8::1",
        on_by_default=True,
    ),
    EntityCase(
        entity="ipv4",
        sample="upstream 10.42.7.19 refused connection",
        value="10.42.7.19",
        other="192.168.14.203",
        on_by_default=True,
    ),
    EntityCase(
        entity="ssn",
        sample="claim filed for 123-45-6789 yesterday",
        value="123-45-6789",
        other="987-65-4321",
        on_by_default=True,
    ),
    EntityCase(
        entity="phone",
        sample="callback to 555-123-4567 scheduled",
        value="555-123-4567",
        other="555-987-6543",
        on_by_default=False,
    ),
)

_BRACKETED = re.compile(r"\[[^\[\]]*\]")


def _redactor(case: EntityCase, mode: str = "strict") -> Redactor:
    """A redactor with the case's entity enabled alongside the shipped defaults.

    Enabling the entity next to the default set rather than alone keeps the interaction
    visible: patterns run in `ENTITY_ORDER` and an earlier one can swallow a later one's
    value, which a single-entity redactor would never show.
    """
    entities = [e for e in ENTITY_ORDER if e in DEFAULT_ENTITIES or e == case.entity]
    return Redactor(mode=mode, entities=entities)


def _tokens(text: str, entity: str) -> list[str]:
    return re.findall(rf"\[{entity.upper()}:[0-9a-f]{{4}}\]", text)


def _by_entity(case: EntityCase) -> str:
    return case.entity


# -------------------------------------------------- properties of every entity


def test_every_supported_entity_has_a_table_row() -> None:
    """The table is only a substitute for per-entity sections while it stays complete: a
    pattern with no row would silently hold none of the properties below."""
    assert {case.entity for case in ENTITY_CASES} == SUPPORTED_ENTITIES


@pytest.mark.parametrize("case", ENTITY_CASES, ids=_by_entity)
def test_value_is_replaced_by_a_placeholder(case: EntityCase) -> None:
    out = _redactor(case).redact(case.sample)
    assert case.value not in out
    assert f"[{case.entity.upper()}:" in out


@pytest.mark.parametrize("case", ENTITY_CASES, ids=_by_entity)
def test_placeholder_has_the_documented_shape(case: EntityCase) -> None:
    """The templater masks `placeholder_pattern()`, so a placeholder off that shape would
    leak one template per distinct source value instead of collapsing into one."""
    out = _redactor(case).redact(case.sample)
    emitted = _BRACKETED.findall(out)
    assert len(emitted) == 1
    assert re.fullmatch(r"\[[A-Z0-9_]+:[0-9a-f]{4}\]", emitted[0])
    assert re.fullmatch(placeholder_pattern(), emitted[0])


@pytest.mark.parametrize("case", ENTITY_CASES, ids=_by_entity)
def test_same_value_yields_the_same_placeholder(case: EntityCase) -> None:
    """Correlation must survive redaction, or the investigator loses the join key."""
    redactor = _redactor(case)
    first = _tokens(redactor.redact(f"first call, {case.sample}"), case.entity)
    second = _tokens(redactor.redact(f"second call, {case.sample}"), case.entity)
    assert first == second != []


@pytest.mark.parametrize("case", ENTITY_CASES, ids=_by_entity)
def test_different_values_yield_different_placeholders(case: EntityCase) -> None:
    other_sample = case.sample.replace(case.value, case.other)
    out = _redactor(case).redact(f"{case.sample} then {other_sample}")
    assert len(set(_tokens(out, case.entity))) == 2


@pytest.mark.parametrize("case", ENTITY_CASES, ids=_by_entity)
def test_entity_is_redacted_inside_nested_fields(case: EntityCase) -> None:
    """JSON logs routinely carry the value in a nested field and never in the message."""
    record = _redactor(case).redact_record(
        _record("checkout failed", user={"trace": [case.sample]}, attempt=3)
    )
    nested = record.fields["user"]["trace"][0]
    assert case.value not in nested
    assert f"[{case.entity.upper()}:" in nested
    assert record.fields["attempt"] == 3


@pytest.mark.parametrize("case", ENTITY_CASES, ids=_by_entity)
def test_mode_off_is_a_no_op(case: EntityCase) -> None:
    redactor = _redactor(case, mode="off")
    assert redactor.redact(case.sample) == case.sample
    assert redactor.counts == {}


@pytest.mark.parametrize("case", ENTITY_CASES, ids=_by_entity)
def test_default_entity_membership_matches_the_table(case: EntityCase) -> None:
    assert (case.entity in DEFAULT_ENTITIES) is case.on_by_default


# ------------------------------------------------- per-pattern shape coverage


def test_api_key_is_redacted_but_key_name_survives() -> None:
    """The log should still say what was redacted, so the line stays diagnostic.

    Kept out of the entity table because this is the named-group branch of the redactor:
    only part of the match is swapped, unlike every other entity.
    """
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


def test_valid_address_at_string_boundaries_is_still_caught() -> None:
    assert Redactor().redact("10.42.7.19") == Redactor().redact("10.42.7.19")
    assert "[IPV4:" in Redactor().redact("10.42.7.19")


# ------------------------------------------------------ correlation and counts


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


@pytest.mark.parametrize(
    "text, expected",
    [
        ("a@b.com and c@d.com from 10.0.0.1", {"email": 2, "ipv4": 1}),
        ("peer fe80::1 ssn 123-45-6789 host 10.0.0.1", {"ipv6": 1, "ssn": 1, "ipv4": 1}),
    ],
)
def test_counts_are_reported_for_health_metrics(text: str, expected: dict[str, int]) -> None:
    redactor = Redactor()
    redactor.redact(text)
    assert redactor.counts == expected


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


# ----------------------------------------------------------------- configuration


def test_credit_card_pattern_is_absent() -> None:
    """Decision G5: explicitly out of scope for v1."""
    assert "credit_card" not in PATTERNS
    assert "credit_card" not in SUPPORTED_ENTITIES


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


def test_unknown_entity_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown redaction entities"):
        Redactor(entities=["email", "retina_scan"])


def test_unknown_mode_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown redaction mode"):
        Redactor(mode="occasionally")

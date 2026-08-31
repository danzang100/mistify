"""Regex library for secret and PII detection.

Patterns are applied in the declared order, so entities whose matches can contain another
entity come first (an API key assignment may embed something email-shaped; redacting the key
first keeps the inner value from being tokenized twice).

Scope note: `credit_card` is deliberately absent. The pattern proposed for it in the v1
scaffolding matched any 13-16 digit run, which shreds epoch-millisecond timestamps, request
IDs and trace IDs -- the correlation keys an investigation depends on. It is out of scope for
v1 (decision G5); if it returns it needs a Luhn checksum and the false-positive corpus.

`phone` is implemented but off by default for the same reason, one step milder: the canonical
`NNN-NNN-NNNN` shape is structurally identical to a numeric identifier or a range, and unlike
a card number it carries no checksum to disambiguate. Tightening it to require a `+` country
code or parenthesised area code would miss the most common written form, so the honest choice
is to leave it available and let a deployment that actually logs phone numbers turn it on.
"""

from __future__ import annotations

import re

__all__ = [
    "CONTEXT_GUARDS",
    "DEFAULT_ENTITIES",
    "ENTITY_ORDER",
    "PATTERNS",
    "SUPPORTED_ENTITIES",
    "placeholder_pattern",
]

#: Order matters -- see module docstring. Longer/structured entities precede the ones whose
#: matches could otherwise be found inside them.
ENTITY_ORDER: tuple[str, ...] = ("api_key", "email", "ipv6", "ipv4", "ssn", "phone")

PATTERNS: dict[str, re.Pattern[str]] = {
    # Key/token assignments: capture the value, keep the key name visible so the log still
    # says *what* was redacted.
    "api_key": re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|bearer|token)"
        r"(\s*[:=]\s*|\s+)"
        r"(?P<value>[A-Za-z0-9_\-\.]{16,})"
    ),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]*[A-Za-z]\b"),
    # Full eight-group form, or any form containing "::". Requiring one of those two shapes
    # is what keeps clock times out: "14:22:01" has colons but neither eight groups nor a
    # double colon, and a timestamp swallowed by the address pattern would misalign every
    # time slice downstream.
    "ipv6": re.compile(
        r"(?<![\w:.])(?:"
        r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
        r"|::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
        r")(?![\w:.])"
    ),
    # Bounded by non-digit/non-dot so version strings like 1.2.3.4-rc and longer dotted
    # sequences are not mistaken for addresses.
    "ipv4": re.compile(
        r"(?<![\d.])"
        r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"(?![\d.])"
    ),
    # Dashes are required. A bare nine-digit run is the credit-card mistake again.
    "ssn": re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])"),
    # Off by default -- see module docstring.
    "phone": re.compile(
        r"(?<![\d.\-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)[ .-]?|\d{3}[ .-])"
        r"\d{3}[ .-]\d{4}(?![\d.\-])"
    ),
}

SUPPORTED_ENTITIES: frozenset[str] = frozenset(PATTERNS)

#: Entities enabled unless a config says otherwise. Everything here survives the
#: false-positive corpus in `tests/test_redaction.py` with no known collisions.
DEFAULT_ENTITIES: tuple[str, ...] = ("api_key", "email", "ipv6", "ipv4", "ssn")

#: Per-entity context guards, matched against the text immediately preceding a candidate.
#: A hit means the match is a false positive and is left alone.
#:
#: `1.2.3.4` is a perfectly valid address shape, so no amount of tightening the ipv4 regex
#: distinguishes an address from a four-part version number -- only the surrounding words do.
#: Redacting a version string would destroy a diagnostic value, which is the over-reach
#: failure mode this library is meant to avoid.
CONTEXT_GUARDS: dict[str, re.Pattern[str]] = {
    "ipv4": re.compile(r"(?i)\b(?:v|ver|version|release|build|rev|schema)\.?\s*$"),
}


def placeholder_pattern() -> str:
    """Regex matching any redaction placeholder this module emits.

    The templater masks this shape so a redacted value contributes one stable token to a
    template instead of one distinct token per distinct source value.
    """
    return r"\[[A-Z0-9_]+:[0-9a-f]+\]"

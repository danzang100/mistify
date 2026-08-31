"""Regex library for secret and PII detection.

Patterns are applied in the declared order, so entities whose matches can contain another
entity come first (an API key assignment may embed something email-shaped; redacting the key
first keeps the inner value from being tokenized twice).

Scope note: `credit_card` is deliberately absent. The pattern proposed for it in the v1
scaffolding matched any 13-16 digit run, which shreds epoch-millisecond timestamps, request
IDs and trace IDs -- the correlation keys an investigation depends on. It is out of scope for
v1 (decision G5); if it returns it needs a Luhn checksum and the false-positive corpus.
"""

from __future__ import annotations

import re

__all__ = ["ENTITY_ORDER", "PATTERNS", "SUPPORTED_ENTITIES", "placeholder_pattern"]

#: Order matters -- see module docstring.
ENTITY_ORDER: tuple[str, ...] = ("api_key", "email", "ipv4")

PATTERNS: dict[str, re.Pattern[str]] = {
    # Key/token assignments: capture the value, keep the key name visible so the log still
    # says *what* was redacted.
    "api_key": re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|bearer|token)"
        r"(\s*[:=]\s*|\s+)"
        r"(?P<value>[A-Za-z0-9_\-\.]{16,})"
    ),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]*[A-Za-z]\b"),
    # Bounded by non-digit/non-dot so version strings like 1.2.3.4-rc and longer dotted
    # sequences are not mistaken for addresses.
    "ipv4": re.compile(
        r"(?<![\d.])"
        r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"(?![\d.])"
    ),
}

SUPPORTED_ENTITIES: frozenset[str] = frozenset(PATTERNS)

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

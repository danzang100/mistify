"""Hash-and-replace redaction engine.

Runs immediately after adapter `parse()` and before every other stage -- templating, the
Drain3 snapshot, the scratchpad, and any model call. Placing it here
rather than after templating is what makes the "nothing unredacted reaches a model or lands
on disk" guarantee true for the unknown-format path as well as the registered-adapter path.

The same source value always yields the same placeholder within a run, so an investigator can
still correlate "this address appears in these fourteen lines" without ever seeing the value.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import replace
from typing import Any

from mistify.common.models import LogRecord
from mistify.redaction.patterns import (
    CONTEXT_GUARDS,
    DEFAULT_ENTITIES,
    ENTITY_ORDER,
    PATTERNS,
)
from mistify.redaction.vault import RedactionVault

__all__ = ["Redactor"]

#: Hex characters in a placeholder. Eight is 32 bits per entity. Four was 16, which sounds
#: like a lot until the birthday bound is worked out: a one-in-two chance of two *different*
#: values sharing a placeholder by ~300 distinct values, and on a log with 5,000 distinct
#: client addresses roughly 190 merged pairs -- clients the investigator would follow as one.
#: At eight, 5,000 values collide with probability ~0.3%.
_HASH_LENGTH = 8


class Redactor:
    """Replaces detected entities with stable `[ENTITY:hash]` placeholders."""

    def __init__(
        self,
        mode: str = "strict",
        entities: list[str] | None = None,
        salt: str = "",
        vault: RedactionVault | None = None,
    ):
        if mode not in {"strict", "off"}:
            raise ValueError(f"unknown redaction mode: {mode!r}")
        self.mode = mode
        self.salt = salt
        # A side-channel, never an input. Redaction output is byte-for-byte identical with a
        # vault attached and without one -- if the vault could change what the log looks
        # like, enabling it would silently change every downstream template and token.
        self.vault = vault
        # Falls back to DEFAULT_ENTITIES, not to every pattern in the library. Opting a
        # caller into `phone` -- and its known collision with numeric identifiers -- simply
        # because they did not name a list would make the opt-in guarantee in
        # `redaction/patterns.py` hold only for callers that route through config.
        requested = list(DEFAULT_ENTITIES) if entities is None else list(entities)
        unknown = sorted(set(requested) - set(PATTERNS))
        if unknown:
            raise ValueError(f"unknown redaction entities: {', '.join(unknown)}")
        # Preserve the declared precedence regardless of the order the caller listed them.
        self.entities: list[str] = [e for e in ENTITY_ORDER if e in requested]
        self._counts: Counter[str] = Counter()

    @property
    def enabled(self) -> bool:
        return self.mode != "off" and bool(self.entities)

    @property
    def counts(self) -> dict[str, int]:
        """Redactions performed per entity, for the run's health metrics."""
        return dict(self._counts)

    def merge_counts(self, counts: dict[str, int]) -> None:
        """Fold another redactor's tally into this one.

        For the worker processes in `redaction.parallel`. Each keeps its own counts and exits;
        without this the health metrics would report whatever the parent happened to redact
        itself, which on a parallel run is nothing at all.
        """
        self._counts.update(counts)

    def reset_counts(self) -> None:
        """Clear the tally.

        Used when a redactor is reused across a preparatory pass and the real load -- the
        preparatory redactions are not part of the run being reported on, and leaving them in
        would inflate the health metric.
        """
        self._counts.clear()

    def _token(self, entity: str, value: str) -> str:
        digest = hashlib.blake2s(
            f"{self.salt}:{entity}:{value}".encode(), digest_size=8
        ).hexdigest()[:_HASH_LENGTH]
        return f"[{entity.upper()}:{digest}]"

    def _token_and_record(self, entity: str, value: str) -> str:
        """Build the placeholder and, when a vault is attached, remember what it replaced.

        Every replacement goes through here so the vault cannot drift out of step with the
        placeholders actually emitted -- a mapping that covers only some branches is worse
        than none, because a missing token looks identical to a value that was never logged.
        """
        token = self._token(entity, value)
        if self.vault is not None:
            self.vault.record(token, entity, value)
        return token

    def redact(self, text: str) -> str:
        """Redact every configured entity in `text`."""
        if not self.enabled or not text:
            return text

        for entity in self.entities:
            pattern = PATTERNS[entity]
            guard = CONTEXT_GUARDS.get(entity)

            def _replace(
                match: re.Match[str],
                _entity: str = entity,
                _guard: re.Pattern[str] | None = guard,
            ) -> str:
                if _guard is not None and _guard.search(match.string[: match.start()]):
                    # Preceding context marks this as a false positive (e.g. a version
                    # string). Leave the value intact rather than destroy a diagnostic.
                    return match.group(0)
                groups = match.groupdict()
                if "value" in groups and groups["value"] is not None:
                    # Keep the surrounding key name; swap only the secret itself.
                    value = groups["value"]
                    self._counts[_entity] += 1
                    start, end = match.span("value")
                    return (
                        match.group(0)[: start - match.start()]
                        + self._token_and_record(_entity, value)
                        + match.group(0)[end - match.start() :]
                    )
                self._counts[_entity] += 1
                return self._token_and_record(_entity, match.group(0))

            text = pattern.sub(_replace, text)
        return text

    def redact_value(self, value: Any) -> Any:
        """Recursively redact strings inside an arbitrary structured field value."""
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            return {k: self.redact_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact_value(v) for v in value]
        return value

    def redact_record(self, record: LogRecord) -> LogRecord:
        """Return a copy of `record` with `raw`, `message` and every field redacted.

        Structured fields are redacted too -- a JSON log routinely carries the address in
        `fields.user.email` and never in the message text, so redacting only the free text
        would leak exactly the formats v1 prioritises.
        """
        if not self.enabled:
            return record
        raw = self.redact(record.raw)
        # On an unstructured log `message` *is* `raw`, and redacting it a second time was
        # doing the most expensive work in the pipeline twice for nothing. Profiling a
        # 400,000-line BGL ingest, redaction was 38% of the run -- 4.4 million regex
        # substitutions, eleven per line -- and half of those passes were over a string that
        # had just been redacted.
        #
        # The counters matter as much as the time. `redact` tallies per-entity hits, so a
        # second pass over the same text counted every value twice and `redacted_ipv4` on an
        # unstructured file was double what the file contained. A health metric that reports
        # twice the truth is worse than one that is merely slow to compute.
        message = raw if record.message == record.raw else self.redact(record.message)
        return replace(
            record,
            raw=raw,
            message=message,
            fields=self.redact_value(record.fields),
        )

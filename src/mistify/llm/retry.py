"""Retry and pacing shared by every real provider adapter.

Written once because it was written twice: the LiteLLM adapter began as a copy of the Gemini
adapter's loop and imported its private helpers to do it, so the next fix to either -- the
timeout that turned a thirty-minute hang into a retryable error was one -- would have had to be
made in both. Only the question "is this failure worth another attempt" differs by vendor, and
it is passed in.
"""

from __future__ import annotations

import random
import re
import time
from collections.abc import Callable

from mistify.llm.base import ProviderError

__all__ = ["RETRYABLE_STATUS", "advertised_delay", "send_with_retries", "space_out"]

#: HTTP statuses worth another attempt, whatever the vendor: timeouts, throttling, and the
#: server-side failures that are usually over by the next request.
RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})

#: Google returns a RetryInfo telling you exactly how long the quota window has left, e.g.
#: `'retryDelay': '54s'`, and LiteLLM passes the text through. Ignoring it and backing off on a
#: guess is how a retry budget gets spent entirely inside a window that had not reset yet.
_RETRY_DELAY = re.compile(r"retryDelay['\"]?\s*:\s*['\"]?(\d+(?:\.\d+)?)s")


def advertised_delay(exc: Exception) -> float | None:
    """Seconds the API asked us to wait, when it said so.

    Free-tier quotas are per-minute, so the wait is routinely longer than any exponential
    schedule reaches in the retries available. Honouring the server's own number is the
    difference between recovering and failing the investigation while the quota was about to
    reset anyway.
    """
    match = _RETRY_DELAY.search(str(exc))
    return float(match.group(1)) if match else None


def send_with_retries[T](
    send: Callable[[], T],
    *,
    is_retryable: Callable[[Exception], bool],
    max_retries: int,
    sleep: Callable[[float], object],
    before_each: Callable[[], None],
    failure: str,
) -> T:
    """Call `send`, retrying what `is_retryable` accepts, and raise `ProviderError` otherwise.

    `failure` prefixes the error, so the message names which provider and model failed.
    """
    for attempt in range(max_retries + 1):
        before_each()
        try:
            return send()
        except Exception as exc:
            if attempt >= max_retries or not is_retryable(exc):
                raise ProviderError(f"{failure}: {exc}") from exc
            # Full jitter: a loop that retries on a fixed schedule marches its own retries into
            # the next rate-limit window together.
            delay = min(2**attempt, 30) * (0.5 + random.random() / 2)
            # The server knows when the window resets and says so. Backing off for less than
            # that guarantees the next attempt fails too, which is how five retries get spent
            # inside one 60-second quota window.
            advertised = advertised_delay(exc)
            if advertised is not None:
                delay = max(delay, advertised + random.random())
            sleep(delay)
    raise ProviderError("unreachable: retry loop exited without returning")


def space_out(
    last_call_at: float, min_interval_seconds: float, sleep: Callable[[float], object]
) -> float:
    """Wait until `min_interval_seconds` have passed since the last call; return the new mark.

    For providers with per-minute quotas: a caller who knows theirs can trade wall clock for
    never being throttled. Zero leaves pacing to the retry path, which is faster when the limit
    is generous.
    """
    if min_interval_seconds <= 0:
        return last_call_at
    elapsed = time.monotonic() - last_call_at
    if elapsed < min_interval_seconds:
        sleep(min_interval_seconds - elapsed)
    return time.monotonic()

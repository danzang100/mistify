"""Last-resort adapter: every line is the message, and nothing is claimed about it.

Phase 4's exit criterion is that a file no adapter recognises "falls back to raw-line mode
loudly, with the reason in run_metadata". Loudly is the operative word. The two failure modes
this replaces are both worse than a degraded parse:

* **Refusing the file.** An investigation that cannot start is not safer than one that starts
  with less; an engineer holding an unrecognised log still needs the templating, the ranking
  and the search, all of which work on message text alone.
* **Guessing.** Inventing a timestamp or a severity produces a scratchpad that looks exactly
  like a well-parsed one, and every number downstream -- the incident window, the severity
  mix, the anomaly score -- silently describes a fiction.

So this adapter claims nothing it cannot read. It never wins detection on its own: `detect`
returns zero always, and the pipeline reaches for it only after everything else has declined,
which is why the fallback is a deliberate act recorded in the metrics rather than an adapter
quietly winning a vote.

What it costs is stated rather than hidden. Without timestamps the incident window collapses,
burstiness cannot be computed, and the anomaly score falls back to severity and rarity alone --
so the report says the file was read this way and why.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mistify.adapters.base import LogAdapter
from mistify.common.models import LogRecord, normalize_severity

__all__ = ["RawLinesAdapter"]

#: Severity words anywhere in the line. Deliberately crude: this is the one thing worth
#: attempting to recover, because severity is the heaviest term in the anomaly score and a file
#: read entirely as INFO ranks nothing above anything else.
_SEVERITY = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|FATAL|CRITICAL|CRIT|SEVERE)\b"
)


class RawLinesAdapter(LogAdapter):
    """Reads any text file as one record per line, inventing nothing."""

    format_name = "raw_lines"

    def detect(self, sample_lines: list[str]) -> float:
        """Always zero.

        This adapter would match every text file on earth, so letting it compete would make it
        win ties against adapters that actually understand the format. It is selected by the
        pipeline explicitly, after everything else has declined.
        """
        return 0.0

    def parse(self, source: str | Path) -> Iterator[LogRecord]:
        """One record per line, with a synthetic ordering timestamp.

        The timestamps are line ordinals from a fixed epoch, not guesses at when anything
        happened. The scratchpad's schema requires a timestamp and every ordering query depends
        on one, so refusing to provide any would mean refusing the file -- but they carry no
        information beyond the order the lines appeared in, and the report says so rather than
        letting a six-minute "incident window" be read off them.
        """
        path = Path(source)
        # A fixed base rather than `now`: two ingests of the same file must produce the same
        # scratchpad, or nothing downstream is reproducible.
        base = datetime(1970, 1, 1, tzinfo=UTC)

        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for lineno, line in enumerate(handle, start=1):
                raw = line.rstrip("\n")
                if not raw.strip():
                    continue
                self.stats.lines_read += 1

                match = _SEVERITY.search(raw)
                severity, mapped = normalize_severity(match.group(1) if match else None)
                if not mapped:
                    self.stats.unmapped_severity += 1
                # Counted on every line: there is no timestamp in this file as far as this
                # adapter knows, and the metric is what tells the report to distrust the window.
                self.stats.unparseable_timestamp += 1

                self.stats.records_emitted += 1
                yield LogRecord(
                    ts=base + timedelta(seconds=lineno),
                    source="unknown",
                    severity=severity,
                    raw=raw,
                    message=raw,
                    fields={"line_number": lineno},
                    format=self.format_name,
                )

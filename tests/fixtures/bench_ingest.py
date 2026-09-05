"""Measure one ingest: throughput, cardinality, storage and peak memory.

The numbers in the handoff's benchmark table were produced by a script that was never kept, so
the next person to want a comparable figure has to invent a measurement and hope it matches.
This is that script, kept.

**Peak memory is read from the operating system, not sampled.** Windows tracks
`PeakWorkingSet64` per process for the whole of its life, so the peak is exact and does not
depend on how often this polls -- polling only exists to catch worker processes, which are
transient and take their counters with them when the pool closes. On POSIX,
`getrusage(RUSAGE_CHILDREN).ru_maxrss` gives the same guarantee for children that have been
waited for.

Two memory numbers are reported, because one of them alone is misleading when
`redaction.workers` is above 1:

*   **concurrent** -- the largest total working set observed across the process tree at one
    sampling instant. What the machine actually had to hold.
*   **sum of peaks** -- every process's own lifetime peak, added. An upper bound, since two
    processes need not peak at the same moment, and the honest thing to quote when the
    sampling interval could have missed the true concurrent maximum.

Usage:

    uv run python tests/fixtures/bench_ingest.py --source path/to.log --incident-id bench
    uv run python tests/fixtures/bench_ingest.py --source path/to.log --config bench.yaml

Nothing here calls a model. The scratchpad it produces is left in place so cardinality can be
checked afterwards.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

#: How often the process tree is sampled, in seconds. Only the *concurrent* figure depends on
#: this; the per-process peaks are the OS's own and are exact whatever this is set to.
SAMPLE_SECONDS = 2.0

_PS_SNAPSHOT = (
    "$p = @(Get-Process python3.12,python,pythonw -ErrorAction SilentlyContinue); "
    "if ($p.Count -eq 0) { '0,0,0' } else { "
    "$c = ($p | Measure-Object WorkingSet64 -Sum).Sum; "
    "$s = ($p | Measure-Object PeakWorkingSet64 -Sum).Sum; "
    "\"$($p.Count),$c,$s\" }"
)


@dataclass
class MemorySampler:
    """Watches the Python process tree until told to stop."""

    max_concurrent: int = 0
    max_sum_peak: int = 0
    samples: int = 0
    supported: bool = True
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def _snapshot(self) -> tuple[int, int] | None:
        if platform.system() != "Windows":
            return None
        try:
            done = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SNAPSHOT],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        parts = done.stdout.strip().split(",")
        if len(parts) != 3:
            return None
        try:
            return int(parts[1]), int(parts[2])
        except ValueError:
            return None

    def _run(self) -> None:
        while not self._stop.is_set():
            snapshot = self._snapshot()
            if snapshot is None:
                self.supported = False
                return
            concurrent, sum_peak = snapshot
            self.max_concurrent = max(self.max_concurrent, concurrent)
            self.max_sum_peak = max(self.max_sum_peak, sum_peak)
            self.samples += 1
            self._stop.wait(SAMPLE_SECONDS)

    def __enter__(self) -> MemorySampler:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=30)


def _posix_peak_bytes() -> int | None:
    """Peak RSS of waited-for children, or None where the platform does not report it."""
    if platform.system() == "Windows":
        return None
    import resource

    usage = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    # Linux reports kilobytes; macOS reports bytes.
    return usage if platform.system() == "Darwin" else usage * 1024


def _scratchpad_stats(path: Path) -> dict[str, int]:
    import sqlite3

    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        events = con.execute("SELECT COUNT(*) FROM log_events").fetchone()[0]
        templates = con.execute("SELECT COUNT(*) FROM templates").fetchone()[0]
        singletons = con.execute(
            "SELECT COUNT(*) FROM templates WHERE occurrence_count = 1"
        ).fetchone()[0]
        largest = con.execute(
            "SELECT MAX(occurrence_count) FROM templates"
        ).fetchone()[0] or 0
        return {
            "events": int(events),
            "templates": int(templates),
            "singleton_templates": int(singletons),
            "largest_template_events": int(largest),
        }
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--incident-id", default="bench")
    parser.add_argument("--config", default=None, type=Path)
    parser.add_argument("--scratchpad-dir", default=Path(".cache"), type=Path)
    parser.add_argument("--out", default=None, type=Path, help="Where to write the JSON row.")
    args = parser.parse_args()

    if not args.source.exists():
        raise SystemExit(f"source not found: {args.source}")
    file_bytes = args.source.stat().st_size

    command = [
        "uv", "run", "mistify", "ingest",
        "--source", str(args.source),
        "--incident-id", args.incident_id,
    ]
    if args.config:
        command += ["--config", str(args.config)]

    print(f"ingesting {args.source} ({file_bytes / 1e9:.2f} GB)")
    started = time.monotonic()
    with MemorySampler() as sampler:
        completed = subprocess.run(command, capture_output=True, text=True)
    elapsed = time.monotonic() - started

    if completed.returncode != 0:
        print(completed.stdout[-4000:])
        print(completed.stderr[-4000:], file=sys.stderr)
        raise SystemExit(f"ingest failed with {completed.returncode}")
    print(completed.stdout.strip())

    scratchpad = args.scratchpad_dir / f"incident_{args.incident_id}.sqlite"
    stats = _scratchpad_stats(scratchpad) if scratchpad.exists() else {}
    scratchpad_bytes = scratchpad.stat().st_size if scratchpad.exists() else 0
    events = stats.get("events", 0)

    row = {
        "source": str(args.source),
        "file_bytes": file_bytes,
        "elapsed_seconds": round(elapsed, 1),
        "records_per_second": round(events / elapsed, 1) if elapsed and events else None,
        "scratchpad_bytes": scratchpad_bytes,
        "file_bytes_per_event": round(file_bytes / events, 1) if events else None,
        "scratchpad_bytes_per_event": round(scratchpad_bytes / events, 1) if events else None,
        **stats,
        "peak_concurrent_bytes": sampler.max_concurrent or _posix_peak_bytes(),
        "peak_sum_of_process_peaks_bytes": sampler.max_sum_peak or None,
        "memory_samples": sampler.samples,
        "memory_supported": sampler.supported,
    }
    if events:
        row["singleton_share"] = round(stats.get("singleton_templates", 0) / stats["templates"], 4)
        row["events_per_template"] = round(events / stats["templates"], 1)

    print()
    for key, value in row.items():
        if isinstance(value, int) and key.endswith("bytes"):
            print(f"  {key:<34} {value:>15,}  ({value / 1e6:.1f} MB)")
        else:
            print(f"  {key:<34} {value}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(row, indent=2), encoding="utf-8")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Reading a directory of logs as one incident.

An incident rarely arrives as one file. It arrives as a directory: one log per service, or one
per pod, or a rotated set of the same log. Pointing the pipeline at that directory used to die
with a bare `PermissionError` from `open()`, which is at least loud, but it is also the first
thing anyone tries.

This adapter is a wrapper, not a parser. Each file underneath keeps its own adapter, chosen by
the same detection the single-file path uses, so a directory holding JSON from one service and
syslog from another is read correctly rather than being forced through one reader. What this
adds is the three things that only make sense across files:

**Every record knows which file it came from.** `source_file` goes into `fields`, always. Two
services can log the identical sentence, and once the records are in one scratchpad the only
thing distinguishing them is where they were read from.

**A file's name stands in for a source nothing else names.** A raw-lines or inferred read
reports `source` as `"unknown"`, which is honest for one file and useless for forty -- every
record in the incident would claim the same non-answer. Where the adapter could not name a
source, the filename is used, because in a per-service directory layout that *is* the service.
Where the adapter did name one, it is left alone: the data beats the filename.

**Counters add up, and skipped files are counted rather than dropped.** A directory holding a
PNG or a tarball should not fail the whole ingest, and it must not silently shrink it either --
files that could not be read are counted and sampled into the same error list as bad lines.

Records still stream. Each member is consumed lazily and yielded straight through, because the
pipeline's memory bound is the batch size and buffering one file's records to check it first
would replace that bound with "however big the largest file is".
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

from mistify.adapters.base import LogAdapter
from mistify.adapters.source import BinarySourceError, compression_of, open_text
from mistify.common.models import LogRecord

__all__ = ["MultiFileAdapter", "log_files"]

#: Directory names never descended into. Build and metadata directories hold thousands of files
#: and no logs, and walking one turns a mistyped path into a very slow way to read nothing.
_SKIP_DIRS = frozenset(
    {".git", ".svn", ".hg", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".mypy_cache"}
)

#: How many skipped-file explanations are kept. The same budget the line-level error samples
#: get, and for the same reason: a reader needs to see what kind of thing was skipped, not all
#: two hundred of them.
_MAX_SKIP_SAMPLES = 5


def log_files(root: Path) -> list[Path]:
    """Every candidate log file under `root`, in a stable order.

    Recursive, because per-pod and per-service layouts nest. Sorted, because the scratchpad is
    supposed to be reproducible from the same directory twice and filesystem order is not.

    Hidden files are skipped: a directory of logs frequently also holds `.DS_Store` and editor
    swap files, and none of them is an incident. Nothing else is filtered here -- deciding
    whether a file is readable is `open_text`'s job, and doing it in two places would mean two
    places that could disagree about it.
    """
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(root).parts
        if set(parts) & _SKIP_DIRS or any(part.startswith(".") for part in parts):
            continue
        files.append(path)
    return sorted(files)


class MultiFileAdapter(LogAdapter):
    """One adapter per file underneath, presented to the pipeline as a single source."""

    #: Never wins detection: it is constructed deliberately by the pipeline when the source is
    #: a directory, exactly as `raw_lines` is constructed deliberately when nothing matched.
    specificity = 0

    def __init__(self, members: list[tuple[Path, LogAdapter]], root: Path) -> None:
        super().__init__()
        self.members = members
        self.root = root
        self.format_name = self._name()
        #: Files that could not be read at all, as opposed to lines that could not be parsed.
        self.files_skipped = 0

    def _name(self) -> str:
        """What format this directory is, when the answer fits in one word.

        A directory whose files all read the same way *is* that format, and reporting it as
        something else would make the metric useless for the common case. A mixed directory
        says so, listing what it found, because "multi_file" alone tells a reader nothing about
        whether to trust the timestamps -- which is the question the metric exists to answer.
        """
        formats = sorted({adapter.format_name for _path, adapter in self.members})
        if not formats:
            return "multi_file"
        if len(formats) == 1:
            return formats[0]
        return "multi:" + "+".join(formats)

    @property
    def component_formats(self) -> frozenset[str]:
        """Every format used underneath, so a wrapper is not opaque to the metrics.

        `format_name` summarises; this enumerates. Anything asking whether a particular reader
        was involved -- the fallback warning above all -- has to ask this rather than parse the
        summary string.
        """
        formats: set[str] = set()
        for _path, adapter in self.members:
            formats |= adapter.component_formats
        return frozenset(formats)

    def detect(self, sample_lines: list[str]) -> float:
        """Always zero -- a directory is not a line format, and is never routed to by score."""
        return 0.0

    def fresh(self) -> MultiFileAdapter:
        """A sibling with the same members, each with its counters reset.

        The pipeline reads a second pass for calibration and needs clean counters. `fresh()` on
        each member rather than a bare `type(self)()`, because an inferred member carries a
        schema that a default construction would lose.
        """
        members = [(path, adapter.fresh()) for path, adapter in self.members]
        return MultiFileAdapter(members, self.root)

    def parse(self, source: str | Path) -> Iterator[LogRecord]:
        """Every member's records in filename order, tagged with the file they came from.

        `source` is ignored: the members were resolved when this adapter was built, and
        re-deriving them here would let the calibration pass walk a directory that had changed
        underneath the run.
        """
        for path, adapter in self.members:
            relative = path.relative_to(self.root).as_posix()
            if not self._readable(path, relative):
                continue
            for record in adapter.parse(path):
                fields = {**record.fields, "source_file": relative}
                # The filename is the best available name for an emitter nothing else named.
                # In the layout this exists to read -- one file per service -- it is usually
                # the right one, and it is never allowed to override a name the data gave.
                source_name = record.source if record.source != "unknown" else self._stem(path)
                yield replace(record, fields=fields, source=source_name)
            self._absorb(adapter)

    @staticmethod
    def _stem(path: Path) -> str:
        """A filename with its extension off, and its compression suffix too.

        `Path.stem` alone leaves `hadoop.log.gz` as `hadoop.log`, which then appears as the
        service name on every record from that file. Compression is a property of how the file
        was stored, not of who wrote it.
        """
        stem = path.stem
        return Path(stem).stem if compression_of(path) is not None else stem

    def _readable(self, path: Path, relative: str) -> bool:
        """Whether this file is text we can read, checked before streaming any of it.

        Opened and closed rather than read: `open_text` does its magic-number and NUL-byte
        checks on the way in, so this costs one small read and answers the question. Catching
        the error by consuming the file instead would mean holding a whole file in memory to
        find out it was a PNG.
        """
        try:
            with open_text(path):
                return True
        except (BinarySourceError, OSError) as exc:
            self.files_skipped += 1
            if len(self.stats.error_samples) < _MAX_SKIP_SAMPLES:
                self.stats.record_error(f"{relative}: {exc}")
            else:
                self.stats.parse_errors += 1
            return False

    def _absorb(self, adapter: LogAdapter) -> None:
        """Fold a finished member's counters into this adapter's own.

        Done per member as it completes rather than at the end, because `parse` is a generator
        and the pipeline reads `stats` straight after the loop -- totals assembled afterwards
        would be assembled after the only caller had already looked at them.
        """
        stats = adapter.stats
        self.stats.lines_read += stats.lines_read
        self.stats.records_emitted += stats.records_emitted
        self.stats.parse_errors += stats.parse_errors
        self.stats.unmapped_severity += stats.unmapped_severity
        self.stats.unparseable_timestamp += stats.unparseable_timestamp
        for sample in stats.error_samples:
            if len(self.stats.error_samples) < _MAX_SKIP_SAMPLES * 2:
                self.stats.error_samples.append(sample)

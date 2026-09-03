"""How a log source is opened, before any adapter looks at it.

One place, because every adapter needs the answer and each one answering separately is how
they came to disagree. They all called `Path.open(encoding="utf-8", errors="replace")`, which
never raises on anything: hand it a gzip file and it returns the compressed bytes as
replacement characters, the raw-line adapter reads 48 "log lines" out of a 400-line archive,
and the run reports `parse_errors: 0` and writes a report. That is measured, not hypothetical.

So two jobs, and the second matters more than the first:

**Decompress what is compressed.** Incident logs arrive as `.gz` far more often than not.
gzip, bzip2 and xz are single-stream and stdlib-supported, so they are read transparently and
the pipeline never knows.

**Refuse what is binary.** Decompression alone does not fix the failure above, it only moves
it: a zip, a tarball, a core dump or a JPEG would still be read as text and still produce
plausible-looking nonsense. A source that is not text and not a compression we can undo is
rejected outright, with the reason, because there is no degraded reading of a JPEG that is
better than saying so.

Detection is by content, never by extension. A file named `.log` is routinely gzip and a file
named `.gz` is occasionally not, and the bytes are not in a position to lie about it.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, cast

__all__ = [
    "BinarySourceError",
    "compression_of",
    "open_text",
    "read_text",
]

#: Magic numbers, mapped to the opener that undoes them. Each is the first bytes of the file
#: format's header and is fixed by its specification.
_MAGIC: tuple[tuple[bytes, str, Callable[..., Any]], ...] = (
    (b"\x1f\x8b", "gzip", gzip.open),
    (b"BZh", "bzip2", bz2.open),
    (b"\xfd7zXZ\x00", "xz", lzma.open),
)

#: Formats that are binary and are *not* a single compressed stream. Named individually so the
#: refusal can say what the file actually is -- "this is a zip archive, extract it first" is
#: actionable in a way that "this file is binary" is not.
_KNOWN_BINARY: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "a zip archive"),
    (b"PK\x05\x06", "an empty zip archive"),
    (b"\x89PNG\r\n\x1a\n", "a PNG image"),
    (b"\xff\xd8\xff", "a JPEG image"),
    (b"%PDF-", "a PDF"),
    (b"SQLite format 3\x00", "a SQLite database"),
    (b"\x7fELF", "an ELF binary"),
)

#: How much of the file is inspected to decide whether it is text. The same rule `git` uses --
#: a NUL byte in the first block -- because no text encoding this pipeline reads produces one,
#: and every binary format produces them almost immediately.
_SNIFF_BYTES = 8192


class BinarySourceError(ValueError):
    """The source is not text, and is not a compression this can undo.

    Its own type rather than a bare `ValueError` so the CLI can report it as a bad input --
    which it is -- rather than as a crash.
    """


def _head(path: Path, count: int = _SNIFF_BYTES) -> bytes:
    with path.open("rb") as handle:
        return handle.read(count)


def compression_of(path: Path) -> str | None:
    """The compression this file uses, by magic number, or None when it is not compressed."""
    head = _head(path, 8)
    for magic, name, _opener in _MAGIC:
        if head.startswith(magic):
            return name
    return None


def _describe_binary(head: bytes) -> str:
    for magic, description in _KNOWN_BINARY:
        if head.startswith(magic):
            return description
    return "binary data"


def _check_is_text(path: Path, head: bytes) -> None:
    """Raise unless `head` looks like text.

    A NUL byte is the whole test. It is crude and it is right: UTF-8, UTF-8 with a BOM, and
    every single-byte encoding a log is written in can all be read without one, and a binary
    file that contains none in its first 8 KB is rare enough to be worth the false negative.

    The alternative -- counting how many bytes fail to decode -- sounds more principled and is
    worse, because `errors="replace"` is exactly what let the gzip file through in the first
    place. A threshold on how much garbage is acceptable is a threshold nobody can set.
    """
    if b"\x00" in head:
        raise BinarySourceError(
            f"{path} is {_describe_binary(head)}, not a log file. "
            "Extract or convert it first: reading it as text produces records that look "
            "real and are not."
        )


@contextmanager
def open_text(path: Path) -> Iterator[IO[str]]:
    """Open a log source for reading as text, decompressing it if it is compressed.

    Raises `BinarySourceError` when the source is neither. `errors="replace"` still applies to
    what gets through, because a single bad byte in the middle of a real log should cost one
    mangled character rather than the whole investigation -- the check above is what stops that
    tolerance from swallowing an entire file.
    """
    head = _head(path, 8)
    for magic, _name, opener in _MAGIC:
        if head.startswith(magic):
            with opener(path, "rb") as raw:
                decompressed_head = raw.read(_SNIFF_BYTES)
            # Compressed *something* is not necessarily compressed text: a gzipped tarball is
            # the ordinary case, and unwrapping one layer to find binary underneath is exactly
            # where a naive decompress-and-carry-on lands.
            _check_is_text(path, decompressed_head)
            with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
                # The stdlib openers are overloaded on `mode`; "rt" is the text branch, and
                # only the cast says so to a type checker.
                yield cast(IO[str], handle)
            return

    _check_is_text(path, _head(path))
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        yield handle


def read_text(path: Path) -> str:
    """The whole source as text, decompressed if need be.

    For the adapters that cannot stream -- a single JSON document has to be held whole, since
    there is no way to parse one JSON value incrementally without a streaming parser.
    """
    with open_text(path) as handle:
        return handle.read()

"""How a source is opened: compression undone, binary refused.

The bug this exists to prevent was measured, not imagined. A gzipped 400-line Hadoop log went
through the whole pipeline and produced "48 events into 48 templates", `parse_errors: 0`, and a
finished report -- because every adapter opened files with `errors="replace"`, which turns
compressed bytes into replacement characters rather than into an error. The first "log message"
in that scratchpad began with the gzip magic number.

So the tests here come in pairs: one that the compressed file now reads, and one that the
binary file now refuses. Either alone would be satisfiable by something useless -- refusing
everything passes every refusal test.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from pathlib import Path

import pytest

from mistify.adapters.registry import read_sample
from mistify.adapters.source import BinarySourceError, compression_of, open_text, read_text
from mistify.common.config import MistifyConfig
from mistify.pipeline import ingest
from mistify.scratchpad.db import ScratchpadDB

LINES = [
    f"2026-08-30T14:{i % 60:02d}:00Z ERROR checkout.pool: exhausted after {i}" for i in range(200)
]
TEXT = "\n".join(LINES) + "\n"


def _plain(tmp_path: Path) -> Path:
    path = tmp_path / "app.log"
    path.write_text(TEXT, encoding="utf-8")
    return path


# --------------------------------------------------------------- compression


@pytest.mark.parametrize(
    ("suffix", "compress"),
    [
        (".gz", gzip.compress),
        (".bz2", bz2.compress),
        (".xz", lzma.compress),
    ],
)
def test_compressed_sources_read_as_their_contents(
    tmp_path: Path, suffix: str, compress: object
) -> None:
    path = tmp_path / f"app.log{suffix}"
    path.write_bytes(compress(TEXT.encode()))  # type: ignore[operator]
    assert read_text(path) == TEXT


def test_an_uncompressed_source_still_reads(tmp_path: Path) -> None:
    """The control: the decompression path must not be the only path that works."""
    assert read_text(_plain(tmp_path)) == TEXT


def test_compression_is_detected_by_content_not_extension(tmp_path: Path) -> None:
    """A file named `.log` is routinely gzip and a file named `.gz` is occasionally not.

    Trusting the name means the common case -- a rotated log someone renamed -- reads as
    garbage, and the bytes are not in a position to lie about what they are.
    """
    misnamed = tmp_path / "app.log"
    misnamed.write_bytes(gzip.compress(TEXT.encode()))
    assert compression_of(misnamed) == "gzip"
    assert read_text(misnamed) == TEXT

    liar = tmp_path / "app.gz"
    liar.write_text(TEXT, encoding="utf-8")
    assert compression_of(liar) is None
    assert read_text(liar) == TEXT


def test_read_sample_sees_through_compression(tmp_path: Path) -> None:
    """Detection reads its sample the same way, or every compressed file scores zero."""
    path = tmp_path / "app.log.gz"
    path.write_bytes(gzip.compress(TEXT.encode()))
    assert read_sample(path, 3) == LINES[:3]


# --------------------------------------------------------------- refusing binary


def test_a_png_is_refused_and_named(tmp_path: Path) -> None:
    path = tmp_path / "screenshot.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00\x01\x02" * 100)
    with pytest.raises(BinarySourceError, match="PNG image"):
        read_text(path)


def test_a_zip_is_refused_and_named(tmp_path: Path) -> None:
    """Named specifically, because "extract it first" is actionable and "binary" is not."""
    path = tmp_path / "logs.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.log", TEXT)
    path.write_bytes(buffer.getvalue())
    with pytest.raises(BinarySourceError, match="zip archive"):
        read_text(path)


def test_a_gzipped_tarball_is_refused(tmp_path: Path) -> None:
    """The layered case, and the one a naive decompress-and-carry-on gets wrong.

    `.tar.gz` is a real gzip stream, so unwrapping it succeeds and hands back tar -- which is
    binary, and would sail straight through a check that only looked at the outer bytes.
    """
    path = tmp_path / "logs.tar.gz"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("app.log")
        info.size = len(TEXT.encode())
        archive.addfile(info, io.BytesIO(TEXT.encode()))
    path.write_bytes(buffer.getvalue())

    assert compression_of(path) == "gzip"
    with pytest.raises(BinarySourceError):
        read_text(path)


def test_a_log_with_a_stray_undecodable_byte_still_reads(tmp_path: Path) -> None:
    """The control on the refusal, and the reason the test is a NUL byte rather than decoding.

    A single bad byte mid-file should cost one mangled character, not the investigation. If the
    check were "did anything fail to decode" this file would be refused, and refusing it would
    be worse than the bug being fixed.
    """
    path = tmp_path / "app.log"
    path.write_bytes(TEXT.encode()[:100] + b"\xff\xfe" + TEXT.encode()[100:])
    text = read_text(path)
    assert "exhausted after 1" in text
    assert "�" in text


def test_an_empty_file_is_not_binary(tmp_path: Path) -> None:
    path = tmp_path / "empty.log"
    path.write_bytes(b"")
    with open_text(path) as handle:
        assert handle.read() == ""


# --------------------------------------------------------------- end to end


def test_a_gzipped_log_ingests_identically_to_the_plain_one(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """The regression, stated as the thing that was actually wrong.

    Before the source layer this ingested 48 events of compressed bytes with `parse_errors: 0`.
    Asserting "more than 48" would pass on any nonsense, so it is pinned to the plain file:
    the two must produce the same incident, because they are the same incident.
    """
    plain = _plain(tmp_path)
    packed = tmp_path / "app.log.gz"
    packed.write_bytes(gzip.compress(TEXT.encode()))

    from_plain = ingest(plain, config, incident_id="plain")
    from_packed = ingest(packed, config, incident_id="packed")

    assert from_packed.events_loaded == from_plain.events_loaded == len(LINES)
    assert from_packed.format_name == from_plain.format_name

    with ScratchpadDB(from_packed.scratchpad_path) as db:
        row = db.get_slice(max_lines=1)[0]
        assert "exhausted after" in row["message"]
        assert "�" not in row["message"]


def test_ingesting_a_binary_file_refuses_rather_than_inventing_records(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """It used to produce a scratchpad, a compression ratio and a report. Now it says no."""
    path = tmp_path / "screenshot.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 40)
    with pytest.raises(BinarySourceError, match="PNG image"):
        ingest(path, config, incident_id="png")

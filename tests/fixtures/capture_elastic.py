"""Capture real Elasticsearch responses, by shipping logs through a real Filebeat.

Elastic and Loki fixtures have to come from running stacks rather
than from hand-authored JSON. `capture_loki.py` is the precedent and it earned itself
immediately: four things about Loki's output would have been guessed wrong, and each was a
whole-file failure rather than a bad line.

Elastic has the same hazard in a different place. The *envelope* is normative -- the `_search`
response shape is in the REST specification and cannot vary by deployment -- but what lands
**inside `_source`** is convention, decided by whatever wrote the document. Three things vary
and an adapter written against a guess gets all three wrong together:

*   **Nested versus dotted.** Elasticsearch accepts `{"log": {"level": "error"}}` and
    `{"log.level": "error"}` and will return whichever was indexed. Filebeat writes nested;
    plenty of application shippers write dotted; a document can carry both at once.
*   **Where the level lives.** ECS says `log.level`. Pre-ECS Logstash wrote `level`, Serilog
    writes `@l`, and a Java shipper often writes `loglevel` or leaves it in the message.
*   **What `message` holds.** Filebeat tailing a plain file puts the whole raw line in
    `message`. A structured shipper puts the parsed message there and the rest in siblings.
    The first means `message` and `raw` are the same string; the second means they are not,
    and the redaction metrics double-count when that is got wrong -- which has already happened
    once on unstructured logs.

Two export shapes are captured, because two different things hand you Elastic data and an
adapter has to read both:

*   **`_search` response** -- `{"hits": {"hits": [{"_index": ..., "_source": {...}}]}}`, one
    JSON document, what saving a `curl` gives you.
*   **NDJSON dump** -- one `{"_index": ..., "_source": {...}}` per line, what
    `elasticsearch-dump` and a scroll-and-write script produce, and the shape that actually
    arrives when somebody exports an index for analysis.

Usage, against a real stack. Elasticsearch single-node with security off, and Filebeat tailing
a log file into it:

    docker run -d --name es -p 9200:9200 \\
        -e discovery.type=single-node -e xpack.security.enabled=false \\
        docker.elastic.co/elasticsearch/elasticsearch:8.15.0

    uv run python tests/fixtures/capture_elastic.py --source loghub --system OpenSSH
    uv run python tests/fixtures/capture_elastic.py --source synthetic

`--shipper filebeat` runs a real Filebeat container so the `_source` is genuinely Filebeat's;
`--shipper bulk` indexes the same lines through the `_bulk` API with an ECS-shaped document
written here, which is faster and is **not** an honest capture of a shipper's conventions --
it is there to exercise the envelope when Filebeat cannot be run, and the provenance file
records which was used so the two are never confused.

Output lands in `.cache/fixtures/elastic/`, never in the repo, for the same two reasons nothing
else generated here is committed: the Loghub-derived captures carry redistribution terms this
project has deliberately never taken on, and a fixture nobody can regenerate is a fixture
nobody can check.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

OUT_DIR = Path(".cache/fixtures/elastic")
INDEX = "mistify-capture"

#: The filebeat container this script starts and stops. Named so a run interrupted half
#: way through leaves something a later run can remove, not a stray beat still shipping.
CONTAINER = "mistify-filebeat-capture"

#: How long to wait for filebeat to get every line into the index, in seconds.
SHIP_TIMEOUT = 180

#: How long to wait for Elasticsearch to answer before giving up, in seconds.
STARTUP_TIMEOUT = 120

#: Documents to capture. Enough to show repeated shapes without producing a fixture too large
#: to read by eye, which is the only way anyone checks whether a capture is right.
DEFAULT_LIMIT = 500


def _request(
    url: str, method: str = "GET", body: bytes | None = None, content_type: str = "application/json"
) -> dict[str, Any]:
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Content-Type", content_type)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_for_elasticsearch(base: str) -> dict[str, Any]:
    """Block until the cluster answers, or fail with something a reader can act on."""
    deadline = time.monotonic() + STARTUP_TIMEOUT
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return _request(base)
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            last = exc
            time.sleep(2)
    raise SystemExit(
        f"Elasticsearch at {base} did not answer within {STARTUP_TIMEOUT}s ({last}).\n"
        "Start it with:\n"
        "  docker run -d --name es -p 9200:9200 -e discovery.type=single-node "
        "-e xpack.security.enabled=false "
        "docker.elastic.co/elasticsearch/elasticsearch:8.15.0"
    )


def _loghub_lines(system: str, limit: int) -> list[str]:
    """Lines from a cached Loghub file, so the capture is of a real log rather than lorem."""
    path = Path(".cache/loghub") / f"{system}_2k.log"
    if not path.exists():
        raise SystemExit(
            f"{path} is not cached. Fetch it first with:\n"
            f"  uv run mistify eval-templating --system {system}"
        )
    with path.open(encoding="utf-8", errors="replace") as handle:
        return [line.rstrip("\n") for _, line in zip(range(limit), handle, strict=False)]


def _synthetic_lines(limit: int) -> list[str]:
    """A deterministic stand-in when no corpus is cached."""
    start = datetime(2026, 8, 30, 14, 0, 0, tzinfo=UTC)
    levels = ("INFO", "WARN", "ERROR")
    return [
        f"{start.isoformat()} {levels[i % len(levels)]} checkout-service "
        f"request {i} completed in {i % 400}ms"
        for i in range(limit)
    ]


def index_via_bulk(base: str, lines: list[str]) -> None:
    """Index an ECS-shaped document per line through `_bulk`.

    Explicitly the *dishonest* path for `_source` conventions: the document shape below is
    written here, so a capture taken this way proves nothing about what a shipper produces. It
    exercises the envelope, and the provenance file says so.
    """
    payload = []
    start = datetime(2026, 8, 30, 14, 0, 0, tzinfo=UTC)
    for offset, line in enumerate(lines):
        payload.append(json.dumps({"index": {"_index": INDEX}}))
        payload.append(
            json.dumps(
                {
                    "@timestamp": start.isoformat().replace("+00:00", "Z"),
                    "message": line,
                    "log": {"level": ("error" if offset % 3 == 0 else "info")},
                    "service": {"name": "capture-service"},
                    "host": {"name": "capture-host"},
                    "event": {"sequence": offset},
                }
            )
        )
    body = ("\n".join(payload) + "\n").encode("utf-8")
    result = _request(
        f"{base}/_bulk?refresh=wait_for",
        method="POST",
        body=body,
        content_type="application/x-ndjson",
    )
    if result.get("errors"):
        first = next(
            (item for item in result.get("items", []) if "error" in item.get("index", {})), None
        )
        raise SystemExit(f"bulk index reported errors, first: {json.dumps(first, indent=2)}")


def index_via_filebeat(base: str, lines: list[str]) -> None:
    """Ship the lines with a real Filebeat, so `_source` is genuinely a shipper's.

    This is the capture that is worth taking. Filebeat decides the nesting, adds its own
    `agent`, `ecs`, `host` and `input` objects, and puts the raw line in `message` -- none of
    which this file gets to choose.
    """
    staging = OUT_DIR / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    log_path = staging / "captured.log"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    config = staging / "filebeat.yml"
    config.write_text(
        "filebeat.inputs:\n"
        "  - type: filestream\n"
        "    id: mistify-capture\n"
        "    paths: [/staging/captured.log]\n"
        "output.elasticsearch:\n"
        f"  hosts: ['{base.replace('localhost', 'host.docker.internal')}']\n"
        f"  index: '{INDEX}'\n"
        "setup.ilm.enabled: false\n"
        "setup.template.enabled: false\n",
        encoding="utf-8",
    )
    # Not `--once`. The `filestream` input scans for its files on an interval, and `--once`
    # tears the beat down before the first scan completes: filebeat exits 0, having reported
    # `harvester.started: 0` and `output.events.total: 0`, and the failure surfaced two calls
    # later as a 404 from `_refresh` on an index nothing had created. Detached, polled until
    # the documents are queryable, then stopped.
    #
    # The deprecated `log` input does honour `--once`, and using it would be the smaller
    # change. It is the wrong one: `input.type` lands in `_source`, so a capture taken that
    # way would record a convention nobody deploys any more.
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, text=True)
    started = subprocess.run(
        [
            "docker", "run", "-d", "--name", CONTAINER,
            "-v", f"{staging.resolve()}:/staging:ro",
            "-v", f"{config.resolve()}:/usr/share/filebeat/filebeat.yml:ro",
            "--add-host", "host.docker.internal:host-gateway",
            "docker.elastic.co/beats/filebeat:8.15.0",
            "filebeat", "-e", "--strict.perms=false",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if started.returncode != 0:
        raise SystemExit(f"filebeat would not start\n{started.stderr[-2000:]}")

    try:
        indexed = _wait_for_documents(base, len(lines))
    finally:
        logs = subprocess.run(
            ["docker", "logs", "--tail", "40", CONTAINER], capture_output=True, text=True
        )
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, text=True)

    if indexed == 0:
        raise SystemExit(
            "filebeat shipped nothing. Its last output:\n"
            + (logs.stdout or logs.stderr)[-2000:]
        )
    if indexed < len(lines):
        print(
            f"warning: {indexed} of {len(lines)} lines indexed; capturing what arrived",
            file=sys.stderr,
        )


def _wait_for_documents(base: str, expected: int) -> int:
    """Documents in the index once the count stops rising, or `SHIP_TIMEOUT` has passed.

    Polled on the count rather than slept through, and the plateau matters as much as the
    target: a shipper that drops some lines would otherwise hold this open for the whole
    timeout and then report a number the caller cannot tell apart from a slow flush.
    """
    deadline = time.monotonic() + SHIP_TIMEOUT
    count = 0
    stable = 0
    while time.monotonic() < deadline:
        time.sleep(2)
        with contextlib.suppress(urllib.error.HTTPError, urllib.error.URLError, OSError):
            _request(f"{base}/{INDEX}/_refresh", method="POST", body=b"")
            now = int(_request(f"{base}/{INDEX}/_count").get("count", 0))
            if now >= expected:
                return now
            stable = stable + 1 if now == count and now > 0 else 0
            count = now
            if stable >= 3:
                return count
    return count


def capture(base: str, limit: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """A `_search` response as it comes back, and the same hits as an NDJSON dump would hold."""
    body = json.dumps({"size": limit, "query": {"match_all": {}}}).encode("utf-8")
    response = _request(f"{base}/{INDEX}/_search", method="POST", body=body)
    hits = response.get("hits", {}).get("hits", [])
    return response, hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://localhost:9200")
    parser.add_argument("--source", choices=("loghub", "synthetic"), default="synthetic")
    parser.add_argument("--system", default="OpenSSH", help="Loghub system, with --source loghub")
    parser.add_argument("--shipper", choices=("filebeat", "bulk"), default="filebeat")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    args = parser.parse_args()

    info = wait_for_elasticsearch(args.base)
    version = str(info.get("version", {}).get("number", "unknown"))
    print(f"elasticsearch {version} at {args.base}")

    lines = (
        _loghub_lines(args.system, args.limit)
        if args.source == "loghub"
        else _synthetic_lines(args.limit)
    )
    print(f"{len(lines)} line(s) from {args.source}")

    # Nothing to delete on a first run, and a stale index from a previous capture would
    # otherwise be appended to rather than replaced.
    with contextlib.suppress(urllib.error.HTTPError):
        _request(f"{args.base}/{INDEX}", method="DELETE")

    if args.shipper == "filebeat":
        index_via_filebeat(args.base, lines)
    else:
        index_via_bulk(args.base, lines)

    response, hits = capture(args.base, args.limit)
    print(f"captured {len(hits)} hit(s)")
    if not hits:
        raise SystemExit("the index came back empty; nothing was captured")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stem = f"{args.source}_{args.shipper}"
    search_path = OUT_DIR / f"{stem}_search.json"
    ndjson_path = OUT_DIR / f"{stem}_dump.ndjson"
    search_path.write_text(json.dumps(response, indent=2), encoding="utf-8")
    ndjson_path.write_text(
        "\n".join(json.dumps(hit) for hit in hits) + "\n", encoding="utf-8"
    )

    source_keys = sorted(hits[0].get("_source", {}))
    provenance = {
        "captured_at": datetime.now(UTC).isoformat(),
        "elasticsearch_version": version,
        "shipper": args.shipper,
        # The whole point of the file. A bulk capture says nothing about a shipper's `_source`
        # conventions, and a reader must never have to guess which kind they are holding.
        "source_conventions_are_real": args.shipper == "filebeat",
        "corpus": args.source,
        "system": args.system if args.source == "loghub" else None,
        "documents": len(hits),
        "source_keys": source_keys,
        "dotted_keys_present": [k for k in source_keys if "." in k],
    }
    (OUT_DIR / f"{stem}.provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf-8"
    )

    print(f"wrote {search_path}")
    print(f"wrote {ndjson_path}")
    print(f"_source keys: {', '.join(source_keys)}")
    if provenance["dotted_keys_present"]:
        print(f"dotted keys: {', '.join(provenance['dotted_keys_present'])}")
    if not provenance["source_conventions_are_real"]:
        print(
            "\nNOTE: --shipper bulk indexed a document written by this script. The envelope is "
            "real; the _source conventions are not. Re-run with --shipper filebeat before "
            "treating the field mapping as captured."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

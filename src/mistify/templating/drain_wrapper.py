"""Drain3 configuration, persistence glue, and per-incident template statistics.

Templating runs on already-redacted text (decision G1). Two consequences worth stating:

1.  The persisted Drain3 tree cannot contain secrets, which closes the leak in the original
    ordering where a durable on-disk snapshot held unredacted tokens (decision G2).
2.  Redaction placeholders are masked back out before clustering. Without that mask each
    distinct source value would produce a distinct placeholder hash, and a template that
    should read "Connection to <REDACTED> failed" would fragment into one cluster per
    address -- redaction would silently destroy the compression it is meant to be neutral to.
"""

from __future__ import annotations

import base64
import binascii
import zlib
from collections import Counter, defaultdict
from pathlib import Path

from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

from mistify.common.models import TemplateResult, TemplateSummary, severity_rank
from mistify.redaction.patterns import placeholder_pattern

__all__ = ["DrainTemplater", "read_snapshot"]


def read_snapshot(path: str | Path) -> str:
    """Return the decoded text of a Drain3 snapshot.

    Drain3 stores state as base64-encoded zlib-compressed JSON. Anything auditing a snapshot
    for leaked values has to decode it first: scanning the file bytes directly matches
    nothing, so a leak check written against the raw file passes whatever the tree contains.
    """
    payload = Path(path).read_bytes()
    try:
        return zlib.decompress(base64.b64decode(payload, validate=True)).decode(
            "utf-8", errors="replace"
        )
    except (binascii.Error, zlib.error, ValueError):
        # Written uncompressed (snapshot_compress_state disabled).
        return payload.decode("utf-8", errors="replace")


class _AtomicFilePersistence(FilePersistence):  # type: ignore[misc]
    """A snapshot writer that cannot leave a half-written file behind.

    Drain3's `FilePersistence` writes straight over the target. Interrupt the process during
    that write -- Ctrl-C, a killed background job, a machine going to sleep -- and what is left
    on disk is a truncated zlib stream that no later run can read. That happened here: a killed
    eval left `drain3_eval-logdx-jest-nextjs-001-master.json` half-written, and the next run of
    that case died with `Error -5 while decompressing data`.

    Writing to a sibling file and renaming makes the swap atomic on both POSIX and Windows, so
    a reader sees either the previous snapshot or the new one and never a partial one. The
    tolerant load in `DrainTemplater` stays as the backstop for snapshots corrupted some other
    way -- a full disk, a bad sector, an older version of this code.
    """

    def save_state(self, state: bytes) -> None:
        target = Path(self.file_path)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_bytes(state)
        tmp.replace(target)


class DrainTemplater:
    """Wraps Drain3 with per-incident statistics and snapshot persistence."""

    def __init__(
        self,
        sim_th: float = 0.4,
        depth: int = 4,
        max_clusters: int = 2000,
        snapshot_path: Path | None = None,
    ) -> None:
        config = TemplateMinerConfig()
        config.drain_sim_th = sim_th
        config.drain_depth = depth
        config.drain_max_clusters = max_clusters
        config.masking_instructions = [
            MaskingInstruction(placeholder_pattern(), "REDACTED"),
        ]

        self.snapshot_path = snapshot_path
        persistence = None
        if snapshot_path is not None:
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            persistence = _AtomicFilePersistence(str(snapshot_path))

        #: Set when an existing snapshot could not be read and was discarded.
        self.snapshot_discarded: str | None = None
        try:
            self._miner = TemplateMiner(persistence_handler=persistence, config=config)
        except Exception as exc:
            # A snapshot that will not load costs a re-clustering, never the run. The same
            # rule `load_schemas` already applies to the inferred-schema cache: a corrupt
            # entry in a cache is a cache miss, not a failure.
            #
            # This is not hypothetical. A killed process left a truncated snapshot behind, and
            # every later run of that incident id died on `Error -5 while decompressing data:
            # incomplete or truncated stream` -- an eval case that had run fine an hour
            # earlier, failing for a reason that had nothing to do with its log.
            self.snapshot_discarded = f"{type(exc).__name__}: {exc}"
            if snapshot_path is not None:
                snapshot_path.unlink(missing_ok=True)
            self._miner = TemplateMiner(persistence_handler=None, config=config)

        # Constructed *with* the handler so a existing snapshot is still restored, then
        # detached so it is not written on every cluster. Drain3 saves whenever a message
        # changes the tree -- `get_snapshot_reason` returns a reason for any `change_type`
        # other than "none" -- and each save jsonpickles the entire cluster tree. That is
        # O(clusters) work per new cluster, so O(n^2) in distinct templates.
        #
        # It is not a theoretical cost. Profiling a 4,000-line CI log, which clusters into
        # 3,053 templates because almost every line is unique, spent **97.5% of a 489-second
        # ingest inside `save_state`**: 3,222 calls, 4.7 million jsonpickle encodes. The
        # clustering itself was a rounding error. Throughput fell from 281 lines/s at 500
        # lines to 31 lines/s at 4,000, which puts a gigabyte-scale log out of reach for a
        # reason that has nothing to do with log analysis.
        #
        # The pipeline already calls `snapshot()` once when ingest finishes, so every
        # intermediate write was discarded by the next one. The handler is reattached there.
        self._persistence = persistence
        self._miner.persistence_handler = None
        self._total_messages = 0
        # Our own registry of every template ever seen, independent of Drain3's tree.
        #
        # Drain3 evicts clusters on an LRU once `max_clusters` is reached, and the evicted
        # ones vanish from `id_to_cluster`. Reading final statistics off that tree meant
        # every event assigned to an evicted cluster pointed at a template row that was
        # never written -- on a high-cardinality file that silently orphaned most of the
        # input while the compression ratio reported a healthy-looking number. Recording
        # each template as it is first seen makes eviction a matching concern only: the
        # tree may forget a shape, but the scratchpad never does.
        self._patterns: dict[int, str] = {}
        self._counts: Counter[int] = Counter()
        self._first_seen: dict[int, str] = {}
        self._last_seen: dict[int, str] = {}
        self._severity_mix: dict[int, Counter[str]] = defaultdict(Counter)

    @property
    def total_messages(self) -> int:
        return self._total_messages

    @property
    def unique_templates(self) -> int:
        """Distinct templates seen across the whole stream, including evicted ones."""
        return len(self._patterns)

    @property
    def evicted_templates(self) -> int:
        """Templates Drain3 has dropped from its matching tree.

        Their statistics survive, but a shape that reappears after eviction is assigned a
        fresh id, which splits one condition's counts across several templates. Non-zero
        here means template statistics are fragmented and `max_clusters` is too low.
        """
        return max(0, len(self._patterns) - len(self._miner.drain.id_to_cluster))

    @property
    def compression_ratio(self) -> float:
        """Unique templates divided by total lines.

        The headline health metric for this stage. Near 1.0 means no compression was
        achieved (under-clustering); a very low ratio paired with a wide severity mix inside
        one template suggests distinct conditions were merged (over-clustering). Phase 2 adds
        the calibration pass that acts on this number.
        """
        if self._total_messages == 0:
            return 0.0
        return self.unique_templates / self._total_messages

    def process(
        self,
        message: str,
        ts: str = "",
        severity: str = "INFO",
        extract_params: bool = False,
    ) -> TemplateResult:
        """Cluster one message and fold it into this incident's template statistics.

        `extract_params` is off by default because nothing in the pipeline reads the result.
        Drain3's `extract_parameters` re-matches the mined template against the message to
        recover the variable parts, and it ran on every line -- about 6% of an ingest -- for a
        list that every caller then dropped on the floor. `TemplateResult.params` is still a
        real field and still tested; it is now computed when somebody asks for it.
        """
        result = self._miner.add_log_message(message)
        template_id = int(result["cluster_id"])
        pattern = str(result["template_mined"])

        self._total_messages += 1
        # Overwrite rather than set-once: Drain3 refines a cluster's template as it sees
        # more members, so the newest pattern is the accurate one.
        self._patterns[template_id] = pattern
        self._counts[template_id] += 1
        if template_id not in self._first_seen or ts < self._first_seen[template_id]:
            self._first_seen[template_id] = ts
        if template_id not in self._last_seen or ts > self._last_seen[template_id]:
            self._last_seen[template_id] = ts
        self._severity_mix[template_id][severity] += 1

        params: list[str] = []
        if extract_params:
            extracted = self._miner.extract_parameters(pattern, message)
            params = [p.value for p in extracted] if extracted else []
        return TemplateResult(template_id=template_id, pattern=pattern, params=params)

    def summaries(self) -> list[TemplateSummary]:
        """Final per-template statistics for the whole incident.

        Built from the registry, so every template an event was ever assigned to appears
        here whether or not Drain3 still holds it in its matching tree. Patterns come from
        the last time the cluster was seen, which is the most refined version available.
        """
        summaries: list[TemplateSummary] = []
        live = self._miner.drain.id_to_cluster
        for template_id, pattern in self._patterns.items():
            mix = self._severity_mix.get(template_id, Counter())
            max_rank = max((severity_rank(s) for s in mix), default=0)
            cluster = live.get(template_id)
            summaries.append(
                TemplateSummary(
                    template_id=template_id,
                    pattern=cluster.get_template() if cluster is not None else pattern,
                    occurrence_count=self._counts[template_id],
                    first_seen=self._first_seen.get(template_id, ""),
                    last_seen=self._last_seen.get(template_id, ""),
                    severity_mix=dict(mix),
                    max_severity_rank=max_rank,
                )
            )
        summaries.sort(key=lambda s: s.template_id)
        return summaries

    def signal_stats(self) -> dict[str, float]:
        """Numbers describing how findable the signal is, not how small the output got.

        Compression on its own is a vanity number: collapsing a file into a handful of
        templates looks excellent right up until the one rare severe template is the thing
        that got collapsed. These describe the haystack the agent is handed.
        """
        if self._total_messages == 0:
            return {"reduction_factor": 0.0, "largest_template_share": 0.0}
        return {
            # How much less the agent reads: lines per template.
            "reduction_factor": self._total_messages / max(1, len(self._patterns)),
            # Share of the file taken by the single noisiest template. A dominant template
            # crowds agent attention even after compression (architecture §6.4).
            "largest_template_share": (
                max(self._counts.values()) / self._total_messages if self._counts else 0.0
            ),
        }

    def snapshot(self) -> None:
        """Persist the tree so re-running the pipeline yields stable template ids.

        The one write. The handler is reattached here rather than left on the miner, because
        leaving it on means Drain3 writes the whole tree again on every cluster it creates --
        see the note in `__init__`. The artifact on disk is identical either way; only the
        number of times it was written on the way there changes.
        """
        if self.snapshot_path is None or self._persistence is None:
            return
        self._miner.persistence_handler = self._persistence
        try:
            self._miner.save_state("mistify snapshot")
        finally:
            # Detached again so a caller that keeps templating after a snapshot -- nothing
            # does today -- does not silently reacquire the quadratic behaviour.
            self._miner.persistence_handler = None

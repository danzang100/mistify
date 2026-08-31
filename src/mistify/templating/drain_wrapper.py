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
            persistence = FilePersistence(str(snapshot_path))

        self._miner = TemplateMiner(persistence_handler=persistence, config=config)
        self._total_messages = 0
        self._first_seen: dict[int, str] = {}
        self._last_seen: dict[int, str] = {}
        self._severity_mix: dict[int, Counter[str]] = defaultdict(Counter)

    @property
    def total_messages(self) -> int:
        return self._total_messages

    @property
    def unique_templates(self) -> int:
        return len(self._miner.drain.id_to_cluster)

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

    def process(self, message: str, ts: str = "", severity: str = "INFO") -> TemplateResult:
        """Cluster one message and fold it into this incident's template statistics."""
        result = self._miner.add_log_message(message)
        template_id = int(result["cluster_id"])
        pattern = str(result["template_mined"])

        self._total_messages += 1
        if template_id not in self._first_seen or ts < self._first_seen[template_id]:
            self._first_seen[template_id] = ts
        if template_id not in self._last_seen or ts > self._last_seen[template_id]:
            self._last_seen[template_id] = ts
        self._severity_mix[template_id][severity] += 1

        extracted = self._miner.extract_parameters(pattern, message)
        params = [p.value for p in extracted] if extracted else []
        return TemplateResult(template_id=template_id, pattern=pattern, params=params)

    def summaries(self) -> list[TemplateSummary]:
        """Final per-template statistics for the whole incident.

        Patterns are read from the finished tree rather than recorded during the stream,
        because Drain3 refines a cluster's template as it sees more members -- an early
        occurrence carries a pattern that is no longer current by the end of the file.
        """
        summaries: list[TemplateSummary] = []
        for cluster_id, cluster in self._miner.drain.id_to_cluster.items():
            mix = self._severity_mix.get(cluster_id, Counter())
            max_rank = max((severity_rank(s) for s in mix), default=0)
            summaries.append(
                TemplateSummary(
                    template_id=int(cluster_id),
                    pattern=cluster.get_template(),
                    occurrence_count=int(cluster.size),
                    first_seen=self._first_seen.get(cluster_id, ""),
                    last_seen=self._last_seen.get(cluster_id, ""),
                    severity_mix=dict(mix),
                    max_severity_rank=max_rank,
                )
            )
        summaries.sort(key=lambda s: s.template_id)
        return summaries

    def snapshot(self) -> None:
        """Persist the tree so re-running the pipeline yields stable template ids."""
        if self.snapshot_path is None:
            return
        self._miner.save_state("mistify snapshot")

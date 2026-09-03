"""Template accuracy against annotated ground truth, on logs this project did not write.

Everything else in the eval suite runs on fixtures generated here, whose lines are
template-shaped by construction. That makes `template_coverage: 1.0` and a compression ratio of
0.0018 numbers about a generator rather than about Drain3. This is the check that uses somebody
else's logs and somebody else's answers.

The corpus is Loghub-2k (github.com/logpai/loghub): 2,000 lines per system, each annotated with
the event template a human assigned it. Sixteen systems, from Hadoop and OpenStack to Linux and
Apache -- multi-line traces, inconsistent timestamps, and shapes nothing here was tuned on.

**No model is called.** This measures clustering, which is the foundation every later stage sits
on: a template that merged two conditions loses the distinction before an investigation ever
starts, and no amount of reasoning recovers it.

The headline metric is Grouping Accuracy, the standard in the log-parsing literature: a line is
correct when the set of lines sharing its parsed template is exactly the set sharing its
annotated template. It is deliberately unforgiving -- a cluster that is right except for one
stray member scores zero for every line in it -- because a nearly-right grouping is exactly the
kind of failure that reads as success downstream.

Data is downloaded on demand into `.cache/` and never committed: Loghub is free for research
use but redistribution carries citation terms, and a corpus vendored into a repository is a
licence question nobody wants to answer later.
"""

from __future__ import annotations

import csv
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from mistify.templating.drain_wrapper import DrainTemplater

__all__ = [
    "LOGHUB_SYSTEMS",
    "TemplatingScore",
    "fetch_loghub",
    "fetch_loghub_raw",
    "grouping_accuracy",
    "score_dataset",
]

#: Every system Loghub-2k annotates. Named here so `--system` can be validated before a
#: download rather than after a 404.
LOGHUB_SYSTEMS: tuple[str, ...] = (
    "Android",
    "Apache",
    "BGL",
    "Hadoop",
    "HDFS",
    "HealthApp",
    "HPC",
    "Linux",
    "Mac",
    "OpenSSH",
    "OpenStack",
    "Proxifier",
    "Spark",
    "Thunderbird",
    "Windows",
    "Zookeeper",
)

_RAW = (
    "https://raw.githubusercontent.com/logpai/loghub/master/{system}/{system}_2k.log_structured.csv"
)

#: The unstructured original the CSV was annotated from. Same 2,000 lines, before anyone split
#: them into columns -- which is the only form the ingest path can read, and the point of
#: having it: the CSV measures clustering against an answer key, and the `.log` measures
#: whether the adapters and the bootstrapper can get to the lines at all.
_RAW_LOG = "https://raw.githubusercontent.com/logpai/loghub/master/{system}/{system}_2k.log"


@dataclass(frozen=True, slots=True)
class TemplatingScore:
    """What clustering did to one annotated dataset."""

    system: str
    lines: int
    grouping_accuracy: float
    parsed_templates: int
    annotated_templates: int
    sim_th: float

    @property
    def template_ratio(self) -> float:
        """Parsed templates over annotated ones.

        Reported next to accuracy because the two fail in opposite directions and the accuracy
        number alone cannot tell them apart: a parser that emits one cluster per line scores
        badly with a huge ratio, and one that merges everything scores badly with a tiny one.
        """
        return self.parsed_templates / self.annotated_templates if self.annotated_templates else 0.0


def fetch_loghub(system: str, directory: Path) -> Path:
    """Download one Loghub-2k structured CSV, or return the copy already on disk."""
    if system not in LOGHUB_SYSTEMS:
        raise ValueError(f"unknown Loghub system {system!r}. Known: {', '.join(LOGHUB_SYSTEMS)}")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{system}_2k.log_structured.csv"
    if path.exists():
        return path
    url = _RAW.format(system=system)
    with urllib.request.urlopen(url, timeout=60) as response:
        path.write_bytes(response.read())
    return path


def fetch_loghub_raw(system: str, directory: Path) -> Path:
    """Download one Loghub-2k unstructured `.log`, or return the copy already on disk.

    The sibling of `fetch_loghub`, and deliberately a separate function rather than a flag: the
    two files answer different questions and are consumed by different code. `score_dataset`
    wants the annotated CSV and never the raw log; ingestion, adapter fixtures and the
    bootstrapper want the raw log and cannot use the CSV at all, because the CSV has already
    done the parsing that is the thing under test.

    Same cache directory and same terms as the CSV: downloaded on demand, never committed.
    """
    if system not in LOGHUB_SYSTEMS:
        raise ValueError(f"unknown Loghub system {system!r}. Known: {', '.join(LOGHUB_SYSTEMS)}")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{system}_2k.log"
    if path.exists():
        return path
    with urllib.request.urlopen(_RAW_LOG.format(system=system), timeout=60) as response:
        path.write_bytes(response.read())
    return path


def _read_annotated(path: Path) -> tuple[list[str], list[str]]:
    """The `Content` column and the `EventId` a human assigned it, in file order."""
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    missing = {"Content", "EventId"} - set(rows[0] if rows else {})
    if missing:
        raise ValueError(f"{path.name} has no {', '.join(sorted(missing))} column")
    return [row["Content"] for row in rows], [row["EventId"] for row in rows]


def grouping_accuracy(parsed: list[int], annotated: list[str]) -> float:
    """Fraction of lines whose parsed cluster matches its annotated cluster exactly.

    The standard log-parsing metric, and stricter than it first sounds: correctness is a
    property of the whole group, not of a line. Splitting one true cluster in two fails every
    line in both halves, and so does merging two true clusters into one -- which is right,
    because both destroy the distinction a later stage would need.
    """
    if not parsed:
        return 0.0
    by_parsed: dict[int, set[int]] = defaultdict(set)
    by_annotated: dict[str, set[int]] = defaultdict(set)
    for index, (cluster, event) in enumerate(zip(parsed, annotated, strict=True)):
        by_parsed[cluster].add(index)
        by_annotated[event].add(index)

    correct = 0
    for members in by_parsed.values():
        truth = by_annotated[annotated[next(iter(members))]]
        if members == truth:
            correct += len(members)
    return correct / len(parsed)


def score_dataset(path: Path, sim_th: float = 0.4, depth: int = 4) -> TemplatingScore:
    """Cluster one annotated dataset and score the result.

    Deliberately no calibration. The shipped pipeline calibrates `sim_th` per file, but a
    calibrated number would measure the calibrator and the parser together and could not say
    which one moved -- so this reports accuracy at a stated threshold, and sweeping the
    threshold is the caller's business.
    """
    contents, annotated = _read_annotated(path)
    templater = DrainTemplater(sim_th=sim_th, depth=depth, max_clusters=10_000)
    parsed = [templater.process(line).template_id for line in contents]
    return TemplatingScore(
        system=path.name.split("_")[0],
        lines=len(contents),
        grouping_accuracy=grouping_accuracy(parsed, annotated),
        parsed_templates=len(set(parsed)),
        annotated_templates=len(set(annotated)),
        sim_th=sim_th,
    )

"""What you get without the agent, scored the same way.

Every number this project has produced answers "did the investigation find the planted cause".
None of them answer "did it beat `grep -i error | sort | uniq -c | sort -rn | head`", which is
the first thing anyone sensible asks and the comparison the build plan's descope ladder names
twice. A system that cannot beat a shell pipeline has not earned the model calls.

Two baselines, because one of them is a straw man:

* **naive** is the pipeline as written. Severity-keyword filter, group identical lines, rank by
  count. It groups almost nothing on real logs, since embedded numbers and identifiers make
  most lines unique -- which is worth showing rather than assuming.
* **templated** hands the baseline this project's own clustering before ranking. That is a
  deliberately generous opponent: it concedes the templating stage entirely and asks whether
  the *investigation* adds anything beyond ranking error-ish templates by frequency.

Both write their answer as a scratchpad note citing real rows, so `score_run` grades them
against the same checks as an agent run. Producing a different artefact would have meant
comparing a number to an anecdote.

No model is called by either.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Literal

from mistify.scratchpad.db import ScratchpadDB

__all__ = ["BASELINES", "BaselineResult", "run_baseline"]

BaselineName = Literal["naive", "templated"]
BASELINES: tuple[str, ...] = ("naive", "templated")

#: What `grep -iE` is pointed at. Severity words rather than the severity column, because the
#: baseline is a text filter -- assuming a parsed severity field would be handing it a share of
#: the ingest stage it has not earned.
_ERROR_WORDS = re.compile(r"\b(error|fatal|exception|fail(ed|ure)?|critical)\b", re.IGNORECASE)

#: `uniq -c` groups identical lines. Numbers, ids and timestamps make most log lines unique, so
#: the naive baseline is shown both ways: raw, and with digits flattened, which is the cheapest
#: thing a person does by hand when raw grouping returns nothing useful.
_DIGITS = re.compile(r"\d+")

#: How many rows the baseline's finding cites. Matches what a person would paste into a ticket.
_CITED_ROWS = 5


@dataclass(frozen=True, slots=True)
class BaselineResult:
    """What the baseline concluded, and how much it had to look at."""

    name: str
    matched_lines: int
    groups: int
    top_count: int
    top_template_id: int | None
    note: str


def _matching_rows(db: ScratchpadDB) -> list[dict[str, Any]]:
    """Every row whose *raw line* mentions a severity word, which is what grep actually sees.

    `raw`, not `message`. The first version filtered the extracted message and found six lines
    on a file with 396 at ERROR or above, because the JSON fixture carries severity in a
    `"level"` field that the message text never mentions. That is a baseline handicapped by a
    parsing stage it does not have, which flatters the agent -- the whole point of the exercise
    is to give the shell pipeline everything it would really have.
    """
    rows = db.run_readonly_sql(
        "SELECT id, ts, source, severity, template_id, message, raw FROM log_events ORDER BY id",
        max_rows=1_000_000,
    )
    return [r for r in rows if _ERROR_WORDS.search(str(r["raw"] or r["message"] or ""))]


def run_baseline(db: ScratchpadDB, name: BaselineName = "templated") -> BaselineResult:
    """Run one baseline and record its answer as a note, exactly as an investigation would.

    The note is written at high confidence deliberately. A shell pipeline expresses no doubt,
    and softening its output to make it score better on the negative control would be scoring a
    baseline nobody runs. When there is nothing to report it writes nothing, which is also what
    the pipeline does.
    """
    if name not in BASELINES:
        raise ValueError(f"unknown baseline {name!r}. Known: {', '.join(BASELINES)}")

    rows = _matching_rows(db)
    if not rows:
        # grep found nothing, so there is nothing to claim. This is the quiet hour's correct
        # answer, reached without any judgement at all -- which is the point of measuring it.
        return BaselineResult(name, 0, 0, 0, None, "")

    keyed: list[tuple[object, dict[str, Any]]]
    if name == "templated":
        keyed = [(int(r["template_id"]), r) for r in rows if r["template_id"] is not None]
    else:
        keyed = [(_DIGITS.sub("#", str(r["message"] or r["raw"])), r) for r in rows]

    counts = Counter(key for key, _ in keyed)
    top_key, top_count = counts.most_common(1)[0]
    members = [row for key, row in keyed if key == top_key]
    cited = [int(row["id"]) for row in members[:_CITED_ROWS]]
    template_id = int(members[0]["template_id"]) if members[0]["template_id"] is not None else None

    sample = str(members[0]["message"] or members[0]["raw"])
    note = (
        f"Most frequent error-level pattern in the log ({top_count} of {len(rows)} matching "
        f"lines): {sample}"
    )
    evidence: dict[str, object] = {"log_event_ids": cited, "selection": f"grep baseline ({name})"}
    if template_id is not None:
        evidence["template_ids"] = [template_id]
    db.write_note(step=1, note=note, evidence=evidence, confidence="high")

    return BaselineResult(name, len(rows), len(counts), top_count, template_id, note)

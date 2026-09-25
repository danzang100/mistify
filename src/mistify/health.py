"""The pre-flight log health check: zero tokens, run after ingest and before any model call.

Three ways a log goes wrong silently, each of which the pipeline would otherwise carry straight
into a paid investigation that reads as a good one:

*   **Templating merged or split the signal (F2).** Drain3 folds a success line and a failure
    line into one template when they differ only in a word it treats as a variable, leaves an
    identifier unmasked so one message becomes a template per request, or splits one message
    across several templates on something in the line header. Loghub grouping accuracy for the
    pipeline's own ingest, measured 2026-09-24: Proxifier 0.002, OpenStack 0.121, Apache 0.000
    -- the last against 1.000 when Apache's message column is clustered alone, because the
    weekday left in its header splits every message in two.
*   **Timestamps that are broken or disagree (F3).** A shape nothing recognised (every row a
    line ordinal), a syslog shape with no year, or two sources whose clocks disagree -- most
    often one writing UTC with an offset and another writing local time without one, which the
    parser has no choice but to read as UTC. Cross-source ordering is then wrong by whole hours
    and nothing downstream can tell.
*   **Multi-line entries split (F5).** A stack trace read line by line is one event per frame,
    cut off from the exception that owns it.

Every measurement ingest already records is reused through `MetricView` rather than derived
again; what is new here is read from the scratchpad directly -- template patterns, per-source
activity, the raw line's own timestamp text, and one sampled text scan.

Each check reports `ok`, `warn` or `fail`. `investigate` and `run` refuse to call a model on
`fail` unless told to with `--ignore-health`, and name the check that refused. Thresholds live
in `HealthConfig`, each beside the measurement that placed it.

The sentence each check writes is composed here rather than in the report, against the usual
split in `mistify.metrics`: the CLI prints it before the loop starts and the report prints it
at the top, and a verdict worded twice is a verdict that will one day say two things.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from mistify.metrics import (
    HEALTH_CHECK,
    HEALTH_CONTINUATION_SHARE,
    HEALTH_FAILED,
    HEALTH_HIDDEN_FAILURE_SHARE,
    HEALTH_MAX_SKEW_MINUTES,
    HEALTH_NAIVE_SOURCES,
    HEALTH_PARSE_ERROR_RATE,
    HEALTH_SPLIT_SHARE,
    HEALTH_STATUS,
    HEALTH_TIMESTAMP_COVERAGE,
    HEALTH_UNMASKED_ID_SHARE,
    HEALTH_WARNED,
    INGEST_EVENTS_LOADED,
    INGEST_FALLBACK,
    INGEST_LINES_READ,
    INGEST_PARSE_ERRORS,
    INGEST_TIMESTAMP_SHAPE,
    INGEST_TIMESTAMP_YEAR_INFERRED,
    INGEST_UNPARSEABLE_TIMESTAMP,
    TEMPLATING_COVERAGE,
    TEMPLATING_LARGEST_SHARE,
    TEMPLATING_OVER_MERGED,
    TEMPLATING_OVER_MERGED_IDS,
    TEMPLATING_REDUCTION_FACTOR,
    Metric,
    MetricView,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to the type checker
    from mistify.common.config import HealthConfig
    from mistify.scratchpad.db import ScratchpadDB

__all__ = [
    "OWNED_METRICS",
    "HealthCheck",
    "HealthReport",
    "HealthStatus",
    "check_health",
    "recorded_checks",
]


class HealthStatus(StrEnum):
    """A check's verdict. Declared in severity order, which `worst` relies on."""

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


_ORDER = {HealthStatus.OK: 0, HealthStatus.WARN: 1, HealthStatus.FAIL: 2}


@dataclass(frozen=True, slots=True)
class HealthCheck:
    """One check's verdict and the sentence a reader acts on."""

    name: str
    status: HealthStatus
    message: str

    def as_metric_value(self) -> str:
        return f"{self.status}: {self.message}"


@dataclass(frozen=True, slots=True)
class HealthReport:
    """Every check, plus the measurements behind them for recording."""

    checks: tuple[HealthCheck, ...]
    measurements: tuple[tuple[Metric, object], ...] = field(default=())

    @property
    def status(self) -> HealthStatus:
        return max((c.status for c in self.checks), key=_ORDER.__getitem__, default=HealthStatus.OK)

    @property
    def failed(self) -> tuple[HealthCheck, ...]:
        return tuple(c for c in self.checks if c.status == HealthStatus.FAIL)

    @property
    def warned(self) -> tuple[HealthCheck, ...]:
        return tuple(c for c in self.checks if c.status == HealthStatus.WARN)

    def metrics(self) -> list[tuple[Metric, object]]:
        """What the check hands the scratchpad: verdicts, the overall status, the numbers."""
        entries: list[tuple[Metric, object]] = [
            (HEALTH_STATUS, str(self.status)),
            (HEALTH_FAILED, ",".join(c.name for c in self.failed)),
            (HEALTH_WARNED, ",".join(c.name for c in self.warned)),
        ]
        entries += [(HEALTH_CHECK.member(c.name), c.as_metric_value()) for c in self.checks]
        entries += list(self.measurements)
        return entries

    def lines(self) -> list[str]:
        """The check as the CLI prints it: problems in full, passes by name."""
        header = f"health  {str(self.status).upper()}"
        problems = [c for c in self.checks if c.status != HealthStatus.OK]
        if problems:
            header += (
                f"  ({len(self.failed)} failed, {len(self.warned)} warned, "
                f"{len(self.checks) - len(problems)} passed)"
            )
        out = [header]
        for check in sorted(problems, key=lambda c: -_ORDER[c.status]):
            out.append(f"  {str(check.status).upper():<4}  {check.name}: {check.message}")
        passed = [c.name for c in self.checks if c.status == HealthStatus.OK]
        if passed:
            out.append(f"  ok    {', '.join(passed)}")
        return out

    def failed_reasons(self) -> str:
        """Every failed check, named with its own sentence."""
        return " ".join(f"[{c.name}] {c.message}" for c in self.failed)

    def refusal(self) -> str:
        """Why no model is being called, naming every check that failed."""
        return (
            f"the pre-flight health check failed, so no model was called. "
            f"{self.failed_reasons()} Otherwise, investigate with --investigator skeleton "
            "(no model), or pass --ignore-health to spend tokens on it anyway."
        )


#: Metrics whose report warning a check here restates, and the check that does. The report
#: drops its own warning only when that check's recorded verdict is not `ok` -- only when the
#: health section is already saying it -- so deduplication can never hide a problem.
OWNED_METRICS: dict[Metric, str] = {
    INGEST_PARSE_ERRORS: "parse_errors",
    TEMPLATING_COVERAGE: "template_coverage",
    TEMPLATING_REDUCTION_FACTOR: "template_count",
    TEMPLATING_LARGEST_SHARE: "dominant_template",
    TEMPLATING_OVER_MERGED: "over_merged",
}

# ---------------------------------------------------------------- the patterns

_WILDCARD = "<*>"

#: An identifier Drain3 left as a literal: a UUID, 16+ hex characters, or a 7+ digit number,
#: at the start of a token or after a separator (`req-<uuid>`, `blk_<digits>`).
_ID_TOKEN = re.compile(
    r"(?i)^(?:.*[^0-9a-f])?"
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|\d{7,})"
)

#: Words that mark a line as an outcome worth finding. Deliberately short: this asks whether
#: a template hides some of these and not others, not whether a line is an error.
_FAILURE = re.compile(
    r"(?i)\b(error|errors|fail|failed|failure|exception|refused|denied|timeout|timed out"
    r"|fatal|cannot|unable|abort|aborted|panic)\b"
)

#: The ISO-8601 shape `bootstrap.schema.TIMESTAMP_PATTERNS` recognises, with the zone captured.
_ISO = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?"
_ISO_ZONED = re.compile(_ISO + r"(?P<zone>Z|[+-]\d{2}:?\d{2})?")

#: A line that continues the entry above it rather than starting one. The optional leading
#: timestamp is a CI runner's, which stamps every line including stack frames.
_CONTINUATION = re.compile(
    r"^(?:" + _ISO + r"Z?\s+)?"
    r"(?:\s+at\s+\S"  # indented Java / .NET / JavaScript frame
    r"|at\s+[\w$]+(?:\.[\w$<>]+)+\("  # unindented Java frame
    r"|\s*Caused by:\s"
    r"|\s*\.\.\. \d+ (?:more|common frames omitted)"
    r"|\s*File \"[^\"]+\", line \d+"  # Python
    r"|\s*Traceback \(most recent call last\)"
    r"|goroutine \d+ \["  # Go
    r"|\s+/\S+\.go:\d+)"
)

#: Raw lines read per source to learn how it writes time.
_RAW_SAMPLE = 200


def _pct(value: float) -> str:
    return f"{value:.1%}"


def _duration(minutes: int) -> str:
    sign = "-" if minutes < 0 else ""
    hours, rest = divmod(abs(minutes), 60)
    return f"{sign}{hours}h{rest:02d}m" if hours else f"{sign}{rest}m"


# ------------------------------------------------------------------ the checks


def _events(view: MetricView, db: ScratchpadDB) -> tuple[HealthCheck, int]:
    loaded = view.number(INGEST_EVENTS_LOADED)
    events = int(loaded) if loaded is not None else db.event_count()
    if events == 0:
        return (
            HealthCheck(
                "events",
                HealthStatus.FAIL,
                "No events were loaded, so there is nothing to investigate.",
            ),
            0,
        )
    return HealthCheck("events", HealthStatus.OK, f"{events:,} events loaded."), events


def _timestamps(view: MetricView, events: int, config: HealthConfig) -> tuple[HealthCheck, float]:
    """Share of events whose time was read from their own line.

    Only a raw-line read keeps an event it could not timestamp -- it inherits the line above's
    time, or a line ordinal -- so that is the only reader whose unparseable count is a count of
    loaded events. Every other adapter drops such a line and counts it as a parse error, which
    the parse-error check already reports; counting it again here would double it.
    """
    coverage = 1.0
    if view.triggers(INGEST_FALLBACK) and events:
        unparseable = view.number(INGEST_UNPARSEABLE_TIMESTAMP) or 0.0
        coverage = min(1.0, max(0.0, 1.0 - unparseable / events))
    shape = view.text(INGEST_TIMESTAMP_SHAPE)
    year_inferred = view.triggers(INGEST_TIMESTAMP_YEAR_INFERRED)

    if coverage < config.timestamp_coverage_warn_below:
        status = (
            HealthStatus.FAIL
            if coverage < config.timestamp_coverage_fail_below
            else HealthStatus.WARN
        )
        if coverage == 0.0:
            message = (
                "No timestamp could be read from any line, so every event carries its line "
                "number instead: the incident window and the burstiness term describe the order "
                "of the file, not when anything happened."
            )
        else:
            message = (
                f"Only {_pct(coverage)} of events carry a timestamp read from their own line "
                f"(below {_pct(config.timestamp_coverage_warn_below)}). The rest inherited the "
                "time of the line above, or a line number where there was none, so timing "
                "around them is approximate."
            )
        return HealthCheck("timestamps", status, message), coverage

    if year_inferred:
        return (
            HealthCheck(
                "timestamps",
                HealthStatus.WARN,
                f"Lines read one at a time had their timestamps read as `{shape}`, which "
                "carries no year, so the year is the one at ingest. Durations and ordering are "
                "sound; absolute dates are not, and a log crossing 31 December will appear to "
                "run backwards.",
            ),
            coverage,
        )
    return (
        HealthCheck(
            "timestamps", HealthStatus.OK, f"{_pct(coverage)} of events carry a parsed timestamp."
        ),
        coverage,
    )


@dataclass(frozen=True, slots=True)
class _Skew:
    source: str
    shift_minutes: int
    aligned: float
    unshifted: float


def _best_shift(
    reference: set[int], other: set[int], config: HealthConfig
) -> tuple[int, float, float] | None:
    """The whole-step shift of `other` that best lines its activity up with `reference`'s.

    Compared in slots one step wide rather than in minutes. Every candidate shift is a whole
    number of steps, so a slot shifted by k steps is exactly the slot its minutes land in, and
    the comparison is the same one at a fifteenth of the cost -- which matters on a directory of
    forty sources each active across a week.

    Overlap is counted against the smaller of the two, so a quiet source fully inside a busy
    one's window scores 1.0 rather than the fraction of the busy one it covers. Returns
    `(shift in minutes, overlap at that shift, overlap unshifted)`.
    """
    step = config.skew_step_minutes
    ref_slots = {minute // step for minute in reference}
    other_slots = {minute // step for minute in other}
    smaller = min(len(ref_slots), len(other_slots))
    if smaller == 0:
        return None
    reach = config.skew_max_hours * 60 // step

    def overlap(shift: int) -> float:
        return sum(1 for slot in other_slots if slot + shift in ref_slots) / smaller

    unshifted = overlap(0)
    best_shift, best = 0, unshifted
    for shift in range(-reach, reach + 1):
        if shift == 0:
            continue
        score = overlap(shift)
        # Ties go to the smaller shift: a steady source overlaps itself under many shifts, and
        # the claim being made is the smallest one the data supports.
        if score > best or (score == best and abs(shift) < abs(best_shift)):
            best_shift, best = shift, score
    return best_shift * step, best, unshifted


def _significant(found: tuple[int, float, float], config: HealthConfig) -> bool:
    shift, aligned, unshifted = found
    return abs(shift) >= config.skew_min_minutes and aligned - unshifted >= config.skew_min_gain


def _find_skews(
    comparable: list[str],
    counts: dict[str, int],
    minutes: dict[str, set[int]],
    config: HealthConfig,
) -> tuple[list[_Skew], str]:
    """Sources whose clock disagrees with the majority's, and the source standing for it.

    Measuring every source against the busiest one alone makes the busiest one's clock the
    truth. In the mixed-timezone fixture the busiest source *is* the skewed one, and the first
    version of this check reported all three healthy services as skewed against it. So the shift
    against the busiest source is used only to group sources by clock; the group holding the
    most events is taken as right, and each source outside it is measured again against that
    group's busiest member.
    """
    pivot = max(comparable, key=lambda s: (counts[s], s))
    clock = {pivot: 0}
    for source in comparable:
        if source == pivot:
            continue
        found = _best_shift(minutes.get(pivot, set()), minutes.get(source, set()), config)
        clock[source] = found[0] if found is not None and _significant(found, config) else 0

    weight: Counter[int] = Counter()
    for source, shift in clock.items():
        weight[shift] += counts[source]
    consensus = max(weight, key=lambda shift: (weight[shift], -abs(shift)))
    anchor = max((s for s in comparable if clock[s] == consensus), key=lambda s: (counts[s], s))

    skews: list[_Skew] = []
    for source in sorted(comparable):
        if clock[source] == consensus:
            continue
        found = _best_shift(minutes.get(anchor, set()), minutes.get(source, set()), config)
        if found is not None and _significant(found, config):
            skews.append(_Skew(source, *found))
    return skews, anchor


def _zone_notation(samples: dict[str, list[str]]) -> dict[str, Counter[str]]:
    """Per source, how its ISO timestamps are written: `utc`, an offset, or `naive`."""
    notation: dict[str, Counter[str]] = {}
    for source, lines in samples.items():
        tally: Counter[str] = Counter()
        for line in lines:
            match = _ISO_ZONED.search(line)
            if match is None:
                continue
            zone = match.group("zone")
            if zone is None:
                tally["naive"] += 1
            elif zone == "Z" or zone.replace(":", "") in {"+0000", "-0000"}:
                tally["utc"] += 1
            else:
                tally[zone if ":" in zone else f"{zone[:3]}:{zone[3:]}"] += 1
        if tally:
            notation[source] = tally
    return notation


def _timezones(
    db: ScratchpadDB, config: HealthConfig
) -> tuple[HealthCheck, list[tuple[Metric, object]]]:
    """Clock skew between sources, and timestamps written with no offset beside ones with.

    Two independent signals. Alignment asks whether shifting one source by whole quarter hours
    lines its activity up with the busiest source's much better than leaving it alone; notation
    asks whether one source writes no UTC offset while another does. Either alone is a warning
    -- a nightly job genuinely runs at a different hour from the service it maintains, and a
    naive timestamp is frequently UTC already. Both together, on the same source, is a clock
    read in the wrong zone, and that refuses spend: every cross-source "this happened first" the
    investigation would write is wrong by the skew.
    """
    measurements: list[tuple[Metric, object]] = []
    counts = {str(row["source"]): int(row["events"]) for row in db.source_activity()}
    notation = _zone_notation(db.raw_samples(_RAW_SAMPLE))

    zoned_anywhere = any(k != "naive" for tally in notation.values() for k in tally)
    naive_sources = sorted(
        source
        for source, tally in notation.items()
        if tally["naive"] and tally["naive"] >= sum(tally.values()) / 2
    )
    mixed = sorted(
        source
        for source, tally in notation.items()
        if tally["naive"] and sum(tally.values()) > tally["naive"]
    )
    naive_beside_zoned = bool(naive_sources and zoned_anywhere)
    if naive_beside_zoned or mixed:
        measurements.append((HEALTH_NAIVE_SOURCES, ",".join(sorted({*naive_sources, *mixed}))))

    comparable = [s for s, n in counts.items() if n >= config.skew_min_source_events]
    skews: list[_Skew] = []
    anchor = None
    if len(comparable) >= 2:
        minutes = db.source_minutes()
        skews, anchor = _find_skews(comparable, counts, minutes, config)
        worst = max(skews, key=lambda s: abs(s.shift_minutes), default=None)
        measurements.append((HEALTH_MAX_SKEW_MINUTES, 0 if worst is None else worst.shift_minutes))

    def naive(source: str) -> bool:
        return source in naive_sources

    parts: list[str] = []
    corroborated = False
    for skew in skews:
        assert anchor is not None
        # The shift lines the source up; the source's clock is off by the opposite amount.
        direction = "later" if skew.shift_minutes < 0 else "earlier"
        disagree = (
            skew.source in notation and anchor in notation and naive(skew.source) != naive(anchor)
        )
        corroborated = corroborated or disagree
        sentence = (
            f"`{skew.source}` appears {_duration(abs(skew.shift_minutes))} {direction} than "
            f"`{anchor}`: shifted by {_duration(skew.shift_minutes)} its activity lines up "
            f"{_pct(skew.aligned)} with `{anchor}`'s, against {_pct(skew.unshifted)} unshifted"
        )
        if disagree:
            who = skew.source if naive(skew.source) else anchor
            other = anchor if who == skew.source else skew.source
            sentence += (
                f", and `{who}` writes its timestamps with no UTC offset while `{other}` "
                "writes one, so its local times were read as UTC"
            )
        parts.append(sentence + ".")

    if skews:
        status = (
            HealthStatus.FAIL
            if corroborated and config.fail_on_corroborated_skew
            else HealthStatus.WARN
        )
        tail = (
            " Every cross-source ordering in this incident is off by that much. Fix the zone "
            "and ingest again."
            if corroborated
            else " This is a clock or zone difference, or a source that genuinely logs at "
            "another hour; check before trusting any cross-source ordering."
        )
        if not notation:
            tail += " The raw lines were not kept, so how each source wrote its zone is unknown."
        return HealthCheck("timezones", status, " ".join(parts) + tail), measurements

    if naive_beside_zoned or mixed:
        who = ", ".join(f"`{s}`" for s in sorted({*naive_sources, *mixed}))
        return (
            HealthCheck(
                "timezones",
                HealthStatus.WARN,
                f"{who} write timestamps with no UTC offset while others carry one; those were "
                "read as UTC. No skew between sources was measurable, so if they are local "
                "time the error is hidden rather than absent.",
            ),
            measurements,
        )
    if len(comparable) < 2:
        message = "One source, so there is no clock to disagree with."
    else:
        message = f"{len(comparable)} sources line up with no shift between their clocks."
    return HealthCheck("timezones", HealthStatus.OK, message), measurements


def _parse_errors(view: MetricView, config: HealthConfig) -> tuple[HealthCheck, float | None]:
    errors = view.number(INGEST_PARSE_ERRORS)
    lines = view.number(INGEST_LINES_READ)
    if errors is None or lines is None:
        return (
            HealthCheck(
                "parse_errors",
                HealthStatus.WARN,
                "Ingest recorded no parse-error count, so how much of the file was skipped is "
                "unknown.",
            ),
            None,
        )
    rate = errors / lines if lines else 0.0
    if rate > config.parse_error_rate_warn_above:
        fail_above = config.parse_error_rate_fail_above
        status = (
            HealthStatus.FAIL if fail_above is not None and rate > fail_above else HealthStatus.WARN
        )
        return (
            HealthCheck(
                "parse_errors",
                status,
                f"{int(errors):,} of {int(lines):,} lines ({_pct(rate)}) failed to parse and "
                "were skipped; nothing in them can be found or cited.",
            ),
            rate,
        )
    if errors:
        # Under the threshold is not the same as none: those lines still cannot be found.
        return (
            HealthCheck(
                "parse_errors",
                HealthStatus.OK,
                f"{int(errors):,} of {int(lines):,} lines ({_pct(rate)}) failed to parse and "
                f"were skipped, under the {_pct(config.parse_error_rate_warn_above)} warning "
                "threshold.",
            ),
            rate,
        )
    return HealthCheck("parse_errors", HealthStatus.OK, "Every line parsed."), rate


def _template_coverage(view: MetricView) -> HealthCheck:
    coverage = view.number(TEMPLATING_COVERAGE)
    if coverage is None:
        return HealthCheck(
            "template_coverage",
            HealthStatus.WARN,
            "Templating recorded no coverage, so whether every event is reachable is unknown.",
        )
    if view.triggers(TEMPLATING_COVERAGE):
        return HealthCheck(
            "template_coverage",
            HealthStatus.FAIL,
            f"{_pct(1.0 - coverage)} of events have no reachable template. Template search "
            "cannot surface them, so any conclusion rests on a partial view of the incident.",
        )
    return HealthCheck("template_coverage", HealthStatus.OK, "Every event has a template.")


def _template_count(view: MetricView, templates: int, config: HealthConfig) -> HealthCheck:
    reduction = view.number(TEMPLATING_REDUCTION_FACTOR)
    if reduction is None:
        return HealthCheck(
            "template_count",
            HealthStatus.WARN,
            "Templating recorded no reduction factor, so how much it compressed is unknown.",
        )
    if 0.0 < reduction < config.min_reduction_factor:
        return HealthCheck(
            "template_count",
            HealthStatus.WARN,
            f"{templates:,} templates at {reduction:.1f} events each: there is little repeated "
            "structure, so the investigation searches close to the raw haystack and the "
            "ranking is weak.",
        )
    return HealthCheck(
        "template_count",
        HealthStatus.OK,
        f"{templates:,} templates, {reduction:.1f} events each.",
    )


def _dominant(view: MetricView, config: HealthConfig) -> HealthCheck:
    share = view.number(TEMPLATING_LARGEST_SHARE)
    if share is not None and share > config.dominant_share_warn_above:
        return HealthCheck(
            "dominant_template",
            HealthStatus.WARN,
            f"One template holds {_pct(share)} of all events. Anything that varies inside it -- "
            "a failing task among passing ones -- is invisible to the ranking; search its text.",
        )
    detail = "unknown" if share is None else _pct(share)
    return HealthCheck(
        "dominant_template", HealthStatus.OK, f"The largest template holds {detail} of events."
    )


def _split(patterns: list[tuple[int, str, int]], config: HealthConfig) -> tuple[HealthCheck, float]:
    """Templates that end identically: one message split by something in the line's header."""
    total = sum(count for _, _, count in patterns)
    groups: dict[tuple[str, ...], list[tuple[int, int]]] = defaultdict(list)
    for template_id, pattern, count in patterns:
        tail = tuple(pattern.split()[-4:])
        if sum(1 for token in tail if token != _WILDCARD) >= 2:
            groups[tail].append((template_id, count))
    shared = {tail: members for tail, members in groups.items() if len(members) > 1}
    events = sum(count for members in shared.values() for _, count in members)
    share = events / total if total else 0.0
    if share > config.split_share_warn_above:
        tail, members = max(shared.items(), key=lambda kv: sum(c for _, c in kv[1]))
        ids = ", ".join(str(t) for t, _ in sorted(members)[:6])
        return (
            HealthCheck(
                "split_templates",
                HealthStatus.WARN,
                f"{_pct(share)} of events sit in templates that end in the same four tokens as "
                f"another template -- templates {ids} all end `{' '.join(tail)}`. One message "
                "has been split by something in its header (a weekday, a host, a file name), "
                "so each piece's count is understated and its rarity overstated.",
            ),
            share,
        )
    return (
        HealthCheck(
            "split_templates",
            HealthStatus.OK,
            f"{_pct(share)} of events in templates sharing an ending with another.",
        ),
        share,
    )


def _unmasked_ids(
    patterns: list[tuple[int, str, int]], config: HealthConfig
) -> tuple[HealthCheck, float]:
    total = sum(count for _, _, count in patterns)
    carrying = [
        (template_id, count)
        for template_id, pattern, count in patterns
        if any(_ID_TOKEN.match(token) for token in pattern.split())
    ]
    share = sum(count for _, count in carrying) / total if total else 0.0
    if share > config.unmasked_id_share_warn_above:
        return (
            HealthCheck(
                "unmasked_ids",
                HealthStatus.WARN,
                f"{_pct(share)} of events sit in {len(carrying)} template(s) that still contain "
                "an identifier -- a UUID, a long hex string or a long number -- as a literal. "
                "One message per request or object means its counts are split and each piece "
                "looks rarer than the message is.",
            ),
            share,
        )
    return (
        HealthCheck(
            "unmasked_ids",
            HealthStatus.OK,
            f"{_pct(share)} of events in templates carrying a literal identifier.",
        ),
        share,
    )


def _over_merged(view: MetricView) -> HealthCheck:
    if view.triggers(TEMPLATING_OVER_MERGED):
        count = int(view.number(TEMPLATING_OVER_MERGED) or 0)
        ids = view.text(TEMPLATING_OVER_MERGED_IDS)
        detail = "" if ids is None else f" (templates {ids})"
        return HealthCheck(
            "over_merged",
            HealthStatus.WARN,
            f"{count} template(s){detail} hold members across a wide severity range, so "
            "distinct conditions were merged into one.",
        )
    return HealthCheck("over_merged", HealthStatus.OK, "No template spans a wide severity range.")


def _text_scan(
    db: ScratchpadDB,
    patterns: list[tuple[int, str, int]],
    events: int,
    config: HealthConfig,
) -> tuple[HealthCheck, HealthCheck, list[tuple[Metric, object]]]:
    """Hidden failures and continuation lines, from one sampled pass over the messages."""
    stride = max(1, math.ceil(events / config.scan_max_events))
    counts = db.text_matches_by_template(
        {"failure": _FAILURE, "continuation": _CONTINUATION}, stride=stride
    )
    sampled = f" (every {stride}th event read)" if stride > 1 else ""
    by_id = {template_id: pattern for template_id, pattern, _ in patterns}

    failure_lines = sum(c["failure"] for c in counts.values())
    hidden_templates = [
        (template_id, c)
        for template_id, c in counts.items()
        if 0 < c["failure"] < c["events"] and not _FAILURE.search(by_id.get(template_id, ""))
    ]
    hidden = sum(c["failure"] for _, c in hidden_templates)
    hidden_share = hidden / failure_lines if failure_lines else 0.0
    if (
        hidden_share > config.hidden_failure_share_warn_above
        and hidden * stride >= config.hidden_failure_min_lines
    ):
        top = sorted(hidden_templates, key=lambda kv: -kv[1]["failure"])[:3]
        ids = ", ".join(str(t) for t, _ in top)
        hidden_check = HealthCheck(
            "hidden_failures",
            HealthStatus.WARN,
            f"{_pct(hidden_share)} of the lines carrying a failure word{sampled} sit in "
            f"templates whose pattern does not show it and whose other members do not carry "
            f"it -- templates {ids}. Success and failure were folded into one template, so the "
            "ranking cannot see these lines; search for them by text.",
        )
    else:
        hidden_check = HealthCheck(
            "hidden_failures",
            HealthStatus.OK,
            f"{_pct(hidden_share)} of failure-worded lines hidden in templates that do not "
            "show them.",
        )

    examined = sum(c["events"] for c in counts.values())
    continuation = sum(c["continuation"] for c in counts.values())
    continuation_share = continuation / examined if examined else 0.0
    if continuation_share > config.continuation_share_warn_above:
        frame_templates = sum(1 for c in counts.values() if c["continuation"] * 2 > c["events"])
        multiline_check = HealthCheck(
            "multiline",
            HealthStatus.WARN,
            f"{_pct(continuation_share)} of events{sampled} are stack-frame or traceback "
            f"continuation lines, spread over {frame_templates} template(s) made mostly of "
            "them. Each frame was read as an event of its own, cut off from the exception "
            "that owns it: read the lines around an error rather than its template alone.",
        )
    else:
        multiline_check = HealthCheck(
            "multiline",
            HealthStatus.OK,
            f"{_pct(continuation_share)} of events are continuation lines.",
        )
    measurements: list[tuple[Metric, object]] = [
        (HEALTH_HIDDEN_FAILURE_SHARE, round(hidden_share, 4)),
        (HEALTH_CONTINUATION_SHARE, round(continuation_share, 4)),
    ]
    return hidden_check, multiline_check, measurements


# ------------------------------------------------------------------ the entry


def check_health(db: ScratchpadDB, config: HealthConfig) -> HealthReport:
    """Run every check against one ingested scratchpad. No model is called."""
    view = MetricView(db.metrics())
    events_check, events = _events(view, db)
    if events == 0:
        return HealthReport(checks=(events_check,))

    patterns = db.template_patterns()
    timestamps, coverage = _timestamps(view, events, config)
    timezones, zone_measurements = _timezones(db, config)
    parse_errors, error_rate = _parse_errors(view, config)
    split, split_share = _split(patterns, config)
    unmasked, id_share = _unmasked_ids(patterns, config)
    hidden, multiline, scan_measurements = _text_scan(db, patterns, events, config)

    checks = (
        events_check,
        timestamps,
        timezones,
        parse_errors,
        _template_coverage(view),
        _template_count(view, len(patterns), config),
        _dominant(view, config),
        split,
        unmasked,
        _over_merged(view),
        hidden,
        multiline,
    )
    measurements: list[tuple[Metric, object]] = [
        (HEALTH_TIMESTAMP_COVERAGE, round(coverage, 4)),
        (HEALTH_SPLIT_SHARE, round(split_share, 4)),
        (HEALTH_UNMASKED_ID_SHARE, round(id_share, 4)),
        *zone_measurements,
        *scan_measurements,
    ]
    if error_rate is not None:
        measurements.append((HEALTH_PARSE_ERROR_RATE, round(error_rate, 6)))
    return HealthReport(checks=checks, measurements=tuple(measurements))


def recorded_checks(view: MetricView) -> list[HealthCheck]:
    """The verdicts a scratchpad holds, in declaration order, for the report to render."""
    checks: list[HealthCheck] = []
    for metric in HEALTH_CHECK.all_members():
        text = view.text(metric)
        if text is None:
            continue
        status, _, message = text.partition(": ")
        try:
            verdict = HealthStatus(status)
        except ValueError:
            # A value this code did not write. Shown as a warning rather than dropped: a
            # verdict nobody can read is not a pass.
            verdict, message = HealthStatus.WARN, text
        checks.append(HealthCheck(metric.name.removeprefix(HEALTH_CHECK.prefix), verdict, message))
    return checks

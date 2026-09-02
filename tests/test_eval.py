"""The evaluation harness: its fixtures, its scoring, and the case definitions.

Everything here runs without a credential or a network. Notes are written straight into the
scratchpad rather than produced by a model, because what is under test is whether the scorer
reads them correctly -- and a scorer validated only by live runs is validated by the thing it
is supposed to be validating.

The scorer earns tests more than most code in this repo. The scratch version written during
development reported one run's metrics for every row of a table, and the wrong numbers were
acted on twice before anyone read them closely.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mistify.eval.cases import CASES, PRECURSOR_MARKER, EvalCase, case_names, get_case
from mistify.eval.fixtures import (
    RED_HERRING_MARKER,
    ROOT_CAUSE_MARKER,
    generate_quiet_hour,
    write_quiet_hour,
)
from mistify.eval.scoring import score_run
from mistify.scratchpad.db import ScratchpadDB

QUIET_CASE = get_case("quiet-hour")
INCIDENT_CASE = get_case("pool-exhaustion")


def _checks(db: ScratchpadDB, case: EvalCase) -> dict[str, bool]:
    return {check.name: check.passed for check in score_run(db, case)}


def _template_id(db: ScratchpadDB, marker: str) -> int:
    rows = db.run_readonly_sql("SELECT template_id, pattern FROM templates", max_rows=500)
    return next(int(r["template_id"]) for r in rows if marker in str(r["pattern"]))


# ------------------------------------------------------------- the quiet hour


def test_the_quiet_hour_contains_nothing_severe() -> None:
    """The negative control only controls for anything if nothing in it is an incident."""
    records = generate_quiet_hour()

    levels = {str(record["level"]) for record in records}

    assert levels == {"INFO", "DEBUG", "WARN"}
    assert len(records) == 5000


def test_the_quiet_hour_is_not_uniform(tmp_path: Path) -> None:
    """Control for the test above: a file of one repeated line would pass it and prove nothing.

    A system could score well on a featureless file by noticing there is only one kind of line,
    which is not the behaviour being measured.
    """
    records = generate_quiet_hour()

    messages = {str(record["message"]).split(" ")[0] for record in records}

    assert len(messages) >= 4


def test_the_quiet_hour_is_deterministic(tmp_path: Path) -> None:
    """A fixture that varies between runs makes every score incomparable."""
    first = write_quiet_hour(tmp_path / "a.jsonl").read_bytes()
    second = write_quiet_hour(tmp_path / "b.jsonl").read_bytes()

    assert first == second


# ------------------------------------------------------------------- scoring


def test_a_confident_finding_on_a_quiet_file_fails(quiet_db: ScratchpadDB) -> None:
    """The failure this fixture exists to catch: an answer where there is none to give."""
    quiet_db.write_note(1, "the cache is degraded", {"template_ids": [1]}, "high")

    assert _checks(quiet_db, QUIET_CASE)["invents-no-incident"] is False


def test_a_low_confidence_observation_on_a_quiet_file_passes(quiet_db: ScratchpadDB) -> None:
    """Control for the bar: it is high confidence that fails, not the act of writing a note.

    Describing normal operation is a reasonable thing for an investigation to report, and a
    harness that failed it would be scoring silence rather than judgement.
    """
    quiet_db.write_note(1, "nothing here looks like an incident", {"template_ids": [1]}, "low")

    assert _checks(quiet_db, QUIET_CASE)["invents-no-incident"] is True


def test_writing_nothing_on_a_quiet_file_passes(quiet_db: ScratchpadDB) -> None:
    assert _checks(quiet_db, QUIET_CASE)["invents-no-incident"] is True


def test_the_incident_case_does_not_ask_about_invented_findings(loaded_db: ScratchpadDB) -> None:
    """The check belongs to the negative control alone; on a real incident it is meaningless."""
    assert "invents-no-incident" not in _checks(loaded_db, INCIDENT_CASE)


# ------------------------------------------------------- citation expectations


def test_citing_the_planted_root_cause_passes(loaded_db: ScratchpadDB) -> None:
    root = _template_id(loaded_db, ROOT_CAUSE_MARKER)
    precursor = _template_id(loaded_db, PRECURSOR_MARKER)
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [root, precursor]}, "high")

    checks = _checks(loaded_db, INCIDENT_CASE)

    assert checks[f"cites[{ROOT_CAUSE_MARKER}]"] is True
    assert checks[f"cites[{PRECURSOR_MARKER}]"] is True


def test_omitting_the_precursor_fails_only_that_check(loaded_db: ScratchpadDB) -> None:
    """The failure every run measured before the coverage nudge exhibited.

    Scored per check rather than as one verdict, because "the run failed" cannot tell you the
    root cause was found and the precursor was not.
    """
    root = _template_id(loaded_db, ROOT_CAUSE_MARKER)
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [root]}, "high")

    checks = _checks(loaded_db, INCIDENT_CASE)

    assert checks[f"cites[{ROOT_CAUSE_MARKER}]"] is True
    assert checks[f"cites[{PRECURSOR_MARKER}]"] is False


def test_leading_with_the_red_herring_fails(loaded_db: ScratchpadDB) -> None:
    """350 events against the root cause's 40: anything ranking on volume leads with it."""
    herring = _template_id(loaded_db, RED_HERRING_MARKER)
    loaded_db.write_note(
        1, "the payment gateway is the problem", {"template_ids": [herring]}, "high"
    )

    assert _checks(loaded_db, INCIDENT_CASE)[f"does-not-lead-with[{RED_HERRING_MARKER}]"] is False


def test_mentioning_the_herring_below_the_conclusion_passes(loaded_db: ScratchpadDB) -> None:
    """Control: citing the herring is allowed, resting the conclusion on it is not.

    An investigation that says "these timeouts are separate and pre-existing" has done the right
    thing, and a check that punished it would push the model into ignoring the herring instead
    of dismissing it.
    """
    root = _template_id(loaded_db, ROOT_CAUSE_MARKER)
    herring = _template_id(loaded_db, RED_HERRING_MARKER)
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [root]}, "high")
    loaded_db.write_note(2, "gateway timeouts are separate", {"template_ids": [herring]}, "low")

    assert _checks(loaded_db, INCIDENT_CASE)[f"does-not-lead-with[{RED_HERRING_MARKER}]"] is True


def test_a_fabricated_citation_fails(loaded_db: ScratchpadDB) -> None:
    root = _template_id(loaded_db, ROOT_CAUSE_MARKER)
    loaded_db.write_note(
        1, "pool exhausted", {"template_ids": [root], "log_event_ids": [10**9]}, "high"
    )

    assert _checks(loaded_db, INCIDENT_CASE)["citations-resolve"] is False


def test_a_real_citation_passes(loaded_db: ScratchpadDB) -> None:
    """Control for the check above, which would also pass on a scorer that always said no."""
    root = _template_id(loaded_db, ROOT_CAUSE_MARKER)
    event = loaded_db.get_slice(template_id=root, max_lines=1)[0]["id"]
    loaded_db.write_note(
        1, "pool exhausted", {"template_ids": [root], "log_event_ids": [int(event)]}, "high"
    )

    assert _checks(loaded_db, INCIDENT_CASE)["citations-resolve"] is True


# ------------------------------------------------------------ case definitions


def test_every_case_is_addressable_by_name() -> None:
    """Cases run individually, which is what makes the suite usable on a per-minute quota."""
    for name in case_names():
        assert get_case(name).name == name


def test_an_unknown_case_names_the_known_ones() -> None:
    with pytest.raises(KeyError, match="quiet-hour"):
        get_case("no-such-case")


def test_case_names_are_unique() -> None:
    assert len(case_names()) == len({*case_names()})


def test_every_case_declares_at_least_one_expectation() -> None:
    """A case with nothing to check would pass forever and measure nothing."""
    for case in CASES:
        assert case.must_cite or case.must_not_lead or not case.expects_incident


# ------------------------------------------------------------------- the judge


class _JudgeProvider:
    """Replays one verdict per call and records what it was asked."""

    name = "scripted"
    model = "judge-model"
    supports_task_budget = False

    def __init__(self, *verdicts: str) -> None:
        self.verdicts = list(verdicts)
        self.prompts: list[str] = []

    def converse(self, system, messages, tools=None, max_tokens=8192, task_budget_tokens=None):
        from mistify.llm.base import Turn

        self.prompts.append(messages[0].text)
        return Turn(text=self.verdicts.pop(0), stop_reason="end_turn")


def test_the_judge_fails_a_claim_its_rows_do_not_support(loaded_db: ScratchpadDB) -> None:
    """The failure verify_citations structurally cannot catch: real ids, unrelated rows.

    One measured run cited two genuine log events for a claim about database credentials; both
    were routine INFO lines from other services. Every id resolved.
    """
    from mistify.eval.judge import judge_notes

    unrelated = [int(row["id"]) for row in loaded_db.get_slice(severity="INFO", max_lines=2)]
    loaded_db.write_note(1, "the database pool was exhausted", {"log_event_ids": unrelated}, "high")
    provider = _JudgeProvider('{"verdict": "unsupported", "reason": "rows are unrelated"}')

    judged = judge_notes(loaded_db, provider)

    assert [j.supported for j in judged] == [False]
    assert "the database pool was exhausted" in provider.prompts[0]


def test_the_judge_passes_a_supported_claim(loaded_db: ScratchpadDB) -> None:
    """Control: the judge returns a verdict, it is not a check that always fails."""
    from mistify.eval.judge import judge_notes

    root = _template_id(loaded_db, ROOT_CAUSE_MARKER)
    events = [int(r["id"]) for r in loaded_db.get_slice(template_id=root, max_lines=2)]
    loaded_db.write_note(1, "the pool was exhausted", {"log_event_ids": events}, "high")
    provider = _JudgeProvider('{"verdict": "supported", "reason": "the rows say exactly this"}')

    assert [j.supported for j in judge_notes(loaded_db, provider)] == [True]


def test_an_unreadable_judgement_is_not_a_pass(loaded_db: ScratchpadDB) -> None:
    """A judge that cannot answer must not look like a judge that approved."""
    from mistify.eval.judge import judge_notes

    events = [int(row["id"]) for row in loaded_db.get_slice(max_lines=1)]
    loaded_db.write_note(1, "something", {"log_event_ids": events}, "high")

    judged = judge_notes(loaded_db, _JudgeProvider("I think it is probably fine"))

    assert [j.supported for j in judged] == [False]


def test_notes_citing_only_templates_are_not_judged(loaded_db: ScratchpadDB) -> None:
    """A template is a shape, not a row: asking whether a claim follows from one invites the
    vague agreement this check exists to avoid."""
    from mistify.eval.judge import judge_notes

    root = _template_id(loaded_db, ROOT_CAUSE_MARKER)
    loaded_db.write_note(1, "pool exhausted", {"template_ids": [root]}, "high")
    provider = _JudgeProvider()

    assert judge_notes(loaded_db, provider) == []
    assert provider.prompts == []


# ---------------------------------------------------- templating against truth


def test_perfect_clustering_scores_one() -> None:
    from mistify.eval.templating_eval import grouping_accuracy

    assert grouping_accuracy([1, 1, 2, 2], ["E1", "E1", "E2", "E2"]) == 1.0


def test_relabelling_does_not_matter() -> None:
    """Cluster ids are ours and arbitrary; only the partition is being scored."""
    from mistify.eval.templating_eval import grouping_accuracy

    assert grouping_accuracy([9, 9, 4, 4], ["E1", "E1", "E2", "E2"]) == 1.0


def test_splitting_one_true_cluster_fails_every_line_in_it() -> None:
    """Grouping accuracy is a property of the group, not of a line.

    Half-right is scored as wrong on purpose: a cluster that is nearly correct is exactly the
    failure that reads as success downstream, because the distinction it lost is invisible by
    the time anything queries it.
    """
    from mistify.eval.templating_eval import grouping_accuracy

    assert grouping_accuracy([1, 2, 3, 3], ["E1", "E1", "E2", "E2"]) == 0.5


def test_merging_two_true_clusters_fails_both() -> None:
    from mistify.eval.templating_eval import grouping_accuracy

    assert grouping_accuracy([1, 1, 1, 1], ["E1", "E1", "E2", "E2"]) == 0.0


def test_an_empty_dataset_scores_zero_rather_than_dividing_by_nothing() -> None:
    from mistify.eval.templating_eval import grouping_accuracy

    assert grouping_accuracy([], []) == 0.0


def test_an_unknown_loghub_system_is_refused_before_the_download(tmp_path: Path) -> None:
    """Naming the known set beats a 404 from a URL the caller never typed."""
    from mistify.eval.templating_eval import fetch_loghub

    with pytest.raises(ValueError, match="OpenSSH"):
        fetch_loghub("NotASystem", tmp_path)


def test_a_csv_without_the_annotation_columns_says_so(tmp_path: Path) -> None:
    from mistify.eval.templating_eval import score_dataset

    path = tmp_path / "Broken_2k.log_structured.csv"
    path.write_text("Content,Something\nhello,1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="EventId"):
        score_dataset(path)


def test_scoring_a_tiny_annotated_dataset_end_to_end(tmp_path: Path) -> None:
    """The real templater over a file with a known partition, so the wiring is covered too."""
    from mistify.eval.templating_eval import score_dataset

    path = tmp_path / "Tiny_2k.log_structured.csv"
    rows = ["Content,EventId"]
    rows += [f"Connection closed by 10.0.0.{n} port {n}00,E1" for n in range(1, 9)]
    rows += [f"Accepted password for alice from 10.0.0.{n},E2" for n in range(1, 9)]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    score = score_dataset(path)

    assert score.lines == 16
    assert score.annotated_templates == 2
    assert score.grouping_accuracy == 1.0
    assert score.template_ratio == score.parsed_templates / 2


# ------------------------------------------------------------- the grep baseline


def test_the_baseline_leads_with_the_red_herring(loaded_db: ScratchpadDB) -> None:
    """The comparison the whole fixture was built to make.

    350 payment-gateway timeouts against 40 pool exhaustions: ranking error-level lines by
    frequency picks the herring, which is what the agent has to beat to be worth its calls.
    """
    from mistify.eval.baselines import run_baseline

    outcome = run_baseline(loaded_db, "templated")

    assert outcome.top_template_id == _template_id(loaded_db, RED_HERRING_MARKER)
    checks = _checks(loaded_db, INCIDENT_CASE)
    assert checks[f"does-not-lead-with[{RED_HERRING_MARKER}]"] is False
    assert checks[f"cites[{ROOT_CAUSE_MARKER}]"] is False


def test_the_baseline_greps_the_raw_line_not_the_parsed_message(loaded_db: ScratchpadDB) -> None:
    """Severity lives in a JSON field the message text never mentions.

    Filtering the extracted message found six lines on a file with 396 at ERROR or above --
    a baseline handicapped by a parsing stage it does not have, which flatters the agent.
    """
    from mistify.eval.baselines import run_baseline

    assert run_baseline(loaded_db, "templated").matched_lines > 300


def test_the_baseline_claims_nothing_on_a_quiet_file(quiet_db: ScratchpadDB) -> None:
    """grep wins the negative control outright: no matches, so nothing to assert.

    Worth stating plainly, because it is the one axis where the shell pipeline is unbeatable
    and the agent currently is not.
    """
    from mistify.eval.baselines import run_baseline

    outcome = run_baseline(quiet_db, "templated")

    assert outcome.matched_lines == 0
    assert quiet_db.notes() == []
    assert _checks(quiet_db, QUIET_CASE)["invents-no-incident"] is True


def test_the_naive_baseline_groups_worse_than_the_templated_one(loaded_db: ScratchpadDB) -> None:
    """Control on the two baselines being different opponents.

    Identical-line grouping is defeated by embedded numbers and ids; conceding this project's
    clustering to the baseline is what makes it a fair fight rather than a straw man.
    """
    from mistify.eval.baselines import run_baseline

    naive = run_baseline(loaded_db, "naive")
    templated = run_baseline(loaded_db, "templated")

    assert naive.groups >= templated.groups


def test_an_unknown_baseline_is_refused(loaded_db: ScratchpadDB) -> None:
    from mistify.eval.baselines import run_baseline

    with pytest.raises(ValueError, match="templated"):
        run_baseline(loaded_db, "regex-magic")  # type: ignore[arg-type]


def test_a_stale_scratchpad_cannot_contaminate_a_run(
    tmp_path: Path, config: object, incident_file: Path
) -> None:
    """Scratchpads persist between invocations, and ids repeat.

    An interrupted sweep left notes behind under an id a later sweep reused, and the baseline
    -- which writes exactly one note -- was scored against three findings. A run must start
    from the freshly ingested master and nothing else.
    """
    from mistify.eval.harness import run_case

    case = get_case("quiet-hour")
    stale = config.scratchpad_path("eval-quiet-hour-1")  # type: ignore[attr-defined]
    stale.parent.mkdir(parents=True, exist_ok=True)
    with ScratchpadDB(stale) as db:
        db.create_incident("eval-quiet-hour-1", source="stale")
        db.write_note(99, "a finding from a previous sweep", {"template_ids": [1]}, "high")

    report = run_case(case, config, tmp_path / "work", runs=1, baseline="templated")  # type: ignore[arg-type]

    assert report.runs[0].metrics["notes"] == 0


def test_a_run_whose_critique_fails_is_still_scored(
    tmp_path: Path, config: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failure that nearly threw away a correct answer.

    An OTLP run investigated the incident correctly -- root cause and precursor both cited --
    and then the adversarial call timed out. The whole run was recorded as an error and never
    scored, so a complete 4/4 result had to be recovered by hand afterwards.

    None of the deterministic checks needs the critique: they read notes and citations out of
    the scratchpad, which the loop has already written by the time a later stage fails.
    """
    from mistify.agent import runner
    from mistify.eval.harness import run_case

    def investigate_then_fail(db: ScratchpadDB, cfg: object, adversarial: bool = True) -> None:
        db.write_note(1, "nothing here is an incident", {"template_ids": [1]}, "low")
        raise RuntimeError("Gemini call failed: 504 DEADLINE_EXCEEDED")

    monkeypatch.setattr(runner, "run_investigation", investigate_then_fail)

    report = run_case(get_case("quiet-hour"), config, tmp_path / "work", runs=1)  # type: ignore[arg-type]
    run = report.runs[0]

    assert run.error is not None and "504" in run.error
    assert run.scored, "a run that got as far as writing notes must be graded"
    assert {c.name: c.passed for c in run.checks}["invents-no-incident"] is True


def test_a_run_that_errored_is_not_counted_as_a_full_pass(
    tmp_path: Path, config: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control for the above: scoring a partial run must not turn it into a clean one.

    The stages after the failure never ran, so the report it would have produced does not
    exist. "Correct but incomplete" and "correct" are different facts.
    """
    from mistify.agent import runner
    from mistify.eval.harness import run_case

    def investigate_then_fail(db: ScratchpadDB, cfg: object, adversarial: bool = True) -> None:
        db.write_note(1, "nothing here is an incident", {"template_ids": [1]}, "low")
        raise RuntimeError("boom")

    monkeypatch.setattr(runner, "run_investigation", investigate_then_fail)

    report = run_case(get_case("quiet-hour"), config, tmp_path / "work", runs=1)  # type: ignore[arg-type]

    assert all(c.passed for c in report.runs[0].checks)
    assert report.runs[0].passed is False
    assert report.pass_rate == "0/1"


def test_a_run_that_never_reached_the_scratchpad_is_not_scored(
    tmp_path: Path, config: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control on `scored`: an empty check list means "not graded", not "graded and failed"."""
    from mistify.eval import harness

    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("ingest failed")

    monkeypatch.setattr(harness, "ingest", explode)

    report = harness.run_case(get_case("quiet-hour"), config, tmp_path / "work", runs=1)  # type: ignore[arg-type]

    assert report.runs[0].error is not None
    assert report.runs[0].scored is False


def test_each_run_is_reported_under_its_own_incident_id(tmp_path: Path, config: object) -> None:
    """The copy carries the master's identity until it is retagged.

    Every report rendered from a run named `...-master`, so a saved report misidentified which
    run produced it -- the sort of thing that is trusted and then quietly misfiles a result.
    """
    from mistify.eval.harness import run_case

    reports = tmp_path / "out"
    report = run_case(
        get_case("quiet-hour"),
        config,
        tmp_path / "work",
        runs=1,  # type: ignore[arg-type]
        baseline="templated",
        report_dir=reports,
    )

    written = Path(report.runs[0].report_path or "")
    assert written.name == "eval-quiet-hour-1.md"
    assert "# Incident report: eval-quiet-hour-1" in written.read_text(encoding="utf-8")


def test_a_sweep_keeps_the_report_behind_every_score(tmp_path: Path, config: object) -> None:
    """The checks say whether a run passed; only the report says what it concluded.

    A sweep that kept just the score could not be re-read afterwards to find out why, which is
    exactly what happened to this project's first nine runs.
    """
    from mistify.eval.harness import run_case

    reports = tmp_path / "out"
    report = run_case(
        get_case("pool-exhaustion"),
        config,
        tmp_path / "work",
        runs=1,  # type: ignore[arg-type]
        baseline="templated",
        report_dir=reports,
    )

    body = Path(report.runs[0].report_path or "").read_text(encoding="utf-8")
    assert "## What was found" in body
    assert "grep baseline" in body

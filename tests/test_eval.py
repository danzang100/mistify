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

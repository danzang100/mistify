"""LogDx-CI case loading, and the two rules that decide what gets checked.

The fixtures here are hand-built, which is normally the thing this project refuses to do for an
external format. It is defensible for exactly one reason: `test_the_real_schema_still_parses`
fetches a real case and asserts the same fields are there. Without that test these fixtures
would be a record of what the schema looked like on the day somebody read it, and a corpus that
moved would leave every test here passing against a shape that no longer exists.

That test needs the network, so it is opt-in rather than probed for: an unrelated HTTP call on
every test run is a slow way to discover that a laptop is on a train.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mistify.eval.logdx import (
    LOGDX_CASES,
    LOGDX_SPLITS,
    fetch_logdx_case,
    load_logdx_case,
    logdx_case_ids,
    split_of,
)

#: Shaped exactly like `cases/dev/pytest-pandas-001/ground_truth.json`, trimmed. Every field
#: read by the loader appears, including the two that decide whether a signal becomes a marker.
GROUND_TRUTH = {
    "root_cause": {
        "summary": "NumPy nightly raises DeprecationWarning for the generic timedelta unit.",
        "category": "test_assertion",
    },
    "required_signals": [
        {
            "type": "exception",
            "value": "DeprecationWarning: The 'generic' unit for NumPy timedelta is deprecated",
            "importance": "critical",
        },
        {
            "type": "stack_location",
            "file": "pandas/tests/arrays/masked/test_indexing.py",
            "line": 43,
            "importance": "critical",
        },
        # Distinctive and long, and it used to be dropped by a type allowlist.
        {
            "type": "compile_error",
            "value": 'error: Module has no attribute "is_null"  [attr-defined]',
            "importance": "critical",
        },
        # Present in the log, but only once its terminal colour codes are ignored. Ground truth
        # is transcribed as a person reads a log; the file is written for a terminal.
        {
            "type": "step_name",
            "value": "tests-build::macros compile_fail_full",
            "importance": "critical",
        },
        # Not log text at all: its value occurs in a thousand unrelated lines.
        {"type": "exit_code", "value": "1", "importance": "critical"},
        # Too short to identify a line, whatever its type.
        {"type": "package", "value": "numpy", "importance": "critical"},
        # Real evidence, but requiring every one turns citation into completeness.
        {"type": "step_name", "value": "===== ERRORS =====", "importance": "important"},
    ],
    "expected_diagnosis": {
        "must_mention": ["pytest", "DeprecationWarning"],
        "must_not_claim": ["network failure", "out of memory or timeout"],
    },
}

CASE_JSON = {
    "case_id": "pytest-pandas-001",
    "repo": "pandas-dev/pandas",
    "framework": "pytest",
    "failure_category": "test_assertion",
    "line_count": 3788,
}


@pytest.fixture
def case_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "dev" / "pytest-pandas-001"
    directory.mkdir(parents=True)
    (directory / "case.json").write_text(json.dumps(CASE_JSON), encoding="utf-8")
    (directory / "ground_truth.json").write_text(json.dumps(GROUND_TRUTH), encoding="utf-8")
    # The log has to contain its own ground truth. A fixture whose `raw.log` did not is exactly
    # what the presence check exists for: a marker the log does not contain produces a check
    # that can only fail, and it fails looking like a wrong answer from the investigation.
    #
    # The `compile_fail_full` line carries ANSI colour codes, as a real CI log writes it, so the
    # check is exercised on the shape that broke first -- 71.9% of the lines in one real tokio
    # log are wrapped like this.
    esc = chr(27)
    (directory / "raw.log").write_text(
        "\n".join(
            [
                "DeprecationWarning: The 'generic' unit for NumPy timedelta is deprecated",
                "  File pandas/tests/arrays/masked/test_indexing.py, line 43",
                'error: Module has no attribute "is_null"  [attr-defined]',
                f"{esc}[35;1mtests-build::macros{esc}[0m {esc}[34;1mcompile_fail_full{esc}[0m",
                "numpy 1.2.3",
                "===== ERRORS =====",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return directory


# --------------------------------------------------------------- the corpus index


def test_every_split_is_named_and_the_corpus_is_35_cases() -> None:
    """The count is the published one. A silent drift in this table is a silent drift in
    what "the LogDx-CI score" means."""
    assert len(logdx_case_ids()) == 35
    assert set(LOGDX_SPLITS) == set(LOGDX_CASES)


def test_a_case_resolves_to_its_split() -> None:
    assert split_of("pytest-pandas-001") == "dev"
    assert split_of("tsc-typescript-001") == "holdout"
    assert split_of("moby-buildx-bake-v2-001") == "v2/dev"


def test_an_unknown_case_is_refused_before_any_download() -> None:
    """Named in a table so a typo is an error rather than a 404 after a wait."""
    with pytest.raises(ValueError, match="unknown LogDx-CI case"):
        split_of("no-such-case-001")


def test_an_unknown_split_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown split"):
        logdx_case_ids("not-a-split")


# --------------------------------------------------------------- what becomes a marker


def test_distinctive_signals_become_citation_markers(case_dir: Path) -> None:
    loaded = load_logdx_case(case_dir)
    assert "DeprecationWarning: The 'generic' unit for NumPy timedelta is deprecated" in (
        loaded.markers
    )
    # `stack_location` carries its string in `file`, not in `value`.
    assert "pandas/tests/arrays/masked/test_indexing.py" in loaded.markers


def test_a_long_compile_error_is_a_marker(case_dir: Path) -> None:
    """The case that broke the first design.

    An allowlist of "types worth keeping" dropped `compile_error`, whose values run to a median
    of 104 characters across the corpus and are the most distinctive strings in it. An allowlist
    has to be right about a vocabulary it does not control.
    """
    assert (
        'error: Module has no attribute "is_null"  [attr-defined]'
        in load_logdx_case(case_dir).markers
    )


def test_an_exit_code_is_never_a_marker(case_dir: Path) -> None:
    """Its value is `"1"`. A citation check on it passes as soon as anything is cited.

    A check that cannot fail is worse than no check: it puts a passing row on a scorecard
    while measuring nothing, and the scorecard is the whole deliverable of this phase.
    """
    loaded = load_logdx_case(case_dir)
    assert "1" not in loaded.markers
    assert any("exit_code" in dropped for dropped in loaded.dropped_signals)


def test_a_short_value_is_not_a_marker_whatever_its_type(case_dir: Path) -> None:
    """The backstop that needs no knowledge of the type vocabulary."""
    loaded = load_logdx_case(case_dir)
    assert "numpy" not in loaded.markers
    assert any("too short" in dropped for dropped in loaded.dropped_signals)


def test_dropped_signals_say_why_they_were_dropped(case_dir: Path) -> None:
    """A signal silently skipped is a check the scorecard implies and never ran."""
    dropped = load_logdx_case(case_dir).dropped_signals
    assert any("not log text" in d for d in dropped)
    assert any("too short" in d for d in dropped)


def test_only_critical_signals_are_required(case_dir: Path) -> None:
    """Requiring the `important` ones too turns a citation check into a completeness check.

    An investigation that found the root cause and cited four of five supporting lines has not
    failed, and scoring it as a failure would push the next change toward citing everything.
    """
    assert "===== ERRORS =====" not in load_logdx_case(case_dir).markers


def test_the_expected_diagnosis_is_carried_through(case_dir: Path) -> None:
    loaded = load_logdx_case(case_dir)
    assert loaded.must_mention == ("pytest", "DeprecationWarning")
    assert loaded.must_not_claim == ("network failure", "out of memory or timeout")
    assert loaded.repo == "pandas-dev/pandas"
    assert loaded.line_count == 3788


def test_the_eval_case_points_at_the_downloaded_log(case_dir: Path, tmp_path: Path) -> None:
    """`source` ignores the run directory: the corpus file is read-only and shared, and
    copying a 200k-line log per run buys nothing."""
    from mistify.eval.cases import EvalCase

    loaded = load_logdx_case(case_dir)
    case = EvalCase(
        name=f"logdx-{loaded.case_id}",
        summary="",
        source=lambda _d, p=loaded.log_path: p,  # type: ignore[misc]
        must_cite=loaded.markers,
        external=True,
    )
    assert case.source(tmp_path / "elsewhere") == case_dir / "raw.log"
    assert case.external


# --------------------------------------------------------------- against the real corpus


@pytest.mark.skipif(
    os.environ.get("MISTIFY_NETWORK_TESTS") != "1",
    reason="set MISTIFY_NETWORK_TESTS=1 to fetch a real LogDx-CI case",
)
def test_the_real_schema_still_parses(tmp_path: Path) -> None:
    """The control on every fixture above.

    Those fixtures were transcribed from a real case once, and a transcription cannot notice
    when the thing it was copied from changes. If LogDx-CI renames `required_signals`, moves
    `expected_diagnosis`, or stops marking signals `critical`, every other test in this file
    keeps passing against a shape the corpus no longer has -- and the eval quietly scores
    nothing at all.
    """
    loaded = load_logdx_case(fetch_logdx_case("pytest-pandas-001", tmp_path))

    assert loaded.log_path.exists() and loaded.log_path.stat().st_size > 0
    assert loaded.repo == "pandas-dev/pandas"
    assert loaded.root_cause
    assert loaded.markers, "no critical signal survived the marker rules"
    assert loaded.must_mention and loaded.must_not_claim


def test_a_marker_the_log_does_not_contain_is_dropped(case_dir: Path) -> None:
    """Ground truth that names a line the file does not have makes an unscorable check.

    Measured on a real case: `396 tests run: 395 passed, 1 failed, 1 skipped` could not be
    found in the log it annotates, and the resulting check failed looking exactly like a wrong
    answer from the investigation. A scorecard that counts its own corpus defects against the
    model is reporting the wrong number.
    """
    ground_truth = json.loads((case_dir / "ground_truth.json").read_text(encoding="utf-8"))
    ground_truth["required_signals"].append(
        {
            "type": "assertion",
            "value": "this sentence is nowhere in the log",
            "importance": "critical",
        }
    )
    (case_dir / "ground_truth.json").write_text(json.dumps(ground_truth), encoding="utf-8")

    loaded = load_logdx_case(case_dir)

    assert "this sentence is nowhere in the log" not in loaded.markers
    assert any("absent from the log" in d for d in loaded.dropped_signals)


def test_a_marker_wrapped_in_ansi_codes_is_kept(case_dir: Path) -> None:
    """The control on the test above, and the harder half.

    A CI log is written for a terminal, so ground truth transcribed as a person reads it says
    `tests-build::macros compile_fail_full` where the file says the same thing with colour
    codes between the words. Comparing literally drops a marker that is genuinely present --
    which would be the same defect as keeping an absent one, in the other direction.
    """
    loaded = load_logdx_case(case_dir)

    assert "tests-build::macros compile_fail_full" in loaded.markers
    assert not any("compile_fail_full" in d for d in loaded.dropped_signals)

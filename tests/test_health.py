"""The pre-flight log health check.

Every test that asserts a check stays quiet is paired with one where the same check fires on the
same kind of input, so none of the silences here can be the silence of a check that never runs.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from mistify.cli import cli
from mistify.common.config import HealthConfig, MistifyConfig
from mistify.eval.fixtures import generate_incident, write_mixed_timezone_bundle
from mistify.health import (
    HealthReport,
    HealthStatus,
    _unmasked_ids,
    check_health,
)
from mistify.metrics import (
    HEALTH_CHECK,
    HEALTH_OVERRIDDEN,
    HEALTH_STATUS,
    TEMPLATING_COVERAGE,
    MetricView,
)
from mistify.pipeline import ingest
from mistify.report.generator import generate_report
from mistify.scratchpad.db import ScratchpadDB

_START = datetime(2026, 8, 30, 14, 0, 0, tzinfo=UTC)


def _check(report: HealthReport, name: str) -> HealthStatus:
    return next(c.status for c in report.checks if c.name == name)


def _message(report: HealthReport, name: str) -> str:
    return next(c.message for c in report.checks if c.name == name)


def _ingest(source: Path, config: MistifyConfig, incident_id: str) -> HealthReport:
    result = ingest(source, config, incident_id=incident_id)
    assert result.health is not None
    return result.health


@pytest.fixture(scope="module")
def bundles(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """The mixed-timezone bundle both ways: local time with no offset, and with one."""
    root = tmp_path_factory.mktemp("bundles")
    return {
        "naive": write_mixed_timezone_bundle(root / "naive", "naive"),
        "explicit": write_mixed_timezone_bundle(root / "explicit", "explicit"),
    }


# ------------------------------------------------------------------- the control


def test_the_sample_incident_is_healthy(ingested: object, loaded_db: ScratchpadDB) -> None:
    """The control every other test leans on: the sample incident passes every check."""
    report = check_health(loaded_db, HealthConfig())
    assert report.status == HealthStatus.OK, report.lines()
    assert not report.failed and not report.warned


def test_ingest_records_the_verdict_it_returns(loaded_db: ScratchpadDB) -> None:
    view = MetricView(loaded_db.metrics())
    assert view.text(HEALTH_STATUS) == "ok"
    assert all(member in view for member in HEALTH_CHECK.all_members())


# ------------------------------------------------------------------ F3: timezones


def test_a_source_logging_local_time_without_an_offset_fails(
    bundles: dict[str, Path], config: MistifyConfig
) -> None:
    report = _ingest(bundles["naive"], config, "tz-naive")

    assert report.status == HealthStatus.FAIL
    assert [c.name for c in report.failed] == ["timezones"]
    message = _message(report, "timezones")
    assert "`payment-service` appears 5h30m later" in message
    assert "no UTC offset" in message


def test_the_same_local_times_with_an_offset_pass(
    bundles: dict[str, Path], config: MistifyConfig
) -> None:
    """The control for the failure above: identical instants, written with `+05:30`."""
    report = _ingest(bundles["explicit"], config, "tz-explicit")
    assert _check(report, "timezones") == HealthStatus.OK
    assert report.status == HealthStatus.OK


def test_skew_without_notation_evidence_warns_rather_than_fails(
    bundles: dict[str, Path], make_config: Callable[..., MistifyConfig]
) -> None:
    """With no raw lines kept, the alignment is the only signal, and one signal only warns."""
    blind = _ingest(bundles["naive"], make_config(scratchpad={"store_raw": False}), "tz-blind")
    assert _check(blind, "timezones") == HealthStatus.WARN
    assert "raw lines were not kept" in _message(blind, "timezones")


def test_naive_timestamps_beside_zoned_ones_warn_even_without_skew(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """Payments writes UTC without saying so: no skew to measure, but an assumption to state."""
    bundle = tmp_path / "naive-utc"
    bundle.mkdir()
    storefront, payments = [], []
    for record in generate_incident(total_lines=3000, seed=7):
        if record["service"] == "payment-service":
            payments.append(json.dumps({**record, "timestamp": str(record["timestamp"])[:-1]}))
        else:
            storefront.append(json.dumps(record))
    (bundle / "storefront.jsonl").write_text("\n".join(storefront) + "\n", encoding="utf-8")
    (bundle / "payments.jsonl").write_text("\n".join(payments) + "\n", encoding="utf-8")

    report = _ingest(bundle, config, "tz-notation")
    assert _check(report, "timezones") == HealthStatus.WARN
    assert "`payment-service` write timestamps with no UTC offset" in _message(report, "timezones")


def test_refusal_can_be_turned_off_in_config(
    bundles: dict[str, Path], make_config: Callable[..., MistifyConfig]
) -> None:
    lenient = make_config(health={"fail_on_corroborated_skew": False})
    report = _ingest(bundles["naive"], lenient, "tz-lenient")
    assert _check(report, "timezones") == HealthStatus.WARN


# ----------------------------------------------------------------- F3: timestamps


def test_a_file_with_no_readable_time_warns(tmp_path: Path, config: MistifyConfig) -> None:
    source = tmp_path / "no-time.log"
    source.write_text(
        "".join(f"worker {i % 7} finished batch {i} with status ok\n" for i in range(300)),
        encoding="utf-8",
    )
    report = _ingest(source, config, "no-time")
    assert _check(report, "timestamps") == HealthStatus.WARN
    assert "No timestamp could be read from any line" in _message(report, "timestamps")


def test_timestamp_coverage_can_be_made_to_refuse(
    tmp_path: Path, make_config: Callable[..., MistifyConfig]
) -> None:
    source = tmp_path / "no-time.log"
    source.write_text("".join(f"worker {i % 7} finished\n" for i in range(300)), encoding="utf-8")
    strict = make_config(health={"timestamp_coverage_fail_below": 0.5})
    report = _ingest(source, strict, "no-time-strict")
    assert _check(report, "timestamps") == HealthStatus.FAIL


# --------------------------------------------------------------- F2: templating


def _apache(path: Path, days: tuple[str, ...]) -> Path:
    """Apache error-log lines in Loghub's shape, with the weekday in the header."""
    lines = []
    for i in range(400):
        day = days[i % len(days)]
        stamp = f"[{day} Dec 0{4 + i % len(days)} 04:{i % 60:02d}:44 2005]"
        if i % 3 == 0:
            lines.append(f"{stamp} [notice] jk2_init() Found child {6000 + i} in scoreboard slot 7")
        elif i % 3 == 1:
            lines.append(
                f"{stamp} [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties"
            )
        else:
            lines.append(f"{stamp} [error] mod_jk child workerEnv in error state {i % 9}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_a_weekday_in_the_header_splitting_every_message_warns(
    tmp_path: Path, config: MistifyConfig
) -> None:
    """The mechanism behind Loghub Apache's pipeline grouping accuracy of 0.000."""
    report = _ingest(_apache(tmp_path / "two-days.log", ("Sun", "Mon")), config, "split")
    assert _check(report, "split_templates") == HealthStatus.WARN


def test_the_same_log_on_one_day_is_not_split(tmp_path: Path, config: MistifyConfig) -> None:
    report = _ingest(_apache(tmp_path / "one-day.log", ("Sun",)), config, "unsplit")
    assert _check(report, "split_templates") == HealthStatus.OK


def test_templates_carrying_a_literal_identifier_warn() -> None:
    config = HealthConfig()
    flooded = [
        (1, "INFO [req-38101a0b-2096-447d-96ea-a692162415ae] GET <*> status: <*>", 40),
        (2, "INFO instance 54fadb412c4e40cdbaed9335e4c35a9e spawned in <*> seconds", 40),
        (3, "INFO heartbeat ok", 20),
    ]
    masked = [
        (1, "INFO [<*>] GET <*> status: <*>", 40),
        (2, "INFO instance <*> spawned in <*> seconds", 40),
        (3, "INFO heartbeat ok", 20),
    ]
    assert _unmasked_ids(flooded, config)[0].status == HealthStatus.WARN
    assert _unmasked_ids(masked, config)[0].status == HealthStatus.OK


def _ssh(path: Path, folded: bool) -> Path:
    """Logins that succeed and fail. `folded` writes both in one shape, as sshd does.

    The outcome sits after the first two tokens on purpose: Drain3 routes on those, so a word
    there can never be folded, and it was a header ahead of it that let Loghub OpenSSH's
    `Failed` and `Accepted` share `<*> password for`.
    """
    records = []
    for i in range(240):
        ts = (_START + timedelta(seconds=i * 7)).isoformat().replace("+00:00", "Z")
        who = f"user{i % 11} from host{i % 5} port {4000 + i}"
        if i % 4:
            message = f"Password check for {who}: ok"
        elif folded:
            message = f"Password check for {who}: failed"
        else:
            # A different length is a different Drain3 tree branch: never folded in.
            message = f"Password check for {who}: failed after 3 attempts"
        records.append({"timestamp": ts, "level": "INFO", "service": "sshd", "message": message})
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def test_failures_folded_into_a_success_template_warn(
    tmp_path: Path, config: MistifyConfig
) -> None:
    report = _ingest(_ssh(tmp_path / "folded.jsonl", folded=True), config, "folded")
    assert _check(report, "hidden_failures") == HealthStatus.WARN


def test_failures_in_their_own_template_do_not(tmp_path: Path, config: MistifyConfig) -> None:
    report = _ingest(_ssh(tmp_path / "apart.jsonl", folded=False), config, "apart")
    assert _check(report, "hidden_failures") == HealthStatus.OK


def test_lost_template_coverage_refuses(loaded_db: ScratchpadDB) -> None:
    assert _check(check_health(loaded_db, HealthConfig()), "template_coverage") == HealthStatus.OK
    loaded_db.record(TEMPLATING_COVERAGE, 0.82)
    report = check_health(loaded_db, HealthConfig())
    assert _check(report, "template_coverage") == HealthStatus.FAIL
    assert "18.0% of events have no reachable template" in report.refusal()


def test_an_empty_scratchpad_refuses(db: ScratchpadDB, loaded_db: ScratchpadDB) -> None:
    assert _check(check_health(loaded_db, HealthConfig()), "events") == HealthStatus.OK
    report = check_health(db, HealthConfig())
    assert report.status == HealthStatus.FAIL
    assert [c.name for c in report.failed] == ["events"]


# ------------------------------------------------------------------- F5: multi-line


def _java(path: Path, traces: bool) -> Path:
    lines = []
    for i in range(600):
        second = f"{i // 60:02d}:{i % 60:02d}"
        lines.append(f"2026-08-30 14:{second},123 INFO [main] c.e.Orders: placed order {i}")
        if traces and i % 40 == 0:
            lines.append(f"2026-08-30 14:{second},124 ERROR [main] c.e.Orders: order {i} failed")
            lines.append("java.lang.IllegalStateException: pool exhausted")
            lines.append("\tat com.example.db.Pool.acquire(Pool.java:88)")
            lines.append("\tat com.example.Orders.place(Orders.java:41)")
            lines.append("\t... 12 more")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_stack_frames_read_one_per_line_warn(tmp_path: Path, config: MistifyConfig) -> None:
    report = _ingest(_java(tmp_path / "traces.log", traces=True), config, "traces")
    assert _check(report, "multiline") == HealthStatus.WARN


def test_the_same_log_without_traces_does_not(tmp_path: Path, config: MistifyConfig) -> None:
    report = _ingest(_java(tmp_path / "plain.log", traces=False), config, "plain")
    assert _check(report, "multiline") == HealthStatus.OK


# ------------------------------------------------------------------------ the gate


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _cli_ingest(runner: CliRunner, source: Path, incident: str, config_file: Path) -> None:
    result = runner.invoke(
        cli,
        [
            "ingest",
            "--source",
            str(source),
            "--incident-id",
            incident,
            "--config",
            str(config_file),
        ],
    )
    assert result.exit_code == 0, result.output


def test_investigate_refuses_to_call_a_model_on_a_failed_check(
    runner: CliRunner, bundles: dict[str, Path], make_config_file: Callable[..., Path]
) -> None:
    config_file = make_config_file()
    _cli_ingest(runner, bundles["naive"], "gate", config_file)
    result = runner.invoke(
        cli, ["investigate", "--incident-id", "gate", "--config", str(config_file)]
    )

    assert result.exit_code != 0
    assert "the pre-flight health check failed, so no model was called" in result.output
    assert "[timezones]" in result.output
    # Refused before a provider was built: had it got that far, the missing key would be the
    # error instead.
    assert "GEMINI_API_KEY" not in result.output


def test_investigate_goes_on_to_the_model_when_the_check_passes(
    runner: CliRunner, bundles: dict[str, Path], make_config_file: Callable[..., Path]
) -> None:
    """The control: a healthy bundle reaches provider construction, which then wants a key."""
    config_file = make_config_file()
    _cli_ingest(runner, bundles["explicit"], "gate-ok", config_file)
    result = runner.invoke(
        cli, ["investigate", "--incident-id", "gate-ok", "--config", str(config_file)]
    )

    assert result.exit_code != 0
    assert "health  OK" in result.output
    assert "GEMINI_API_KEY" in result.output
    assert "no model was called" not in result.output


def test_ignore_health_passes_the_gate_and_is_recorded(
    runner: CliRunner, bundles: dict[str, Path], make_config_file: Callable[..., Path]
) -> None:
    config_file = make_config_file()
    _cli_ingest(runner, bundles["naive"], "override", config_file)
    result = runner.invoke(
        cli,
        [
            "investigate",
            "--incident-id",
            "override",
            "--ignore-health",
            "--config",
            str(config_file),
        ],
    )

    assert "GEMINI_API_KEY" in result.output  # past the gate, stopped by the missing key
    config = MistifyConfig.model_validate(yaml.safe_load(config_file.read_text(encoding="utf-8")))
    with ScratchpadDB(config.scratchpad_path("override")) as db:
        assert MetricView(db.metrics()).flag(HEALTH_OVERRIDDEN) is True
        assert "run anyway" in generate_report(db)


def test_the_skeleton_is_never_refused(
    runner: CliRunner, bundles: dict[str, Path], make_config_file: Callable[..., Path]
) -> None:
    """It calls no model, so there is nothing for the gate to protect."""
    config_file = make_config_file()
    _cli_ingest(runner, bundles["naive"], "skel", config_file)
    result = runner.invoke(
        cli,
        [
            "investigate",
            "--incident-id",
            "skel",
            "--investigator",
            "skeleton",
            "--config",
            str(config_file),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "health  FAIL" in result.output


def test_run_refuses_before_the_loop_and_keeps_the_ingest(
    runner: CliRunner, bundles: dict[str, Path], make_config_file: Callable[..., Path]
) -> None:
    config_file = make_config_file()
    result = runner.invoke(
        cli,
        [
            "run",
            "--source",
            str(bundles["naive"]),
            "--incident-id",
            "run-gate",
            "--config",
            str(config_file),
        ],
    )
    assert result.exit_code != 0
    assert "[timezones]" in result.output
    assert "The ingest is kept" in result.output
    assert "GEMINI_API_KEY" not in result.output


def test_the_health_command_calls_no_model_and_exits_on_failure(
    runner: CliRunner, bundles: dict[str, Path], make_config_file: Callable[..., Path]
) -> None:
    config_file = make_config_file()
    _cli_ingest(runner, bundles["naive"], "cmd-bad", config_file)
    _cli_ingest(runner, bundles["explicit"], "cmd-ok", config_file)

    bad = runner.invoke(cli, ["health", "--incident-id", "cmd-bad", "--config", str(config_file)])
    good = runner.invoke(cli, ["health", "--incident-id", "cmd-ok", "--config", str(config_file)])

    assert bad.exit_code == 1
    assert "FAIL  timezones" in bad.output
    assert good.exit_code == 0, good.output
    assert "health  OK" in good.output


# ---------------------------------------------------------------------- the report


def test_the_report_leads_with_the_check(
    bundles: dict[str, Path], config: MistifyConfig, loaded_db: ScratchpadDB
) -> None:
    ingest(bundles["naive"], config, incident_id="report-bad")
    with ScratchpadDB(config.scratchpad_path("report-bad")) as db:
        bad = generate_report(db)
    good = generate_report(loaded_db)

    assert bad.index("## Log health") < bad.index("## What was found")
    assert "**FAIL**" in bad and "**FAIL - timezones.**" in bad
    assert "**OK**" in good and "**FAIL" not in good
    # The sentence is in the health section and nowhere else: not again in the appendix tables.
    assert bad.count("appears 5h30m later") == 1


def test_a_warning_the_check_states_is_not_repeated(tmp_path: Path, config: MistifyConfig) -> None:
    """The dominant-template warning, said by the health section and not again below it."""
    records = []
    for i in range(500):
        ts = (_START + timedelta(seconds=i * 5)).isoformat().replace("+00:00", "Z")
        message = f"Heartbeat ok, uptime {1000 + i}s" if i % 5 else f"Job {i} used {i % 9} MB"
        records.append({"timestamp": ts, "level": "INFO", "service": "svc", "message": message})
    source = tmp_path / "dominant.jsonl"
    source.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    ingest(source, config, incident_id="dominant")

    with ScratchpadDB(config.scratchpad_path("dominant")) as db:
        text = generate_report(db)
        assert "**WARN - dominant_template.**" in text
        assert "One template accounts for" not in text

        # Control: a verdict that did not fire must never silence the report's own warning.
        db.record(HEALTH_CHECK.member("dominant_template"), "ok: pretended to pass")
        assert "One template accounts for" in generate_report(db)


def test_a_scratchpad_from_before_the_check_says_so(
    ingested: object, loaded_db: ScratchpadDB
) -> None:
    assert "No pre-flight health check was recorded" not in generate_report(loaded_db)
    connection = sqlite3.connect(loaded_db.path)
    connection.execute("DELETE FROM run_metadata WHERE stage = 'health'")
    connection.commit()
    connection.close()
    assert "No pre-flight health check was recorded" in generate_report(loaded_db)


# ------------------------------------------------------------------ review fixes, 2026-09-26


def _parse_verdict(db: ScratchpadDB, errors: int) -> str:
    from mistify.metrics import INGEST_LINES_READ, INGEST_PARSE_ERRORS

    db.record_many([(INGEST_PARSE_ERRORS, errors), (INGEST_LINES_READ, 100_000)])
    # Raised from its default of 0, under which any parse error warns: the false "every line
    # parsed" could only be said once a user had set a threshold above zero.
    config = HealthConfig(parse_error_rate_warn_above=0.01)
    check = next(c for c in check_health(db, config).checks if c.name == "parse_errors")
    assert check.status == HealthStatus.OK, "under the threshold either way"
    return check.message


def test_a_few_parse_errors_under_the_threshold_are_still_named(loaded_db: ScratchpadDB) -> None:
    """Found in review: 40 skipped lines were reported as "Every line parsed."."""
    message = _parse_verdict(loaded_db, 40)
    assert "40 of 100,000 lines" in message
    assert "Every line parsed" not in message


def test_no_parse_errors_says_every_line_parsed(loaded_db: ScratchpadDB) -> None:
    """The control: the sentence the first test rules out is still said when it is true."""
    assert _parse_verdict(loaded_db, 0) == "Every line parsed."


def test_sampled_text_scan_reads_exactly_the_ids_divisible_by_the_stride(
    loaded_db: ScratchpadDB,
) -> None:
    """The seek-based sample must pick the same rows the full-scan filter did."""
    import re as regex

    pattern = {"any": regex.compile(r".")}
    for stride in (1, 3, 7):
        got = loaded_db.text_matches_by_template(pattern, stride=stride)
        expected: dict[int, int] = {}
        for event_id, template_id in loaded_db._conn.execute(
            "SELECT id, template_id FROM log_events"
        ):
            if event_id % stride == 0:
                expected[int(template_id)] = expected.get(int(template_id), 0) + 1
        assert {t: c["events"] for t, c in got.items()} == expected, stride


def test_raw_samples_match_the_first_lines_of_every_source(loaded_db: ScratchpadDB) -> None:
    """One early-stopping pass must return what a query per source returned."""
    sources = [r[0] for r in loaded_db._conn.execute("SELECT DISTINCT source FROM log_events")]
    assert len(sources) > 1, "the control needs several sources to be a test of anything"
    for per_source in (1, 5, 200):
        expected = {
            str(source): [
                str(r[0])
                for r in loaded_db._conn.execute(
                    "SELECT raw FROM log_events WHERE source IS ? AND raw IS NOT NULL"
                    " ORDER BY id LIMIT ?",
                    (source, per_source),
                )
            ]
            for source in sources
        }
        assert loaded_db.raw_samples(per_source) == expected, per_source

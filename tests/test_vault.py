"""Reversible redaction vault: storage, redactor integration, and the file boundary.

The boundary tests near the bottom are the point of the feature's design, not incidental
coverage: the vault is only safe to offer at all because it cannot be reached from the
investigator's read-only SQL channel.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from mistify.cli import cli
from mistify.common.config import MistifyConfig
from mistify.common.models import LogRecord, parse_timestamp
from mistify.redaction.redactor import Redactor
from mistify.redaction.vault import RedactionVault
from mistify.scratchpad.db import ReadOnlyViolation, ScratchpadDB

INCIDENT = "vault-incident"


@pytest.fixture
def vault(tmp_path: Path) -> RedactionVault:
    with RedactionVault(tmp_path / "vault.sqlite") as store:
        yield store


def _record(raw: str, message: str | None = None, **fields: object) -> LogRecord:
    return LogRecord(
        ts=parse_timestamp("2026-08-30T14:22:01Z"),
        source="checkout-service",
        severity="ERROR",
        raw=raw,
        message=message if message is not None else raw,
        fields=dict(fields),
        format="json_lines",
    )


# ------------------------------------------------------------------ storage


def test_record_and_reveal_round_trip(vault: RedactionVault) -> None:
    vault.record("[EMAIL:a7f2]", "email", "ana.silva@northwind-retail.com")
    assert vault.reveal("[EMAIL:a7f2]") == "ana.silva@northwind-retail.com"


def test_unknown_token_reveals_nothing(vault: RedactionVault) -> None:
    """None, not an exception: "never seen" is an ordinary answer for an operator typing a
    token from a report that predates the vault being enabled."""
    assert vault.reveal("[EMAIL:0000]") is None


def test_recording_the_same_pair_twice_is_idempotent(vault: RedactionVault) -> None:
    """The redactor calls `record` once per match, so repeats are the normal case."""
    for _ in range(5):
        vault.record("[IPV4:1234]", "ipv4", "10.42.7.19")
    assert vault.count() == 1
    assert vault.reveal("[IPV4:1234]") == "10.42.7.19"


def test_entries_filter_by_entity(vault: RedactionVault) -> None:
    vault.record("[EMAIL:a7f2]", "email", "ana.silva@northwind-retail.com")
    vault.record("[IPV4:1234]", "ipv4", "10.42.7.19")
    vault.record("[IPV4:5678]", "ipv4", "192.168.14.203")

    addresses = vault.entries(entity="ipv4")
    # Ordered by token, so a dump is stable across runs.
    assert [row["value"] for row in addresses] == ["10.42.7.19", "192.168.14.203"]
    assert {row["entity"] for row in addresses} == {"ipv4"}
    assert len(vault.entries(entity="email")) == 1
    assert vault.entries(entity="ssn") == []


def test_entries_returns_every_column(vault: RedactionVault) -> None:
    vault.record("[EMAIL:a7f2]", "email", "ana.silva@northwind-retail.com")
    (row,) = vault.entries()
    assert set(row) == {"token", "entity", "value", "first_seen"}
    assert row["first_seen"].endswith("Z")


def test_count_tracks_distinct_tokens(vault: RedactionVault) -> None:
    assert vault.count() == 0
    vault.record("[EMAIL:a7f2]", "email", "ana.silva@northwind-retail.com")
    vault.record("[IPV4:1234]", "ipv4", "10.42.7.19")
    assert vault.count() == 2


def test_the_mapping_survives_close_and_reopen(tmp_path: Path) -> None:
    """Buffered writes must not be a way to lose the mapping -- close commits."""
    path = tmp_path / "vault.sqlite"
    with RedactionVault(path) as store:
        store.record("[EMAIL:a7f2]", "email", "ana.silva@northwind-retail.com")
    with RedactionVault(path) as reopened:
        assert reopened.reveal("[EMAIL:a7f2]") == "ana.silva@northwind-retail.com"
        assert reopened.count() == 1


def test_reopening_reapplies_no_migrations(tmp_path: Path) -> None:
    path = tmp_path / "vault.sqlite"
    with RedactionVault(path) as store:
        assert store.apply_migrations() == []
    with RedactionVault(path) as reopened:
        assert reopened.apply_migrations() == []


def test_many_records_are_flushed_by_a_read(vault: RedactionVault) -> None:
    """Reads flush first, so the commit batching is invisible to a caller."""
    for i in range(1200):
        vault.record(f"[IPV4:{i:04x}]", "ipv4", f"10.0.0.{i}")
    assert vault.count() == 1200


# ---------------------------------------------------- redactor integration


def test_a_vault_does_not_change_what_redaction_produces(tmp_path: Path) -> None:
    """The vault is a side-channel. If attaching one altered the output, enabling it would
    shift every template and token downstream."""
    text = (
        "ana.silva@northwind-retail.com from 10.42.7.19 peer fe80::1 "
        "ssn 123-45-6789 api_key=sk_live_9f3ba71c4d2e8a06b5c1"
    )
    plain = Redactor()
    with RedactionVault(tmp_path / "vault.sqlite") as store:
        vaulted = Redactor(vault=store)
        assert vaulted.redact(text) == plain.redact(text)
        assert vaulted.counts == plain.counts


def test_a_redacted_token_reveals_its_source_value(vault: RedactionVault) -> None:
    redactor = Redactor(vault=vault)
    out = redactor.redact("upstream 10.42.7.19 refused connection")
    token = out.split("upstream ")[1].split(" ")[0]
    assert vault.reveal(token) == "10.42.7.19"


def test_the_same_value_twice_records_one_entry(vault: RedactionVault) -> None:
    redactor = Redactor(vault=vault)
    redactor.redact("login from 10.42.7.19")
    redactor.redact("timeout talking to 10.42.7.19")
    assert vault.count() == 1
    assert redactor.counts == {"ipv4": 2}


def test_different_values_record_separate_entries(vault: RedactionVault) -> None:
    Redactor(vault=vault).redact("hop 10.42.7.19 then 192.168.14.203")
    assert vault.count() == 2
    assert {row["value"] for row in vault.entries("ipv4")} == {"10.42.7.19", "192.168.14.203"}


def test_api_key_records_the_secret_not_the_whole_match(vault: RedactionVault) -> None:
    """The named-group branch replaces only the value; the vault must store only the value.

    Recording `api_key=sk_live_...` would make reveal return something that is not what the
    placeholder stands for -- and would leak the key name into a store keyed on values.
    """
    Redactor(vault=vault).redact("refresh failed api_key=sk_live_9f3ba71c4d2e8a06b5c1")
    (row,) = vault.entries("api_key")
    assert row["value"] == "sk_live_9f3ba71c4d2e8a06b5c1"
    assert vault.reveal(row["token"]) == "sk_live_9f3ba71c4d2e8a06b5c1"


def test_structured_fields_are_recorded(vault: RedactionVault) -> None:
    """A JSON log routinely carries the address in a field and never in the message."""
    redactor = Redactor(vault=vault)
    record = redactor.redact_record(
        _record(
            "checkout failed",
            user={"email": "ana.silva@northwind-retail.com", "ips": ["10.42.7.19"]},
            attempt=3,
        )
    )
    assert vault.reveal(record.fields["user"]["email"]) == "ana.silva@northwind-retail.com"
    assert vault.reveal(record.fields["user"]["ips"][0]) == "10.42.7.19"
    assert vault.count() == 2


def test_every_default_entity_is_recorded(vault: RedactionVault) -> None:
    Redactor(vault=vault).redact(
        "ana.silva@northwind-retail.com from 10.42.7.19 peer fe80::1 "
        "ssn 123-45-6789 api_key=sk_live_9f3ba71c4d2e8a06b5c1"
    )
    assert {row["entity"] for row in vault.entries()} == {
        "api_key",
        "email",
        "ipv4",
        "ipv6",
        "ssn",
    }


def test_redaction_off_records_nothing(vault: RedactionVault) -> None:
    Redactor(mode="off", vault=vault).redact("ana.silva@northwind-retail.com at 10.42.7.19")
    assert vault.count() == 0


def test_a_salted_redactor_records_the_salted_token(tmp_path: Path) -> None:
    """Reveal is keyed on the token as printed, so the salt must flow through unchanged."""
    with RedactionVault(tmp_path / "vault.sqlite") as store:
        redactor = Redactor(salt="pepper", vault=store)
        out = redactor.redact("10.42.7.19")
        assert store.reveal(out) == "10.42.7.19"
        assert Redactor().redact("10.42.7.19") != out


# ------------------------------------------------------- the file boundary


def test_vault_path_is_not_the_scratchpad_path() -> None:
    """The security constraint, stated directly.

    `run_readonly_sql` runs model-authored SQL and its authorizer permits reading any table
    in the database it is pointed at, so a vault table in the scratchpad would hand the model
    every value redaction removed.
    """
    config = MistifyConfig.model_validate({"redaction": {"vault": True}})
    vault_path = config.vault_path(INCIDENT)
    assert vault_path is not None
    assert vault_path != config.scratchpad_path(INCIDENT)
    assert vault_path.resolve() != config.scratchpad_path(INCIDENT).resolve()


def test_disabled_config_yields_no_vault_path() -> None:
    assert MistifyConfig().vault_path(INCIDENT) is None


def test_the_scratchpad_has_no_vault_table(db: ScratchpadDB) -> None:
    tables = {
        row["name"]
        for row in db.run_readonly_sql("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert "vault" not in tables
    assert "log_events" in tables  # the query itself works, so the absence means something


def test_the_readonly_channel_cannot_reach_a_vault(db: ScratchpadDB, tmp_path: Path) -> None:
    """A separate file is a real boundary: the authorizer denies ATTACH, so knowing the
    vault's path buys a model-authored query nothing."""
    vault_file = tmp_path / "vault.sqlite"
    with RedactionVault(vault_file) as store:
        store.record("[EMAIL:a7f2]", "email", "ana.silva@northwind-retail.com")

    with pytest.raises(ReadOnlyViolation):
        db.run_readonly_sql("SELECT * FROM vault")
    with pytest.raises(ReadOnlyViolation):
        db.run_readonly_sql(f"ATTACH DATABASE '{vault_file.as_posix()}' AS v")


def test_the_vault_file_carries_only_its_own_table(tmp_path: Path) -> None:
    """Nothing about the incident beyond the mapping lives here."""
    path = tmp_path / "vault.sqlite"
    with RedactionVault(path) as store:
        store.record("[EMAIL:a7f2]", "email", "ana.silva@northwind-retail.com")

    conn = sqlite3.connect(path)
    try:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    finally:
        conn.close()
    assert {row[0] for row in rows} == {"vault", "schema_migrations"}


# ------------------------------------------------------------------- CLI


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def write_config(make_config_file: Callable[..., Path], tmp_path: Path) -> Callable[..., Path]:
    """The shared scratch config plus a vault, with the switch left as a parameter.

    Both settings are load-bearing here: half these tests exercise the enabled path and half
    the disabled one, and the vault file has to land in the scratch directory rather than the
    `.cache` the default names.
    """

    def build(*, vault: bool) -> Path:
        return make_config_file(
            redaction={
                "vault": vault,
                "vault_path": str(tmp_path / "vault_{incident_id}.sqlite"),
            }
        )

    return build


@pytest.fixture
def vault_config(write_config: Callable[..., Path]) -> Path:
    """A config with the vault enabled, and a populated vault at the path it names."""
    config_path = write_config(vault=True)
    store_path = MistifyConfig.model_validate(
        yaml.safe_load(config_path.read_text(encoding="utf-8"))
    ).vault_path(INCIDENT)
    assert store_path is not None
    with RedactionVault(store_path) as store:
        redactor = Redactor(vault=store)
        redactor.redact("login for ana.silva@northwind-retail.com from 10.42.7.19")
    return config_path


def test_reveal_by_token_prints_the_value(
    runner: CliRunner, vault_config: Path, tmp_path: Path
) -> None:
    config = MistifyConfig.model_validate(yaml.safe_load(vault_config.read_text("utf-8")))
    store_path = config.vault_path(INCIDENT)
    assert store_path is not None
    with RedactionVault(store_path) as store:
        (row,) = store.entries("email")

    result = runner.invoke(
        cli,
        [
            "reveal",
            "--incident-id",
            INCIDENT,
            "--token",
            row["token"],
            "--config",
            str(vault_config),
        ],
    )
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == "ana.silva@northwind-retail.com"
    assert "unredacted" in result.stderr


def test_reveal_all_lists_entity_token_and_value(runner: CliRunner, vault_config: Path) -> None:
    result = runner.invoke(
        cli, ["reveal", "--incident-id", INCIDENT, "--all", "--config", str(vault_config)]
    )
    assert result.exit_code == 0, result.output
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 2
    assert {line.split("\t")[0] for line in lines} == {"email", "ipv4"}
    assert "ana.silva@northwind-retail.com" in result.stdout
    assert "10.42.7.19" in result.stdout
    # The warning goes to stderr so a redirected dump stays machine-readable.
    assert "unredacted" in result.stderr
    assert "warning" not in result.stdout


def test_reveal_of_an_unknown_token_fails_clearly(runner: CliRunner, vault_config: Path) -> None:
    result = runner.invoke(
        cli,
        [
            "reveal",
            "--incident-id",
            INCIDENT,
            "--token",
            "[EMAIL:0000]",
            "--config",
            str(vault_config),
        ],
    )
    assert result.exit_code != 0
    assert "not in the vault" in result.output


def test_reveal_with_the_vault_disabled_explains_the_one_way_hash(
    runner: CliRunner, write_config: Callable[..., Path]
) -> None:
    config_path = write_config(vault=False)
    result = runner.invoke(
        cli, ["reveal", "--incident-id", INCIDENT, "--all", "--config", str(config_path)]
    )
    assert result.exit_code != 0
    assert "redaction.vault is disabled" in result.output
    assert "one-way" in result.output
    assert "re-ingest" in result.output


def test_the_vault_flag_keeps_a_vault_the_config_did_not_ask_for(
    runner: CliRunner, write_config: Callable[..., Path], incident_file: Path
) -> None:
    """`--vault` on ingest is the config key, decided at the one moment it can be, and
    `reveal` finds the result without the config being edited to match."""
    config_path = write_config(vault=False)
    ingested = runner.invoke(
        cli,
        [
            "ingest",
            "--source",
            str(incident_file),
            "--incident-id",
            INCIDENT,
            "--vault",
            "--config",
            str(config_path),
        ],
    )
    assert ingested.exit_code == 0, ingested.output

    revealed = runner.invoke(
        cli, ["reveal", "--incident-id", INCIDENT, "--all", "--config", str(config_path)]
    )
    assert revealed.exit_code == 0, revealed.output
    entities = {line.split("	")[0] for line in revealed.output.splitlines() if "	" in line}
    assert entities >= {"email", "ipv4"}


def test_without_the_flag_no_vault_is_kept(
    runner: CliRunner, write_config: Callable[..., Path], incident_file: Path
) -> None:
    """The control for the test above: same config, same file, no flag, nothing to reveal."""
    config_path = write_config(vault=False)
    ingested = runner.invoke(
        cli,
        [
            "ingest",
            "--source",
            str(incident_file),
            "--incident-id",
            INCIDENT,
            "--config",
            str(config_path),
        ],
    )
    assert ingested.exit_code == 0, ingested.output
    revealed = runner.invoke(
        cli, ["reveal", "--incident-id", INCIDENT, "--all", "--config", str(config_path)]
    )
    assert revealed.exit_code != 0
    assert "redaction.vault is disabled" in revealed.output
    assert "--vault" in revealed.output


def test_reveal_without_an_ingested_vault_fails_clearly(
    runner: CliRunner, write_config: Callable[..., Path]
) -> None:
    config_path = write_config(vault=True)
    result = runner.invoke(
        cli, ["reveal", "--incident-id", "never-ingested", "--all", "--config", str(config_path)]
    )
    assert result.exit_code != 0
    assert "no vault for incident" in result.output
    assert "one-way" in result.output


def test_reveal_requires_a_selection(runner: CliRunner, vault_config: Path) -> None:
    result = runner.invoke(
        cli, ["reveal", "--incident-id", INCIDENT, "--config", str(vault_config)]
    )
    assert result.exit_code != 0
    assert "exactly one of --token or --all" in result.output


def test_reveal_refuses_both_selections(runner: CliRunner, vault_config: Path) -> None:
    result = runner.invoke(
        cli,
        [
            "reveal",
            "--incident-id",
            INCIDENT,
            "--all",
            "--token",
            "[EMAIL:0000]",
            "--config",
            str(vault_config),
        ],
    )
    assert result.exit_code != 0
    assert "exactly one of --token or --all" in result.output


def test_reveal_of_an_empty_vault_says_so(
    runner: CliRunner, write_config: Callable[..., Path]
) -> None:
    config_path = write_config(vault=True)
    config = MistifyConfig.model_validate(yaml.safe_load(config_path.read_text("utf-8")))
    store_path = config.vault_path(INCIDENT)
    assert store_path is not None
    RedactionVault(store_path).close()

    result = runner.invoke(
        cli, ["reveal", "--incident-id", INCIDENT, "--all", "--config", str(config_path)]
    )
    assert result.exit_code == 0, result.output
    assert "vault is empty" in result.stderr
    assert result.stdout.strip() == ""

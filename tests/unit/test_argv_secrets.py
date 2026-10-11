"""Credentials given on the command line draw a warning that never echoes them."""

from __future__ import annotations

from click.testing import CliRunner

from shadowscan import cli
from shadowscan.config import argv_credential_keys

SECRET = "Zq8Lm2Xw9Rt4Yu7Io1Pa5Sd3Fg6Hj0Kl"
JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."


def test_credential_keys_are_found_and_ordinary_keys_are_not() -> None:
    conf = {"token": SECRET, "org_url": "https://acme.okta.com", "fetch_tokens": True}
    assert argv_credential_keys(conf) == ["token"]


def test_credential_file_paths_are_not_credentials_but_tokens_always_are() -> None:
    # Passing a credential file's location on the command line is the documented
    # practice; the location is withheld from representations, not a secret.
    conf = {
        "credentials_file": "/etc/shadowscan/sa.json",
        "service_account_file": "~/.config/gcloud/sa.json",
        "token_file": "/run/secrets/token",
        "project": "demo",
    }
    assert argv_credential_keys(conf) == []
    # A credential given under one of those keys is still a credential on argv.
    assert argv_credential_keys({"token_file": JWT}) == ["token_file"]
    # identity.jwt `tokens` holds credential material whatever its shape.
    assert argv_credential_keys({"tokens": "opaque"}) == ["tokens"]


def test_run_does_not_warn_for_a_credential_file_path(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_run_scan", lambda config, opts: None)
    result = CliRunner().invoke(
        cli.main, ["run", "cloud.gcp", "--set", "credentials_file=/etc/shadowscan/sa.json"]
    )
    assert result.exit_code == 0, result.output
    assert "command line" not in result.output


def test_run_warns_for_a_secret_set_value(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_run_scan", lambda config, opts: None)
    result = CliRunner().invoke(
        cli.main,
        ["run", "identity.okta", "--set", "org_url=https://acme.okta.com", "--set", f"token={SECRET}"],
    )
    assert result.exit_code == 0, result.output
    assert "--set token on the command line" in result.output
    assert SECRET not in result.output


def test_run_without_secrets_does_not_warn(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_run_scan", lambda config, opts: None)
    result = CliRunner().invoke(cli.main, ["run", "identity.okta", "--set", "org_url=https://acme.okta.com"])
    assert result.exit_code == 0, result.output
    assert "command line" not in result.output


def test_jwt_arguments_warn_without_echoing_the_token(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_run_scan", lambda config, opts: None)
    result = CliRunner().invoke(cli.main, ["jwt", JWT])
    assert result.exit_code == 0, result.output
    assert "JWT arguments on the command line" in result.output
    assert JWT not in result.output

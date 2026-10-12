"""Credentials given on the command line draw a warning that never echoes them."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan import cli
from shadowscan.config import argv_credential_keys

ROOT = Path(__file__).resolve().parents[2]

SECRET = "Zq8Lm2Xw9Rt4Yu7Io1Pa5Sd3Fg6Hj0Kl"
JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."
# The random part of a synthetic downloaded key or mounted secret file name.
HEX = "1a2b3c4d" + "5e6f7a8b9c0d1e2f"


def test_credential_keys_are_found_and_ordinary_keys_are_not() -> None:
    conf = {"token": SECRET, "org_url": "https://acme.okta.com", "fetch_tokens": True}
    assert argv_credential_keys(conf) == ["token"]


def test_a_credential_in_the_key_position_is_never_named() -> None:
    # Plugin keys are not validated, so a token can be pasted as the key itself.
    token = "ghp_" + SECRET + "1234"
    assert argv_credential_keys({token: "1", "api_key": SECRET}) == ["<withheld key>", "api_key"]
    assert token not in repr(argv_credential_keys({token: "1"}))


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
    # Judged by value: an opaque credential pasted where the file path belongs
    # warns even when no known token format names it.
    assert argv_credential_keys({"credentials_file": "f554a0579bed" + "6908c1b34a1c4ba12d112b0c19a5"}) == [
        "credentials_file"
    ]
    assert argv_credential_keys({"credentials_file": SECRET}) == ["credentials_file"]
    # identity.jwt `tokens` holds credential material whatever its shape.
    assert argv_credential_keys({"tokens": "opaque"}) == ["tokens"]


@pytest.mark.parametrize(
    "location",
    [
        f"acme-prod-123456-{HEX[:12]}.json",
        f"gws-admin-{HEX[4:16]}.json",
        f"/run/secrets/{HEX}{HEX}",
        f"/Users/alice/keys/{HEX}",
        # Directory names in capitalized words, as some home directories are named.
        f"/Users/JohnDoe/keys/{HEX}",
        f"/home/JaneRoe/{HEX}",
        f"~/keys/{HEX}",
        f"./{HEX}",
        f".config/gcloud/{HEX}",
        f"C:\\keys\\{HEX}",
    ],
)
@pytest.mark.parametrize("key", ["credentials_file", "service_account_file", "token_file"])
def test_a_credential_file_with_a_random_name_is_still_a_location(key: str, location: str) -> None:
    # The random part reads as an opaque literal; the file-name or path shape
    # around it marks the value as a location, which the command line may carry.
    assert argv_credential_keys({key: location}) == []


@pytest.mark.parametrize(
    "credential",
    [
        HEX + HEX,
        SECRET,
        # Base64 credentials hold '/': an unanchored relative path or a root and a
        # single name may be one.
        "wJalrXUtnFEMI/K7MDENG/" + SECRET[:18],
        "/K7MDENG/" + SECRET,
        "/6/tDCy4F+Oo+PZ/" + SECRET[:24],
        f"secrets/{SECRET}",
        # Mixed case that is not capitalized words is not a plain directory name.
        "/xK9mQ/Lp2Wz/" + SECRET[:20],
        # Dotted tokens end in a segment far longer than a file extension.
        "MTIzNDU2Nzg5MDEyMzQ1Njc4.Cl2FMQ." + SECRET[:27],
    ],
)
def test_an_opaque_credential_without_path_shape_still_warns(credential: str) -> None:
    assert argv_credential_keys({"credentials_file": credential}) == ["credentials_file"]


@pytest.mark.parametrize("location", ["/etc/shadowscan/sa.json", f"acme-prod-123456-{HEX[:12]}.json"])
def test_run_does_not_warn_for_a_credential_file_path(monkeypatch, location: str) -> None:
    monkeypatch.setattr(cli, "_run_scan", lambda config, opts: None)
    result = CliRunner().invoke(cli.main, ["run", "cloud.gcp", "--set", f"credentials_file={location}"])
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


def test_the_guide_checks_key_formats_with_a_synthetic_value() -> None:
    # `signatures test` reads the value from argv only: the guide must not send a
    # live key there, and the synthetic value it shows must be enough to match.
    guide = (ROOT / "docs" / "getting-started" / "configuration.md").read_text(encoding="utf-8")
    section = guide.split("## Signature listing", 1)[1]
    assert "never a live key" in section and "paste" not in section
    example = re.search(r"signatures test \"sk-proj-\$\(printf 'x%\.0s' \$\(seq (\d+)\)\)\"", section)
    assert example is not None
    result = CliRunner().invoke(cli.main, ["signatures", "test", "sk-proj-" + "x" * int(example[1])])
    assert result.exit_code == 0, result.output
    assert "provider.openai" in result.output and "no match" not in result.output


def test_jwt_arguments_warn_without_echoing_the_token(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_run_scan", lambda config, opts: None)
    result = CliRunner().invoke(cli.main, ["jwt", JWT])
    assert result.exit_code == 0, result.output
    assert "JWT arguments on the command line" in result.output
    assert JWT not in result.output

"""Tool credential files are read by name for the credential pass, and for it alone.

``.npmrc``, ``.netrc``, ``.pypirc``, ``.git-credentials`` and their kin have
no suffix, so the suffix rules that select source and configuration never
opened them, and a provider key committed in one was neither reported nor
disclosed as unread. They are selected by name now; a file whose name selects
no analysis is still never opened and is not a coverage gap.

Selected by name, they first ran every analysis pass: a one-line netrc entry
for ``api.openai.com`` became framework-usage evidence whose excerpt was the
whole line, password included, in every report format. Only the credential
pass reads them now, and no excerpt is cut from them.
"""

from __future__ import annotations

import random
import string

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import (
    CREDENTIAL_FILE_NAMES,
    FilesystemConnector,
    _analyzed_by_name,
)
from shadowscan.engine import Engine
from shadowscan.models import Kind
from shadowscan.reporters import RENDERERS

_RANDOM = random.Random(2931)
_ALPHABET = string.ascii_letters + string.digits


def _random(length: int) -> str:
    return "".join(_RANDOM.choice(_ALPHABET) for _ in range(length))


def _openai_key() -> str:
    # The prefix is assembled at run time so no key form is committed.
    return "sk-" + "proj-" + _random(48) + "T3BlbkFJ" + _random(20)


def _anthropic_key() -> str:
    return "sk-" + "ant-" + "api03-" + _random(48)


def _password() -> str:
    return "pw-" + _random(28)


def _write(root, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _scan(index, root, files: dict[str, str], **config):
    _write(root, files)
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def _secret_files(findings) -> dict[str, list[str]]:
    return {f.resource.rsplit("/", 1)[-1]: f.metadata["providers"] for f in findings if f.kind == Kind.SECRET}


@pytest.mark.parametrize("name", sorted(CREDENTIAL_FILE_NAMES))
def test_credential_file_names_are_analyzed(name):
    assert _analyzed_by_name(name)
    assert _analyzed_by_name(name.upper())


@pytest.mark.parametrize("name", ["train.jsonl", "settings.bak", "config.j2", "weights.bin"])
def test_other_suffixed_names_are_still_not_analyzed(name):
    assert not _analyzed_by_name(name)


def test_provider_keys_in_credential_files_are_reported(tmp_path, index):
    findings, ctx = _scan(
        index,
        tmp_path,
        {
            ".npmrc": f"//registry.npmjs.org/:_authToken={_openai_key()}\n",
            ".netrc": f"machine api.anthropic.com\n  login user\n  password {_anthropic_key()}\n",
            "src/app.py": "import requests\n",
        },
    )
    assert _secret_files(findings) == {".npmrc": ["provider.openai"], ".netrc": ["provider.anthropic"]}
    assert not ctx.stats.incomplete and not ctx.stats.warnings


def test_credential_files_without_a_provider_key_are_read_quietly(tmp_path, index):
    findings, ctx = _scan(
        index,
        tmp_path,
        {
            ".pypirc": "[pypi]\nusername = __token__\n",
            ".git-credentials": "https://github.com\n",
            "src/app.py": "import requests\n",
        },
    )
    assert _secret_files(findings) == {}
    assert not ctx.stats.incomplete and not ctx.stats.warnings


def _credential_files() -> tuple[dict[str, str], list[str]]:
    """One file of each credential kind in its own syntax, and every secret value in them."""
    values = [_password() for _ in range(15)]
    openai_key, anthropic_key = _openai_key(), _anthropic_key()
    akia = "AKIA" + _random(16).upper()
    files = {
        ".netrc": (
            f"machine api.openai.com login deploy password {values[0]}\n"
            f"machine api.anthropic.com login {openai_key} password {values[1]}\n"
            "machine generativelanguage.googleapis.com\n"
            f"  login ci\n  passwd {values[2]}\n  account {values[3]}\n"
            f"default login anonymous password\n  {values[4]}\n"
            f"macdef init\n  user deploy {values[5]}\n\n"
        ),
        "win/_netrc": f"machine api.mistral.ai login deploy password {values[6]}\n",
        "upper/.NETRC": f"machine api.openai.com login x password {values[7]}\n",
        ".npmrc": (
            f"//registry.npmjs.org/:_authToken={anthropic_key}\n_auth={values[8]}\n"
            f"//npm.pkg.example.com/:_password={values[9]}\n"
        ),
        ".yarnrc": f'"//registry.yarnpkg.com/:_authToken" "{values[10]}"\n',
        ".pypirc": f"[pypi]\nusername = __token__\npassword = {values[11]}\n",
        # Joined at run time, as the URL userinfo shape is itself a committed-secret pattern.
        ".git-credentials": "https://deploy:" + values[12] + "@git.example.com\n",
        ".boto": f"[Credentials]\naws_access_key_id = {akia}\naws_secret_access_key = {values[13]}\n",
        ".s3cfg": f"[default]\naccess_key = {akia}\nsecret_key = {values[14]}\n",
        "src/app.py": "import requests\n",
    }
    return files, [*values, openai_key, anthropic_key, akia]


def test_no_report_format_shows_a_credential_file_secret(tmp_path, index):
    files, secrets = _credential_files()
    _write(tmp_path, files)
    spec = ConnectorSpec("code.filesystem", {"path": str(tmp_path), "use_git": False})
    result = Engine(ScanConfig(connectors=[spec]), index).run()
    assert result.complete, [error for stats in result.stats for error in stats.errors]
    for name, render in RENDERERS.items():
        report = render(result)
        assert not [secret for secret in secrets if secret in report], name
    # The credential pass still reports what it finds, each finding with its count.
    found = {
        f.resource.rsplit("/", 1)[-1]: (f.metadata["providers"], f.metadata["count"])
        for f in result.findings
        if f.kind == Kind.SECRET
    }
    assert set(found) == {".netrc", ".npmrc", ".boto", ".s3cfg"}
    assert found[".netrc"] == (["provider.openai"], 1)  # the key in a login field
    assert "provider.anthropic" in found[".npmrc"][0]
    assert all(count >= 1 for _, count in found.values())


@pytest.mark.parametrize("name", [".netrc", "_netrc", ".NETRC"])
def test_a_netrc_entry_is_read_for_credentials_alone(tmp_path, index, name):
    password = _password()
    findings, ctx = _scan(
        index, tmp_path, {name: f"machine api.openai.com login deploy password {password}\n"}
    )
    # The provider host is where a credential goes, not usage of the provider,
    # and the line holding the password is never excerpted.
    assert findings == []
    assert not ctx.stats.incomplete and not ctx.stats.warnings


def test_a_credential_file_finding_carries_no_excerpt(tmp_path, index):
    password = _password()
    findings, _ = _scan(
        index, tmp_path, {".netrc": f"machine api.anthropic.com login {_openai_key()} password {password}\n"}
    )
    (finding,) = findings if all(f.kind == Kind.SECRET for f in findings) else [None]
    assert finding is not None and finding.metadata["count"] == 1
    assert [(e.location, e.snippet) for e in finding.evidence] == [(".netrc:1", "")]


def test_credential_files_are_not_read_without_the_credential_pass(tmp_path, index):
    # Only the credential pass reads them, so with it off an oversize one is
    # not content the scan would have read: no gap, as for an unselected name.
    files = {".netrc": "machine h login u password " + "x" * 2048 + "\n", "src/app.py": "import requests\n"}
    findings, ctx = _scan(index, tmp_path, files, scan_secrets=False, max_file_size=1024)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert not [f for f in findings if f.kind == Kind.SECRET]
    _, ctx = _scan(index, tmp_path / "on", files, max_file_size=1024)
    assert ctx.stats.incomplete


@pytest.mark.parametrize(
    "config",
    [{}, {"scan_secrets": False}, {"triage": True}],
    ids=["default", "no-secrets", "triage"],
)
def test_a_credential_file_in_a_coding_agent_directory_still_configures_the_agent(tmp_path, index, config):
    # A file name carries no content: '.codex/.netrc' establishes Codex as any
    # file under '.codex/' does, in every mode, while its lines stay unread.
    passwords = [_password(), _password()]
    files = {
        ".codex/.netrc": f"machine example.com login u password {passwords[0]}\n",
        ".gemini/.npmrc": "registry=https://registry.example.com/\n",
        ".claude/hooks/.netrc": f"machine example.org login u password {passwords[1]}\n",
    }
    findings, _ = _scan(index, tmp_path, files, **config)
    agents = {f.title.split(" configured")[0]: f for f in findings if f.kind == Kind.AGENT_CONFIG}
    assert sorted(agents) == ["Claude Code", "Gemini CLI / Jules", "OpenAI Codex (CLI / cloud agent)"]
    assert agents["OpenAI Codex (CLI / cloud agent)"].metadata["files"] == [".codex/.netrc"]
    assert agents["Claude Code"].metadata["files"] == [".claude/hooks/.netrc"]
    assert all(not evidence.snippet for finding in findings for evidence in finding.evidence)
    assert not any(password in repr(findings) for password in passwords)

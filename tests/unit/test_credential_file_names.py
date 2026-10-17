"""Tool credential files are read by name for the credential pass.

``.npmrc``, ``.netrc``, ``.pypirc``, ``.git-credentials`` and their kin have
no suffix, so the suffix rules that select source and configuration never
opened them, and a provider key committed in one was neither reported nor
disclosed as unread. They are selected by name now; a file whose name selects
no analysis is still never opened and is not a coverage gap.
"""

from __future__ import annotations

import random
import string

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import (
    CREDENTIAL_FILE_NAMES,
    FilesystemConnector,
    _analyzed_by_name,
)
from shadowscan.models import Kind

_RANDOM = random.Random(2931)
_ALPHABET = string.ascii_letters + string.digits


def _random(length: int) -> str:
    return "".join(_RANDOM.choice(_ALPHABET) for _ in range(length))


def _openai_key() -> str:
    # The prefix is assembled at run time so no key form is committed.
    return "sk-" + "proj-" + _random(48) + "T3BlbkFJ" + _random(20)


def _anthropic_key() -> str:
    return "sk-" + "ant-" + "api03-" + _random(48)


def _scan(index, root, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    ctx = ConnectorContext(config={"path": str(root), "use_git": False}, index=index)
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

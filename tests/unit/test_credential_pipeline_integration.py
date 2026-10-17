"""The generic credential filters (#255, #258) and the disclosed quota (#257) compose.

Rejected candidates take no place under the five-per-signal quota and never
count past it; an accepted match past it is disclosed, and no candidate cap
hides a key behind any number of rejected references; placeholders neither
take a place nor mark a scan incomplete; name, reference and label rules
apply to assigned values only, so the signal's bare token patterns (AKIA...,
ghp_...) still report key material in source code and in tool credential
files. Ported from the cross-PR credential review's recommended design (the
candidate-cap test inverted: the integration removed that cap). Keys are
assembled at run time.
"""

from __future__ import annotations

import random
import string
from pathlib import Path

import pytest

from shadowscan.models import Kind
from shadowscan.signatures.matcher import MAX_SECRETS_PER_SIGNAL

GENERIC = "heuristic.inline-credential"
RANDOM = "R4nd0m9Qx2Vb7Lp6"
_RANDOM = random.Random(7193)
_B62 = string.ascii_letters + string.digits


def _rnd(alphabet: str, length: int) -> str:
    return "".join(_RANDOM.choice(alphabet) for _ in range(length))


def _aws_key_id(*, digits: bool) -> str:
    body = _rnd(string.ascii_uppercase + "234567", 16) if digits else _rnd(string.ascii_uppercase, 16)
    if digits and not any(char.isdigit() for char in body):
        body = body[:-1] + "7"
    return "AK" + "IA" + body


def _github_token() -> str:
    return "gh" + "p_" + _rnd(_B62, 36)


def _openai_key(number: int) -> str:
    return "sk-" + "proj-" + _rnd(_B62, 48) + "T3Blbk" + "FJ" + f"{number:02d}" + _rnd(_B62, 20)


def _references(count: int) -> str:
    return "".join(f"        self.service{n}_api_key = service{n}_api_key\n" for n in range(count))


def _scan(run_connector, root: Path, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    findings, ctx = run_connector("code.filesystem", path=str(root), use_git=False)
    secrets = {f.metadata["path"]: f for f in findings if f.kind == Kind.SECRET}
    return secrets, ctx.stats


# ------------------------------------------------------------------ quota position
def test_rejected_references_neither_take_a_place_nor_count_past_the_quota(index):
    text = "class S:\n    def __init__(self):\n" + _references(8) + f'BACKUP_API_KEY = "{RANDOM}"\n'
    limited: set[str] = set()
    found = [
        m.value for m in index.match_secrets(text, limited=limited, code=True) if m.signature_id == GENERIC
    ]
    assert found == [f'BACKUP_API_KEY = "{RANDOM}']
    assert limited == set()


def test_an_accepted_match_past_the_quota_is_disclosed_after_filtering(index):
    text = "".join(f'OPENAI_KEY_{n} = "{_openai_key(n)}"\n' for n in range(MAX_SECRETS_PER_SIGNAL + 3))
    limited: set[str] = set()
    matches = index.match_secrets(text, limited=limited, code=True)
    assert sum(m.signature_id == "provider.openai" for m in matches) == MAX_SECRETS_PER_SIGNAL
    assert limited == {"provider.openai"}


def test_no_candidate_cap_hides_a_key_behind_rejected_references(run_connector, tmp_path):
    # #255 read 25 raw candidates per signal; 30 references then hid the key.
    # Every candidate is judged now, so the key is reported and nothing is limited.
    text = "class S:\n    def __init__(self):\n" + _references(30) + f'BACKUP_API_KEY = "{RANDOM}"\n'
    secrets, stats = _scan(run_connector, tmp_path, {"settings.py": text})
    assert secrets["settings.py"].metadata["count"] == 1
    assert not stats.incomplete and not stats.errors


def test_placeholders_do_not_make_a_sample_env_file_incomplete(run_connector, tmp_path):
    samples = "".join(f"SERVICE{n}_API_KEY=sk-your-key-here-{n}a7c9e1f3\n" for n in range(8))
    secrets, stats = _scan(run_connector, tmp_path, {".env.example": samples})
    assert secrets == {} and not stats.incomplete and not stats.errors
    secrets, stats = _scan(run_connector, tmp_path, {".env.example": samples + f"REAL_API_KEY={RANDOM}\n"})
    assert set(secrets) == {".env.example"} and not stats.incomplete


# ------------------------------------------------------------------ bare token patterns
def test_an_aws_key_id_in_source_code_is_still_a_credential(run_connector, tmp_path):
    secrets, _ = _scan(
        run_connector, tmp_path, {"src/aws.py": f'AWS_ACCESS_KEY_ID = "{_aws_key_id(digits=True)}"\n'}
    )
    assert set(secrets) == {"src/aws.py"}


@pytest.mark.parametrize(
    ("name", "text"),
    [
        (".boto", "[Credentials]\naws_access_key_id = {aws}\n"),
        (".s3cfg", "[default]\naccess_key = {aws}\n"),
        (".git-credentials", "https:" + "//octocat:{gh}@github.com\n"),
        (".netrc", "machine github.com login octocat password {gh}\n"),
    ],
)
def test_token_patterns_in_credential_files_are_reported(run_connector, tmp_path, name, text):
    body = text.format(aws=_aws_key_id(digits=False), gh=_github_token())
    secrets, stats = _scan(run_connector, tmp_path, {name: body})
    assert set(secrets) == {name} and not stats.incomplete


# ------------------------------------------------------------------ one definition of a name
@pytest.mark.parametrize(
    "line",
    [
        "const anthropicApiKey = process.env.ANTHROPIC_API_KEY;",
        "api_key = settings.OPENAI_API_KEY",
        "self.api_key = resolved_api_key",
        "include_tracing_api_key=include_tracing_api_key,",
    ],
)
def test_references_stay_rejected_under_both_name_rules(index, line):
    assert [m for m in index.match_secrets(line, code=True) if m.signature_id == GENERIC] == []

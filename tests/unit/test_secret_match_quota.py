"""The per-signal credential quota discloses itself instead of truncating silently.

``SignatureIndex.match_secrets`` keeps at most ``MAX_SECRETS_PER_SIGNAL``
matches per secret signal. A file with more real credentials of one format
than that used to be reported with ``count`` equal to the quota, no diagnostic
and a complete scan, so a clean-looking report under-counted the one finding
kind whose count is read literally. The matcher now tells a caller which
signatures hit the quota, and the code connector records the scan incomplete
and marks the finding.
"""

from __future__ import annotations

import json
import random
import string

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.common import placeholder_reason
from shadowscan.models import Kind
from shadowscan.signatures.matcher import MAX_SECRETS_PER_SIGNAL, reported_credential

_RANDOM = random.Random(5811)
_ALPHABET = string.ascii_letters + string.digits


def _openai_project_key(number: int) -> str:
    """A distinct synthetic OpenAI project-key form; the prefix is assembled at run time."""
    body = "".join(_RANDOM.choice(_ALPHABET) for _ in range(48))
    tail = "".join(_RANDOM.choice(_ALPHABET) for _ in range(20))
    return "sk-" + "proj-" + body + "T3BlbkFJ" + f"{number:02d}" + tail


def _assignments(count: int) -> str:
    return "".join(f'OPENAI_KEY_{number} = "{_openai_project_key(number)}"\n' for number in range(count))


def _scan(index, root, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    ctx = ConnectorContext(config={"path": str(root), "use_git": False}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def _secret_finding(findings):
    return next(f for f in findings if f.kind == Kind.SECRET)


def test_matcher_reports_signatures_whose_quota_was_exceeded(index):
    text = _assignments(MAX_SECRETS_PER_SIGNAL + 3)
    limited: set[str] = set()
    matches = index.match_secrets(text, limited=limited)
    assert sum(m.signature_id == "provider.openai" for m in matches) == MAX_SECRETS_PER_SIGNAL
    assert limited == {"provider.openai"}


def test_matcher_at_exact_quota_reports_nothing_hidden(index):
    limited: set[str] = set()
    matches = index.match_secrets(_assignments(MAX_SECRETS_PER_SIGNAL), limited=limited)
    assert sum(m.signature_id == "provider.openai" for m in matches) == MAX_SECRETS_PER_SIGNAL
    assert limited == set()


def test_matcher_without_a_collector_keeps_the_silent_quota(index):
    # Callers that do not report credentials (connector blob scans) are unchanged.
    matches = index.match_secrets(_assignments(MAX_SECRETS_PER_SIGNAL + 3))
    assert sum(m.signature_id == "provider.openai" for m in matches) == MAX_SECRETS_PER_SIGNAL


def test_file_past_the_quota_marks_the_scan_incomplete_and_the_finding(tmp_path, index):
    findings, ctx = _scan(index, tmp_path, {"settings.py": _assignments(MAX_SECRETS_PER_SIGNAL + 3)})
    secret = _secret_finding(findings)
    assert secret.metadata["count"] == MAX_SECRETS_PER_SIGNAL
    assert secret.metadata["secrets_limited"] == ["provider.openai"]
    assert ctx.stats.incomplete
    assert [error for error in ctx.stats.errors if "credential evidence incomplete" in error] == [
        f"code.filesystem: settings.py: more than {MAX_SECRETS_PER_SIGNAL} credentials matched "
        "provider.openai; credential evidence incomplete"
    ]


def test_file_at_the_quota_stays_complete(tmp_path, index):
    findings, ctx = _scan(index, tmp_path, {"settings.py": _assignments(MAX_SECRETS_PER_SIGNAL)})
    secret = _secret_finding(findings)
    assert secret.metadata["count"] == MAX_SECRETS_PER_SIGNAL
    assert "secrets_limited" not in secret.metadata
    assert not ctx.stats.incomplete


def test_quota_is_disclosed_once_per_file_and_format(tmp_path, index):
    # A notebook is scanned as code cells and as its raw document; a manifest's
    # structured values and its text are both read. One file names a format once.
    cells = [
        {
            "cell_type": "code",
            "metadata": {},
            "source": [line + "\n" for line in _assignments(MAX_SECRETS_PER_SIGNAL + 2).splitlines()],
            "outputs": [],
            "execution_count": None,
        }
    ]
    notebook = {"cells": cells, "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    findings, ctx = _scan(index, tmp_path, {"train.ipynb": json.dumps(notebook)})
    assert _secret_finding(findings).metadata["secrets_limited"] == ["provider.openai"]
    assert sum("credential evidence incomplete" in error for error in ctx.stats.errors) == 1


# Only credentials count toward the quota. #255 read 25 raw candidates per
# signal before filtering, so a settings module of environment reads hid every
# key after the 25th; #257 counted raw matches, so one token two patterns of
# the generic signal both match counted twice. Both now count accepted,
# distinct credentials only.
def _environment_reads(count: int) -> str:
    return "".join(
        f"export const PROVIDER{n}_API_KEY = process.env.PROVIDER{n}_API_KEY;\n" for n in range(count)
    )


def _github_token(number: int) -> str:
    body = "".join(_RANDOM.choice(_ALPHABET) for _ in range(34))
    return "ghp" + "_" + body + f"{number:02d}"


def test_references_never_hide_the_keys_after_them(index):
    aws_key = "AKIA" + "QSXMKVTWPLRNHGDJ"  # a digit-free body, as about one AWS key id in 28 has
    text = _environment_reads(40) + (
        'export const LEGACY_API_KEY = "R4nd0m9Qx2Vb7Lp6Zz";\n'
        'export const ADMIN_PASSWORD = "R4nd0m9Qx2Vb7Lp6Yy";\n'
        f'const deployToken = "{_github_token(1)}";\n'
        f'const awsId = "{aws_key}";\n'
    )
    limited: set[str] = set()
    values = [m.value for m in index.match_secrets(text, code=True, limited=limited)]
    assert any("R4nd0m9Qx2Vb7Lp6Zz" in value for value in values)
    assert any("R4nd0m9Qx2Vb7Lp6Yy" in value for value in values)
    assert any(value.startswith("ghp_") for value in values)
    assert aws_key in values
    assert limited == set()


def test_a_settings_module_of_references_stays_complete(tmp_path, index):
    findings, ctx = _scan(index, tmp_path, {"config.ts": _environment_reads(60)})
    assert not [f for f in findings if f.kind == Kind.SECRET]
    assert not ctx.stats.incomplete, ctx.stats.errors


def _samples(count: int) -> str:
    """Documentation samples that pass the generic rule's entropy test but are placeholders."""
    return "".join(f"SERVICE{n}_API_KEY=sk-your-key-here-{n}a7c9e1f3\n" for n in range(count))


def test_placeholders_take_no_place_in_the_quota(index):
    limited: set[str] = set()
    text = _samples(8) + "REAL_API_KEY=R4nd0m9Qx2Vb7Lp6\n"
    matches = index.match_secrets(text, limited=limited, placeholder=placeholder_reason)
    assert limited == set()
    reported = [m for m in matches if placeholder_reason(reported_credential(m)) is None]
    assert [reported_credential(m) for m in reported] == ["R4nd0m9Qx2Vb7Lp6"]
    # A few samples per format come back for the example evidence, never more.
    assert 0 < len(matches) - len(reported) <= MAX_SECRETS_PER_SIGNAL


def test_a_file_of_placeholders_is_complete_and_its_real_key_reported(tmp_path, index):
    findings, ctx = _scan(index, tmp_path / "samples", {".env.example": _samples(8)})
    assert not [f for f in findings if f.kind == Kind.SECRET]
    assert not ctx.stats.incomplete, ctx.stats.errors
    words = "".join(f"SERVICE{n}_API_KEY=your_service{n}_api_key_here\n" for n in range(8))
    findings, ctx = _scan(index, tmp_path / "words", {".env.example": words})
    assert not [f for f in findings if f.kind == Kind.SECRET]
    assert not ctx.stats.incomplete, ctx.stats.errors
    text = _samples(8) + "REAL_API_KEY=R4nd0m9Qx2Vb7Lp6\n"
    findings, ctx = _scan(index, tmp_path / "mixed", {".env.example": text})
    assert _secret_finding(findings).metadata["count"] == 1
    assert not ctx.stats.incomplete, ctx.stats.errors


def test_short_sk_look_alikes_take_no_place_in_the_quota(tmp_path, index):
    # Ticket branches have the short sk- shape but not its randomness; none is reported.
    branches = "".join(f'BRANCH_{n} = "sk-1234-fix-the-login-page-{n:02d}"\n' for n in range(8))
    limited: set[str] = set()
    assert index.match_secrets(branches, code=True, limited=limited) == []
    assert limited == set()
    findings, ctx = _scan(index, tmp_path, {"release.py": branches})
    assert not [f for f in findings if f.kind == Kind.SECRET]
    assert not ctx.stats.incomplete, ctx.stats.errors


def test_a_token_two_patterns_match_counts_once(tmp_path, index):
    tokens = "".join(f"{name}_GITHUB_ACCESS_TOKEN={_github_token(n)}\n" for n, name in enumerate("ABC"))
    limited: set[str] = set()
    index.match_secrets(tokens, limited=limited)
    assert limited == set()
    findings, ctx = _scan(index, tmp_path, {".env": tokens})
    assert _secret_finding(findings).metadata["count"] == 3
    assert not ctx.stats.incomplete, ctx.stats.errors

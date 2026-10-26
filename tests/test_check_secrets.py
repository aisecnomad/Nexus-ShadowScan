"""The no-hardcoded-secrets hook (`tools/check_secrets.py`).

Every credential below is synthetic: a vendor prefix split across string
literals plus seeded random characters, assembled at run time so that this
file holds no credential-shaped literal for the hook, push protection or the
private-key pre-commit check to find.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import random
import re
import string
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from shadowscan.utils import redaction_formats
from tools import check_secrets
from tools.check_secrets import digest, display, findings, main

_ALNUM = string.ascii_letters + string.digits
_UPPER = string.ascii_uppercase + string.digits
_BASE64 = _ALNUM + "+/"
_URLSAFE = _ALNUM + "_-"
_HEX = string.digits + "abcdef"


def _random(seed: str, length: int, alphabet: str = _ALNUM) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(length))


# (id, family, text before the random part, random part, text after it)
_PLANTED = [
    ("openai-legacy", "OpenAI API key", "OPENAI_API_KEY=" + "sk" + "-", _random("o1", 48), ""),
    ("openai-project", "OpenAI project key", "sk-" + "proj" + "-", _random("o2", 40, _URLSAFE), ""),
    ("anthropic", "Anthropic API key", "sk-" + "ant-" + "api03-", _random("a1", 40, _URLSAFE), ""),
    ("anthropic-oauth", "Anthropic API key", "sk-" + "ant-" + "oat01-", _random("a2", 60, _URLSAFE), ""),
    ("aws-akia", "AWS access key ID", "AK" + "IA", _random("k1", 16, _UPPER), ""),
    ("aws-asia", "AWS access key ID", "AS" + "IA", _random("k2", 16, _UPPER), ""),
    ("aws-secret", "AWS secret access key", "aws_secret_" + "access_key = ", _random("k3", 40, _BASE64), ""),
    ("github-classic", "GitHub token", "gh" + "p_", _random("g1", 36), ""),
    ("github-oauth", "GitHub token", "gh" + "o_", _random("g2", 36), ""),
    ("github-user", "GitHub token", "gh" + "u_", _random("g3", 36), ""),
    ("github-app", "GitHub token", "gh" + "s_", _random("g4", 36), ""),
    ("github-refresh", "GitHub token", "gh" + "r_", _random("g5", 36), ""),
    (
        "github-fine-grained",
        "GitHub fine-grained token",
        "github" + "_pat_",
        _random("g6", 22) + "_" + _random("g7", 59),
        "",
    ),
    ("gitlab", "GitLab token", "gl" + "pat-", _random("l1", 20, _URLSAFE), ""),
    ("gitlab-runner", "GitLab token", "gl" + "rt-", _random("l2", 20, _URLSAFE), ""),
    ("gitlab-trigger", "GitLab token", "gl" + "ptt-", _random("l3", 40, _HEX), ""),
    ("gitlab-runner-registration", "GitLab token", "GR" + "1348941", _random("l4", 20, _URLSAFE), ""),
    ("slack-bot", "Slack token", "xo" + "xb-" + "123456789012-1234567890123-", _random("s1", 24), ""),
    ("slack-user", "Slack token", "xo" + "xp-" + "123456789012-123456789012-", _random("s2", 32), ""),
    ("slack-app", "Slack token", "xo" + "xa-" + "2-", _random("s3", 30), ""),
    ("slack-refresh", "Slack token", "xo" + "xr-" + "1-", _random("s4", 30), ""),
    ("slack-rotating", "Slack token", "xo" + "xe.xoxp-" + "1-", _random("s5", 40), ""),
    (
        "slack-app-level",
        "Slack token",
        "xa" + "pp-" + "1-A0123456789-1234567890123-",
        _random("s6", 64, _HEX),
        "",
    ),
    ("google", "Google API key", "AI" + "za", _random("y1", 35, _URLSAFE), ""),
    ("google-oauth-access", "Google OAuth credential", "ya" + "29.", _random("y2", 80, _URLSAFE), ""),
    ("google-oauth-refresh", "Google OAuth credential", "1/" + "/0", _random("y3", 60, _URLSAFE), ""),
    ("google-client-secret", "Google OAuth credential", "GOC" + "SPX-", _random("y4", 28, _URLSAFE), ""),
    ("huggingface", "Hugging Face token", "hf" + "_", _random("h1", 34), ""),
    ("stripe-secret", "Stripe key", "sk" + "_live_", _random("p1", 24), ""),
    ("stripe-restricted", "Stripe key", "rk" + "_live_", _random("p2", 24), ""),
    ("stripe-test", "Stripe key", "sk" + "_test_", _random("p3", 24), ""),
    ("stripe-webhook-secret", "Stripe key", "wh" + "sec_", _random("p4", 32), ""),
    ("openrouter", "AI service API key", "sk-" + "or-v1-", _random("i1", 64, _HEX), ""),
    ("langfuse", "AI service API key", "sk-" + "lf-", _random("i2", 36, _URLSAFE), ""),
    ("litellm", "AI service API key", "sk-" + "litellm-", _random("i3", 32), ""),
    ("groq", "AI service API key", "gs" + "k_", _random("i4", 52), ""),
    ("pinecone", "AI service API key", "pc" + "sk_", _random("i5", 60, _ALNUM + "_"), ""),
    ("e2b", "AI service API key", "e2" + "b_", _random("i6", 40, _HEX), ""),
    ("together", "AI service API key", "tgp" + "_v1_", _random("i7", 43, _URLSAFE), ""),
    (
        "langsmith",
        "AI service API key",
        "ls" + "v2_pt_",
        _random("i8", 32, _HEX) + "_" + _random("i9", 10, _HEX),
        "",
    ),
    ("tavily", "AI service API key", "tv" + "ly-dev-", _random("ia", 32), ""),
    ("xai", "AI service API key", "xa" + "i-", _random("ib", 80), ""),
    ("perplexity", "AI service API key", "pp" + "lx-", _random("ic", 48), ""),
    ("cerebras", "AI service API key", "cs" + "k-", _random("id", 48), ""),
    ("nvidia", "AI service API key", "nv" + "api-", _random("ie", 64, _URLSAFE), ""),
    ("replicate", "AI service API key", "r" + "8_", _random("if", 37), ""),
    ("firecrawl", "AI service API key", "f" + "c-", _random("ig", 32, _HEX), ""),
    ("elevenlabs", "AI service API key", "sk" + "_", _random("ih", 48, _HEX), ""),
    ("fireworks", "AI service API key", "fw" + "_", _random("ii", 24), ""),
    ("bedrock-long-term", "AI service API key", "AB" + "SK", _random("ij", 120, _BASE64), ""),
    ("bedrock-short-term", "AI service API key", "bedrock-" + "api-key-", _random("ik", 60, _URLSAFE), ""),
    ("npm", "package registry token", "np" + "m_", _random("r1", 36), ""),
    ("pypi", "package registry token", "py" + "pi-AgE", _random("r2", 80, _URLSAFE), ""),
    ("digitalocean", "developer platform token", "do" + "p_v1_", _random("d1", 64, _HEX), ""),
    (
        "sendgrid",
        "developer platform token",
        "S" + "G.",
        _random("d2", 22, _URLSAFE) + "." + _random("d3", 43, _URLSAFE),
        "",
    ),
    ("databricks", "developer platform token", "da" + "pi", _random("d4", 32, _HEX), ""),
    ("shopify", "developer platform token", "sh" + "pat_", _random("d5", 32, _HEX), ""),
    ("atlassian", "developer platform token", "ATA" + "TT3", _random("d6", 180, _URLSAFE), ""),
    ("linear", "developer platform token", "lin" + "_api_", _random("d7", 40), ""),
    ("notion", "developer platform token", "nt" + "n_", _random("d8", 46), ""),
    (
        "postman",
        "developer platform token",
        "PM" + "AK-",
        _random("d9", 24, _HEX) + "-" + _random("da", 34, _HEX),
        "",
    ),
    ("doppler", "developer platform token", "d" + "p.pt.", _random("db", 43), ""),
    ("supabase-access", "developer platform token", "sb" + "p_", _random("dc", 40, _HEX), ""),
    ("supabase-secret", "developer platform token", "sb" + "_secret_", _random("dd", 32, _URLSAFE), ""),
    (
        "grafana-service-account",
        "developer platform token",
        "gl" + "sa_",
        _random("de", 32) + "_" + _random("df", 8, _HEX),
        "",
    ),
    ("grafana-cloud", "developer platform token", "gl" + "c_", _random("dg", 80, _BASE64), ""),
    ("sentry", "developer platform token", "sn" + "trys_", _random("dh", 60, _BASE64), ""),
    ("vault", "developer platform token", "h" + "vs.", _random("di", 90, _URLSAFE), ""),
    (
        "terraform-cloud",
        "developer platform token",
        _random("dj", 14) + ".atl" + "asv1.",
        _random("dk", 67, _URLSAFE),
        "",
    ),
    (
        "slack-webhook",
        "webhook URL",
        "https://hooks." + "slack.com/services/T0123ABCD/B0123ABCD/",
        _random("wh1", 24),
        "",
    ),
    (
        "discord-webhook",
        "webhook URL",
        "https://discord" + ".com/api/webhooks/123456789012345678/",
        _random("wh2", 68, _URLSAFE),
        "",
    ),
    (
        "teams-webhook",
        "webhook URL",
        "https://contoso.webhook" + ".office.com/webhookb2/",
        _random("wh3", 64, _HEX),
        "",
    ),
    (
        "outlook-webhook",
        "webhook URL",
        "https://outlook" + ".office.com/webhook/",
        _random("wh4", 40, _HEX),
        "",
    ),
    (
        "zapier-hook",
        "webhook URL",
        "https://hooks" + ".zapier.com/hooks/catch/1234567/",
        _random("wh5", 12),
        "/",
    ),
    (
        "zapier-mcp",
        "webhook URL",
        "https://mcp" + ".zapier.com/api/mcp/s/",
        _random("wh6", 64, _URLSAFE),
        "/mcp",
    ),
    ("zapier-actions", "webhook URL", "https://actions" + ".zapier.com/mcp/", _random("wh7", 48), "/sse"),
    ("make-webhook", "webhook URL", "https://hook.eu1" + ".make.com/", _random("wh8", 32, _HEX), ""),
    (
        "ifttt-webhook",
        "webhook URL",
        "https://maker" + ".ifttt.com/trigger/deploy/with/key/",
        _random("wh9", 22, _URLSAFE),
        "",
    ),
    (
        "telegram-bot",
        "webhook URL",
        "https://api.telegram" + ".org/bot123456789:",
        _random("wh10", 35, _URLSAFE),
        "/sendMessage",
    ),
    (
        "jwt",
        "JSON Web Token",
        "ey" + "J" + _random("j1", 20, _URLSAFE) + ".ey" + "J",
        _random("j2", 30, _URLSAFE) + "." + _random("j3", 43, _URLSAFE),
        "",
    ),
    ("pem-rsa", "private key", "-----BEGIN " + "RSA PRIVATE" + " KEY-----\n", _random("m1", 64, _BASE64), ""),
    ("pem-openssh", "private key", "-----BEGIN " + "OPENSSH PRIVATE" + " KEY-----\n", _random("m2", 64), ""),
    ("pem-pkcs8", "private key", "-----BEGIN " + "PRIVATE" + " KEY-----\n", _random("m3", 64, _BASE64), ""),
    (
        "azure-storage",
        "Azure account or shared access key",
        "DefaultEndpointsProtocol=https;AccountName=demo;Account" + "Key=",
        _random("z1", 86, _BASE64) + "==",
        ";EndpointSuffix=core.windows.net",
    ),
    (
        "azure-shared-access",
        "Azure account or shared access key",
        "Endpoint=sb://demo.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccess" + "Key=",
        _random("z2", 43, _BASE64) + "=",
        "",
    ),
    (
        "url-password",
        "password in a URL",
        "postgres" + "://scanner:",
        _random("u1", 20),
        "@db.internal:5432/app",
    ),
    ("url-password-without-user", "password in a URL", "redis" + "://:", _random("u2", 24), "@cache:6379/0"),
]


@pytest.mark.parametrize(
    "family,before,sample,after",
    [pytest.param(*case[1:], id=case[0]) for case in _PLANTED],
)
def test_planted_credential_is_reported_without_its_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    family: str,
    before: str,
    sample: str,
    after: str,
) -> None:
    text = f"# config\nvalue = {before}{sample}{after}\n"
    assert [(line, kind) for line, kind, _ in findings(text)] == [(2, family)]
    # No approvals: the repository's manifest would re-read every approved file for each case.
    manifest = tmp_path / "allowlist.json"
    manifest.write_text('{"version": 1, "entries": []}', encoding="utf-8")
    monkeypatch.setattr(check_secrets, "ALLOWLIST_PATH", manifest)
    monkeypatch.chdir(tmp_path)
    Path("sample.txt").write_text(text, encoding="utf-8")
    assert main(["sample.txt"]) == 1
    output = capsys.readouterr().out
    ((_, _, match),) = findings(text)
    assert output == (
        f"sample.txt:2: possible hardcoded {family}: {match[:4]}... ({len(match)} characters)\n"
    )
    # At most four characters of a match are printed, never a run of the planted value.
    assert not [
        sample[index : index + 5] for index in range(len(sample) - 4) if sample[index : index + 5] in output
    ]


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("aws_secret_access_key = <your-secret-access-key>", id="angle-placeholder"),
        pytest.param("SLACK_BOT_TOKEN=" + "xo" + "xb-your-bot-token", id="slack-placeholder"),
        pytest.param("risk-" + "assessmentframeworkversion2026", id="sk-inside-a-word"),
        pytest.param("task-" + _random("w1", 30), id="sk-inside-task"),
        pytest.param("lookup_" + "gh" + "p_" + _random("w2", 36), id="github-prefix-inside-identifier"),
        pytest.param("hf_hub_download(repo_id='org/model')", id="hf-identifier"),
        pytest.param("git clone git@github.com:org/repo.git https://github.com/org/repo", id="plain-urls"),
        pytest.param("ssh://git@example.net:22/org/repo", id="ssh-user-without-password"),
        pytest.param("-----BEGIN " + "PUBLIC KEY-----\n-----BEGIN CERTIFICATE-----", id="public-material"),
        pytest.param("signature: eyJhbGciOi", id="short-jwt-prefix"),
        pytest.param("redis" + "://:@cache:6379/0", id="url-without-password"),
        pytest.param("https://hooks." + "slack.com/services/...", id="webhook-placeholder"),
        pytest.param("npm_config_cache=/tmp/npm", id="npm-setting"),
        pytest.param("MIIB+" + "AB" + "SK" + _random("w3", 80, _BASE64), id="bedrock-prefix-inside-base64"),
        pytest.param("f" + "c-" + _random("w4", 48, _HEX), id="hex-run-longer-than-a-firecrawl-key"),
    ],
)
def test_lookalikes_that_have_no_credential_shape_are_not_reported(text: str) -> None:
    assert list(findings(text)) == []


# Formats the scanner withholds that the gate leaves out: neither has a prefix or host of its
# own, so ordinary names and routes match them.
_NOT_GATED = {
    "app-[A-Za-z0-9]{24}": "a common word prefix",
    ".+": "any host, since n8n is self-hosted: every '/webhook/' route matches",
}


def test_every_format_the_scanner_withholds_is_a_planted_family() -> None:
    # The scanner's backstop withholds these formats from every report, so a committed token
    # or webhook URL in one of them must fail the gate as well. Each '|' outside a group
    # separates two token formats: the next parenthesis after it opens a group, if any.
    texts = [f"{before}{sample}{after}" for _, _, before, sample, after in _PLANTED]
    formats = [
        alternative
        for pattern in (redaction_formats._SPECIFIC_TOKEN, redaction_formats._GENERIC_TOKEN)
        for alternative in re.split(r"\|(?![^()]*\))", pattern)
    ]
    urls = [urlsplit(url) for text in texts for url in re.findall(r"https://\S+", text)]
    hosts = [(host.pattern, prefix) for host, prefix in redaction_formats._PATH_SECRET_RULES]
    assert set(_NOT_GATED) <= set(formats) | {host for host, _ in hosts}
    assert [
        alternative
        for alternative in formats
        if alternative not in _NOT_GATED
        and not any(re.search(rf"\b(?:{alternative})\b", text, re.ASCII) for text in texts)
    ] == []
    assert [
        host
        for host, prefix in hosts
        if host not in _NOT_GATED
        and not any(re.fullmatch(host, url.hostname or "") and prefix.match(url.path) for url in urls)
    ] == []


def test_exit_codes_and_all_directories_are_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    planted = "gh" + "p_" + _random("e1", 36)
    scanned = [
        "tests/unit/test_example.py",
        "./tests/fixtures/export.json",
        "shadowscan/signatures/data/pack.yaml",
        "tools/evaluation/corpus.json",
        "tools/evaluation/review_corpus.json",
    ]
    reported = [
        "contests/app.py",
        "tools/evaluation/independent_annotations.json",
        "tools/evaluation/x/corpus.json",
    ]
    for name in scanned + reported:
        Path(name).parent.mkdir(parents=True, exist_ok=True)
        Path(name).write_text(planted, encoding="utf-8")
    Path("clean.md").write_text("No credentials here.\n", encoding="utf-8")
    Path("link.txt").symlink_to(tmp_path / reported[0])
    Path("submodule").mkdir()
    assert main(["clean.md", "link.txt", "submodule"]) == 0
    assert capsys.readouterr().out == ""
    # No file at all means the listing that feeds the check failed: never a pass.
    assert main([]) == 2
    assert "no files to check" in capsys.readouterr().err
    for name in scanned + reported:
        assert main([name]) == 1
        assert capsys.readouterr().out.startswith(f"{name}:1: possible hardcoded GitHub token")
    # A named file that cannot be read fails closed instead of passing unchecked.
    assert main(["missing.txt"]) == 1
    assert "missing.txt: cannot read" in capsys.readouterr().err


@pytest.mark.parametrize(
    "text",
    [
        "sk-" + "x" * 40,
        "sk-proj-" + _random("placeholder", 32) + "example",
        "sk-ant-api03-" + _random("redacted", 32) + "redacted",
        "AK" + "IAIOSFODNN7EXAMPLE",
        "postgres://app:${DB_PASSWORD}@db:5432/app",
        "postgres://app:REPLACE_ME@localhost:5432/app",
        "postgres://postgres:postgres@localhost/app",
        "postgres://returns:password@localhost/app",
        "postgres://app:" + _random("your", 20) + "your@db/app",
    ],
)
def test_credential_shaped_placeholders_also_need_an_exact_approval(text: str) -> None:
    assert list(findings(text))


def _approve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str, text: str) -> dict:
    source = tmp_path / path
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(text, encoding="utf-8")
    ((_, family, value),) = findings(text)
    entry = {"path": path, "family": family, "sha256": digest(value), "reason": "Synthetic test input."}
    if family == "private key":
        entry["content_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest = tmp_path / "allowlist.json"
    manifest.write_text(json.dumps({"version": 1, "entries": [entry]}), encoding="utf-8")
    monkeypatch.setattr(check_secrets, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(check_secrets, "ALLOWLIST_PATH", manifest)
    monkeypatch.chdir(tmp_path)
    return entry


@pytest.mark.parametrize(
    "path",
    [
        "tests/fixtures/export.json",
        "tests/unit/test_example.py",
        "shadowscan/signatures/data/pack.yaml",
        "tools/evaluation/corpus.json",
        "SECURITY.md",
    ],
)
def test_exact_synthetic_approval_does_not_exempt_new_values_or_another_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], path: str
) -> None:
    synthetic = "gh" + "p_" + _random("approved", 36)
    _approve(tmp_path, monkeypatch, path, synthetic)
    assert main([path]) == 0
    assert main([str(tmp_path / path)]) == 0
    assert main(["./" + path]) == 0
    unexpected = "gh" + "p_" + _random("unexpected", 36)
    (tmp_path / path).write_text(synthetic + "\n" + unexpected, encoding="utf-8")
    assert main([path]) == 1
    assert ":2: possible hardcoded GitHub token" in capsys.readouterr().out
    copied = tmp_path / "copied.txt"
    copied.write_text(synthetic, encoding="utf-8")
    assert main([str(copied)]) == 1
    assert "possible hardcoded GitHub token" in capsys.readouterr().out


@pytest.mark.parametrize(
    "mark,codec",
    [
        pytest.param(b"\xff\xfe", "utf-16-le", id="utf-16-le"),
        pytest.param(b"\xfe\xff", "utf-16-be", id="utf-16-be"),
        pytest.param(b"\xff\xfe\x00\x00", "utf-32-le", id="utf-32-le"),
        pytest.param(b"\x00\x00\xfe\xff", "utf-32-be", id="utf-32-be"),
    ],
)
def test_file_with_a_utf16_or_utf32_byte_order_mark_is_checked_in_that_encoding(
    tmp_path, monkeypatch, capsys, mark, codec
):
    # Windows PowerShell 5.1 redirects output to UTF-16LE with a mark, and the scanner
    # decodes such a file; read as UTF-8, NUL bytes split every credential in it.
    synthetic = "gh" + "p_" + _random("bom-approved", 36)
    _approve(tmp_path, monkeypatch, "tests/fixture.env", synthetic)
    fixture = tmp_path / "tests/fixture.env"
    fixture.write_bytes(mark + synthetic.encode(codec))
    # The approval reads the fixture as the check does, so it is neither stale nor bypassed.
    assert main(["tests/fixture.env"]) == 0
    unexpected = "gh" + "p_" + _random("bom-unexpected", 36)
    fixture.write_bytes(mark + f"{synthetic}\r\nGITHUB_TOKEN={unexpected}\r\n".encode(codec))
    assert main(["tests/fixture.env"]) == 1
    assert capsys.readouterr().out == (
        f"tests/fixture.env:2: possible hardcoded GitHub token: {unexpected[:4]}... (40 characters)\n"
    )


def test_stale_approvals_fail_even_during_a_partial_hook_run(tmp_path, monkeypatch, capsys):
    _approve(tmp_path, monkeypatch, "tests/fixture.txt", "gh" + "p_" + _random("stale", 36))
    (tmp_path / "tests/fixture.txt").write_text("removed fixture", encoding="utf-8")
    (tmp_path / "clean.txt").write_text("clean", encoding="utf-8")
    assert main(["clean.txt"]) == 1
    assert "stale approval" in capsys.readouterr().err


def test_private_key_approval_binds_its_body_and_not_only_the_begin_marker(tmp_path, monkeypatch, capsys):
    marker = "-----BEGIN " + "PRIVATE" + " KEY-----"
    _approve(tmp_path, monkeypatch, "tests/key.txt", marker + "\nSYNTHETIC_BODY\n")
    assert main(["tests/key.txt"]) == 0
    (tmp_path / "tests/key.txt").write_text(marker + "\n" + _random("body", 64), encoding="utf-8")
    assert main(["tests/key.txt"]) == 1
    assert "fixture contents changed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "change,message",
    [
        ({"path": "../fixture.txt"}, "repository-relative"),
        ({"family": "unknown"}, "unknown family"),
        ({"sha256": "invalid"}, "invalid SHA-256"),
        ({"reason": ""}, "missing review reason"),
        ({"content_sha256": "invalid"}, "invalid whole-file"),
        ({"extra": "field"}, "invalid fields"),
    ],
)
def test_malformed_approval_fails_closed(tmp_path, monkeypatch, capsys, change, message):
    entry = _approve(tmp_path, monkeypatch, "fixture.txt", "gh" + "p_" + _random("schema", 36))
    entry.update(change)
    check_secrets.ALLOWLIST_PATH.write_text(json.dumps({"version": 1, "entries": [entry]}))
    assert main(["fixture.txt"]) == 1
    assert message in capsys.readouterr().err


def test_private_key_marker_cannot_be_approved_without_its_whole_file_digest(tmp_path, monkeypatch, capsys):
    entry = _approve(tmp_path, monkeypatch, "fixture.txt", "-----BEGIN " + "PRIVATE" + " KEY-----")
    del entry["content_sha256"]
    check_secrets.ALLOWLIST_PATH.write_text(json.dumps({"version": 1, "entries": [entry]}))
    assert main(["fixture.txt"]) == 1
    assert "whole-file digest" in capsys.readouterr().err


def test_unparseable_allowlist_does_not_echo_its_contents(tmp_path, monkeypatch, capsys):
    _approve(tmp_path, monkeypatch, "fixture.txt", "gh" + "p_" + _random("parse", 36))
    for malformed in (_random("bad-json", 36), "[" * 2000 + "0" + "]" * 2000):
        check_secrets.ALLOWLIST_PATH.write_text(malformed)
        assert main(["fixture.txt"]) == 1
        output = capsys.readouterr().err
        assert output in {
            "check_secrets: cannot read or parse approval manifest\n",
            "check_secrets: allowlist must contain version and entries\n",
        }
        assert malformed not in output


def test_duplicate_approvals_and_json_fields_fail_closed(tmp_path, monkeypatch, capsys):
    entry = _approve(tmp_path, monkeypatch, "fixture.txt", "gh" + "p_" + _random("duplicate", 36))
    check_secrets.ALLOWLIST_PATH.write_text(json.dumps({"version": 1, "entries": [entry, entry]}))
    assert main(["fixture.txt"]) == 1
    assert "duplicate approval" in capsys.readouterr().err
    check_secrets.ALLOWLIST_PATH.write_text('{"version":1,"entries":[],"entries":[]}')
    assert main(["fixture.txt"]) == 1
    assert "duplicate JSON field" in capsys.readouterr().err


def test_missing_manifest_or_approved_fixture_fails_closed(tmp_path, monkeypatch, capsys):
    _approve(tmp_path, monkeypatch, "fixture.txt", "gh" + "p_" + _random("missing", 36))
    (tmp_path / "fixture.txt").unlink()
    assert main(["fixture.txt"]) == 1
    assert "missing or is not a regular file" in capsys.readouterr().err
    check_secrets.ALLOWLIST_PATH.unlink()
    assert main(["fixture.txt"]) == 1
    assert "cannot read or parse approval manifest" in capsys.readouterr().err


def test_patterns_stay_linear_on_hostile_input() -> None:
    hostile = [
        "eyJ" * 70_000,
        "eyJ" + "A" * 200_000,
        "x://" + "a:" * 100_000,
        "a" * 200_000,
        "-----BEGIN " + "A " * 100_000,
        "sk-" * 70_000,
        "aws_secret_access_key" + " " * 200_000,
        "AccountKey" + " " * 200_000 + "=",
        "ICAg" * 70_000,
        ".ICAg" * 56_000,
        "ICAg" * 50_000 + "ewoi" + "A" * 100_000 + ".",
        "x://" + ":" * 200_000,
        "fw_" + "a" * 200_000,
        "hook." * 40_000,
    ]
    started = time.perf_counter()
    for text in hostile:
        list(findings(text))
    # Linear scans of every pattern take about a second and a half here; a quadratic one
    # would take minutes. The bound leaves room for a loaded test runner.
    assert time.perf_counter() - started < 3


def test_reported_file_names_cannot_forge_a_report_line_or_a_workflow_command(tmp_path, capsys):
    # A tracked file name may hold control characters; the report escapes them
    # so a crafted name cannot start a new line or a `::` workflow command.
    path = tmp_path / "config.py\n::error::forged"
    path.write_text("token = 'sk-" + "proj-" + _random("n1", 40, _URLSAFE) + "'\n", encoding="utf-8")
    assert main([str(path)]) == 1
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and "\\x0a::error::forged" in out
    assert display("plain/name.py") == "plain/name.py"


@pytest.mark.parametrize(
    "header", [b' {"alg":"HS256"}', b'{ "alg":"HS256"}', b'{\n "alg":"RS256"}', b'\t{"alg":"none"}']
)
def test_jwt_with_whitespace_header_is_reported(header):
    import base64

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    token = b64(header) + "." + b64(b'{"sub":"synthetic-subject"}') + "." + b64(bytes(range(40)))
    ((_, family, value),) = findings(f"auth = {token}\n")
    assert family == "JSON Web Token" and value == token


def test_jwt_with_any_json_whitespace_around_the_header_brace_is_reported():
    # json.loads, and so PyJWT, accepts any JSON whitespace before or after the header's '{':
    # '{\t"' (ewki), '{\r\n' (ew0K), '  {' (ICB7), '\r\n{' (DQp7), three or more bytes before it.
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    runs = [bytes(run) for size in range(5) for run in itertools.product(b" \t\r\n", repeat=size)]
    tail = "." + b64(b'{"sub":"synthetic-subject"}') + "." + b64(bytes(range(40)))
    for before in [*runs, b" " * 5, b"\r\n" * 4, b"\n\t" * 3 + b" " * 4]:
        for after in runs[:21]:
            for key in (b'"alg":"HS256"}', b'"0":1,"alg":"none"}'):
                if before or after:
                    token = b64(before + b"{" + after + key) + tail
                    assert [value for _, _, value in findings(token)] == [token], (before, after, key)

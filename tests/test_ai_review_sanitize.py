"""Regression tests for tools.ai_review.sanitize.

The sanitizer is the last line of defense before untrusted pull-request
text reaches a posted review or a workflow log: credential-shaped strings
must never survive it, and no line it emits may be a workflow command.
The families mirror tools/check_secrets.py closely enough for posted text;
check_secrets.py remains the authoritative file gate with exact approvals.
"""

from __future__ import annotations

import time

import pytest

from tools.ai_review.sanitize import _PATTERNS, redact
from tools.check_secrets import PATTERNS, findings


def test_a_private_key_block_is_withheld_whole() -> None:
    body = "\n".join(["MIIEow" + "IBAAKCAQEA" * 6, "Zz9" * 21, "Qq1" * 10 + "=="])
    # Assembled at runtime so no key-shaped literal sits in the source.
    begin, end = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"
    key = f"{begin}\nProc-Type: 4,ENCRYPTED\n\n{body}\n{end}"
    out = redact(f"Scenario: key committed:\n{key}\nRotate it.")
    assert out == "Scenario: key committed:\n[redacted]\nRotate it."


@pytest.mark.parametrize(
    "quote",
    [
        '"private_key": "{begin}\\n{body}\\n{end}\\n"',
        "{begin} {body} {end}",
        "> {begin}\n> {body}\n> {end}",
    ],
)
def test_a_private_key_quoted_on_one_line_or_escaped_is_withheld_whole(quote: str) -> None:
    begin, end = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 2
    out = redact(quote.format(begin=begin, body=body, end=end) + " Rotate it.")
    assert body not in out and "END" not in out and out.endswith(" Rotate it.")


@pytest.mark.parametrize(
    "quote",
    [
        "{begin} {body}",
        "{begin}\\n{body}\\n",
        # Escaped CRLF, as a JSON string of a Windows file quotes it.
        "{begin}\\r\\n{body}\\r\\n{line}\\r\\n",
        # A Markdown blockquote, the usual way a review finding quotes a file.
        "> {begin}\n> {body}\n> {line}\n",
        "> {begin}\r\n> {body}\r\n> {line}\r\n",
        "> > {begin}\n> > {body}\n> > {line}\n",
        "> {begin}\n>\n> {body}\n> {line}\n",
        "> {begin}\n> Proc-Type: 4,ENCRYPTED\n> DEK-Info: AES-128-CBC,00FF\n>\n> {body}\n> {line}\n",
        # Encryption headers after escaped line breaks, as a JSON string quotes them.
        "{begin}\\nProc-Type: 4,ENCRYPTED\\nDEK-Info: AES-128-CBC,00FF\\n\\n{body}\\n{line}\\n",
        "{begin}\\r\\nProc-Type: 4,ENCRYPTED\\r\\nDEK-Info: AES-128-CBC,00FF\\r\\n\\r\\n{body}\\r\\n{line}\\r\\n",
        "{begin}\\n> Proc-Type: 4,ENCRYPTED\\n> DEK-Info: AES-128-CBC,00FF\\n>\\n> {body}\\n> {line}\\n",
    ],
)
def test_a_footerless_private_key_on_one_line_or_escaped_is_withheld(quote: str) -> None:
    # A reviewer may quote a truncated key without its footer; the body must not be published.
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    body, line = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 2, "Qq1Zz9" * 5
    out = redact(quote.format(begin=begin, body=body, line=line) + " Rotate it.")
    assert body not in out and line not in out and out.endswith(" Rotate it.")


@pytest.mark.parametrize("scheme", ["postgresql+psycopg2", "postgresql+asyncpg", "mysql+mysqlconnector"])
@pytest.mark.parametrize(
    "quote",
    [
        "> {begin}\n> {url}\nRotate it.",
        "> > {begin}\n> > {url}\nRotate it.",
        "> {begin}\n>\n> {url}\nRotate it.",
        '"{begin}\\r\\n{url}"',
        '"{begin}\\n{url}"',
        "{begin} {url}",
        "{begin}\n{url}",
        "{begin}\n{body}\n{url}",
    ],
)
def test_a_url_password_after_a_footerless_key_header_is_withheld(quote: str, scheme: str) -> None:
    # A footerless key's base64 run takes in a long URL scheme on the next line and
    # stops at ':'. The URL rule must still see the whole URL and withhold its password.
    begin, password = "-----BEGIN " + "PRIVATE KEY-----", "Synthetic-" + "Passw0rd"
    url = f"{scheme}://admin:{password}@db.internal/prod"
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 2
    out = redact(quote.format(begin=begin, url=url, body=body))
    assert password not in out and body not in out and "BEGIN" not in out


def test_a_credential_inside_a_key_body_hides_neither() -> None:
    # Each rule sees the original text, and the text as the earlier rules left it:
    # an Azure key inside a footerless key body leaves the lines after it withheld,
    # and a key run that swallows one Azure key label leaves the next key withheld.
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    body, first, second = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 2, "U3ludGhldGljS2V5" * 3, "QWxhZGRp" * 6
    out = redact(f"{begin}\n\nAccountKey={first}\\n{body}\\n")
    assert first not in out and body not in out
    out = redact(f"{begin}\tAAAA{body}==/SharedAccessKey = {first}/AccountKey={second}=\nRotate them.")
    assert body not in out and first not in out and second not in out and out.endswith("\nRotate them.")


def test_prose_after_a_quoted_key_header_is_kept() -> None:
    begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
    finding = (
        f"Scenario: the file begins with\n{begin}\n\nRecommendation: Rotate the key.\n\nAssumptions: None."
    )
    assert redact(finding) == (
        "Scenario: the file begins with\n[redacted]\n\nRecommendation: Rotate the key.\n\nAssumptions: None."
    )
    assert redact(f"```\n{begin}\n```") == "```\n[redacted]\n```"
    # Quoted as a Markdown blockquote, the prose after the header is kept too.
    assert redact(f"> {begin}\n>\n> Recommendation: Rotate the key.") == (
        "> [redacted]\n>\n> Recommendation: Rotate the key."
    )


def test_every_check_secrets_family_is_redacted() -> None:
    samples = {
        "OpenAI API key": "call with sk-" + "aA1" * 7 + "aA",
        "OpenAI project key": "key sk-proj-" + "Ab1-" * 9,
        "Anthropic API key": "sk-ant-api03-" + "Zz9_" * 6,
        "AWS access key ID": "AKIA" + "1A2B" * 4,
        "AWS secret access key": "aws_secret_access_key = " + "A1b2/+" * 6 + "C3d4",
        "GitHub token": "ghp_" + "a1" * 20,
        "GitHub fine-grained token": "github_pat_" + "a" * 22 + "_" + "b" * 59,
        "GitLab token": "glpat-" + "x1-" * 8,
        "Slack token": "xoxb-" + "1234-" + "abcDEF0123-xyz",
        "Google API key": "AIza" + "qQ1-" * 8 + "_x1",
        "Google OAuth credential": "ya" + "29." + "Ab1_" * 10,
        "Hugging Face token": "hf_" + "zZ9" * 12,
        "Stripe key": "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "AI service API key": "gs" + "k_" + "aA1" * 18,
        "package registry token": "np" + "m_" + "aA1" * 12,
        "developer platform token": "da" + "pi" + "0a1b" * 8,
        "webhook URL": "https://hooks." + "slack.com/services/T0/B0/" + "aA1" * 8,
        "JSON Web Token": "eyJ" + "h" * 12 + ".eyJ" + "p" * 12 + "." + "s" * 12,
        "private key": "-----BEGIN " + "PRIVATE KEY-----",
        "Azure account or shared access key": "AccountKey=" + "QWxhZGRpbjEyMzQ1" * 3 + "==",
        "password in a URL": "https://" + "user:" + "synthetic-password@" + "example.internal/path",
    }
    # The two lists cannot drift: a family check_secrets.py learns needs a
    # redacted sample here, and a sample here must still be a known family.
    assert set(samples) == {family for family, _ in PATTERNS}
    for family, sample in samples.items():
        detected = {fam for _, fam, _ in findings(sample)}
        assert family in detected, f"test sample for {family!r} is not shaped like one"
        out = redact(f"prefix {sample} suffix")
        assert sample not in out, f"{family} survived redact()"
        assert "[redacted]" in out
        assert out.startswith("prefix ") and out.endswith(" suffix")


def test_every_check_secrets_pattern_but_the_key_header_is_matched_unchanged() -> None:
    # Only the private key rule differs: the sanitizer withholds the whole block, the file
    # gate reports its header. Every other format is the gate's own pattern.
    assert {pattern.pattern for family, pattern in PATTERNS if family != "private key"} <= {
        pattern.pattern for pattern in _PATTERNS
    }


def test_a_url_password_without_a_user_name_is_redacted() -> None:
    password = "Hq7Zr2" + "Lm9Xw4"
    out = redact("REDIS_URL=redis" + "://:" + password + "@cache:6379/0")
    assert password not in out and out.startswith("REDIS_URL=[redacted]")


@pytest.mark.parametrize("token", ["sk-" + "A" * 8171, "glpat-" + "B" * 8200, "hf_" + "C" * 8300])
def test_a_key_whose_footer_a_long_token_moves_out_of_reach_is_withheld_whole(token: str) -> None:
    # Matched in turn, an earlier rule replaced the token with the marker, which
    # brought the footer within the key rule's bounded search. A replacement
    # that kept the token's length left the footer out of reach, and the key
    # lines after the token and the footer were published.
    begin, end = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
    line = "Zqu8" + "jzPde0IgxLd6"
    out = redact(f"Scenario:\n{begin}\n{token}\n{line}\n{end}\nRotate it.")
    assert out == "Scenario:\n[redacted]\nRotate it."


def _url_password_cases() -> list[tuple[str, int, list[str]]]:
    header = "-----BEGIN " + "PRIVATE KEY-----"
    azure = "AccountKey=" + "Ab3/" * 11
    password, inner, tail = "Hq7Zr2" + "Lm9Xw4", "Pw6Ys0" + "Ga2Fe8", "Vt3Nb8" + "Kc5Jd1"
    # Joined at runtime so the source holds no URL with a password.
    scheme, user = "postgresql+psycopg2://", "u:"
    url = scheme + user + f"{password};{azure};{tail}@h"
    google = "AIzaHq7Zr2Lm9Xw4Vt3N" + "_b8Kc5Jd1Pw6Ys0Ga2F"
    return [
        (f"> {header}\n> {url}", 1, [password, tail]),
        (f"{header} {url}", 1, [password, tail]),
        (
            f"> {header}\n> " + scheme + user + password + "redis://" + "a:" + f"{inner}@cache{tail}@h",
            2,
            [password, inner, tail],
        ),
        (f"> {header}\n> {google}{header}", 2, [google[20:]]),
    ]


@pytest.mark.parametrize(("text", "passes", "secrets"), _url_password_cases())
def test_a_quoted_key_header_leaves_a_url_password_to_the_url_rule(
    text: str, passes: int, secrets: list[str]
) -> None:
    # The key rule's run took in the URL's scheme ('postgresql+psycopg2'), so the
    # URL rule, which matches only once the Azure key or inner URL in the password
    # is replaced, never did. The earlier key rules stopped at the header and left
    # the scheme; the patterns are matched in turn with them as well, twice, as a
    # posted review body is redacted twice.
    out = text
    for _ in range(passes):
        out = redact(out)
    assert not any(secret in out for secret in secrets)


@pytest.mark.parametrize("layout", ["\n>", "\n> ", " ", "\\n", "\\r\\n"])
@pytest.mark.parametrize("depth", [2, 3])
def test_a_url_nested_in_a_url_password_after_a_key_header_is_withheld_on_the_first_pass(
    layout: str, depth: int
) -> None:
    # Matched in turn, the outer URL matches only once every URL inside its
    # password is replaced, one per sweep; the gate's later passes did that
    # while the key rule's wider run had already taken the outer scheme. The
    # rules now sweep until they match nothing more.
    header = "-----BEGIN " + "PRIVATE KEY-----"
    secret = "IkRveITF" + "o1CPdwbf"
    inner = "u" + ":" + "rfnUCi@h@;"
    for _ in range(depth):
        inner = "s://u" + ":" + inner
    text = header + layout + "postgresql+psycopg2://u" + ":" + inner + secret + "@h"
    assert secret not in redact(text)


def test_a_long_blank_run_after_a_key_header_is_scanned_in_linear_time() -> None:
    # The blank runs before a footerless key's base64 lines could be split
    # between two quantifiers, which made the scan quadratic in the run's length.
    header = "-----BEGIN " + "PRIVATE KEY-----"
    started = time.perf_counter()
    for blank in (" ", "\t", "\\n "):
        redact(header + "\n" + blank * 40_000 + "!")
    assert time.perf_counter() - started < 5


def test_workflow_commands_are_neutralized() -> None:
    out = redact("normal line\n::set-output name=x::1\n::warning::hi")
    assert "\n::" not in out
    assert not out.startswith("::")
    assert "set-output" in out  # content stays readable, command is inert


def test_plain_text_passes_through() -> None:
    text = "requests.post(url, timeout=30)  # no retry on 429"
    assert redact(text) == text


def test_redaction_is_idempotent() -> None:
    text = "token ghp_" + "a1" * 20 + " here"
    assert redact(redact(text)) == redact(text)


def test_jwt_with_whitespace_header_is_redacted():
    import base64

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    token = b64(b' {"alg":"HS256"}') + "." + b64(b'{"sub":"synthetic"}') + "." + b64(bytes(range(40)))
    assert token not in redact(f"leaked {token} here")


def test_jwt_with_any_json_whitespace_around_the_header_brace_is_redacted():
    import base64
    import itertools

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    # Up to three whitespace bytes before the '{' and two after it ('{\t"' is ewki, '  {' is
    # ICB7, '\r\n{' is DQp7); the first token, with none, is the compact 'eyJ' one.
    runs = [bytes(run) for size in range(4) for run in itertools.product(b" \t\r\n", repeat=size)]
    tail = "." + b64(b'{"sub":"synthetic"}') + "." + b64(bytes(range(40)))
    tokens = [b64(before + b"{" + after + b'"alg":"HS256"}') + tail for before in runs for after in runs[:21]]
    assert redact(" ".join(tokens[1:])) == " ".join(["[redacted]"] * (len(tokens) - 1))

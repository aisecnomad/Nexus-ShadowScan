"""The run glued after an authorization scheme's credential ('<token>--x', '<token>=x').

A run that names nothing a later pass reads is the token's own tail and is
withheld with it. A run that holds such a name anywhere stays in the text for
the pass that withholds the value after it, and a run that ends in another
scheme is left to the scan, which withholds that scheme's credential. Each
value below was withheld before the run was read with the credential, and
reading it there must not show it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text

ROOT = Path(__file__).resolve().parents[2]
# Synthetic and built at runtime, like every credential-shaped test value here.
SECRET = "Zq8" + "Lm2Xw9Rt4Yu7Io1Pa5Sd3Fg6Hj0Kl"
VALUE = "Hv7" + "Qx2Lm9Pw4Rt6Yu1"
SCHEMES = ("Bearer", "Basic", "SSWS")


def _shown(text: str, value: str) -> bool:
    return value in sanitize_text(text) or value in sanitize({"note": text})["note"]


@pytest.mark.parametrize(
    "context", ["{}", "x \\n{}", "run --header={}", "please send {} now", '{{"h": "{}"}}']
)
@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize(
    "glued",
    [
        # Options the option rules read whose names the credential-name test missed.
        "--auth ",
        "--pat ",
        "--authorization ",
        "--cookie ",
        # A credential name after the first piece of the run.
        "=x--password ",
        "--x=password: ",
        "=x--token ",
        "=user--api-key ",
        "--x/password: ",
        "=a=b--passwd ",
    ],
)
@pytest.mark.parametrize("credential", ["abc123", SECRET])
def test_a_name_anywhere_in_a_glued_run_keeps_the_value_after_it_withheld(
    credential: str, glued: str, scheme: str, context: str
) -> None:
    # The run was judged as one name ('x--password', 'x=password'), which none
    # of these is, so it went with the credential and took with it the name
    # the option or assignment rule needed to withhold the value.
    text = context.format(f"{scheme} {credential}{glued}{VALUE}")
    assert not _shown(text, VALUE)
    assert not _shown(text, SECRET)


@pytest.mark.parametrize(
    "text",
    [
        # A quoted value that does not look opaque: only the option rule withholds it.
        'Bearer {secret}--password="hunter2pass"',
        'Basic {secret}--password="hunter2pass"',
        'SSWS {secret}--password="hunter2pass"',
        # Base64 padding ends the credential before the glued run.
        "SSWS dXNlcjpwYXNz==db--password hunter2pass",
        "Authorization: Basic dXNlcjpwYXNz==api-key\n= hunter2pass",
        "x \\nBearer abc123=x--password hunter2pass",
    ],
)
def test_a_glued_name_keeps_a_value_no_other_rule_withholds(text: str) -> None:
    assert not _shown(text.format(secret=SECRET), "hunter2pass")


@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize("credential", ["abc123", SECRET])
@pytest.mark.parametrize(
    "glued",
    [
        # Joined at runtime so the source holds no URL with a password.
        "--x.https://h/login?next=https://u" + ":{v}@b",
        "=redis://:{v}x@a,redis://:{v}@b",
        "--x+postgres://h/login?next=https://u" + ":{v}@b",
    ],
)
def test_a_glued_run_a_colon_follows_stays_for_the_url_rules(
    credential: str, glued: str, scheme: str
) -> None:
    # Withheld with the credential, the run took the scheme of the URL after
    # it, and the rule that reads a URL inside another URL's text no longer
    # found the outer one, so the inner URL's password was shown.
    text = f"{scheme} {credential}" + glued.format(v=VALUE)
    assert not _shown(text, VALUE)


@pytest.mark.parametrize("scheme", SCHEMES)
def test_the_token_word_form_keeps_a_glued_run_a_colon_follows(scheme: str) -> None:
    # The token word form now withholds a glued tail too; a run a colon
    # follows is not a tail and stays for the URL rules, as before.
    text = f"{scheme} token {SECRET}=redis://:{VALUE}x@a,redis://:{VALUE}@b"
    assert not _shown(text, VALUE)
    assert not _shown(text, SECRET)


@pytest.mark.parametrize("context", ["{}", "run --header={}", "please send {} now", '{{"h": "{}"}}'])
@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize("glued", ["--SSWS ", "=Basic ", "--x.Bearer\t"])
@pytest.mark.parametrize("credential", ["abc123", SECRET, "token " + SECRET])
def test_a_glued_run_ending_in_a_scheme_leaves_that_scheme_to_the_scan(
    credential: str, glued: str, scheme: str, context: str
) -> None:
    # Read with the credential, the run hid the next scheme from the scan, so
    # that scheme's credential was shown, or withheld only on a second pass.
    text = context.format(f"{scheme} {credential}{glued}{VALUE}")
    cleaned = sanitize_text(text)
    assert VALUE not in cleaned and SECRET not in cleaned
    assert sanitize_text(cleaned) == cleaned
    assert not _shown(text, VALUE)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"Bearer\n{SECRET}--password {VALUE}", f"Bearer {REDACTED}\n--password {REDACTED}"),
        (f"Basic \n {SECRET}=password: {VALUE}", f'Basic {REDACTED}\n=password: "{REDACTED}"'),
        (f"SSWS\n\n{SECRET}--auth {VALUE}", f"SSWS {REDACTED}\n\n--auth {REDACTED}"),
    ],
)
def test_a_kept_glued_run_keeps_the_line_breaks_after_the_scheme(text: str, expected: str) -> None:
    # The scheme's blanks may span lines; excerpt lines stay aligned.
    assert sanitize_text(text) == expected


def test_long_glued_runs_are_read_in_linear_time() -> None:
    # Each glued run is split once and each distinct name in it judged once.
    # This generous bound tells linear work (a second or two) from quadratic
    # work, which takes minutes at this size.
    script = """
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize_text
n = 100_000
secret = 'Zq8' + 'Lm2Xw9Rt4Yu7Io1Pa5Sd3Fg6Hj0Kl'
shapes = [
    'Bearer a' + '--a' * n, 'Bearer a=' + 'a=' * n, 'Bearer a--' + 'a_' * n + 'pass',
    'Bearer a--' + 'a-' * n + 'password', 'Bearer a--' + 'aA0' * n, 'Bearer a--' + '--ab' * n,
    'Bearer a--Bearer ' * (n // 4), '\\\\nBearer a--x' * (n // 4), 'Bearer a--' + 'x' * n + '.Bearer ',
    'Bearer token ' + secret + '--' + 'a+' * n, 'Bearer a--' + '__' * n, 'Bearer a--' + 'a/' * n,
]
for shape in shapes:
    try:
        sanitize_text(shape)
    except SanitizationLimitError:
        pass  # a nesting limit fails closed, quickly
assert sanitize_text('Bearer ' + secret + '--' + 'a' * n) == 'Bearer ' + REDACTED
"""
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr

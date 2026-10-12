"""The run glued after an authorization scheme's credential ('<token>--x', '<token>=x').

The credential stops before the run, and every pass reads the run as any
other text: a name in it withholds the value after it, a run the assignment
rules read on past keeps the value they reach withheld, and a run that ends in
another scheme leaves that scheme to the scan. After all of them, a run that
may hold no name a pass reads is the token's own tail and is withheld with the
credential, with or without the 'token' word. That last step only removes
text, so each value below stays withheld as the passes withhold it, and no
tail below is shown.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text

ROOT = Path(__file__).resolve().parents[2]
# Synthetic and built at runtime, like every credential-shaped test value here.
SECRET = "Zq8" + "Lm2Xw9Rt4Yu7Io1Pa5Sd3Fg6Hj0Kl"
VALUE = "Hv7" + "Qx2Lm9Pw4Rt6Yu1"
TAIL = "Xw7Qa2Zr9Lt4Mn1Vb5" + "Cd8Ef3Gh6Jk0PqSt"
SCHEMES = ("Bearer", "Basic", "SSWS")
# Plain text, after an escaped line break, and inside a JSON string.
CONTEXTS = ("{}", "x\\n{}", "json")


def _placed(context: str, text: str) -> str:
    if context == "json":
        return '{"a": "' + text.replace('"', '\\"') + '"}'
    return context.format(text)


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


@pytest.mark.parametrize("context", CONTEXTS)
@pytest.mark.parametrize(
    "follow",
    [
        # The assignment rules read '=v1=' or '=x=y' as an assignment whose
        # value runs on, and find the name in what it runs over; or they read
        # the run as the key before '": "'.
        "=v1= user: u\\npassword: {v}",
        "=x=y(x = password: {v}",
        '=x": "v"=y\\npassword: {v}',
        "=a.b=c&user: u\\npassword: {v}",
        "=x=y\\nuser: u\\npassword: {v}",
        "--a-b=c=d#user: u\\npassword: {v}",
        "=v1=(y = password: {v}&",
    ],
)
@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize("credential", ["abc123", SECRET, "dXNlcjpwYXNz==", "token " + SECRET])
def test_a_glued_run_a_rule_reads_past_keeps_the_value_it_reaches_withheld(
    credential: str, scheme: str, follow: str, context: str
) -> None:
    # Withheld with the credential, in the scheme's own pass, the run took
    # with it the text those rules read, with or without the 'token' word,
    # and they showed the value.
    text = _placed(context, f"{scheme} {credential}" + follow.format(v=VALUE))
    assert not _shown(text, VALUE)
    assert not _shown(text, SECRET)


@pytest.mark.parametrize("context", [*CONTEXTS, "please send {} now"])
@pytest.mark.parametrize(
    "glued",
    [
        "--{t}",
        "=x{t} more words",
        # A colon after the run, which the URL and setting rules read first.
        "--{t}:",
        "={t}:x",
        # A run that ends in another scheme, whose credential the scan withholds.
        "--{t}-Bearer {v}",
        "--{t}.SSWS\t{v}",
        "=x{t}=Basic {v}",
        # That scheme's own tail.
        "--{t}-Bearer {v}--{t}",
        "=Bearer {v}={t}",
    ],
)
@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize("credential", [SECRET, "token " + SECRET, "dXNlcjpwYXNz=="])
def test_a_token_tail_is_withheld_whatever_follows_it(
    credential: str, scheme: str, glued: str, context: str
) -> None:
    # Before, a tail a colon or a scheme followed was left out of the match
    # and shown, and so was any tail after the 'token' word.
    text = _placed(context, f"{scheme} {credential}" + glued.format(t=TAIL, v=VALUE))
    for value in (TAIL[:9], TAIL[-9:], VALUE, SECRET):
        assert not _shown(text, value)
    cleaned = sanitize_text(text)
    assert sanitize_text(cleaned) == cleaned


def _tokens(text: str) -> Counter[str]:
    counts = Counter(re.findall(r"[A-Za-z0-9]+", text))
    del counts["REDACTED"]
    return counts


def test_withholding_the_tails_last_shows_nothing_the_other_passes_withhold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Without the last step the passes read the glued run as they did before
    # the step existed. With it, no word may be shown more often than without.
    texts = [
        _placed(context, f"{scheme} {credential}{glued}")
        for scheme in SCHEMES
        for credential in ("abc123", SECRET, "dXNlcjpwYXNz==", "token " + SECRET)
        for glued in (
            f"--password {VALUE}",
            f"=x--auth {VALUE}",
            f"--x=api-key: {VALUE}",
            f"=v1= user: u\\npassword: {VALUE}",
            f'=x": "v"=y\\npassword: {VALUE}',
            f"--a-b=c=d#user: u\\npassword: {VALUE}",
            f"--{TAIL}:",
            f"--{TAIL}-Bearer {VALUE}--{TAIL}",
            # Joined at runtime so the source holds no URL with a password.
            "--x.https://h/login?next=https://u" + f":{VALUE}@b",
            f"=x{TAIL} more words",
        )
        for context in CONTEXTS
    ]
    last = [(sanitize_text(text), sanitize({"note": text})["note"]) for text in texts]
    monkeypatch.setattr(redaction, "_withhold_scheme_tails", lambda text: text)
    passes = [(sanitize_text(text), sanitize({"note": text})["note"]) for text in texts]
    for text, (text_last, note_last), (text_passes, note_passes) in zip(texts, last, passes, strict=True):
        assert not _tokens(text_last) - _tokens(text_passes), text
        assert not _tokens(note_last) - _tokens(note_passes), text
        assert VALUE not in text_last + note_last and TAIL[:9] not in text_last + note_last, text


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
def test_a_glued_run_a_colon_follows_is_withheld_after_the_url_rules(
    credential: str, glued: str, scheme: str
) -> None:
    # Withheld with the credential, the run took the scheme of the URL after
    # it, and the rule that reads a URL inside another URL's text no longer
    # found the outer one, so the inner URL's password was shown. Withheld
    # after every rule, it hides nothing from them.
    text = f"{scheme} {credential}" + glued.format(v=VALUE)
    assert not _shown(text, VALUE)


@pytest.mark.parametrize("prefix", ["Basic abc123==Bearertoken:", "run --header=Basic\tabc123==Bearertoken:"])
def test_a_glued_run_is_withheld_only_after_the_second_reading_of_nested_urls(prefix: str) -> None:
    # The nested URL rule changes this text, and the passes then read it
    # once more; that reading withholds the whole URL as the value of the
    # assignment the glued run starts. Withheld before it, the run left the
    # URL's host and path shown.
    text = prefix + "Bearer abc123==api-keySSWSa.bv1Basic.https://h/?next=https://u" + f":{VALUE}@b"
    for shown in (sanitize_text(text), sanitize({"note": text})["note"]):
        assert "next" not in shown and VALUE not in shown


@pytest.mark.parametrize("scheme", SCHEMES)
def test_the_token_word_form_withholds_a_glued_url_run_after_the_url_rules(scheme: str) -> None:
    # The token word form withholds its glued tail too, and only after the
    # URL rules have read the URLs in it.
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
        (f"Bearer\n{SECRET}--{TAIL} x", f"Bearer {REDACTED}\n x"),
        (f"Bearer token\n{SECRET}=x{TAIL}\n", f"Bearer {REDACTED}\n\n"),
    ],
)
def test_a_glued_run_keeps_the_line_breaks_after_the_scheme(text: str, expected: str) -> None:
    # The scheme's blanks may span lines; excerpt lines stay aligned whether
    # the run is kept or withheld.
    assert sanitize_text(text) == expected


def test_long_glued_runs_are_read_in_linear_time() -> None:
    # Each glued run is split once and each distinct name in it judged once,
    # and a run stops at the next scheme's marker. This generous bound tells
    # linear work (a second or two) from quadratic work, which takes minutes
    # at this size.
    script = """
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize_text
n = 100_000
secret = 'Zq8' + 'Lm2Xw9Rt4Yu7Io1Pa5Sd3Fg6Hj0Kl'
marker = 'Bearer ' + REDACTED
shapes = [
    'Bearer a' + '--a' * n, 'Bearer a=' + 'a=' * n, 'Bearer a--' + 'a_' * n + 'pass',
    'Bearer a--' + 'a-' * n + 'password', 'Bearer a--' + 'aA0' * n, 'Bearer a--' + '--ab' * n,
    'Bearer a--Bearer ' * (n // 4), '\\\\nBearer a--x' * (n // 4), 'Bearer a--' + 'x' * n + '.Bearer ',
    'Bearer token ' + secret + '--' + 'a+' * n, 'Bearer a--' + '__' * n, 'Bearer a--' + 'a/' * n,
    'Bearer a--x-' * (n // 4), (marker + '=') * (n // 4), 'Bearer a--' + 'Bearer' * n,
    marker + '\\n' * n + '--x', 'x\\\\nBearer a=v1= ' * (n // 4), (marker + '\\n') * (n // 4) + '--x',
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

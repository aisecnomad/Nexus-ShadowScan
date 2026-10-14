"""The run glued after an authorization scheme's credential ('<token>--x', '<token>=x').

The credential stops before the run, and every pass reads the run as any
other text: a name in it withholds the value after it, a run the assignment
rules read on past keeps the value they reach withheld, and a run that ends in
another scheme leaves that scheme to the scan. After all of them, and in
``sanitize`` after the known values are removed too, the run is withheld with
the credential, with or without the 'token' word, unless the whole run is one
name a pass reads ('--password'). That last step only removes text, so each
value below stays withheld as the passes withhold it, and no tail below is
shown.
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


@pytest.mark.parametrize("context", [*CONTEXTS, "please send {} now", "Authorization: {}"])
@pytest.mark.parametrize(
    "glued",
    [
        # A run that may hold a name, but is not one, was kept whole when no
        # pass withheld anything after it, and the token's tail was shown.
        "={t}=--abc={v}",
        "={t}=--abc={v}: x",
        "=x{t}+--abc",
        "--{t}/password",
        "=x{t}--token",
        "=x{t}=password",
        "=x{t}=api-key",
        # A name's last word ('pass') kept a run that is the token's tail.
        "--{t}.pass",
    ],
)
@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize("credential", [SECRET, "token " + SECRET, "dXNlcjpwYXNz=="])
def test_a_token_tail_that_only_may_hold_a_name_is_withheld(
    credential: str, scheme: str, glued: str, context: str
) -> None:
    text = _placed(context, f"{scheme} {credential}" + glued.format(t=TAIL, v=VALUE))
    for value in (TAIL[:9], TAIL[-9:], VALUE, SECRET):
        assert not _shown(text, value)


def test_a_token_tail_after_a_private_key_block_is_withheld() -> None:
    # Fuzzing found the tail above shown next to an armored PGP key block,
    # which sends the text through the block comparison first.
    block = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----\n\nabc\n-----END PGP " + "PRIVATE KEY BLOCK-----"
    text = f"password: x{block}Bearer\r\n{SECRET}={TAIL}=--abc={VALUE}: x"
    for value in (TAIL[:9], TAIL[-9:], VALUE, SECRET):
        assert not _shown(text, value)


@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize("word", ["", "token "])
@pytest.mark.parametrize("glued", ["=x ", "--x ", "=x=y "])
def test_a_known_value_a_glued_run_starts_is_withheld_whole(word: str, scheme: str, glued: str) -> None:
    # The value nested in a credential container is removed from the other
    # fields last. Withheld before that, the run took the start of the value
    # with it, and the rest of the value was no longer found and was shown.
    known = glued[1:] + VALUE
    record = {"password": [known], "note": f"{scheme} {word}{SECRET}{glued}{VALUE}"}
    note = sanitize(record)["note"]
    assert VALUE not in note and SECRET not in note
    # A known value that is not nested is removed before the text passes.
    assert VALUE not in sanitize({"password": known, "note": record["note"]})["note"]


# Fuzzer-found shapes, rebuilt from synthetic parts: a credential nested in a
# container under a sensitive key, then the same text glued after a scheme
# credential in another field. Removed last, the nested value was split by the
# withheld run first, and the rest of it was shown.
_PART = "Tq7Rb" + "N3pXc"
_NESTED = [
    ({"password": [f"Bearer a--{_PART}"], "m": f"Bearer a--{_PART}--key"}, _PART),
    ({"secret": {"x": f"Basic a={_PART}"}, "m": f"Basic a={_PART}=apikey"}, _PART),
    ({"token": [f"SSWS a--{_PART}"], "m": f"SSWS a--{_PART}=-"}, _PART),
    ({"password": [f"Bearer token {SECRET}--{_PART}"], "m": f"Bearer token {SECRET}--{_PART}--auth"}, _PART),
    ({"password": [f"x {VALUE}"], "note": f"Bearer {SECRET}--x {VALUE}"}, VALUE),
    ({"password": [f"b&db={VALUE}"], "note": f"ssws x--b&db={VALUE}"}, VALUE),
    ({"password": [f"l\ndb: {VALUE}"], "note": f"ssws x--l\ndb: {VALUE}"}, VALUE),
    ({"client_secret": [{"v": f"g\n{VALUE}"}], "note": f"Bearer\nx--g\n{VALUE}"}, VALUE),
    (
        {
            "password": [f"{VALUE[:6]}!{VALUE[6:]}"],
            "note": f"headers: Bearer {SECRET}--{VALUE[:6]}!{VALUE[6:]}",
        },
        VALUE[6:],
    ),
    # A short credential withholds the whole field it occurs in.
    ({"password": ["k:Q7w"], "note": "BASIC x--k:Q7wSessionId"}, "Q7w"),
]


@pytest.mark.parametrize("short", [False, True])
@pytest.mark.parametrize(("record", "value"), _NESTED)
def test_a_nested_credential_after_a_glued_run_is_withheld_whole(
    record: dict[str, object], value: str, short: bool
) -> None:
    cleaned = sanitize(record, redact_short_secrets=short)
    assert all(value not in str(field) for field in cleaned.values())


def _key_block(armor: str, body: str = "") -> str:
    begin, end = (
        "-----BEGIN " + armor + "PRIVATE KEY BLOCK-----",
        "-----END " + armor + "PRIVATE KEY BLOCK-----",
    )
    return f"{begin}\n{body}{end}"


@pytest.mark.parametrize(
    ("text", "values"),
    [
        (f"Basic F=L= password: {VALUE}" + _key_block("") + TAIL, [VALUE, TAIL]),
        (
            f"Basic F=L= password: {VALUE}"
            + _key_block("PGP ", "lQOYBF0Ab12Cd34\n")
            + f"\nBearer {SECRET}={TAIL}=--abc",
            [VALUE, TAIL, "lQOYBF0Ab12Cd34"],
        ),
        (
            f"note {VALUE} " + _key_block("PGP ", "lQOYBF7wQ2kBCAC9\n") + f"-Bearer {SECRET}--trace",
            [VALUE, "trace"],
        ),
        (
            "a " + _key_block("PGP ", "lQOYBF7wQ2kBCAC9\n") + f"-Bearer {SECRET}--trace\nsession {VALUE}",
            [VALUE],
        ),
        (f"{VALUE}{_key_block('')}-Bearer 3--", [VALUE]),
    ],
)
def test_a_glued_run_does_not_loosen_the_key_block_fallback(text: str, values: list[str]) -> None:
    # Withheld inside the extended passes, the run made the two readings that
    # _withhold_key_blocks compares agree, and the text after the block, which
    # the fallback withholds, was shown.
    cleaned = sanitize_text(text)
    assert not any(value in cleaned for value in values)


@pytest.mark.parametrize(
    "text",
    [
        "Bearer\ne=o=\\password: s://a://@",
        "s://a://@SSWS b=Q: token: t",
        "SSWS t--s://s://:s://@b",
        "SSWS 7--s://?token=&G://?sig=",
    ],
)
def test_the_text_left_without_a_glued_run_is_read_again(text: str) -> None:
    # Without the run, the text can say plainly what the passes did not read
    # in it ('...password: v'); it is read once more, so sanitizing the result
    # again changes nothing.
    cleaned = sanitize_text(text)
    assert sanitize_text(cleaned) == cleaned


# Shapes a second fuzzing round found, with synthetic values: an earlier pass
# changes how the scheme pass reads a run, which the established reading,
# withholding the run in that pass, reads as the established rules did.
_SECOND_ROUND_TEXTS = [
    # A run that starts a quoted value on the credential's own line after the scheme's.
    (f'Authorization:basic\nT--password"\n{VALUE}', [VALUE]),
    # A scheme word glued on, after an option the option rule reads first.
    (f"--token Bearer Bearer K--bearer Bearer {VALUE}", [VALUE]),
    (f"SSWS B=c: {VALUE}_key: " + _key_block(""), [VALUE]),
    (
        '{"msg": "retry: Bearer Qm9iOnBhc3M5=trace: '
        + VALUE
        + "\\nprivate_key: "
        + _key_block("PGP ", "AAAA\\n").replace("\n", "\\n")
        + '"}',
        [VALUE],
    ),
    (f"{VALUE}--auth=2\\p_key: " + _key_block("") + "Basic o--", [VALUE]),
    (f"{VALUE}\nBasic\nk--token v\n" + _key_block("PGP ", "x\n"), [VALUE]),
]
_SECOND_ROUND_RECORDS = [
    ({"token": "kQ9v7Lm2Xp", "h": f"Authorization: Bearer\nxZlj6QNd8uHvDZo--token-kQ9v7Lm2Xp {VALUE}"}, {}),
    ({"token": ["Bearer K"], "h": f"--token Bearer Bearer K=x{VALUE}"}, {}),
    ({"credentials": [f"svc:{VALUE}"], "log": f"Bearer t--svc:{VALUE}"}, {}),
    ({"credentials": {"value": f"deploy@{VALUE}"}, "log": f"Basic dXNlcjpwYXNz=deploy@{VALUE}"}, {}),
    (
        {"settings": [{"name": "OpenAIKey", "value": f"ab:{VALUE}"}], "log": f"Basic t=ab:{VALUE}"},
        {"redact_short_secrets": True},
    ),
    (
        {"argv": ["tool", "--key", f"ab:{VALUE}"], "log": f"Bearer t=ab:{VALUE}"},
        {"redact_short_secrets": True},
    ),
    ({"credentials": ["N"], "notes": f"Bearer F=N|{VALUE}"}, {}),
]


@pytest.mark.parametrize(("text", "values"), _SECOND_ROUND_TEXTS)
def test_a_value_the_established_scheme_pass_withholds_stays_withheld(text: str, values: list[str]) -> None:
    for value in values:
        assert not _shown(text, value)


@pytest.mark.parametrize(("record", "options"), _SECOND_ROUND_RECORDS)
def test_a_record_value_the_established_reading_withholds_stays_withheld(
    record: dict[str, object], options: dict[str, bool]
) -> None:
    cleaned = sanitize(record, **options)
    assert all(VALUE not in str(field) for field in cleaned.values())


@pytest.mark.parametrize("scheme", SCHEMES)
def test_a_value_a_later_sanitization_withholds_is_withheld_at_once(scheme: str) -> None:
    # Evidence is sanitized more than once. After the 'token' word, the
    # established reading kept '--a=:v' on the credential's line and withheld v
    # on the next sanitization; the other reading withheld the run, so no
    # sanitization withheld v.
    text = f"{scheme} token\n{SECRET[:16]}--a=:{VALUE}"
    cleaned = sanitize_text(text)
    assert VALUE not in cleaned and VALUE not in sanitize({"note": text})["note"]
    assert sanitize_text(cleaned) == cleaned


def _established(text: str) -> str:
    """The text as the established rules read it: the passes outside any reading."""
    return redaction._redact_extended(redaction._sanitize_established(text))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # No credential stopped at a run, so the established rules' reading is
        # kept, and the option on the line after the scheme's stays.
        (
            f"Bearer {SECRET}\n--insecure --location https://example.test/x",
            f"Bearer {REDACTED}\n--insecure --location https://example.test/x",
        ),
        (f"auth: Bearer {SECRET}\n---\nnext: doc", f"auth: Bearer {REDACTED}\n---\nnext: doc"),
        ("## Basic usage\n\n--verbose prints more", f"## Basic {REDACTED}\n\n--verbose prints more"),
        # After a glued run, a run that starts a later line is withheld, with a
        # marker where it was.
        (
            f"Bearer {SECRET}--x9\n--insecure --location https://example.test/x",
            f"Bearer {REDACTED}\n{REDACTED} --location https://example.test/x",
        ),
        (f"Bearer {SECRET}=x9\n\n--verbose run", f"Bearer {REDACTED}\n\n{REDACTED} run"),
    ],
)
def test_a_run_that_starts_a_later_line_is_not_removed_silently(text: str, expected: str) -> None:
    # The step that withholds a glued run also took a run at the start of
    # any line after a scheme credential, with no marker, so an excerpt lost
    # an option or a separator and did not show that anything was withheld.
    assert sanitize_text(text) == expected
    assert sanitize({"note": text})["note"] == expected
    if "--x9" not in text and "=x9" not in text:
        assert expected == _established(text)


@pytest.mark.parametrize("lead", ["", "--r0\n", "--r0\n\n"])
@pytest.mark.parametrize("credential", [SECRET, SECRET + "--x9"])
def test_a_value_read_once_the_later_line_runs_go_stays_withheld(credential: str, lead: str) -> None:
    # A run that starts a later line stays only where removing it changes
    # nothing else. Removed, it can let the passes read the value after it
    # (see _without_glued_runs), and that reading is kept. The value does not
    # look opaque, so no other rule withholds it.
    text = f"Bearer {credential}\n{lead}=abc.def = password: hunter2pass"
    assert not _shown(text, "hunter2pass")


@pytest.mark.parametrize("glued", ["--{t}", "=x{t}"])
def test_the_scheme_pass_outside_a_reading_withholds_the_run_with_the_credential(glued: str) -> None:
    # Outside sanitize_text and sanitize no reading is set. The scheme pass
    # then left the run in the text for a step that only those two run, and
    # a direct call of the passes showed the token's tail.
    text = f"x Bearer {SECRET}" + glued.format(t=TAIL) + " y"
    assert redaction._redact_authorization(text) == f"x Bearer {REDACTED} y"
    for passes in (redaction._established_passes, redaction._sanitize_established):
        assert TAIL[:9] not in redaction._redact_extended(passes(text))


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
    # The established reading, merged in, is turned off as well.
    monkeypatch.setattr(redaction, "_withhold_scheme_tails", lambda text: text)
    monkeypatch.setattr(redaction, "_merge_readings", lambda first, second: first)
    monkeypatch.setattr(redaction, "_merge_copies", lambda first, second: first)
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
        # A name stays beside the value it withholds on the scheme's line.
        (f"Bearer {SECRET}--password {VALUE}", f"Bearer {REDACTED}--password {REDACTED}"),
        (f"Basic {SECRET}=password: {VALUE}", f'Basic {REDACTED}=password: "{REDACTED}"'),
        (f"SSWS {SECRET}--token {VALUE}", f"SSWS {REDACTED}--token {REDACTED}"),
        # The established rules withheld this name with the credential and showed
        # the value; neither reading shows only what the other does.
        (f"SSWS {SECRET}--auth {VALUE}", REDACTED),
        # A name on the credential's line after the scheme's: the established
        # rules joined that line to the scheme's, so the readings' lines no
        # longer pair up and the text is withheld, keeping its line breaks.
        (f"Bearer\n{SECRET}--password {VALUE}", f"{REDACTED}\n"),
        (f"Basic \n {SECRET}=password: {VALUE}", f"{REDACTED}\n"),
        (f"SSWS\n\n{SECRET}--token {VALUE}", f"{REDACTED}\n\n"),
        (f"Bearer\n{SECRET}--{TAIL} x", f"Bearer {REDACTED}\n x"),
        # The established rules kept the tail after the 'token' word at the
        # start of the credential's line; a marker shows where it was.
        (f"Bearer token\n{SECRET}=x{TAIL}\n", f"Bearer {REDACTED}\n{REDACTED}\n"),
    ],
)
def test_a_glued_run_keeps_the_line_breaks_after_the_scheme(text: str, expected: str) -> None:
    # The scheme's blanks may span lines; excerpt lines stay aligned whether
    # the run is kept or withheld.
    assert sanitize_text(text) == expected


@pytest.mark.parametrize(
    "prefix", ["Authorization: ", "Cookie: a=b; ", "-H 'Authorization: ", 'curl -H "Authorization: ']
)
@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize(
    "follow",
    [
        "--Token\\u0022: {v}",
        "---pass|{v}",
        '--subscription-key":"{v}"}} x',
        "--DB_PASSWORD {v} {t}",
        "--apikey\\n{v}",
    ],
)
def test_a_name_on_the_credentials_line_after_a_header_scheme_is_withheld(
    prefix: str, scheme: str, follow: str
) -> None:
    # The header rule withholds the scheme and the credential, and the line
    # after it held the glued name and the value no rule read after it. The
    # established rules joined the two lines, and the header rule withheld both.
    text = f"{prefix}{scheme}\n{SECRET}" + follow.format(v=VALUE, t=TAIL)
    assert not _shown(text, VALUE)
    assert not _shown(text, TAIL)
    assert sanitize_text(text).count("\n") == text.count("\n")


@pytest.mark.parametrize(
    ("kept", "shown", "within"),
    [
        ("a b c", "a b c", True),
        ("a b c", f"a {REDACTED} c", True),
        # Text removed beside a marker or at either end of the line.
        ("a b c", " b c", True),
        ("a b c", f"a {REDACTED}c", True),
        ("a b c", REDACTED, True),
        ("a b c", REDACTED + REDACTED, True),
        ("a b c", "", True),
        ("a b\r", f"{REDACTED}\r", True),
        (f"a {REDACTED} c", f"a {REDACTED} c", True),
        # A character the kept line does not show.
        ("a b c", "a b d", False),
        # Text removed inside a piece, with no marker there.
        ("a b c", "a  c", False),
        ("a b c", f"a {REDACTED} d", False),
        # A piece that straddles the kept line's marker shows what it withholds.
        (f"a{REDACTED}b", "ab", False),
        # Pieces in another order, or overlapping in the kept line.
        ("a b", f"b {REDACTED} a", False),
        ("ab", f"ab{REDACTED}b", False),
    ],
)
def test_shows_within_reads_the_markers_as_withheld_spans(kept: str, shown: str, within: bool) -> None:
    assert redaction._shows_within(kept, shown) is within


@pytest.mark.parametrize(
    ("one", "other", "merged"),
    [
        ("a b", "a b", "a b"),
        (f"a {REDACTED}", "a b", f"a {REDACTED}"),
        ("a b", f"a {REDACTED}", f"a {REDACTED}"),
        # Two spans differ, but one line shows only what the other shows: kept.
        (f"a {REDACTED} b {REDACTED} c", "a X b Y c", f"a {REDACTED} b {REDACTED} c"),
        ("a X b Y c", f"a {REDACTED} b {REDACTED} c", f"a {REDACTED} b {REDACTED} c"),
        # Each shows what the other withholds: the whole line, keeping its CR.
        (f"a {REDACTED} c", f"{REDACTED} b c", REDACTED),
        (f"a {REDACTED} c\r", f"{REDACTED} b c\r", f"{REDACTED}\r"),
        # The first reading removed the run that starts the second's line.
        (" --location u", "--insecure --location u", f"{REDACTED} --location u"),
        (" x\r", "=abc.def x\r", f"{REDACTED} x\r"),
        ("", "---", REDACTED),
        # Text that is not such a run is not marked.
        (" x", "abc x", " x"),
    ],
)
def test_a_merged_line_shows_nothing_either_reading_withholds(one: str, other: str, merged: str) -> None:
    assert redaction._merged_line(one, other) == merged
    assert redaction._shows_within(one, merged) and redaction._shows_within(other, merged)


def test_readings_whose_lines_do_not_pair_up_withhold_the_whole_text() -> None:
    assert redaction._merge_readings("a\nb\nc", "a b\nc") == REDACTED + "\n\n"
    assert redaction._merge_readings("a\nb", "a\nb") == "a\nb"


_CAPPED = [
    # A cut after a cut: the second run is read only once the first goes.
    f"Bearer {SECRET}--x9\n--r0\n=abc.def = password: hunter2pass",
    # A reading a later sanitization withholds more of (see _settled).
    f"Bearer token\n{SECRET[:16]}--a=:{VALUE}",
    f"Bearer {SECRET}--x9\n--a=:{VALUE}",
]


@pytest.mark.parametrize("text", _CAPPED)
def test_a_reading_cut_short_by_its_cap_still_shows_only_what_both_readings_show(
    text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The caps bound the work on a text that keeps changing. A reading cut
    # short is still merged with the established one, line by line.
    monkeypatch.setattr(redaction, "_GLUED_READINGS_AGAIN", 1)
    monkeypatch.setattr(redaction, "_GLUED_RUN_READINGS", 1)
    merged: list[tuple[str, str]] = []
    merge = redaction._merge_readings
    monkeypatch.setattr(
        redaction,
        "_merge_readings",
        lambda first, second: merged.append((first, second)) or merge(first, second),
    )
    cleaned = sanitize_text(text)
    assert "hunter2pass" not in cleaned and VALUE not in cleaned and SECRET[:9] not in cleaned
    assert cleaned.count("\n") == text.count("\n")
    ((plain, established),) = merged
    for line, plain_line, established_line in zip(
        cleaned.split("\n"), plain.split("\n"), established.split("\n"), strict=True
    ):
        assert redaction._shows_within(plain_line, line) and redaction._shows_within(established_line, line)


def test_a_glued_text_in_a_list_is_merged_member_by_member() -> None:
    record = {"notes": [f"Bearer {SECRET}--x9\n--insecure x", "plain words", f"Basic {SECRET}=x9 more"]}
    assert sanitize(record)["notes"] == [
        f"Bearer {REDACTED}\n{REDACTED} x",
        "plain words",
        f"Basic {REDACTED} more",
    ]


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

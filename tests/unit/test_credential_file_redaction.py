"""The tool credential files' own syntax is redacted wherever their text appears.

netrc parts a password from its name by blanks alone ('machine h login u
password v'), which no assignment, mapping or option rule read, so
``sanitize_text`` returned such a line unchanged and a report excerpt of a
``.netrc``, a Dockerfile that writes one or a CI script showed the password.
Yarn 1's ``.yarnrc`` writes its registry tokens the same way. Every other
credential file's syntax (``.npmrc``, ``.pypirc``, ``.git-credentials``,
``.boto``, ``.s3cfg``) was already withheld; it is pinned here so that no
path can echo any of them.

Values are random but deterministic, and prefixed provider tokens are
assembled at run time so this file does not itself trip secret scanners.
"""

from __future__ import annotations

import random
import string

import pytest

from shadowscan.utils.redaction import REDACTED, _sanitize_established, sanitize_text

_RANDOM = random.Random(20261017)
_ALPHABET = string.ascii_letters + string.digits


def _random(length: int, alphabet: str = _ALPHABET) -> str:
    return "".join(_RANDOM.choice(alphabet) for _ in range(length))


SECRET = "pw-" + _random(24)
OTHER = "acct-" + _random(16)
WORD = "batterystaple"  # word-like: no shape gives it away, only its name

# netrc entries in every layout a client reads: one line, one token per line,
# CRLF, comments, several entries on a line, 'passwd', 'account', 'default',
# a value on the line after its keyword, quoted values, a missing login name.
NETRC_FORMS = [
    f"machine api.openai.com login deploy password {SECRET}\n",
    f"machine api.anthropic.com\n  login ci\n  password {SECRET}\n",
    f"machine h\r\n\tlogin ci\r\n\tpassword {SECRET}\r\n",
    f"machine h login ci passwd {SECRET}\n",
    f"machine h login ci account {SECRET} password {OTHER}\n",
    f"machine a login u password {OTHER} machine b login v password {SECRET}\n",
    f"default login anonymous password {SECRET}\n",
    f"default login anonymous password\n  {SECRET}\n",
    f"machine h login ci # the deploy user\n  password {SECRET}\n",
    f'machine h login ci password "{SECRET} {WORD}"\n',
    f'machine h login ci password "{SECRET} {WORD}\n',
    f"machine h login password {SECRET}\n",
    f"machine h login deploy password {SECRET}\n",
    f"machine h login ci password {WORD}\n",
    # The 'port' and 'protocol' of the netrc credential helper shipped with Git.
    f"machine example.com port 443 protocol https login ci password {SECRET}\n",
]
# netrc written from a script or kept in a JSON string.
EMBEDDED_FORMS = [
    f'RUN echo "machine github.com login x password {SECRET}" > /root/.netrc',
    f"echo 'machine github.com login x password {SECRET}' >> ~/.netrc",
    f'f.write("machine h login u password {SECRET}");',
    f"printf 'machine h\\nlogin u\\npassword {SECRET}\\n' > ~/.netrc",
    f'{{"netrc": "machine a login u password {OTHER}\\nmachine b login v password {SECRET}"}}',
]
# Forms that curl, PowerShell and other netrc readers accept, which the rule
# first missed: keywords in any case, PowerShell '`n' escapes, a 'default'
# entry that is not first on its line, vertical-tab and form-feed blanks, a
# login named 'account' or 'password', a quoted name followed by an escape,
# a comment between escaped lines or in the middle of an entry, a name whose
# quote never closes, and a macro whose name line holds more.
CLIENT_FORMS = [
    f"MACHINE api.openai.com LOGIN deploy PASSWORD {SECRET}\n",
    f"machine h login u PASSWORD {SECRET}\n",
    f'RUN echo "MACHINE api.openai.com LOGIN x PASSWORD {SECRET}" > /root/.netrc',
    f"printf 'MACHINE api.openai.com LOGIN x PASSWORD {SECRET}\\n' > ~/.netrc",
    f"echo machine api.openai.com login x Password {SECRET} >> ~/.netrc",
    f"echo default login x password {SECRET} >> ~/.netrc # api.openai.com",
    f'Set-Content $HOME\\_netrc "machine api.openai.com`nlogin u`npassword {SECRET}"',
    f"echo 'machine api.openai.com login account password {SECRET}' > ~/.netrc",
    f"machine h login password password {SECRET}\n",
    f"machine h\vlogin u\vpassword\v{SECRET}\n",
    f"machine h\flogin u\fpassword {SECRET}\n",
    f'printf "machine h\\vlogin u\\fpassword {SECRET}" > ~/.netrc',
    f'x = "machine h\\nlogin \\"u\\"\\npassword {SECRET}"',
    f'x = "machine h\\n# the deploy user\\npassword {SECRET}"',
    f"machine a login u\n# machine b login v password {SECRET}\npassword {OTHER}\n",
    f'machine h login "u password {SECRET}\n',
    f"MACDEF init\nuser deploy {SECRET}\n\n",
    f"machine h login u password {OTHER} macdef init now\nuser deploy {SECRET}\n\n",
]
# A macro's lines are withheld up to the empty line that ends it.
MACRO_FORMS = [
    f"machine h login u password {OTHER}\nmacdef init\ncd /pub\nuser deploy {SECRET}\n\n",
    f"macdef upload\r\n  user deploy {SECRET}\r\n  put build.tar\r\n\r\n",
    f'{{"netrc": "macdef init\\nuser deploy {SECRET}\\n\\n"}}',
]
# Yarn 1 '.yarnrc': 'name value', either one optionally quoted.
YARNRC_FORMS = [
    f'"//registry.yarnpkg.com/:_authToken" "{SECRET}"\n',
    f"//npm.pkg.example.com/:_authToken {SECRET}\n",
    f'"_authToken" {SECRET}\n',
    f"_auth {SECRET}==\n",
    f"  //npm.pkg.example.com/:_password '{SECRET}'\n",
]
# The syntax of the other credential files, which earlier rules withhold.
OWN_SYNTAX_FORMS = [
    f"//registry.npmjs.org/:_authToken={SECRET}\n_auth={OTHER}\n",
    f"//npm.pkg.example.com/:_password={SECRET}=\n",
    f"[pypi]\nusername = __token__\npassword = {SECRET}\n\n[private]\npassword: {WORD}\n",
    # Joined at run time, as the URL userinfo shape is itself a committed-secret pattern.
    "https://deploy:" + SECRET + "@github.com\nhttps://" + WORD + "@git.example.com\n",
    f"[Credentials]\naws_access_key_id = AKIA{_random(16, string.ascii_uppercase)}\n"
    f"aws_secret_access_key = {SECRET}\ngs_oauth2_refresh_token = {WORD}\n",
    f"[default]\naccess_key = AKIA{_random(16, string.ascii_uppercase)}\nsecret_key = {SECRET}\n"
    f"gpg_passphrase = {WORD}\n",
]


@pytest.mark.parametrize(
    "source", NETRC_FORMS + EMBEDDED_FORMS + CLIENT_FORMS + MACRO_FORMS + YARNRC_FORMS + OWN_SYNTAX_FORMS
)
def test_a_credential_file_value_is_withheld_in_its_own_syntax(source):
    safe = sanitize_text(source)
    for value in (SECRET, OTHER, WORD):
        if value in source:
            assert value not in safe
    assert safe.count("\n") == source.count("\n")  # excerpt lines keep their numbers
    assert sanitize_text(safe) == safe


def _only_adds_markers(before: str, after: str) -> bool:
    """Whether ``after`` is ``before`` with some spans replaced by the marker."""
    position = 0
    for index, piece in enumerate(after.split(REDACTED)):
        found = before.find(piece, position)
        if found < 0 or (index == 0 and found != 0):
            return False
        position = found + len(piece)
    return after.endswith(REDACTED) or before.endswith(after.split(REDACTED)[-1])


@pytest.mark.parametrize("source", NETRC_FORMS + EMBEDDED_FORMS + CLIENT_FORMS + MACRO_FORMS + YARNRC_FORMS)
def test_the_netrc_and_yarnrc_rules_only_add_markers_to_what_the_others_leave(source):
    # Every form reached them intact: no earlier rule withheld its secret.
    # They run last and only add markers, so they hide no name another rule reads.
    established = _sanitize_established(source)
    assert all(value in established for value in (SECRET, OTHER, WORD) if value in source)
    assert _only_adds_markers(established, sanitize_text(source))


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "machine api.openai.com login deploy password VALUE\n",
            f"machine api.openai.com login deploy password {REDACTED}\n",
        ),
        (
            "machine h\n  login ci\n  passwd VALUE\n  account VALUE\n",
            f"machine h\n  login ci\n  passwd {REDACTED}\n  account {REDACTED}\n",
        ),
        (
            'echo "machine h login u password VALUE" > ~/.netrc',
            f'echo "machine h login u password {REDACTED}" > ~/.netrc',
        ),
        (
            "macdef init\ncd /pub\nget VALUE\n\nmachine h\n",
            f"macdef init\n{REDACTED}\n{REDACTED}\n\nmachine h\n",
        ),
        ('"//registry.yarnpkg.com/:_authToken" "VALUE"', f'"//registry.yarnpkg.com/:_authToken" {REDACTED}'),
        (
            "MACHINE api.openai.com LOGIN deploy PASSWORD VALUE\n",
            f"MACHINE api.openai.com LOGIN deploy PASSWORD {REDACTED}\n",
        ),
        (
            'Set-Content $HOME\\_netrc "machine h`nlogin u`npassword VALUE"',
            f'Set-Content $HOME\\_netrc "machine h`nlogin u`npassword {REDACTED}"',
        ),
        # Clients read the login 'account'; read as a missing login, 'password' is its value.
        ("machine h login account password VALUE\n", f"machine h login account {REDACTED} {REDACTED}\n"),
        (
            "echo default login x password VALUE >> ~/.netrc",
            f"echo default login x password {REDACTED} >> ~/.netrc",
        ),
    ],
)
def test_names_hosts_and_layout_stay_visible(source, expected):
    assert sanitize_text(source.replace("VALUE", SECRET)) == expected


@pytest.mark.parametrize(
    "source",
    [
        'echo "machine github.com login x password $GH_TOKEN" > ~/.netrc',
        'echo "machine github.com login x password ${GH_TOKEN}" > ~/.netrc',
        "machine github.com login x password ${{ secrets.GH_TOKEN }}",
        "machine h login u password <your-password>",
        "//npm.pkg.github.com/:_authToken ${NPM_TOKEN}",
    ],
)
def test_a_reference_in_place_of_the_value_stays_visible(source):
    assert sanitize_text(source) == source


@pytest.mark.parametrize(
    "source",
    [
        "Change the default password.",
        "The default login is admin",
        "MACHINE LEARNING needs a LOGIN",
        "machine learning models need a login and password",
        "machine = Machine()\nmachine.login(user)",
        "my machine has no login password set",
        "macdef is an ftp macro keyword",
        "_auth helpers live in auth.py",
    ],
)
def test_prose_and_code_that_merely_use_the_words_stay(source):
    assert sanitize_text(source) == source


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # 'default' starts an entry anywhere a word starts, as 'machine' does, and
        # keywords are read in any case, so a prose word after 'default password'
        # is withheld rather than a password shown ('echo default login x
        # password v >> ~/.netrc').
        ("Change the default password before deploying", f"Change the default password {REDACTED} deploying"),
        ("Default Password Policy", f"Default Password {REDACTED}"),
    ],
)
def test_a_prose_word_after_a_netrc_keyword_is_withheld(source, expected):
    assert sanitize_text(source) == expected

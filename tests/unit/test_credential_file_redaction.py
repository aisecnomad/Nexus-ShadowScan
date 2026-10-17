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

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.reporters import RENDERERS
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
# A login with a backslash or backtick before an escape letter, as a Windows
# domain login has, in a netrc file's own text (where clients read the
# backslash as part of the name) and in an escaped string in source (where
# '\\' is one backslash), and a token the format does not define before the
# password, on the line of the entry's last token. Each ended the entry, so
# the password after it was shown; a head inside such a token still starts
# an entry of its own.
SPLIT_FORMS = [
    f"machine proxy.corp login CORP\\fred password {SECRET}\n",
    f"machine proxy.corp login CORP\\victor password {SECRET}\n",
    f"machine proxy.corp\nlogin CORP\\frank\npassword {SECRET}\n",
    f"machine proxy.corp login CORP\\tom password {SECRET}\n",
    f"machine proxy.corp login CORP\\nancy password {SECRET}\n",
    f"machine proxy.corp login CORP\\rob password {SECRET}\n",
    f"MACHINE proxy.corp LOGIN CORP\\FRED PASSWORD {SECRET}\n",
    f"machine fs.corp login u`fred password {SECRET}\n",
    f"machine fs.corp login u`nfred password {SECRET}\n",
    f'NETRC = "machine api.openai.com login CORP\\\\fred password {SECRET}"',
    f'NETRC = "machine api.openai.com\\nlogin CORP\\\\frank\\npassword {SECRET}\\n"',
    f'NETRC = "machine api.openai.com\\nlogin CORP\\\\victor\\npassword {SECRET}\\n"',
    f'NETRC = "machine api.openai.com\\nlogin CORP\\\\nancy\\npassword {SECRET}\\n"',
    f'NETRC = "machine api.openai.com\\nlogin CORP\\\\tom\\npassword {SECRET}\\n"',
    f"const netrc = 'machine h\\nlogin CORP\\\\fred\\npassword {SECRET}';",
    f'{{"netrc": "machine h login CORP\\\\fred password {SECRET}"}}',
    f"machine h force yes password {SECRET}\n",
    f"machine h login u force yes password {SECRET}\n",
    f'x = "machine h\\nforce yes\\npassword {SECRET}"',
    f'machine a login u password {OTHER} x="macdef init\\nuser deploy {SECRET}\\n\\n"',
]
# A comment in an escaped string ends at the next line-break escape, where
# its line does: read to the end of the physical line, an indented comment
# line or a trailing comment hid every escaped line after it, the password
# among them. An entry right after a comment's '#' is read too.
COMMENT_FORMS = [
    f'x = "machine h\\n  # note\\nlogin u\\npassword {SECRET}\\n"',
    f'x = "machine h\\nlogin u # note\\npassword {SECRET}\\n"',
    f'x = "machine h\\n\\t# note\\nlogin u\\npassword {SECRET}\\n"',
    f"x = 'machine h\\r\\n  # note\\r\\nlogin u\\r\\npassword {SECRET}\\r\\n'",
    f'Set-Content $HOME\\_netrc "machine h`n  # note`nlogin u`npassword {SECRET}"',
    f'{{"netrc": "machine api.openai.com\\n  # deploy bot\\n  login bot\\n  password {SECRET}\\n"}}',
    f"#machine h login u password {SECRET}\n",
    # Escaped text with no quote: its escapes next to keywords give it away.
    f"NETRC=machine h # note\\nlogin u\\npassword {SECRET}",
]
# A netrc file's own comment that holds an apostrophe or a quote and a Windows
# path. Read as an escaped string because its line held a quote, the comment
# ended at the path's first '\n' or '\r', the rest of it ended the entry, and
# the password on a later line was shown. A comment now ends at such an escape
# only in an escaped string, and a token the format does not define ends no
# entry before a password that follows it in the entry's region, as the rest
# of a comment cut inside quotes does not either.
PATH_COMMENT_FORMS = [
    f"machine fileserver.corp\n  # Bob's share is C:\\new\\data\n  login bob\n  password {SECRET}\n",
    f"machine fs.corp\n# don't change: used by \\\\nas\\backup\nlogin svc\npassword {SECRET}\n",
    f"machine fs.corp login svc\n# it's for D:\\repo\\nightly\npassword {SECRET}\n",
    f'machine fs.corp\n  # share: "C:\\new\\data"\n  login svc\n  password {SECRET}\n',
    f"machine fs.corp\n  # see `\\\\fs\\releases`\n  login svc\n  password {SECRET}\n",
    f"machine h\n  login u\n  # Bob's PC at C:\\new\n  password {SECRET}\n",
    f"machine h\r\n  # Bob's share is C:\\new\\data\r\n  login bob\r\n  password {SECRET}\r\n",
    f"machine h\n  # Bob's share is C:\\new\\data\n  # and D:\\rest\\of\\it\n  login bob\n  password {SECRET}\n",
    f'x = """\nmachine proxy.corp\n  # Bob\'s proxy share is C:\\new\\data\n  login bob\n  password {SECRET}\n"""',
    f'machine h\n  "x" # see "C:\\new\\data"\n  login u\n  password {SECRET}\n',
    f"machine h\nforce yes\npassword {SECRET}\n",
    f"machine h\n  force\n  yes\n  login u\n  password {SECRET}\n",
]
# An entry spread over adjacent string literals: Python's implicit
# concatenation, a JavaScript or C '+' chain, literals parted by a line
# continuation or by a comment. The closing quote and the next line's
# opening quote were tokens the format does not define, so the entry ended
# after 'machine' and the password was shown.
ADJACENT_FORMS = [
    f'NETRC = ("machine api.openai.com\\n"\n         "login bot\\n"\n         "password {SECRET}\\n")',
    f'const n = "machine h\\n" +\n  "login u\\n" +\n  "password {SECRET}\\n";',
    f'NETRC = "machine api.openai.com\\n" "login bot\\n" "password {SECRET}\\n"',
    f"NETRC = ('machine h\\n'\n         'login bot\\n'\n         'password {SECRET}\\n')",
    f'char *n = "machine h\\n"\n           "login u\\n"\n           "password {SECRET}\\n";',
    f'NETRC = ("machine h "\n         "login bot "\n         "password {SECRET}")',
    f'n = "machine h\\n" \\\n  "login u\\n" \\\n  "password {SECRET}\\n"',
    f'n = "machine h\\n"\r\n  "login u\\n"\r\n  "password {SECRET}\\n"',
    f'n = ("machine h\\n"  # the proxy\n  "password {SECRET}\\n")',
]
# What is glued to a closing quote is the next token, as clients read it: read
# as the rest of the quoted name or value, a 'password' there hid its value.
GLUED_FORMS = [
    f'machine h login "u"password {SECRET}\n',
    f'x = "machine h login \\"u\\"password {SECRET}"',
    f'machine h login u password "{OTHER}"password {SECRET}\n',
    f'machine h login "u"account {SECRET}\n',
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
    "source",
    NETRC_FORMS
    + EMBEDDED_FORMS
    + CLIENT_FORMS
    + SPLIT_FORMS
    + COMMENT_FORMS
    + PATH_COMMENT_FORMS
    + ADJACENT_FORMS
    + GLUED_FORMS
    + MACRO_FORMS
    + YARNRC_FORMS
    + OWN_SYNTAX_FORMS,
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


@pytest.mark.parametrize(
    "source",
    NETRC_FORMS
    + EMBEDDED_FORMS
    + CLIENT_FORMS
    + SPLIT_FORMS
    + COMMENT_FORMS
    + PATH_COMMENT_FORMS
    + ADJACENT_FORMS
    + GLUED_FORMS
    + MACRO_FORMS
    + YARNRC_FORMS,
)
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
        # A Windows domain login stays whole, in a netrc file and in an escaped string.
        (
            "machine proxy.corp login CORP\\fred password VALUE\n",
            f"machine proxy.corp login CORP\\fred password {REDACTED}\n",
        ),
        (
            'NETRC = "machine h\\nlogin CORP\\\\frank\\npassword VALUE"',
            f'NETRC = "machine h\\nlogin CORP\\\\frank\\npassword {REDACTED}"',
        ),
        ("machine h force yes password VALUE\n", f"machine h force yes password {REDACTED}\n"),
        # A name glued to the keyword after it stays.
        ('machine h login "u"password VALUE\n', f'machine h login "u"password {REDACTED}\n'),
        # A comment in an escaped string stays, up to the next line-break escape.
        (
            'x = "machine h\\n  # note\\nlogin u # bot\\npassword VALUE"',
            f'x = "machine h\\n  # note\\nlogin u # bot\\npassword {REDACTED}"',
        ),
        # A netrc file's own comment stays whole, a path in it included, and so
        # does a token the format does not define on a line of its own.
        (
            "machine fs.corp\n  # Bob's share is C:\\new\\data\n  login bob\n  password VALUE\n",
            f"machine fs.corp\n  # Bob's share is C:\\new\\data\n  login bob\n  password {REDACTED}\n",
        ),
        ("machine h\nforce yes\npassword VALUE\n", f"machine h\nforce yes\npassword {REDACTED}\n"),
        # Adjacent string literals stay, and so does what parts them.
        (
            'NETRC = ("machine h\\n"\n  "login u\\n" +\n  "password VALUE\\n")',
            f'NETRC = ("machine h\\n"\n  "login u\\n" +\n  "password {REDACTED}")',
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
        "macdef is an ftp macro keyword",
        # A token the format does not define on a later line ends the entry when
        # no 'password', 'passwd' or 'account' follows it in the entry's region,
        # which a blank line ends, and which spans eight lines at most.
        "machine learning tools\n\ncreate an account for each user",
        "machine learning tools\n" + "and more\n" * 7 + "create an account for each user",
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
        # After 'machine' or 'login', a token the format does not define on the
        # same line ends no entry, as it ends none for curl.
        ("my machine has no login password set", f"my machine has no login password {REDACTED}"),
        (
            "This machine learning library needs an account and a key",
            f"This machine learning library needs an account {REDACTED} a key",
        ),
        # Nor does one on a later line before an 'account' in the entry's region,
        # so that the rest of a comment cut at an escape never shows a password.
        (
            "machine learning tools\ncreate an account for each user",
            f"machine learning tools\ncreate an account {REDACTED} each user",
        ),
        (
            "machine learning tools\n" + "and more\n" * 6 + "create an account for each user",
            "machine learning tools\n" + "and more\n" * 6 + f"create an account {REDACTED} each user",
        ),
    ],
)
def test_a_prose_word_after_a_netrc_keyword_is_withheld(source, expected):
    assert sanitize_text(source) == expected


@pytest.mark.parametrize(
    ("line", "shown"),
    [
        ('NETRC = "machine api.openai.com login CORP\\\\fred password VALUE"', "CORP"),
        ("# machine api.openai.com login CORP\\victor password VALUE", "CORP"),
        (
            'NETRC = "machine api.openai.com\\n  # deploy bot\\n  login bot\\n  password VALUE\\n"',
            "deploy bot",
        ),
        (
            'NETRC = r"""\nmachine proxy.corp\n  # Bob\'s proxy share is C:\\new\\data\n  login bob\n'
            '  password VALUE  # proxy for api.openai.com\n"""',
            "proxy for api.openai.com",
        ),
        (
            'NETRC = ("machine proxy.corp\\n"\n         "login bot\\n"\n'
            '         "password VALUE\\n")  # proxy for api.openai.com',
            "proxy for api.openai.com",
        ),
    ],
)
def test_no_report_format_shows_a_netrc_password_from_source(tmp_path, index, line, shown):
    # An app that uses OpenAI and keeps a netrc entry in a string or a
    # comment: the entry ended at the escape a domain login seemed to hold, an
    # indented comment in the string hid the lines after it, a comment with
    # an apostrophe and a path ended at the path, or the entry was spread over
    # adjacent string literals, and the excerpt showed the password in every
    # report format.
    password = "pw-" + _random(24)
    (tmp_path / "app.py").write_text(
        "import openai\n\nclient = openai.OpenAI()\n" + line.replace("VALUE", password) + "\n"
    )
    spec = ConnectorSpec("code.filesystem", {"path": str(tmp_path), "use_git": False})
    result = Engine(ScanConfig(connectors=[spec]), index).run()
    assert result.complete
    reports = {name: render(result) for name, render in RENDERERS.items()}
    assert any(shown in report for report in reports.values())  # the excerpt is reported
    assert [name for name, report in reports.items() if password in report] == []

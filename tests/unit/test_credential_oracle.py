"""One oracle for the credential pipeline: every concrete input of its reviews, judged against main.

The reviews of the credential detection and redaction rounds (the leak and
precision reviews of rounds 1 and 3, round 4's credential and netrc
reviews, review-cred255, review-x-credentials and the possessive-placeholder
findings of review-misc) each showed their problems with concrete inputs:
sanitizer lines, matcher lines with their mode, small file trees,
``saas.generic`` records and placeholder values. Fixing one finding kept
breaking another's evidence, because each fix was judged on its newest
example alone. This table holds all 554 of them, with the fixes' own cases,
so every heuristic change is judged on the same fixed set.

Each row gives the outcome on this branch (``head``), which the test
asserts, and the outcome on main 8c72467 (``main``), which is data: it was
computed once, by running the same evaluation (``_outcome`` below, with
main's ``match_secrets(text)`` and ``placeholder_reason(match.value)`` in
place of this branch's ``code``/``env_file`` modes and
``reported_credential``) in a detached worktree of 8c72467, and written in.
A row may be worse than main (shows a credential main withheld, misses a
line main reported, or leaves a scan incomplete that main completed) only
with an ``accepted`` reason, and only one of these: the value is no
credential (a reference, a label, a placeholder, a name), or the scan
discloses more than five distinct credentials of one format (#257's quota).
A credential repeated on several lines counts once but is listed at up to
five of them, as main listed it, so missed repeats are no reason.

Outcomes: ``sanitize`` and ``saas`` rows are ``withheld`` or ``shown`` (no
secret of the row in the output); ``match`` rows are ``reported`` or
``unreported`` (a match whose credential is no placeholder), with mode
``code``, ``text`` (neither code nor an env file) or ``env`` (an env or
credential file); ``placeholder`` rows are ``placeholder`` or
``credential``; ``scan`` rows are the secret findings' evidence locations,
``complete`` or ``incomplete``, and ``withheld`` or ``shown`` for the whole
report and its diagnostics. Credential-shaped values are assembled at run
time (``VALUES``); ``<=text>`` marks a literal credential that must not be
shown.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import NamedTuple

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.common import placeholder_reason
from shadowscan.connectors.saas.generic import GenericSaaSConnector
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.matcher import reported_credential
from shadowscan.utils.redaction import sanitize_text


def _key(seed: str, length: int = 32) -> str:
    """A mixed-case key of letters and digits derived from ``seed``, so none sits in the source."""
    digest = base64.b64encode(hashlib.sha256(seed.encode()).digest() * 3).decode()
    return "".join(char for char in digest if char.isalnum())[:length]


def _openai_key(number: int) -> str:
    """A synthetic OpenAI project key; the prefix is assembled at run time."""
    return (
        "sk-"
        + "proj-"
        + _key(f"oracle-oai-{number}", 48)
        + "T3BlbkFJ"
        + f"{number:02d}"
        + _key(f"oracle-tail-{number}", 20)
    )


_BASE32 = base64.b32encode(hashlib.sha256(b"oracle-akia").digest()).decode()
_HELLO = base64.b32encode(b"Hello!\xde\xad\xbe\xef").decode()
# What each <token> of a row stands for. A row's secrets are the values of its
# tokens and every <=text> literal; none of them may be shown.
VALUES: dict[str, str] = {
    "<K>": _key("oracle-k"),
    **{f"<K{n}>": _key(f"oracle-k{n}") for n in range(1, 9)},
    "<R>": "R4nd0m" + "9Qx2Vb7Lp6",
    "<P>": "Xk9#mQ2$" + "vL!pR7@wZ4%",
    "<PW1>": "hunter2!" * 2,
    "<PW2>": "S3cr3t!" + "P@ssw0rd",
    "<PW3>": "9fK!x2#L" + "q8$zP0&w",
    "<PW4>": "P@ssw0rd" + "-2024!Prod",
    "<PW5>": "aB3$dE6^" + "gH9*jK2(mN5",
    "<PW6>": "Tr0ub4dor" + "&3",
    # A base32 TOTP secret, a letters-only keyboard run and two digit-poor runs pasted as names.
    "<B32A>": _HELLO * 2,
    "<B32L>": "QWERTYUIOP" + "ASDFGHJKL" + "ZXCVBNM",
    "<B32N>": _HELLO.replace("3", "") * 2 + "AB",
    "<B32M>": "ZXCVBNM" + "ASDFGHJKL" + "2" + "QWERTYUIOP",
    "<AKIA>": "AKIA" + _BASE32[:16],
    "<AKIAL>": "AKIA" + "".join(char for char in _BASE32 if char.isalpha())[:16],
    "<GHP>": "ghp_" + _key("oracle-ghp", 36),
    # A mixed-case letters-only run, as in a token after a possessive.
    "<MIX>": "QzWp" + "LmNx" + "VbRt" + "YcDf" + "Gh",
    # A password's opaque-looking start, before its tail.
    "<KS>": _key("oracle-ks", 12),
    **{f"<OAI{n}>": _openai_key(n) for n in range(1, 9)},
    **{f"<HEX{n}>": hashlib.sha256(f"oracle-hex-{n}".encode()).hexdigest()[:32] for n in range(1, 8)},
}
_TOKEN = re.compile(r"<=(?P<literal>[^<>]+)>|<[A-Z][A-Z0-9]*>")


def _expand(text: str) -> tuple[str, set[str]]:
    """``text`` with its tokens replaced, and the secrets they stand for."""
    secrets: set[str] = set()

    def value(token: re.Match[str]) -> str:
        found = token["literal"] if token["literal"] is not None else VALUES[token.group()]
        secrets.add(found)
        return found

    return _TOKEN.sub(value, text), secrets


def _numbered(rel: str, template: str, count: int) -> dict[str, str]:
    """A file of ``count`` lines, each ``template`` with ``{n}`` its number."""
    return {rel: "".join(template.replace("{n}", str(n)) for n in range(count))}


class Row(NamedTuple):
    id: str
    kind: str
    given: str | dict[str, str]
    mode: str
    head: object
    main: object
    accepted: str = ""


ACCEPTED_KINDS = ("not a credential: ", "disclosed: ")

# Round 4's sentence passphrases, each judged in an env file, a compose file
# and a settings module (joined by '_' there), as the review scanned them.
R4_SENTENCES = (
    "may-the-force-be-with-you",
    "my-dog-is-named-rex",
    "now-is-the-winter-of-discontent",
    "bring-me-the-horizon",
    "meet-me-at-midnight",
    "dance-with-me-tonight",
    "winter-is-coming-to-town",
    "hello-from-the-other-side",
    "walk-on-the-wild-side",
    "fly-me-to-the-moon",
    "stairway-to-heaven-now",
    "in-the-air-tonight",
    "gravel-by-the-sea",
    "snout-at-the-bloom",
    "these-only-thump-bloom",
)
# Round 4's possessive passphrases: the placeholder test, saas.generic's copies
# of the value in other columns, and the matcher in an env file and in code.
R4_POSSESSIVES = (
    "ton-jardin-secret",
    "votre-jardin-secret",
    "ton-secret-jardin",
    "votre-secret-favori",
    "su-token-de-casa",
    "tu-token-azul-grande",
    "vos-secrets-bien-gardes",
    "sua-senha-forte-azul",
    "tu-clave-secreta-roja",
    "ta-key-lime-pie",
    "ton-pass-navigo",
    "ta-cle-de-sol",
    "su-clave-de-sol",
    "jouw-geheime-tuin",
    "dein-geheimer-garten",
)
# Round 4's env-file passwords of the enlarged label vocabulary, read as
# '.env' 'DB_PASSWORD=<value>' lines.
R4_ENV_PASSWORDS = (
    "MyStrongPassword",
    "InternalUserPassword",
    "TheAdminUserPassword",
    "StrongInternalAdminUser",
    "CommitStrongAdminUser",
    "admin_user_strong_internal",
    "user_admin_internal",
    "strong_admin_at_home",
    "my_user_is_admin",
    "yet_another_admin_user",
    "super_strong_user_pass",
    "the_secret_admin_key",
    "my_secret_password",
    "AdminPasswordStrong",
    "StrongAdminPassword2024",
    "LocalAdmin2024Strong",
    "WelcomeToTheJungle",
)
# Round 4's settings reads whose default argument is a hard-coded key.
R4_DEFAULT_READS = (
    (
        "cs-typed-get-value",
        "src/A.cs",
        'var openaiApiKey = configuration.GetValue<string>("OpenAI:ApiKey", "<K>");\n',
    ),
    ("cs-get-value", "src/A.cs", 'var openaiApiKey = configuration.GetValue("OpenAI:ApiKey", "<K>");\n'),
    ("ts-config-get", "src/a.ts", "const openaiApiKey = this.configService.get('OPENAI_API_KEY', '<K>');\n"),
    (
        "ts-typed-config-get",
        "src/a.ts",
        "const openaiApiKey = this.configService.get<string>('OPENAI_API_KEY', '<K>');\n",
    ),
    (
        "java-or-else",
        "src/A.java",
        'String openaiApiKey = Optional.ofNullable(System.getenv("OPENAI_API_KEY")).orElse("<K>");\n',
    ),
    (
        "java-require-non-null-else",
        "src/A.java",
        'String openaiApiKey = Objects.requireNonNullElse(System.getenv("OPENAI_API_KEY"), "<K>");\n',
    ),
    (
        "ts-spaced-type-arguments",
        "src/a.ts",
        "const openaiApiKey = this.configService.get <string>('OPENAI_API_KEY') ?? '<K>';\n",
    ),
)
# Round 4's password fallbacks after an environment read, in four forms.
R4_PASSWORD_FALLBACK_FORMS = (
    ("js-or", "src/db.js", 'const dbPassword = process.env.DB_PASSWORD || "{v}";\n'),
    ("ts-nullish", "src/db.ts", "export const dbPassword = process.env.DB_PASSWORD ?? '{v}';\n"),
    ("ts-entry", "src/db.ts", "export const cfg = { dbPassword: process.env.DB_PASSWORD || '{v}' };\n"),
    (
        "cs-nullish",
        "src/A.cs",
        'var dbPassword = Environment.GetEnvironmentVariable("DB_PASSWORD") ?? "{v}";\n',
    ),
)
R4_PASSWORD_FALLBACKS = (
    ("punctuated", "<P>"),
    ("leet", "<PW2>"),
    ("token-start", "<KS>&<=mypass>"),
    ("passphrase", "<=snout-fiber-thump-bloom-gravel>"),
    ("spaced", "<=correct horse battery staple>"),
    ("camel", "<=TrustNoOneEverAgain>"),
    ("snake", "<=snout_fiber_thump_bloom>"),
    ("camel-year", "<=PostgresProd2024Secure>"),
)
R4_SENTENCE_PLACES = (
    ("env", "DB_PASSWORD={v}", "env"),
    ("compose", "POSTGRES_PASSWORD: {v}", "text"),
    ("settings", 'DB_PASSWORD = "{u}"', "code"),
)

ROWS = [
    # --- creds-rereview-leak.json (round 3)
    Row(
        "r3l.1-sendgrid-optional-chain",
        "sanitize",
        'sgMail.setApiKey(process.env.SENDGRID_API_KEY?.trim() ?? "<K>");',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.1-callee-optional-chain",
        "sanitize",
        'client.setApiKey(process.env.OPENAI_API_KEY?.trim() || "<K>");',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.1-callee-plain-read",
        "sanitize",
        'client.setApiKey(process.env.OPENAI_API_KEY || "<K>");',
        mode="",
        head="withheld",
        main="withheld",
    ),
    Row(
        "r3l.1-php-arrow-trim-getenv",
        "sanitize",
        "'api_key' => trim(getenv('OPENAI_API_KEY')) ?: '<K>',",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.1-php-arrow-trim-env-default",
        "sanitize",
        "'api_key' => trim(env('OPENAI_API_KEY', '')) ?: '<K>',",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.1-black-or-settings",
        "sanitize",
        'llm = ChatOpenAI(\n    openai_api_key=settings.openai_api_key\n    or "<K>",\n)',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.1-black-or-getenv",
        "sanitize",
        'client = OpenAI(\n    api_key=os.getenv("OPENAI_API_KEY")\n    or "<K>",\n)',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.1-java-builder-ternary",
        "sanitize",
        'OpenAIClient.builder().apiKey(System.getenv("OPENAI_API_KEY") != null ? System.getenv("OPENAI_API_KEY") : "<K>").build();',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.1-xml-multiline-comment",
        "sanitize",
        '<add key="OpenaiApiKey" value="%OPENAI_API_KEY%" /> <!--\n  old: <K>\n-->',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.1-report-path",
        "scan",
        {
            "config/app.php": "<?php\nreturn [\n    'api_key' => trim(getenv('OPENAI_API_KEY')) ?: '<K>',\n    'other_key' => trim(env('OPENAI_API_KEY', '')) ?: '<K>',\n];\n",
            "src/mail.js": 'sgMail.setApiKey(process.env.SENDGRID_API_KEY?.trim() ?? "<K>");\nclient.setApiKey(process.env.OPENAI_API_KEY?.trim() || "<K>");\n',
            "src/Client.java": 'class C { void f() { OpenAIClient.builder().apiKey(System.getenv("OPENAI_API_KEY") != null ? System.getenv("OPENAI_API_KEY") : "<K>").build(); } }\n',
            "notebook.ipynb": '{"cells": [{"cell_type": "code", "execution_count": null, "metadata": {}, "outputs": [], "source": ["client = OpenAI(\\n", "    api_key=os.getenv(\\"OPENAI_API_KEY\\")\\n", "    or \\"<K>\\",\\n", ")\\n"]}], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}\n',
        },
        mode="",
        head=((), "complete", "withheld"),
        main=((), "complete", "withheld"),
    ),
    Row(
        "r3l.2-p-optional-chain",
        "sanitize",
        'dbPassword: process.env.DB_PASSWORD?.trim() || "<P>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-p-spaced-subscript",
        "sanitize",
        "db_password: os.environ[ 'DB_PASSWORD' ] if PROD else '<P>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-p-default-argument",
        "sanitize",
        'db_password: os.getenv("<K>", "<P>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-hunter-optional-chain",
        "sanitize",
        'dbPassword: process.env.DB_PASSWORD?.trim() || "<PW1>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-hunter-spaced-subscript",
        "sanitize",
        "db_password: os.environ[ 'DB_PASSWORD' ] if PROD else '<PW1>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-hunter-default-argument",
        "sanitize",
        'db_password: os.getenv("<K>", "<PW1>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-s3cr3t-optional-chain",
        "sanitize",
        'dbPassword: process.env.DB_PASSWORD?.trim() || "<PW2>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-s3cr3t-spaced-subscript",
        "sanitize",
        "db_password: os.environ[ 'DB_PASSWORD' ] if PROD else '<PW2>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-s3cr3t-default-argument",
        "sanitize",
        'db_password: os.getenv("<K>", "<PW2>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-9fk-optional-chain",
        "sanitize",
        'dbPassword: process.env.DB_PASSWORD?.trim() || "<PW3>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-9fk-spaced-subscript",
        "sanitize",
        "db_password: os.environ[ 'DB_PASSWORD' ] if PROD else '<PW3>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-9fk-default-argument",
        "sanitize",
        'db_password: os.getenv("<K>", "<PW3>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-p-2024-optional-chain",
        "sanitize",
        'dbPassword: process.env.DB_PASSWORD?.trim() || "<PW4>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-p-2024-spaced-subscript",
        "sanitize",
        "db_password: os.environ[ 'DB_PASSWORD' ] if PROD else '<PW4>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-p-2024-default-argument",
        "sanitize",
        'db_password: os.getenv("<K>", "<PW4>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-ab3-optional-chain",
        "sanitize",
        'dbPassword: process.env.DB_PASSWORD?.trim() || "<PW5>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-ab3-spaced-subscript",
        "sanitize",
        "db_password: os.environ[ 'DB_PASSWORD' ] if PROD else '<PW5>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-ab3-default-argument",
        "sanitize",
        'db_password: os.getenv("<K>", "<PW5>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-slug-optional-chain",
        "sanitize",
        'dbPassword: process.env.DB_PASSWORD?.trim() || "<=snout-fiber-thump-bloom-gravel>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-slug-spaced-subscript",
        "sanitize",
        "db_password: os.environ[ 'DB_PASSWORD' ] if PROD else '<=snout-fiber-thump-bloom-gravel>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-slug-default-argument",
        "sanitize",
        'db_password: os.getenv("<K>", "<=snout-fiber-thump-bloom-gravel>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-spaced-optional-chain",
        "sanitize",
        'dbPassword: process.env.DB_PASSWORD?.trim() || "<=correct horse battery staple>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-spaced-spaced-subscript",
        "sanitize",
        "db_password: os.environ[ 'DB_PASSWORD' ] if PROD else '<=correct horse battery staple>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-spaced-default-argument",
        "sanitize",
        'db_password: os.getenv("<K>", "<=correct horse battery staple>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-troub-optional-chain",
        "sanitize",
        'dbPassword: process.env.DB_PASSWORD?.trim() || "<PW6>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-troub-spaced-subscript",
        "sanitize",
        "db_password: os.environ[ 'DB_PASSWORD' ] if PROD else '<PW6>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-troub-default-argument",
        "sanitize",
        'db_password: os.getenv("<K>", "<PW6>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r3l.2-assignment-form",
        "sanitize",
        'db_password = os.getenv("DB_PASS", "<P>")',
        mode="",
        head="withheld",
        main="withheld",
    ),
    Row(
        "r3l.3-postgres-prod",
        "scan",
        {".env": "POSTGRES_PASSWORD=<=PostgresProd2024Secure>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-redis-local",
        "scan",
        {".env.local": "REDIS_PASSWORD=<=RedisCacheProd2024>\n"},
        mode="",
        head=((".env.local:1",), "complete", "withheld"),
        main=((".env.local:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-keycloak",
        "scan",
        {".env": "KEYCLOAK_ADMIN_PASSWORD=<=KeycloakAdmin2024Strong>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-local-admin",
        "scan",
        {".env": "DB_PASSWORD=<=LocalAdmin2024Strong>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-passed-slug",
        "scan",
        {".env": "DB_PASSWORD=<=snout_passed_thump_bloom>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-dev-slug",
        "scan",
        {".env": "DB_PASSWORD=<=snout_dev_thump_bloom>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-keyed-slug",
        "scan",
        {".env": "DB_PASSWORD=<=glider_keyed_thump_bloom>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-camel-passed",
        "scan",
        {".env": "DB_PASSWORD=<=SnoutPassedThump2024>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-dash-dev-slug",
        "scan",
        {".env": "DB_PASSWORD=<=snout-dev-thump-bloom>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-compose-postgres-prod",
        "scan",
        {
            "docker-compose.yml": "services:\n  db:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: <=PostgresProd2024Secure>\n"
        },
        mode="",
        head=(("docker-compose.yml:5",), "complete", "withheld"),
        main=(("docker-compose.yml:5",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-yaml-passed-slug",
        "scan",
        {"config/db.yaml": "db_password: <=snout_passed_thump_bloom>\n"},
        mode="",
        head=(("config/db.yaml:1",), "complete", "withheld"),
        main=(("config/db.yaml:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.3-env-MyCompanyName2024Prod",
        "match",
        "DB_PASSWORD=MyCompanyName2024Prod",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3l.3-text-MyCompanyName2024Prod",
        "match",
        "DB_PASSWORD=MyCompanyName2024Prod",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r3l.3-env-MailServerKey2024Abc",
        "match",
        "DB_PASSWORD=MailServerKey2024Abc",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3l.3-text-MailServerKey2024Abc",
        "match",
        "DB_PASSWORD=MailServerKey2024Abc",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r3l.3-env-BlueSkyValue2024Go",
        "match",
        "DB_PASSWORD=BlueSkyValue2024Go",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3l.3-text-BlueSkyValue2024Go",
        "match",
        "DB_PASSWORD=BlueSkyValue2024Go",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r3l.3-env-GrafanaAdmin_2024_Zz",
        "match",
        "DB_PASSWORD=GrafanaAdmin_2024_Zz",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3l.3-text-GrafanaAdmin_2024_Zz",
        "match",
        "DB_PASSWORD=GrafanaAdmin_2024_Zz",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r3l.3-env-myDevPassword123x",
        "match",
        "DB_PASSWORD=myDevPassword123x",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3l.3-text-myDevPassword123x",
        "match",
        "DB_PASSWORD=myDevPassword123x",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r3l.4-ts-get-string",
        "scan",
        {"src/a.ts": "const openaiApiKey = this.configService.get<string>('OPENAI_API_KEY') ?? '<K>';\n"},
        mode="",
        head=(("src/a.ts:1",), "complete", "withheld"),
        main=(("src/a.ts:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.4-ts-object-get-string",
        "scan",
        {
            "src/a.ts": "export const cfg = {\n  openaiApiKey: this.configService.get<string>('OPENAI_API_KEY') ?? '<K>',\n};\n"
        },
        mode="",
        head=(("src/a.ts:2",), "complete", "withheld"),
        main=(("src/a.ts:2",), "complete", "withheld"),
    ),
    Row(
        "r3l.4-ts-get-string-non-null",
        "scan",
        {"src/a.ts": 'const openaiApiKey = this.configService.get<string>("OPENAI_API_KEY")! || "<K>";\n'},
        mode="",
        head=(("src/a.ts:1",), "complete", "withheld"),
        main=(("src/a.ts:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.4-ts-chain-get-string",
        "scan",
        {"src/a.ts": 'const openaiApiKey = this.config.values.get<string>("x") ?? "<K>";\n'},
        mode="",
        head=(("src/a.ts:1",), "complete", "withheld"),
        main=(("src/a.ts:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.4-cs-getvalue-string",
        "scan",
        {"src/A.cs": 'var openaiApiKey = configuration.GetValue<string>("OpenAI:ApiKey") ?? "<K>";\n'},
        mode="",
        head=(("src/A.cs:1",), "complete", "withheld"),
        main=(("src/A.cs:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.4-kt-getproperty-string",
        "scan",
        {"src/A.kt": 'val openaiApiKey = config.getProperty<String>("openai") ?: "<K>"\n'},
        mode="",
        head=(("src/A.kt:1",), "complete", "withheld"),
        main=(("src/A.kt:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.4-ts-untyped",
        "scan",
        {"src/a.ts": "const openaiApiKey = this.configService.get('OPENAI_API_KEY') ?? '<K>';\n"},
        mode="",
        head=(("src/a.ts:1",), "complete", "withheld"),
        main=(("src/a.ts:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.5-ts-base32-name",
        "scan",
        {"src/a.ts": "const openaiApiKey = process.env.<B32A>;\n"},
        mode="",
        head=(("src/a.ts:1",), "complete", "withheld"),
        main=(("src/a.ts:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.5-ts-letters-name",
        "scan",
        {"src/a.ts": "const openaiApiKey = process.env.<B32L>;\n"},
        mode="",
        head=(("src/a.ts:1",), "complete", "withheld"),
        main=(("src/a.ts:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.5-py-environ-attribute",
        "scan",
        {"src/a.py": "openai_api_key = os.environ.<B32N>\n"},
        mode="",
        head=(("src/a.py:1",), "complete", "withheld"),
        main=(("src/a.py:1",), "complete", "withheld"),
    ),
    Row(
        "r3l.5-sanitize-letters-name",
        "sanitize",
        "apiKey: process.env.<B32L>,",
        mode="",
        head="withheld",
        main="withheld",
    ),
    Row(
        "r3l.6-compose-six-services",
        "scan",
        {
            "docker-compose.yml": "services:\n  svc1:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: <K>\n  svc2:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: <K>\n  svc3:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: <K>\n  svc4:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: <K>\n  svc5:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: <K>\n  svc6:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: <K>\n"
        },
        mode="",
        head=(
            (
                "docker-compose.yml:13",
                "docker-compose.yml:17",
                "docker-compose.yml:21",
                "docker-compose.yml:5",
                "docker-compose.yml:9",
            ),
            "complete",
            "withheld",
        ),
        main=(
            (
                "docker-compose.yml:13",
                "docker-compose.yml:17",
                "docker-compose.yml:21",
                "docker-compose.yml:5",
                "docker-compose.yml:9",
            ),
            "complete",
            "withheld",
        ),
    ),
    Row(
        "r3l.6-k8s-six-secrets",
        "scan",
        {
            "k8s/deploy.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s1\nstringData:\n  OPENAI_API_KEY: <K>\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: s2\nstringData:\n  OPENAI_API_KEY: <K>\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: s3\nstringData:\n  OPENAI_API_KEY: <K>\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: s4\nstringData:\n  OPENAI_API_KEY: <K>\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: s5\nstringData:\n  OPENAI_API_KEY: <K>\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: s6\nstringData:\n  OPENAI_API_KEY: <K>\n"
        },
        mode="",
        head=(
            (
                "k8s/deploy.yaml:13",
                "k8s/deploy.yaml:20",
                "k8s/deploy.yaml:27",
                "k8s/deploy.yaml:34",
                "k8s/deploy.yaml:6",
            ),
            "complete",
            "withheld",
        ),
        main=(
            (
                "k8s/deploy.yaml:13",
                "k8s/deploy.yaml:20",
                "k8s/deploy.yaml:27",
                "k8s/deploy.yaml:34",
                "k8s/deploy.yaml:6",
            ),
            "complete",
            "withheld",
        ),
    ),
    Row(
        "r3l.6-py-six-lines",
        "scan",
        {
            "src/a.py": 'SVC1_OPENAI_API_KEY = "<K>"\nSVC2_OPENAI_API_KEY = "<K>"\nSVC3_OPENAI_API_KEY = "<K>"\nSVC4_OPENAI_API_KEY = "<K>"\nSVC5_OPENAI_API_KEY = "<K>"\nSVC6_OPENAI_API_KEY = "<K>"\n'
        },
        mode="",
        head=(("src/a.py:1", "src/a.py:2", "src/a.py:3", "src/a.py:4", "src/a.py:5"), "complete", "withheld"),
        main=(
            (
                "src/a.py:1",
                "src/a.py:2",
                "src/a.py:3",
                "src/a.py:4",
                "src/a.py:5",
            ),
            "complete",
            "withheld",
        ),
    ),
    Row(
        "r3l.6-py-five-lines",
        "scan",
        {
            "src/a.py": 'SVC1_OPENAI_API_KEY = "<K>"\nSVC2_OPENAI_API_KEY = "<K>"\nSVC3_OPENAI_API_KEY = "<K>"\nSVC4_OPENAI_API_KEY = "<K>"\nSVC5_OPENAI_API_KEY = "<K>"\n'
        },
        mode="",
        head=(("src/a.py:1", "src/a.py:2", "src/a.py:3", "src/a.py:4", "src/a.py:5"), "complete", "withheld"),
        main=(
            (
                "src/a.py:1",
                "src/a.py:2",
                "src/a.py:3",
                "src/a.py:4",
                "src/a.py:5",
            ),
            "complete",
            "withheld",
        ),
    ),
    Row(
        "r3l.7-must-be-overridden",
        "scan",
        {"src/settings.py": 'OPENAI_API_KEY = "must-be-overridden"\n'},
        mode="",
        head=((), "complete", "withheld"),
        main=(("src/settings.py:1",), "complete", "withheld"),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3l.7-must-be-set-at-deploy-time",
        "scan",
        {"src/settings.py": 'OPENAI_API_KEY = "must-be-set-at-deploy-time"\n'},
        mode="",
        head=((), "complete", "withheld"),
        main=(("src/settings.py:1",), "complete", "withheld"),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3l.7-not-set-upper",
        "scan",
        {"src/settings.py": 'OPENAI_API_KEY = "NOT-SET-IN-THIS-ENVIRONMENT"\n'},
        mode="",
        head=((), "complete", "withheld"),
        main=(("src/settings.py:1",), "complete", "withheld"),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3l.7-set-via-environment",
        "scan",
        {"src/settings.py": 'OPENAI_API_KEY = "SET-VIA-ENVIRONMENT-VAR"\n'},
        mode="",
        head=((), "complete", "withheld"),
        main=(("src/settings.py:1",), "complete", "withheld"),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3l.7-yaml-not-set",
        "scan",
        {"config/app.yaml": "openai_api_key: not-set-in-this-environment\n"},
        mode="",
        head=((), "complete", "withheld"),
        main=(("config/app.yaml:1",), "complete", "withheld"),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3l.7-CHANGE-ME-PLEASE-NOW-text",
        "match",
        "export DB_PASSWORD=CHANGE-ME-PLEASE-NOW",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3l.7-CHANGE-ME-PLEASE-NOW-code",
        "match",
        "db_password = 'CHANGE-ME-PLEASE-NOW'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3l.7-CHANGE-ME-PLEASE-NOW-env",
        "match",
        "DB_PASSWORD=CHANGE-ME-PLEASE-NOW",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3l.7-not-configured-yet-xyz-text",
        "match",
        "export DB_PASSWORD=not-configured-yet-xyz",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3l.7-not-configured-yet-xyz-code",
        "match",
        "db_password = 'not-configured-yet-xyz'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3l.7-not-configured-yet-xyz-env",
        "match",
        "DB_PASSWORD=not-configured-yet-xyz",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    # --- creds-rereview-precision.json (round 3)
    Row(
        "r3p.1-change-me-before-deploying-text",
        "match",
        "export DB_PASSWORD=change-me-before-deploying",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change-me-before-deploying-code",
        "match",
        "db_password = 'change-me-before-deploying'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change-me-before-deploying-env",
        "match",
        "DB_PASSWORD=change-me-before-deploying",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change-me-please-text",
        "match",
        "export DB_PASSWORD=change-me-please",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change-me-please-code",
        "match",
        "db_password = 'change-me-please'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change-me-please-env",
        "match",
        "DB_PASSWORD=change-me-please",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-please-change-me-now-text",
        "match",
        "export DB_PASSWORD=please-change-me-now",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-please-change-me-now-code",
        "match",
        "db_password = 'please-change-me-now'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-please-change-me-now-env",
        "match",
        "DB_PASSWORD=please-change-me-now",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change-me-asap-please-text",
        "match",
        "export DB_PASSWORD=change-me-asap-please",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change-me-asap-please-code",
        "match",
        "db_password = 'change-me-asap-please'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change-me-asap-please-env",
        "match",
        "DB_PASSWORD=change-me-asap-please",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change_me_please-text",
        "match",
        "export DB_PASSWORD=change_me_please",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change_me_please-code",
        "match",
        "db_password = 'change_me_please'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-change_me_please-env",
        "match",
        "DB_PASSWORD=change_me_please",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-CHANGE-ME-BEFORE-DEPLOY-text",
        "match",
        "export DB_PASSWORD=CHANGE-ME-BEFORE-DEPLOY",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-CHANGE-ME-BEFORE-DEPLOY-code",
        "match",
        "db_password = 'CHANGE-ME-BEFORE-DEPLOY'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-CHANGE-ME-BEFORE-DEPLOY-env",
        "match",
        "DB_PASSWORD=CHANGE-ME-BEFORE-DEPLOY",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-do-not-commit-this-text",
        "match",
        "export DB_PASSWORD=do-not-commit-this",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-do-not-commit-this-code",
        "match",
        "db_password = 'do-not-commit-this'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-do-not-commit-this-env",
        "match",
        "DB_PASSWORD=do-not-commit-this",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-never-commit-real-ones-text",
        "match",
        "export DB_PASSWORD=never-commit-real-ones",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-never-commit-real-ones-code",
        "match",
        "db_password = 'never-commit-real-ones'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-never-commit-real-ones-env",
        "match",
        "DB_PASSWORD=never-commit-real-ones",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-be-set-at-runtime-text",
        "match",
        "export DB_PASSWORD=must-be-set-at-runtime",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-be-set-at-runtime-code",
        "match",
        "db_password = 'must-be-set-at-runtime'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-be-set-at-runtime-env",
        "match",
        "DB_PASSWORD=must-be-set-at-runtime",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-not-set-in-this-repo-text",
        "match",
        "export DB_PASSWORD=not-set-in-this-repo",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-not-set-in-this-repo-code",
        "match",
        "db_password = 'not-set-in-this-repo'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-not-set-in-this-repo-env",
        "match",
        "DB_PASSWORD=not-set-in-this-repo",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-come-from-vault-text",
        "match",
        "export DB_PASSWORD=must-come-from-vault",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-come-from-vault-code",
        "match",
        "db_password = 'must-come-from-vault'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-come-from-vault-env",
        "match",
        "DB_PASSWORD=must-come-from-vault",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-do-not-use-this-one-text",
        "match",
        "export DB_PASSWORD=do-not-use-this-one",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-do-not-use-this-one-code",
        "match",
        "db_password = 'do-not-use-this-one'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-do-not-use-this-one-env",
        "match",
        "DB_PASSWORD=do-not-use-this-one",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-override-at-deploy-text",
        "match",
        "export DB_PASSWORD=must-override-at-deploy",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-override-at-deploy-code",
        "match",
        "db_password = 'must-override-at-deploy'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-override-at-deploy-env",
        "match",
        "DB_PASSWORD=must-override-at-deploy",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-not-be-empty-text",
        "match",
        "export DB_PASSWORD=must-not-be-empty",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-not-be-empty-code",
        "match",
        "db_password = 'must-not-be-empty'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-must-not-be-empty-env",
        "match",
        "DB_PASSWORD=must-not-be-empty",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-not-configured-yet-text",
        "match",
        "export DB_PASSWORD=not-configured-yet",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-not-configured-yet-code",
        "match",
        "db_password = 'not-configured-yet'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-not-configured-yet-env",
        "match",
        "DB_PASSWORD=not-configured-yet",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-jwt-signing-key-material-text",
        "match",
        "export DB_PASSWORD=jwt-signing-key-material",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-jwt-signing-key-material-code",
        "match",
        "db_password = 'jwt-signing-key-material'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-jwt-signing-key-material-env",
        "match",
        "DB_PASSWORD=jwt-signing-key-material",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-pg-replica-sync-user-text",
        "match",
        "export PG_PASSWORD=pg-replica-sync-user",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-pg-replica-sync-user-code",
        "match",
        "pg_password = 'pg-replica-sync-user'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-pg-replica-sync-user-env",
        "match",
        "PG_PASSWORD=pg-replica-sync-user",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3p.1-db-readonly-reporting-user-text",
        "match",
        "export DB_PASSWORD=db-readonly-reporting-user",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-db-readonly-reporting-user-code",
        "match",
        "db_password = 'db-readonly-reporting-user'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-db-readonly-reporting-user-env",
        "match",
        "DB_PASSWORD=db-readonly-reporting-user",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3p.1-ai-gateway-internal-route-text",
        "match",
        "export AI_API_KEY=ai-gateway-internal-route",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-ai-gateway-internal-route-code",
        "match",
        "ai_api_key = 'ai-gateway-internal-route'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-ai-gateway-internal-route-env",
        "match",
        "AI_API_KEY=ai-gateway-internal-route",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-mq-broker-admin-user-text",
        "match",
        "export MQ_PASSWORD=mq-broker-admin-user",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-mq-broker-admin-user-code",
        "match",
        "mq_password = 'mq-broker-admin-user'",
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1-mq-broker-admin-user-env",
        "match",
        "MQ_PASSWORD=mq-broker-admin-user",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3p.1a-env-example-six-labels",
        "scan",
        {
            ".env.example": "POSTGRES_PASSWORD=must-be-set-at-runtime\nREDIS_PASSWORD=must-be-set-at-runtime\nSMTP_PASSWORD=must-be-set-at-runtime\nKEYCLOAK_ADMIN_PASSWORD=must-be-set-at-runtime\nMINIO_ROOT_PASSWORD=must-be-set-at-runtime\nGRAFANA_ADMIN_PASSWORD=must-be-set-at-runtime\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                ".env.example:1",
                ".env.example:2",
                ".env.example:3",
                ".env.example:4",
                ".env.example:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1b-compose-do-not-commit",
        "scan",
        {
            "docker-compose.yml": "services:\n  db:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: do-not-commit-this\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(("docker-compose.yml:5",), "complete", "withheld"),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1b-settings-not-configured",
        "scan",
        {"app/settings.py": 'DATABASE_PASSWORD = "not-configured-yet"\n'},
        mode="",
        head=((), "complete", "withheld"),
        main=(("app/settings.py:1",), "complete", "withheld"),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1b-readme-exports",
        "scan",
        {
            "README.md": "# Setup\n\n```sh\nexport DATABASE_PASSWORD=change-me-before-deploying\nexport ADMIN_PASSWORD=please-change-me-now\n```\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                "README.md:4",
                "README.md:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.1b-compose-change-me",
        "scan",
        {
            "docker-compose.yml": "services:\n  db:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: change-me-please\n      ADMIN_PASSWORD: change_me_asap_please\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                "docker-compose.yml:5",
                "docker-compose.yml:6",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r3p.2-no-blanks",
        "match",
        "POSTGRES_PASSWORD=TrustNoOneEverAgain",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3p.2-colon",
        "match",
        "POSTGRES_PASSWORD: TrustNoOneEverAgain",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3p.2-blanks",
        "match",
        "POSTGRES_PASSWORD = TrustNoOneEverAgain",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r3p.2-env-two-lines",
        "scan",
        {
            ".env": "POSTGRES_PASSWORD = <=TrustNoOneEverAgain>\nDB_PASSWORD = <=correct-horse-battery-staple>\n"
        },
        mode="",
        head=(
            (
                ".env:1",
                ".env:2",
            ),
            "complete",
            "withheld",
        ),
        main=(
            (
                ".env:1",
                ".env:2",
            ),
            "complete",
            "withheld",
        ),
    ),
    Row(
        "r3p.2-env-no-blanks",
        "scan",
        {".env": "POSTGRES_PASSWORD=<=TrustNoOneEverAgain>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "r3p.3-anthropic-placeholder-fallback",
        "scan",
        {
            "package.json": '{"name": "app", "dependencies": {"@anthropic-ai/sdk": "^0.30.0"}}\n',
            "src/client.ts": 'import Anthropic from "@anthropic-ai/sdk";\nconst anthropicApiKey = process.env.ANTHROPIC_API_KEY ?? "sk-ant-api03-...";\nexport const client = new Anthropic({ apiKey: anthropicApiKey });\n',
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(("src/client.ts:2",), "complete", "withheld"),
        accepted="not a credential: a placeholder fallback after an environment read",
    ),
    # --- creds-review-leak.json (round 1)
    Row(
        "r1l.1-optional-chain-name",
        "sanitize",
        'azureApiKey: process.env.<K>?.trim() || "<K>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r1l.1-spaced-subscript",
        "sanitize",
        "azureApiKey: process.env[ '<K>' ] || \"<K>\",",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r1l.1-spaced-subscript-if-else",
        "sanitize",
        "azure_api_key: os.environ[ '<K>' ] if PROD else '<K>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r1l.1-two-argument-call",
        "sanitize",
        'azureApiKey: cfg("a", "b") || "<K>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r1l.1-get-process-env",
        "sanitize",
        "azureApiKey: get(process.env, '<K>') || \"<K>\",",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r1l.1-getenv-default",
        "sanitize",
        'azure_api_key: os.getenv("<K>", "<K>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r1l.1-constructor-optional-chain",
        "sanitize",
        'const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY?.trim() || "<K>" });',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r1l.1-unspaced-subscript-if-else",
        "sanitize",
        "azure_api_key: os.environ['<K>'] if PROD else '<K>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r1l.1-unspaced-subscript",
        "sanitize",
        "azureApiKey: process.env['<K>'] || '<K>',",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r1l.2-js-nbsp",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY\xa0|| "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.2-py-nbsp",
        "scan",
        {"src/a.py": 'openai_api_key = settings.openai_api_key or\xa0"<K>"\n'},
        mode="",
        head=(("src/a.py:1",), "incomplete", "withheld"),
        main=(("src/a.py:1",), "incomplete", "withheld"),
    ),
    Row(
        "r1l.2-js-thin",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY\u2009|| "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.2-py-thin",
        "scan",
        {"src/a.py": 'openai_api_key = settings.openai_api_key or\u2009"<K>"\n'},
        mode="",
        head=(("src/a.py:1",), "incomplete", "withheld"),
        main=(("src/a.py:1",), "incomplete", "withheld"),
    ),
    Row(
        "r1l.2-js-ideographic",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY\u3000|| "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.2-py-ideographic",
        "scan",
        {"src/a.py": 'openai_api_key = settings.openai_api_key or\u3000"<K>"\n'},
        mode="",
        head=(("src/a.py:1",), "incomplete", "withheld"),
        main=(("src/a.py:1",), "incomplete", "withheld"),
    ),
    Row(
        "r1l.2-js-zwsp",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY\u200b|| "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.2-py-zwsp",
        "scan",
        {"src/a.py": 'openai_api_key = settings.openai_api_key or\u200b"<K>"\n'},
        mode="",
        head=(("src/a.py:1",), "incomplete", "withheld"),
        main=(("src/a.py:1",), "incomplete", "withheld"),
    ),
    Row(
        "r1l.2-js-bom",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY\ufeff|| "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.2-py-bom",
        "scan",
        {"src/a.py": 'openai_api_key = settings.openai_api_key or\ufeff"<K>"\n'},
        mode="",
        head=(("src/a.py:1",), "incomplete", "withheld"),
        main=(("src/a.py:1",), "incomplete", "withheld"),
    ),
    Row(
        "r1l.2-js-ff",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY\x0c|| "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.2-py-ff",
        "scan",
        {"src/a.py": 'openai_api_key = settings.openai_api_key or\x0c"<K>"\n'},
        mode="",
        head=(("src/a.py:1",), "complete", "withheld"),
        main=(("src/a.py:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.2-js-vt",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY\x0b|| "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.2-py-vt",
        "scan",
        {"src/a.py": 'openai_api_key = settings.openai_api_key or\x0b"<K>"\n'},
        mode="",
        head=(("src/a.py:1",), "incomplete", "withheld"),
        main=(("src/a.py:1",), "incomplete", "withheld"),
    ),
    Row(
        "r1l.2-match-nbsp",
        "match",
        'const openaiApiKey = process.env.OPENAI_API_KEY\xa0|| "<K>";',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1l.3-js-parenthesised",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY || ("<K>");\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.3-js-parenthesised-single",
        "scan",
        {"src/a.js": "const openaiApiKey = process.env.OPENAI_API_KEY ?? ('<K>');\n"},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.3-py-parenthesised",
        "scan",
        {"src/a.py": 'openai_api_key = settings.openai_api_key or ("<K>")\n'},
        mode="",
        head=(("src/a.py:1",), "complete", "withheld"),
        main=(("src/a.py:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.3-py-triple-double",
        "scan",
        {"src/a.py": 'openai_api_key = settings.openai_api_key or """<K>"""\n'},
        mode="",
        head=(("src/a.py:1",), "complete", "withheld"),
        main=(("src/a.py:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.3-py-triple-single",
        "scan",
        {"src/a.py": "openai_api_key = settings.openai_api_key or '''<K>'''\n"},
        mode="",
        head=(("src/a.py:1",), "complete", "withheld"),
        main=(("src/a.py:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.3-ts-as-cast",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY as string || "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.4-comment-line",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY ||\n  // dev fallback\n  "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.4-two-comment-lines",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY // a\n  // b\n  || "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.4-empty-line",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY ||\n\n  "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.4-crlf",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY ||\r\n  "<K>";\r\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.4-backslash",
        "scan",
        {"src/a.py": 'openai_api_key = settings.openai_api_key or \\\n    "<K>"\n'},
        mode="",
        head=(("src/a.py:1",), "complete", "withheld"),
        main=(("src/a.py:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.4-leading-operator",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY\n  || "<K>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "r1l.5-ts-2000-chains",
        "scan",
        _numbered(
            "src/a.ts",
            'const svc{n}ApiKey = process.env.SVC_API_KEY_{n} || cfg.get("svc").and("x").then((v) => v.trim()).catch(() => null) || undefined\n',
            2000,
        ),
        mode="slow",
        head=((), "complete", "withheld"),
        main=(
            (
                "src/a.ts:1",
                "src/a.ts:2",
                "src/a.ts:3",
                "src/a.ts:4",
                "src/a.ts:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: environment reads with no key literal",
    ),
    Row(
        "r1l.5-py-2000-calls",
        "scan",
        _numbered(
            "src/a.py",
            'svc{n}_api_key = settings.svc_api_key_{n} or load_default(config("a", b(c, d(e, f(g, h(i, j(k)))))), fallback=[1, 2, 3])\n',
            2000,
        ),
        mode="slow",
        head=((), "complete", "withheld"),
        main=(
            (
                "src/a.py:1",
                "src/a.py:2",
                "src/a.py:3",
                "src/a.py:4",
                "src/a.py:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: environment reads with no key literal",
    ),
    Row(
        "r1l.5-ts-500-unclosed",
        "scan",
        _numbered("src/a.ts", "const svc{n}ApiKey = process.env.SVC_API_KEY_{n} || (a(b(c(d(e(f(g(h(\n", 500),
        mode="slow",
        head=((), "complete", "withheld"),
        main=(
            (
                "src/a.ts:1",
                "src/a.ts:2",
                "src/a.ts:3",
                "src/a.ts:4",
                "src/a.ts:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: environment reads with no key literal",
    ),
    Row(
        "r1l.6-xml-comment",
        "sanitize",
        '<add key="OpenaiApiKey" value="%OPENAI_API_KEY%" /> <!-- <K> -->',
        mode="",
        head="withheld",
        main="shown",
    ),
    # --- creds-review-precision.json (round 1)
    Row(
        "r1p.1-env-example-labels",
        "scan",
        {
            ".env.example": "KEYCLOAK_ADMIN_PASSWORD=KeycloakAdminPassword\nPOSTGRES_PASSWORD=change_me_to_a_strong_password\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                ".env.example:1",
                ".env.example:2",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: a setting name or label in a template or configuration file",
    ),
    Row(
        "r1p.1-env-sample",
        "scan",
        {".env.sample": "POSTGRES_PASSWORD=change_me_to_a_strong_password\n"},
        mode="",
        head=((), "complete", "withheld"),
        main=((".env.sample:1",), "complete", "withheld"),
        accepted="not a credential: a setting name or label in a template or configuration file",
    ),
    Row(
        "r1p.1-env-template",
        "scan",
        {"config/.env.template": "POSTGRES_PASSWORD=change_me_to_a_strong_password\n"},
        mode="",
        head=((), "complete", "withheld"),
        main=(("config/.env.template:1",), "complete", "withheld"),
        accepted="not a credential: a setting name or label in a template or configuration file",
    ),
    Row(
        "r1p.1-docs-configuration",
        "scan",
        {"docs/configuration.md": "POSTGRES_PASSWORD=change_me_to_a_strong_password\n"},
        mode="",
        head=((), "complete", "withheld"),
        main=(("docs/configuration.md:1",), "complete", "withheld"),
        accepted="not a credential: a setting name or label in a template or configuration file",
    ),
    Row(
        "r1p.1-helm-values",
        "scan",
        {
            "charts/app/values.yaml": "adminPassword: useExistingSecretKey\nclientCredential: ManagedIdentityCredential\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                "charts/app/values.yaml:1",
                "charts/app/values.yaml:2",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: a setting name or label in a template or configuration file",
    ),
    Row(
        "r1p.1-spring-properties",
        "scan",
        {
            "src/main/resources/application.properties": "spring.datasource.password=springDatasourcePassword\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(("src/main/resources/application.properties:1",), "complete", "withheld"),
        accepted="not a credential: a setting name or label in a template or configuration file",
    ),
    Row(
        "r1p.1-compose-docker-password",
        "scan",
        {
            "docker-compose.yml": "services:\n  db:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: PostgresDockerPassword\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(("docker-compose.yml:5",), "complete", "withheld"),
        accepted="not a credential: a setting name or label in a template or configuration file",
    ),
    Row(
        "r1p.1-workflow-ci-password",
        "scan",
        {
            ".github/workflows/ci.yml": "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    services:\n      postgres:\n        image: postgres\n        env:\n          POSTGRES_PASSWORD: CiPostgresPassword\n    steps:\n      - run: make test\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=((".github/workflows/ci.yml:9",), "complete", "withheld"),
        accepted="not a credential: a setting name or label in a template or configuration file",
    ),
    Row(
        "r1p.1-env-example-eight-dev",
        "scan",
        {
            ".env.example": "SVC1_DB_PASSWORD=svc1_local_dev_password\nSVC2_DB_PASSWORD=svc2_local_dev_password\nSVC3_DB_PASSWORD=svc3_local_dev_password\nSVC4_DB_PASSWORD=svc4_local_dev_password\nSVC5_DB_PASSWORD=svc5_local_dev_password\nSVC6_DB_PASSWORD=svc6_local_dev_password\nSVC7_DB_PASSWORD=svc7_local_dev_password\nSVC8_DB_PASSWORD=svc8_local_dev_password\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                ".env.example:1",
                ".env.example:2",
                ".env.example:3",
                ".env.example:4",
                ".env.example:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: a setting name or label in a template or configuration file",
    ),
    Row(
        "r1p.1-real-env-eight-dev",
        "scan",
        {
            ".env": "SVC1_DB_PASSWORD=svc1_local_dev_password\nSVC2_DB_PASSWORD=svc2_local_dev_password\nSVC3_DB_PASSWORD=svc3_local_dev_password\nSVC4_DB_PASSWORD=svc4_local_dev_password\nSVC5_DB_PASSWORD=svc5_local_dev_password\nSVC6_DB_PASSWORD=svc6_local_dev_password\nSVC7_DB_PASSWORD=svc7_local_dev_password\nSVC8_DB_PASSWORD=svc8_local_dev_password\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                ".env:1",
                ".env:2",
                ".env:3",
                ".env:4",
                ".env:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: the value repeats its own name and label words",
    ),
    Row(
        "r1p.1-real-env-labels",
        "scan",
        {".env": "KEYCLOAK_ADMIN_PASSWORD=KeycloakAdminPassword\n"},
        mode="",
        head=((), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
        accepted="not a credential: the value repeats its own name and label words",
    ),
    Row(
        "r1p.1-text-change_me_to_a_strong_password",
        "match",
        "DB_PASSWORD=change_me_to_a_strong_password",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: a setting name or label outside an env file (#258's name rules)",
    ),
    Row(
        "r1p.1-env-change_me_to_a_strong_password",
        "match",
        "DB_PASSWORD=change_me_to_a_strong_password",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "r1p.1-text-a_very_long_random_string",
        "match",
        "DB_PASSWORD=a_very_long_random_string",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: a setting name or label outside an env file (#258's name rules)",
    ),
    Row(
        "r1p.1-env-a_very_long_random_string",
        "match",
        "DB_PASSWORD=a_very_long_random_string",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.1-text-admin_password_123",
        "match",
        "DB_PASSWORD=admin_password_123",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: a setting name or label outside an env file (#258's name rules)",
    ),
    Row(
        "r1p.1-env-admin_password_123",
        "match",
        "DB_PASSWORD=admin_password_123",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.1-text-password_for_local_db_1",
        "match",
        "DB_PASSWORD=password_for_local_db_1",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: a setting name or label outside an env file (#258's name rules)",
    ),
    Row(
        "r1p.1-env-password_for_local_db_1",
        "match",
        "DB_PASSWORD=password_for_local_db_1",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.1-text-postgres_password_2024",
        "match",
        "DB_PASSWORD=postgres_password_2024",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: a setting name or label outside an env file (#258's name rules)",
    ),
    Row(
        "r1p.1-env-postgres_password_2024",
        "match",
        "DB_PASSWORD=postgres_password_2024",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.1-text-the_quick_brown_fox_1",
        "match",
        "DB_PASSWORD=the_quick_brown_fox_1",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: a setting name or label outside an env file (#258's name rules)",
    ),
    Row(
        "r1p.1-env-the_quick_brown_fox_1",
        "match",
        "DB_PASSWORD=the_quick_brown_fox_1",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.1-text-AzureKeyVaultReference",
        "match",
        "DB_PASSWORD=AzureKeyVaultReference",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: a setting name or label outside an env file (#258's name rules)",
    ),
    Row(
        "r1p.1-env-AzureKeyVaultReference",
        "match",
        "DB_PASSWORD=AzureKeyVaultReference",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.1-text-DbPasswordFromSecretsManager",
        "match",
        "DB_PASSWORD=DbPasswordFromSecretsManager",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: a setting name or label outside an env file (#258's name rules)",
    ),
    Row(
        "r1p.1-env-DbPasswordFromSecretsManager",
        "match",
        "DB_PASSWORD=DbPasswordFromSecretsManager",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.1-text-managedIdentityCredential",
        "match",
        "DB_PASSWORD=managedIdentityCredential",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: a setting name or label outside an env file (#258's name rules)",
    ),
    Row(
        "r1p.1-env-managedIdentityCredential",
        "match",
        "DB_PASSWORD=managedIdentityCredential",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.2-kotlin-dotted-keys",
        "scan",
        {
            "app/src/main/java/com/acme/AuthKeys.kt": 'const val KEY_ACCESS_TOKEN = "net.openid.appauth.state"\nconst val KEYSTORE_PASSWORD = "android.injected.signing.store"\n'
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                "app/src/main/java/com/acme/AuthKeys.kt:1",
                "app/src/main/java/com/acme/AuthKeys.kt:2",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: a package, preference or i18n key in source code",
    ),
    Row(
        "r1p.2-i18n-dotted-keys",
        "scan",
        {
            "src/i18n/keys.ts": 'export const I18N_PASSWORD = "forms.login.field.hint";\nexport const msg_password = "validation.errors.too.short";\n'
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                "src/i18n/keys.ts:1",
                "src/i18n/keys.ts:2",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: a package, preference or i18n key in source code",
    ),
    Row(
        "r1p.2-pref-access-token",
        "match",
        'PREF_ACCESS_TOKEN = "com.acme.mobile.session"',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a package, preference or i18n key in source code",
    ),
    Row(
        "r1p.2-bundle-api-key",
        "match",
        'BUNDLE_API_KEY = "com.google.android.geo"',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a package, preference or i18n key in source code",
    ),
    Row(
        "r1p.3-snout-passed-thump-bloom-gravel-text",
        "match",
        "DB_PASSWORD=snout-passed-thump-bloom-gravel",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-passed-thump-bloom-gravel-code",
        "match",
        'db_password = "snout-passed-thump-bloom-gravel"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-passed-thump-bloom-gravel-env",
        "match",
        "DB_PASSWORD=snout-passed-thump-bloom-gravel",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-valued-snout-fiber-thump-text",
        "match",
        "DB_PASSWORD=valued-snout-fiber-thump",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-valued-snout-fiber-thump-code",
        "match",
        'db_password = "valued-snout-fiber-thump"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-valued-snout-fiber-thump-env",
        "match",
        "DB_PASSWORD=valued-snout-fiber-thump",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-glider-keyed-thump-bloom-text",
        "match",
        "DB_PASSWORD=glider-keyed-thump-bloom",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-glider-keyed-thump-bloom-code",
        "match",
        'db_password = "glider-keyed-thump-bloom"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-glider-keyed-thump-bloom-env",
        "match",
        "DB_PASSWORD=glider-keyed-thump-bloom",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-locals-thump-text",
        "match",
        "DB_PASSWORD=snout-fiber-locals-thump",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-locals-thump-code",
        "match",
        'db_password = "snout-fiber-locals-thump"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-locals-thump-env",
        "match",
        "DB_PASSWORD=snout-fiber-locals-thump",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-devs-thump-text",
        "match",
        "DB_PASSWORD=snout-fiber-devs-thump",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-devs-thump-code",
        "match",
        'db_password = "snout-fiber-devs-thump"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-devs-thump-env",
        "match",
        "DB_PASSWORD=snout-fiber-devs-thump",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-unsafe-gravel-thump-bloom-text",
        "match",
        "DB_PASSWORD=unsafe-gravel-thump-bloom",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-unsafe-gravel-thump-bloom-code",
        "match",
        'db_password = "unsafe-gravel-thump-bloom"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-unsafe-gravel-thump-bloom-env",
        "match",
        "DB_PASSWORD=unsafe-gravel-thump-bloom",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-default-thump-text",
        "match",
        "DB_PASSWORD=snout-fiber-default-thump",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-default-thump-code",
        "match",
        'db_password = "snout-fiber-default-thump"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-default-thump-env",
        "match",
        "DB_PASSWORD=snout-fiber-default-thump",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-lorem-snout-fiber-thump-text",
        "match",
        "DB_PASSWORD=lorem-snout-fiber-thump",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-lorem-snout-fiber-thump-code",
        "match",
        'db_password = "lorem-snout-fiber-thump"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-lorem-snout-fiber-thump-env",
        "match",
        "DB_PASSWORD=lorem-snout-fiber-thump",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-bazaars-thump-text",
        "match",
        "DB_PASSWORD=snout-fiber-bazaars-thump",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-bazaars-thump-code",
        "match",
        'db_password = "snout-fiber-bazaars-thump"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-snout-fiber-bazaars-thump-env",
        "match",
        "DB_PASSWORD=snout-fiber-bazaars-thump",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-basked-snout-fiber-thump-bloom-text",
        "match",
        "DB_PASSWORD=basked-snout-fiber-thump-bloom",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-basked-snout-fiber-thump-bloom-code",
        "match",
        'db_password = "basked-snout-fiber-thump-bloom"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-basked-snout-fiber-thump-bloom-env",
        "match",
        "DB_PASSWORD=basked-snout-fiber-thump-bloom",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-envied-snout-fiber-thump-text",
        "match",
        "DB_PASSWORD=envied-snout-fiber-thump",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-envied-snout-fiber-thump-code",
        "match",
        'db_password = "envied-snout-fiber-thump"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.3-envied-snout-fiber-thump-env",
        "match",
        "DB_PASSWORD=envied-snout-fiber-thump",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.4-ts-800-trim-chains",
        "scan",
        _numbered(
            "src/a.ts",
            "openaiApiKey = process.env.OPENAI_API_KEY?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim()?.trim();\n",
            800,
        ),
        mode="slow",
        head=((), "complete", "withheld"),
        main=(
            (
                "src/a.ts:1",
                "src/a.ts:2",
                "src/a.ts:3",
                "src/a.ts:4",
                "src/a.ts:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: environment reads with no key literal",
    ),
    Row(
        "r1p.4-ts-1500-get-chains",
        "scan",
        _numbered(
            "src/a.ts",
            'openaiApiKey = process.env.OPENAI_API_KEY.get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a").get("a");\n',
            1500,
        ),
        mode="slow",
        head=((), "complete", "withheld"),
        main=(
            (
                "src/a.ts:1",
                "src/a.ts:2",
                "src/a.ts:3",
                "src/a.ts:4",
                "src/a.ts:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: environment reads with no key literal",
    ),
    Row(
        "r1p.4-ts-12531-ors",
        "scan",
        _numbered(
            "src/a.ts",
            "const openaiApiKey = process.env.OPENAI_API_KEY || a || b || c || d || e || f;\n",
            12531,
        ),
        mode="slow",
        head=((), "complete", "withheld"),
        main=(
            (
                "src/a.ts:1",
                "src/a.ts:2",
                "src/a.ts:3",
                "src/a.ts:4",
                "src/a.ts:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: environment reads with no key literal",
    ),
    Row(
        "r1p.5-anonymous-public-access",
        "match",
        'const openaiApiKey = process.env.OPENAI_API_KEY || "anonymous-public-access";',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a mode, header name, URL path or model id as a fallback",
    ),
    Row(
        "r1p.5-disabled-in-this-build",
        "match",
        'const openaiApiKey = process.env.OPENAI_API_KEY ?? "disabled-in-this-build";',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a mode, header name, URL path or model id as a fallback",
    ),
    Row(
        "r1p.5-managed-identity-fallback",
        "match",
        'const azureClientSecret = process.env.AZURE_CLIENT_SECRET || "managed-identity-fallback";',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "r1p.5-header-name",
        "match",
        'this.serviceApiKey = config.serviceApiKey ?? "x-api-key-header-name";',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a mode, header name, URL path or model id as a fallback",
    ),
    Row(
        "r1p.5-url-path",
        "match",
        'const authApiKey = process.env.API_BASE + "/oauth2/v2.0/authorize";',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a mode, header name, URL path or model id as a fallback",
    ),
    Row(
        "r1p.5-model-id",
        "match",
        'self.openai_api_key = self.openai_api_key or "gpt-4o-mini-2024-07-18"',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a mode, header name, URL path or model id as a fallback",
    ),
    # --- review-cred255.json
    Row(
        "c255.1-secret-path",
        "match",
        'openaiApiKey: process.env.OPENAI_API_KEY ?? getSecret("projects/my-proj-123/secrets/openaiApiKey/versions/latest"),',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an environment read whose literal is a call argument or message",
    ),
    Row(
        "c255.1-config-key",
        "match",
        'openaiApiKey: process.env.OPENAI_API_KEY || config.get("openai.apiKey.v2"),',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an environment read whose literal is a call argument or message",
    ),
    Row(
        "c255.1-file-path",
        "match",
        'openaiApiKey: process.env.OPENAI_API_KEY ?? readFileSync("/run/secrets/OpenAI_Api_Key_2"),',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an environment read whose literal is a call argument or message",
    ),
    Row(
        "c255.1-action-input",
        "match",
        'githubAccessToken: process.env.GITHUB_ACCESS_TOKEN || core.getInput("github-access-token-v2"),',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an environment read whose literal is a call argument or message",
    ),
    Row(
        "c255.1-kotlin-error",
        "match",
        'val openaiApiKey = BuildConfig.OPENAI_API_KEY ?: error("OPENAI_API_KEY missing from local.properties")',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an environment read whose literal is a call argument or message",
    ),
    Row(
        "c255.1-python-raise",
        "match",
        'openai_api_key = settings.OPENAI_API_KEY or _raise("OPENAI_API_KEY is required for production")',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: an environment read whose literal is a call argument or message",
    ),
    Row(
        "c255.1-placeholder-fallback-sk-ant",
        "match",
        'anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? "sk-ant-api03-...",',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a documentation placeholder",
    ),
    Row(
        "c255.1-placeholder-fallback-your-api-key",
        "match",
        'anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? "your-api-key-here-Abc123XyZ",',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a documentation placeholder",
    ),
    Row(
        "c255.1-placeholder-fallback-placeholder",
        "match",
        'anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? "PLACEHOLDER-a1B2c3D4e5F6g7H8",',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a documentation placeholder",
    ),
    Row(
        "c255.1-placeholder-fallback-changeme",
        "match",
        'anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? "changeme-Abc123Def456Ghi789",',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a documentation placeholder",
    ),
    Row(
        "c255.1-placeholder-fallback-fake",
        "match",
        'anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? "fake_A1b2C3d4E5f6G7h8I9j0",',
        mode="code",
        head="unreported",
        main="reported",
        accepted="not a credential: a documentation placeholder",
    ),
    Row(
        "c255.1-placeholder-direct",
        "match",
        'anthropic_api_key: "sk-ant-api03-..."',
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: a documentation placeholder",
    ),
    Row(
        "c255.1-ts-fail-lines",
        "scan",
        {
            "src/config.ts": 'export const OPENAI_API_KEY = process.env.OPENAI_API_KEY ?? fail("OPENAI_API_KEY is not set");\nexport const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY ?? fail("ANTHROPIC_API_KEY is not set");\nexport const GROQ_API_KEY = process.env.GROQ_API_KEY ?? fail("GROQ_API_KEY is not set");\nexport const MISTRAL_API_KEY = process.env.MISTRAL_API_KEY ?? fail("MISTRAL_API_KEY is not set");\nexport const COHERE_API_KEY = process.env.COHERE_API_KEY ?? fail("COHERE_API_KEY is not set");\nexport const GEMINI_API_KEY = process.env.GEMINI_API_KEY ?? fail("GEMINI_API_KEY is not set");\nexport const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY ?? fail("DEEPSEEK_API_KEY is not set");\n'
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                "src/config.ts:1",
                "src/config.ts:2",
                "src/config.ts:3",
                "src/config.ts:4",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: an environment read whose literal is a call argument or message",
    ),
    Row(
        "c255.1-fixture-fail-lines",
        "scan",
        {
            "tests/fixtures/config.ts": 'export const OPENAI_API_KEY = process.env.OPENAI_API_KEY ?? fail("OPENAI_API_KEY is not set");\nexport const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY ?? fail("ANTHROPIC_API_KEY is not set");\nexport const GROQ_API_KEY = process.env.GROQ_API_KEY ?? fail("GROQ_API_KEY is not set");\nexport const MISTRAL_API_KEY = process.env.MISTRAL_API_KEY ?? fail("MISTRAL_API_KEY is not set");\nexport const COHERE_API_KEY = process.env.COHERE_API_KEY ?? fail("COHERE_API_KEY is not set");\nexport const GEMINI_API_KEY = process.env.GEMINI_API_KEY ?? fail("GEMINI_API_KEY is not set");\nexport const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY ?? fail("DEEPSEEK_API_KEY is not set");\n'
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                "tests/fixtures/config.ts:1",
                "tests/fixtures/config.ts:2",
                "tests/fixtures/config.ts:3",
                "tests/fixtures/config.ts:4",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: an environment read whose literal is a call argument or message",
    ),
    Row(
        "c255.1-kotlin-error-lines",
        "scan",
        {
            "src/Config.kt": 'val openaiApiKey = BuildConfig.OPENAI_API_KEY ?: error("OPENAI_API_KEY missing from local.properties")\nval anthropicApiKey = BuildConfig.ANTHROPIC_API_KEY ?: error("ANTHROPIC_API_KEY missing from local.properties")\nval groqApiKey = BuildConfig.GROQ_API_KEY ?: error("GROQ_API_KEY missing from local.properties")\nval mistralApiKey = BuildConfig.MISTRAL_API_KEY ?: error("MISTRAL_API_KEY missing from local.properties")\nval cohereApiKey = BuildConfig.COHERE_API_KEY ?: error("COHERE_API_KEY missing from local.properties")\nval geminiApiKey = BuildConfig.GEMINI_API_KEY ?: error("GEMINI_API_KEY missing from local.properties")\nval deepseekApiKey = BuildConfig.DEEPSEEK_API_KEY ?: error("DEEPSEEK_API_KEY missing from local.properties")\n'
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                "src/Config.kt:1",
                "src/Config.kt:2",
                "src/Config.kt:3",
                "src/Config.kt:4",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: an environment read whose literal is a call argument or message",
    ),
    Row(
        "c255.2-cs-getenv",
        "match",
        'var openaiApiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY") ?? "<R>";',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.2-cs-azure-getenv",
        "match",
        'string azureOpenAiApiKey = Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY") ?? "<R>";',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.2-js-optional-trim",
        "match",
        'const openaiApiKey = process.env.OPENAI_API_KEY?.trim() || "<R>";',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.2-js-non-null-trim",
        "match",
        'openaiApiKey = process.env.OPENAI_API_KEY!.trim() || "<R>";',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.2-js-getter-call",
        "match",
        'const openaiApiKey = configService.getOpenAiApiKey() ?? "<R>";',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.2-js-trailing-operator",
        "match",
        'const openaiApiKey = process.env.OPENAI_API_KEY ||\n  "<R>";',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.2-js-leading-operator",
        "match",
        'const openaiApiKey = process.env.OPENAI_API_KEY\n  || "<R>";',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.2-py-backslash",
        "match",
        'openai_api_key = settings.OPENAI_API_KEY or \\\n    "<R>"',
        mode="code",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.2-scan-cs",
        "scan",
        {"src/a.cs": 'var openaiApiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY") ?? "<R>";\n'},
        mode="",
        head=(("src/a.cs:1",), "complete", "withheld"),
        main=(("src/a.cs:1",), "complete", "withheld"),
    ),
    Row(
        "c255.2-scan-js",
        "scan",
        {"src/a.js": 'const openaiApiKey = process.env.OPENAI_API_KEY ||\n  "<R>";\n'},
        mode="",
        head=(("src/a.js:1",), "complete", "withheld"),
        main=(("src/a.js:1",), "complete", "withheld"),
    ),
    Row(
        "c255.3-local-development-only",
        "match",
        "DB_PASSWORD=local-development-only",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.3-insecure-default-for-dev",
        "match",
        "DB_PASSWORD=insecure-default-for-dev",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.3-unsafe-dev-only-default",
        "match",
        "DB_PASSWORD=unsafe-dev-only-default",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.3-development-only-insecure",
        "match",
        "DB_PASSWORD=development-only-insecure",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.3-for-local-dev-use-only",
        "match",
        "DB_PASSWORD=for-local-dev-use-only",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.3-this-should-be-changed",
        "match",
        "DB_PASSWORD=this-should-be-changed",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.3-dont-use-this-in-prod",
        "match",
        "DB_PASSWORD=dont-use-this-in-prod",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.3-foo-bar-baz-qux-quux",
        "match",
        "DB_PASSWORD=foo-bar-baz-qux-quux",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.3-lorem-ipsum-dolor-sit-amet",
        "match",
        "DB_PASSWORD=lorem-ipsum-dolor-sit-amet",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.3-hello-world-foo-bar",
        "match",
        "DB_PASSWORD=hello-world-foo-bar",
        mode="text",
        head="unreported",
        main="reported",
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.3-snout.fiber.thump.bloom.gravel-text",
        "match",
        "DB_PASSWORD=snout.fiber.thump.bloom.gravel",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.3-snout.fiber.thump.bloom.gravel-env",
        "match",
        "DB_PASSWORD=snout.fiber.thump.bloom.gravel",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.3-SNOUT-FIBER-THUMP-BLOOM-GRAVEL-text",
        "match",
        "DB_PASSWORD=SNOUT-FIBER-THUMP-BLOOM-GRAVEL",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.3-SNOUT-FIBER-THUMP-BLOOM-GRAVEL-env",
        "match",
        "DB_PASSWORD=SNOUT-FIBER-THUMP-BLOOM-GRAVEL",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.3-db-fiber-thump-bloom-gravel-text",
        "match",
        "DB_PASSWORD=db-fiber-thump-bloom-gravel",
        mode="text",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.3-db-fiber-thump-bloom-gravel-env",
        "match",
        "DB_PASSWORD=db-fiber-thump-bloom-gravel",
        mode="env",
        head="reported",
        main="reported",
    ),
    Row(
        "c255.3-fixture-env-labels",
        "scan",
        {
            "tests/fixtures/.env.test": "USER1_PASSWORD=local-development-only\nUSER2_PASSWORD=insecure-default-for-dev\nUSER3_PASSWORD=unsafe-dev-only-default\nUSER4_PASSWORD=development-only-insecure\nUSER5_PASSWORD=for-local-dev-use-only\nUSER6_PASSWORD=this-should-be-changed\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                "tests/fixtures/.env.test:1",
                "tests/fixtures/.env.test:2",
                "tests/fixtures/.env.test:3",
                "tests/fixtures/.env.test:4",
                "tests/fixtures/.env.test:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: an instruction or development label",
    ),
    Row(
        "c255.4-getenv-letters-name",
        "sanitize",
        'secret = os.getenv("<B32N>")',
        mode="",
        head="withheld",
        main="withheld",
    ),
    Row(
        "c255.4-process-env-letters-name",
        "sanitize",
        "password: process.env.<B32L>",
        mode="",
        head="withheld",
        main="withheld",
    ),
    Row(
        "c255.4-env-subscript-name",
        "sanitize",
        'token = ENV["<B32M>"]',
        mode="",
        head="withheld",
        main="withheld",
    ),
    Row(
        "c255.5-comma-comment",
        "sanitize",
        "  apiKey: process.env.AZURE_OPENAI_API_KEY, // old: <K>",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "c255.5-semicolon-comment",
        "sanitize",
        "apiKey = process.env.OPENAI_API_KEY; // <K>",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "c255.5-spaced-comma-comment",
        "sanitize",
        "apiKey: import.meta.env.VITE_OPENAI_API_KEY , // <K>",
        mode="",
        head="withheld",
        main="shown",
    ),
    # --- review-x-credentials.json
    Row(
        "xc.0-eight-openai-keys",
        "scan",
        {
            "keys.py": 'OPENAI_KEY_1 = "<OAI1>"\nOPENAI_KEY_2 = "<OAI2>"\nOPENAI_KEY_3 = "<OAI3>"\nOPENAI_KEY_4 = "<OAI4>"\nOPENAI_KEY_5 = "<OAI5>"\nOPENAI_KEY_6 = "<OAI6>"\nOPENAI_KEY_7 = "<OAI7>"\nOPENAI_KEY_8 = "<OAI8>"\n'
        },
        mode="",
        head=(
            (
                "keys.py:1",
                "keys.py:2",
                "keys.py:3",
                "keys.py:4",
                "keys.py:5",
            ),
            "incomplete",
            "withheld",
        ),
        main=(
            (
                "keys.py:1",
                "keys.py:2",
                "keys.py:3",
                "keys.py:4",
                "keys.py:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="disclosed: more than five distinct keys of one format (#257)",
    ),
    Row(
        "xc.0-eight-openai-keys-http-path",
        "scan",
        {
            "src/http_client/keys.py": 'OPENAI_KEY_1 = "<OAI1>"\nOPENAI_KEY_2 = "<OAI2>"\nOPENAI_KEY_3 = "<OAI3>"\nOPENAI_KEY_4 = "<OAI4>"\nOPENAI_KEY_5 = "<OAI5>"\nOPENAI_KEY_6 = "<OAI6>"\nOPENAI_KEY_7 = "<OAI7>"\nOPENAI_KEY_8 = "<OAI8>"\n'
        },
        mode="",
        head=(
            (
                "src/http_client/keys.py:1",
                "src/http_client/keys.py:2",
                "src/http_client/keys.py:3",
                "src/http_client/keys.py:4",
                "src/http_client/keys.py:5",
            ),
            "incomplete",
            "withheld",
        ),
        main=(
            (
                "src/http_client/keys.py:1",
                "src/http_client/keys.py:2",
                "src/http_client/keys.py:3",
                "src/http_client/keys.py:4",
                "src/http_client/keys.py:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="disclosed: more than five distinct keys of one format (#257)",
    ),
    Row(
        "xc.0-seven-hex-keys",
        "scan",
        {
            "config/app.env": "SERVICE1_API_KEY=<HEX1>\nSERVICE2_API_KEY=<HEX2>\nSERVICE3_API_KEY=<HEX3>\nSERVICE4_API_KEY=<HEX4>\nSERVICE5_API_KEY=<HEX5>\nSERVICE6_API_KEY=<HEX6>\nSERVICE7_API_KEY=<HEX7>\n"
        },
        mode="",
        head=(
            (
                "config/app.env:1",
                "config/app.env:2",
                "config/app.env:3",
                "config/app.env:4",
                "config/app.env:5",
            ),
            "incomplete",
            "withheld",
        ),
        main=(
            (
                "config/app.env:1",
                "config/app.env:2",
                "config/app.env:3",
                "config/app.env:4",
                "config/app.env:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="disclosed: more than five distinct keys of one format (#257)",
    ),
    Row(
        "xc.0-placeholders-then-real-key",
        "scan",
        {
            ".env.example": "SERVICE1_API_KEY=sk-your-key-here-1a2b\nSERVICE2_API_KEY=sk-your-key-here-1a2b\nSERVICE3_API_KEY=sk-your-key-here-1a2b\nSERVICE4_API_KEY=sk-your-key-here-1a2b\nSERVICE5_API_KEY=sk-your-key-here-1a2b\nSERVICE6_API_KEY=sk-your-key-here-1a2b\nSERVICE7_API_KEY=sk-your-key-here-1a2b\nSERVICE8_API_KEY=sk-your-key-here-1a2b\nREAL_API_KEY=<R>\n"
        },
        mode="",
        head=((".env.example:9",), "complete", "withheld"),
        main=((), "complete", "withheld"),
    ),
    Row(
        "xc.1-thirty-references-then-key",
        "scan",
        {
            "settings.py": 'self.service0_api_key = service0_api_key\nself.service1_api_key = service1_api_key\nself.service2_api_key = service2_api_key\nself.service3_api_key = service3_api_key\nself.service4_api_key = service4_api_key\nself.service5_api_key = service5_api_key\nself.service6_api_key = service6_api_key\nself.service7_api_key = service7_api_key\nself.service8_api_key = service8_api_key\nself.service9_api_key = service9_api_key\nself.service10_api_key = service10_api_key\nself.service11_api_key = service11_api_key\nself.service12_api_key = service12_api_key\nself.service13_api_key = service13_api_key\nself.service14_api_key = service14_api_key\nself.service15_api_key = service15_api_key\nself.service16_api_key = service16_api_key\nself.service17_api_key = service17_api_key\nself.service18_api_key = service18_api_key\nself.service19_api_key = service19_api_key\nself.service20_api_key = service20_api_key\nself.service21_api_key = service21_api_key\nself.service22_api_key = service22_api_key\nself.service23_api_key = service23_api_key\nself.service24_api_key = service24_api_key\nself.service25_api_key = service25_api_key\nself.service26_api_key = service26_api_key\nself.service27_api_key = service27_api_key\nself.service28_api_key = service28_api_key\nself.service29_api_key = service29_api_key\nBACKUP_API_KEY = "<R>"\n'
        },
        mode="",
        head=(("settings.py:31",), "complete", "withheld"),
        main=(
            (
                "settings.py:1",
                "settings.py:2",
                "settings.py:3",
                "settings.py:4",
                "settings.py:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: references to credentials, not literals",
    ),
    Row(
        "xc.2-five-references-then-key",
        "scan",
        {
            "settings.py": 'self.service0_api_key = service0_api_key\nself.service1_api_key = service1_api_key\nself.service2_api_key = service2_api_key\nself.service3_api_key = service3_api_key\nself.service4_api_key = service4_api_key\nBACKUP_API_KEY = "<R>"\n'
        },
        mode="",
        head=(("settings.py:6",), "complete", "withheld"),
        main=(
            (
                "settings.py:1",
                "settings.py:2",
                "settings.py:3",
                "settings.py:4",
                "settings.py:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: references to credentials, not literals",
    ),
    Row(
        "xc.3-akia-in-source",
        "scan",
        {"src/aws.py": 'AWS_ACCESS_KEY_ID = "<AKIA>"\n'},
        mode="",
        head=(("src/aws.py:1",), "complete", "withheld"),
        main=(("src/aws.py:1",), "complete", "withheld"),
    ),
    Row(
        "xc.6-boto-digit-free-akia",
        "scan",
        {".boto": "[Credentials]\naws_access_key_id = <AKIAL>\n"},
        mode="",
        head=((".boto:2",), "complete", "withheld"),
        main=((), "complete", "withheld"),
    ),
    Row(
        "xc.6-s3cfg-digit-free-akia",
        "scan",
        {".s3cfg": "[default]\naccess_key = <AKIAL>\n"},
        mode="",
        head=((".s3cfg:2",), "complete", "withheld"),
        main=((), "complete", "withheld"),
    ),
    Row(
        "xc.6-git-credentials-ghp",
        "scan",
        {".git-credentials": "https://user:<GHP>@github.com\n"},
        mode="",
        head=((".git-credentials:1",), "complete", "withheld"),
        main=((), "complete", "withheld"),
    ),
    Row(
        "xc.6-netrc-ghp",
        "scan",
        {".netrc": "machine github.com login user password <GHP>\n"},
        mode="",
        head=((".netrc:1",), "complete", "withheld"),
        main=((), "complete", "withheld"),
    ),
    Row(
        "xc.6-npmrc-ghp",
        "scan",
        {".npmrc": "//npm.pkg.github.com/:_authToken=<GHP>\n"},
        mode="",
        head=((".npmrc:1",), "complete", "withheld"),
        main=((), "complete", "withheld"),
    ),
    Row(
        "xc.5-env-example-six-placeholders",
        "scan",
        {
            ".env.example": "SERVICE1_API_KEY=your_service1_api_key_here\nSERVICE2_API_KEY=your_service2_api_key_here\nSERVICE3_API_KEY=your_service3_api_key_here\nSERVICE4_API_KEY=your_service4_api_key_here\nSERVICE5_API_KEY=your_service5_api_key_here\nSERVICE6_API_KEY=your_service6_api_key_here\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=((), "complete", "withheld"),
    ),
    Row(
        "xc.5-six-rejected-references",
        "scan",
        {
            "settings.py": "self.service0_api_key = service0_api_key\nself.service1_api_key = service1_api_key\nself.service2_api_key = service2_api_key\nself.service3_api_key = service3_api_key\nself.service4_api_key = service4_api_key\nself.service5_api_key = service5_api_key\n"
        },
        mode="",
        head=((), "complete", "withheld"),
        main=(
            (
                "settings.py:1",
                "settings.py:2",
                "settings.py:3",
                "settings.py:4",
                "settings.py:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="not a credential: references to credentials, not literals",
    ),
    # --- review-misc.json (possessive placeholders)
    Row(
        "misc.1-saas-je-suis-le-patron",
        "saas",
        "je-suis-le-patron",
        mode="",
        head="withheld",
        main="withheld",
    ),
    Row("misc.1-saas-tu-es-ma-cherie", "saas", "tu-es-ma-cherie", mode="", head="withheld", main="withheld"),
    Row(
        "misc.1-saas-ta_mere_en_short", "saas", "ta_mere_en_short", mode="", head="withheld", main="withheld"
    ),
    Row(
        "misc.1-saas-su-casa-es-mi-casa",
        "saas",
        "su-casa-es-mi-casa",
        mode="",
        head="withheld",
        main="withheld",
    ),
    Row(
        "misc.1-saas-ton-chat-noir-dort",
        "saas",
        "ton-chat-noir-dort",
        mode="",
        head="withheld",
        main="withheld",
    ),
    Row(
        "misc.1-saas-your-secret-garden",
        "saas",
        "your-secret-garden",
        mode="",
        head="withheld",
        main="withheld",
    ),
    Row("misc.1-saas-ta-<MIX>", "saas", "ta-<MIX>", mode="", head="withheld", main="withheld"),
    Row("misc.1-saas-Su<MIX>", "saas", "Su<MIX>", mode="", head="withheld", main="withheld"),
    Row(
        "misc.2-placeholder-sua_chave_openai",
        "placeholder",
        "sua_chave_openai",
        mode="",
        head="placeholder",
        main="credential",
        accepted="not a credential: a translated or possessive placeholder",
    ),
    Row(
        "misc.2-placeholder-votre-cle-api",
        "placeholder",
        "votre-cle-api",
        mode="",
        head="placeholder",
        main="credential",
        accepted="not a credential: a translated or possessive placeholder",
    ),
    Row(
        "misc.2-placeholder-your_api_key",
        "placeholder",
        "your_api_key",
        mode="",
        head="placeholder",
        main="placeholder",
    ),
    Row(
        "misc.2-placeholder-SUA_CHAVE_AQUI",
        "placeholder",
        "SUA_CHAVE_AQUI",
        mode="",
        head="placeholder",
        main="credential",
        accepted="not a credential: a translated or possessive placeholder",
    ),
    Row(
        "misc.2-placeholder-tu_clave",
        "placeholder",
        "tu_clave",
        mode="",
        head="placeholder",
        main="credential",
        accepted="not a credential: a translated or possessive placeholder",
    ),
    Row(
        "misc.2-placeholder-SuaChaveAqui",
        "placeholder",
        "SuaChaveAqui",
        mode="",
        head="credential",
        main="credential",
    ),
    Row(
        "misc.2-placeholder-InsiraSuaChave",
        "placeholder",
        "InsiraSuaChave",
        mode="",
        head="credential",
        main="credential",
    ),
    Row(
        "misc.2-placeholder-deinApiSchluessel",
        "placeholder",
        "deinApiSchluessel",
        mode="",
        head="credential",
        main="credential",
    ),
    Row(
        "misc.2-placeholder-ChaveDeApi123",
        "placeholder",
        "ChaveDeApi123",
        mode="",
        head="credential",
        main="credential",
    ),
    Row(
        "misc.2-placeholder-chave123",
        "placeholder",
        "chave123",
        mode="",
        head="credential",
        main="credential",
    ),
    Row(
        "misc.2-placeholder-senha123",
        "placeholder",
        "senha123",
        mode="",
        head="credential",
        main="credential",
    ),
    Row(
        "misc.2-placeholder-minhasenha",
        "placeholder",
        "minhasenha",
        mode="",
        head="credential",
        main="credential",
    ),
    Row(
        "misc.2-placeholder-sua",
        "placeholder",
        "sua",
        mode="",
        head="placeholder",
        main="credential",
        accepted="not a credential: a translated or possessive placeholder",
    ),
    Row(
        "misc.2-placeholder-seu_token_",
        "placeholder",
        "seu_token_",
        mode="",
        head="placeholder",
        main="credential",
        accepted="not a credential: a translated or possessive placeholder",
    ),
    Row("misc.2-placeholder-su-", "placeholder", "su-", mode="", head="credential", main="credential"),
    Row("misc.2-placeholder-your", "placeholder", "your", mode="", head="placeholder", main="placeholder"),
    Row(
        "misc.2-placeholder-je-suis-le-patron",
        "placeholder",
        "je-suis-le-patron",
        mode="",
        head="credential",
        main="credential",
    ),
    Row(
        "misc.2-placeholder-ta-<MIX>",
        "placeholder",
        "ta-<MIX>",
        mode="",
        head="credential",
        main="credential",
    ),
    Row(
        "misc.2-env-case-joined",
        "scan",
        {"src/app/.env": "OPENAI_API_KEY=SuaChaveDaOpenAI\n"},
        mode="",
        head=(("src/app/.env:1",), "complete", "withheld"),
        main=(("src/app/.env:1",), "complete", "withheld"),
    ),
    Row(
        "misc.2-env-separated",
        "scan",
        {"src/app/.env": "OPENAI_API_KEY=sua_chave_openai\n"},
        mode="",
        head=((), "complete", "withheld"),
        main=(("src/app/.env:1",), "complete", "withheld"),
        accepted="not a credential: #258's translated placeholder",
    ),
    Row(
        "misc.2-env-upper",
        "scan",
        {"src/app/.env": "OPENAI_API_KEY=SUA_CHAVE_AQUI\n"},
        mode="",
        head=((), "complete", "withheld"),
        main=((), "complete", "withheld"),
    ),
    # --- the fixes' own cases: dotenv forms and distinct keys
    Row(
        "fix.2-dotenv-export-blanks",
        "scan",
        {".env": "export POSTGRES_PASSWORD = <=TrustNoOneEverAgain>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "fix.2-dotenv-quoted-blanks",
        "scan",
        {".env": 'POSTGRES_PASSWORD = "<=TrustNoOneEverAgain>"\n'},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "fix.2-dotenv-tab-blanks",
        "scan",
        {".env": "POSTGRES_PASSWORD\t=\t<=TrustNoOneEverAgain>\n"},
        mode="",
        head=((".env:1",), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
    ),
    Row(
        "fix.2-dotenv-blanks-label",
        "scan",
        {".env": "KEYCLOAK_ADMIN_PASSWORD = KeycloakAdminPassword\n"},
        mode="",
        head=((), "complete", "withheld"),
        main=((".env:1",), "complete", "withheld"),
        accepted="not a credential: the value repeats its own name (a label)",
    ),
    Row(
        "fix.5-py-six-distinct",
        "scan",
        {
            "src/a.py": 'SVC1_OPENAI_API_KEY = "<K1>"\nSVC2_OPENAI_API_KEY = "<K2>"\nSVC3_OPENAI_API_KEY = "<K3>"\nSVC4_OPENAI_API_KEY = "<K4>"\nSVC5_OPENAI_API_KEY = "<K5>"\nSVC6_OPENAI_API_KEY = "<K6>"\n'
        },
        mode="",
        head=(
            (
                "src/a.py:1",
                "src/a.py:2",
                "src/a.py:3",
                "src/a.py:4",
                "src/a.py:5",
            ),
            "incomplete",
            "withheld",
        ),
        main=(
            (
                "src/a.py:1",
                "src/a.py:2",
                "src/a.py:3",
                "src/a.py:4",
                "src/a.py:5",
            ),
            "complete",
            "withheld",
        ),
        accepted="disclosed: six distinct keys, more than the quota of five (#257)",
    ),
    Row(
        "fix.5-py-five-distinct-repeated",
        "scan",
        {
            "src/a.py": 'SVC1_OPENAI_API_KEY = "<K1>"\nSVC1_BACKUP_API_KEY = "<K1>"\nSVC2_OPENAI_API_KEY = "<K2>"\nSVC2_BACKUP_API_KEY = "<K2>"\nSVC3_OPENAI_API_KEY = "<K3>"\nSVC3_BACKUP_API_KEY = "<K3>"\nSVC4_OPENAI_API_KEY = "<K4>"\nSVC4_BACKUP_API_KEY = "<K4>"\nSVC5_OPENAI_API_KEY = "<K5>"\nSVC5_BACKUP_API_KEY = "<K5>"\n'
        },
        mode="",
        head=(
            (
                "src/a.py:1",
                "src/a.py:10",
                "src/a.py:2",
                "src/a.py:3",
                "src/a.py:4",
                "src/a.py:5",
                "src/a.py:6",
                "src/a.py:7",
                "src/a.py:8",
                "src/a.py:9",
            ),
            "complete",
            "withheld",
        ),
        main=(
            (
                "src/a.py:1",
                "src/a.py:2",
                "src/a.py:3",
                "src/a.py:4",
                "src/a.py:5",
            ),
            "complete",
            "withheld",
        ),
    ),
    # --- r4-review-creds4.json (round 4): a password entry after another credential's name
    Row(
        "r4.1-password-after-api-key-entry",
        "sanitize",
        "const cfg = { apiKey: process.env.API_KEY, password: process.env.DB_PASSWORD?.trim() || '<P>' };",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.1-db-password-after-token-entry",
        "sanitize",
        "const cfg = { token: process.env.T, dbPassword: process.env.DB_PASSWORD?.trim() || '<P>' };",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.1-password-after-secret-entry",
        "sanitize",
        "const cfg = { secret: env.SECRET, password: process.env.DB_PASSWORD?.trim() || '<P>' };",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.1-password-after-api-key-argument",
        "sanitize",
        "connect({ apiKey: k, password: process.env.DB_PASSWORD?.trim() || '<P>' })",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.1-password-after-credential-callee",
        "sanitize",
        "client.setApiKey(k); const pw = { password: process.env.DB_PASSWORD?.trim() || '<P>' }",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.1-passphrase-after-api-key-entry",
        "sanitize",
        "const cfg = { apiKey: process.env.API_KEY, "
        "password: process.env.DB_PASSWORD?.trim() || '<=correct horse battery staple>' };",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.1-password-keyword-fallback",
        "sanitize",
        "'PASSWORD': cfg.get('db', 'password', fallback='<PW2>'),",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.1-password-default-value-argument",
        "sanitize",
        "password: env('DB_PASSWORD', default_value='<P>')",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.1-passphrase-keyword-fallback",
        "sanitize",
        "'PASSWORD': get_secret('db', fallback='<=correct horse battery staple>')",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.1-passphrase-fallback-object",
        "sanitize",
        "{ anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? '<K>', "
        "password: cfg.get('db','password', { fallback: '<=correct horse battery staple>' }) }",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.1-report-excerpts",
        "scan",
        {
            "src/a.ts": "export const cfg = { apiKey: \"<OAI1>\", password: process.env.DB_PASSWORD?.trim() || '<P>' };\n"
            "export const c3 = { anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? '<K>', "
            "password: cfg.get('db','password', { fallback: '<=correct horse battery staple>' }) };\n",
            "app/s.py": "CONF = {'OPENAI_API_KEY': '<OAI2>', 'PASSWORD': cfg.get('db', 'password', fallback='<PW2>-Prod')}\n",
        },
        mode="",
        head=(("app/s.py:1", "src/a.ts:1", "src/a.ts:2"), "complete", "withheld"),
        main=(("app/s.py:1", "src/a.ts:1", "src/a.ts:2"), "complete", "shown"),
    ),
    # --- r4-review-creds4.json: a password that starts like a token (its tail is a secret too)
    Row(
        "r4.2-token-start-optional-chain",
        "sanitize",
        'dbPassword: process.env.DB_PASSWORD?.trim() || "<KS>&<=mypass>",',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.2-token-start-ternary",
        "sanitize",
        "db_password: os.environ[ 'DB_PASSWORD' ] if PROD else '<KS>&<=mypass>'",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.2-token-start-default-argument",
        "sanitize",
        'db_password: os.getenv("<K>", "<KS>&<=mypass>")',
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.2-token-start-joi-default",
        "sanitize",
        "password: Joi.string().default('<KS>&<=3xyz>')",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.2-token-start-zod-default",
        "sanitize",
        "password: z.string().default('<KS>&<=mypass>'),",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.2-report-excerpt",
        "scan",
        {
            "src/a.ts": 'export const c1 = { openaiApiKey: "<OAI3>" };\n'
            'export const c2 = { openaiApiKey: "<OAI4>", dbPassword: process.env.P?.trim() || "<KS>&<=mypass>" };\n'
        },
        mode="",
        head=(("src/a.ts:1", "src/a.ts:2"), "complete", "withheld"),
        main=(("src/a.ts:1", "src/a.ts:2"), "complete", "shown"),
    ),
    # --- r4-review-creds4.json: sentence passphrases that two function words made labels
    *[
        Row(
            f"r4.3-{place}-{sentence}",
            "match",
            template.format(v=sentence, u=sentence.replace("-", "_")),
            mode=mode,
            head="reported",
            main="reported",
        )
        for sentence in R4_SENTENCES
        for place, template, mode in R4_SENTENCE_PLACES
    ],
    Row(
        "r4.3-scan-three-places",
        "scan",
        {
            ".env": "DB_PASSWORD=<=my-dog-is-named-rex>\n",
            "docker-compose.yml": "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: <=fly-me-to-the-moon>\n",
            "app/settings.py": 'REDIS_PASSWORD = "<=may_the_force_be_with_you>"\n',
        },
        mode="",
        head=((".env:1", "app/settings.py:1", "docker-compose.yml:4"), "complete", "withheld"),
        main=((".env:1", "app/settings.py:1", "docker-compose.yml:4"), "complete", "withheld"),
    ),
    # --- r4-review-creds4.json: possessive passphrases read as templates
    *[
        Row(f"r4.4-placeholder-{value}", "placeholder", value, mode="", head="credential", main="credential")
        for value in R4_POSSESSIVES
    ],
    *[
        Row(f"r4.4-saas-{value}", "saas", value, mode="", head="withheld", main="withheld")
        for value in R4_POSSESSIVES
    ],
    *[
        Row(
            f"r4.4-{mode}-{value}",
            "match",
            template.format(v=value),
            mode=mode,
            head="reported",
            main="reported",
        )
        for value in R4_POSSESSIVES
        if len(value) >= 16
        for mode, template in (("env", "DB_PASSWORD={v}"), ("code", 'DB_PASSWORD = "{v}"'))
    ],
    # --- r4-review-creds4.json: env-file passwords of the enlarged label vocabulary
    *[
        Row(
            f"r4.5-env-{value}", "match", f"DB_PASSWORD={value}", mode="env", head="reported", main="reported"
        )
        for value in R4_ENV_PASSWORDS
    ],
    Row(
        "r4.5-env-DevPasswordLocal",
        "match",
        "DB_PASSWORD=DevPasswordLocal",
        mode="env",
        head="unreported",
        main="reported",
        accepted="not a credential: every word is label vocabulary or the name's own (dev, password, local)",
    ),
    # --- r4-review-creds4.json: a hard-coded key as a settings read's default argument
    *[
        Row(
            f"r4.6-{label}",
            "scan",
            {rel: line},
            mode="",
            head=((f"{rel}:1",), "complete", "withheld"),
            main=((f"{rel}:1",), "complete", "withheld"),
        )
        for label, rel, line in R4_DEFAULT_READS
    ],
    # --- r4-review-creds4.json: a worded or punctuated password fallback after a read
    *[
        Row(
            f"r4.7-{form}-{label}",
            "scan",
            {rel: template.replace("{v}", value)},
            mode="",
            head=((f"{rel}:1",), "complete", "withheld"),
            main=((f"{rel}:1",), "complete", "withheld"),
        )
        for form, rel, template in R4_PASSWORD_FALLBACK_FORMS
        for label, value in R4_PASSWORD_FALLBACKS
    ],
    # --- r4-review-creds4.json: a repeated credential's locations
    Row(
        "r4.8-py-six-names-one-provider-key",
        "scan",
        _numbered("app/k.py", 'SVC{n}_OPENAI_API_KEY = "<OAI5>"\n', 6),
        mode="",
        head=(("app/k.py:1", "app/k.py:2", "app/k.py:3", "app/k.py:4", "app/k.py:5"), "complete", "withheld"),
        main=(("app/k.py:1", "app/k.py:2", "app/k.py:3", "app/k.py:4", "app/k.py:5"), "complete", "withheld"),
    ),
    Row(
        "r4.8-env-six-names-one-provider-key",
        "scan",
        _numbered(".env", "SVC{n}_OPENAI_API_KEY=<OAI6>\n", 6),
        mode="",
        head=((".env:1", ".env:2", ".env:3", ".env:4", ".env:5", ".env:6"), "complete", "withheld"),
        main=((".env:1", ".env:2", ".env:3", ".env:4", ".env:5", ".env:6"), "complete", "withheld"),
    ),
    Row(
        "r4.8-env-six-names-one-password",
        "scan",
        _numbered(".env", "SVC{n}_DB_PASSWORD=<K2>\n", 6),
        mode="",
        head=((".env:1", ".env:2", ".env:3", ".env:4", ".env:5"), "complete", "withheld"),
        main=((".env:1", ".env:2", ".env:3", ".env:4", ".env:5"), "complete", "withheld"),
    ),
    # --- r4-review-creds4.json: long names without separators read as pasted keys
    Row(
        "r4.9-seven-long-names",
        "scan",
        _numbered("src/config.ts", "export const svc{n}ApiKey = process.env.SVC{n}OPENAIAPIKEYPROD;\n", 7),
        mode="",
        head=(
            ("src/config.ts:1", "src/config.ts:2", "src/config.ts:3", "src/config.ts:4", "src/config.ts:5"),
            "complete",
            "withheld",
        ),
        main=(
            ("src/config.ts:1", "src/config.ts:2", "src/config.ts:3", "src/config.ts:4", "src/config.ts:5"),
            "complete",
            "withheld",
        ),
    ),
    # --- r4-review-netrc4.json: a keyword-named directory in a netrc comment's Windows path
    *[
        Row(f"r4n.1-{label}", "sanitize", text, mode="", head="withheld", main="shown")
        for label, text in (
            ("nas-user", "machine fs\n  login bob\n  # home share \\\\nas\\user\\fred\n\n  password <K>\n"),
            ("no-quote", "machine fs\n  login bob\n  # no quote C:\\user\\new\n\n  password <K>\n"),
            (
                "users-default",
                "machine fs\n  login bob\n  # Bob's home is C:\\Users\\bob\\default\\new\n\n  password <K>\n",
            ),
            (
                "comment-block",
                "machine fs\n  login bob\n  # home share \\\\nas\\user\\fred\n"
                + "  # x\n" * 8
                + "  password <K>\n",
            ),
            ("srv-account", "machine fs\n  login bob\n  # \\\\srv\\account\\new\n\n  password <K>\n"),
            ("x-machine", "machine fs\n  login bob\n  # C:\\x\\machine\\new\n\n  password <K>\n"),
            ("nas-login", "machine fs\n  login bob\n  # \\\\nas\\login\\tom\n\n  password <K>\n"),
        )
    ],
    # --- r4-review-creds4.json: a punctuated secret after a cut read, which round 5 reports
    Row(
        "r4.10-client-secret-entry",
        "sanitize",
        "clientSecret: process.env.CLIENT_SECRET?.trim() || '<P>',",
        mode="",
        head="withheld",
        main="shown",
    ),
    Row(
        "r4.10-report-excerpt",
        "scan",
        {
            "src/a.ts": "export const cfg = { azureClientSecret: process.env.AZURE_CLIENT_SECRET?.trim() || '<P>' };\n"
        },
        mode="",
        head=(("src/a.ts:1",), "complete", "withheld"),
        main=(("src/a.ts:1",), "complete", "shown"),
    ),
    Row(
        "r4.10-run-together-name",
        "scan",
        {"src/a.ts": "export const cfg = { dbpassword: process.env.DBPASSWORD?.trim() || '<P>' };\n"},
        mode="",
        head=(("src/a.ts:1",), "complete", "withheld"),
        main=(("src/a.ts:1",), "complete", "shown"),
    ),
]


def _worse(row: Row) -> bool:
    """Whether the head shows, misses or leaves incomplete what main withheld, reported or completed."""
    head, main = row.head, row.main
    if row.kind in {"sanitize", "saas"}:
        return head == "shown" and main == "withheld"
    if row.kind == "match":
        return head == "unreported" and main == "reported"
    if row.kind == "placeholder":
        return head == "placeholder" and main == "credential"
    assert isinstance(head, tuple) and isinstance(main, tuple)
    missed = set(main[0]) - set(head[0])
    return (
        bool(missed)
        or (head[1], main[1]) == ("incomplete", "complete")
        or (head[2], main[2]) == ("shown", "withheld")
    )


# The matching budget of the slow rows (CPU seconds per 256 KiB of a file, and four times that
# in elapsed time). The rows hold inputs of 1,500 to 12,531 lines whose outcome is the
# pipeline's answer on a scan that completes; the default budget of 2 s completes them on an
# idle machine but not under coverage tracing (the CI 3.11 leg) or a loaded runner, where a
# row then read 'incomplete' for the budget alone. What the budget does to a scan has its own
# tests (tests/unit/test_adaptive_timeout.py, tests/unit/test_performance_guards.py).
SLOW_ROW_SCAN_TIMEOUT = 60.0


def _scan_outcome(
    index: SignatureIndex, root: Path, files: dict[str, str], *, slow: bool = False
) -> tuple[object, ...]:
    from shadowscan.connectors import get_connector_class

    secrets: set[str] = set()
    for rel, content in files.items():
        text, found = _expand(content)
        secrets |= found
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())
    config: dict[str, object] = {"path": str(root), "use_git": False}
    if slow:
        config["scan_timeout"] = SLOW_ROW_SCAN_TIMEOUT
    ctx = ConnectorContext(config=config, index=index)
    findings = get_connector_class("code.filesystem")(ctx).run()
    report = json.dumps([f.to_dict() for f in findings], default=str)
    report += json.dumps(
        [str(e) for e in ctx.stats.errors] + [str(w) for w in getattr(ctx.stats, "warnings", [])]
    )
    locations = sorted(
        {e.location for f in findings if f.kind.value == "secret" for e in f.evidence if e.location}
    )
    return (
        tuple(locations),
        "incomplete" if ctx.stats.incomplete else "complete",
        "shown" if any(secret in report for secret in secrets) else "withheld",
    )


def _outcome(index: SignatureIndex, row: Row, root: Path) -> object:
    if row.kind == "scan":
        assert isinstance(row.given, dict)
        return _scan_outcome(index, root, row.given, slow=row.mode == "slow")
    assert isinstance(row.given, str)
    text, secrets = _expand(row.given)
    if row.kind == "sanitize":
        safe = sanitize_text(text)
        return "shown" if any(secret in safe for secret in secrets) else "withheld"
    if row.kind == "match":
        matches = index.match_secrets(
            text, code=row.mode == "code", env_file=row.mode == "env", placeholder=placeholder_reason
        )
        reported = any(placeholder_reason(reported_credential(m)) is None for m in matches)
        return "reported" if reported else "unreported"
    if row.kind == "placeholder":
        return "placeholder" if placeholder_reason(text) is not None else "credential"
    assert row.kind == "saas", row.kind
    connector = GenericSaaSConnector(ConnectorContext(index=index))
    record = {"id": "app-1", "name": "Claude", "scopes": text, "publisher": text, "api_key": text}
    report = json.dumps([f.to_dict() for f in connector.analyze([record])], default=str)
    return "shown" if text in report else "withheld"


def _params() -> list[object]:
    return [
        pytest.param(row, id=row.id, marks=[pytest.mark.slow] if row.mode == "slow" else []) for row in ROWS
    ]


@pytest.mark.parametrize("row", _params())
def test_the_head_gives_the_oracle_outcome(index: SignatureIndex, tmp_path: Path, row: Row):
    assert _outcome(index, row, tmp_path) == row.head


@pytest.mark.parametrize("row", _params())
def test_a_row_worse_than_main_names_why(row: Row):
    if _worse(row):
        assert row.accepted.startswith(ACCEPTED_KINDS) and len(row.accepted) > 30, row.accepted
    else:
        # An annotation on a row that is no worse than main is stale.
        assert row.accepted == ""


def test_no_row_shows_a_credential():
    # Not even where main did: the head withholds every credential of the table.
    shown = [row.id for row in ROWS if row.head == "shown" or (row.kind == "scan" and row.head[2] == "shown")]
    assert shown == []


def test_the_table_has_one_row_per_input():
    assert len({row.id for row in ROWS}) == len(ROWS)
    assert len({(row.kind, json.dumps(row.given, sort_keys=True), row.mode) for row in ROWS}) == len(ROWS)

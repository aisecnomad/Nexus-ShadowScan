"""The generic assigned-credential rule reports literals, not names of credentials.

Its value class admits '.' and '_', so an environment read, a member chain or a
variable passed through ('api_key = api_key') looked like a long, diverse key
and was reported as a hard-coded credential at high risk. Labels made of words
and documentation ellipses were reported the same way. A read of an
environment variable by name was also withheld from evidence, which hid what a
reviewer needs to see.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from pathlib import Path

import pytest

from shadowscan.connectors.common import placeholder_reason
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.redaction import REDACTED, sanitize_text

GENERIC = "heuristic.inline-credential"
RANDOM = "R4nd0m9Qx2Vb7Lp6"  # the same synthetic value the rule's own tests use


def _generic(index: SignatureIndex, text: str, *, code: bool, env_file: bool = False) -> list[str]:
    """The generic matches the scanner reports as credentials (not placeholders).

    A placeholder test judges the literal a match stands for, which for a
    reference is the fallback after it (``extra["credential"]``).
    """
    return [
        m.value
        for m in index.match_secrets(text, code=code, env_file=env_file)
        if m.signature_id == GENERIC and placeholder_reason(m.extra.get("credential", m.value)) is None
    ]


@pytest.mark.parametrize(
    "line",
    [
        "const anthropicApiKey = process.env.ANTHROPIC_API_KEY;",
        "self.serper_search_api_key = serper_search_api_key",
        'old_password = self.cleaned_data["old_password"]',
        "usable_password = SetUnusablePasswordMixin.create_usable_password_field()",
        'old_password = connection.settings_dict["PASSWORD"]',
        "requireCredential: options.requireCredential ?? false,",
        "api_key = settings.OPENAI_API_KEY",
    ],
)
def test_names_and_member_chains_in_source_code_are_not_credentials(index: SignatureIndex, line: str):
    assert _generic(index, line, code=True) == []


@pytest.mark.parametrize(
    "line",
    [
        # Code in documentation and in configuration strings: code follows the chain.
        "const FIRECRAWL_API_KEY = process.env.FIRECRAWL_API_KEY;",
        "user.password = hasher.encode_md5_hash(md5_hash, salt)",
        "(config) => ({ env: { FIRECRAWL_API_KEY: config.fireCrawlApiKey, URL: u } })",
        # An environment or instance root is a reference wherever it is written.
        "OPENAI_API_KEY=process.env.OPENAI_API_KEY",
    ],
)
def test_member_chains_that_code_follows_are_not_credentials_in_any_text(index: SignatureIndex, line: str):
    assert _generic(index, line, code=False) == []


@pytest.mark.parametrize(
    "line",
    [
        "const REQUEST_SCOPED_CREDENTIAL = 'request-scoped-credential';",
        "const resolvedApiKey = 'fc-resolved-api-key-value';",
        "FIRECRAWL_API_KEY: 'fc-shared-env-must-not-be-used',",
        # A slug that repeats a word of the name it is assigned to labels it.
        "const SESSION_PASSWORD = 'session-cookie-signing';",
    ],
)
def test_labels_made_of_words_are_not_credentials(index: SignatureIndex, line: str):
    assert _generic(index, line, code=True) == []


@pytest.mark.parametrize(
    ("line", "code"),
    [
        # Password managers generate passphrases as random words joined by '-' or '_'.
        ("DB_PASSWORD=snout-fiber-thump-bloom-gravel", False),
        ('ADMIN_PASSWORD = "unclad-dismount-uncork-unlit-quartz"', False),
        ('ADMIN_PASSWORD = "unclad-dismount-uncork-unlit-quartz"', True),
        ("SMTP_PASSWORD: Ostrich-Lantern-Volcano-Tangerine", False),
        ("VAULT_ACCESS_TOKEN=granite_meadow_falcon_ribbon", False),
    ],
)
def test_generated_passphrases_are_credentials(index: SignatureIndex, line: str, code: bool):
    assert _generic(index, line, code=code) != []


@pytest.mark.parametrize(
    "passphrase",
    [
        # An upper-case slug that is not CONSTANT_CASE, and a word as short as
        # the name's 'db'.
        "SNOUT-FIBER-THUMP-BLOOM-GRAVEL",
        "db-fiber-thump-bloom-gravel",
    ],
)
def test_passphrases_in_other_separators_and_cases_are_credentials(index: SignatureIndex, passphrase: str):
    assert _generic(index, f"DB_PASSWORD={passphrase}", code=False) != []
    assert _generic(index, f'DB_PASSWORD = "{passphrase}"', code=True) != []


@pytest.mark.parametrize(
    "passphrase",
    ["snout.fiber.thump.bloom.gravel", "Snout.Fiber.Thump.Bloom.Gravel", "SNOUT.FIBER.THUMP.BLOOM.GRAVEL"],
)
def test_a_dotted_passphrase_is_a_credential_in_an_env_file(index: SignatureIndex, passphrase: str):
    # A password manager's '.' separator: only a password in an env or
    # credential file can name nothing, so only there is it read as one.
    assert _generic(index, f"DB_PASSWORD={passphrase}", code=False, env_file=True) != []


@pytest.mark.parametrize(
    ("line", "code"),
    [
        # Android preference and extra keys, i18n message keys, package names
        # and namespaces under credential-named constants name something.
        ('const val KEY_ACCESS_TOKEN = "net.openid.appauth.state"', True),
        ('const val KEYSTORE_PASSWORD = "android.injected.signing.store"', True),
        ('export const I18N_PASSWORD = "forms.login.field.hint";', True),
        ('export const msg_password = "validation.errors.too.short";', True),
        ('PREF_ACCESS_TOKEN = "com.acme.mobile.session"', True),
        ('PREF_ACCESS_TOKEN = "com.acme.mobile.session"', False),
        ('BUNDLE_API_KEY = "com.google.android.geo"', True),
        ('BUNDLE_API_KEY = "com.google.android.geo"', False),
        ('const string CREDENTIAL_PROVIDER = "Microsoft.Identity.Client";', True),
    ],
)
def test_a_dotted_string_of_words_in_code_or_configuration_is_a_name(
    index: SignatureIndex, line: str, code: bool
):
    assert _generic(index, line, code=code) == []


def test_a_scan_reports_no_credential_for_dotted_keys(tmp_path: Path, run_connector):
    files = {
        "app/src/main/java/com/acme/AuthKeys.kt": (
            'const val KEY_ACCESS_TOKEN = "net.openid.appauth.state"\n'
            'const val KEYSTORE_PASSWORD = "android.injected.signing.store"\n'
        ),
        "src/i18n/keys.ts": (
            'export const I18N_PASSWORD = "forms.login.field.hint";\n'
            'export const msg_password = "validation.errors.too.short";\n'
        ),
    }
    findings = _scan(tmp_path, run_connector, files)
    assert [f.metadata["path"] for f in findings if f.kind.value == "secret"] == []


@pytest.mark.parametrize(
    "label",
    [
        "local-development-only",
        "insecure-default-for-dev",
        "unsafe-dev-only-default",
        "development-only-insecure",
        "for-local-dev-use-only",
        "this-should-be-changed",
        "dont-use-this-in-prod",
        "foo-bar-baz-qux-quux",
        "lorem-ipsum-dolor-sit-amet",
        "hello-world-foo-bar",
        # Plurals and past forms of the vocabulary.
        "defaults-were-replaced",
        "rotate-these-tokens",
    ],
)
def test_development_defaults_and_filler_are_labels(index: SignatureIndex, label: str):
    assert _generic(index, f"DB_PASSWORD={label}", code=False) == []
    assert _generic(index, f'DB_PASSWORD = "{label}"', code=True) == []


@pytest.mark.parametrize(
    "passphrase",
    [
        # One common word of the label vocabulary, or its plural or past
        # form, is also a word of a passphrase list: alone it labels nothing.
        "snout-passed-thump-bloom-gravel",
        "valued-snout-fiber-thump",
        "glider-keyed-thump-bloom",
        "snout-fiber-locals-thump",
        "snout-fiber-devs-thump",
        "unsafe-gravel-thump-bloom",
        "snout-fiber-default-thump",
        "lorem-snout-fiber-thump",
        # Words that only start like the vocabulary.
        "snout-fiber-bazaars-thump",
        "basked-snout-fiber-thump-bloom",
        "envied-snout-fiber-thump",
    ],
)
def test_a_passphrase_with_one_common_label_word_is_a_credential(index: SignatureIndex, passphrase: str):
    assert _generic(index, f"DB_PASSWORD={passphrase}", code=False) != []
    assert _generic(index, f'db_password = "{passphrase}"', code=True) != []


def test_a_fixture_env_file_of_development_defaults_stays_complete(tmp_path: Path, run_connector):
    labels = ["local-development-only", "insecure-default-for-dev", "this-should-be-changed"]
    labels += ["dont-use-this-in-prod", "foo-bar-baz-qux-quux", "lorem-ipsum-dolor-sit-amet"]
    env = "".join(f"USER{n}_PASSWORD={label}\n" for n, label in enumerate(labels))
    findings = _scan(tmp_path, run_connector, {"tests/fixtures/.env.test": env})
    assert [f.title for f in findings if f.kind.value == "secret"] == []


def test_a_documentation_ellipsis_is_a_placeholder(index: SignatureIndex):
    [match] = [
        m for m in index.match_secrets('anthropic_api_key: "sk-ant-api03-..."') if m.signature_id == GENERIC
    ]
    assert placeholder_reason(match.value) == "placeholder-word"


@pytest.mark.parametrize(
    ("line", "code"),
    [
        (f"CUSTOM_API_KEY={RANDOM}", False),
        (f"CUSTOM_API_KEY={RANDOM}", True),  # an unquoted random value in code (a comment) stays
        (f'CUSTOM_API_KEY = "{RANDOM}"', True),
        # In an env file an unquoted value is a literal, dotted or not.
        ("DB_PASSWORD=Summer.Vacation2024", False),
        ("SERVICE_API_KEY = 'XyZ9.QwErTy8.UiOp7AsDf6'", True),
    ],
)
def test_literal_credentials_are_still_reported(index: SignatureIndex, line: str, code: bool):
    assert _generic(index, line, code=code) != []


@pytest.mark.parametrize(
    "line",
    [
        # The match ends at the read; the hard-coded fallback after it is the key.
        f'const openaiApiKey = process.env.OPENAI_API_KEY || "{RANDOM}";',
        f'openaiApiKey: process.env.OPENAI_API_KEY ?? "{RANDOM}",',
        f"const githubAccessToken = process.env.PREFIX + '{RANDOM}';",
        f"openaiApiKey: process.env.OPENAI_API_KEY ?? process.env.AZURE_KEY_FALLBACK ?? '{RANDOM}',",
        f"openaiApiKey: process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY : '{RANDOM}',",
        f"openai_api_key = os.environ.OPENAI_API_KEY or '{RANDOM}'",
    ],
)
@pytest.mark.parametrize("code", [True, False])
def test_a_hard_coded_fallback_after_a_reference_is_reported(index: SignatureIndex, line: str, code: bool):
    assert _generic(index, line, code=code) != []


@pytest.mark.parametrize(
    "line",
    [
        "const anthropicApiKey = process.env.ANTHROPIC_API_KEY;",
        "const anthropicApiKey = process.env.ANTHROPIC_API_KEY",
        "self.api_key = api_key",
        # A fallback with no key in it, or a value end before the next literal.
        "openaiApiKey: process.env.OPENAI_API_KEY || '',",
        "openaiApiKey: process.env.OPENAI_API_KEY ?? undefined,",
        "openaiApiKey: process.env.OPENAI_API_KEY || defaults.azureOpenAiKey,",
        "openaiApiKey: process.env.OPENAI_API_KEY || 'your-openai-api-key',",
        "openaiApiKey: process.env.OPENAI_API_KEY ? 'configured' : 'missing',",
        f"openaiApiKey: process.env.OPENAI_API_KEY, model: '{RANDOM}'",
    ],
)
def test_a_reference_without_a_literal_key_after_it_is_not_reported(index: SignatureIndex, line: str):
    assert _generic(index, line, code=True) == []


@pytest.mark.parametrize(
    "line",
    [
        # A literal passed to a call, a constructor or a throw after the
        # fallback operator is a path, a setting's name or a message, not a key.
        'openaiApiKey: process.env.OPENAI_API_KEY ?? getSecret("projects/my-proj-123/secrets/openaiApiKey/versions/latest"),',
        'openaiApiKey: process.env.OPENAI_API_KEY || config.get("openai.apiKey.v2"),',
        'openaiApiKey: process.env.OPENAI_API_KEY ?? readFileSync("/run/secrets/OpenAI_Api_Key_2"),',
        'githubAccessToken: process.env.GITHUB_ACCESS_TOKEN || core.getInput("github-access-token-v2"),',
        'val openaiApiKey = BuildConfig.OPENAI_API_KEY ?: error("OPENAI_API_KEY missing from local.properties")',
        'openai_api_key = settings.OPENAI_API_KEY or _raise("OPENAI_API_KEY is required for production")',
        'export const OPENAI_API_KEY = process.env.OPENAI_API_KEY ?? fail("OPENAI_API_KEY is not set");',
        'openaiApiKey: process.env.OPENAI_API_KEY || throw("OPENAI_API_KEY_missing_value_2"),',
        # A direct fallback that is a sentence is a message, not one token.
        'openaiApiKey: process.env.OPENAI_API_KEY ?? "OPENAI API KEY is not set 123",',
    ],
)
def test_a_literal_that_is_no_direct_fallback_operand_is_not_reported(index: SignatureIndex, line: str):
    assert _generic(index, line, code=True) == []
    if "process.env." in line:
        # An environment read is a reference in documentation too.
        assert _generic(index, line, code=False) == []


@pytest.mark.parametrize(
    "line",
    [
        # A fallback made of words and numbers is a default mode, a label, a
        # header name, a URL path or a model id, not a key.
        'const openaiApiKey = process.env.OPENAI_API_KEY || "anonymous-public-access";',
        'const openaiApiKey = process.env.OPENAI_API_KEY ?? "disabled-in-this-build";',
        'const azureClientSecret = process.env.AZURE_CLIENT_SECRET || "managed-identity-fallback";',
        'this.serviceApiKey = config.serviceApiKey ?? "x-api-key-header-name";',
        'const authApiKey = process.env.API_BASE + "/oauth2/v2.0/authorize";',
        'self.openai_api_key = self.openai_api_key or "gpt-4o-mini-2024-07-18"',
    ],
)
def test_a_fallback_of_words_and_numbers_is_not_a_credential(index: SignatureIndex, line: str):
    assert _generic(index, line, code=True) == []


# A base64 key with '/' in it and a UUID, derived so no key sits in the source.
_SLASHED_KEY = base64.b64encode(hashlib.sha256(b"slashed-fallback").digest()).decode().rstrip("=")
_UUID_KEY = str(uuid.UUID(bytes=hashlib.sha256(b"uuid-fallback").digest()[:16]))


@pytest.mark.parametrize("key", [RANDOM, _SLASHED_KEY, _UUID_KEY])
def test_a_token_shaped_fallback_with_separators_is_still_reported(index: SignatureIndex, key: str):
    line = f'const openaiApiKey = process.env.OPENAI_API_KEY || "{key}";'
    assert _generic(index, line, code=True) != []


@pytest.mark.parametrize(
    "fallback",
    [
        "sk-ant-api03-...",
        "your-api-key-here-Abc123XyZ",
        "PLACEHOLDER-a1B2c3D4e5F6g7H8",
        "changeme-Abc123Def456Ghi789",
        "fake_A1b2C3d4E5f6G7h8I9j0",
    ],
)
def test_a_placeholder_fallback_is_judged_as_the_literal_itself(index: SignatureIndex, fallback: str):
    # The same literals assigned directly are documentation placeholders.
    assert placeholder_reason(fallback) is not None
    line = f'anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? "{fallback}",'
    assert _generic(index, line, code=True) == []


def test_messages_after_fallback_operators_leave_a_scan_complete(tmp_path: Path, run_connector):
    # Seven providers, one quota's worth and more: a message is no credential,
    # so neither a finding nor the quota disclosure (exit 3) follows.
    providers = ["OPENAI", "ANTHROPIC", "GEMINI", "MISTRAL", "COHERE", "GROQ", "TOGETHER"]
    source = "".join(
        f'export const {name}_API_KEY = process.env.{name}_API_KEY ?? fail("{name}_API_KEY is not set");\n'
        for name in providers
    )
    kotlin = "".join(
        f'val {name.lower()}ApiKey = BuildConfig.{name}_API_KEY ?: error("{name}_API_KEY missing")\n'
        for name in providers
    )
    findings = _scan(
        tmp_path,
        run_connector,
        {"src/config.ts": source, "tests/fixtures/config.ts": source, "app/Keys.kt": kotlin},
    )
    assert [f.title for f in findings if f.kind.value == "secret"] == []


def test_a_scan_reports_no_credential_for_a_placeholder_fallback(tmp_path: Path, run_connector):
    source = 'const anthropicApiKey = process.env.ANTHROPIC_API_KEY ?? "your-api-key-here-Abc123XyZ";\n'
    findings = _scan(tmp_path, run_connector, {"src/a.ts": source})
    assert [f.title for f in findings if f.kind.value == "secret"] == []


def test_rejected_references_do_not_use_up_the_places_of_a_later_key(index: SignatureIndex):
    # At most five matches per signal are reported; references are dropped
    # before that cap, so a settings module full of them still shows its key.
    references = "".join(f"self.service{n}_api_key = service{n}_api_key\n" for n in range(8))
    found = _generic(index, references + f'BACKUP_API_KEY = "{RANDOM}"\n', code=True)
    assert found == [f'BACKUP_API_KEY = "{RANDOM}']


def _scan(tmp_path: Path, run_connector, files: dict[str, str]):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors, ctx.stats.errors
    return findings


def test_a_scan_reports_no_credential_for_references(tmp_path: Path, run_connector):
    findings = _scan(
        tmp_path,
        run_connector,
        {
            "src/validate-env.ts": (
                "export function validate() {\n"
                "  const anthropicApiKey = process.env.ANTHROPIC_API_KEY;\n"
                "  return anthropicApiKey;\n"
                "}\n"
            ),
            "search/rm.py": (
                "class SearchRM:\n"
                "    def __init__(self, serper_search_api_key=None):\n"
                "        self.serper_search_api_key = serper_search_api_key\n"
            ),
            "accounts/forms.py": (
                "def clean(self):\n"
                '    old_password = self.cleaned_data["old_password"]\n'
                "    return old_password\n"
            ),
            "docs/setup.md": "```js\nconst FIRECRAWL_API_KEY = process.env.FIRECRAWL_API_KEY;\n```\n",
        },
    )
    assert [f.title for f in findings if f.kind.value == "secret"] == []


def test_a_scan_still_reports_a_literal_key_and_withholds_it(tmp_path: Path, run_connector):
    findings = _scan(tmp_path, run_connector, {"settings.py": f'CUSTOM_API_KEY = "{RANDOM}"\n'})
    [secret] = [f for f in findings if f.kind.value == "secret"]
    assert RANDOM not in json.dumps(secret.to_dict(), default=str)


def test_a_scan_reports_a_passphrase_and_withholds_it(tmp_path: Path, run_connector):
    passphrase = "snout-fiber-thump-bloom-gravel"
    findings = _scan(tmp_path, run_connector, {"deploy/.env": f"DB_PASSWORD={passphrase}\n"})
    [secret] = [f for f in findings if f.kind.value == "secret"]
    assert passphrase not in json.dumps(secret.to_dict(), default=str)


def test_a_scan_reports_a_hard_coded_fallback_and_withholds_it(tmp_path: Path, run_connector):
    source = f'const openaiApiKey = process.env.OPENAI_API_KEY || "{RANDOM}";\n'
    findings = _scan(tmp_path, run_connector, {"src/a.js": source})
    [secret] = [f for f in findings if f.kind.value == "secret"]
    assert RANDOM not in json.dumps(secret.to_dict(), default=str)


@pytest.mark.parametrize(
    "line",
    [
        # A call, subscript, optional or non-null chain between the read and the operator.
        f'var openaiApiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY") ?? "{RANDOM}";',
        f'string azureOpenAiApiKey = Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY") ?? "{RANDOM}";',
        f'const openaiApiKey = process.env.OPENAI_API_KEY?.trim() || "{RANDOM}";',
        f'openaiApiKey = process.env.OPENAI_API_KEY!.trim() || "{RANDOM}";',
        f'const openaiApiKey = configService.getOpenAiApiKey() ?? "{RANDOM}";',
        f'const openaiApiKey = appConfig.secrets["openai"]?.key ?? "{RANDOM}";',
        # The operator ends the line or starts the next one, or Python continues the line.
        f'const openaiApiKey = process.env.OPENAI_API_KEY ||\n  "{RANDOM}";',
        f'const openaiApiKey = process.env.OPENAI_API_KEY\n  || "{RANDOM}";',
        f'openai_api_key = settings.OPENAI_API_KEY or \\\n    "{RANDOM}"',
        f'client = OpenAI(\n    openai_api_key=settings.OPENAI_API_KEY\n    or "{RANDOM}"\n)',
        # A comment with an apostrophe in it is skipped whole.
        f'const openaiApiKey = process.env.OPENAI_API_KEY || // don\'t commit\n  "{RANDOM}";',
        f'const openaiApiKey = process.env.OPENAI_API_KEY // don\'t commit\n  || "{RANDOM}";',
        f'const openaiApiKey = process.env.OPENAI_API_KEY || /* don\'t */ "{RANDOM}";',
        f"openai_api_key = settings.OPENAI_API_KEY or \\\n    '{RANDOM}'  # don't commit",
    ],
)
def test_a_fallback_after_a_call_chain_or_a_line_break_is_reported(index: SignatureIndex, line: str):
    assert _generic(index, line, code=True) != []


@pytest.mark.parametrize(
    "text",
    [
        # A blank line, a statement, a value end or a call argument comes first.
        f'const openaiApiKey = process.env.OPENAI_API_KEY\n\n  || "{RANDOM}";',
        f'api_key = settings.OPENAI_API_KEY\nif DEBUG:\n    api_key = "{RANDOM}"',
        f'const openaiApiKey = process.env.OPENAI_API_KEY // don\'t commit\nconst model = "{RANDOM}";',
        f'const openaiApiKey = process.env.OPENAI_API_KEY,\n  model = "{RANDOM}";',
        f'const openaiApiKey = configService.getOpenAiApiKey(\n  "{RANDOM}"\n);',
        f'const openaiApiKey = process.env.OPENAI_API_KEY?.trim() ?? getSecret(\n  "{RANDOM}"\n);',
        f'const openaiApiKey = process.env.OPENAI_API_KEY (\n  "{RANDOM}");',
    ],
)
def test_a_literal_past_the_end_of_the_value_is_not_a_fallback(index: SignatureIndex, text: str):
    assert _generic(index, text, code=True) == []


@pytest.mark.parametrize(
    "text",
    [
        # An operator needs an operand, so whole comment lines and empty lines
        # may come between it and the literal; comment lines may also come
        # between the reference and an operator that starts a later line.
        f'const openaiApiKey = process.env.OPENAI_API_KEY ||\n  // dev fallback\n  "{RANDOM}";',
        f'const openaiApiKey = process.env.OPENAI_API_KEY ||\n\n  "{RANDOM}";',
        f'const openaiApiKey = process.env.OPENAI_API_KEY ||\n  // a\n\n  /* b */\n  "{RANDOM}";',
        f'const openaiApiKey = process.env.OPENAI_API_KEY // a\n  // b\n  || "{RANDOM}";',
        f'client = OpenAI(\n    openai_api_key=settings.OPENAI_API_KEY\n    # dev fallback\n    or "{RANDOM}"\n)',
    ],
)
def test_a_fallback_after_comment_or_empty_lines_is_reported(index: SignatureIndex, text: str):
    assert _generic(index, text, code=True) != []


def test_a_scan_reports_a_fallback_after_a_comment_line(tmp_path: Path, run_connector):
    source = f'const openaiApiKey = process.env.OPENAI_API_KEY ||\n  // dev fallback\n  "{RANDOM}";\n'
    findings = _scan(tmp_path, run_connector, {"src/a.js": source})
    [secret] = [f for f in findings if f.kind.value == "secret"]
    assert RANDOM not in json.dumps(secret.to_dict(), default=str)


@pytest.mark.parametrize(
    "line",
    [
        # A parenthesised literal, a Python triple-quoted literal and a
        # TypeScript cast before the operator are direct fallbacks too.
        f'const openaiApiKey = process.env.OPENAI_API_KEY || ("{RANDOM}");',
        f"const openaiApiKey = process.env.OPENAI_API_KEY ?? ('{RANDOM}');",
        f'const openaiApiKey = process.env.OPENAI_API_KEY || (process.env.B || "{RANDOM}");',
        f'openai_api_key = settings.openai_api_key or ("{RANDOM}")',
        f'openai_api_key = settings.openai_api_key or """{RANDOM}"""',
        f"openai_api_key = settings.openai_api_key or '''{RANDOM}'''",
        f'const openaiApiKey = process.env.OPENAI_API_KEY as string || "{RANDOM}";',
        # A cast to a generic type: its type arguments are read through.
        f'const openaiApiKey = process.env.OPENAI_API_KEY as Record<string, string> || "{RANDOM}";',
    ],
)
def test_a_parenthesised_triple_quoted_or_cast_fallback_is_reported(index: SignatureIndex, line: str):
    assert _generic(index, line, code=True) != []


@pytest.mark.parametrize(
    "line",
    [
        # Parentheses do not make a call's argument a fallback.
        f'const openaiApiKey = process.env.OPENAI_API_KEY || (getSecret("{RANDOM}"));',
        f'const openaiApiKey = process.env.OPENAI_API_KEY || (() => "{RANDOM}");',
    ],
)
def test_a_literal_inside_a_parenthesised_call_is_not_a_fallback(index: SignatureIndex, line: str):
    assert _generic(index, line, code=True) == []


# Blanks other than a space or a tab that editors and pastes leave between
# tokens: no-break, thin and ideographic spaces, the zero-width space, the
# byte order mark, a form feed and a vertical tab.
_OTHER_BLANKS = [chr(code) for code in (0xA0, 0x2009, 0x3000, 0x200B, 0xFEFF, 0x0C, 0x0B)]


@pytest.mark.parametrize("blank", _OTHER_BLANKS, ids=[f"U+{ord(blank):04X}" for blank in _OTHER_BLANKS])
def test_a_fallback_after_any_blank_is_reported(index: SignatureIndex, blank: str):
    js = f'const openaiApiKey = process.env.OPENAI_API_KEY{blank}|| "{RANDOM}";'
    python = f'openai_api_key = settings.openai_api_key or{blank}"{RANDOM}"'
    assert _generic(index, js, code=True) != []
    assert _generic(index, python, code=True) != []


def test_a_scan_reports_a_fallback_after_a_no_break_space(tmp_path: Path, run_connector):
    source = f'const openaiApiKey = process.env.OPENAI_API_KEY{chr(0xA0)}|| "{RANDOM}";\n'
    findings = _scan(tmp_path, run_connector, {"src/a.js": source})
    [secret] = [f for f in findings if f.kind.value == "secret"]
    assert RANDOM not in json.dumps(secret.to_dict(), default=str)


def test_a_scan_reports_a_fallback_on_the_next_line_and_withholds_it(tmp_path: Path, run_connector):
    files = {
        "src/a.cs": f'var openaiApiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY") ?? "{RANDOM}";\n',
        "src/a.js": f'const openaiApiKey = process.env.OPENAI_API_KEY ||\n  "{RANDOM}";\n',
    }
    findings = _scan(tmp_path, run_connector, files)
    secrets = [f for f in findings if f.kind.value == "secret"]
    assert sorted(f.metadata["path"] for f in secrets) == ["src/a.cs", "src/a.js"]
    assert RANDOM not in json.dumps([f.to_dict() for f in secrets], default=str)


# ------------------------------------------------------------------ evidence
@pytest.mark.parametrize(
    "line",
    [
        "const anthropicApiKey = process.env.ANTHROPIC_API_KEY;",
        "const apiKey = import.meta.env.VITE_OPENAI_API_KEY;",
        'api_key = os.environ["OPENAI_API_KEY"]',
        'api_key = os.getenv("OPENAI_API_KEY")',
        'api_key = os.environ.get("OPENAI_API_KEY")',
        'String apiKey = System.getenv("OPENAI_API_KEY");',
        'apiKey := os.Getenv("OPENAI_API_KEY")',
        'api_key = ENV["OPENAI_API_KEY"]',
        "apiKey: process.env.OPENAI_API_KEY,",
        # Names of one word or with digits are names too.
        'password = os.getenv("PGPASSWORD")',
        "token = process.env.K8S_TOKEN",
        # Blanks may come between the read and the end of its value.
        "apiKey: process.env.OPENAI_API_KEY ,",
        "new OpenAI({ apiKey: process.env.OPENAI_API_KEY })",
        "  apiKey: process.env.OPENAI_API_KEY \n  model: 'gpt-4o',",
    ],
)
def test_an_environment_read_stays_visible_after_a_credential_name(line: str):
    assert sanitize_text(line) == line


AZURE_KEY = "3f9a8b7c6d5e4f30a1b2c3d4e5f60718"  # an Azure OpenAI-style 32-hex key


@pytest.mark.parametrize(
    "line",
    [
        # Text after the read and a blank is part of the value, not its end:
        # a comment, a chained fallback, a concatenation or another token.
        f"  apiKey: process.env.AZURE_OPENAI_API_KEY // old: {AZURE_KEY}",
        f"  apiKey: process.env.AZURE_OPENAI_API_KEY /* {AZURE_KEY} */,",
        f"  apiKey: process.env.AZURE_OPENAI_API_KEY ?? process.env.AZURE_KEY_FALLBACK ?? '{AZURE_KEY}',",
        f"  apiKey: process.env.AZURE_OPENAI_API_KEY || defaults.azure || '{AZURE_KEY}',",
        f"  apiKey: process.env.AZURE_OPENAI_API_KEY + '{AZURE_KEY}',",
        f"api-key: process.env.AZURE_OPENAI_API_KEY {AZURE_KEY}",
        f"api_key = os.environ['AZURE_OPENAI_API_KEY'] # {AZURE_KEY}",
    ],
)
def test_text_after_an_environment_read_keeps_the_value_withheld(line: str):
    safe = sanitize_text(line)
    assert AZURE_KEY not in safe and REDACTED in safe
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    ("line", "kept"),
    [
        # The read ends its value at ',' or ';', and the comment after it is
        # withheld where it holds key material; the read itself stays visible.
        (
            f"  apiKey: process.env.AZURE_OPENAI_API_KEY, // old: {AZURE_KEY}",
            "process.env.AZURE_OPENAI_API_KEY,",
        ),
        (f"apiKey = process.env.OPENAI_API_KEY; // {AZURE_KEY}", "process.env.OPENAI_API_KEY;"),
        (
            f"apiKey: import.meta.env.VITE_OPENAI_API_KEY , // {AZURE_KEY}",
            "import.meta.env.VITE_OPENAI_API_KEY ,",
        ),
        (
            f"  apiKey: process.env.AZURE_OPENAI_API_KEY, /* {AZURE_KEY} */",
            "process.env.AZURE_OPENAI_API_KEY,",
        ),
        (f"api_key = os.environ['OPENAI_API_KEY']; # {AZURE_KEY}", "os.environ['OPENAI_API_KEY'];"),
        # After any other credential value too.
        (f'  apiKey: "{RANDOM}", // was {AZURE_KEY}', "// was"),
        (f"  openaiKey: config.azure, // {AZURE_KEY}", "config.azure,"),
        # An XML or HTML comment after a credential-named setting.
        (
            f'<add key="OpenaiApiKey" value="%OPENAI_API_KEY%" /> <!-- {AZURE_KEY} -->',
            'value="%OPENAI_API_KEY%" /> <!--',
        ),
        (f'<add key="OpenAI:Key" value="%OPENAI_KEY%"/><!--old {AZURE_KEY}-->', "<!--old "),
    ],
)
def test_key_material_in_a_comment_after_a_credential_value_is_withheld(line: str, kept: str):
    safe = sanitize_text(line)
    assert AZURE_KEY not in safe and RANDOM not in safe and kept in safe
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "line",
    [
        # Words, references and placeholders in the comment stay, and a comment
        # on a line that assigns no credential name is read as before.
        "  apiKey: process.env.AZURE_OPENAI_API_KEY, // rotate quarterly via $VAULT_PATH",
        "apiKey = process.env.OPENAI_API_KEY; // see docs/credentials.md",
        "api_key = os.environ['OPENAI_API_KEY']; # your-api-key-here",
        "color: '#a8f3c91d', // brand",
        "  url: 'https://example.com/#a8f3c91d7e2b', // docs",
        '<add key="OpenaiApiKey" value="%OPENAI_API_KEY%" /> <!-- rotate via the vault -->',
    ],
)
def test_a_comment_without_key_material_keeps_its_text(line: str):
    assert sanitize_text(line) == line


# An upper-case random key and a base32 TOTP secret, derived so no key sits in the source.
UPPER_KEY = base64.b32encode(hashlib.sha256(b"upper-case-key").digest()).decode()[:40]
TOTP_SECRET = base64.b32encode(hashlib.sha256(b"totp-secret").digest()).decode()[:32]


@pytest.mark.parametrize(
    ("line", "secret"),
    [
        # A credential pasted where the variable's name belongs is not a name.
        (f'aws_secret_access_key = os.getenv("{UPPER_KEY}")', UPPER_KEY),
        (f'otp_secret = os.getenv("{TOTP_SECRET}")', TOTP_SECRET),
        (f"password: ENV['{UPPER_KEY[:30]}']", UPPER_KEY[:30]),
    ],
)
def test_a_key_in_place_of_the_variable_name_is_withheld(line: str, secret: str):
    safe = sanitize_text(line)
    assert secret not in safe and REDACTED in safe


# Upper-case keys whose letters and digits do not alternate: a base32 secret
# with no digit, one with a single run of digits, and a 16-character one.
_BASE32_LETTERS = "".join(
    c for c in base64.b32encode(hashlib.sha256(b"no-digit").digest()).decode() if c.isalpha()
)
LETTERS_ONLY_KEY = _BASE32_LETTERS[:30]
ONE_DIGIT_RUN_KEY = _BASE32_LETTERS[:16] + "2" + _BASE32_LETTERS[16:26]
SHORT_TOTP_KEY = _BASE32_LETTERS[-16:]


@pytest.mark.parametrize(
    ("line", "secret"),
    [
        (f'secret = os.getenv("{LETTERS_ONLY_KEY}")', LETTERS_ONLY_KEY),
        (f"password: process.env.{LETTERS_ONLY_KEY[:26]}", LETTERS_ONLY_KEY[:26]),
        (f'token = ENV["{ONE_DIGIT_RUN_KEY}"]', ONE_DIGIT_RUN_KEY),
        (f"otp_secret = os.environ['{SHORT_TOTP_KEY}']", SHORT_TOTP_KEY),
    ],
)
def test_a_long_name_without_separators_is_withheld_as_a_pasted_key(line: str, secret: str):
    safe = sanitize_text(line)
    assert secret not in safe and REDACTED in safe


@pytest.mark.parametrize(
    "line",
    [
        'api_key = os.getenv("OPENAI_API_KEY")',
        "token = process.env.GITHUBTOKEN",
        'api_key = os.getenv("ANTHROPICAPIKEY")',
        "secret = process.env.AZURE_OPENAI_API_KEY_SECONDARY",
    ],
)
def test_names_with_separators_or_short_names_stay_visible(line: str):
    assert sanitize_text(line) == line


HEX = "a8f3c91d7e2b4f6a9d0c"


@pytest.mark.parametrize(
    "line",
    [
        # A default, a fallback or any other operand keeps the whole value withheld.
        f'api_key = os.getenv("OPENAI_API_KEY", "{HEX}")',
        f'const apiKey = process.env.OPENAI_API_KEY || "{HEX}";',
        f'api_key = os.getenv("OPENAI_API_KEY") or "{HEX}"',
        f'const apiKey = process.env.OPENAI_API_KEY ?? "{HEX}";',
        f'apiKey = process.env.OPENAI_API_KEY + "{HEX}"',
        f'apiKey: process.env.OPENAI_API_KEY, secret: "{HEX}"',
    ],
)
def test_a_literal_beside_an_environment_read_is_still_withheld(line: str):
    safe = sanitize_text(line)
    assert HEX not in safe and REDACTED in safe
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "line",
    [
        # The value lexer stops at the quote of a subscript or call argument;
        # the fallback after the read is the credential (main showed it too).
        f"azure_api_key: os.environ['K'] if PROD else '{AZURE_KEY}'",
        f'azure_api_key: os.environ["K"] if PROD else "{AZURE_KEY}"',
        f"azure_api_key: os.environ['K'] or '{AZURE_KEY}'",
        f"azureApiKey: process.env['K'] ?? '{AZURE_KEY}'",
        f"azureApiKey: process.env['K'] || '{AZURE_KEY}'",
        f"azure_api_key: os.getenv('K') or '{AZURE_KEY}'",
        f"azureApiKey: getKey('K') ?? '{AZURE_KEY}'",
        f"  azure_api_key: os.environ['K'] if PROD else '{AZURE_KEY}',",
        f"config = {{'azure_api_key': os.environ['K'] if PROD else '{AZURE_KEY}'}}",
        # A name whose last word names a key withholds an opaque fallback.
        f"azureKey: process.env['K'] ?? '{AZURE_KEY}'",
        f"key: os.environ['K'] or '{AZURE_KEY}'",
    ],
)
def test_a_fallback_after_a_subscript_or_call_read_is_withheld(line: str):
    safe = sanitize_text(line)
    assert AZURE_KEY not in safe and REDACTED in safe
    assert sanitize_text(safe) == safe


# A mixed-case random key, derived so no key sits in the source.
TAIL_KEY = "".join(
    c for c in base64.b64encode(hashlib.sha256(b"line-tail").digest()).decode() if c.isalnum()
)[:32]


@pytest.mark.parametrize(
    "line",
    [
        # The value lexer cuts these reads at a quote, a bracket or a comma: a
        # spaced subscript, an optional-chain call, a call with two arguments,
        # a default argument. The literal after the cut is shown no more.
        'azureApiKey: process.env.<K>?.trim() || "<K>",',
        "azureApiKey: process.env[ '<K>' ] || \"<K>\",",
        "azure_api_key: os.environ[ '<K>' ] if PROD else '<K>'",
        'azureApiKey: cfg("a", "b") || "<K>",',
        "azureApiKey: get(process.env, '<K>') || \"<K>\",",
        'azure_api_key: os.getenv("<K>", "<K>")',
        'azure_api_key: os.getenv("OPENAI_API_KEY", "<K>")',
        'const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY?.trim() || "<K>" });',
        "azureApiKey: cfg.get('a', { d: 1 }) ?? `<K>`,",
        "azure_api_key: os.environ.get('OPENAI_API_KEY', '<K>')",
    ],
)
def test_a_literal_after_a_credential_name_on_its_line_is_withheld(line: str):
    text = line.replace("<K>", TAIL_KEY)
    safe = sanitize_text(text)
    assert TAIL_KEY not in safe and REDACTED in safe
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "line",
    [
        # Words, model names, references and templates after the name stay.
        "{ apiKey: os.environ['OPENAI_API_KEY'], model: 'gpt-4o-mini-2024-07-18' }",
        "const openaiKey = `${prefix}<K>`;",
        # A literal before the credential's name is no value of it.
        "log('<K>'); apiKey: process.env.OPENAI_API_KEY",
    ],
)
def test_other_literals_on_a_credential_line_keep_their_text(line: str):
    text = line.replace("<K>", TAIL_KEY)
    assert sanitize_text(text) == text


@pytest.mark.parametrize(
    "line",
    [
        # A plain read, a word-like fallback under a conditional name, a comparison.
        "{ apiKey: os.environ['K'] }",
        "{ apiKey: os.environ['K'], model: 'gpt-4o' }",
        "cacheKey: cache['users'] ?? 'users-by-id'",
        "if token == os.environ['K'] or debug: pass",
    ],
)
def test_reads_without_a_credential_fallback_keep_their_text(line: str):
    assert sanitize_text(line) == line


@pytest.mark.parametrize(
    "line",
    [
        # Not a read by name: a computed name, a method on the value, a variable,
        # a call, or an unquoted literal in an env file.
        "api_key = os.environ[name]",
        "const apiKey = process.env.OPENAI_API_KEY.trim();",
        "self.api_key = api_key",
        "password = getpass.getpass()",
        "DB_PASSWORD=Summer.Vacation2024",
    ],
)
def test_other_values_after_a_credential_name_stay_withheld(line: str):
    assert REDACTED in sanitize_text(line)


# #258 required a digit-free value to mix cases evenly, to drop program names
# ('include_tracing_api_key', 'ANTHROPIC_API_KEY', 'includeTracingApiKey').
# Applied to every digit-free value it also dropped single-word passphrases
# and AWS key ids whose body has no digit; only name-shaped values are held to
# it now.
@pytest.mark.parametrize(
    "line",
    [
        "DB_PASSWORD=correcthorsebatterystaple",
        "DB_PASSWORD=CORRECTHORSEBATTERYSTAPLE",
        'aws_access_key_id = "' + "AKIA" + 'QSXMKVTWPLRNHGDJ"',
    ],
)
def test_digit_free_tokens_without_name_structure_are_reported(index: SignatureIndex, line: str):
    assert _generic(index, line, code=False)


@pytest.mark.parametrize(
    "line",
    [
        "include_tracing_api_key=include_tracing_api_key",
        'ENV_API_KEY = "ANTHROPIC_API_KEY"',
        'apiKey = "includeTracingApiKey"',
        'secret_key = "settings.openai_api_key"',
        # A dotted name is no dotted passphrase: its words change case inside.
        'OPENAI_API_KEY = "config.openai.apiKey"',
        "OPENAI_API_KEY=ANTHROPIC_API_KEY",
    ],
)
def test_digit_free_names_are_still_not_credentials(index: SignatureIndex, line: str):
    assert _generic(index, line, code=False) == []


# In an env or credential file a PASSWORD or CREDENTIAL value is chosen by a
# person and cannot name another variable, so the name rules (#258's case mix,
# single-case identifiers, CONSTANT_CASE slugs) do not drop it there. Token
# names (API_KEY, ACCESS_TOKEN, CLIENT_SECRET) keep them, and labels and
# placeholders stay unreported under any name. A template of an env file, a
# Helm values file, a compose file, a workflow or a document is no env file.
@pytest.mark.parametrize(
    "line",
    [
        "DB_PASSWORD=correct-horse-battery-staple",
        "POSTGRES_PASSWORD=TrustNoOneEverAgain",
        "SERVICE_CREDENTIAL=TrustNoOneEverAgain",
        "DB_PASSWORD=summer_vacation_beach_2024",
        "DB_PASSWORD=SNOUT_FIBER_THUMP_BLOOM",
        # A word or a number that is no label vocabulary makes a value built
        # like a label a password (main 8c72467 reports each of these).
        "DB_PASSWORD=admin_password_123",
        "DB_PASSWORD=DbPasswordFromSecretsManager",
        "DB_PASSWORD=managedIdentityCredential",
    ],
)
def test_a_password_in_an_env_file_is_never_read_as_a_name(index: SignatureIndex, line: str):
    assert _generic(index, line, code=False, env_file=True) != []


@pytest.mark.parametrize(
    "line",
    [
        "OPENAI_API_KEY=include_tracing_api_key",
        "CLIENT_SECRET=resolvedClientSecret",
        "ACCESS_TOKEN=ANTHROPIC_API_KEY",
        "OPENAI_API_KEY=sua_chave_openai",
        "DB_PASSWORD=request-scoped-credential",
        "DB_PASSWORD=local-development-only",
        "DB_PASSWORD=your_database_password_here",
        # A value built like a name whose words say what it stands for.
        "KEYCLOAK_ADMIN_PASSWORD=KeycloakAdminPassword",
        "POSTGRES_PASSWORD=change_me_to_a_strong_password",
        "SVC1_DB_PASSWORD=svc1_local_dev_password",
    ],
)
def test_token_names_labels_and_placeholders_keep_their_exemptions_in_env_files(
    index: SignatureIndex, line: str
):
    assert _generic(index, line, code=False, env_file=True) == []


@pytest.mark.parametrize(
    "value",
    [
        "change_me_to_a_strong_password",
        "a_very_long_random_string",
        "admin_password_123",
        "password_for_local_db_1",
        "postgres_password_2024",
        "the_quick_brown_fox_1",
        "AzureKeyVaultReference",
        "DbPasswordFromSecretsManager",
        "managedIdentityCredential",
        "springDatasourcePassword",
        "useExistingSecretKey",
    ],
)
def test_a_password_outside_an_env_file_keeps_the_name_rules(index: SignatureIndex, value: str):
    # Helm values, compose files, workflows, documentation and env templates
    # name settings and secrets in a password's place; 90d22be reported none.
    assert _generic(index, f"DB_PASSWORD={value}", code=False) == []


def test_env_templates_and_configuration_files_report_no_password_labels(tmp_path: Path, run_connector):
    postgres = "POSTGRES_PASSWORD=change_me_to_a_strong_password\n"
    files = {
        ".env.example": "KEYCLOAK_ADMIN_PASSWORD=KeycloakAdminPassword\n" + postgres,
        ".env.sample": postgres,
        "config/.env.template": postgres,
        "docs/configuration.md": "```\n" + postgres + "```\n",
        "charts/app/values.yaml": "adminPassword: useExistingSecretKey\nclientCredential: ManagedIdentityCredential\n",
        "src/main/resources/application.properties": "spring.datasource.password=springDatasourcePassword\n",
        "docker-compose.yml": "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: PostgresDockerPassword\n",
        ".github/workflows/ci.yml": "env:\n  POSTGRES_PASSWORD: CiPostgresPassword\n",
        # More than a quota's worth: the scan must stay complete (_scan checks).
        "svc/.env.example": "".join(f"SVC{n}_DB_PASSWORD=svc{n}_local_dev_password\n" for n in range(8)),
        "svc/.env": "".join(f"SVC{n}_DB_PASSWORD=svc{n}_local_dev_password\n" for n in range(8)),
    }
    findings = _scan(tmp_path, run_connector, files)
    assert [f.metadata["path"] for f in findings if f.kind.value == "secret"] == []


@pytest.mark.parametrize(
    ("name", "values"),
    [
        (".env", True),
        (".env.local", True),
        (".env.production", True),
        ("prod.env", True),
        (".netrc", True),
        (".env.example", False),
        (".env.sample", False),
        (".env.template", False),
        (".env.dist", False),
        ("values.yaml", False),
        ("docker-compose.yml", False),
    ],
)
def test_env_values_files_are_told_from_templates(name: str, values: bool):
    from shadowscan.connectors.code.filesystem import _env_values_file

    assert _env_values_file(name) is values


def test_a_password_name_in_source_code_still_reads_a_name(index: SignatureIndex):
    assert _generic(index, 'DB_PASSWORD = "POSTGRES_ROOT_PASSWORD_FILE"', code=True) == []
    assert _generic(index, 'DB_PASSWORD = "summer_vacation_beach_2024"', code=True) == []


def test_a_scan_reports_env_file_passwords_and_withholds_them(tmp_path: Path, run_connector):
    env = "DB_PASSWORD=correct-horse-battery-staple\nPOSTGRES_PASSWORD=TrustNoOneEverAgain\n"
    findings = _scan(tmp_path, run_connector, {".env": env})
    [secret] = [f for f in findings if f.kind.value == "secret"]
    assert secret.metadata["count"] == 2
    dumped = json.dumps(secret.to_dict(), default=str)
    assert "TrustNoOneEverAgain" not in dumped and "battery-staple" not in dumped


# A generic call's type arguments between the read and the fallback operator
# ended the operand reader at '<', so the idiomatic NestJS, .NET and Kotlin
# forms of a typed settings read lost their fallback key, which main 8c72467
# reported.
@pytest.mark.parametrize(
    "line",
    [
        "const openaiApiKey = this.configService.get<string>('OPENAI_API_KEY') ?? '<K>';",
        "  openaiApiKey: this.configService.get<string>('OPENAI_API_KEY') ?? '<K>',",
        'const openaiApiKey = this.configService.get<string>("OPENAI_API_KEY")! || "<K>";',
        'const openaiApiKey = this.config.values.get<string>("x") ?? "<K>";',
        'var openaiApiKey = configuration.GetValue<string>("OpenAI:ApiKey") ?? "<K>";',
        'val openaiApiKey = config.getProperty<String>("openai") ?: "<K>"',
        # Nested, nullable, array and union type arguments.
        'const openaiApiKey = this.configService.get<Map<string, string[]>>("x")?.key ?? "<K>";',
        'val openaiApiKey = config.getProperty<String?>("openai") ?: "<K>"',
        'const openaiApiKey = this.configService.get<string | undefined>("x") ?? "<K>";',
    ],
)
def test_a_fallback_after_generic_type_arguments_is_reported(index: SignatureIndex, line: str):
    assert _generic(index, line.replace("<K>", TAIL_KEY), code=True) != []


def test_type_arguments_do_not_make_a_call_argument_a_fallback(index: SignatureIndex):
    line = f'const openaiApiKey = this.configService.get<string>("{TAIL_KEY}");'
    assert _generic(index, line, code=True) == []


def test_a_scan_reports_a_fallback_after_typed_reads(tmp_path: Path, run_connector):
    files = {
        "src/a.ts": f"const openaiApiKey = this.configService.get<string>('OPENAI_API_KEY') ?? '{TAIL_KEY}';\n",
        "src/A.cs": f'var openaiApiKey = configuration.GetValue<string>("OpenAI:ApiKey") ?? "{TAIL_KEY}";\n',
        "src/A.kt": f'val openaiApiKey = config.getProperty<String>("openai") ?: "{TAIL_KEY}"\n',
    }
    findings = _scan(tmp_path, run_connector, files)
    secrets = [f for f in findings if f.kind.value == "secret"]
    assert sorted(f.metadata["path"] for f in secrets) == ["src/A.cs", "src/A.kt", "src/a.ts"]
    assert TAIL_KEY not in json.dumps([f.to_dict() for f in secrets], default=str)


# A key pasted in place of an environment variable's name reads no variable:
# the name is the credential, written into the code. Evidence withheld it,
# but the detector read the chain as a reference and reported nothing, where
# main 8c72467 reported it. Built at run time: a base32 TOTP secret, a
# letters-only run and the same secret without its digits.
_TOTP = base64.b32encode(b"Hello!\xde\xad\xbe\xef").decode() * 2
_LETTERS = "QWERTYUIOP" + "ASDFGHJKL" + "ZXCVBNM"
_DIGIT_FREE = _TOTP.replace("3", "") + "AB"


@pytest.mark.parametrize(
    ("line", "name"),
    [
        (f"const openaiApiKey = process.env.{_TOTP};", _TOTP),
        (f"const openaiApiKey = process.env.{_LETTERS};", _LETTERS),
        (f"openai_api_key = os.environ.{_DIGIT_FREE}", _DIGIT_FREE),
        (f"const openaiApiKey = import.meta.env.{_TOTP};", _TOTP),
        (f'var openaiApiKey = Environment.GetEnvironmentVariable("{_LETTERS}");', _LETTERS),
    ],
)
def test_a_key_pasted_as_the_variable_name_is_reported(index: SignatureIndex, line: str, name: str):
    [match] = [m for m in index.match_secrets(line, code=True) if m.signature_id == GENERIC]
    assert match.extra["credential"] == name


@pytest.mark.parametrize(
    "name",
    [
        _TOTP,
        _LETTERS,
        _DIGIT_FREE,
        "OPENAI_API_KEY",
        "PGPASSWORD",
        "K8S_TOKEN",
        "GITHUBTOKEN",
        "OPENAI_API_KEY_2",
    ],
)
def test_detection_and_evidence_read_a_pasted_name_alike(index: SignatureIndex, name: str):
    # One test decides both: a name the detector reports is withheld from
    # evidence, and a name it leaves as a reference stays visible there.
    line = f"const openaiApiKey = process.env.{name};"
    reported = any(m.signature_id == GENERIC for m in index.match_secrets(line, code=True))
    withheld = name not in sanitize_text(line)
    assert reported is withheld


def test_a_scan_reports_a_pasted_name_and_withholds_it(tmp_path: Path, run_connector):
    files = {"src/a.ts": f"const openaiApiKey = process.env.{_TOTP};\n"}
    findings = _scan(tmp_path, run_connector, files)
    [secret] = [f for f in findings if f.kind.value == "secret"]
    assert _TOTP not in json.dumps(secret.to_dict(), default=str)


# Instructions written as labels: function words and ordinary words, which
# generated passphrases leave out ('change-me-please', 'do-not-commit-this',
# 'must-be-set-at-runtime'), and a word of two letters of the name with an
# account or service word ('pg-replica-sync-user'). They were reported as
# hard-coded credentials, and six in an .env.example made the scan incomplete.
INSTRUCTION_LABELS = [
    "change-me-before-deploying",
    "change-me-please",
    "please-change-me-now",
    "change-me-asap-please",
    "change_me_please",
    "CHANGE-ME-BEFORE-DEPLOY",
    "CHANGE-ME-PLEASE-NOW",
    "do-not-commit-this",
    "never-commit-real-ones",
    "must-be-set-at-runtime",
    "not-set-in-this-repo",
    "must-come-from-vault",
    "do-not-use-this-one",
    "must-override-at-deploy",
    "must-not-be-empty",
    "must-be-overridden",
    "must-be-set-at-deploy-time",
    "not-configured-yet",
    "not-configured-yet-xyz",
    "jwt-signing-key-material",
    "NOT-SET-IN-THIS-ENVIRONMENT",
    "SET-VIA-ENVIRONMENT-VAR",
]


@pytest.mark.parametrize("label", INSTRUCTION_LABELS)
def test_instruction_labels_are_not_credentials(index: SignatureIndex, label: str):
    assert _generic(index, f"export DB_PASSWORD={label}", code=False) == []
    assert _generic(index, f"db_password = '{label}'", code=True) == []
    assert _generic(index, f"DB_PASSWORD={label}", code=False, env_file=True) == []
    assert _generic(index, f'OPENAI_API_KEY = "{label}"', code=True) == []


@pytest.mark.parametrize(
    ("name", "label"),
    [
        ("PG_PASSWORD", "pg-replica-sync-user"),
        ("DB_PASSWORD", "db-readonly-reporting-user"),
        ("AI_API_KEY", "ai-gateway-internal-route"),
        ("MQ_PASSWORD", "mq-broker-admin-user"),
    ],
)
def test_a_two_letter_word_of_the_name_with_an_account_word_is_a_label(
    index: SignatureIndex, name: str, label: str
):
    assert _generic(index, f"{name}={label}", code=False) == []
    assert _generic(index, f"{name.lower()} = '{label}'", code=True) == []
    assert _generic(index, f"{name}={label}", code=False, env_file=True) == []


@pytest.mark.parametrize(
    "passphrase",
    [
        # The same rules leave generated passphrases reported: no function
        # word, and at most one word that is common label vocabulary or a
        # two-letter word of the name.
        "snout-fiber-thump-bloom-gravel",
        "db-fiber-thump-bloom-gravel",
        "snout-admin-thump-bloom",
        "glider-user-thump-bloom",
        "snout-strong-thump-gravel",
        "commit-snout-fiber-thump",
    ],
)
def test_one_account_or_name_word_does_not_label_a_passphrase(index: SignatureIndex, passphrase: str):
    assert _generic(index, f"DB_PASSWORD={passphrase}", code=False) != []
    assert _generic(index, f'db_password = "{passphrase}"', code=True) != []
    assert _generic(index, f"DB_PASSWORD={passphrase}", code=False, env_file=True) != []


def test_an_env_example_of_instruction_labels_stays_complete(tmp_path: Path, run_connector):
    names = ["POSTGRES", "REDIS", "SMTP", "KEYCLOAK_ADMIN", "MINIO_ROOT", "GRAFANA_ADMIN"]
    files = {
        ".env.example": "".join(f"{name}_PASSWORD=must-be-set-at-runtime\n" for name in names),
        "docker-compose.yml": (
            "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: do-not-commit-this\n"
            "      ADMIN_PASSWORD: change_me_asap_please\n"
        ),
        "app/settings.py": 'DATABASE_PASSWORD = "not-configured-yet"\n',
        "README.md": "```sh\nexport DATABASE_PASSWORD=change-me-before-deploying\n```\n",
    }
    findings = _scan(tmp_path, run_connector, files)
    assert [f.metadata["path"] for f in findings if f.kind.value == "secret"] == []


# In an env or credential file a PASSWORD value was dropped as a label when
# one of its words was any label word or a word of the name, so ordinary
# passwords with a year and generated passphrases with one common word went
# unreported there, while YAML and compose files and main 8c72467 reported
# them. Only a value whose every word labels it is a label now.
@pytest.mark.parametrize(
    "line",
    [
        "POSTGRES_PASSWORD=PostgresProd2024Secure",
        "REDIS_PASSWORD=RedisCacheProd2024",
        "KEYCLOAK_ADMIN_PASSWORD=KeycloakAdmin2024Strong",
        "DB_PASSWORD=LocalAdmin2024Strong",
        "DB_PASSWORD=snout_passed_thump_bloom",
        "DB_PASSWORD=snout_dev_thump_bloom",
        "DB_PASSWORD=glider_keyed_thump_bloom",
        "DB_PASSWORD=SnoutPassedThump2024",
        "DB_PASSWORD=MyCompanyName2024Prod",
        "DB_PASSWORD=MailServerKey2024Abc",
        "DB_PASSWORD=BlueSkyValue2024Go",
        "DB_PASSWORD=GrafanaAdmin_2024_Zz",
        "DB_PASSWORD=myDevPassword123x",
    ],
)
def test_a_password_with_any_word_of_its_own_is_reported_in_an_env_file(index: SignatureIndex, line: str):
    assert _generic(index, line, code=False, env_file=True) != []


# python-dotenv and Node's dotenv read blanks around '=': the name kept them,
# so 'POSTGRES_PASSWORD ' named no password and the name rules dropped a
# password built like a name.
@pytest.mark.parametrize(
    "line",
    [
        "POSTGRES_PASSWORD = TrustNoOneEverAgain",
        "POSTGRES_PASSWORD\t=\tTrustNoOneEverAgain",
        'POSTGRES_PASSWORD = "TrustNoOneEverAgain"',
        "export POSTGRES_PASSWORD = TrustNoOneEverAgain",
        "POSTGRES_PASSWORD : TrustNoOneEverAgain",
    ],
)
def test_blanks_around_the_operator_keep_a_password_named(index: SignatureIndex, line: str):
    assert _generic(index, line, code=False, env_file=True) != []


def test_a_label_with_blanks_around_the_operator_stays_a_label(index: SignatureIndex):
    assert _generic(index, "KEYCLOAK_ADMIN_PASSWORD = KeycloakAdminPassword", code=False, env_file=True) == []


def test_a_scan_reports_dotenv_passwords_with_blanks(tmp_path: Path, run_connector):
    env = "POSTGRES_PASSWORD = TrustNoOneEverAgain\nDB_PASSWORD = correct-horse-battery-staple\n"
    findings = _scan(
        tmp_path, run_connector, {".env": env, ".env.local": "DB_PASSWORD=snout_dev_thump_bloom\n"}
    )
    secrets = {f.metadata["path"]: f for f in findings if f.kind.value == "secret"}
    assert secrets[".env"].metadata["count"] == 2 and ".env.local" in secrets
    dumped = json.dumps([f.to_dict() for f in secrets.values()], default=str)
    assert (
        "TrustNoOneEverAgain" not in dumped and "battery-staple" not in dumped and "thump_bloom" not in dumped
    )


# Outside source code a password's words joined by '.' are a passphrase, as in
# an env file: a compose or YAML value names no package or message key there.
@pytest.mark.parametrize(
    "line", ["DB_PASSWORD=snout.fiber.thump.bloom.gravel", "db_password: Snout.Fiber.Thump.Bloom.Gravel"]
)
def test_a_dotted_passphrase_outside_source_code_is_a_credential(index: SignatureIndex, line: str):
    assert _generic(index, line, code=False) != []
    # In source code it still reads as a name ('android.injected.signing.store').
    assert _generic(index, line.replace("=", ' = "').replace(": ", ' = "') + '"', code=True) == []

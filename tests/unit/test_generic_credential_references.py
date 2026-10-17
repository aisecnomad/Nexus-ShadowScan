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
from pathlib import Path

import pytest

from shadowscan.connectors.common import placeholder_reason
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.redaction import REDACTED, sanitize_text

GENERIC = "heuristic.inline-credential"
RANDOM = "R4nd0m9Qx2Vb7Lp6"  # the same synthetic value the rule's own tests use


def _generic(index: SignatureIndex, text: str, *, code: bool) -> list[str]:
    """The generic matches the scanner reports as credentials (not placeholders).

    A placeholder test judges the literal a match stands for, which for a
    reference is the fallback after it (``extra["credential"]``).
    """
    return [
        m.value
        for m in index.match_secrets(text, code=code)
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
    ],
)
def test_digit_free_names_are_still_not_credentials(index: SignatureIndex, line: str):
    assert _generic(index, line, code=False) == []

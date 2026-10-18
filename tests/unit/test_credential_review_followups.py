"""Regressions from the adversarial review of the round-5 credential rules.

Each input is synthetic and assembled by concatenation, so no credential-shaped
literal sits in this file.
"""

from __future__ import annotations

import json

import pytest


def _scan(run_connector, tmp_path, rel: str, text: str):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return findings


def _secret_lines(findings) -> list[int]:
    return sorted(
        int(evidence.location.rsplit(":", 1)[1])
        for finding in findings
        if finding.kind.value == "secret"
        for evidence in finding.evidence
        if evidence.location.rsplit(":", 1)[-1].isdigit()
    )


@pytest.mark.parametrize(
    "password",
    ["NowIs" + "TheTimeToCome", "ItIs" + "TimeToComeIn", "ComeWith" + "MeNowPlease", "ComeOn" + "InTheVault"],
)
def test_a_sentence_password_with_a_weak_verb_is_a_password_in_an_env_file(run_connector, tmp_path, password):
    # Regression: 'come', 'use' and 'set' made any closed-vocabulary sentence an
    # instruction, so these env-file passwords, which main reported, were dropped
    # as labels.
    findings = _scan(run_connector, tmp_path, ".env", f"DB_HOST=db.internal\nDB_PASSWORD={password}\n")
    assert _secret_lines(findings) == [2]


@pytest.mark.parametrize(
    "label", ["must-come-from-vault", "never-use-in-prod", "use-your-own", "change-me-please", "set-me-first"]
)
def test_an_instruction_is_still_a_label_in_an_env_file(run_connector, tmp_path, label):
    findings = _scan(run_connector, tmp_path, ".env", f"DB_HOST=db.internal\nDB_PASSWORD={label}\n")
    assert _secret_lines(findings) == []


def _snippets(findings) -> str:
    return json.dumps([finding.to_dict() for finding in findings])


@pytest.mark.parametrize("name", ["dbPassWord", "userPassWord"])
def test_a_password_fallback_under_a_split_password_name_is_withheld(run_connector, tmp_path, name):
    # Regression: the detector reads 'dbPassWord' as a password's name and reports
    # its fallback literal, but the redactor read its last word, 'Word', and showed
    # the password in the finding's own snippet.
    password = "Xk9#mQ2" + "$vL!pR7@wZ4%"
    text = (
        "export const settings = {\n"
        '  host: process.env.PGHOST ?? "localhost",\n'
        f'  {name}: process.env.DB_PASSWORD?.trim() || "{password}",\n'
        "};\n"
    )
    findings = _scan(run_connector, tmp_path, "src/db.ts", text)
    assert _secret_lines(findings) == [3]
    assert password not in _snippets(findings)


def test_a_uuid_key_given_as_a_settings_default_is_withheld(run_connector, tmp_path):
    # Regression: the detector reports a UUID-shaped default of an API key's
    # settings read, but its hyphens cut it into runs the opaque-key test does not
    # take, so the snippet showed the key.
    key = "9aea6429-b149-" + "4e24-b192-b70442594052"
    text = (
        "export class VectorConfig {\n"
        "  readonly options = {\n"
        f"    pineconeApiKey: this.configService.get<string>('PINECONE_API_KEY', '{key}'),\n"
        "  };\n"
        "}\n"
    )
    findings = _scan(run_connector, tmp_path, "src/vector.config.ts", text)
    assert key not in _snippets(findings)


def test_message_catalog_defaults_under_password_names_are_not_passwords(run_connector, tmp_path):
    # Regression: the any-shape password rule took a message catalog's default
    # ('Forgot password?') for a password, and eight of them filled the quota, so
    # an ordinary i18n module made the scan incomplete. Main reported five lines
    # and stayed complete; neither is right.
    names = ["FORGOT", "LABEL", "CONFIRM", "RESET", "NEW", "OLD", "SHOW", "HIDE"]
    texts = [
        "Forgot password?",
        "Password",
        "Confirm password",
        "Reset it",
        "New one",
        "Old one",
        "Show",
        "Hide",
    ]
    text = "".join(
        f'{name}_PASSWORD = catalog_messages.get("{name.lower()}_password", "{label}")\n'
        for name, label in zip(names, texts, strict=True)
    )
    findings = _scan(run_connector, tmp_path, "app/messages.py", text)
    assert _secret_lines(findings) == []


def test_a_configparser_option_name_is_not_a_password(run_connector, tmp_path):
    text = 'db_password = config_parser.get("database", "password")\n'
    assert _secret_lines(_scan(run_connector, tmp_path, "app/settings.py", text)) == []


def test_an_environment_read_keeps_its_password_fallback_of_any_shape(run_connector, tmp_path):
    password = "correct horse " + "battery staple"
    text = f'export const cfg = {{ dbPassword: process.env.DB_PASSWORD || "{password}" }};\n'
    findings = _scan(run_connector, tmp_path, "src/db.ts", text)
    assert _secret_lines(findings) == [1]
    assert password not in _snippets(findings)


@pytest.mark.parametrize("prefix", ["/* note */ ", "/* don't */ ", "/* a */ /* b */ ", "<!-- x --> "])
@pytest.mark.parametrize(
    "shape",
    [
        'const opts = {{ apiKey: env.KEY, other: "{key}" }};',
        'dbPassword: process.env.DB_PASSWORD?.trim() || "{password}",',
        'password: env("P", default_value="{password}")',
    ],
)
def test_a_line_after_a_closed_block_comment_is_read_as_code(prefix, shape):
    # Regression (shared with main): a block comment that closed on the line made
    # the whole rest of the line read as comment, where only key-shaped tokens are
    # withheld, so a credential name's fallback literal after it was shown.
    from shadowscan.utils.redaction import sanitize_text

    key, password = "Zx9QwEr7Ty" + "Ui3OpAs5Df", "Xk9#mQ2" + "$vL!pR7@wZ4%"
    out = sanitize_text(prefix + shape.format(key=key, password=password))
    assert key not in out and password not in out


def test_code_after_a_multiline_comment_that_closes_mid_line_is_read_alone():
    # The comment's own text ("don't */") is not read as code: its apostrophe would open
    # a literal that hid the fallback after the closer.
    from shadowscan.utils.redaction import sanitize_text

    password = "Xk9#mQ2" + "$vL!pR7@wZ4%"
    text = f"/* start\n it's don't */ dbPassword: process.env.DB_PASSWORD?.trim() || \"{password}\",\n"
    assert password not in sanitize_text(text)


def test_a_line_of_many_block_comments_is_read_in_linear_time():
    import time

    from shadowscan.utils.redaction import sanitize_text

    def cost(count: int) -> float:
        text = "apiKey = x; " + "/**/ " * count
        best = float("inf")
        for _ in range(3):
            started = time.process_time()
            sanitize_text(text)
            best = min(best, time.process_time() - started)
        return best

    small, large = cost(4_000), cost(16_000)
    assert large < max(small, 0.02) * 10, (small, large)

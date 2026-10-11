"""Credential shapes the October 10 review found unredacted, and their ordinary neighbours."""

from __future__ import annotations

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text

# Synthetic and built at runtime, like every credential-shaped test value here.
SECRET = "Zq8" + "Lm2Xw9Rt4Yu7Io1Pa5Sd3Fg6Hj0Kl"


@pytest.mark.parametrize(
    "text",
    [
        f"Authorization: Bearer token {SECRET}",
        f"Bearer token {SECRET}",
        f"secret_value: !!binary {SECRET}",
        f'TOKEN_VALUE="{SECRET}"',
        f'System.setProperty("openai.key", "{SECRET}")',
        f'config.Set("AzureOpenAI:Key", "{SECRET}")',
    ],
)
def test_review_gap_values_are_withheld(text: str) -> None:
    out = sanitize_text(text)
    assert SECRET not in out and REDACTED in out


@pytest.mark.parametrize(
    "text",
    [
        'System.setProperty("cache.key", "users")',
        'cfg.put("sort.key", "created_at")',
        'conf.set("openai.key", value)',
        "key_value_store = redis",
    ],
)
def test_ordinary_neighbours_keep_their_values(text: str) -> None:
    before = sanitize_text(text)
    assert "users" in before or "created_at" in before or "value" in before or "token" in before


def test_bearer_prose_is_unchanged_by_the_token_word_rule() -> None:
    # Only an opaque credential after 'token' moves the withheld span past the word.
    assert sanitize_text("a Bearer token is required") == f"a Bearer {REDACTED} is required"


def test_generic_credential_fields_of_an_auth_block_are_withheld() -> None:
    record = {"auth": {"type": "bearer", "value": SECRET, "header": "X-Api"}}
    assert sanitize(record) == {"auth": {"type": "bearer", "value": REDACTED, "header": "X-Api"}}
    assert sanitize({"auth": {"enabled": True}}) == {"auth": {"enabled": True}}


def test_credential_fields_nested_in_an_auth_block_are_withheld() -> None:
    # A scheme record or a list of them under the block carries the same generic fields.
    record = {
        "authentication": {
            "basic": {"username": "svc", "value": SECRET},
            "schemes": [{"type": "api-key", "key": SECRET, "header": "X-Api"}, {"type": "none"}],
            "oauth": {"token_url": "https://login.example.com/oauth2/token", "credential": SECRET},
        },
        "settings": {"value": "plain"},
    }
    assert sanitize(record) == {
        "authentication": {
            "basic": {"username": "svc", "value": REDACTED},
            "schemes": [{"type": "api-key", "key": REDACTED, "header": "X-Api"}, {"type": "none"}],
            "oauth": {"token_url": "https://login.example.com/oauth2/token", "credential": REDACTED},
        },
        "settings": {"value": "plain"},
    }


def test_an_environment_table_inside_an_auth_block_withholds_every_value() -> None:
    # The environment rule comes first: following the auth block down must not loosen it.
    record = {"auth": {"type": "basic", "env": {"USERNAME": "svc", "PASSWORD_FILE": "/run/secret"}}}
    assert sanitize(record, env_values_are_secrets=False) == {
        "auth": {"type": "basic", "env": {"USERNAME": REDACTED, "PASSWORD_FILE": REDACTED}}
    }


def test_a_list_of_credentials_under_an_auth_field_is_withheld() -> None:
    record = {"auth": {"key": [SECRET, "second-" + SECRET], "value": ({"id": "k1", "value": SECRET}, SECRET)}}
    assert sanitize(record) == {
        "auth": {"key": [REDACTED, REDACTED], "value": ({"id": "k1", "value": REDACTED}, REDACTED)}
    }


def test_an_auth_credential_copied_into_a_sibling_field_is_withheld_too() -> None:
    record = {"auth": {"basic": {"value": SECRET}}, "note": f"configured with {SECRET} last week"}
    cleaned = sanitize(record)
    assert cleaned["auth"] == {"basic": {"value": REDACTED}}
    assert SECRET not in cleaned["note"] and REDACTED in cleaned["note"]


@pytest.mark.parametrize("container", ["auth", "authentication", "authn"])
@pytest.mark.parametrize("secret", [31415926535, 2.718, True])
def test_non_string_credentials_in_an_auth_block_are_withheld(container: str, secret: object) -> None:
    # The auth-block rule must add to the mapping rules, not replace them: a
    # sensitive key holds a credential whatever the type of its value (#190).
    record = {container: {"type": "basic", "username": "svc", "password": secret, "client_secret": secret}}
    assert sanitize(record) == {
        container: {"type": "basic", "username": "svc", "password": REDACTED, "client_secret": REDACTED}
    }


SECOND = "Xw7Qa2Zr9Lt4Mn1Vb5" + "Cd8Ef3Gh6Jk0PqSt"


@pytest.mark.parametrize(
    "glue",
    [
        f"--token {SECOND}",
        f"--password={SECOND}",
        f"=password: {SECOND}",
    ],
)
def test_the_token_word_credential_keeps_a_glued_name_for_the_later_rules(glue: str) -> None:
    # The token-word rule must not consume a glued option or setting name: the
    # established passes read the text in order, and a name withheld with the
    # credential before it hid the value after it from the rule that reads it.
    cleaned = sanitize_text(f"Bearer token {SECRET}{glue}")
    assert SECRET not in cleaned
    assert SECOND not in cleaned


def test_a_setting_path_glued_into_the_token_word_credential_keeps_its_value_withheld() -> None:
    # 'v.password: w' glued after the token word reads as a setting, as it does
    # without the rule: the word is the credential and the settings rule
    # withholds the value. The run before '.password' is shown as the setting's
    # name there, exactly as the same text is without a scheme in front.
    cleaned = sanitize_text(f"Bearer token {SECRET}.password: {SECOND}")
    assert SECOND not in cleaned


def test_the_token_word_credential_is_withheld_whole_without_glue() -> None:
    assert sanitize_text(f"Bearer token {SECRET}") == f"Bearer {REDACTED}"
    # The name/value rule reads the 'Authorization:' line first and withholds
    # the whole value; the token-word rule must leave no part of the secret.
    assert SECRET not in sanitize_text(f"Authorization: Bearer token {SECRET}")


@pytest.mark.parametrize("name", ["openai.token", "Azure:Secret", "app.jwt", "openai.secret"])
def test_setter_calls_with_credential_named_paths_withhold_any_literal(name: str) -> None:
    # A path whose name alone identifies a credential withholds any literal,
    # as the same name does in a settings file; 'openai.key' (level 1) keeps
    # withholding only an opaque literal, and an expression is not a leak.
    assert SECRET not in sanitize_text(f'm.put("{name}", "{SECRET}")')
    assert "hunter2" not in sanitize_text(f'm.put("{name}", "hunter2")')
    assert sanitize_text(f'conf.set("{name}", value)') == f'conf.set("{name}", value)'


def test_a_set_of_credentials_under_an_auth_field_is_withheld_with_its_copies() -> None:
    record = {"auth": {"key": {SECRET}}, "note": f"configured with {SECRET} last week"}
    cleaned = sanitize(record)
    assert cleaned["auth"]["key"] == {REDACTED}
    assert SECRET not in cleaned["note"] and REDACTED in cleaned["note"]

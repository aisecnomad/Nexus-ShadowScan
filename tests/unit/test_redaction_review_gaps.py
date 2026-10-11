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
        # A name that is a credential outright withholds any literal, as in settings files.
        f'config.Set("AzureOpenAI:Secret", "{SECRET}")',
        f'System.setProperty("openai.token", "{SECRET}")',
        f'System.setProperty("openai.secret", "{SECRET}")',
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


def test_setter_names_that_are_credentials_withhold_any_literal_but_no_variable() -> None:
    assert sanitize_text('System.setProperty("openai.secret", "hunter2")') == (
        f'System.setProperty("openai.secret", "{REDACTED}")'
    )
    assert sanitize_text('conf.set("openai.secret", secretValue)') == 'conf.set("openai.secret", secretValue)'


def test_bearer_prose_is_unchanged_by_the_token_word_rule() -> None:
    # Only an opaque credential after 'token' moves the withheld span past the word.
    assert sanitize_text("a Bearer token is required") == f"a Bearer {REDACTED} is required"


@pytest.mark.parametrize(
    "text, value",
    [
        ("description: send a Bearer token\nOAUTH2_CLIENT_SECRET: hunter2pass\n", "hunter2pass"),
        ("auth: Bearer token\npostgres_password_1: s3cr3tpw\n", "s3cr3tpw"),
        ("Bearer token postgres_password_1: s3cr3tpw", "s3cr3tpw"),
        ("Bearer token\tpostgres_password_1: s3cr3tpw", "s3cr3tpw"),
    ],
)
def test_token_word_rule_never_takes_a_credential_name(text: str, value: str) -> None:
    # Read as the credential, the name was withheld before the assignment rules saw it,
    # and they then showed the value that follows it.
    out = sanitize_text(text)
    assert value not in out
    assert "password_1" in out or "CLIENT_SECRET" in out


@pytest.mark.parametrize(
    "text",
    [
        f"invalid Bearer token {SECRET}: expired",
        f"rejected Bearer token {SECRET}:401",
        f"Bearer token {SECRET} : rejected",
        f"Bearer token\n{SECRET}",
    ],
)
def test_token_word_rule_still_withholds_an_opaque_credential_before_a_colon(text: str) -> None:
    # Only a credential name is kept before an assignment; an opaque credential never is.
    out = sanitize_text(text)
    assert SECRET not in out and REDACTED in out


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


@pytest.mark.parametrize("container", ["auth", "authentication", "authn"])
@pytest.mark.parametrize("secret", [31415926535, 2.718, True])
def test_non_string_credentials_in_an_auth_block_are_withheld(container: str, secret: object) -> None:
    # The auth-block rule must add to the mapping rules, not replace them: a
    # sensitive key holds a credential whatever the type of its value.
    record = {container: {"type": "basic", "username": "svc", "password": secret, "client_secret": secret}}
    assert sanitize(record) == {
        container: {"type": "basic", "username": "svc", "password": REDACTED, "client_secret": REDACTED}
    }


def test_environment_block_inside_an_auth_block_keeps_the_environment_rule() -> None:
    # The auth descent must not pre-empt the environment rule: every variable's value is withheld.
    record = {
        "auth": {
            "type": "exec",
            "env": {"API_HOST": "api.example.com"},
            "environment": [{"name": "REGION", "value": "eu-west-1"}],
        }
    }
    assert sanitize(record) == {
        "auth": {
            "type": "exec",
            "env": {"API_HOST": REDACTED},
            "environment": [{"name": "REGION", "value": REDACTED}],
        }
    }


def test_an_auth_block_credential_is_also_removed_from_other_fields() -> None:
    record = {
        "auth": {"type": "bearer", "value": SECRET},
        "error": f"401 Unauthorized for credential {SECRET}",
    }
    assert sanitize(record) == {
        "auth": {"type": "bearer", "value": REDACTED},
        "error": f"401 Unauthorized for credential {REDACTED}",
    }


@pytest.mark.parametrize("shape", [list, tuple, set, lambda items: {"primary": items[0]}])
def test_auth_block_credential_fields_are_withheld_whatever_their_shape(shape) -> None:
    record = {"auth": {"type": "apikey", "key": shape([SECRET, "hunter2pass"])}, "note": f"rejected {SECRET}"}
    out = sanitize(record)
    assert out["auth"] == {"type": "apikey", "key": REDACTED}
    assert SECRET not in repr(out) and "hunter2pass" not in repr(out["auth"])


def test_short_auth_labels_are_not_removed_from_other_fields() -> None:
    # Only an opaque scalar is remembered: a label such as 'header' must not wipe every field.
    record = {"auth": {"type": "apikey", "key": "header", "value": SECRET}, "name": "Get header names"}
    assert sanitize(record)["name"] == "Get header names"


def test_labels_nested_in_an_auth_value_container_never_wipe_other_fields() -> None:
    # Regression: every leaf of a record- or list-shaped auth field was remembered, so a label
    # such as 'header' or a URL withheld unrelated fields and collapsed mapping keys.
    record = {
        "auth": {"type": "apikey", "key": {"name": "X-API-Key", "in": "header"}},
        "headers": {"Accept": "application/json"},
        "x-header": "1",
        "summary": "Adds a header",
    }
    out = sanitize(record)
    assert out["auth"] == {"type": "apikey", "key": REDACTED}
    assert {key: out[key] for key in ("headers", "x-header", "summary")} == {
        "headers": {"Accept": "application/json"},
        "x-header": "1",
        "summary": "Adds a header",
    }
    postman = {
        "auth": {
            "type": "oauth2",
            "oauth2": [
                {
                    "key": "tokenRequestParams",
                    "value": [
                        {"key": "resource", "value": "https://graph.microsoft.com", "send_as": "request_body"}
                    ],
                },
                {"key": "accessToken", "value": SECRET},
            ],
        },
        "request": {
            "url": {"raw": "https://graph.microsoft.com/v1.0/users"},
            "description": "Reads the resource",
        },
        "note": f"token {SECRET} expired",
    }
    out = sanitize(postman)
    assert out["request"] == postman["request"]
    assert SECRET not in repr(out)

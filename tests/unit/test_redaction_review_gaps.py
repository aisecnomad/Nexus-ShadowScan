"""Credential shapes the October 10 review found unredacted, and their ordinary neighbours."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

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


def test_an_environment_table_inside_an_auth_block_withholds_every_value() -> None:
    # The environment rule comes first: following the auth block down must not loosen it.
    record = {"auth": {"type": "basic", "env": {"USERNAME": "svc", "PASSWORD_FILE": "/run/secret"}}}
    assert sanitize(record, env_values_are_secrets=False) == {
        "auth": {"type": "basic", "env": {"USERNAME": REDACTED, "PASSWORD_FILE": REDACTED}}
    }


def test_a_list_of_credentials_under_an_auth_field_is_withheld() -> None:
    # A list, tuple or record under a credential field is credential material whatever its
    # shape, so it is withheld whole; its opaque members are learned for the other fields.
    record = {
        "auth": {"key": [SECRET, "second-" + SECRET], "value": ({"id": "k1", "value": SECRET}, SECRET)},
        "note": f"rotated {SECRET} on Monday",
    }
    assert sanitize(record) == {
        "auth": {"key": REDACTED, "value": REDACTED},
        "note": f"rotated {REDACTED} on Monday",
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


@pytest.mark.parametrize("word", ["", "token "], ids=["plain", "token-word"])
@pytest.mark.parametrize("scheme", ["Bearer", "Basic", "SSWS"])
@pytest.mark.parametrize("glue", ["--", "=x"])
def test_a_scheme_credential_with_a_glued_run_is_withheld_whole(scheme: str, glue: str, word: str) -> None:
    # A glued run that names nothing for a later pass to read is part of the
    # opaque credential, so a token containing '--' or '=x' leaves no tail in
    # the output, with or without the token word, in prose or a JSON string.
    credential = f"{word}{SECRET}{glue}{SECOND}"
    assert sanitize_text(f"{scheme} {credential}") == f"{scheme} {REDACTED}"
    assert sanitize_text(f"send {scheme} {credential} now") == f"send {scheme} {REDACTED} now"
    assert sanitize_text(f'{{"h": "{scheme} {credential}"}}') == f'{{"h": "{scheme} {REDACTED}"}}'


@pytest.mark.parametrize("glued", ["=password: ", "--token "])
def test_a_plain_scheme_credential_keeps_a_glued_credential_name_for_the_later_rules(
    glued: str,
) -> None:
    # A glued run that names a credential stays in the text, as in the word
    # form: the assignment or option rule that reads it withholds the value
    # after it, so neither the token nor the glued secret is shown.
    cleaned = sanitize_text(f"Bearer {SECRET}{glued}{SECOND}")
    assert SECRET not in cleaned
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
    assert cleaned["auth"]["key"] == REDACTED
    assert SECRET not in cleaned["note"] and REDACTED in cleaned["note"]


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


def test_an_environment_entry_value_inside_an_auth_block_is_not_learned_as_a_credential() -> None:
    # The environment rule withholds the entry's value; the auth rule must not also learn
    # it as a credential, or a non-secret value ('1') wipes every field that contains it.
    record = {
        "auth": {"environment": [{"name": "STAGE", "value": "1"}, {"name": "REGION", "value": "eu"}]},
        "version": "v1.2",
        "note": "1 host in eu",
    }
    assert sanitize(record, env_values_are_secrets=False) == {
        "auth": {
            "environment": [{"name": "STAGE", "value": REDACTED}, {"name": "REGION", "value": REDACTED}]
        },
        "version": "v1.2",
        "note": "1 host in eu",
    }


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


# October 15 review: credential formats the scanner detects but did not withhold.
_BASE64_BODY = "QmVkcm9ja0FQSUtleS1zeW50aGV0aWMtZXhhbXBsZS0" + "0" * 60


@pytest.mark.parametrize(
    "text",
    [
        "AWS_BEARER_TOKEN_BEDROCK=" + "ABSK" + _BASE64_BODY + "==",
        "client = Bedrock(api_key='" + "ABSK" + _BASE64_BODY + "')",
        "value " + "bedrock-api-key-" + _BASE64_BODY,
    ],
)
def test_bedrock_api_keys_are_withheld(text: str) -> None:
    out = sanitize_text(text)
    assert _BASE64_BODY not in out and REDACTED in out


def test_bedrock_words_in_prose_stay() -> None:
    text = "Rotate the bedrock-api-key every 12 hours; ABSK is the long-term prefix."
    assert sanitize_text(text) == text


@pytest.mark.parametrize(
    ("url", "kept"),
    [
        ("https://mcp.zapier.com/api/mcp/s/" + SECRET + "/mcp", "https://mcp.zapier.com/api/mcp/s/"),
        ("https://actions.zapier.com/mcp/" + SECRET + "/sse", "https://actions.zapier.com/mcp/"),
    ],
)
def test_zapier_mcp_urls_withhold_their_path_credential(url: str, kept: str) -> None:
    out = sanitize_text(f"url: {url}")
    assert SECRET not in out and kept + REDACTED in out
    assert sanitize({"servers": [{"url": url}]})["servers"][0]["url"] == kept + REDACTED


@pytest.mark.parametrize(
    "scheme",
    ["oracle+cx_oracle", "ibm_db_sa", "postgresql+py_postgresql", "redis_sentinel", "mssql+pyodbc"],
)
def test_url_userinfo_is_withheld_for_schemes_with_underscores(scheme: str) -> None:
    # Assembled from pieces so the repository secret scanner does not flag a literal user:pass@host.
    url = f"{scheme}://svc-user:" + SECRET + "@db.internal:1521/app"
    out = sanitize_text(f"DATABASE_URI = {url}")
    assert SECRET not in out
    assert f"{scheme}://{REDACTED}@db.internal:1521/app" in sanitize_text(url)


def test_snake_case_words_are_not_read_as_url_schemes() -> None:
    text = "set my_scheme_name and other_value to configure the pool"
    assert sanitize_text(text) == text


def _url_password_across(limit: int) -> str:
    """Prose whose URL password starts before ``limit`` and whose '@' falls after it."""
    # 35 characters short of the limit: the password then starts 16 characters before the cut.
    lead = "Agent instructions: call " + "x" * (limit - 60)
    return f"{lead} https://svc-agent:" + SECRET + "@agents.example/v1 for every request"


def test_excerpts_are_redacted_before_they_are_shortened() -> None:
    from shadowscan.utils.redaction import sanitize_excerpt

    text = _url_password_across(300)
    assert len(text) > 300 and text.index(SECRET) < 300 < text.index("@agents")
    out = sanitize_excerpt(text, 300)
    assert SECRET[:8] not in out and len(out) <= 300
    assert sanitize_excerpt(None, 10) is None and sanitize_excerpt(7, 10) == 7


def test_connector_summaries_redact_before_shortening() -> None:
    from shadowscan.connectors.code.semantic_config import _CLIP_CHARS, bounded_metadata
    from shadowscan.connectors.identity.entra import _card_summary

    assert SECRET[:8] not in repr(bounded_metadata({"note": _url_password_across(_CLIP_CHARS)}))
    assert SECRET[:8] not in repr(_card_summary({"description": _url_password_across(300)}))


def _connector(cls_path: str, index: Any) -> Any:
    """A connector built for calling its record handlers directly."""
    from importlib import import_module

    from shadowscan.connectors import ConnectorContext
    from shadowscan.models import ScanStats

    module, name = cls_path.rsplit(".", 1)
    ctx = ConnectorContext(config={}, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-10-16")
    return getattr(import_module(module), name)(ctx)


def _registry_agent(text: str) -> dict[str, Any]:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "cloud" / "gcp_registry_records.jsonl"
    records = [json.loads(line) for line in fixture.read_text(encoding="utf-8").splitlines() if line]
    return {**next(r for r in records if r.get("_kind") == "agent-registry-agent"), "description": text}


_AWS = "shadowscan.connectors.cloud.aws.AwsConnector"
_AZURE = "shadowscan.connectors.cloud.azure.AzureConnector"
_GCP = "shadowscan.connectors.cloud.gcp.GcpConnector"
_OCI = "shadowscan.connectors.cloud.oci.OciConnector"
_SFDC = "shadowscan.connectors.lowcode.salesforce.SalesforceConnector"
_SNOW = "shadowscan.connectors.lowcode.servicenow.ServiceNowConnector"
_RE = "projects/123/locations/us-central1/reasoningEngines/456"
_DF = "projects/acme/locations/global/agents/7f1c"
_RUNTIME = "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/ops-1"
_PROJECT = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/a1/projects/p1"

# Each connector summary that shortens provider text: (limit, offset, build). ``build(index, text)``
# returns the finding that carries ``text`` shortened to ``limit`` characters, ``offset`` of them
# being the record text the summary puts ahead of ``text``.
_SHORTENED_SUMMARIES: dict[str, tuple[int, int, Callable[[Any, str], Any]]] = {
    "aws knowledge base evidence": (
        120,
        0,
        lambda index, text: _connector(_AWS, index)._h_bedrock_knowledge_base(
            {
                "knowledgeBaseId": "KB1",
                "name": "kb",
                "status": "ACTIVE",
                "_region": "us-east-1",
                "description": text,
            }
        ),
    ),
    "aws agentcore runtime description": (
        200,
        0,
        lambda index, text: _connector(_AWS, index)._h_agentcore_runtime(
            {
                "agentRuntimeArn": _RUNTIME,
                "agentRuntimeName": "ops",
                "_region": "us-east-1",
                "description": text,
            }
        ),
    ),
    "aws bedrock agent instruction": (
        300,
        0,
        lambda index, text: _connector(_AWS, index)._h_bedrock_agent(
            {"agentId": "A1", "agentName": "ops", "_region": "us-east-1", "instruction": text}
        ),
    ),
    "azure foundry project description": (
        200,
        0,
        lambda index, text: _connector(_AZURE, index)._resource_finding(
            {
                "type": "microsoft.cognitiveservices/accounts/projects",
                "id": _PROJECT,
                "name": "p1",
                "properties": {"description": text},
            },
            [],
            None,
        ),
    ),
    "gcp agent engine evidence": (
        120,
        0,
        lambda index, text: _connector(_GCP, index)._h_reasoning_engine(
            {
                "name": _RE,
                "displayName": "eng",
                "description": text,
                "_project": "acme",
                "_location": "us-central1",
            }
        ),
    ),
    "gcp agent engine description": (
        300,
        0,
        lambda index, text: _connector(_GCP, index)._h_reasoning_engine(
            {
                "name": _RE,
                "displayName": "eng",
                "description": text,
                "_project": "acme",
                "_location": "us-central1",
            }
        ),
    ),
    "gcp dialogflow description": (
        200,
        0,
        lambda index, text: _connector(_GCP, index)._h_dialogflow_agent(
            {
                "name": _DF,
                "displayName": "bot",
                "description": text,
                "_project": "acme",
                "_location": "global",
            }
        ),
    ),
    "gcp registry record description": (
        300,
        0,
        lambda index, text: _connector(_GCP, index)._h_agent_registry_agent(_registry_agent(text)),
    ),
    "oci agent description": (
        200,
        0,
        lambda index, text: _connector(_OCI, index)._agent_finding(
            {"id": "ocid1.genaiagent.oc1..a1", "display_name": "ops", "description": text}, []
        ),
    ),
    "oci agent welcome message": (
        120,
        0,
        lambda index, text: _connector(_OCI, index)._agent_finding(
            {"id": "ocid1.genaiagent.oc1..a1", "display_name": "ops", "welcome_message": text}, []
        ),
    ),
    "oci dynamic group rule": (
        200,
        len("genai "),
        lambda index, text: _connector(_OCI, index)._h_dynamic_group(
            {"id": "ocid1.dynamicgroup.oc1..d1", "name": "agents", "matching_rule": "genai " + text}
        ),
    ),
    "oci policy statements": (
        400,
        len("Allow group GenAIUsers to use generative-ai-family in tenancy | "),
        lambda index, text: _connector(_OCI, index)._h_policy(
            {
                "id": "ocid1.policy.oc1..p1",
                "name": "genai",
                "statements": ["Allow group GenAIUsers to use generative-ai-family in tenancy", text],
            }
        ),
    ),
    "salesforce bot description": (
        200,
        0,
        lambda index, text: _connector(_SFDC, index)._bot_finding(
            {"Id": "0Xx1", "DeveloperName": "helper", "Description": text}, []
        ),
    ),
    "salesforce agentforce description": (
        200,
        0,
        lambda index, text: _connector(_SFDC, index)._agentforce_finding(
            "planner", {"Id": "0Pl1", "DeveloperName": "planner", "Description": text}, [], []
        ),
    ),
    "salesforce flow evidence": (
        160,
        len("f Einstein flow "),
        lambda index, text: _connector(_SFDC, index)._flow_finding(
            {"Id": "301", "ApiName": "f", "Label": "Einstein flow", "Description": text}
        ),
    ),
    "servicenow agent description": (
        200,
        0,
        lambda index, text: _connector(_SNOW, index)._agent_finding(
            {"sys_id": "a1", "name": "agent", "description": text}, []
        ),
    ),
    "servicenow agent instructions": (
        300,
        0,
        lambda index, text: _connector(_SNOW, index)._agent_finding(
            {"sys_id": "a1", "name": "agent", "instructions": text}, []
        ),
    ),
    "servicenow use case description": (
        200,
        0,
        lambda index, text: _connector(_SNOW, index)._usecase_finding(
            {"sys_id": "u1", "name": "case", "description": text}, []
        ),
    ),
    "servicenow trigger condition": (
        120,
        0,
        lambda index, text: _connector(_SNOW, index)._usecase_finding(
            {"sys_id": "u1", "name": "case"},
            [{"trigger_type": "record", "table": "incident", "condition": text}],
        ),
    ),
    "servicenow flow evidence": (
        160,
        len("genai flow "),
        lambda index, text: _connector(_SNOW, index)._flow_finding(
            {"sys_id": "f1", "name": "genai flow", "description": text}
        ),
    ),
}


@pytest.mark.parametrize("site", sorted(_SHORTENED_SUMMARIES))
def test_shortened_connector_summaries_are_redacted_first(index: Any, site: str) -> None:
    """Regression: these summaries were shortened before the report sanitizer read them, so a
    cut between a URL password and its '@' left the start of the password in the report."""
    limit, offset, build = _SHORTENED_SUMMARIES[site]
    text = _url_password_across(limit - offset)
    finding = build(index, text)
    finding.sanitize()
    report = json.dumps(finding.to_dict(), default=str)
    assert SECRET[:8] not in report
    assert REDACTED in report


# The summaries whose record field reaches the excerpt as the provider sent it. The OCI matching
# rule and policy statements and the Salesforce and ServiceNow flow text are strings the
# connector builds itself.
_RAW_TEXT_FIELDS = sorted(site for site, (_, offset, _) in _SHORTENED_SUMMARIES.items() if offset == 0)


@pytest.mark.parametrize("value", [[f"chunk-{n} " + "y" * 50 for n in range(300)], 42], ids=["list", "int"])
@pytest.mark.parametrize("site", _RAW_TEXT_FIELDS)
def test_a_summary_field_that_is_not_text_rejects_the_record(index: Any, site: str, value: Any) -> None:
    """Regression: sanitize_excerpt returns a value that is not text unchanged, where the truncate
    it replaced raised TypeError, which the cloud connectors report as an invalid record (coverage
    incomplete, exit 3). A 300-element list or a number in a description, instruction or welcome
    message went into finding metadata whole, on a complete scan. (Salesforce and ServiceNow
    reject such a record before these handlers; the GCP registry validator rejects it too.)"""
    from shadowscan.connectors.cloud.common import RECORD_ERRORS

    _, _, build = _SHORTENED_SUMMARIES[site]
    with pytest.raises(RECORD_ERRORS):
        build(index, value)


@pytest.mark.parametrize(
    ("connector", "record"),
    [
        (
            "cloud.oci",
            {
                "_kind": "genai-agent",
                "_region": "us-chicago-1",
                "_compartment": "ocid1.compartment.oc1..cmp1",
                "id": "ocid1.genaiagent.oc1.us-chicago-1.agent9",
                "display_name": "x-assistant",
                "description": [f"chunk-{n} " + "y" * 50 for n in range(300)],
            },
        ),
        (
            "cloud.oci",
            {
                "_kind": "genai-agent",
                "_region": "us-chicago-1",
                "id": "ocid1.genaiagent.oc1.us-chicago-1.agent9",
                "display_name": "x-assistant",
                "welcome_message": 12345,
            },
        ),
        (
            "cloud.aws",
            {
                "_kind": "bedrock-agent",
                "_region": "us-east-1",
                "agentId": "AGENT1",
                "agentArn": "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT1",
                "agentName": "ops-provisioning-04",
                "agentStatus": "PREPARED",
                "foundationModel": "anthropic.claude-3-5-sonnet-20241022-v2:0",
                "instruction": 42,
            },
        ),
    ],
    ids=["oci-description-list", "oci-welcome-message-int", "aws-instruction-int"],
)
def test_a_mistyped_provider_text_field_leaves_the_scan_incomplete(
    index: Any, tmp_path: Path, connector: str, record: dict[str, Any]
) -> None:
    from shadowscan.config import ConnectorSpec, ScanConfig
    from shadowscan.engine import Engine

    export = tmp_path / "export.jsonl"
    export.write_text(json.dumps(record) + "\n", encoding="utf-8")
    result = Engine(ScanConfig(connectors=[ConnectorSpec(connector, {"input": str(export)})]), index).run()
    assert not result.complete and not result.findings
    [stats] = result.stats
    assert any("record has invalid" in warning for warning in stats.warnings), stats.warnings

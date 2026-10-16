"""Regressions for credential exposure, report injection and scan completeness."""

from __future__ import annotations

import csv
import datetime
import hashlib
import io
import json
import re
import stat

import jwt
import pytest
from rich.console import Console

from shadowscan.comparison import IDENTITY_KEY_ENV, compare_reports
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.connectors.code.filesystem import _excerpt
from shadowscan.connectors.identity.jwt import JwtConnector
from shadowscan.connectors.saas.generic import GenericSaaSConnector
from shadowscan.engine import Engine
from shadowscan.models import FINDING_IDENTITY_SCHEMA, Evidence, Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.reporters import render
from shadowscan.reporters.csv_ import render_csv
from shadowscan.reporters.table import print_table
from shadowscan.signatures.loader import Signature
from shadowscan.signatures.matcher import SignatureIndex
from shadowscan.utils import redaction_formats
from shadowscan.utils.credential_identity import (
    credential_identity_scope,
    reset_credential_identity_key,
    set_credential_identity_key,
)
from shadowscan.utils.redaction import REDACTED, credential_id, sanitize, sanitize_text

SECRET = "opaque-synthetic-credential-value"
PROVIDER_KEY = "sk-proj-syntheticcredentialvaluenotarealkey"


def _index():
    return SignatureIndex([Signature(id="framework.test", name="Test", category="framework")])


def _finding(**kwargs):
    return Finding(
        surface=Surface.CODE,
        connector="test",
        kind=Kind.AGENT,
        title=kwargs.pop("title", "Agent"),
        resource="repo:example",
        resource_type="repository",
        **kwargs,
    )


def test_sanitizes_structured_credentials_urls_argv_and_copies():
    original = {
        "api_key": SECRET,
        "note": f"debug copy {SECRET}",
        "config": {
            "env": {"CUSTOM_CREDENTIAL_NAME": SECRET, "MODE": "debug"},
            "args": ["--token", SECRET, "--model", "gpt-example", "PASSWORD='a value with spaces'"],
            "url": f"https://user:{SECRET}@example.com/path?token={SECRET}&model=gpt-example",
        },
        "environment": "production",
        "repository": "org/repo",
        "deployment_id": "deploy-1",
        "events": 15,
        "capabilities": ["tool-use", "memory"],
    }
    result = sanitize(original)
    assert SECRET not in json.dumps(result)
    assert "a value with spaces" not in json.dumps(result)
    assert result["config"]["env"] == {"CUSTOM_CREDENTIAL_NAME": REDACTED, "MODE": REDACTED}
    assert result["config"]["args"][3] == "gpt-example"
    assert "model=gpt-example" in result["config"]["url"]
    for key in ("environment", "repository", "deployment_id", "events", "capabilities"):
        assert result[key] == original[key]
    assert sanitize(result) == result
    assert original["api_key"] == SECRET  # analysis still receives the original input


@pytest.mark.parametrize(
    "record",
    [
        {"env": [{"name": "PASSWORD", "value": SECRET}]},
        {"environment": [{"name": "CUSTOM_NAME", "value": SECRET}]},
        {"Environment": {"Variables": {"CUSTOM_NAME": SECRET}}},
        {"key": "OPENAI_API_KEY", "value": SECRET},
        {"Name": "CLIENT_SECRET", "Value": SECRET},
        {"SecretString": SECRET},
        {"keyString": SECRET},
        {"privateKeyData": SECRET},
    ],
)
def test_cloud_environment_and_name_value_exports(record):
    assert SECRET not in json.dumps(sanitize(record))


def test_gcp_api_key_string_never_reaches_report_or_record_dump(tmp_path, index):
    secret = "opaque-private-google-api-value-123"
    export = tmp_path / "api-keys.jsonl"
    export.write_text(
        json.dumps(
            {
                "_kind": "api-key",
                "_project": "test-project",
                "name": "projects/test-project/locations/global/keys/example",
                "displayName": "Gemini service",
                "keyString": secret,
            }
        )
        + "\n"
    )
    dumped = tmp_path / "dumped"
    config = ScanConfig(
        connectors=[ConnectorSpec("cloud.gcp", {"input": str(export)})], dump_records=str(dumped)
    )
    result = Engine(config, index).run()
    assert result.complete
    assert any(finding.kind == Kind.SECRET for finding in result.findings)
    dump_files = list(dumped.glob("*.jsonl"))
    assert len(dump_files) == 1
    assert json.loads(dump_files[0].read_text())["keyString"] == REDACTED
    assert secret not in result.to_json() and secret not in dump_files[0].read_text()


def test_generic_saas_record_dump_withholds_fields_named_for_a_credential_by_their_words(tmp_path, index):
    names = [
        "webhook_secret",
        "signing_secret",
        "bot_token",
        "slack_token",
        "npm_token",
        "client_key",
        "consumer_secret",
        "openai_key",
        "authorization_token",
        "verification_token",
        "pwd",
        "passphrase",
        "db_pass",
        "security_token",
        "jwtSecret",
        "access_secret",
    ]
    secrets = {name: f"synthetic-{name}-value-0123456789" for name in names}
    export = tmp_path / "apps.jsonl"
    record = {"id": "app-1", "name": "Slack bot", "users": 4, "next_token": "page-2"}
    export.write_text(json.dumps({**record, **secrets}) + "\n")
    dumped = tmp_path / "dumped"
    config = ScanConfig(
        connectors=[ConnectorSpec("saas.generic", {"input": str(export)})], dump_records=str(dumped)
    )
    result = Engine(config, index).run()
    assert result.complete
    (dump_file,) = dumped.glob("*.jsonl")
    row = json.loads(dump_file.read_text())
    assert {name: row[name] for name in names} == dict.fromkeys(names, REDACTED)
    assert {key: row[key] for key in record} == record
    assert not any(secret in dump_file.read_text() for secret in secrets.values())


@pytest.mark.parametrize(
    "value",
    [
        f'OPENAI_API_KEY = "{PROVIDER_KEY}"',
        f'password="{SECRET}"',
        f'wrapper = "api_key={SECRET}"',
        f"Authorization: Bearer {SECRET}",
        f"https://example.com?api_key={SECRET}&safe=yes",
        f"https://example.com?%61pi_key={SECRET}&safe=yes",
        f"https://user:{SECRET}@example.com/path",
        "-----BEGIN PRIVATE KEY-----\n" + SECRET + "\n-----END PRIVATE KEY-----",
    ],
)
def test_text_redaction_idempotent(value):
    result = sanitize_text(value)
    assert SECRET not in result and PROVIDER_KEY not in result
    assert sanitize_text(result) == result


def test_credential_fingerprint_is_stable_nonsecret_and_survives_sanitization():
    identity = credential_id(SECRET)
    assert identity == credential_id(SECRET) == credential_id(identity)
    assert identity != credential_id(SECRET + "other")
    assert SECRET not in identity
    assert sanitize({"api_key": identity, "caller": identity}) == {"api_key": identity, "caller": identity}


def test_credential_pseudonym_uses_a_private_key_and_restores_nested_context():
    candidate = "copper-73-moon"
    public = "credential:sha256:" + hashlib.sha256(candidate.encode()).hexdigest()
    token = set_credential_identity_key(b"a" * 32)
    try:
        first = credential_id(candidate)
        assert first.startswith("credential:hmac-sha256:") and first != public
        assert credential_id(first) == first and credential_id(public) != public
        assert sanitize_text("--token " + first) == "--token " + first
        nested = set_credential_identity_key(b"b" * 32)
        try:
            assert credential_id(candidate) != first
        finally:
            reset_credential_identity_key(nested)
        assert credential_id(candidate) == first
    finally:
        reset_credential_identity_key(token)


def test_credential_identity_scope_follows_the_active_key():
    assert credential_identity_scope() == "run"
    token = set_credential_identity_key(b"a" * 32, stable=True)
    try:
        assert credential_identity_scope() == "keyed"
        nested = set_credential_identity_key(b"b" * 32)
        try:
            assert credential_identity_scope() == "run"
        finally:
            reset_credential_identity_key(nested)
        assert credential_identity_scope() == "keyed"
    finally:
        reset_credential_identity_key(token)
    assert credential_identity_scope() == "run"


@pytest.mark.parametrize("key", [b"", b"short", "a" * 32, None])
def test_credential_identity_context_rejects_unusable_keys(key):
    with pytest.raises(ValueError, match="32 secret bytes"):
        set_credential_identity_key(key)


def test_finding_and_serialization_sanitize_sibling_evidence():
    f = _finding(
        title=f"Agent {PROVIDER_KEY}",
        metadata={"api_key": SECRET, "repository": "org/repo"},
        evidence=[
            Evidence(
                signal="import",
                description=f"copy {SECRET}",
                snippet=f"import langchain; KEY='{PROVIDER_KEY}'",
            )
        ],
        capabilities=["tool-use"],
    )
    assert SECRET not in str(f.evidence)
    assert PROVIDER_KEY not in f.title
    f.metadata["password"] = SECRET
    f.title = f"Agent {PROVIDER_KEY}"
    result = f.to_dict()
    assert SECRET not in json.dumps(result) and PROVIDER_KEY not in json.dumps(result)
    assert f.capabilities == ["tool-use"] and f.metadata["repository"] == "org/repo"


class _RecordConnector(BaseConnector):
    name = "test.records"

    def collect(self):
        yield {"api_key": SECRET, "debug": SECRET, "environment": "production"}

    def analyze(self, records):
        for record in records:
            self.ctx.examined()
            finding = _finding()
            finding.metadata = record
            yield finding


def test_export_is_sanitized_atomic_and_owner_only(tmp_path):
    target = tmp_path / "records.jsonl"
    target.write_text("old contents")
    target.chmod(0o644)
    connector = _RecordConnector(ConnectorContext(config={"_dump_path": str(target)}, index=_index()))
    findings = connector.run()
    assert SECRET not in target.read_text()
    assert SECRET not in str(findings)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert json.loads(target.read_text())["environment"] == "production"
    assert list(tmp_path.iterdir()) == [target]
    assert not connector.ctx.stats.errors


def test_jwt_dump_never_writes_token_records(tmp_path):
    target = tmp_path / "jwt.jsonl"
    token = jwt.encode(
        {"sub": "agent", "agent_id": "agent-1"},
        "synthetic-test-signing-key-only-32-bytes",
        algorithm="HS256",
    )
    connector = JwtConnector(
        ConnectorContext(
            config={"tokens": [token], "_dump_path": str(target)},
            index=_index(),
        )
    )
    findings = connector.run()
    assert len(findings) == 1 and not connector.ctx.stats.errors
    assert not target.exists()
    assert token not in json.dumps(findings[0].to_dict())
    assert findings[0].metadata["agent_claims"]["agent_id"] == "agent-1"


def test_generic_saas_does_not_copy_arbitrary_export_columns():
    connector = GenericSaaSConnector(ConnectorContext(config={"keep_all": True}, index=_index()))
    result = list(
        connector.analyze(
            [
                {"name": "Agent", "id": "app-1", "users": 4, "custom_private_column": SECRET},
            ]
        )
    )
    assert len(result) == 1
    assert SECRET not in json.dumps(result[0].to_dict())
    assert result[0].metadata["users"] == 4
    assert "raw" not in result[0].metadata


@pytest.mark.parametrize("fmt", ["json", "html", "markdown", "csv", "sarif", "cyclonedx", "ocsf", "table"])
def test_generic_saas_preserves_record_credential_context_in_all_reports(fixtures, tmp_path, index, fmt):
    source = fixtures / "saas" / "generic_review_credentials.json"
    dumped = tmp_path / "dumped"
    result = Engine(
        ScanConfig(
            connectors=[ConnectorSpec("saas.generic", {"input": str(source)})],
            dump_records=str(dumped),
        ),
        index,
    ).run()
    assert result.complete and len(result.findings) == 1
    finding = result.findings[0]
    assert finding.resource == "saas:app:app-1"
    assert finding.frameworks and "files:read" in finding.permissions
    assert REDACTED in finding.title and "Claude" in finding.title
    if fmt == "table":
        output = io.StringIO()
        print_table(result, console=Console(file=output, width=180))
        rendered = output.getvalue()
    else:
        rendered = render(result, fmt)
    assert SECRET not in rendered
    assert SECRET not in result.to_json()
    assert "not-for-publication" not in result.to_json()
    (dump_file,) = dumped.glob("*.jsonl")
    assert SECRET not in dump_file.read_text()
    assert json.loads(source.read_text())[0]["api_key"] == SECRET


@pytest.mark.parametrize("separator", [" ", ",", ";"])
def test_generic_saas_removes_known_credentials_before_splitting_scopes(index, separator):
    credential = separator.join(["privatefragmentone", "privatefragmenttwo"])
    connector = GenericSaaSConnector(ConnectorContext(index=index))
    (finding,) = connector.analyze(
        [{"id": "app-1", "name": "Claude", "scopes": credential, "api_key": credential}]
    )
    report = json.dumps(finding.to_dict())
    assert "privatefragmentone" not in report and "privatefragmenttwo" not in report


def test_generic_saas_removes_known_credentials_before_scope_excerpt_truncation(index):
    credential = "privatefragment" * 30
    connector = GenericSaaSConnector(ConnectorContext(index=index))
    (finding,) = connector.analyze(
        [{"id": "app-1", "name": "Claude", "scopes": [credential], "api_key": credential}]
    )
    assert "privatefragment" not in json.dumps(finding.to_dict())


def test_generic_saas_credential_values_do_not_establish_app_identity(index):
    connector = GenericSaaSConnector(ConnectorContext(index=index))
    connector.ctx.stats = ScanStats(connector="saas.generic", started_at="now")
    credential = "Claude-7Kq2Lp9x"
    assert not list(connector.analyze([{"id": "app-1", "name": credential, "api_key": credential}]))
    # Nothing of the name is left to classify: incomplete, never a silent omission.
    assert connector.ctx.stats.incomplete
    assert any("withheld its name" in warning for warning in connector.ctx.stats.warnings)


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize(
    "value",
    [
        "N",
        "Y",
        "-",
        "a",
        "e",
        "Yes",
        "N/A",
        "none",
        "****",
        "changeme",
        "xxxxxxxx",
        "xxxxxxxxxxxx",
        "your_client_secret",
        "<client-secret>",
        "${CLIENT_SECRET}",
        "NULL",
        "TODO",
        "XXXX",
        "<api_key>",
        "your-api_key",
    ],
)
def test_generic_saas_credential_flags_and_placeholders_do_not_withhold_fields(index, value, nested):
    # Flags and whole-value placeholders. Learned as credentials, they withheld every
    # field containing them: the name (so the app was silently not reported), dates, the
    # resource type (so the finding was omitted) and columns holding the same flag.
    connector = GenericSaaSConnector(ConnectorContext(index=index))
    connector.ctx.stats = ScanStats(connector="saas.generic", started_at="now")
    record = {
        "id": "app-7",
        "name": "ChatGPT Notion Connector",
        "installed_at": "2025-01-02",
        "status": value,
        **(
            {"credentials": {"client_secret": value, "enabled": value}}
            if nested
            else {"client_secret": value}
        ),
    }
    (finding,) = connector.analyze([record])
    assert finding.title == "saas app: ChatGPT Notion Connector"
    assert finding.resource == "saas:app:app-7" and finding.id == finding.compute_id()
    assert finding.first_seen == "2025-01-02" and finding.metadata["status"] == value
    assert "identity_scope" not in finding.metadata
    assert not connector.ctx.stats.incomplete


def test_generic_saas_csv_credential_flags_keep_findings_and_completeness(tmp_path, index):
    export = tmp_path / "apps.csv"
    export.write_text(
        "id,name,publisher,url,scopes,installed_at,status,client_secret\n"
        "app-1,ChatGPT Notion Connector,OpenAI,https://chatgpt.com,,2025-01-02,approved,N\n"
        "app-7,Claude for Sheets,Anthropic,https://claude.ai/sheets,spreadsheets.readonly,2025-01-02,approved,-\n"
        "app-8,ChatGPT for Slack,OpenAI,https://chatgpt.com,chat:write,2025-02-03,approved,s3cr3t-value-long\n",
        encoding="utf-8",
    )
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("saas.generic", {"input": str(export)})]), index
    ).run()
    assert result.complete, result.stats[0].warnings
    assert sorted((f.title, f.resource, f.first_seen) for f in result.findings) == [
        ("saas app: ChatGPT Notion Connector", "saas:app:app-1", "2025-01-02"),
        ("saas app: ChatGPT for Slack", "saas:app:app-8", "2025-02-03"),
        ("saas app: Claude for Sheets", "saas:app:app-7", "2025-01-02"),
    ]


def test_generic_saas_name_withheld_by_a_credential_is_incomplete(tmp_path, index):
    export = tmp_path / "apps.csv"
    export.write_text(
        "id,name,api_key\napp-1,ChatGPT-9fQ2xLm7,ChatGPT-9fQ2xLm7\napp-2,Claude for Sheets,\n",
        encoding="utf-8",
    )
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("saas.generic", {"input": str(export)})]), index
    ).run()
    assert not result.complete
    assert [finding.title for finding in result.findings] == ["saas app: Claude for Sheets"]
    assert any("withheld its name" in warning for warning in result.stats[0].warnings)
    assert "9fQ2xLm7" not in result.to_json()


def _generic_scan(tmp_path, index, rows):
    export = tmp_path / "apps.json"
    export.write_text(json.dumps(rows), encoding="utf-8")
    return Engine(ScanConfig(connectors=[ConnectorSpec("saas.generic", {"input": str(export)})]), index).run()


def _unkeyed_identity_digest(resource):
    identity = [FINDING_IDENTITY_SCHEMA, "saas", "saas.generic", "saas", None, None, resource, "saas-app"]
    raw = json.dumps(identity, separators=(",", ":"), ensure_ascii=True)
    return "ss-" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def test_generic_saas_redacted_resource_id_is_keyed_and_scan_local(tmp_path, index, monkeypatch):
    monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
    rows = [{"name": "Claude Summer2024!", "password": "Summer2024!"}]
    first, second = _generic_scan(tmp_path, index, rows), _generic_scan(tmp_path, index, rows)
    assert first.complete and second.complete
    (one,), (two,) = first.findings, second.findings
    assert one.resource == two.resource == "saas:app:Claude [REDACTED]"
    # A public digest of the raw resource would confirm a guessed credential offline.
    assert one.id != _unkeyed_identity_digest("saas:app:Claude Summer2024!")
    assert one.id != one.compute_id()
    assert one.id != two.id
    assert one.metadata["identity_scope"] == two.metadata["identity_scope"] == "run"
    comparison = compare_reports(first.to_dict(), second.to_dict())
    assert not comparison["comparable"]
    assert comparison["new"] == comparison["resolved"] == []
    assert {side: [f["id"] for f in found] for side, found in comparison["not_comparable"].items()} == {
        "baseline": [one.id],
        "current": [two.id],
    }

    monkeypatch.setenv(IDENTITY_KEY_ENV, f"hex:{bytes(range(32)).hex()}")
    first, second = _generic_scan(tmp_path, index, rows), _generic_scan(tmp_path, index, rows)
    (one,), (two,) = first.findings, second.findings
    assert one.id == two.id and one.metadata["identity_scope"] == "keyed"
    assert one.id != _unkeyed_identity_digest("saas:app:Claude Summer2024!")
    comparison = compare_reports(first.to_dict(), second.to_dict())
    assert comparison["comparable"] and comparison["new"] == comparison["resolved"] == []


def test_generic_saas_unredacted_resource_keeps_its_resource_digest(tmp_path, index, monkeypatch):
    monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
    rows = [{"id": "app-1", "name": "Claude Summer2024!", "password": "Summer2024!"}]
    (one,), (two,) = (
        _generic_scan(tmp_path, index, rows).findings,
        _generic_scan(tmp_path, index, rows).findings,
    )
    assert one.title == "saas app: Claude [REDACTED]" and one.resource == "saas:app:app-1"
    assert one.id == two.id == one.compute_id() == _unkeyed_identity_digest("saas:app:app-1")
    assert "identity_scope" not in one.metadata


# looks_like_placeholder() calls these documentation examples: a word such as here, Test or
# Demo, or a sequence such as Abcd1234 or 12345678. Under a credential name they are
# credentials; only a placeholder as a whole value is not.
PLACEHOLDER_LOOKING_CREDENTIALS = [
    "prod-secret-here-7Hq2",
    "MyTestPassword99",
    "Hello-Demo-2024!",
    "Abcd1234",
    "12345678",
]


@pytest.mark.parametrize("field", ["name", "owner", "status", "id"])
@pytest.mark.parametrize("credential", PLACEHOLDER_LOOKING_CREDENTIALS)
def test_generic_saas_withholds_copies_of_credentials_that_look_like_placeholders(
    tmp_path, index, monkeypatch, credential, field
):
    # They were left out of the credential context, so a copy in a display field was
    # printed, the scan was complete, and an ID copy gave the public digest of the raw ID.
    monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
    row = {"name": "ChatGPT Connector", "client_secret": credential, "installed_at": "2025-01-02"}
    if field == "name":
        row["name"] = f"ChatGPT Connector {credential}"
    else:
        row[field] = credential
    result = _generic_scan(tmp_path, index, [row])
    # An ID withheld whole can no longer match a client-ID signature: incomplete, never silent.
    assert result.complete == (field != "id"), result.stats[0].warnings
    assert any("withheld its id; coverage incomplete" in w for w in result.stats[0].warnings) == (
        field == "id"
    )
    (finding,) = result.findings
    assert credential not in result.to_json()
    assert finding.first_seen == "2025-01-02"
    if field == "name":
        assert finding.title == "saas app: ChatGPT Connector [REDACTED]"
    elif field == "owner":
        assert finding.owner == REDACTED
    elif field == "status":
        assert finding.metadata["status"] == REDACTED
    if field in ("name", "id"):
        raw_resource = f"saas:app:{row[field]}"
        assert finding.resource == (
            "saas:app:ChatGPT Connector [REDACTED]" if field == "name" else "saas:app:[REDACTED]"
        )
        assert finding.id != finding.compute_id()
        assert finding.id != _unkeyed_identity_digest(raw_resource)
        assert finding.metadata["identity_scope"] == "run"
    else:
        assert finding.resource == "saas:app:ChatGPT Connector" and finding.id == finding.compute_id()


@pytest.mark.parametrize("credential", [*PLACEHOLDER_LOOKING_CREDENTIALS, "hunter2", "Pa55!"])
def test_generic_saas_name_equal_to_a_credential_is_withheld_and_incomplete(tmp_path, index, credential):
    result = _generic_scan(
        tmp_path, index, [{"name": credential, "client_secret": credential}, {"name": "Claude for Sheets"}]
    )
    assert not result.complete
    assert [finding.title for finding in result.findings] == ["saas app: Claude for Sheets"]
    assert any("withheld its name" in warning for warning in result.stats[0].warnings)
    assert credential not in result.to_json()


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("field", ["owner", "status", "id"])
@pytest.mark.parametrize("credential", ["hunter2", "Pa55!", "admin"])
def test_generic_saas_withholds_a_field_equal_to_a_short_credential(
    tmp_path, index, monkeypatch, credential, field, nested
):
    # A credential shorter than eight characters is not learned: it would withhold each
    # field containing it. A field that equals it is withheld, and an ID equal to it gives
    # a keyed finding ID, never the public digest of the raw resource.
    monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
    secret = {"credentials": {"client_secret": credential}} if nested else {"client_secret": credential}
    row = {"name": "ChatGPT Connector", "installed_at": "2025-01-02", field: f" {credential} ", **secret}
    result = _generic_scan(tmp_path, index, [row])
    # An ID withheld whole can no longer match a client-ID signature: incomplete, never silent.
    assert result.complete == (field != "id"), result.stats[0].warnings
    assert any("withheld its id; coverage incomplete" in w for w in result.stats[0].warnings) == (
        field == "id"
    )
    (finding,) = result.findings
    assert credential not in result.to_json()
    assert finding.title == "saas app: ChatGPT Connector" and finding.first_seen == "2025-01-02"
    if field == "id":
        assert finding.resource == "saas:app:[REDACTED]"
        assert finding.id != finding.compute_id()
        assert finding.id != _unkeyed_identity_digest(f"saas:app: {credential} ")
        assert finding.metadata["identity_scope"] == "run"
    else:
        assert (finding.owner if field == "owner" else finding.metadata["status"]) == REDACTED
        assert finding.resource == "saas:app:ChatGPT Connector" and finding.id == finding.compute_id()


# Each value alone, in its field, makes the record an AI app or a privileged grant.
MATCHED_FIELD_VALUES = [
    ("publisher", "OpenAI"),  # shorter than eight characters: withheld only where a field equals it
    ("publisher", "Anthropic"),  # learned: withheld wherever it occurs
    ("description", "ChatGPT connector"),
    ("url", "https://chatgpt.com"),
    ("scopes", "Mail.ReadWrite"),
    ("scopes", ["Mail.ReadWrite"]),
    ("id", "fb8d773d-7ef8-4ec0-a117-179f88add510"),
]


@pytest.mark.parametrize(("field", "value"), MATCHED_FIELD_VALUES)
def test_generic_saas_matched_field_a_credential_withholds_leaves_the_scan_incomplete(
    tmp_path, index, field, value
):
    # Only a withheld name was a coverage gap. A publisher, description, URL, scope or ID
    # equal to a credential was withheld too, nothing was left to match, and the app
    # vanished from a complete scan.
    base = _generic_scan(tmp_path, index, [{"name": "Acme Helper", field: value}])
    assert base.complete and len(base.findings) == 1
    credential = value[0] if isinstance(value, list) else value
    result = _generic_scan(tmp_path, index, [{"name": "Acme Helper", field: value, "api_key": credential}])
    assert not result.complete
    assert result.stats[0].warnings == [
        f"saas.generic: a credential in an app record withheld its {field}; coverage incomplete"
    ]
    assert all(credential not in json.dumps(finding.to_dict()) for finding in result.findings)


@pytest.mark.parametrize("vendor", ["OpenAI", "Anthropic"])
def test_generic_saas_csv_vendor_equal_to_the_api_key_is_a_coverage_gap(tmp_path, index, vendor):
    export = tmp_path / "apps.csv"
    export.write_text(f"App,Vendor,API Key\nAcme Helper,{vendor},{vendor}\n", encoding="utf-8")
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("saas.generic", {"input": str(export)})]), index
    ).run()
    assert not result.complete and not result.findings
    assert result.stats[0].warnings == [
        "saas.generic: a credential in an app record withheld its publisher; coverage incomplete"
    ]


@pytest.mark.parametrize("password", [48213977, 4821.3977, 1234567])
def test_generic_saas_learns_a_numeric_credential_as_the_csv_text_would_be(
    tmp_path, index, monkeypatch, password
):
    # A JSON number was never learned: its copies in the owner and the ID were printed,
    # with the public digest of the raw resource as the finding ID, while the same row
    # as CSV was withheld with a keyed ID.
    monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
    text = str(password)
    result = _generic_scan(
        tmp_path, index, [{"name": "ChatGPT Enterprise", "id": text, "owner": text, "password": password}]
    )
    export = tmp_path / "apps.csv"
    export.write_text(f"name,id,owner,password\nChatGPT Enterprise,{text},{text},{text}\n", encoding="utf-8")
    as_csv = Engine(
        ScanConfig(connectors=[ConnectorSpec("saas.generic", {"input": str(export)})]), index
    ).run()
    for scanned in (result, as_csv):
        assert text not in scanned.to_json()
        (finding,) = scanned.findings
        assert finding.owner == REDACTED and finding.resource == "saas:app:[REDACTED]"
        assert finding.id != finding.compute_id()
        assert finding.id != _unkeyed_identity_digest(f"saas:app:{text}")
        assert finding.metadata["identity_scope"] == "run"
        assert not scanned.complete
        assert any("withheld its id; coverage incomplete" in w for w in scanned.stats[0].warnings)


def test_generic_saas_numeric_fields_equal_to_a_numeric_credential_are_withheld(tmp_path, index):
    # Sanitization leaves numbers as they are: a number equal to a credential is withheld
    # as a short credential's copy is, whatever its length.
    row = {
        "name": "ChatGPT Enterprise",
        "status": 1234567,
        "users": 48213977,
        "secret": 1234567,
        "password": 48213977,
    }
    result = _generic_scan(tmp_path, index, [row])
    assert result.complete, result.stats[0].warnings
    (finding,) = result.findings
    assert finding.metadata["status"] == finding.metadata["users"] == REDACTED
    assert "1234567" not in result.to_json() and "48213977" not in result.to_json()


def test_generic_saas_boolean_credential_values_are_flags(tmp_path, index):
    result = _generic_scan(
        tmp_path, index, [{"name": "ChatGPT Enterprise", "owner": "True", "status": "True", "password": True}]
    )
    assert result.complete, result.stats[0].warnings
    (finding,) = result.findings
    assert finding.owner == "True" and finding.metadata["status"] == "True"


# The whole-value placeholder test of connectors.common took 'your' in any case with any
# letters after it, and any text in '<...>' or '${...}': these client secrets were left
# out of the credential context, and their copies printed with the public-digest ID.
PLACEHOLDER_SHAPED_CREDENTIALS = [
    "YourOrgProdSecretKey",
    "<Xk9#mP2$qL7vB>",
    "${Xk9#mP2qL7vB}",
    "Your_api_key",
]


@pytest.mark.parametrize("field", ["name", "owner", "id"])
@pytest.mark.parametrize("credential", PLACEHOLDER_SHAPED_CREDENTIALS)
def test_generic_saas_learns_credentials_shaped_like_loose_placeholders(
    tmp_path, index, monkeypatch, credential, field
):
    monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
    row = {"name": "ChatGPT Enterprise", "client_secret": credential}
    if field == "name":
        row["name"] = f"ChatGPT Enterprise {credential}"
    else:
        row[field] = credential
    result = _generic_scan(tmp_path, index, [row])
    assert credential not in result.to_json()
    (finding,) = result.findings
    if field == "owner":
        assert finding.owner == REDACTED and finding.id == finding.compute_id()
        assert result.complete, result.stats[0].warnings
    else:
        assert finding.id != finding.compute_id()
        assert finding.id != _unkeyed_identity_digest(f"saas:app:{row[field]}")
        assert finding.metadata["identity_scope"] == "run"
        assert result.complete == (field == "name"), result.stats[0].warnings


@pytest.mark.parametrize("with_id", [False, True])
def test_generic_saas_redacts_resource_without_collapsing_distinct_identities(index, with_id):
    connector = GenericSaaSConnector(ConnectorContext(config={"keep_all": True}, index=index))
    records = []
    for suffix in ("one", "two"):
        credential = f"private-identity-{suffix}"
        records.append(
            {"name": f"Claude {credential}", "api_key": credential, **({"id": credential} if with_id else {})}
        )
    findings = list(connector.analyze(records))
    assert len(findings) == 2
    assert findings[0].id != findings[1].id and findings[0].resource == findings[1].resource
    assert all("private-identity-" not in json.dumps(finding.to_dict()) for finding in findings)


def test_generic_saas_context_limit_omits_record_and_marks_incomplete(index, monkeypatch):
    monkeypatch.setattr("shadowscan.utils.redaction._MAX_SANITIZATION_CHARS", 1000)
    connector = GenericSaaSConnector(ConnectorContext(config={"keep_all": True}, index=index))
    connector.ctx.stats = ScanStats(connector="saas.generic", started_at="now")
    result = list(connector.analyze([{"name": "Claude", "irrelevant": "x" * 1001}]))
    assert not result and connector.ctx.stats.incomplete


@pytest.mark.parametrize(
    "formula,expected",
    [
        ("=1+1", "'=1+1"),
        ("+1+1", "'+1+1"),
        ("-1+1", "'-1+1"),
        ("@SUM(1)", "'@SUM(1)"),
        # A tab or line break also starts a cell when the report is split on it.
        ("\t=1+1", "'\t'=1+1"),
        ("\r=1+1", "'\r'=1+1"),
        ("\n=1+1", "'\n'=1+1"),
        ("  =1+1", "'  =1+1"),
        ("\ufeff=1+1", "\\ufeff=1+1"),
    ],
)
def test_csv_formula_values_are_literal_text(formula, expected):
    f = _finding(title=formula, owner=formula, evidence=[Evidence(signal="test", description=formula)])
    # A complete scan: an incomplete one leads with a status row.
    complete = ScanResult(findings=[f], stats=[ScanStats(connector="test", started_at="now")])
    row = next(csv.DictReader(io.StringIO(render_csv(complete))))
    for column in ("title", "owner", "top_evidence"):
        assert row[column] == expected
    assert row["confidence"] == "0.0"


def test_incomplete_status_and_sanitized_context_diagnostics(caplog):
    context = ConnectorContext(index=_index())
    context.stats = ScanStats(connector="test", started_at="now")
    assert ScanResult(stats=[context.stats]).complete
    context.warn("advisory only", incomplete=False)
    assert ScanResult(stats=[context.stats]).complete
    context.warn(f"could not access url?api_key={SECRET}")
    assert not ScanResult(stats=[context.stats]).complete
    context.error(f"password={SECRET}")
    assert SECRET not in str(context.stats) and SECRET not in caplog.text
    assert not ScanResult().complete
    assert ScanResult(stats=[context.stats]).summary()["status"] == "incomplete"


def test_completed_findings_survive_connector_failure():
    class PartialConnector(_RecordConnector):
        def analyze(self, records):
            yield from super().analyze(records)
            raise ValueError(f"bad token={SECRET}")

    connector = PartialConnector(ConnectorContext(index=_index()))
    findings = connector.run()
    assert len(findings) == 1
    result = ScanResult(findings=findings, stats=[connector.ctx.stats])
    assert not result.complete and result.summary()["errors"] == 1
    assert SECRET not in result.to_json()


def test_cyclic_untrusted_metadata_does_not_recurse_or_leak():
    record = {"token": SECRET}
    record["cycle"] = record
    safe = sanitize(record)
    assert safe == {"token": REDACTED, "cycle": REDACTED}
    assert SECRET not in str(_finding(metadata=record).to_dict())


def test_machine_signal_identifiers_and_jwt_fingerprints_are_preserved():
    for value in ("jwt:hygiene", "jwt:delegated-agent", "jwt:1234567890abcdef", "secret:provider.openai"):
        assert sanitize_text(value) == value


def test_source_secret_copies_are_redacted_using_parsed_environment_and_argv():
    parsed = {"env": {"CUSTOM_NAME": SECRET}, "args": ["--token", "other-opaque-credential"]}
    source = json.dumps(parsed)
    safe = sanitize({"source": source, "parsed": parsed})["source"]
    assert SECRET not in safe and "other-opaque-credential" not in safe


def test_safe_token_statistics_and_secret_reference_lists_are_preserved():
    value = {"tokens": 12, "secrets": ["approved-secret-reference"], "environment": "production"}
    assert sanitize(value) == value


def test_multiline_private_keys_preserve_source_line_numbers():
    source = "-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----\nimport langchain"
    safe = sanitize_text(source)
    assert source.count("\n") == safe.count("\n")
    assert safe.splitlines()[3] == "import langchain"
    assert "secret-material" not in safe


@pytest.mark.parametrize("from_environment", [False, True])
def test_diagnostics_redact_opaque_configured_credentials(caplog, monkeypatch, from_environment):
    config = {} if from_environment else {"api_key": SECRET}
    context = ConnectorContext(config=config, index=_index())
    context.stats = ScanStats(connector="test", started_at="now")
    if from_environment:
        monkeypatch.setenv("TEST_PROVIDER_KEY", SECRET)
        assert context.get("api_key", env="TEST_PROVIDER_KEY") == SECRET
    message = f"remote server rejected supplied value {SECRET}"
    context.warn(message)
    context.error(message)
    assert SECRET not in str(context.stats) and SECRET not in caplog.text


@pytest.mark.parametrize(
    "credential",
    [
        "gsk_" + "a" * 40,
        "pcsk_" + "a" * 20,
        "e2b_" + "a" * 40,
        "tgp_v1_" + "a" * 30,
        "lsv2_pt_" + "a" * 32 + "_" + "b" * 10,
        "tvly-prod-" + "a" * 20,
        "xai-" + "a" * 60,
        "pplx-" + "a" * 40,
        "csk-" + "a" * 30,
        "nvapi-" + "a" * 60,
        "r8_" + "a" * 30,
        "fc-" + "a" * 32,
        "app-" + "a" * 24,
    ],
)
def test_additional_provider_tokens_are_redacted(credential):
    assert credential not in sanitize_text(f"credential={credential}")


def test_ssws_authorization_is_redacted():
    credential = "synthetic-okta-token-value"
    assert credential not in sanitize_text(f"Authorization: SSWS {credential}")


def test_repr_escaped_configured_secret_is_redacted():
    credential = "first-line\nsecond-line"
    result = sanitize({"client_secret": credential, "debug": repr(credential)})
    assert credential not in result["debug"]
    assert repr(credential)[1:-1] not in result["debug"]


def test_long_secret_is_redacted_before_excerpt_truncation():
    credential = "opaque-" + "x" * 240
    excerpt = _excerpt([f"token={credential}"], 1, credential)
    assert credential not in excerpt
    assert credential[:120] not in excerpt


LEAF_KEY = "sk" + "-proj-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"


class _PluginObject:
    """An arbitrary object a plugin may leave in metadata; only its repr shows the value."""

    def __repr__(self) -> str:
        return f"PluginObject(token={LEAF_KEY})"


def _leaf_finding():
    return _finding(
        metadata={
            "b": LEAF_KEY.encode(),
            "ba": bytearray(LEAF_KEY.encode()),
            "s": {LEAF_KEY},
            "fs": frozenset({LEAF_KEY}),
            "e": ValueError(LEAF_KEY),
            "o": _PluginObject(),
            "nested": [{"deeper": (b"\xff" + LEAF_KEY.encode(),)}],
        }
    )


def test_unknown_leaf_types_are_stringified_and_sanitized():
    clean = sanitize({"b": LEAF_KEY.encode(), "s": {LEAF_KEY, "other"}, "e": ValueError(LEAF_KEY), "n": 3})
    assert LEAF_KEY not in repr(clean)
    assert clean["n"] == 3
    assert clean["b"] == REDACTED
    assert sorted(clean["s"]) == sorted([REDACTED, "other"])
    assert clean["e"] == REDACTED
    # Bytes that are not text are decoded with replacement characters, not an error.
    assert sanitize({"x": b"\xff\xfe ok"}) == {"x": "�� ok"}
    # Plain JSON-like leaves and the standard library's scalars keep their type.
    scalars = {"i": 1, "f": 1.5, "t": True, "none": None, "when": datetime.date(2024, 1, 2)}
    assert sanitize(scalars) == scalars


@pytest.mark.parametrize("fmt", ["json", "html", "markdown", "csv", "sarif"])
def test_unknown_leaf_types_never_reach_a_report(fmt):
    result = ScanResult(findings=[_leaf_finding()])
    assert LEAF_KEY not in render(result, fmt)
    assert LEAF_KEY not in repr(result.findings[0].metadata)


def test_unknown_leaf_types_never_reach_the_terminal_table():
    out = io.StringIO()
    print_table(ScanResult(findings=[_leaf_finding()]), console=Console(file=out, width=200), verbose=True)
    assert LEAF_KEY not in out.getvalue()


def test_unknown_leaf_types_never_reach_a_record_dump(tmp_path):
    target = tmp_path / "records.jsonl"

    class Connector(BaseConnector):
        name = "test.leaf"

        def collect(self):
            yield {
                "id": "1",
                "payload": LEAF_KEY.encode(),
                "labels": {LEAF_KEY},
                "error": RuntimeError(LEAF_KEY),
            }

        def analyze(self, records):
            for _ in records:
                self.ctx.examined()
            yield from ()

    connector = Connector(ConnectorContext(config={"_dump_path": str(target)}, index=_index()))
    connector.run()
    assert target.exists() and LEAF_KEY not in target.read_text()


KEY_BODY = "\n".join("Zm9vYmFyU3ludGhldGljS2V5TWF0ZXJpYWw" + chr(ord("a") + line) * 6 for line in range(6))


@pytest.mark.parametrize(
    "block",
    [
        f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{KEY_BODY}\n=ab12\n-----END PGP PRIVATE KEY BLOCK-----",
        f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----",
        f'---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: "key"\n{KEY_BODY}\n---- END SSH2 ENCRYPTED PRIVATE KEY ----',
        f"PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: key\nPublic-Lines: 2\n{KEY_BODY}\n"
        f"Private-Lines: 2\n{KEY_BODY}\nPrivate-MAC: 0123456789abcdef0123456789abcdef01234567",
        f"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: key\nPublic-Lines: 2\n{KEY_BODY}\n"
        f"Key-Derivation: Argon2id\nPrivate-Lines: 2\n{KEY_BODY}\nPrivate-MAC: 0123456789abcdef0123456789abcdef01234567",
    ],
)
def test_every_private_key_block_is_withheld_with_its_line_count(block):
    source = f"before\n{block}\nafter\n"
    safe = sanitize_text(source)
    assert KEY_BODY.splitlines()[0] not in safe and "0123456789abcdef" not in safe
    assert safe.startswith("before\n" + REDACTED) and safe.endswith("\nafter\n")
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "start",
    [
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
        "PuTTY-User-Key-File-2: ssh-rsa",
    ],
)
def test_an_unterminated_key_block_is_withheld_to_the_end_of_the_text(start):
    source = f"note\n{start}\n{KEY_BODY}\nnot a marker line\n"
    safe = sanitize_text(source)
    assert safe.startswith("note\n" + REDACTED) and KEY_BODY.splitlines()[-1] not in safe
    assert "not a marker line" not in safe


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQENBGZ\n-----END PGP PUBLIC KEY BLOCK-----",
        "---- BEGIN SSH2 PUBLIC KEY ----\nAAAAB3NzaC1yc2E\n---- END SSH2 PUBLIC KEY ----",
        "-----BEGIN CERTIFICATE-----\nMIIBkTCB\n-----END CERTIFICATE-----",
        "see PuTTY-User-Key-File formats in the PuTTY manual",
    ],
)
def test_public_keys_and_prose_about_key_formats_are_kept(text):
    assert sanitize_text(text) == text


# ---------------------------------------------------------------- token formats


def _run(alphabet: str, length: int) -> str:
    # Ends in a word character: the backstop stops at a word boundary, so a token that ended in
    # a hyphen would legitimately leave that one character behind.
    return (alphabet * length)[: length - 1] + "7"


_ALNUM, _HEX, _WORD = "aB3xY7", "0123456789abcdef", "aB3_x-Y7"


def _token_samples() -> list[tuple[str, str]]:
    """One synthetic token per alternative of the backstop, assembled so that no sample is a literal.

    The pairs are (the alternative's own source, a string it matches in full). Splitting a prefix
    keeps a secret scanner from reading a test fixture as a credential.
    """
    return [
        ("sk-(?:proj|ant|live|or-v1|lf|litellm|svcacct|admin)-", "sk" + "-proj-" + _run(_WORD, 20)),
        ("gh[pousr]_", "gh" + "p_" + _run(_ALNUM, 36)),
        ("github_pat_", "github" + "_pat_" + _run(_ALNUM + "_", 40)),
        ("gl(?:pat|rt|ptt|dt|ft|soat|cbt|imt|oas|agent|ffct)-", "gl" + "pat-" + _run(_WORD, 20)),
        ("GR1348941", "GR" + "1348941" + _run(_WORD, 24)),
        ("xox[abeprs]-", "xo" + "xb-" + _run(_ALNUM + "-", 24)),
        ("xoxe\\.xox[bp]-", "xo" + "xe.xoxp-" + _run(_ALNUM + "-", 24)),
        ("xapp-", "xa" + "pp-" + _run(_ALNUM + "-", 24)),
        ("AIza", "AI" + "za" + _run(_WORD, 30)),
        ("ya29\\.", "ya" + "29." + _run(_WORD, 30)),
        ("1//0", "1/" + "/0" + _run(_WORD, 40)),
        ("GOCSPX-", "GOC" + "SPX-" + _run(_WORD, 28)),
        ("(?:AKIA|ASIA)", "AK" + "IA" + _run("ABCDEF0123456789", 16)),
        ("hf_", "hf" + "_" + _run(_ALNUM, 30)),
        ("sk-[A-Za-z0-9_-]{8,}", "sk" + "-" + _run(_WORD, 24)),
        ("gsk_", "gs" + "k_" + _run(_ALNUM, 52)),
        ("pcsk_", "pc" + "sk_" + _run(_ALNUM + "_", 30)),
        ("e2b_", "e2" + "b_" + _run(_HEX, 40)),
        ("tgp_v1_", "tgp" + "_v1_" + _run(_WORD, 40)),
        ("lsv2_(?:pt|sk)_", "ls" + "v2_pt_" + _run(_HEX, 32) + "_" + _run(_HEX, 10)),
        ("tvly-(?:dev-|prod-)?", "tv" + "ly-dev-" + _run(_WORD, 28)),
        ("xai-", "xa" + "i-" + _run(_ALNUM, 70)),
        ("pplx-", "pp" + "lx-" + _run(_ALNUM, 50)),
        ("csk-", "cs" + "k-" + _run(_ALNUM, 40)),
        ("nvapi-", "nv" + "api-" + _run(_WORD, 70)),
        ("r8_", "r" + "8_" + _run(_ALNUM, 40)),
        ("fc-", "f" + "c-" + _run(_HEX, 32)),
        ("app-", "ap" + "p-" + _run(_ALNUM, 24)),
        ("sk_[a-f0-9]{40,}", "sk" + "_" + _run(_HEX, 44)),
        ("npm_", "np" + "m_" + _run(_ALNUM, 40)),
        ("pypi-AgE", "py" + "pi-AgE" + _run(_WORD, 56)),
        ("do[opr]_v1_", "do" + "p_v1_" + _run(_HEX, 64)),
        ("(?:sk|rk)_(?:live|test)_", "rk" + "_live_" + _run(_ALNUM, 24)),
        ("whsec_", "wh" + "sec_" + _run(_ALNUM, 32)),
        ("SG\\.", "S" + "G." + _run(_WORD, 22) + "." + _run(_WORD, 22)),
        ("dapi", "da" + "pi" + _run(_HEX, 32)),
        ("shp(?:at|ca|pa|ss)_", "sh" + "pat_" + _run(_HEX, 32)),
        ("ATATT3", "ATA" + "TT3" + _run(_WORD, 50)),
        ("lin_api_", "lin" + "_api_" + _run(_ALNUM, 40)),
        ("ntn_", "nt" + "n_" + _run(_ALNUM, 46)),
        ("PMAK-", "PM" + "AK-" + _run(_HEX, 24) + "-" + _run(_HEX, 34)),
        ("dp\\.(?:pt|st|sa|ct|scim|audit)\\.", "d" + "p.pt." + _run(_ALNUM, 46)),
        ("sbp_", "sb" + "p_" + _run(_HEX, 40)),
        ("sb_secret_", "sb" + "_secret_" + _run(_WORD, 30)),
        ("glsa_", "gl" + "sa_" + _run(_ALNUM, 32) + "_" + _run(_HEX, 8)),
        ("glc_", "gl" + "c_" + _run(_ALNUM + "+/", 40)),
        ("sntry[su]_", "sn" + "trys_" + _run(_ALNUM + "+=_-", 40)),
        ("hv[sbr]\\.", "h" + "vs." + _run(_WORD, 30)),
        ("fw_", "fw_" + "aB3xY7" * 4),
        ("[A-Za-z0-9]{14}\\.atlasv1\\.", _run(_ALNUM, 14) + "." + "atl" + "asv1." + _run(_WORD, 70)),
        ("ABSK", "AB" + "SK" + _run(_ALNUM + "+/", 80)),
        ("bedrock-api-key-", "bedrock-" + "api-key-" + _run(_WORD, 60)),
    ]


def _backstop_alternatives() -> list[str]:
    alternatives: list[str] = []
    for pattern in (redaction_formats._SPECIFIC_TOKEN, redaction_formats._GENERIC_TOKEN):
        depth, current, in_class, index = 0, "", False, 0
        while index < len(pattern):
            char = pattern[index]
            if char == "\\":
                current += pattern[index : index + 2]
                index += 2
                continue
            if in_class:
                in_class = char != "]"
            elif char == "[":
                in_class = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "|" and depth == 0:
                alternatives.append(current)
                current = ""
                index += 1
                continue
            current += char
            index += 1
        alternatives.append(current)
    return alternatives


def test_the_token_table_covers_every_alternative_of_the_backstop():
    alternatives = _backstop_alternatives()
    samples = _token_samples()
    assert len(samples) == len(alternatives), "a token format was added or removed: update the samples"
    for (prefix, sample), alternative in zip(samples, alternatives, strict=True):
        assert alternative.startswith(prefix), (prefix, alternative)
        assert re.fullmatch(alternative, sample), f"the sample for {prefix} does not match its format"


@pytest.mark.parametrize("prefix,sample", _token_samples(), ids=[prefix for prefix, _ in _token_samples()])
def test_every_provider_token_format_is_withheld(prefix, sample):
    for text in (f"key = {sample}", f"see {sample} here", f"Authorization failed for {sample}."):
        redacted = sanitize_text(text)
        assert sample not in redacted, text
        assert REDACTED in redacted, text
    # The token is cut at its own boundary: the surrounding words stay readable.
    assert sanitize_text(f"see {sample} here") == f"see {REDACTED} here"

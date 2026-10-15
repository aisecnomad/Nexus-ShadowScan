"""AWS connector collection, analysis and SDK transport contracts, without cloud credentials."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock
from unittest.mock import Mock

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud.aws import AwsConnector, _cloudtrail_record
from shadowscan.models import ScanStats
from shadowscan.utils.redaction import REDACTED

ACCOUNT = "123456789012"
KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def _context(index, **config) -> ConnectorContext:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-01-01T00:00:00+00:00")
    return ctx


def _lambda_record() -> dict:
    return {
        "_kind": "lambda",
        "_region": "us-east-1",
        "FunctionName": "prod-agent",
        "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:prod-agent",
        "Runtime": "python3.12",
        "Role": f"arn:aws:iam::{ACCOUNT}:role/prod-agent",
        "Handler": "app.handler",
        # Ordinary settings whose values occur inside sibling identifiers, plus a real key.
        "Environment": {"OPENAI_API_KEY": KEY, "STAGE": "prod", "WORKERS": "4", "REGION": "us-east-1"},
        "Layers": [f"arn:aws:lambda:us-east-1:{ACCOUNT}:layer:langchain:3"],
        "LastModified": "2025-01-01",
        "PackageType": "Zip",
        "Description": None,
        "ImageUri": None,
        "Tags": {},
    }


def aws(index, service):
    connector = AwsConnector(
        ConnectorContext(
            index=index,
            config={
                "account_id": ACCOUNT,
                "services": [service],
                "regions": ["us-east-1"],
                "cloudtrail_days": 0,
            },
        )
    )
    connector.check_requirements = Mock()
    connector._session_ = Mock()
    connector._client = Mock(return_value=Mock(list_tags=Mock(return_value={"Tags": {}})))
    return connector


def test_aws_scalar_settings_are_single_items_and_unknown_services_are_rejected(index):
    connector = AwsConnector(context(index, services="lambda", regions="us-east-1"))
    assert connector.services == {"lambda"} and connector.regions == ["us-east-1"]
    with pytest.raises(ConnectorError):
        AwsConnector(context(index, services="nope"))
    with pytest.raises(ConnectorError):
        AwsConnector(context(index, regions="US East"))


def test_aws_layer_name_and_ssm_parameter_arn(index):
    connector = AwsConnector(context(index, account_id="123456789012"))
    finding = connector._h_lambda(
        {
            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:f",
            "FunctionName": "f",
            "_region": "us-east-1",
            "Layers": ["arn:aws:lambda:us-east-1:123456789012:layer:langchain-deps:4"],
        }
    )
    assert finding is not None and "framework.langchain" in finding.frameworks
    plain = connector._h_ssm_parameter({"Name": "OPENAI_API_KEY", "_region": "us-east-1"})
    nested = connector._h_ssm_parameter({"Name": "/prod/OPENAI_API_KEY", "_region": "us-east-1"})
    assert (
        plain is not None and plain.resource == "arn:aws:ssm:us-east-1:123456789012:parameter/OPENAI_API_KEY"
    )
    assert (
        nested is not None
        and nested.resource == "arn:aws:ssm:us-east-1:123456789012:parameter/prod/OPENAI_API_KEY"
    )


def test_aws_clients_carry_explicit_timeouts(index, monkeypatch):
    pytest.importorskip("botocore")
    connector = AwsConnector(context(index, account_id="123456789012"))
    session = Mock()
    connector._session = session
    connector._client("lambda", "us-east-1")
    config = session.client.call_args.kwargs["config"]
    assert config.connect_timeout == 10 and config.read_timeout == 30
    assert config.retries == {"mode": "standard", "total_max_attempts": 3}


def test_lambda_record_export_round_trip_keeps_resource_identity(tmp_path, index):
    pytest.importorskip("boto3")  # live collection path needs the [aws] extra
    dump = tmp_path / "aws.jsonl"
    ctx = _context(index, services=["lambda"], regions=["us-east-1"], _dump_path=str(dump))
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    with (
        mock.patch.object(connector, "_session_", lambda: None),
        mock.patch.object(connector, "_regions", lambda: ["us-east-1"]),
        mock.patch.object(connector, "_collect_lambda", lambda region: iter([_lambda_record()])),
    ):
        live = connector.run()
    assert ctx.stats.incomplete is False and len(live) == 1
    exported = [json.loads(line) for line in dump.read_text().splitlines()]
    lam = next(rec for rec in exported if rec.get("_kind") == "lambda")
    assert lam["FunctionArn"] == f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:prod-agent"
    assert lam["Role"] == f"arn:aws:iam::{ACCOUNT}:role/prod-agent" and lam["FunctionName"] == "prod-agent"
    assert set(lam["Environment"].values()) == {REDACTED}
    assert KEY not in dump.read_text()
    offline_ctx = _context(index, input=str(dump))
    offline = AwsConnector(offline_ctx).run()
    assert offline_ctx.stats.incomplete is False and not offline_ctx.stats.warnings
    assert [(f.id, f.resource, f.account, f.region) for f in offline] == [
        (live[0].id, live[0].resource, ACCOUNT, "us-east-1")
    ]


def test_sagemaker_environment_values_never_enter_findings_or_wipe_identity(index):
    record = {
        "_kind": "sagemaker-endpoint",
        "_region": "us-east-1",
        "EndpointName": "llama-3-endpoint",
        "EndpointArn": f"arn:aws:sagemaker:us-east-1:{ACCOUNT}:endpoint/llama-3-endpoint",
        "EndpointStatus": "InService",
        "models": [
            {
                "name": "llama3",
                "instance": "ml.g5.12xlarge",
                "images": ["huggingface-pytorch-tgi-inference:2.3.0"],
                "env": {"HF_MODEL_ID": "meta-llama/Llama-3-8B", "SM_NUM_GPUS": "4"},
                "model_data": [],
            }
        ],
    }
    ctx = _context(index)
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    (finding,) = list(connector.analyze([record]))
    finding.sanitize()
    assert finding.account == ACCOUNT and finding.region == "us-east-1"
    assert finding.resource == f"arn:aws:sagemaker:us-east-1:{ACCOUNT}:endpoint/llama-3-endpoint"
    (model,) = finding.metadata["models"]
    assert "env" not in model and model["env_names"] == ["HF_MODEL_ID", "SM_NUM_GPUS"]
    assert "meta-llama" not in json.dumps(finding.to_dict())


@pytest.mark.parametrize(
    "environment",
    [
        {"Error": {"ErrorCode": "KMSAccessDeniedException", "Message": "sensitive-error-text"}},
        {"Error": {}},
        {"Error": None},
        None,
        {"Variables": None},
        {"Variables": {"invalid": 42, "OPENAI_API_KEY": "${SECRET}"}},
        {"Error": {"ErrorCode": "KMSAccessDeniedException"}, "Variables": {"OPENAI_API_KEY": "${SECRET}"}},
    ],
)
def test_lambda_environment_failure_preserves_other_signals_and_marks_unknown(index, environment):
    connector = aws(index, "lambda")
    connector._paginate = Mock(
        return_value=iter(
            [
                {
                    "FunctionName": "worker",
                    "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker",
                    "Environment": environment,
                    "Layers": [{"Arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:layer:langchain:1"}],
                }
            ]
        )
    )
    findings = connector.run()
    assert len(findings) == 1
    assert "framework.langchain" in findings[0].frameworks
    assert findings[0].metadata["environment_coverage"] == "unknown"
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors
    assert "sensitive-error-text" not in str(connector.ctx.stats.warnings)
    if isinstance(environment, dict) and "OPENAI_API_KEY" in (environment.get("Variables") or {}):
        assert "provider.openai" in findings[0].model_providers


def test_lambda_environment_failure_without_ai_signal_still_fails_coverage(index):
    connector = aws(index, "lambda")
    connector._paginate = Mock(
        return_value=iter(
            [
                {
                    "FunctionName": "worker",
                    "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker",
                    "Environment": {"Error": {"ErrorCode": "KMSAccessDeniedException"}},
                }
            ]
        )
    )
    assert connector.run() == []
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("fields", [{}, {"Environment": {}}, {"Environment": {"Variables": {}}}])
def test_lambda_known_empty_environment_remains_complete(index, fields):
    connector = aws(index, "lambda")
    connector._paginate = Mock(
        return_value=iter(
            [
                {
                    "FunctionName": "worker",
                    "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker",
                    **fields,
                }
            ]
        )
    )
    assert connector.run() == []
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize(
    "code,expected",
    [
        ("AccessDenied", "access denied"),
        ("AccessDeniedException", "access denied"),
        ("UnauthorizedOperation", "access denied"),
        ("ExpiredToken", "SDKError"),
    ],
)
def test_aws_denial_diagnostic_has_safe_machine_readable_code(index, code, expected):
    class SDKError(Exception):
        response = {"Error": {"Code": code, "Message": "sensitive-provider-message"}}

    connector = aws(index, "lambda")
    connector.ctx.stats = ScanStats(connector=connector.name, started_at="2026-09-24")
    client = Mock()
    client.get_paginator.side_effect = SDKError("sensitive-provider-message")
    assert list(connector._pages(client, "list_functions")) == []
    assert expected in connector.ctx.stats.warnings[0]
    assert "sensitive-provider-message" not in connector.ctx.stats.warnings[0]


def test_aws_transport_ignores_ambient_service_endpoint_overrides(index, monkeypatch):
    boto3 = pytest.importorskip("boto3")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://untrusted.example")
    monkeypatch.setenv("AWS_ENDPOINT_URL_STS", "https://untrusted-sts.example")
    client = boto3.client(
        "sts",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=AwsConnector._sdk_config(),
    )
    assert client.meta.endpoint_url == "https://sts.us-east-1.amazonaws.com"


@pytest.mark.parametrize("assume_role", [False, True])
def test_aws_signed_endpoint_rules_ignore_external_sdk_models(index, monkeypatch, tmp_path, assume_role):
    boto3 = pytest.importorskip("boto3")
    from botocore.loaders import Loader

    external = tmp_path / "models" / "sts" / "2011-06-15"
    external.mkdir(parents=True)
    (external / "endpoint-rule-set-1.json").write_text(
        json.dumps(
            {
                "version": "1.0",
                "parameters": {},
                "rules": [
                    {
                        "conditions": [],
                        "type": "endpoint",
                        "endpoint": {"url": "http://127.0.0.1:8000", "properties": {}, "headers": {}},
                    }
                ],
            }
        )
    )
    monkeypatch.setenv("AWS_DATA_PATH", str(tmp_path / "models"))
    monkeypatch.setattr(Loader, "CUSTOMER_DATA_PATH", str(tmp_path / "models"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    sts = Mock()
    sts.get_caller_identity.return_value = {"Account": ACCOUNT}
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "assumed-test",
            "SecretAccessKey": "assumed-test",
            "SessionToken": "assumed-token",
        }
    }
    monkeypatch.setattr(boto3.Session, "client", Mock(return_value=sts))
    connector = AwsConnector(
        ConnectorContext(
            index=index,
            config={
                "account_id": ACCOUNT,
                **({"role_arn": f"arn:aws:iam::{ACCOUNT}:role/audit"} if assume_role else {}),
            },
        )
    )
    session = connector._session_()
    loader = session._session.get_component("data_loader")
    assert str(tmp_path / "models") not in loader.search_paths
    assert "127.0.0.1" not in json.dumps(loader.load_service_model("sts", "endpoint-rule-set-1"))
    assert sts.assume_role.call_count == int(assume_role)


# --------------------------------------------------- untrusted response shapes
def test_safe_call_diagnostic_names_the_operation_and_code_never_the_message(index):
    class SDKError(Exception):
        response = {"Error": {"Code": "AccessDeniedException", "Message": "arn:aws:iam::123:role/secret-ctx"}}

    def get_agent(**kwargs):
        raise SDKError("User is not authorized to perform get_agent on arn:aws:iam::123:role/secret-ctx")

    def list_tags(**kwargs):
        raise ValueError("Invalid parameter Resource=arn:aws:lambda:us-east-1:123:function:internal-name")

    connector = aws(index, "lambda")
    connector.ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-01-01")
    assert connector._safe(get_agent, agentId="A1") is None
    assert connector._safe(list_tags, Resource="x") is None
    denied, failed = connector.ctx.stats.warnings
    assert denied == "cloud.aws: get_agent access denied (AccessDeniedException)"
    assert failed == "cloud.aws: list_tags request failed (ValueError)"
    assert "secret-ctx" not in denied and "internal-name" not in failed
    assert connector.ctx.stats.incomplete


def test_malformed_lambda_record_is_skipped_and_the_others_survive(index):
    connector = aws(index, "lambda")
    connector.ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-01-01")
    good = {"FunctionName": "worker", "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker"}
    connector._paginate = Mock(return_value=iter([{"FunctionName": "no-arn"}, good]))
    records = [record for record in connector.collect() if record.get("_kind") == "lambda"]
    assert [record["FunctionName"] for record in records] == ["worker"]
    assert any(
        "malformed Lambda function record skipped (KeyError)" in w for w in connector.ctx.stats.warnings
    )
    assert connector.ctx.stats.incomplete


def test_non_string_alias_version_does_not_abort_the_bedrock_agent(index):
    items = {
        "list_agents": [{"agentId": "A1", "agentName": "ops"}],
        "list_agent_aliases": [{"routingConfiguration": [{"agentVersion": 1}, {"agentVersion": "2"}]}],
    }
    connector = aws(index, "bedrock")
    connector.ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-01-01")
    connector._paginate = Mock(side_effect=lambda client, op, key, **kwargs: iter(items.get(op, [])))
    client = connector._client.return_value
    client.get_agent = Mock(return_value={"agent": {"agentId": "A1", "agentName": "ops"}})
    client.get_agent_version = Mock(return_value={"agentVersion": {"agentId": "A1", "agentVersion": "2"}})
    client.get_model_invocation_logging_configuration = Mock(return_value={"loggingConfig": {}})
    agents = [
        record for record in connector._collect_bedrock("us-east-1") if record["_kind"] == "bedrock-agent"
    ]
    assert len(agents) == 1
    assert agents[0]["_versions_scanned"] == ["2", "DRAFT"]
    assert any("invalid alias version for agent A1" in w for w in connector.ctx.stats.warnings)


def _lineage_records():
    source = Path(__file__).parents[1] / "fixtures/cloud/lineage/assumed_session.jsonl"
    return [json.loads(line) for line in source.read_text().splitlines()]


def _lineage(index, records):
    ctx = _context(index, input="synthetic-cloudtrail.jsonl")
    findings = list(AwsConnector(ctx).analyze(records))
    return findings, ctx


def test_cloudtrail_export_preserves_scoped_session_lineage_and_ignores_ordinary_events(index):
    findings, ctx = _lineage(index, _lineage_records())
    assert not ctx.stats.incomplete and len(findings) == 1
    finding = findings[0]
    assert finding.account == "222222222222" and finding.metadata["events"] == 1
    (observation,) = finding.metadata["cloudtrail_lineage"]["observations"]
    assert observation["eventID"] == "invocation-17"
    assert observation["eventName"] == "ConverseStream"
    assert observation["recipientAccountId"] == "222222222222"
    assert observation["_region"] == "us-west-2"
    assert observation["sourceIdentity"] == "build-17"
    assert observation["assumption_status"] == "linked"
    assert observation["assumption"]["_region"] == "us-east-1"
    assert observation["assumption"]["principal"].startswith("arn:aws:sts::111111111111:")
    assert finding.metadata["cloudtrail_lineage"]["coverage"] == "export-observations-only"
    # STS events are lineage context, never an independent AI finding.
    assert _lineage(index, _lineage_records()[:1])[0] == []


def test_cloudtrail_normalization_never_exports_credentials_or_request_bodies():
    assumption, invocation, _ = _lineage_records()
    assumption["responseElements"]["credentials"].update(
        {
            "accessKeyId": "synthetic-access-value",
            "secretAccessKey": "synthetic-secret-value",
            "sessionToken": "synthetic-session-value",
        }
    )
    assumption["requestParameters"]["policy"] = "private-policy-body"
    record = _cloudtrail_record({"CloudTrailEvent": json.dumps(assumption)}, "us-east-1")
    assert record["sessionExpiresAt"] == "2026-01-01T01:00:00Z"
    encoded = json.dumps(record)
    for forbidden in ("synthetic-access", "synthetic-secret", "synthetic-session", "private-policy"):
        assert forbidden not in encoded
    invocation["requestParameters"]["messages"] = "private-prompt-body"
    assert "private-prompt" not in json.dumps(
        _cloudtrail_record({"CloudTrailEvent": json.dumps(invocation)}, "us-west-2")
    )


@pytest.mark.parametrize(
    "detail",
    [
        [],
        {"userIdentity": []},
        {"requestParameters": []},
        {"responseElements": {"credentials": []}},
        {"eventID": "x" * 2049},
    ],
)
def test_cloudtrail_malformed_nested_metadata_fails_closed(detail):
    assert _cloudtrail_record({"CloudTrailEvent": json.dumps(detail)}, "us-east-1") is None


def test_cloudtrail_duplicate_event_ids_do_not_inflate_counts_and_order_does_not_change_links(index):
    assumption, invocation, _ = _lineage_records()
    first, _ = _lineage(index, [assumption, invocation, invocation])
    second, _ = _lineage(index, [invocation, assumption])
    assert first[0].metadata["events"] == second[0].metadata["events"] == 1
    assert first[0].metadata["cloudtrail_lineage"] == second[0].metadata["cloudtrail_lineage"]


@pytest.mark.parametrize(
    "change", ["recipient", "issuer", "created", "expired", "source", "missing-time", "wrong-service"]
)
def test_cloudtrail_session_links_require_exact_account_identity_and_lifetime(index, change):
    assumption, invocation, _ = _lineage_records()
    if change == "recipient":
        assumption["recipientAccountId"] = "333333333333"
    elif change == "issuer":
        invocation["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = (
            "arn:aws:iam::333333333333:role/ml-worker"
        )
    elif change == "created":
        invocation["userIdentity"]["sessionContext"]["attributes"]["creationDate"] = "2025-12-31T23:00:00Z"
    elif change == "expired":
        invocation["eventTime"] = "2026-01-01T02:00:00Z"
    elif change == "source":
        invocation["userIdentity"]["sessionContext"]["sourceIdentity"] = "another-build"
    elif change == "missing-time":
        del assumption["responseElements"]["credentials"]["expiration"]
    else:
        assumption["eventSource"] = "untrusted.example"
    findings, _ = _lineage(index, [assumption, invocation])
    (observation,) = findings[0].metadata["cloudtrail_lineage"]["observations"]
    assert observation["assumption_status"] == "unlinked" and observation["assumption"] is None


def test_cloudtrail_ambiguous_sessions_and_conflicting_event_ids_do_not_bind(index):
    assumption, invocation, _ = _lineage_records()
    duplicate = {**assumption, "eventID": "other-assumption"}
    findings, _ = _lineage(index, [assumption, duplicate, invocation])
    assert findings[0].metadata["cloudtrail_lineage"]["observations"][0]["assumption_status"] == "ambiguous"
    duplicate["eventID"] = assumption["eventID"]
    duplicate["userIdentity"] = {"type": "IAMUser", "arn": "arn:aws:iam::111111111111:user/different"}
    findings, ctx = _lineage(index, [assumption, duplicate, invocation])
    assert ctx.stats.incomplete
    assert "conflicting-event-id" in findings[0].metadata["cloudtrail_lineage"]["limits"]
    assert findings[0].metadata["cloudtrail_lineage"]["observations"][0]["assumption"] is None


def test_cloudtrail_lineage_invalid_times_are_explicit(index):
    _, invocation, _ = _lineage_records()
    invocation["eventTime"] = "not-a-time"
    findings, ctx = _lineage(index, [invocation])
    assert ctx.stats.incomplete
    assert "invalid-timestamp" in findings[0].metadata["cloudtrail_lineage"]["limits"]


def test_cloudtrail_event_limit_is_per_principal_and_bounds_ancestry_not_the_scan(index, monkeypatch):
    from shadowscan.connectors.cloud import aws_lineage

    monkeypatch.setattr(aws_lineage, "MAX_LINEAGE_EVENTS", 1)
    assumption, invocation, _ = _lineage_records()
    # One retained event per principal: the assumption and the invocation are different principals.
    findings, ctx = _lineage(index, [assumption, invocation])
    assert not ctx.stats.incomplete
    assert findings[0].metadata["cloudtrail_lineage"]["coverage"] == "export-observations-only"
    second = {**invocation, "eventID": "another-call", "eventTime": "2026-01-01T00:20:00Z"}
    findings, ctx = _lineage(index, [assumption, invocation, second])
    assert not ctx.stats.incomplete
    assert any("events per principal" in warning for warning in ctx.stats.warnings)
    finding = findings[0]
    assert finding.metadata["events"] == 2  # the invocation tally is never bounded
    lineage = finding.metadata["cloudtrail_lineage"]
    assert lineage["coverage"] == "partial" and "event-limit" in lineage["limits"]
    assert [o["assumption_status"] for o in lineage["observations"]] == ["linked"]
    assert any("per-principal retention limit" in text for text in lineage["limitations"])


def test_cloudtrail_event_limit_on_an_ancestor_marks_the_descendant_session_partial(index, monkeypatch):
    from shadowscan.connectors.cloud import aws_lineage

    monkeypatch.setattr(aws_lineage, "MAX_LINEAGE_EVENTS", 1)
    path = Path(__file__).parents[1] / "fixtures/cloud/lineage/assumed_chain.jsonl"
    root, assumption, invocation = (json.loads(line) for line in path.read_text().splitlines())
    repeat = {**root, "eventID": "root-assumption-18", "eventTime": "2025-12-31T23:55:00Z"}
    findings, ctx = _lineage(index, [root, repeat, assumption, invocation])
    assert not ctx.stats.incomplete
    lineage = findings[0].metadata["cloudtrail_lineage"]
    (observation,) = lineage["observations"]
    assert observation["chain_status"] == "observed-origin" and len(observation["assumption_chain"]) == 2
    # The origin's dropped event could have changed the chain, so the descendant is partial too.
    assert lineage["coverage"] == "partial" and "event-limit" in lineage["limits"]
    findings, ctx = _lineage(index, [root, assumption, invocation])
    lineage = findings[0].metadata["cloudtrail_lineage"]
    assert lineage["coverage"] == "export-observations-only" and "event-limit" not in lineage["limits"]


def test_cloudtrail_per_caller_limit_preserves_counts_but_reports_partial_provenance(index, monkeypatch):
    from shadowscan.connectors.cloud import aws_lineage

    monkeypatch.setattr(aws_lineage, "MAX_CALLER_OBSERVATIONS", 1)
    assumption, invocation, _ = _lineage_records()
    findings, ctx = _lineage(index, [assumption, invocation, {**invocation, "eventID": "another-call"}])
    # A bounded sample is disclosed provenance, not a coverage gap: the tally is complete.
    assert not ctx.stats.incomplete and findings[0].metadata["events"] == 2
    assert any("observations per caller" in warning for warning in ctx.stats.warnings)
    lineage = findings[0].metadata["cloudtrail_lineage"]
    assert len(lineage["observations"]) == 1 and lineage["observations_truncated"] is True
    assert lineage["coverage"] == "partial" and "caller-observation-limit" in lineage["limits"]
    assert any("capped at 1 per caller" in text for text in lineage["limitations"])


def test_cloudtrail_two_hop_cross_account_chain_preserves_exact_ancestry(index):
    path = Path(__file__).parents[1] / "fixtures/cloud/lineage/assumed_chain.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines()]
    findings, ctx = _lineage(index, list(reversed(records)))
    assert not ctx.stats.incomplete
    (observation,) = findings[0].metadata["cloudtrail_lineage"]["observations"]
    assert observation["chain_status"] == "observed-origin"
    assert [hop["eventID"] for hop in observation["assumption_chain"]] == [
        "assumption-17",
        "root-assumption-17",
    ]
    # Equal role/session names in a different account are not an ancestry edge.
    records[0]["responseElements"]["assumedRoleUser"]["arn"] = (
        "arn:aws:sts::444444444444:assumed-role/build/runner"
    )
    findings, ctx = _lineage(index, records)
    (observation,) = findings[0].metadata["cloudtrail_lineage"]["observations"]
    assert observation["chain_status"] == "partial" and len(observation["assumption_chain"]) == 1
    assert not ctx.stats.incomplete  # incomplete export ancestry is a disclosed limitation, not a parse error


def test_cloudtrail_lineage_survives_real_offline_collection_and_sanitization(run_connector):
    source = Path(__file__).parents[1] / "fixtures/cloud/lineage/assumed_chain.jsonl"
    findings, ctx = run_connector("cloud.aws", input=str(source))
    assert not ctx.stats.incomplete and len(findings) == 1
    lineage = findings[0].to_dict()["metadata"]["cloudtrail_lineage"]
    assert lineage["observations"][0]["chain_status"] == "observed-origin"
    assert len(lineage["observations"][0]["assumption_chain"]) == 2


def _normalized_chain(length):
    def role(i):
        return f"arn:aws:iam::222222222222:role/r{i}"

    def session(i):
        return f"arn:aws:sts::222222222222:assumed-role/r{i}/worker"

    common = {
        "_kind": "cloudtrail-event",
        "_region": "us-east-1",
        "recipientAccountId": "222222222222",
        "eventTime": "2026-01-01T00:00:00Z",
    }
    assumptions = [
        {
            **common,
            "eventID": f"assume-{i}",
            "eventName": "AssumeRole",
            "eventSource": "sts.amazonaws.com",
            "principal": session(i - 1) if i else "arn:aws:iam::222222222222:user/origin",
            "identityType": "AssumedRole" if i else "IAMUser",
            "sessionIssuerArn": role(i - 1),
            "sessionCreatedAt": common["eventTime"],
            "assumedRoleArn": session(i),
            "roleArn": role(i),
            "sessionExpiresAt": "2026-01-01T01:00:00Z",
        }
        for i in range(length)
    ]
    invocation = {
        **common,
        "eventID": "invoke-chain",
        "eventName": "ConverseStream",
        "eventTime": "2026-01-01T00:10:00Z",
        "principal": session(length - 1),
        "identityType": "AssumedRole",
        "sessionIssuerArn": role(length - 1),
        "sessionCreatedAt": common["eventTime"],
    }
    return assumptions, invocation


def test_cloudtrail_chain_hop_budget_and_cycles_fail_incomplete(index):
    assumptions, invocation = _normalized_chain(9)
    findings, ctx = _lineage(index, [*assumptions, invocation])
    observation = findings[0].metadata["cloudtrail_lineage"]["observations"][0]
    assert observation["chain_status"] == "depth-limit" and len(observation["assumption_chain"]) == 8
    assert ctx.stats.incomplete
    assumptions, invocation = _normalized_chain(1)
    assumptions[0].update(
        principal=invocation["principal"],
        identityType="AssumedRole",
        sessionIssuerArn=invocation["sessionIssuerArn"],
    )
    findings, ctx = _lineage(index, [*assumptions, invocation])
    observation = findings[0].metadata["cloudtrail_lineage"]["observations"][0]
    assert observation["chain_status"] == "cycle" and ctx.stats.incomplete


@pytest.mark.parametrize(
    "role_path,session_role,linked",
    [
        ("team/ml-worker", "ml-worker", True),
        ("ml-worker", "DifferentRole", False),
        ("team/ml-worker", "team/ml-worker", False),
    ],
)
def test_cloudtrail_session_role_name_must_match_issuer_even_when_both_events_repeat_mismatch(
    index, role_path, session_role, linked
):
    assumption, invocation, _ = _lineage_records()
    role = f"arn:aws:iam::222222222222:role/{role_path}"
    session = f"arn:aws:sts::222222222222:assumed-role/{session_role}/job-17"
    assumption["requestParameters"]["roleArn"] = role
    assumption["responseElements"]["assumedRoleUser"]["arn"] = session
    invocation["userIdentity"]["arn"] = session
    invocation["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = role
    findings, _ = _lineage(index, [assumption, invocation])
    observation = findings[0].metadata["cloudtrail_lineage"]["observations"][0]
    assert (observation["assumption_status"] == "linked") is linked


def test_cloudtrail_display_format_expiration_links_the_session(index):
    # CloudTrail renders responseElements.credentials.expiration as "Jan 1, 2026, 1:00:00 PM".
    path = Path(__file__).parents[1] / "fixtures/cloud/lineage/assumed_session_display_time.jsonl"
    assumption, invocation = (json.loads(line) for line in path.read_text().splitlines())
    assert assumption["responseElements"]["credentials"]["expiration"] == "Jan 1, 2026, 1:00:00 PM"
    findings, ctx = _lineage(index, [assumption, invocation])
    assert not ctx.stats.incomplete
    (observation,) = findings[0].metadata["cloudtrail_lineage"]["observations"]
    assert observation["assumption_status"] == "linked"
    assert observation["assumption"]["sessionExpiresAt"] == "2026-01-01T13:00:00+00:00"
    assumption["responseElements"]["credentials"]["expiration"] = "not-a-time"
    findings, ctx = _lineage(index, [assumption, invocation])
    assert ctx.stats.incomplete
    (observation,) = findings[0].metadata["cloudtrail_lineage"]["observations"]
    assert observation["assumption_status"] == "unlinked"
    assert "invalid-timestamp" in findings[0].metadata["cloudtrail_lineage"]["limits"]


def test_cloudtrail_ai_events_outside_the_lineage_operation_list_still_count_for_callers(index):
    # Before session lineage every cloudtrail-event reached the caller tally; lineage must not change that.
    assumption, invocation, control = _lineage_records()
    extra = [
        {**invocation, "eventID": f"{name}-1", "eventName": name, "eventSource": source, "awsRegion": region}
        for name, source, region in (
            ("InvokeModelWithBidirectionalStream", "bedrock.amazonaws.com", "us-west-2"),
            ("Retrieve", "bedrock.amazonaws.com", "eu-west-1"),
            ("ApplyGuardrail", "bedrock.amazonaws.com", "us-west-2"),
            ("InvokeEndpointAsync", "sagemaker.amazonaws.com", "us-east-1"),
        )
    ]
    findings, ctx = _lineage(index, [assumption, invocation, *extra, control])
    assert not ctx.stats.incomplete and len(findings) == 1  # the S3 control event is still no caller
    finding = findings[0]
    assert finding.metadata["events"] == 5
    assert set(finding.metadata["operations"]) == {
        "ConverseStream",
        "InvokeModelWithBidirectionalStream",
        "Retrieve",
        "ApplyGuardrail",
        "InvokeEndpointAsync",
    }
    assert finding.metadata["regions"] == ["eu-west-1", "us-east-1", "us-west-2"]
    # Only the listed operations carry a session trace; the others are counted and disclosed.
    assert [o["eventName"] for o in finding.metadata["cloudtrail_lineage"]["observations"]] == [
        "ConverseStream"
    ]
    assert any("4 CloudTrail AI event(s) outside the lineage operation list" in w for w in ctx.stats.warnings)


def test_cloudtrail_trace_reads_only_the_hops_that_can_match_on_a_large_export(monkeypatch):
    # A busy role with a fixed session name repeats one session ARN across thousands of
    # AssumeRole events; each observation must read the hops keyed by its exact creation
    # time, not every hop into that session (quadratic within the export limits).
    import time

    from shadowscan.connectors.cloud.aws_lineage import CloudTrailLineage, normalize_detail

    assumption, invocation, _ = _lineage_records()
    assumers = ("arn:aws:sts::111111111111:assumed-role/build/runner", "arn:aws:iam::111111111111:user/ops")
    lineage = CloudTrailLineage(lambda *a, **k: None)
    for n in range(1000):
        hop = json.loads(json.dumps(assumption))
        hop["eventID"] = f"hop-{n}"
        hop["eventTime"] = f"2025-12-{1 + n // 250:02d}T{(n // 10) % 24:02d}:{(n % 10) * 6:02d}:00Z"
        hop["userIdentity"]["arn"] = assumers[n % 2]
        assert lineage.add(normalize_detail(hop))
    assert lineage.add(normalize_detail(assumption))
    for n in range(100):
        assert lineage.add(normalize_detail({**invocation, "eventID": f"invocation-{n}"}))
    calls: list[int] = []
    original = CloudTrailLineage._matches
    monkeypatch.setattr(
        CloudTrailLineage, "_matches", staticmethod(lambda i, a: calls.append(1) or original(i, a))
    )
    started = time.monotonic()
    result = lineage.for_principal(invocation["userIdentity"]["arn"])
    assert time.monotonic() - started < 1.0
    assert len(calls) <= 2 * len(result["observations"])
    assert not lineage.limits
    assert len(result["observations"]) == 100
    assert {o["assumption_status"] for o in result["observations"]} == {"linked"}
    assert {o["assumption"]["eventID"] for o in result["observations"]} == {"assumption-17"}


@pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-14:00"])
@pytest.mark.parametrize("field", ["eventTime", "sessionCreatedAt", "sessionExpiresAt"])
def test_cloudtrail_timestamp_outside_the_utc_range_is_invalid_not_a_crash(index, field, stamp):
    # The value parses, but shifting it to UTC overflows datetime; that is an invalid
    # timestamp for this event, never an exception that abandons the rest of the export.
    from shadowscan.connectors.cloud.aws_lineage import _parse_time

    assert _parse_time(stamp) is None
    assumption, invocation, _ = _lineage_records()
    broken = json.loads(json.dumps(assumption if field == "sessionExpiresAt" else invocation))
    broken["eventID"] = "overflow-1"
    if field == "eventTime":
        broken["eventTime"] = stamp
    elif field == "sessionCreatedAt":
        broken["userIdentity"]["sessionContext"]["attributes"]["creationDate"] = stamp
    else:
        broken["responseElements"]["credentials"]["expiration"] = stamp
    findings, ctx = _lineage(index, [broken, assumption, invocation])
    assert ctx.stats.incomplete
    (finding,) = findings
    assert finding.metadata["events"] == (1 if field == "sessionExpiresAt" else 2)
    lineage = finding.metadata["cloudtrail_lineage"]
    assert "invalid-timestamp" in lineage["limits"]
    # The record after the overflowing one was still analyzed.
    assert any(o["eventID"] == "invocation-17" for o in lineage["observations"])

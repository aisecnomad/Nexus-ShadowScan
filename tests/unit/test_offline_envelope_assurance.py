"""An offline page cannot claim completeness through resource-shaped labels."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.base import BaseConnector


@pytest.mark.parametrize(
    "label",
    [
        {"type": "collection"},
        {"object": "collection"},
        {"type": "app"},
        {"id": "page-1", "name": "listed apps"},
    ],
)
def test_labeled_page_with_continuation_is_incomplete(tmp_path: Path, label: dict) -> None:
    source = tmp_path / "export.json"
    source.write_text(
        json.dumps(
            {
                **label,
                "items": [
                    {"_kind": "approved_app", "app": {"id": "A1", "name": "Claude"}, "scopes": []},
                ],
                "next_cursor": "opaque-page-token",
            }
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        main,
        [
            "run",
            "saas.slack",
            "--input",
            str(source),
            "--format",
            "json",
            "--set",
            "team_id=T1",
        ],
    )
    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False
    assert len(report["findings"]) == 1
    assert "opaque-page-token" not in result.output


def test_collection_data_and_nested_error_page_are_not_native_records() -> None:
    item = {"id": "observed-app"}
    errors: list[str] = []
    assert list(
        BaseConnector._unwrap(
            {
                "object": "collection",
                "data": [item],
                "next_cursor": "next-page",
            },
            errors.append,
        )
    ) == [item]
    assert errors == ["offline export contains an uncollected next page"]

    errors.clear()
    page = {
        "id": "failed-page",
        "error": {"message": "denied"},
        "data": [{"timestamp": "2026-01-01", "items": [item]}],
    }
    assert list(BaseConnector._unwrap(page, errors.append)) == []
    assert errors == [
        "provider error response in offline export; coverage is incomplete",
        "export record contains a collection envelope; expected a native record",
    ]


# Page identities and malformed successful responses must not hide collection gaps.
_APP = {"_kind": "approved_app", "app": {"id": "A1", "name": "Claude"}, "scopes": []}


def _cli_scan(tmp_path, connector: str, body: object, settings: tuple[str, ...] = (), suffix: str = ".json"):
    source = tmp_path / f"export{suffix}"
    report = tmp_path / "report.json"
    if suffix == ".jsonl":
        assert isinstance(body, list)
        source.write_text("\n".join(json.dumps(record) for record in body), encoding="utf-8")
    else:
        source.write_text(json.dumps(body), encoding="utf-8")
    if connector == "saas.slack":
        settings = ("team_id=T1", *settings)
    outcome = CliRunner().invoke(
        main,
        ["run", connector, "--input", str(source), "--format", "json", "-o", str(report), "--fail-on", "high"]
        + [argument for setting in settings for argument in ("--set", setting)],
    )
    return outcome, json.loads(report.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "connector,record",
    [
        ("saas.slack", _APP),
        (
            "identity.entra",
            {"_kind": "servicePrincipal", "id": "sp-1", "appId": "app-1", "displayName": "Claude"},
        ),
        ("lowcode.power-platform", {"_kind": "bot", "botid": "bot-1", "name": "Claude Agent"}),
    ],
)
def test_id_on_export_envelope_does_not_hide_items(tmp_path, connector, record):
    outcome, report = _cli_scan(tmp_path, connector, {"id": "export-1", "items": [record]})
    assert outcome.exit_code in {0, 2}, outcome.output
    assert report["summary"]["complete"] is True
    assert len(report["findings"]) == 1
    assert not report["stats"][0]["incomplete"]


@pytest.mark.parametrize("connector", ["saas.slack", "identity.entra", "lowcode.power-platform"])
@pytest.mark.parametrize(
    "body",
    [
        {"id": "export-1", "error": {"code": "access_denied", "message": "synthetic denied"}},
        {"id": "export-1", "ok": False, "error": "access_denied"},
        {"id": "export-1", "name": "OpenAI", "error": "access_denied"},
        {"object": "error", "error": "access_denied"},
        {"id": "export-1", "items": [], "error": "access_denied"},
    ],
)
def test_provider_error_with_page_id_is_incomplete_for_cli(tmp_path, connector, body):
    outcome, report = _cli_scan(tmp_path, connector, body)
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert not report["findings"]
    assert report["stats"][0]["incomplete"] and report["stats"][0]["errors"]


def test_export_error_keeps_valid_items_without_claiming_completeness(tmp_path):
    outcome, report = _cli_scan(
        tmp_path, "saas.slack", {"id": "export-1", "error": "later page denied", "items": [_APP]}
    )
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert len(report["findings"]) == 1


def test_id_on_explicit_empty_envelope_is_complete(tmp_path):
    outcome, report = _cli_scan(tmp_path, "saas.slack", {"id": "export-1", "items": []})
    assert outcome.exit_code == 0, outcome.output
    assert report["summary"]["complete"] is True
    assert not report["findings"]


def test_labelled_export_items_are_unwrapped(tmp_path):
    outcome, report = _cli_scan(tmp_path, "saas.slack", {"name": "export-1", "items": [_APP]})
    assert outcome.exit_code in {0, 2}, outcome.output
    assert len(report["findings"]) == 1 and report["summary"]["complete"] is True


def test_jsonl_error_with_request_id_is_incomplete_and_preserves_neighbor(tmp_path):
    source = tmp_path / "export.jsonl"
    output = tmp_path / "report.json"
    source.write_text(
        json.dumps({"error": "permission denied", "id": "req1"}) + "\n" + json.dumps(_APP) + "\n"
    )
    outcome = CliRunner().invoke(
        main,
        [
            "run",
            "saas.slack",
            "--input",
            str(source),
            "--format",
            "json",
            "-o",
            str(output),
            "--fail-on",
            "high",
            "--set",
            "team_id=T1",
        ],
    )
    report = json.loads(output.read_text())
    assert outcome.exit_code == 3, outcome.output
    assert len(report["findings"]) == 1 and report["summary"]["complete"] is False


def test_csv_error_row_is_incomplete_and_preserves_valid_neighbor(tmp_path):
    source = tmp_path / "export.csv"
    output = tmp_path / "report.json"
    source.write_text("id,name,error\napp1,Claude,\nreq1,,permission denied\n")
    outcome = CliRunner().invoke(
        main,
        [
            "run",
            "saas.generic",
            "--input",
            str(source),
            "--format",
            "json",
            "-o",
            str(output),
            "--fail-on",
            "high",
        ],
    )
    report = json.loads(output.read_text())
    assert outcome.exit_code == 3, outcome.output
    assert len(report["findings"]) == 1 and report["summary"]["complete"] is False


@pytest.mark.parametrize(
    "connector,record",
    [
        (
            "saas.microsoft-teams",
            {
                "_kind": "teamsApp",
                "id": "A1",
                "displayName": "OpenAI",
                "distributionMethod": "organization",
                "error": "access_denied",
            },
        ),
        ("saas.generic", {"_kind": "saas-app", "id": "A1", "name": "Claude", "error": "access_denied"}),
    ],
)
@pytest.mark.parametrize("as_array", [False, True])
def test_typed_provider_error_is_not_a_complete_native_app(tmp_path, connector, record, as_array):
    outcome, report = _cli_scan(tmp_path, connector, [record] if as_array else record)
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert report["findings"] == []


def test_failed_nested_page_keeps_observed_items_but_marks_incomplete(tmp_path):
    another = {"_kind": "approved_app", "app": {"id": "A2", "name": "Claude"}, "scopes": []}
    outcome, report = _cli_scan(
        tmp_path, "saas.slack", [_APP, {"id": "req1", "error": "denied", "items": [another]}]
    )
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert len(report["findings"]) == 2


@pytest.mark.parametrize(
    "pagination,reason",
    [
        ({"nextToken": "synthetic-uncollected-page"}, "unscanned-input"),
        ({"nextToken": False}, "unparsed-input"),
        ({}, "unparsed-input"),
    ],
)
@pytest.mark.parametrize("container", ["array", "envelope"])
def test_nested_collection_cannot_attest_complete_inventory(tmp_path, pagination, reason, container):
    page = {"name": "ordinary inventory", "items": [], **pagination}
    records = [{"id": "app-1", "name": "Claude"}, page]
    body = records if container == "array" else {"items": records}
    outcome, report = _cli_scan(tmp_path, "saas.generic", body)

    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert report["stats"][0]["incomplete_reasons"] == {reason: 1}
    assert len(report["findings"]) == 1
    assert "synthetic-uncollected-page" not in json.dumps(report)


def test_native_record_in_array_keeps_nested_collection_fields():
    native = {
        "id": "app-1",
        "name": "Native",
        "type": "app",
        "items": [{"id": "child"}],
    }
    errors: list[str] = []

    assert list(BaseConnector._unwrap([native], errors.append)) == [native]
    assert errors == []


# gateway.logs expands two nested collections itself, so an array of them stays
# complete; the record-array check must not drop them as misplaced pages.
def _cloudwatch_batch(number: int) -> dict[str, object]:
    invocation = {
        "schemaType": "ModelInvocationLog",
        "timestamp": "2026-10-26T12:00:00Z",
        "accountId": "111122223333",
        "region": "us-east-1",
        "requestId": f"synthetic-request-{number}",
        "operation": "Converse",
        "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0",
        "identity": {"arn": "arn:aws:sts::111122223333:assumed-role/agent-runner/session"},
    }
    return {
        "messageType": "DATA_MESSAGE",
        "owner": "111122223333",
        "logGroup": "/aws/bedrock/modelinvocations",
        "logStream": f"stream-{number}",
        "subscriptionFilters": ["synthetic"],
        "logEvents": [{"id": str(number), "timestamp": 1761480000000, "message": json.dumps(invocation)}],
    }


def _usage_bucket(start: int) -> dict[str, object]:
    result = {
        "object": "organization.usage.completions.result",
        "input_tokens": 1200,
        "output_tokens": 300,
        "num_model_requests": 4,
        "project_id": "proj_synthetic",
        "api_key_id": "key_synthetic",
        "model": "gpt-4o-2024-08-06",
    }
    return {"start_time": start, "end_time": start + 86400, "results": [result]}


@pytest.mark.parametrize("container", ["array", "envelope"])
@pytest.mark.parametrize(
    "records,settings",
    [
        ([_cloudwatch_batch(1), _cloudwatch_batch(2)], ("format=bedrock",)),
        ([_usage_bucket(1761436800), _usage_bucket(1761523200)], ("format=openai-usage",)),
    ],
    ids=["cloudwatch-batches", "usage-buckets"],
)
def test_gateway_nested_collections_in_a_record_array_stay_complete(tmp_path, records, settings, container):
    body = records if container == "array" else {"data": records}
    outcome, report = _cli_scan(tmp_path, "gateway.logs", body, settings)

    assert outcome.exit_code != 3, outcome.output
    assert report["summary"]["complete"] is True
    assert report["stats"][0]["incomplete_reasons"] == {}
    assert report["findings"]


def test_gateway_nested_batch_with_a_continuation_is_still_incomplete(tmp_path):
    batch = {**_cloudwatch_batch(1), "nextToken": "synthetic-uncollected-page"}
    outcome, report = _cli_scan(tmp_path, "gateway.logs", [batch], ("format=bedrock",))

    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert report["stats"][0]["incomplete_reasons"] == {"unscanned-input": 1}
    assert "synthetic-uncollected-page" not in json.dumps(report)


def _gateway_layout_scan(tmp_path, layout, record, neighbor, settings):
    records = [record, neighbor]
    body = record if layout == "single" else {"data": records} if layout == "envelope" else records
    return _cli_scan(
        tmp_path, "gateway.logs", body, settings, suffix=".jsonl" if layout == "jsonl" else ".json"
    )


@pytest.mark.parametrize("layout", ["single", "array", "envelope", "jsonl"])
@pytest.mark.parametrize(
    "family,label,settings",
    [
        ("cloudwatch", {"resource": {"labels": {"project_id": "synthetic"}}}, ("format=bedrock",)),
        ("cloudwatch", {"type": "app"}, ("format=bedrock",)),
        ("cloudwatch", {"_kind": "batch"}, ("format=bedrock",)),
        ("usage", {"object": "bucket"}, ()),
        ("usage", {"resource": "synthetic"}, ("format=openai-usage",)),
        ("usage", {"type": "app"}, ("format=openai-usage",)),
        ("usage", {"_kind": "usage"}, ("format=openai-usage",)),
    ],
)
@pytest.mark.parametrize("ambiguous", [False, True], ids=["one-collection", "two-collections"])
def test_gateway_collection_labels_preserve_context_without_hiding_ambiguity(
    tmp_path, layout, family, label, settings, ambiguous
):
    record = _cloudwatch_batch(1) if family == "cloudwatch" else _usage_bucket(1761436800)
    neighbor = _cloudwatch_batch(2) if family == "cloudwatch" else _usage_bucket(1761523200)
    record.update(label)
    if ambiguous:
        key = "logEvents" if family == "cloudwatch" else "results"
        record["records"], record[key] = record[key], []
    outcome, report = _gateway_layout_scan(tmp_path, layout, record, neighbor, settings)

    assert report["summary"]["complete"] is not ambiguous, outcome.output
    assert (outcome.exit_code == 3) is ambiguous
    assert report["stats"][0]["incomplete_reasons"] == ({"unparsed-input": 1} if ambiguous else {})
    observed_records = int(not ambiguous) + int(layout != "single")
    expected_requests = observed_records * (4 if family == "usage" else 1)
    assert sum(finding["metadata"]["events"] for finding in report["findings"]) == expected_requests


@pytest.mark.parametrize("layout", ["single", "array", "envelope", "jsonl"])
@pytest.mark.parametrize("family", ["cloudwatch", "usage"])
@pytest.mark.parametrize(
    "pagination,reason",
    [
        ({"nextToken": "synthetic-uncollected-page"}, "unscanned-input"),
        ({"nextToken": False}, "unparsed-input"),
    ],
)
def test_gateway_collection_pagination_is_reported_once_and_observed_records_survive(
    tmp_path, layout, family, pagination, reason
):
    record = _cloudwatch_batch(1) if family == "cloudwatch" else _usage_bucket(1761436800)
    neighbor = _cloudwatch_batch(2) if family == "cloudwatch" else _usage_bucket(1761523200)
    record.update(pagination)
    settings = ("format=bedrock",) if family == "cloudwatch" else ("format=openai-usage",)
    outcome, report = _gateway_layout_scan(tmp_path, layout, record, neighbor, settings)

    assert outcome.exit_code == 3, outcome.output
    assert report["stats"][0]["incomplete_reasons"] == {reason: 1}
    expected_requests = (1 + int(layout != "single")) * (4 if family == "usage" else 1)
    assert sum(finding["metadata"]["events"] for finding in report["findings"]) == expected_requests
    assert "synthetic-uncollected-page" not in json.dumps(report)


@pytest.mark.parametrize("layout", ["single", "array", "envelope", "jsonl"])
@pytest.mark.parametrize("malformed", [False, True])
def test_anonymous_usage_wrapper_is_validated_before_auto_format_event_detection(tmp_path, layout, malformed):
    record = _usage_bucket(1761436800)
    if malformed:
        record.update(results={}, service="worker", model="gpt-4o")
    outcome, report = _gateway_layout_scan(tmp_path, layout, record, _usage_bucket(1761523200), ())

    assert report["summary"]["complete"] is not malformed, outcome.output
    assert (outcome.exit_code == 3) is malformed
    expected_requests = (int(not malformed) + int(layout != "single")) * 4
    assert sum(finding["metadata"]["events"] for finding in report["findings"]) == expected_requests


def test_native_gateway_event_keeps_ordinary_nested_results_in_auto_format(tmp_path):
    record = {
        "id": "native-event",
        "service": "worker",
        "model": "gpt-4o",
        "start_time": 1761436800,
        "end_time": 1761436801,
        "results": {"answer": "ready"},
    }
    outcome, report = _cli_scan(tmp_path, "gateway.logs", [record])

    assert report["summary"]["complete"] is True, outcome.output
    assert outcome.exit_code != 3
    assert sum(finding["metadata"]["events"] for finding in report["findings"]) == 1

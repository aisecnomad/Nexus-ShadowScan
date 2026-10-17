"""AWS collection against botocore's own client, via ``Stubber``.

The rest of the AWS tests replace ``_paginate`` with a ``Mock``, which hands
the connector a ready-made list of records. That tests analysis but skips
everything between the wire and those records: paginator construction,
continuation tokens, the page cap, the shape botocore raises a ``ClientError``
in, and the non-pageable fallback. AWS is the largest connector in the
codebase, and that is the part of it those tests do not reach.

``Stubber`` is botocore's own fixture. It validates each queued response
against the real service model, so a response shaped wrongly fails here
rather than silently passing a test that a live call would not. Nothing in
this module mocks a connector method.
"""

from __future__ import annotations

from typing import Any

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.cloud.aws import MAX_LIST_PAGES, AwsConnector
from shadowscan.models import ScanStats

botocore = pytest.importorskip("botocore")
boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber  # noqa: E402

ACCOUNT = "123456789012"


@pytest.fixture
def connector(index) -> AwsConnector:
    ctx = ConnectorContext(config={"regions": ["us-east-1"]}, index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-01-01T00:00:00+00:00")
    return AwsConnector(ctx)


def _lambda_client() -> Any:
    # No credentials are used: Stubber intercepts before anything is signed.
    return boto3.client(
        "lambda",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )


def _function(name: str) -> dict[str, Any]:
    return {
        "FunctionName": name,
        "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{name}",
        "Runtime": "python3.12",
        "Handler": "app.handler",
        "Role": f"arn:aws:iam::{ACCOUNT}:role/{name}",
    }


class TestPagination:
    def test_a_continuation_token_is_followed(self, connector: AwsConnector) -> None:
        """The Mock-based tests cannot see this: they hand over one flat list."""
        client = _lambda_client()
        with Stubber(client) as stub:
            stub.add_response(
                "list_functions",
                {"Functions": [_function("one")], "NextMarker": "page-2"},
                {},
            )
            stub.add_response(
                "list_functions",
                {"Functions": [_function("two")]},
                {"Marker": "page-2"},
            )
            items = list(connector._paginate(client, "list_functions", "Functions"))
            stub.assert_no_pending_responses()
        assert [i["FunctionName"] for i in items] == ["one", "two"]

    def test_an_empty_page_yields_nothing_and_is_not_an_error(self, connector: AwsConnector) -> None:
        client = _lambda_client()
        with Stubber(client) as stub:
            stub.add_response("list_functions", {"Functions": []}, {})
            assert list(connector._paginate(client, "list_functions", "Functions")) == []
        assert connector.ctx.stats is not None
        assert connector.ctx.stats.warnings == []

    def test_the_page_cap_truncates_and_warns(self, connector: AwsConnector) -> None:
        """A listing longer than the cap must say so rather than look complete."""
        client = _lambda_client()
        with Stubber(client) as stub:
            for page in range(MAX_LIST_PAGES):
                expected = {} if page == 0 else {"Marker": f"page-{page}"}
                stub.add_response(
                    "list_functions",
                    {"Functions": [_function(f"fn{page}")], "NextMarker": f"page-{page + 1}"},
                    expected,
                )
            items = list(connector._paginate(client, "list_functions", "Functions"))
        assert len(items) == MAX_LIST_PAGES
        assert connector.ctx.stats is not None
        assert any("pagination limit reached" in w for w in connector.ctx.stats.warnings)

    def test_pages_read_before_a_failure_are_kept(self, connector: AwsConnector) -> None:
        """The documented contract of ``_pages``, exercised through the real client."""
        client = _lambda_client()
        with Stubber(client) as stub:
            stub.add_response(
                "list_functions",
                {"Functions": [_function("kept")], "NextMarker": "page-2"},
                {},
            )
            stub.add_client_error(
                "list_functions",
                service_error_code="ThrottlingException",
                http_status_code=429,
                expected_params={"Marker": "page-2"},
            )
            items = list(connector._paginate(client, "list_functions", "Functions"))
        assert [i["FunctionName"] for i in items] == ["kept"]
        assert connector.ctx.stats is not None
        assert connector.ctx.stats.incomplete


class TestErrorShapes:
    """A ``ClientError`` as botocore actually raises it, not a hand-built stand-in."""

    @pytest.mark.parametrize(
        "code",
        ["AccessDeniedException", "AccessDenied", "UnauthorizedOperation", "AuthorizationError"],
    )
    def test_access_denied_names_the_code_and_marks_coverage(
        self, connector: AwsConnector, code: str
    ) -> None:
        client = _lambda_client()
        with Stubber(client) as stub:
            stub.add_client_error("list_functions", service_error_code=code, http_status_code=403)
            assert list(connector._paginate(client, "list_functions", "Functions")) == []
        stats = connector.ctx.stats
        assert stats is not None
        assert stats.incomplete
        assert any(code in w and "access denied" in w for w in stats.warnings)

    def test_an_error_message_never_reaches_the_report(self, connector: AwsConnector) -> None:
        """SDK messages echo request parameters, which can carry credentials."""
        secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
        client = _lambda_client()
        with Stubber(client) as stub:
            stub.add_client_error(
                "list_functions",
                service_error_code="ValidationException",
                service_message=f"bad request containing {secret}",
                http_status_code=400,
            )
            list(connector._paginate(client, "list_functions", "Functions"))
        stats = connector.ctx.stats
        assert stats is not None
        joined = " ".join([*stats.warnings, *stats.errors])
        assert secret not in joined
        assert "ValidationException" in joined or "ClientError" in joined

    def test_a_server_error_is_recorded_as_incomplete(self, connector: AwsConnector) -> None:
        client = _lambda_client()
        with Stubber(client) as stub:
            stub.add_client_error(
                "list_functions", service_error_code="InternalFailure", http_status_code=500
            )
            assert list(connector._paginate(client, "list_functions", "Functions")) == []
        assert connector.ctx.stats is not None
        assert connector.ctx.stats.incomplete


class TestMalformedResponses:
    """Shapes a provider should never send. The scanner must not trust that it won't."""

    def test_a_missing_result_key_warns_rather_than_raising(self, connector: AwsConnector) -> None:
        client = _lambda_client()
        with Stubber(client) as stub:
            stub.add_response("list_functions", {}, {})
            assert list(connector._paginate(client, "list_functions", "Functions")) == []
        assert connector.ctx.stats is not None
        assert any("missing or failed" in w for w in connector.ctx.stats.warnings)

    def test_a_non_dict_record_is_skipped_not_fatal(self, connector: AwsConnector) -> None:
        """Stubber validates against the service model, so this bypasses it deliberately:
        the guard exists for a response that reached the connector some other way."""
        pages = [{"Functions": [_function("ok"), "not-a-dict", None]}]
        items = list(connector._paginate(_FakeClient(pages), "list_functions", "Functions"))
        assert [i["FunctionName"] for i in items] == ["ok"]
        assert connector.ctx.stats is not None
        assert sum("invalid Functions record" in w for w in connector.ctx.stats.warnings) == 2

    def test_a_non_list_result_is_skipped(self, connector: AwsConnector) -> None:
        items = list(connector._paginate(_FakeClient([{"Functions": "nope"}]), "list_functions", "Functions"))
        assert items == []
        assert connector.ctx.stats is not None
        assert any("invalid Functions page" in w for w in connector.ctx.stats.warnings)


class _FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any) -> Any:
        return iter(self._pages)


class _FakeClient:
    """Only for shapes botocore's own model would refuse to produce."""

    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = pages

    def get_paginator(self, _op: str) -> _FakePaginator:
        return _FakePaginator(self._pages)


class TestScopeAttestation:
    def test_a_successful_listing_is_attested_ok(self, connector: AwsConnector) -> None:
        client = _lambda_client()
        connector._scope = ("lambda", "aws")
        with Stubber(client) as stub:
            stub.add_response("list_functions", {"Functions": [_function("one")]}, {})
            list(connector._paginate(client, "list_functions", "Functions"))
        operations = connector.ctx._scope_operations
        assert any(outcome == "ok" for outcome in operations.values())

    def test_a_denied_listing_is_not_attested_ok(self, connector: AwsConnector) -> None:
        client = _lambda_client()
        connector._scope = ("lambda", "aws")
        with Stubber(client) as stub:
            stub.add_client_error(
                "list_functions", service_error_code="AccessDeniedException", http_status_code=403
            )
            list(connector._paginate(client, "list_functions", "Functions"))
        operations = connector.ctx._scope_operations
        assert operations
        assert all(outcome != "ok" for outcome in operations.values())

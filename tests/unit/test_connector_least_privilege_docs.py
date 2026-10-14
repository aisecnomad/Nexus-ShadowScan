"""The least-privilege table in docs/connectors.md names what a live connector reads."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shadowscan.connectors.lowcode import automation

ROOT = Path(__file__).resolve().parents[2]


def _least_privilege_row(connector: str) -> str:
    guide = (ROOT / "docs" / "connectors.md").read_text(encoding="utf-8")
    table = guide.split("## Least privilege", 1)[1]
    [row] = [line for line in table.splitlines() if line.startswith(f"| {connector} |")]
    return row


def test_the_make_row_names_every_endpoint_the_connector_reads(monkeypatch, run_connector) -> None:
    # An operator scopes the token from this row. With `organization_id` the
    # connector lists the organization's teams first, so a token scoped to
    # scenarios and AI agents alone leaves the scan incomplete.
    called: list[str] = []

    class MakeAPI:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def get_json(self, path: str, params: Any = None) -> Any:
            called.append(path)
            return {
                "/teams": {"teams": [{"id": 7}]},
                "/scenarios": {"scenarios": [{"id": "s1", "name": "scenario"}]},
                "/scenarios/s1/blueprint": {"response": {"blueprint": {"flow": []}}},
                "/ai-agents/v1/agents": [],
            }[path]

    monkeypatch.setattr(automation, "HttpClient", MakeAPI)
    _, ctx = run_connector(
        "lowcode.make", api_url="https://eu1.make.com/api/v2", token="synthetic", organization_id="1"
    )
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert called[0] == "/teams"
    row = _least_privilege_row("Make")
    for path in dict.fromkeys(called):
        assert f"`/api/v2{path.replace('/s1/', '/{id}/')}`" in row, path

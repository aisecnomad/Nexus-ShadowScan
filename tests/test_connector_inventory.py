"""docs/connectors/inventory.json stays generated from the registered connectors."""

from __future__ import annotations

import json

from shadowscan.connectors import builtin_connector_names
from tools import connector_inventory


def test_connector_inventory_is_current() -> None:
    message = connector_inventory.stale_message(connector_inventory.INVENTORY.read_text(encoding="utf-8"))
    assert message is None, message


def test_inventory_data_file_is_consistent_with_code_and_guides() -> None:
    assert connector_inventory.problems() == []


def test_inventory_lists_every_registered_connector_once() -> None:
    data = json.loads(connector_inventory.INVENTORY.read_text(encoding="utf-8"))
    names = [entry["name"] for entry in data["connectors"]]
    assert names == sorted(set(names))
    assert set(names) == set(builtin_connector_names())
    assert data["connector_count"] == len(names)


def test_undetermined_permissions_are_listed_not_guessed() -> None:
    data = json.loads(connector_inventory.INVENTORY.read_text(encoding="utf-8"))
    for entry in data["connectors"]:
        assert entry["permissions"].get("model"), entry["name"]
    assert data["needs_tenant_verification"] == sorted(data["needs_tenant_verification"])


def test_check_mode_fails_on_drift() -> None:
    assert connector_inventory.stale_message("{}\n") is not None

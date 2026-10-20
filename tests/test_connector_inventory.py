"""The maintenance inventory follows real built-ins and documentation changes."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from shadowscan.connectors import builtin_connector_names
from tools import connector_inventory as inventory


def test_inventory_counts_and_sources_match_builtins():
    result = inventory.inventory()
    assert result["connector_count"] == len(builtin_connector_names())
    assert sum(result["surface_counts"].values()) == result["connector_count"]
    assert {item["name"] for item in result["connectors"]} == builtin_connector_names()
    assert "okta.apps.read" in result["permissions_reference"]["text"]
    assert "incomplete" in result["shared_collection_rules"]["text"]
    for item in result["connectors"]:
        assert (inventory.ROOT / item["source"]).is_file()
        assert item["documentation"]["entry"].startswith("docs/connectors.md#")
        assert len(item["documentation"]["entry_sha256"]) == 64
    assert json.dumps(result, sort_keys=True) == json.dumps(inventory.inventory(), sort_keys=True)


def test_grouped_connector_headings_retain_their_real_anchor():
    sections = inventory._sections("### `cloud.kubernetes` and `cloud.openshift`\n\nPartial is incomplete.\n")
    assert sections["cloud.kubernetes"] == sections["cloud.openshift"]
    assert sections["cloud.kubernetes"][1] == "cloudkubernetes-and-cloudopenshift"


@pytest.fixture
def docs_tree(tmp_path: Path) -> Path:
    (tmp_path / "docs").mkdir()
    for name in ["pyproject.toml", "requirements.lock", "docs/connectors.md"]:
        shutil.copyfile(inventory.ROOT / name, tmp_path / name)
    return tmp_path


def test_new_undocumented_builtin_fails_instead_of_under_counting(monkeypatch, docs_tree):
    names = builtin_connector_names() | {"code.new-provider"}
    monkeypatch.setattr(inventory, "builtin_connector_names", lambda: names)
    with pytest.raises(ValueError, match="code.new-provider"):
        inventory.inventory(docs_tree)


def test_permission_changes_are_captured_without_a_second_metadata_copy(docs_tree):
    guide = docs_tree / "docs/connectors.md"
    guide.write_text(guide.read_text().replace("okta.apps.read", "okta.apps.new-read"))
    assert "okta.apps.new-read" in inventory.inventory(docs_tree)["permissions_reference"]["text"]


def test_connector_notes_change_digest_and_failure_excerpt(docs_tree):
    before = inventory.inventory(docs_tree)
    guide = docs_tree / "docs/connectors.md"
    guide.write_text(
        guide.read_text().replace(
            "### `identity.okta`\n",
            "### `identity.okta`\n\nA newly denied read makes coverage incomplete.\n\n",
        )
    )
    after = inventory.inventory(docs_tree)
    first = next(item for item in before["connectors"] if item["name"] == "identity.okta")["documentation"]
    second = next(item for item in after["connectors"] if item["name"] == "identity.okta")["documentation"]
    assert first["entry_sha256"] != second["entry_sha256"]
    assert "A newly denied read makes coverage incomplete." in second["failure_mode_notes"]

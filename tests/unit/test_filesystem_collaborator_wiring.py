"""The filesystem connector gives each of its collaborators the options it reads (ADR-005).

`FilesystemConnector.__init__` copies the validated options into the walk, file scan, findings and
ownership collaborators, and `scan_tree` hands the walker the two settings that `remote.py` sets after
construction. A slip in either place changes what a scan reports without any collaborator failing on
its own, and few scans use more than a handful of the options. Every option below is set to a value
that is not its default, so a collaborator that did not receive an option, or received another value,
fails here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector

OPTIONS: dict[str, Any] = {
    "max_file_size": 4321,
    "max_files": 77,
    "max_entries": 888,
    "max_notebook_size": 5432,
    "scan_timeout": 3.5,
    "max_ast_nodes": 5000,
    "oversize_skip_globs": ["*.dat"],
    "scan_secrets": False,
    "inspect_model_artifacts": True,
    "model_metadata_bytes": 4096,
    "use_git": True,
    "strict_coverage": True,
    "include_tests": True,
    "triage": True,
    "agent_granularity": "source",
    "default_excludes": False,
    "exclude": ["vendored", "generated/*.py"],
    "include": ["src"],
    "owner": "team-a",
    # A gap budget of 0 is strict accounting, like strict_coverage above (the ci profile is refused
    # with either, so it has a test of its own below).
    "max_coverage_gap": 0,
}

# The connector attributes each collaborator keeps a copy of, under the same name.
COPIED: dict[str, tuple[str, ...]] = {
    "walker": (
        "max_file_size",
        "max_files",
        "max_entries",
        "max_notebook_size",
        "scan_timeout",
        "oversize_skip_globs",
        "scan_secrets",
        "inspect_model_artifacts",
        "model_metadata_bytes",
        "use_git",
        "strict_coverage",
        "include_tests",
        "default_excludes",
        "exclude_names",
        "exclude_globs",
        "include_paths",
        "_zero_budget",
    ),
    "file_scanner": (
        "max_file_size",
        "max_ast_nodes",
        "scan_timeout",
        "scan_secrets",
        "strict_coverage",
        "include_tests",
        "triage",
        "agent_granularity",
        "model_metadata_bytes",
    ),
    "findings": ("include_tests", "agent_granularity", "owner", "scan_timeout"),
    "ownership": ("use_git", "owner", "max_file_size"),
}


def _connector(path: Path, index, **config: Any) -> FilesystemConnector:
    return FilesystemConnector(ConnectorContext(config={"path": str(path), **config}, index=index))


@pytest.fixture
def connector(tmp_path: Path, index) -> FilesystemConnector:
    return _connector(tmp_path, index, **OPTIONS)


@pytest.fixture
def defaults(tmp_path: Path, index) -> FilesystemConnector:
    return _connector(tmp_path, index)


@pytest.mark.parametrize(
    ("collaborator", "name"),
    [(collaborator, name) for collaborator, names in COPIED.items() for name in names],
)
def test_collaborator_has_the_connectors_option(
    connector: FilesystemConnector, defaults: FilesystemConnector, collaborator: str, name: str
):
    value = getattr(connector, name)
    assert value != getattr(defaults, name), f"{name} is at its default in this test, so it proves nothing"
    assert getattr(getattr(connector, collaborator), name) == value


def test_collaborators_are_wired_to_each_other_and_to_the_connector(connector: FilesystemConnector):
    assert connector.file_scanner.walker is connector.walker
    assert connector.findings.walker is connector.walker
    assert connector.findings.ownership is connector.ownership
    assert connector.findings.file_scanner is connector.file_scanner
    assert connector.ownership._included == connector.walker.included
    # The finding constructor and the root naming read the connector's own configuration.
    assert connector.file_scanner._base == connector._base
    assert connector.findings._base == connector._base
    assert connector.walker._root_prefix == connector._root_prefix
    assert connector.findings._root_prefix == connector._root_prefix
    assert connector.walker._explicit_exclude_names == connector._explicit_exclude_names == {"vendored"}


@pytest.mark.parametrize("incomplete", [True, False])
def test_scan_tree_gives_the_walker_what_remote_sets_after_construction(
    tmp_path: Path, index, monkeypatch: pytest.MonkeyPatch, incomplete: bool
):
    connector = _connector(tmp_path, index)
    connector.unread_settings = [".claude/settings.local.json"]
    connector.tree_listing_incomplete = incomplete
    # What the previous root left behind must not decide this one.
    connector.walker.root_listing_incomplete = not incomplete
    seen: dict[str, Any] = {}

    def walk(scan, scan_file, unread_settings):
        seen.update(
            scan_file=scan_file,
            unread_settings=list(unread_settings),
            listing_incomplete=connector.walker.root_listing_incomplete,
        )

    monkeypatch.setattr(connector.walker, "walk", walk)
    list(connector.scan_tree(tmp_path))
    assert seen == {
        "scan_file": connector.file_scanner.scan_file,
        "unread_settings": [".claude/settings.local.json"],
        "listing_incomplete": incomplete,
    }


def test_the_walker_receives_the_coverage_profile(tmp_path: Path, index):
    """The ci profile declares gaps on the walker, so it must see the profile the connector parsed."""
    connector = _connector(tmp_path, index, profile="ci")
    assert connector.profile == "ci"
    assert connector.walker.profile == "ci"
    assert connector.walker._zero_budget is False

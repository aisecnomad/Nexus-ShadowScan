"""Distinct repositories sharing one display label must retain distinct identities."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig
from shadowscan.engine import Engine


def _repositories(tmp_path: Path) -> tuple[Path, Path]:
    first, second = tmp_path / "first", tmp_path / "second"
    for root, dependency in ((first, "langchain"), (second, "crewai")):
        root.mkdir()
        (root / "requirements.txt").write_text(dependency + "\n")
    return first, second


def _scan(
    tmp_path: Path,
    roots: tuple[Path, ...],
    *,
    index,
    incremental: bool,
    inventory: Path | None = None,
    root_ids: tuple[str, ...] | None = None,
):
    connector_config = {"paths": [str(root) for root in roots], "use_git": False}
    if root_ids is not None:
        connector_config["root_ids"] = list(root_ids)
    return Engine(
        ScanConfig(
            connectors=[ConnectorSpec("code.filesystem", connector_config, label="github:acme/shared")],
            incremental=incremental,
            state_dir=str(tmp_path / "state"),
            inventory=[str(inventory)] if inventory else [],
            parallel=1,
        ),
        index,
    ).run()


@pytest.mark.parametrize("incremental", [False, True])
def test_labeled_multi_root_scan_never_merges_or_approves_the_other_root(tmp_path, index, incremental):
    first, second = _repositories(tmp_path)
    initial = _scan(tmp_path, (first, second), index=index, incremental=incremental)
    assert initial.complete and len(initial.findings) == 2
    by_root = {f.metadata["scan_root"]: f for f in initial.findings}
    assert set(by_root) == {str(first), str(second)}
    assert len({f.id for f in by_root.values()}) == 2
    assert len({f.resource for f in by_root.values()}) == 2
    assert all(f.resource.startswith("github:acme/shared/") for f in by_root.values())
    assert "framework.langchain" in by_root[str(first)].frameworks
    assert "framework.crewai" in by_root[str(second)].frameworks

    # Approving one concrete finding must not authorize the other repository.
    inventory = tmp_path / "approved.json"
    inventory.write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "id": "approved-first",
                        "resources": [by_root[str(first)].resource],
                    }
                ]
            }
        )
    )
    approved = _scan(tmp_path, (first, second), index=index, incremental=incremental, inventory=inventory)
    assert approved.complete and len(approved.findings) == 2
    assert approved.stats[0].cached is incremental
    approved_by_root = {f.metadata["scan_root"]: f for f in approved.findings}
    assert approved_by_root[str(first)].registry_match == "approved-first"
    assert approved_by_root[str(first)].shadow is False
    assert approved_by_root[str(second)].registry_match is None
    assert approved_by_root[str(second)].shadow is True
    assert {key: f.resource for key, f in approved_by_root.items()} == {
        key: f.resource for key, f in by_root.items()
    }


def test_multi_root_identity_is_stable_across_order_and_incremental_mode(tmp_path, index):
    first, second = _repositories(tmp_path)
    original = _scan(tmp_path, (first, second), index=index, incremental=False)
    reversed_cached = _scan(tmp_path, (second, first), index=index, incremental=True)
    original_ids = {f.metadata["scan_root"]: (f.resource, f.id) for f in original.findings}
    cached_ids = {f.metadata["scan_root"]: (f.resource, f.id) for f in reversed_cached.findings}
    assert original_ids == cached_ids


@pytest.mark.parametrize("incremental", [False, True])
@pytest.mark.parametrize("root_ids", [None, ("first-repository", "second-repository")])
def test_paths_list_identity_survives_shrinking_to_one_root(tmp_path, index, incremental, root_ids):
    first, second = _repositories(tmp_path)
    before = _scan(tmp_path, (first, second), index=index, incremental=incremental, root_ids=root_ids)
    after = _scan(
        tmp_path, (first,), index=index, incremental=incremental, root_ids=root_ids[:1] if root_ids else None
    )
    before_first = next(f for f in before.findings if f.metadata["scan_root"] == str(first))
    assert after.complete and len(after.findings) == 1
    assert (after.findings[0].resource, after.findings[0].id) == (before_first.resource, before_first.id)


@pytest.mark.parametrize("incremental", [False, True])
def test_explicit_root_ids_survive_relocated_checkouts(tmp_path, index, incremental):
    first, second = _repositories(tmp_path)
    original = _scan(
        tmp_path,
        (first, second),
        index=index,
        incremental=incremental,
        root_ids=("first-repository", "second-repository"),
    )
    relocated = tmp_path / "relocated"
    relocated.mkdir()
    new_first, new_second = relocated / "first", relocated / "second"
    shutil.copytree(first, new_first)
    shutil.copytree(second, new_second)
    moved = _scan(
        tmp_path,
        (new_second, new_first),
        index=index,
        incremental=incremental,
        root_ids=("second-repository", "first-repository"),
    )
    assert original.complete and moved.complete
    assert {f.resource for f in moved.findings} == {f.resource for f in original.findings}
    assert {f.id for f in moved.findings} == {f.id for f in original.findings}
    assert {f.resource for f in moved.findings} == {
        "github:acme/shared/root-id-first-repository",
        "github:acme/shared/root-id-second-repository",
    }


@pytest.mark.parametrize("incremental", [False, True])
@pytest.mark.parametrize("root_ids", [("duplicate", "duplicate"), ("only-one",), ("valid", "bad/*")])
def test_invalid_root_ids_fail_closed(tmp_path, index, incremental, root_ids):
    first, second = _repositories(tmp_path)
    result = _scan(tmp_path, (first, second), index=index, incremental=incremental, root_ids=root_ids)
    assert not result.complete and not result.findings
    assert any(st.errors for st in result.stats)


@pytest.mark.parametrize("incremental", [False, True])
@pytest.mark.parametrize("root_ids", [None, ("first-repository", "alias")])
def test_duplicate_resolved_paths_fail_closed(tmp_path, index, incremental, root_ids):
    (first, _) = _repositories(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(first, target_is_directory=True)
    result = _scan(tmp_path, (first, alias), index=index, incremental=incremental, root_ids=root_ids)
    assert not result.complete and not result.findings
    assert any(st.errors for st in result.stats)


@pytest.mark.parametrize("incremental", [False, True])
def test_single_path_string_retains_legacy_resource(tmp_path, index, incremental):
    (first, _) = _repositories(tmp_path)
    result = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(
                    "code.filesystem",
                    {
                        "path": str(first),
                        "use_git": False,
                    },
                    label="github:acme/shared",
                )
            ],
            incremental=incremental,
            state_dir=str(tmp_path / "state"),
            parallel=1,
        ),
        index,
    ).run()
    assert result.complete and len(result.findings) == 1
    assert result.findings[0].resource == "github:acme/shared"


def _entries_scan(tmp_path: Path, specs: list[ConnectorSpec], *, index, only: list[str] | None = None):
    config = ScanConfig(connectors=specs, state_dir=str(tmp_path / "state"), parallel=1)
    return Engine(config, index).run(only)


def _entry(entry: str, **config) -> ConnectorSpec:
    """A code.filesystem entry with id ``entry`` and its connector configuration."""
    return ConnectorSpec("code.filesystem", {"use_git": False, **config}, label=entry)


@pytest.mark.parametrize("layout", ["entry label", "nested label", "root ids"])
def test_entries_repeating_a_label_for_different_roots_are_refused(tmp_path, index, layout):
    # Separate entries do not get the per-root suffix of one entry's paths: the
    # second repository's findings would take the first one's ids and approval.
    first, second = _repositories(tmp_path)
    shared = "github:acme/shared"
    if layout == "entry label":
        specs = [_entry(shared, path=str(root)) for root in (first, second)]
    elif layout == "nested label":
        specs = [_entry(f"entry-{n}", path=str(root), label=shared) for n, root in enumerate((first, second))]
    else:
        specs = [
            _entry(f"entry-{n}", paths=[str(root)], root_ids=["main"], label=shared)
            for n, root in enumerate((first, second))
        ]
    with pytest.raises(ConfigValidationError, match="distinct label"):
        _entries_scan(tmp_path, specs, index=index)


@pytest.mark.parametrize("unlabelled", ["path", "paths"])
def test_explicit_label_repeating_an_unlabelled_root_path_is_refused(tmp_path, index, unlabelled):
    # An unlabelled root is labelled by its own path, which another entry can name explicitly.
    first, second = _repositories(tmp_path)
    plain = ConnectorSpec(
        "code.filesystem",
        {"use_git": False, unlabelled: str(first) if unlabelled == "path" else [str(first)]},
    )
    specs = [plain, _entry(str(first.resolve()), path=str(second))]
    with pytest.raises(ConfigValidationError, match="distinct label"):
        _entries_scan(tmp_path, specs, index=index)

    # Two unlabelled entries for the same root still scan it.
    again = [plain, ConnectorSpec("code.filesystem", {"use_git": False, "path": f"{first}/."})]
    assert _entries_scan(tmp_path, again, index=index).complete


def test_entries_repeating_a_label_for_one_root_or_unrun_entries_still_scan(tmp_path, index):
    first, second = _repositories(tmp_path)
    shared = "github:acme/shared"
    same_root = [_entry(shared, path=str(first)), _entry(shared, path=f"{tmp_path}/./first")]
    result = _entries_scan(tmp_path, same_root, index=index)
    assert result.complete and [f.resource for f in result.findings] == [shared]

    # Unnamed labelled paths roots keep distinct hashed prefixes, and an entry
    # left out by --only cannot collide with the one that runs.
    hashed = [_entry(shared, paths=[str(root)]) for root in (first, second)]
    assert len(_entries_scan(tmp_path, hashed, index=index).findings) == 2
    selected = [_entry(shared, path=str(first)), _entry("entry-b", path=str(second), label=shared)]
    only = _entries_scan(tmp_path, selected, index=index, only=["entry-b"])
    assert only.complete and [f.metadata["scan_root"] for f in only.findings] == [str(second)]

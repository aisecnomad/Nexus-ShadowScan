"""``diff`` never reads content a complete scan left unread as a resolved finding.

A ``ci`` profile scan stays complete although it declared omissions, and any
scan stays complete although its coverage budget tolerated gaps. A finding
observed in such content and missing from the current report may only have
gone unread: the comparison is incomplete (exit 3) and the finding unknown.
A finding missing from content the scan did read still resolves, so the
profile keeps diff useful. Credentials are derived at runtime so no
key-shaped literal appears here.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import compare_reports, drift_counts
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.code.path_context import may_be_declared
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface

_UNREAD = "absence there is not resolution"


def _credential(seed: str) -> str:
    return f"SERVICE_API_KEY={hashlib.sha256(seed.encode()).hexdigest()[:32]}\n"


def _scan(index, root: Path, *, label: str | None = None, **options) -> dict:
    spec = ConnectorSpec("code.filesystem", {"path": str(root), "use_git": False, **options}, label=label)
    return Engine(ScanConfig(connectors=[spec]), index=index).run().to_dict()


def _secrets(report: dict) -> list[str]:
    return sorted(f["metadata"]["path"] for f in report["findings"] if f["kind"] == "secret")


def _diff(tmp_path: Path, baseline: dict, current: dict):
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_text(json.dumps(baseline))
    after.write_text(json.dumps(current))
    return CliRunner().invoke(main, ["diff", str(before), str(after), "--json"])


def _repo(root: Path) -> Path:
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname = "svc"\nversion = "0.1"\n')
    (root / "src" / "app").mkdir(parents=True)
    for name in ("a", "b", "c", "d"):
        (root / "src" / "app" / f"{name}.py").write_text(f"VALUE_{name.upper()} = 1\n")
    return root


def test_ci_profile_declared_omission_does_not_resolve_a_credential(tmp_path, index):
    # The review's case: under --profile ci a credential whose docs file grew
    # past max_file_size was "1 resolved", exit 0; the key was still in it.
    # The profile no longer declares a file left unread for credentials: the
    # budget charges it (tolerated here), and diff still holds the key unknown.
    root = _repo(tmp_path / "repo")
    (root / "docs").mkdir()
    (root / "docs" / "setup.md").write_text("# Setup\n\n" + _credential("docs"))
    options = {"profile": "ci", "max_file_size": 4096, "max_coverage_gap": 0.5}
    baseline = _scan(index, root, **options)
    assert baseline["summary"]["complete"] and _secrets(baseline) == ["docs/setup.md"]
    with (root / "docs" / "setup.md").open("a") as handle:
        handle.write("lorem ipsum " * 600)
    current = _scan(index, root, **options)
    assert current["summary"]["complete"] and current["summary"]["declared_omissions"] == 0
    assert current["summary"]["tolerated_gaps"] == 1
    assert [gap["path"] for gap in current["stats"][0]["coverage"]["details"]] == ["docs/setup.md"]
    assert _secrets(current) == []
    result = _diff(tmp_path, baseline, current)
    assert result.exit_code == 3, result.output
    comparison = json.loads(result.output)
    assert comparison["comparable"] is False and comparison["resolved"] == []
    assert [f["metadata"]["path"] for f in comparison["unknown"]] == ["docs/setup.md"]
    assert any(_UNREAD in reason for reason in comparison["reasons"])
    assert drift_counts(baseline, current)["counts"]["resolved"] == 0


def test_tolerated_coverage_gap_does_not_resolve_a_credential(tmp_path, index):
    # The same with the coverage budget (#254): an oversize source file is a
    # partial gap the budget tolerates, so the scan is complete without the key.
    root = _repo(tmp_path / "repo")
    (root / "src" / "app" / "settings.py").write_text(_credential("settings"))
    options = {"max_file_size": 4096, "max_coverage_gap": 0.5}
    baseline = _scan(index, root, **options)
    assert baseline["summary"]["complete"] and _secrets(baseline) == ["src/app/settings.py"]
    with (root / "src" / "app" / "settings.py").open("a") as handle:
        handle.write("# padding\n" * 600)
    current = _scan(index, root, **options)
    coverage = current["stats"][0]["coverage"]
    assert current["summary"]["complete"] and coverage["within_budget"]
    assert [gap["path"] for gap in coverage["details"]] == ["src/app/settings.py"]
    result = _diff(tmp_path, baseline, current)
    assert result.exit_code == 3, result.output
    comparison = json.loads(result.output)
    assert comparison["resolved"] == []
    assert [f["metadata"]["path"] for f in comparison["unknown"]] == ["src/app/settings.py"]
    assert any(_UNREAD in reason and "1 tolerated coverage gap" in reason for reason in comparison["reasons"])


@pytest.mark.parametrize("unread", ["ci-profile", "tolerated"])
def test_a_result_reused_by_incremental_keeps_unread_content_from_resolving(tmp_path, index, unread):
    # The review's --incremental case: the third run reuses the second's
    # result, which once dropped declared_omissions and stats.coverage, so
    # diff of the first and third runs read the credential as resolved.
    root = _repo(tmp_path / "repo")
    if unread == "ci-profile":
        # The profile never declares a file left unread for credentials, so the
        # oversize docs file is a gap the budget tolerates, under the profile too.
        path, options, budget = root / "docs" / "setup.md", {"profile": "ci"}, 0.5
        path.parent.mkdir()
        path.write_text("# Setup\n\n" + _credential("docs"))
    else:
        path, options, budget = root / "src" / "app" / "settings.py", {}, 0.5
        path.write_text(_credential("settings"))
    spec = ConnectorSpec(
        "code.filesystem", {"path": str(root), "use_git": False, "max_file_size": 4096, **options}
    )
    config = ScanConfig(
        connectors=[spec], incremental=True, state_dir=str(tmp_path / "state"), max_coverage_gap=budget
    )

    def scan() -> dict:
        return Engine(config, index=index).run().to_dict()

    baseline = scan()
    assert baseline["summary"]["complete"] and len(_secrets(baseline)) == 1
    with path.open("a") as handle:
        handle.write("# padding\n" * 600)
    scan()
    current = scan()
    stats = current["stats"][0]
    assert current["summary"]["complete"] and stats["cached"] and _secrets(current) == []
    assert stats["declared_omissions"] == 0
    assert [gap["path"] for gap in stats["coverage"]["details"]] == [path.relative_to(root).as_posix()]
    result = _diff(tmp_path, baseline, current)
    assert result.exit_code == 3, result.output
    comparison = json.loads(result.output)
    assert comparison["resolved"] == [] and len(comparison["unknown"]) == 1
    assert any(_UNREAD in reason for reason in comparison["reasons"])


_AGENT = "from openai import OpenAI\n\nclient = OpenAI()\nclient.chat.completions.create(model='gpt-4o', messages=[])\n"


# A project directory is reported as its report-safe name, which keeps a
# literal backslash and writes undecodable bytes as \xNN escapes. Unread
# content inside it must hold the removed project back whatever its name.
_PROJECT_NAMES = [
    pytest.param(b"bot", id="plain"),
    pytest.param(
        b"b\\ot", id="backslash", marks=pytest.mark.skipif(sys.platform == "win32", reason="POSIX name")
    ),
    pytest.param(
        b"b\xffot", id="undecodable", marks=pytest.mark.skipif(sys.platform != "linux", reason="raw bytes")
    ),
]


@pytest.mark.parametrize("name", _PROJECT_NAMES)
@pytest.mark.parametrize("unread", ["declared", "tolerated"])
def test_unread_content_inside_a_project_holds_it_back_whatever_its_name(tmp_path, index, name, unread):
    root = _repo(tmp_path / "repo")
    project = os.path.join(os.fsencode(root), name)
    os.mkdir(project)
    with open(os.path.join(project, b"pyproject.toml"), "w") as handle:
        handle.write('[project]\nname = "bot"\nversion = "0.1"\n')
    with open(os.path.join(project, b"agent.py"), "w") as handle:
        handle.write(_AGENT)
    options = {"profile": "ci"} if unread == "declared" else {"max_coverage_gap": 0.5}
    baseline = _scan(index, root, max_file_size=4096, **options)
    projects = [f for f in baseline["findings"] if f.get("resource_type") == "project"]
    assert len({f["metadata"]["path"] for f in projects if f["metadata"]["path"] != "."}) == 1
    # The agent's code moves somewhere the scan no longer reads: behind a link
    # the profile declares, or into a file the budget tolerates.
    os.unlink(os.path.join(project, b"agent.py"))
    if unread == "declared":
        os.makedirs(os.path.join(project, b"examples"))
        os.symlink(b"../../outside/agent.py", os.path.join(project, b"examples", b"agent.py"))
    else:
        with open(os.path.join(project, b"tools.py"), "w") as handle:
            handle.write(_AGENT + "#" * 5000 + "\n")
    current = _scan(index, root, max_file_size=4096, **options)
    assert current["summary"]["complete"]
    result = _diff(tmp_path, baseline, current)
    assert result.exit_code == 3, result.output
    comparison = json.loads(result.output)
    assert comparison["comparable"] is False
    unknown = {f["metadata"].get("path") for f in comparison["unknown"]}
    assert {f["metadata"]["path"] for f in projects if f["metadata"]["path"] != "."} <= unknown


@pytest.mark.parametrize("cassettes", ["tests/cassettes", "src/bot/tests/cassettes"])
def test_a_removed_project_resolves_unless_a_declared_omission_lies_in_it(tmp_path, index, cassettes):
    # The review's case: any declared omission anywhere held back every
    # missing project finding, so removing an agent under --profile ci always
    # exited 3. A cassette elsewhere cannot hold the project's evidence.
    root = _repo(tmp_path / "repo")
    project = root / "src" / "bot"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname = "bot"\nversion = "0.1"\ndependencies = ["openai"]\n'
    )
    (project / "agent.py").write_text(_AGENT)
    (root / cassettes).mkdir(parents=True)
    # A dangling link: declared under the profile, and no credential left unread.
    (root / cassettes / "run.json").symlink_to(root / "missing-run.json")
    baseline = _scan(index, root, profile="ci", max_file_size=4096)
    assert baseline["summary"]["complete"] and baseline["summary"]["declared_omissions"] == 1
    assert "src/bot" in {f["metadata"].get("path") for f in baseline["findings"]}
    for name in ("pyproject.toml", "agent.py"):
        (project / name).unlink()
    current = _scan(index, root, profile="ci", max_file_size=4096)
    assert current["summary"]["complete"] and current["stats"][0]["declared_paths"] == [
        f"{cassettes}/run.json"
    ]
    assert current["findings"] == []
    result = _diff(tmp_path, baseline, current)
    comparison = json.loads(result.output)
    if cassettes == "tests/cassettes":
        assert result.exit_code == 0, result.output
        assert comparison["comparable"] is True and comparison["unknown"] == []
        assert len(comparison["resolved"]) == len(baseline["findings"])
    else:
        assert result.exit_code == 3, result.output
        assert comparison["resolved"] == [] and any(_UNREAD in reason for reason in comparison["reasons"])


def test_a_credential_removed_from_read_content_still_resolves_under_the_profile(tmp_path, index):
    # A declared omission in docs/ does not hold back a credential deleted from src/.
    root = _repo(tmp_path / "repo")
    (root / "src" / "app" / "settings.py").write_text(_credential("settings"))
    (root / "docs").mkdir()
    # A dangling certificate link: declared, and no credential detection skipped for it.
    (root / "docs" / "ca.pem").symlink_to(root / "missing-ca.pem")
    baseline = _scan(index, root, profile="ci", max_file_size=4096)
    assert baseline["summary"]["declared_omissions"] == 1 and _secrets(baseline) == ["src/app/settings.py"]
    (root / "src" / "app" / "settings.py").write_text("SERVICE_API_KEY = load_from_vault()\n")
    current = _scan(index, root, profile="ci", max_file_size=4096)
    assert current["summary"]["declared_omissions"] == 1 and _secrets(current) == []
    comparison = compare_reports(baseline, current)
    assert comparison["comparable"] is True and comparison["unknown"] == []
    assert [f["metadata"]["path"] for f in comparison["resolved"]] == ["src/app/settings.py"]


@pytest.mark.parametrize("unread", ["ci-profile", "tolerated"])
def test_a_labeled_connectors_unread_content_does_not_resolve_a_credential(tmp_path, index, unread):
    # The review's labeled case: stats[].connector is the label while the
    # finding names code.filesystem, so the lookup missed and diff printed
    # "1 resolved", exit 0, for a key still in the file.
    root = _repo(tmp_path / "repo")
    if unread == "ci-profile":
        # Never declared while unread for credentials: the budget tolerates it.
        path, options = root / "docs" / "setup.md", {"profile": "ci", "max_coverage_gap": 0.5}
        path.parent.mkdir()
        path.write_text("# Setup\n\n" + _credential("docs"))
    else:
        path, options = root / "src" / "app" / "settings.py", {"max_coverage_gap": 0.5}
        path.write_text(_credential("settings"))
    label = "github:acme/ops-agent"
    baseline = _scan(index, root, label=label, max_file_size=4096, **options)
    assert baseline["summary"]["complete"] and len(_secrets(baseline)) == 1
    with path.open("a") as handle:
        handle.write("# padding\n" * 600)
    current = _scan(index, root, label=label, max_file_size=4096, **options)
    stats = current["stats"][0]
    assert stats["connector"] == label and stats["name"] == "code.filesystem"
    assert current["summary"]["complete"] and _secrets(current) == []
    result = _diff(tmp_path, baseline, current)
    assert result.exit_code == 3, result.output
    comparison = json.loads(result.output)
    assert comparison["resolved"] == [] and len(comparison["unknown"]) == 1


def test_a_record_that_does_not_name_its_connector_holds_back_every_finding_it_may_own():
    # A report from before stats[].name: the record's id may be a label, so
    # its unread content applies to every connector's findings, and a label
    # locates no declared omission (fail closed). A named record applies only
    # to its own connector's findings.
    baseline = _report(_finding("src/app/settings.py"), connectors=("github:acme/ops-agent",))
    current = _report(connectors=("github:acme/ops-agent",))
    stats = current["stats"][0]
    stats["coverage"] = _coverage("src/app/settings.py")
    del stats["name"]
    assert _resolved(baseline, current) == []
    stats["coverage"] = None
    stats["declared_omissions"] = current["summary"]["declared_omissions"] = 1
    assert _resolved(baseline, current) == []
    stats["name"] = "code.github"
    stats["coverage"] = _coverage("src/app/settings.py")
    assert _resolved(baseline, current) == ["src/app/settings.py"]
    stats["name"] = "code.filesystem"
    assert _resolved(baseline, current) == []
    stats["coverage"] = None
    assert _resolved(baseline, current) == ["src/app/settings.py"]


# ------------------------------------------------------------ the rule, on synthetic reports
def _finding(path: str, *, connector: str = "code.filesystem", resource_type: str = "file") -> dict:
    finding = Finding(
        surface=Surface.CODE,
        connector=connector,
        kind=Kind.SECRET if resource_type == "file" else Kind.AGENT,
        title=path,
        resource=f"repo/{path}",
        resource_type=resource_type,
    ).to_dict()
    finding["risk"] = {"level": "high", "score": 55, "factors": []}
    finding["metadata"] = {"path": path}
    finding["evidence"] = [{"signal": "s", "description": "d", "location": f"{path}:3", "weight": 0.5}]
    if resource_type == "project":
        finding["evidence"][0]["location"] = f"{path}/agent.py:1"
    return finding


def _gap(path: str) -> dict:
    return {
        "detail": "d",
        "path": path,
        "kind": "partial",
        "entries": 1,
        "full_weight": False,
        "reason": "unresolved-link",
        "relevance": "high",
    }


def _coverage(*paths: str, total: int | None = None) -> dict:
    gaps = total if total is not None else len(paths)
    return {
        "examined": 100,
        "gaps": gaps,
        "blinding_gaps": 0,
        "gap_entries": gaps,
        "weighted_gap_entries": float(gaps),
        "allowance": 2.0,
        "within_budget": True,
        "max_gap_ratio": 0.02,
        "details": [_gap(path) for path in paths],
        **({"details_truncated": gaps - len(paths)} if gaps > len(paths) else {}),
    }


def _report(*findings: dict, connectors: tuple[str, ...] = ("code.filesystem",)) -> dict:
    report = ScanResult(
        # As the engine records them: the configured id, and the name findings carry.
        stats=[ScanStats(connector=name, started_at="2026-01-01", name=name) for name in connectors],
        collection_scope={
            "schema": "shadowscan.collection-scope/v1",
            "comparable": True,
            "fingerprint": "a" * 64,
        },
    ).to_dict()
    report["findings"] = list(findings)
    report["summary"].update(
        total=len(findings),
        by_surface=dict(Counter(f["surface"] for f in findings)),
        by_kind=dict(Counter(f["kind"] for f in findings)),
    )
    return report


def _resolved(baseline: dict, current: dict) -> list[str]:
    comparison = compare_reports(baseline, current)
    counts = drift_counts(baseline, current)
    assert counts["comparable"] is comparison["comparable"]
    assert counts["counts"]["resolved"] == len(comparison["resolved"])
    if not comparison["comparable"]:
        assert comparison["resolved"] == [] and any(_UNREAD in reason for reason in comparison["reasons"])
    return sorted(f["metadata"]["path"] for f in comparison["resolved"])


def test_gap_paths_hold_back_only_the_findings_observed_there():
    baseline = _report(_finding("src/app/settings.py"), _finding("src/app/other.py"))
    current = _report()
    current["stats"][0]["coverage"] = _coverage("lib/vendor.py")
    assert _resolved(baseline, current) == ["src/app/other.py", "src/app/settings.py"]
    current["stats"][0]["coverage"] = _coverage("src/app/settings.py")
    assert _resolved(baseline, current) == []
    # A gap at a directory (a directory link) covers the files below it.
    current["stats"][0]["coverage"] = _coverage("src/app")
    assert _resolved(baseline, current) == []


def test_a_project_is_held_back_by_unread_content_inside_or_above_it():
    baseline = _report(_finding("services/bot", resource_type="project"))
    current = _report()
    stats = current["stats"][0]
    stats["coverage"] = _coverage("services/other/main.py")
    assert _resolved(baseline, current) == ["services/bot"]
    # Its evidence could have moved to any file in it, read or not.
    stats["coverage"] = _coverage("services/bot/tools.py")
    assert _resolved(baseline, current) == []
    stats["coverage"] = None
    stats["declared_omissions"] = current["summary"]["declared_omissions"] = 1
    for listed, resolved in [
        # A declared omission in another project, or beside this one, cannot hide it.
        (["services/other/tests/big.json"], ["services/bot"]),
        (["services/bot-two/docs/a.md"], ["services/bot"]),
        (["tests/cassettes/run.yaml"], ["services/bot"]),
        # One inside it, at it or above it (a directory entry) can.
        (["services/bot/tests/big.json"], []),
        (["services/bot"], []),
        (["services"], []),
    ]:
        stats["declared_paths"] = listed
        assert _resolved(baseline, current) == resolved, listed
    # A report that cannot say where every declared omission lies holds every project back:
    # one from before the list, a list cut short, or a malformed or root entry.
    for listed in [None, [], ["tests/a.json", "tests/b.json"], [3], ["."]]:
        stats["declared_paths"] = listed
        assert _resolved(baseline, current) == [], listed
    del stats["declared_paths"]
    assert _resolved(baseline, current) == []
    # The root project holds every listed omission.
    stats["declared_paths"] = ["tests/cassettes/run.yaml"]
    assert _resolved(_report(_finding(".", resource_type="project")), current) == []


@pytest.mark.parametrize("path", ["tests/fixtures/key.json", "docs/setup.md", "examples/x/app.py"])
def test_a_declared_omission_holds_back_findings_in_the_paths_the_profile_declares(path):
    baseline = _report(_finding(path), _finding("src/app/settings.py"))
    current = _report()
    current["stats"][0]["declared_omissions"] = current["summary"]["declared_omissions"] = 1
    assert _resolved(baseline, current) == []
    comparison = compare_reports(baseline, current)
    assert sorted(f["metadata"]["path"] for f in comparison["unknown"]) == sorted(
        [path, "src/app/settings.py"]
    )
    assert any("1 missing finding(s)" in reason for reason in comparison["reasons"])
    # Only the finding the profile could have hidden blocks the comparison.
    assert _resolved(_report(_finding("src/app/settings.py")), current) == ["src/app/settings.py"]


@pytest.mark.parametrize(
    "mutation", ["truncated", "malformed", "unattributed", "boolean_summary", "plugin", "bad_count"]
)
def test_unread_content_the_report_cannot_locate_holds_back_every_missing_finding(mutation):
    connector = "acme.scanner" if mutation == "plugin" else "code.filesystem"
    baseline = _report(_finding("src/app/settings.py", connector=connector), connectors=(connector,))
    current = _report(connectors=(connector,))
    stats = current["stats"][0]
    if mutation == "truncated":
        # 60 gaps, 50 listed: the one not listed may be the finding's file.
        stats["coverage"] = _coverage(*(f"lib/{n}.py" for n in range(50)), total=60)
    elif mutation == "malformed":
        stats["coverage"] = {**_coverage("lib/a.py"), "details": "src/app/settings.py"}
    elif mutation == "unattributed":
        current["summary"]["declared_omissions"] = 1
    elif mutation == "boolean_summary":
        stats["declared_omissions"] = 1
        current["summary"]["declared_omissions"] = True
    elif mutation == "plugin":
        # A plugin's declared omission is not bound to the ci profile's paths.
        stats["declared_omissions"] = current["summary"]["declared_omissions"] = 1
    else:
        stats["declared_omissions"] = "1"
    assert _resolved(baseline, current) == []
    assert compare_reports(baseline, current)["comparable"] is False


def test_a_finding_whose_connector_is_not_a_name_is_held_back_without_failing():
    # drift_counts (dashboard history) validates records without exporting them,
    # so an unhashable connector field reaches the unread check: every
    # connector's gaps apply to it.
    record = _finding("src/app/settings.py")
    record["connector"] = ["code.filesystem"]
    connectors = ("code.filesystem", "code.github")
    baseline, current = _report(record, connectors=connectors), _report(connectors=connectors)
    current["stats"][1]["coverage"] = _coverage("src/app/settings.py")
    held = drift_counts(baseline, current)
    assert held["comparable"] is False and held["counts"]["unknown"] == 1
    current["stats"][1]["coverage"] = _coverage("lib/vendor.py")
    assert drift_counts(baseline, current)["counts"]["resolved"] == 1


def test_a_report_without_unread_content_resolves_as_before():
    baseline = _report(_finding("src/app/settings.py"), _finding(".", resource_type="project"))
    current = _report()
    assert _resolved(baseline, current) == [".", "src/app/settings.py"]
    # Baseline-side gaps never hold back a resolution: they could only make a finding look new.
    gapped = copy.deepcopy(baseline)
    gapped["stats"][0]["coverage"] = _coverage("src/app/settings.py")
    gapped["stats"][0]["declared_omissions"] = gapped["summary"]["declared_omissions"] = 1
    assert _resolved(gapped, current) == [".", "src/app/settings.py"]


@pytest.mark.parametrize(
    "rel",
    [
        "tests/fixtures/a.json",
        "pkg/test_mod.py",
        "docs/a.md",
        "svc/docs/a.md",
        "examples/svc/docs/a.md",
        "templates/crew/crew.py",
        # A template's own manifest does not make its directory a project (judged from the root).
        "templates/{{cookiecutter.slug}}/pyproject.toml",
        "lib/schema.generated.json",
        "gen/api_pb2.py",
    ],
)
def test_may_be_declared_covers_every_path_the_profile_declares(run_connector, tmp_path, rel):
    # The diff rule is a superset of the connector's: whatever project root a
    # declared path has, may_be_declared names it. A dangling link is declared
    # in every such path (an oversize file is not, while credentials are read).
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(tmp_path / "missing")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, profile="ci")
    assert ctx.stats.declared_omissions == 1, ctx.stats.warnings
    assert may_be_declared(rel)
    assert not may_be_declared("src/app/settings.py") and not may_be_declared("demo")


def test_diff_reads_a_ledger_over_budget_as_incomplete_whatever_the_flag_says(tmp_path, index):
    # The rule merge applies: a report whose own ledger is over budget (or
    # blinded) did not read everything, so its missing findings do not resolve.
    root = _repo(tmp_path / "repo")
    (root / "svc").mkdir()
    (root / "svc" / ".mcp.json").write_text('{"mcpServers": {"evil": {"command": "npx"}}}')
    (root / "certs").mkdir()
    (root / "certs" / "server.pem").symlink_to(root / "missing.pem")
    options = {"max_coverage_gap": 0.5}
    baseline = _scan(index, root, **options)
    assert baseline["summary"]["complete"] and baseline["stats"][0]["coverage"]["within_budget"]
    (root / "svc" / ".mcp.json").unlink()
    current = _scan(index, root, **options)
    assert not [f for f in current["findings"] if f["kind"] == "mcp-server"]
    result = _diff(tmp_path, baseline, current)
    assert result.exit_code == 0 and json.loads(result.output)["comparable"] is True
    for forged in ({"within_budget": False}, {"blinding_gaps": 1}):
        report = copy.deepcopy(current)
        report["stats"][0]["coverage"].update(forged)
        result = _diff(tmp_path, baseline, report)
        assert result.exit_code == 3, result.output
        comparison = json.loads(result.output)
        assert comparison["comparable"] is False and comparison["resolved"] == []

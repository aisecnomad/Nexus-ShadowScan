"""Unit tests for the ShadowBench cases-track tool adapters, install script and code fetcher.

No third-party tool runs here: adapters are fed recorded-shape output, ``subprocess.run`` is
replaced where a probe or ``git`` would run, and ``install_tools.sh`` is read as text only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools.discovery_benchmark import taxonomy
from tools.shadowbench.cases import fetch_code
from tools.shadowbench.cases.adapters.registry import load_adapters
from tools.shadowbench.cases.contract import AdapterResult, MaterializedCase, RunResult, ToolEnv

ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "tools" / "shadowbench" / "cases" / "install_tools.sh"
MANIFEST = ROOT / "benchmarks" / "shadowbench" / "cases" / "results" / "2026-10-11" / "manifest.json"
ADAPTERS, PROBLEMS = load_adapters()
SHA = "0123456789abcdef0123456789abcdef01234567"


def _case(tmp_path: Path, surface: str, modality: str, **extra: Any) -> MaterializedCase:
    root = tmp_path / "case"
    inputs = root / "inputs"
    inputs.mkdir(parents=True)
    home = None
    if surface == "endpoint":
        home = inputs / "home"
        home.mkdir()
    if surface == "code":
        (inputs / "repo").mkdir()
    return MaterializedCase("case-001", surface, modality, "family", root, inputs, home=home, **extra)


def _work(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    work.mkdir()
    return work


def _normalize(
    tmp_path: Path, tool: str, surface: str, modality: str, stdout: str, **extra: Any
) -> tuple[AdapterResult, MaterializedCase, Path]:
    case = _case(tmp_path, surface, modality, **extra)
    work = _work(tmp_path)
    result = ADAPTERS[tool].normalize(case, work, [RunResult(0, stdout, "", 1.0)])
    return result, case, work


def test_every_adapter_module_loads() -> None:
    assert not PROBLEMS
    assert {
        "agentdiscover",
        "agentmesh-discovery",
        "ai-infra-guard",
        "cisco-mcp-scanner",
        "fleet-ai-tools",
        "numbat",
        "shadowscan",
        "snyk-agent-scan",
        "vet",
    } <= set(ADAPTERS)


# --- fail closed: no output, or output that does not parse, is an error ---------------------------

SERVICES = [{"ip": "127.0.0.1", "port": 18434, "product": "ollama"}]
SUPPORTED: list[tuple[str, str, str]] = [
    ("agentdiscover", "endpoint", "home"),
    ("agentdiscover", "code", "checkout"),
    ("agentmesh-discovery", "endpoint", "home"),
    ("agentmesh-discovery", "code", "checkout"),
    ("agentmesh-discovery", "runtime", "live"),
    ("ai-infra-guard", "network", "active"),
    ("cisco-mcp-scanner", "endpoint", "home"),
    ("fleet-ai-tools", "endpoint", "home"),
    ("fleet-ai-tools", "runtime", "live"),
    ("numbat", "endpoint", "home"),
    ("snyk-agent-scan", "endpoint", "home"),
    ("vet", "endpoint", "home"),
    ("vet", "code", "checkout"),
    ("shadowscan", "identity", "okta-export"),
    ("shadowscan", "endpoint", "home"),
]


@pytest.mark.parametrize(("tool", "surface", "modality"), SUPPORTED)
def test_empty_output_with_exit_zero_is_an_error(
    tmp_path: Path, tool: str, surface: str, modality: str
) -> None:
    """numbat, fleet-ai-tools, AI-Infra-Guard and vet scored an empty run as a clean negative."""
    services = SERVICES if surface == "network" else []
    result, _, _ = _normalize(tmp_path, tool, surface, modality, "", services=services)
    assert result.status == "error", result.note
    assert result.entities == []


@pytest.mark.parametrize(("tool", "surface", "modality"), SUPPORTED)
def test_unparseable_output_is_an_error(tmp_path: Path, tool: str, surface: str, modality: str) -> None:
    case = _case(tmp_path, surface, modality, services=SERVICES if surface == "network" else [])
    work = _work(tmp_path)
    garbled = '{"truncated": [1, 2'
    # Tools that write a report file get the garbled text there; the others print it.
    if tool == "vet":
        (work / "vet.json").write_text(garbled, encoding="utf-8")
    if tool == "shadowscan":
        (work / "report.json").write_text(garbled, encoding="utf-8")
    result = ADAPTERS[tool].normalize(case, work, [RunResult(0, garbled, "", 1.0)])
    assert result.status == "error", result.note
    assert result.entities == []


def test_numbat_marks_an_incomplete_at_rest_scan(tmp_path: Path) -> None:
    rows = [
        {"agent": "Claude Code", "present": True, "detected": True, "at_rest_scan_incomplete": True},
        {"agent": "Codex", "present": False, "detected": False, "at_rest_scan_incomplete": False},
    ]
    result, _, _ = _normalize(tmp_path, "numbat", "endpoint", "home", json.dumps(rows))
    assert result.status == "ok"
    assert [e.key for e in result.entities] == ["artifact:.claude"]
    assert result.raw["incomplete"] is True
    assert "at-rest scan incomplete for: Claude Code" in result.note


@pytest.mark.parametrize(
    ("flag", "incomplete"),
    [
        (True, True),
        ("true", True),
        (1, True),
        ({"reason": "budget"}, True),
        (False, False),
        (None, False),
        ("", False),
        ("false", False),
        (0, False),
    ],
)
def test_numbat_incomplete_flag_values(tmp_path: Path, flag: Any, incomplete: bool) -> None:
    rows = [{"agent": "Codex", "present": True, "at_rest_scan_incomplete": flag}]
    result, _, _ = _normalize(tmp_path, "numbat", "endpoint", "home", json.dumps(rows))
    assert result.status == "ok"
    assert bool(result.raw.get("incomplete")) is incomplete


def test_numbat_empty_array_is_a_clean_complete_result(tmp_path: Path) -> None:
    result, _, _ = _normalize(tmp_path, "numbat", "endpoint", "home", "[]\n")
    assert result.status == "ok"
    assert result.entities == []
    assert result.raw["incomplete"] is False


@pytest.mark.parametrize("report", ["null", "[]", "null\n"])
def test_vet_explicit_empty_report_is_ok(tmp_path: Path, report: str) -> None:
    case = _case(tmp_path, "endpoint", "home")
    work = _work(tmp_path)
    (work / "vet.json").write_text(report, encoding="utf-8")
    result = ADAPTERS["vet"].normalize(case, work, [RunResult(0, "", "", 1.0)])
    assert result.status == "ok"
    assert result.entities == []


def test_vet_empty_report_file_is_an_error(tmp_path: Path) -> None:
    case = _case(tmp_path, "endpoint", "home")
    work = _work(tmp_path)
    (work / "vet.json").write_text("  \n", encoding="utf-8")
    result = ADAPTERS["vet"].normalize(case, work, [RunResult(0, "", "", 1.0)])
    assert result.status == "error"


AIG_BANNER = "\x1b[1mAI Infrastructure Guard System v4.6.5\x1b[0m\n[INFO] loaded 166 fingerprints\n"
AIG_LINE = "http://127.0.0.1:18434 [\x1b[32m200\x1b[0m]  [] [ollama:0.5.1]\n"


def test_ai_infra_guard_banner_without_result_line_is_an_error(tmp_path: Path) -> None:
    result, _, _ = _normalize(tmp_path, "ai-infra-guard", "network", "active", AIG_BANNER, services=SERVICES)
    assert result.status == "error"
    assert "no result line" in result.note


def test_ai_infra_guard_reads_result_lines_from_stdout(tmp_path: Path) -> None:
    """The stdout check passed ``re.MULTILINE`` as a start position and always fell back to ``-o``."""
    case = _case(tmp_path, "network", "active", services=SERVICES)
    work = _work(tmp_path)
    (work / "aig.txt").write_text("", encoding="utf-8")
    result = ADAPTERS["ai-infra-guard"].normalize(case, work, [RunResult(0, AIG_BANNER + AIG_LINE, "", 1.0)])
    assert result.status == "ok"
    assert [(e.key, e.label) for e in result.entities] == [("service:127.0.0.1:18434", "llm")]


def test_ai_infra_guard_falls_back_to_the_output_file(tmp_path: Path) -> None:
    case = _case(tmp_path, "network", "active", services=SERVICES)
    work = _work(tmp_path)
    (work / "aig.txt").write_text(AIG_LINE, encoding="utf-8")
    result = ADAPTERS["ai-infra-guard"].normalize(case, work, [RunResult(0, AIG_BANNER, "", 1.0)])
    assert result.status == "ok"
    assert [e.key for e in result.entities] == ["service:127.0.0.1:18434"]


def test_shadowscan_report_without_findings_is_an_error(tmp_path: Path) -> None:
    case = _case(tmp_path, "identity", "okta-export")
    work = _work(tmp_path)
    (work / "report.json").write_text(json.dumps({"summary": {"complete": True}}), encoding="utf-8")
    result = ADAPTERS["shadowscan"].normalize(case, work, [RunResult(0, "", "", 1.0)])
    assert result.status == "error"


def test_shadowscan_empty_complete_report_is_ok(tmp_path: Path) -> None:
    case = _case(tmp_path, "identity", "okta-export")
    work = _work(tmp_path)
    report = {"summary": {"complete": True}, "findings": []}
    (work / "report.json").write_text(json.dumps(report), encoding="utf-8")
    result = ADAPTERS["shadowscan"].normalize(case, work, [RunResult(0, "", "", 1.0)])
    assert result.status == "ok"
    assert result.raw["incomplete"] is False


# --- code surface: hits that map to no taxonomy fact are dropped -----------------------------------


def _only_facts(result: AdapterResult) -> None:
    assert result.status == "ok", result.note
    keys = [e.key for e in result.entities]
    assert all(taxonomy.is_fact(k) for k in keys), keys
    assert not any(k.startswith("artifact:") for k in keys), keys


def test_agentdiscover_drops_unmappable_code_hits(tmp_path: Path) -> None:
    case = _case(tmp_path, "code", "checkout")
    work = _work(tmp_path)
    repo = case.inputs / "repo"
    (repo / ".mcp").mkdir()
    (repo / ".mcp" / "config.json").write_text(
        '{"mcpServers": {"files": {"command": "npx"}}}', encoding="utf-8"
    )
    report = {
        "summary": {"total_agents": 1, "detection_coverage": {"layer1": 2}},
        "inventory": {"confirmed": [{"code_file": "crew.py", "framework": "CrewAI", "rule_id": "DAI002"}]},
        "mcp": {
            "servers": [
                {"server_name": "files", "client": "Project MCP"},
                {"server_name": "left-pad", "client": "Project MCP", "source": "package.json"},
            ]
        },
        "scan_path": str(repo),
    }
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": rule,
                        "message": {"text": text},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                    }
                    for rule, text, uri in (
                        ("DAI002", "CrewAI Agent detected", "crew.py"),
                        ("DAI009", "Generation parameters detected", "gen.py"),
                    )
                ]
            }
        ]
    }
    (work / "agentdiscover").mkdir()
    (work / "agentdiscover" / "layer1_code.sarif").write_text(json.dumps(sarif), encoding="utf-8")
    stdout = "AgentDiscover v2.9.5\n" + json.dumps(report) + "\n"
    result = ADAPTERS["agentdiscover"].normalize(case, work, [RunResult(0, stdout, "", 1.0)])
    _only_facts(result)
    assert {e.key for e in result.entities} == {"framework:crewai"}
    assert "unmapped" in result.note and ".mcp/config.json" in result.note


def test_agentmesh_discovery_drops_unmappable_code_hits(tmp_path: Path) -> None:
    case = _case(tmp_path, "code", "checkout")
    work = _work(tmp_path)
    repo = case.inputs / "repo"
    records = [
        {"agent_type": "agt", "name": "mesh", "evidence": [{"source": str(repo / "agentmesh.yaml")}]},
        {"agent_type": "crewai", "name": "crew", "evidence": [{"source": str(repo / "crewai.yaml")}]},
    ]
    stdout = "Agent Discovery Scan\nFound 2 agents\n" + json.dumps(records) + "\nInventory saved to x\n"
    result = ADAPTERS["agentmesh-discovery"].normalize(case, work, [RunResult(0, stdout, "", 1.0)])
    _only_facts(result)
    assert {e.key for e in result.entities} == {"framework:crewai"}
    assert "agentmesh.yaml" in result.note


def test_vet_drops_unmappable_code_hits(tmp_path: Path) -> None:
    case = _case(tmp_path, "code", "checkout")
    work = _work(tmp_path)
    repo = case.inputs / "repo"
    items = [
        {"Kind": 4, "App": "claude", "ConfigPath": str(repo / "bin" / "claude")},
        {"Kind": 1, "App": "cursor", "ConfigPath": str(repo / ".cursor" / "mcp.json")},
    ]
    (work / "vet.json").write_text(json.dumps(items), encoding="utf-8")
    result = ADAPTERS["vet"].normalize(case, work, [RunResult(0, "", "", 1.0)])
    _only_facts(result)
    assert {e.key for e in result.entities} == {"mcp-client-config:cursor"}


# --- version probes: scrubbed environment, throwaway home, timeout ---------------------------------

SECRETS = {
    "HTTPS_PROXY": "http://proxy.invalid:3128",
    "https_proxy": "http://proxy.invalid:3128",
    "ALL_PROXY": "socks5://proxy.invalid:1080",
    "AWS_SECRET_ACCESS_KEY": "probe-test-not-a-secret",
    "GITHUB_TOKEN": "probe-test-not-a-token",
    "OPENAI_API_KEY": "probe-test-not-a-key",
}
PROBE_ENV_KEYS = {
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "NO_COLOR",
    "TERM",
    "VET_DISABLE_TELEMETRY",
    "PYTHONPATH",
    "PYTHONDONTWRITEBYTECODE",
}
PROBED = [
    "agentdiscover",
    "agentmesh-discovery",
    "ai-infra-guard",
    "cisco-mcp-scanner",
    "fleet-ai-tools",
    "numbat",
    "shadowscan",
    "snyk-agent-scan",
    "vet",
]
BINARIES = (
    "python",
    "agentdiscover",
    "agent-discovery",
    "mcp-scanner",
    "snyk-agent-scan",
    "numbat",
    "vet",
    "ai-infra-guard",
    "fleet-ai-tools",
)


def _tool_env(tmp_path: Path) -> ToolEnv:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in BINARIES:
        (bindir / name).write_text("", encoding="utf-8")
    # cisco-mcp-scanner is listed under both its adapter name and the console-script name earlier
    # configurations used, so this test does not depend on which key the adapter reads.
    tools: dict[str, dict[str, str]] = {
        "agentdiscover": {"bin": str(bindir / "agentdiscover")},
        "agentmesh-discovery": {"bin": str(bindir / "agent-discovery")},
        "cisco-mcp-scanner": {"bin": str(bindir / "mcp-scanner")},
        "mcp-scanner": {"bin": str(bindir / "mcp-scanner")},
        "snyk-agent-scan": {"bin": str(bindir / "snyk-agent-scan")},
        "numbat": {"bin": str(bindir / "numbat")},
        "vet": {"bin": str(bindir / "vet")},
        "ai-infra-guard": {"bin": str(bindir / "ai-infra-guard")},
        "fleet-ai-tools": {"bin": str(bindir / "fleet-ai-tools")},
        "shadowscan": {"bin": str(bindir / "python"), "repo": str(tmp_path)},
    }
    return ToolEnv(tool_root=tmp_path, config={"tools": tools})


@pytest.mark.parametrize("tool", PROBED)
def test_version_probe_runs_scrubbed_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    """version() ran the third-party binary with the operator's environment and no timeout."""
    real_home = tmp_path / "operator-home"
    real_home.mkdir()
    monkeypatch.setenv("HOME", str(real_home))
    for key, value in SECRETS.items():
        monkeypatch.setenv(key, value)
    env = _tool_env(tmp_path)
    calls: list[dict[str, Any]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        probe_env = kwargs.get("env")
        home = Path(probe_env["HOME"]) if probe_env and "HOME" in probe_env else None
        calls.append({"argv": list(argv), **kwargs, "home_existed": bool(home and home.is_dir())})
        return subprocess.CompletedProcess(argv, 0, stdout="tool v1.2.3\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    ADAPTERS[tool].version(env)
    probes = [c for c in calls if c["argv"][0] != "git"]  # git reads the operator's own ShadowScan checkout
    assert probes, f"{tool}: version() ran nothing"
    for call in probes:
        argv, probe_env = call["argv"], call.get("env")
        if argv[0].endswith("unshare"):
            assert argv[1:3] == ["--net", "--"]
        assert probe_env is not None, f"{tool}: {argv} inherited the caller's environment"
        assert set(probe_env) <= PROBE_ENV_KEYS, sorted(set(probe_env) - PROBE_ENV_KEYS)
        assert not set(SECRETS.values()) & set(probe_env.values())
        assert probe_env["LANG"] == "C.UTF-8"
        assert probe_env["HOME"] != str(real_home)
        assert call["home_existed"], "the probe home is a real (throwaway) directory"
        assert not Path(probe_env["HOME"]).exists(), "the throwaway home is removed afterwards"
        assert call.get("timeout") is not None and call["timeout"] <= 60
        assert call.get("stdin") is subprocess.DEVNULL


def test_probe_isolates_the_network_only_as_root(monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.shadowbench.cases.adapters import _probe

    monkeypatch.setattr(_probe.shutil, "which", lambda name, path=None: "/usr/bin/unshare")
    monkeypatch.setattr(_probe.os, "geteuid", lambda: 0)
    assert _probe.isolation() == ["/usr/bin/unshare", "--net", "--"]
    monkeypatch.setattr(_probe.os, "geteuid", lambda: 1000)
    assert _probe.isolation() == []


def test_failed_probe_is_unknown_and_never_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout") or 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert ADAPTERS["numbat"].version(_tool_env(tmp_path)) == "unknown"
    assert len(calls) == 1


# --- install_tools.sh: versions recorded as the results manifest records them ----------------------


def _heredoc(script: str, tag: str, values: dict[str, str]) -> str:
    match = re.search(rf"<<('?){tag}\1\n(.*?)\n{tag}\n", script, flags=re.S)
    assert match, tag
    body = match.group(2)
    if match.group(1):  # quoted delimiter: bash does not expand
        return body
    return re.sub(r"\$\{?(\w+)\}?", lambda m: values[m.group(1)], body)


def _script_values(script: str, root: Path) -> dict[str, str]:
    """Top-level ``name=value`` assignments (``fleet_version`` and the like), with ``root`` = ``root``."""
    values = {"root": str(root)}
    for name, value in re.findall(r'^(\w+)="?([^"\n]*)"?$', script, flags=re.M):
        values.setdefault(name, re.sub(r"\$(\w+)", lambda m: values.get(m.group(1), m.group(0)), value))
    return values


def test_install_script_records_the_manifest_versions(tmp_path: Path) -> None:
    script = INSTALL.read_text(encoding="utf-8")
    values = _script_values(script, tmp_path)
    tools = json.loads(_heredoc(script, "EOF_JSON", values))["tools"]
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))["tools"]
    for name, recorded in manifest.items():
        if name == "shadowscan":
            continue  # runs from this checkout; the operator adds its entry
        assert tools[name]["version"] == recorded["version"], name
    wrapper = _heredoc(script, "EOF_MAIN", values)
    printed = re.search(r'fmt\.Println\("([^"]*)"\)', wrapper)
    assert printed and printed.group(1) == manifest["fleet-ai-tools"]["version"]


def test_install_script_layout_satisfies_every_adapter(tmp_path: Path) -> None:
    """The cisco adapter looked up ``mcp-scanner`` while tools.json names it ``cisco-mcp-scanner``."""
    script = INSTALL.read_text(encoding="utf-8")
    config = json.loads(_heredoc(script, "EOF_JSON", _script_values(script, tmp_path)))
    for entry in config["tools"].values():
        Path(entry["bin"]).parent.mkdir(parents=True, exist_ok=True)
        Path(entry["bin"]).write_text("", encoding="utf-8")
        for key in ("fingerprints", "vuln"):
            if key in entry:
                Path(entry[key]).mkdir(parents=True, exist_ok=True)
    env = ToolEnv(tool_root=tmp_path, config=config)
    for name, adapter in ADAPTERS.items():
        if name == "shadowscan":
            continue
        assert adapter.unavailable_reason(env) is None, name


def test_install_script_fails_closed() -> None:
    script = INSTALL.read_text(encoding="utf-8")
    assert "set -euo pipefail" in script
    assert "shopt -s inherit_errexit" in script
    assert "|| true" not in script
    assert ">/dev/null 2>&1" not in script
    assert "-mod=mod" not in script
    assert "version-pinned, not hash-locked" in script


# --- fetch_code.py: hardened git, pinned HEAD, no symlinks -----------------------------------------

FAKE_PASSWORD = "not-a-real-password"


class _FakeGit:
    """Stands in for ``subprocess.run``: records git calls and reports ``head`` for ``rev-parse``."""

    def __init__(self, head: str) -> None:
        self.head = head
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        stdout = self.head + "\n" if "rev-parse" in argv else ""
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")


def _fetch_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, url: str, head: str) -> tuple[int, _FakeGit]:
    repo = SimpleNamespace(id="demo__repo", url=url, commit=SHA, default_branch="main")
    monkeypatch.setattr(fetch_code, "load_corpus", lambda path: SimpleNamespace(get=lambda rid: repo))
    monkeypatch.setattr(fetch_code, "CODE_REPOS", ("demo__repo",))
    fake = _FakeGit(head)
    monkeypatch.setattr(subprocess, "run", fake)
    return fetch_code.main([str(tmp_path / "dest")]), fake


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/demo/repo.git",
        "ssh://git@github.com/demo/repo.git",
        "git@github.com:demo/repo.git",
        "file:///srv/demo/repo.git",
        # A fake password, joined at run time so the source holds no credential-shaped URL.
        "http://user:" + FAKE_PASSWORD + "@github.com/demo/repo.git",
        "https://user:" + FAKE_PASSWORD + "@github.com/demo/repo.git",
    ],
)
def test_fetch_refuses_non_https_remotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], url: str
) -> None:
    code, fake = _fetch_main(tmp_path, monkeypatch, url, SHA)
    assert code == 1
    assert fake.calls == []
    assert not (tmp_path / "dest" / "demo__repo").exists()
    assert FAKE_PASSWORD not in capsys.readouterr().out  # a credential in the URL is never printed


def test_fetch_disables_hooks_and_submodules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, fake = _fetch_main(tmp_path, monkeypatch, "https://github.com/demo/repo.git", SHA)
    assert code == 0
    assert fake.calls
    for argv in fake.calls:
        assert argv[0] == "git"
        pairs = set(zip(argv, argv[1:], strict=False))
        for setting in ("core.hooksPath=/dev/null", "submodule.recurse=false", "protocol.allow=never"):
            assert ("-c", setting) in pairs, (setting, argv)
    for verb in ("fetch", "checkout"):
        called = [argv for argv in fake.calls if verb in argv]
        assert called and all("--no-recurse-submodules" in argv for argv in called), verb


def test_fetch_rejects_a_head_other_than_the_pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, _ = _fetch_main(tmp_path, monkeypatch, "https://github.com/demo/repo.git", "f" * 40)
    assert code == 1


def test_fetch_never_follows_a_symlinked_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "dest").mkdir()
    link = tmp_path / "dest" / "demo__repo"
    link.symlink_to(elsewhere, target_is_directory=True)
    code, fake = _fetch_main(tmp_path, monkeypatch, "https://github.com/demo/repo.git", SHA)
    assert code == 1
    assert fake.calls == []
    assert link.is_symlink() and list(elsewhere.iterdir()) == []


def _git(*args: str, cwd: Path) -> str:
    settings = ("user.name=bench", "user.email=bench@example.invalid", "commit.gpgsign=false")
    config = [part for setting in settings for part in ("-c", setting)]
    done = subprocess.run(["git", *config, *args], cwd=cwd, capture_output=True, text=True, check=True)
    return done.stdout.strip()


@pytest.mark.skipif(not shutil.which("git"), reason="needs git")
def test_fetch_pinned_against_a_real_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The hardened command lines run as written; only the transport rule is relaxed to reach a local repo."""
    src = tmp_path / "src"
    src.mkdir()
    _git("init", "-q", "-b", "main", cwd=src)
    _git("commit", "-q", "--allow-empty", "-m", "pinned", cwd=src)
    pinned = _git("rev-parse", "HEAD", cwd=src)
    url = f"file://{src}"
    monkeypatch.setattr(fetch_code, "https_remote", lambda remote: remote)
    with pytest.raises(fetch_code.FetchError):  # protocol.allow=never also blocks file://
        fetch_code.fetch_pinned(url, pinned, "main", tmp_path / "blocked")
    monkeypatch.setattr(fetch_code, "GIT_CONFIG", (*fetch_code.GIT_CONFIG, "protocol.file.allow=always"))
    dest = tmp_path / "dest" / "repo"
    assert fetch_code.fetch_pinned(url, pinned, "main", dest) == pinned
    assert _git("rev-parse", "HEAD", cwd=dest) == pinned
    assert _git("rev-parse", "--abbrev-ref", "HEAD", cwd=dest) == "HEAD"  # detached
    assert fetch_code.fetch_pinned(url, pinned, "main", dest) == pinned  # an existing checkout is kept
    assert os.path.isdir(dest / ".git")

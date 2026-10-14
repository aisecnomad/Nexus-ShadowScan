"""runtime.processes: AI tools seen running, and lifecycle links to endpoint findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.runtime import processes as runtime_processes
from shadowscan.connectors.runtime.processes import RuntimeProcessConnector, _split, classify
from shadowscan.correlation import correlate_lifecycle
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Surface

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.mark.parametrize(
    ("exe", "argv", "tool", "package"),
    [
        (None, ["/home/dana/.local/bin/claude", "--resume"], "claude-code", None),
        (None, ["node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"], "claude-code", None),
        (
            "C:\\Program Files\\nodejs\\node.exe",
            ["node.exe", "C:\\Users\\sam\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\bin\\codex.js"],
            "codex",
            None,
        ),
        (None, ["npx", "-y", "@modelcontextprotocol/server-github@2025.4.8"], "mcp:@modelcontextprotocol/server-github",
         "@modelcontextprotocol/server-github"),
        (None, ["uv", "tool", "run", "mcp-server-fetch"], "mcp:mcp-server-fetch", "mcp-server-fetch"),
        (None, ["uvx", "--from", "git+https://x/y", "mcp-server-git"], "mcp:mcp-server-git", "mcp-server-git"),
        (None, ["python3", "-m", "vllm.entrypoints.openai.api_server", "--model", "x"], "vllm", None),
        (None, ["python", "-m", "aider", "--model", "sonnet"], "aider", None),
        (None, ["python", "agent.py"], None, None),
        (None, ["npm", "install", "-g", "mcp-server-fetch"], None, None),
        (None, ["uv", "pip", "install", "mcp-server-git"], None, None),
        (None, ["npm", "exec", "@modelcontextprotocol/server-github"], "mcp:@modelcontextprotocol/server-github",
         "@modelcontextprotocol/server-github"),
        (None, ["ollama", "serve"], "ollama", None),
        (None, ["ollama", "list"], None, None),
        ("/Applications/Claude.app/Contents/MacOS/Claude", [], "claude-desktop", None),
        ("C:\\Users\\sam\\AppData\\Local\\AnthropicClaude\\app-0.9.3\\claude.exe", [], "claude-desktop", None),
        ("/usr/share/cursor/cursor", ["/usr/share/cursor/cursor"], "cursor", None),
        (None, ["bash", "-c", "claude"], None, None),
        (None, [], None, None),
    ],
)  # fmt: skip
def test_classify(exe, argv, tool, package):
    match = classify(exe, argv)
    if tool is None:
        assert match is None
        return
    assert match is not None
    assert (match[0].tool, match[1]) == (tool, package)


def test_command_lines_are_never_exported():
    from shadowscan.connectors.base import _NoDump

    assert issubclass(RuntimeProcessConnector, _NoDump)


def test_split_honours_quotes():
    assert _split("\"C:\\Program Files\\nodejs\\node.exe\" cli.js --name 'a b'") == [
        "C:\\Program Files\\nodejs\\node.exe",
        "cli.js",
        "--name",
        "a b",
    ]


def _rows(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "processes.json"
    path.write_text(json.dumps(rows))
    return path


def test_osquery_defender_and_generic_rows(run_connector, tmp_path):
    rows = [
        {"hostIdentifier": "dev-laptop-07", "columns": {"pid": "4242", "name": "node", "uid": "1000",
         "cmdline": "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js --api-key sk-ant-secret",
         "start_time": "1759132800"}},
        {"hostIdentifier": "dev-laptop-07", "columns": {"pid": "4300", "name": "npx", "uid": "1000",
         "cmdline": "npx -y @modelcontextprotocol/server-github"}},
        {"DeviceName": "WIN-22.corp.example", "AccountName": "sam", "FileName": "ollama.exe",
         "FolderPath": "C:\\Users\\sam\\AppData\\Local\\Programs\\Ollama",
         "ProcessCommandLine": "\"ollama.exe\" serve", "Timestamp": "2025-09-29T08:00:00Z"},
        {"host": "build-01", "user": "ci", "command_line": "python -m pytest"},
        {"host": "build-01", "user": "ci"},
    ]  # fmt: skip
    findings, ctx = run_connector("runtime.processes", input=str(_rows(tmp_path, rows)))
    assert ctx.stats.incomplete and any("no command line" in w for w in ctx.stats.warnings)
    by = {f.title: f for f in findings}
    assert set(by) == {
        "Claude Code running on dev-laptop-07 (uid-1000)",
        "MCP server: @modelcontextprotocol/server-github running on dev-laptop-07 (uid-1000)",
        "Ollama running on WIN-22.corp.example (sam)",
    }
    claude = by["Claude Code running on dev-laptop-07 (uid-1000)"]
    assert claude.surface == Surface.RUNTIME and claude.kind == Kind.RUNTIME_PROCESS
    assert claude.frameworks == ["coding-agent.claude-code"] and "observed-running" in claude.tags
    assert claude.metadata["pids"] == [4242] and claude.first_seen == "2025-09-29T08:00:00+00:00"
    assert "sk-ant-secret" not in json.dumps(claude.to_dict())
    ollama = by["Ollama running on WIN-22.corp.example (sam)"]
    assert ollama.model_providers == ["provider.ollama"] and ollama.account == "WIN-22.corp.example"


ROOT_STATUS = "Gid:\t0\t0\t0\t0\nGroups:\t\n"
HOST_GIDS = "         0          0 4294967295\n"


def _proc_self(
    proc,
    monkeypatch,
    *,
    initial=True,
    options="rw",
    status=ROOT_STATUS,
    gid_map=HOST_GIDS,
    mountinfo=None,
):
    """The parts of /proc/self that the restricted-view check reads, for a fake /proc tree."""
    (proc / "self" / "ns").mkdir(parents=True, exist_ok=True)
    link = proc / "self" / "ns" / "pid"
    link.write_text("pid")
    if initial:
        # Stands in for the initial PID namespace's fixed inode number.
        monkeypatch.setattr(runtime_processes, "_INIT_PID_NS_INO", link.stat().st_ino)
    if mountinfo is None:
        mountinfo = f"22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc {options}\n"
    (proc / "self" / "mountinfo").write_text(mountinfo)
    (proc / "self" / "status").write_text(status)
    (proc / "self" / "gid_map").write_text(gid_map)


def test_live_mode_reads_proc(run_connector, monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
    for pid, argv in {"10": [b"/usr/bin/bash"], "11": [b"claude", b"-p", b"x"], "x": [b"no"]}.items():
        (proc / pid).mkdir(parents=True)
        (proc / pid / "cmdline").write_bytes(b"\0".join(argv) + b"\0")
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert not ctx.stats.warnings
    assert [f.title.split(" running on ")[0] for f in findings] == ["Claude Code"]
    assert findings[0].account == "box"


@pytest.mark.parametrize(
    ("cmdline", "found"),
    [
        # A long prompt passed with -p: the leading arguments are intact.
        (b"claude\0-p\0" + b"x" * 70_000 + b"\0", True),
        # The partial final argument is dropped: cut at the limit, the package
        # @anthropic-ai/claude-codex would read as @anthropic-ai/claude-code.
        (b"npx\0" + b"y" * (64 * 1024 - 30) + b"\0@anthropic-ai/claude-codex\0", False),
    ],
    ids=["long-prompt", "partial-final-argument"],
)
def test_live_mode_classifies_a_truncated_command_line(run_connector, monkeypatch, tmp_path, cmdline, found):
    """Regression (#220 review F3): a command line over the byte limit is truncated, not dropped."""
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
    (proc / "11").mkdir(parents=True)
    (proc / "11" / "cmdline").write_bytes(cmdline)
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert ctx.stats.incomplete
    assert any("1 command line(s) exceeded 65,536 bytes" in w for w in ctx.stats.warnings)
    if not found:
        assert findings == []
        return
    (finding,) = findings
    assert finding.title == "Claude Code running on box (root)"
    assert finding.metadata["command_lines_truncated"] == 1
    assert any("truncated" in limitation for limitation in finding.metadata["limitations"])


def test_live_mode_command_line_at_the_limit_is_complete(run_connector, monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
    (proc / "11").mkdir(parents=True)
    cmdline = b"claude\0-p\0"
    (proc / "11" / "cmdline").write_bytes(cmdline + b"x" * (64 * 1024 - len(cmdline) - 1) + b"\0")
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert len(findings) == 1 and not ctx.stats.incomplete and not ctx.stats.warnings
    assert "command_lines_truncated" not in findings[0].metadata


def test_live_mode_outside_linux_is_refused(run_connector, monkeypatch):
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Darwin")
    _, ctx = run_connector("runtime.processes")
    assert ctx.stats.skipped and ctx.stats.incomplete


def test_lifecycle_links_endpoint_configuration_to_running_processes(index, tmp_path):
    rows = [
        {"hostIdentifier": "dev-laptop-07", "columns": {"pid": "1", "uid": "1000",
         "cmdline": "/home/dana/.local/bin/claude", "name": "claude"}},
        {"host": "dev-laptop-07", "user": "dana",
         "cmdline": "npx -y @modelcontextprotocol/server-github@2025.4.8"},
        {"host": "dev-laptop-07", "user": "dana", "cmdline": "npx -y mcp-server-unrelated"},
        {"host": "dev-laptop-07", "user": "dana", "cmdline": "ollama serve"},
        {"host": "other-host", "user": "dana", "cmdline": "codex exec"},
    ]  # fmt: skip
    processes = _rows(tmp_path, rows)
    config = ScanConfig(
        connectors=[
            ConnectorSpec("endpoint.inventory", {"input": str(FIXTURES / "endpoint" / "inventory.jsonl")}),
            ConnectorSpec("runtime.processes", {"input": str(processes)}),
        ]
    )
    result = Engine(config, index).run()
    by = {f.title: f for f in result.findings}
    claude = by["Claude Code configured on dev-laptop-07 (~dana)"]
    assert "observed-running" in claude.tags
    assert claude.metadata["lifecycle"]["states"] == ["configured", "running"]
    assert claude.metadata["lifecycle"]["same_user"] is False
    assert any(e.signal == "lifecycle:observed-running" and e.weight == 0.0 for e in claude.evidence)
    cursor_mcp = by["MCP servers configured for Cursor on dev-laptop-07 (~dana)"]
    assert cursor_mcp.metadata["lifecycle"]["same_user"] is True
    assert "mcp-package:@modelcontextprotocol/server-github" in cursor_mcp.metadata["lifecycle"]["subjects"]
    assert "observed-running" in by["Local models stored for Ollama on dev-laptop-07 (~dana)"].tags
    assert "lifecycle" not in by["OpenAI Codex CLI running on other-host (dana)"].metadata
    assert "lifecycle" not in by["MCP server: mcp-server-unrelated running on dev-laptop-07 (dana)"].metadata
    running = by["Claude Code running on dev-laptop-07 (uid-1000)"]
    assert running.metadata["lifecycle"]["states"] == ["configured", "running"]

    # Idempotent: a second pass replaces, never duplicates.
    correlate_lifecycle(result.findings)
    assert sum(e.signal == "lifecycle:observed-running" for e in claude.evidence) == 1


@pytest.mark.parametrize(
    ("value", "pid"),
    [
        (4242, 4242),
        ("4242", 4242),
        ("٤٢", None),
        ("²", None),
        (True, None),
        (-1, None),
        ("4419516131012", 4419516131012),  # CrowdStrike's TargetProcessId is a 64-bit id
        (2**64 - 1, 2**64 - 1),
        (2**64, None),
        ("1" * 21, None),
        (None, None),
    ],
)
def test_export_pids_are_plain_decimal(value, pid):
    assert runtime_processes._pid(value) == pid


def test_non_decimal_pid_does_not_lose_the_export(run_connector, tmp_path):
    rows = [
        {"host": "box", "user": "dana", "pid": "²", "cmdline": "claude -p hi"},
        {"host": "box", "user": "dana", "pid": "7", "cmdline": "codex exec fix"},
    ]
    findings, ctx = run_connector("runtime.processes", input=str(_rows(tmp_path, rows)))
    assert not ctx.stats.errors
    assert sorted(f.title.split(" running on ")[0] for f in findings) == ["Claude Code", "OpenAI Codex CLI"]


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        ({}, None),
        # A container's own /proc shows a single NSpid entry, as the host's does; the inode tells them apart.
        ({"initial": False}, "separate PID namespace"),
        ({"options": "rw,subset=pid"}, None),  # hides only entries that are not processes
        ({"options": "rw,hidepid=off"}, None),
        ({"options": "rw,hidepid=invisible"}, None),  # root is in the default gid=0 group
        ({"options": "rw,hidepid=2"}, None),  # older kernels print the number
        ({"options": "rw,hidepid=invisible,gid=1000"}, "hidepid=invisible"),
        (
            {
                "options": "rw,hidepid=invisible,gid=1000",
                "status": "Gid:\t1000\t1000\t1000\t1000\nGroups:\t27\n",
            },
            None,
        ),
        (
            {"options": "rw,hidepid=noaccess", "status": "Gid:\t1000\t1000\t1000\t1000\nGroups:\t\n"},
            "noaccess",
        ),
        (
            {"options": "rw,hidepid=ptraceable"},
            "hidepid=ptraceable",
        ),  # hides untraceable processes from root too
        ({"options": "rw,hidepid=invisible", "gid_map": "0 100000 65536\n"}, "hidepid=invisible"),
        ({"options": "rw,hidepid=invisible,gid=1000", "status": "Gid:\t0\t0\t0\t0\nGroups:\t1000\n"}, None),
        (
            {
                "mountinfo": (
                    "22 1 0:21 / /proc rw - proc proc rw,hidepid=invisible,gid=1000\n"
                    "40 22 0:35 / /proc rw - proc proc rw\n"
                )
            },
            None,  # the last mount on /proc is the one that is read
        ),
        ({"mountinfo": "22 1 0:21 / /sys rw - sysfs sysfs rw\n"}, "mount options of /proc"),
    ],
)
def test_restricted_proc_view(monkeypatch, tmp_path, setup, reason):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch, **setup)
    found = runtime_processes._restricted_view(proc)
    assert (found is None) if reason is None else (reason in found)


def test_proc_namespace_is_read_from_pid_one_when_visible(monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch, initial=False)
    (proc / "1" / "ns").mkdir(parents=True)
    init = proc / "1" / "ns" / "pid"
    init.write_text("pid")
    # /proc/1 is the init of the namespace this procfs belongs to; it decides over /proc/self.
    monkeypatch.setattr(runtime_processes, "_INIT_PID_NS_INO", init.stat().st_ino)
    assert runtime_processes._restricted_view(proc) is None
    monkeypatch.setattr(runtime_processes, "_INIT_PID_NS_INO", 0xEFFFFFFC)
    assert "separate PID namespace" in runtime_processes._restricted_view(proc)
    init.unlink()
    (proc / "self" / "ns" / "pid").unlink()
    assert "could not be determined" in runtime_processes._restricted_view(proc)


def test_live_scan_in_a_container_is_incomplete_not_empty(run_connector, monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch, initial=False)
    (proc / "11").mkdir()
    (proc / "11" / "cmdline").write_bytes(b"claude\0")
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert len(findings) == 1
    assert ctx.stats.incomplete
    assert any("not every process is visible" in w and "PID namespace" in w for w in ctx.stats.warnings)


def test_lifecycle_links_tools_without_a_signature_by_tool_id(index, tmp_path):
    home = tmp_path / "dana"
    (home / ".config" / "Claude").mkdir(parents=True)
    (home / ".config" / "Claude" / "claude_desktop_config.json").write_text(
        json.dumps({"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    )
    (home / ".kiro" / "settings").mkdir(parents=True)
    (home / ".kiro" / "settings" / "mcp.json").write_text(json.dumps({"mcpServers": {}}))
    rows = [
        {"host": "lap", "user": "dana", "path": "/Applications/Claude.app/Contents/MacOS/Claude"},
        {"host": "lap", "user": "dana", "cmdline": "kiro-cli chat"},
    ]
    config = ScanConfig(
        connectors=[
            ConnectorSpec("endpoint.inventory", {"path": str(home), "label": "lap"}),
            ConnectorSpec("runtime.processes", {"input": str(_rows(tmp_path, rows))}),
        ]
    )
    result = Engine(config, index).run()
    configured = {f.title: f for f in result.findings if f.resource_type == "agent-config"}
    claude = next(f for t, f in configured.items() if t.startswith("Claude Desktop configured"))
    assert (
        "observed-running" in claude.tags
        and "tool:claude-desktop" in claude.metadata["lifecycle"]["subjects"]
    )
    kiro = next(f for t, f in configured.items() if t.startswith("Kiro configured"))
    assert "observed-running" in kiro.tags


def test_lifecycle_ignores_malformed_server_args(index, tmp_path):
    record = {
        "device": "lap",
        "home": "dana",
        "record_type": "agent_config",
        "client": "cursor",
        "product": "Cursor",
        "signature": "coding-agent.cursor",
        "mcp_servers": [{"name": "github", "command": "npx", "args": 5}],
    }
    records = tmp_path / "records.jsonl"
    records.write_text(json.dumps(record))
    rows = [{"host": "lap", "user": "dana", "cmdline": "npx -y @modelcontextprotocol/server-github"}]
    config = ScanConfig(
        connectors=[
            ConnectorSpec("endpoint.inventory", {"input": str(records)}),
            ConnectorSpec("runtime.processes", {"input": str(_rows(tmp_path, rows))}),
        ]
    )
    result = Engine(config, index).run()
    assert not result.complete
    assert not any(s.errors for s in result.stats)
    # The malformed server is dropped with a warning; the rest of the record is kept.
    assert any(f.title.startswith("Cursor configured") for f in result.findings)
    # The engine's lifecycle pass also tolerates such a server if one ever reaches it.
    rogue = Finding(
        surface=Surface.ENDPOINT,
        connector="endpoint.inventory",
        kind=Kind.MCP_SERVER,
        title="MCP servers configured for Cursor on lap (~dana)",
        resource="endpoint:lap:dana:mcp-config:cursor",
        resource_type="mcp-config",
        account="lap",
        metadata={"servers": [{"name": "github", "args": 5}, {"name": "x", "args": ["@scope/pkg"]}]},
    )
    correlate_lifecycle([rogue, *result.findings])
    assert "lifecycle" not in rogue.metadata


def _inspection_proc(tmp_path, monkeypatch, *, argv=b"python\0-c\0pass\0"):
    """A completely synthetic proc tree; tests never inspect a real process."""
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
    pid = proc / "12"
    (pid / "ns").mkdir(parents=True)
    (pid / "ns" / "pid").write_text("namespace")
    (pid / "stat").write_text("12 (worker) " + " ".join(["S", *(["0"] * 18), "12345", "0"]))
    (pid / "cmdline").write_bytes(argv)
    (pid / "maps").write_text("1000-2000 r--p 0000 00:00 0 /private/path/libggml.so\n")
    (pid / "fd").mkdir()
    (pid / "fd" / "7").symlink_to("/private/path/example.gguf (deleted)")
    (pid / "environ").write_bytes(b"OLLAMA_MODELS=private-value-sentinel\0UNLISTED=private-value-sentinel\0")
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    return pid


def test_opt_in_runtime_inspection_is_bounded_non_agent_and_private(run_connector, monkeypatch, tmp_path):
    _inspection_proc(tmp_path, monkeypatch)
    findings, ctx = run_connector("runtime.processes", label="box")
    assert findings == [] and not ctx.stats.incomplete
    findings, ctx = run_connector(
        "runtime.processes",
        label="box",
        inspect_maps=True,
        inspect_fds=True,
        inspect_env_keys=["OLLAMA_MODELS"],
    )
    assert not ctx.stats.incomplete and len(findings) == 1
    finding = findings[0]
    assert finding.kind == Kind.LOCAL_MODEL and finding.resource_type == "process/model-runtime-indicator"
    assert finding.confidence == 0.35 and "observed-running" not in finding.tags
    assert not finding.frameworks and not finding.metadata.get("agent_indicators")
    inspection = finding.metadata["runtime_inspection"][0]
    assert inspection["mapped_libraries"] == ["ggml"]
    assert inspection["open_model_formats"] == ["gguf"]
    assert inspection["environment_keys"] == ["OLLAMA_MODELS"]
    assert finding.metadata["process_identities"][0]["start_time_ticks"] == "12345"
    assert finding.metadata["observed_at"] and finding.metadata["observation_source"] == "live-proc"
    serialized = json.dumps(finding.to_dict())
    assert "private-value-sentinel" not in serialized and "/private/path" not in serialized


def test_sanitized_runtime_inspection_fixture(run_connector):
    findings, ctx = run_connector("runtime.processes", input=str(FIXTURES / "runtime" / "inspection.jsonl"))
    assert not ctx.stats.incomplete and len(findings) == 1  # Packaging alone produces no finding.
    assert findings[0].kind == Kind.LOCAL_MODEL and not findings[0].capabilities
    assert findings[0].metadata["runtime_inspection"][0]["mapped_libraries"] == ["torch"]
    assert findings[0].metadata["observation_source"] == "process-inventory"


def test_inspection_enriches_known_tool_without_scoring_it_again(run_connector, monkeypatch, tmp_path):
    _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    baseline, _ = run_connector("runtime.processes", label="box")
    findings, ctx = run_connector("runtime.processes", label="box", inspect_maps=True)
    assert not ctx.stats.incomplete and len(findings) == 1
    assert findings[0].confidence == baseline[0].confidence
    assert findings[0].metadata["runtime_inspection"][0]["mapped_libraries"] == ["ggml"]


@pytest.mark.parametrize("source", ["maps", "fd", "environ"])
def test_inspection_permission_denial_is_incomplete(run_connector, monkeypatch, tmp_path, source):
    _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    original = runtime_processes.os.open

    def denied(path, flags, *args, **kwargs):
        if path == source:
            raise PermissionError("private-path-must-not-escape")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_processes.os, "open", denied)
    findings, ctx = run_connector(
        "runtime.processes", inspect_maps=True, inspect_fds=True, inspect_env_keys=["OLLAMA_MODELS"]
    )
    assert findings and ctx.stats.incomplete
    assert any("inspection denied" in w for w in ctx.stats.warnings)
    assert "private-path-must-not-escape" not in json.dumps(ctx.stats.warnings)


@pytest.mark.parametrize("change", ["exit", "reuse", "malformed", "denied"])
def test_inspection_process_identity_races_are_not_attributed(run_connector, monkeypatch, tmp_path, change):
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    original = RuntimeProcessConnector._inspect

    def alter(self, directory, budget):
        result = original(self, directory, budget)
        if change == "exit":
            (pid / "stat").unlink()
            (pid / "cmdline").unlink()
        elif change == "reuse":
            (pid / "stat").write_text((pid / "stat").read_text().replace("12345", "54321"))
        elif change == "malformed":
            (pid / "stat").write_text("malformed")
        else:

            def denied(*args):
                raise PermissionError("opaque sentinel")

            monkeypatch.setattr(runtime_processes, "_proc_identity", denied)
        return result

    monkeypatch.setattr(RuntimeProcessConnector, "_inspect", alter)
    findings, ctx = run_connector("runtime.processes", inspect_maps=True)
    assert len(findings) == (1 if change in {"malformed", "denied"} else 0)
    if findings:
        assert "runtime_inspection" not in findings[0].metadata
    assert ctx.stats.incomplete == (change in {"malformed", "denied"})
    assert ctx.stats.warnings


@pytest.mark.parametrize(
    "options",
    [
        {"max_inspection_bytes": 10},
        {"max_inspection_total_bytes": 10},
        {"max_inspection_entries": 1},
        {"max_mappings": 1},
        {"max_fds": 1},
    ],
)
def test_inspection_budgets_are_incomplete(run_connector, monkeypatch, tmp_path, options):
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    (pid / "maps").write_text((pid / "maps").read_text() * 2)
    (pid / "fd" / "8").symlink_to("/model/other.onnx")
    _, ctx = run_connector("runtime.processes", inspect_maps=True, inspect_fds=True, **options)
    assert ctx.stats.incomplete and ctx.stats.warnings


def test_inspection_deadline_stops_only_enrichment(run_connector, monkeypatch, tmp_path):
    _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    count = 0

    def clock():
        nonlocal count
        count += 1
        return 0 if count == 1 else 31

    monkeypatch.setattr(runtime_processes.time, "monotonic", clock)
    findings, ctx = run_connector("runtime.processes", inspect_maps=True)
    assert len(findings) == 1 and ctx.stats.incomplete
    assert "runtime_inspection" not in findings[0].metadata
    assert any("deadline" in warning for warning in ctx.stats.warnings)


def test_inspection_does_not_open_fd_targets(run_connector, monkeypatch, tmp_path):
    pid = _inspection_proc(tmp_path, monkeypatch)
    target = tmp_path / "secret.gguf"
    target.write_text("must never be read")
    (pid / "fd" / "7").unlink()
    (pid / "fd" / "7").symlink_to(target)
    original = runtime_processes.os.open

    def confined(path, flags, *args, **kwargs):
        assert path != target and str(path) != str(target)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_processes.os, "open", confined)
    findings, ctx = run_connector("runtime.processes", inspect_fds=True)
    assert len(findings) == 1 and not ctx.stats.incomplete


@pytest.mark.parametrize("field", ["maps", "environ"])
def test_inspection_refuses_symlink_sources(run_connector, monkeypatch, tmp_path, field):
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    (pid / field).unlink()
    (pid / field).symlink_to(pid / "cmdline")
    _, ctx = run_connector("runtime.processes", inspect_maps=True, inspect_env_keys=["OLLAMA_MODELS"])
    assert ctx.stats.incomplete


def test_inspection_malformed_map_and_packaging_decoy(run_connector, monkeypatch, tmp_path):
    pid = _inspection_proc(tmp_path, monkeypatch)
    (pid / "maps").write_text("1000-2000 r--p 0000 00:00 0 /tmp/_MEI123/libordinary.so\n")
    findings, ctx = run_connector("runtime.processes", inspect_maps=True)
    assert not findings and not ctx.stats.incomplete
    (pid / "maps").write_text("private-path-malformed-sentinel")
    findings, ctx = run_connector("runtime.processes", inspect_maps=True)
    assert not findings and ctx.stats.incomplete
    assert "private-path-malformed-sentinel" not in json.dumps(ctx.stats.warnings)


@pytest.mark.parametrize(
    "mutation", ["bad_label", "bad_status", "bad_identity", "no_pid", "bad_shape", "conflict"]
)
def test_offline_inspection_rejects_untrusted_shapes(run_connector, tmp_path, mutation):
    row = json.loads((FIXTURES / "runtime" / "inspection.jsonl").read_text().splitlines()[0])
    if mutation == "bad_label":
        row["inspection"]["environment_keys"] = ["UNLISTED=private-value-sentinel"]
    elif mutation == "bad_status":
        row["inspection"]["status"]["maps"] = []
    elif mutation == "bad_identity":
        row["inspection"]["identity"]["start_time_ticks"] = "secret"
    elif mutation == "no_pid":
        del row["pid"]
    elif mutation == "bad_shape":
        row["inspection"] = []
    else:
        row["inspection"]["status"]["maps"] = "not_requested"
    findings, ctx = run_connector("runtime.processes", input=str(_rows(tmp_path, [row])))
    assert not findings and ctx.stats.incomplete
    assert "private-value-sentinel" not in json.dumps(ctx.stats.warnings)


@pytest.mark.parametrize(
    "options", [{"inspect_maps": "true"}, {"inspect_env_keys": ["UNLISTED"]}, {"inspect_env_keys": True}]
)
def test_inspection_configuration_rejects_unsafe_options(options):
    from shadowscan.connectors.base import ConnectorContext, ConnectorError

    with pytest.raises(ConnectorError):
        RuntimeProcessConnector(ConnectorContext(config=options))


def test_missing_inspection_source_is_not_misreported_as_exit(run_connector, monkeypatch, tmp_path):
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    (pid / "maps").unlink()
    findings, ctx = run_connector("runtime.processes", inspect_maps=True)
    assert findings and ctx.stats.incomplete
    assert any("unreadable" in warning for warning in ctx.stats.warnings)
    assert not any("exited" in warning for warning in ctx.stats.warnings)


def test_descriptor_close_is_reported_as_race_not_denial(run_connector, monkeypatch, tmp_path):
    _inspection_proc(tmp_path, monkeypatch)

    def closed(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(runtime_processes.os, "readlink", closed)
    findings, ctx = run_connector("runtime.processes", inspect_fds=True)
    assert not findings and not ctx.stats.incomplete
    assert any("descriptor closed" in warning for warning in ctx.stats.warnings)


def test_empty_cmdline_still_allows_scoped_inspection_inventory(run_connector, monkeypatch, tmp_path):
    _inspection_proc(tmp_path, monkeypatch, argv=b"")
    findings, ctx = run_connector("runtime.processes", inspect_maps=True)
    assert len(findings) == 1 and not ctx.stats.incomplete
    assert findings[0].kind == Kind.FRAMEWORK_USAGE and not findings[0].capabilities


def test_malformed_descriptor_entries_are_incomplete(run_connector, monkeypatch, tmp_path):
    pid = _inspection_proc(tmp_path, monkeypatch)
    (pid / "fd" / "unexpected").symlink_to("/models/example.gguf")
    findings, ctx = run_connector("runtime.processes", inspect_fds=True)
    assert not findings and ctx.stats.incomplete


def test_proc_visibility_probe_is_bounded(monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
    (proc / "self" / "mountinfo").write_bytes(b"x" * (256 * 1024))
    assert "mount options" in runtime_processes._restricted_view(proc)


@pytest.mark.parametrize("source", ["stat", "ns"])
def test_denied_inspection_identity_preserves_independent_cmdline(
    run_connector, monkeypatch, tmp_path, source
):
    _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    original = runtime_processes.os.open

    def denied(path, flags, *args, **kwargs):
        if path == source:
            raise PermissionError("private sentinel")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_processes.os, "open", denied)
    baseline, _ = run_connector("runtime.processes", label="box")
    findings, ctx = run_connector("runtime.processes", label="box", inspect_maps=True)
    assert len(findings) == len(baseline) == 1 and ctx.stats.incomplete
    assert findings[0].confidence == baseline[0].confidence
    assert "runtime_inspection" not in findings[0].metadata


@pytest.mark.parametrize("source", ["stat", "ns/pid"])
def test_missing_identity_is_not_process_exit_while_cmdline_exists(
    run_connector, monkeypatch, tmp_path, source
):
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    (pid / source).unlink()
    findings, ctx = run_connector("runtime.processes", inspect_maps=True)
    assert len(findings) == 1 and ctx.stats.incomplete
    assert "runtime_inspection" not in findings[0].metadata
    assert not any("exited" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("options", [{"max_inspection_total_bytes": 10}, {"max_inspection_entries": 1}])
def test_global_inspection_budget_does_not_erase_known_tools(run_connector, monkeypatch, tmp_path, options):
    import shutil

    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    other = pid.parent / "13"
    shutil.copytree(pid, other, symlinks=True)
    (other / "cmdline").write_bytes(b"codex\0")
    baseline, _ = run_connector("runtime.processes", label="box")
    findings, ctx = run_connector("runtime.processes", label="box", inspect_maps=True, **options)
    assert ctx.stats.incomplete
    assert {f.resource for f in findings} == {f.resource for f in baseline}


def test_packaging_without_observed_source_is_incomplete(run_connector, tmp_path):
    row = json.loads((FIXTURES / "runtime" / "inspection.jsonl").read_text().splitlines()[1])
    row["exe"] = "claude"
    row["inspection"]["status"] = dict.fromkeys(("maps", "fds", "environ"), "not_requested")
    findings, ctx = run_connector("runtime.processes", input=str(_rows(tmp_path, [row])))
    assert len(findings) == 1 and ctx.stats.incomplete
    assert "runtime_inspection" not in findings[0].metadata

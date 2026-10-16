"""runtime.processes: AI tools seen running, and lifecycle links to endpoint findings."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.runtime import processes as runtime_processes
from shadowscan.connectors.runtime.processes import (
    RuntimeProcessConnector,
    _split,
    classify,
    classify_command,
)
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


@pytest.mark.parametrize(
    "argument",
    [
        "@a/" + "mcp" * 20_000 + "!",
        "x" + "mcp-server" * 6_000 + "!",
        "mcp-" + "a." * 30_000 + "!",
    ],
)
def test_overlong_package_arguments_are_not_matched(argument):
    # The package patterns backtrack on long arguments and re holds the GIL for a whole
    # match, so an argument no package name could be is never matched against them.
    started = time.perf_counter()
    assert classify(None, ["node", argument]) is None
    # A runner's first positional argument is the command it runs: an overlong one runs no
    # known tool, and a package after it is only that command's argument.
    assert classify(None, ["npx", "-y", argument, "@modelcontextprotocol/server-github"]) is None
    assert classify_command(None, ["npx", "-y", argument]) == (None, False)
    # An overlong argument of the server a runner runs does not hide that server.
    assert classify(None, ["npx", "-y", "@modelcontextprotocol/server-github", argument]) is not None
    assert time.perf_counter() - started < 1.0


@pytest.mark.parametrize(
    "argv",
    [
        ["python", "audit.py", "mcp-server-fetch"],
        ["python", "-c", "print(1)", "mcp-server-fetch"],
        ["python", "-m", "http.server", "mcp-server-fetch"],
        ["node", "audit.js", "@openai/codex"],
        ["node", "--eval", "@openai/codex"],
        ["node", "-p", "@openai/codex"],
        ["node", "--require", "@openai/codex", "audit.js"],
        ["npx", "--package", "@openai/codex", "audit"],
        ["npm", "exec", "--package=@openai/codex", "--", "node", "audit.js"],
        ["uvx", "--from", "mcp-server-fetch", "audit"],
        ["uv", "run", "python", "audit.py", "mcp-server-fetch"],
        ["uvx", "ollama", "list"],
        ["uvx", "ollama", "pull", "run"],
        ["ollama", "list", "serve"],
        ["npm", "run", "mcp-server-fetch"],
        ["pipx", "install", "mcp-server-fetch"],
        ["npx", "--unrecognized-option", "mcp-server-fetch"],
    ],
)
def test_launchers_do_not_promote_program_arguments_or_dependency_options(argv):
    assert classify(None, argv) is None


@pytest.mark.parametrize(
    "argv,tool",
    [
        (["python3.13", "-B", "-W", "ignore", "-X", "dev", "-m", "aider"], "aider"),
        (["python", "-maider"], "aider"),
        (["uv", "run", "python", "-m", "aider"], "aider"),
        (["uv", "run", "python", "-m", "vllm.entrypoints.openai.api_server"], "vllm"),
        (["uv", "tool", "run", "mcp-server-fetch"], "mcp:mcp-server-fetch"),
        (["uvx", "--from=mcp-server-fetch", "mcp-server-fetch"], "mcp:mcp-server-fetch"),
        (["uvx", "ollama", "serve"], "ollama"),
        (["uvx", "ollama", "run", "model-name"], "ollama"),
        (["pipx", "run", "--spec", "mcp-server-fetch", "mcp-server-fetch"], "mcp:mcp-server-fetch"),
        (["npx", "-y", "--", "@openai/codex"], "codex"),
        (["npm", "exec", "--package=@openai/codex", "--", "codex"], "codex"),
        (["npm", "exec", "--", "node", "/lib/node_modules/@openai/codex/cli.js"], "codex"),
        (["node", "--no-warnings", "--", "/lib/node_modules/@openai/codex/cli.js"], "codex"),
        (["pnpm", "dlx", "mcp-server-fetch"], "mcp:mcp-server-fetch"),
        (["yarn", "dlx", "mcp-server-fetch"], "mcp:mcp-server-fetch"),
        (["bunx", "mcp-server-fetch"], "mcp:mcp-server-fetch"),
        (["bun", "x", "mcp-server-fetch"], "mcp:mcp-server-fetch"),
        (
            ["deno", "run", "npm:@modelcontextprotocol/server-github"],
            "mcp:@modelcontextprotocol/server-github",
        ),
    ],
)
def test_launchers_preserve_execution_targets_and_nested_wrappers(argv, tool):
    result = classify(None, argv)
    assert result is not None and result[0].tool == tool


@pytest.mark.parametrize("field", ["argv", "command_line"])
def test_offline_argument_limit_marks_empty_scan_incomplete(index, tmp_path, field):
    argv = ["python"] + ["-B"] * 63 + ["-m", "vllm.entrypoints.openai.api_server"]
    source = _rows(tmp_path, [{"host": "box", field: argv if field == "argv" else " ".join(argv)}])
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("runtime.processes", {"input": str(source)})]), index
    ).run()
    assert not result.complete and not result.findings
    assert any("truncated" in warning for stat in result.stats for warning in stat.warnings)


@pytest.mark.parametrize("field", ["argv", "command_line"])
def test_offline_argument_limit_boundary_remains_complete(run_connector, tmp_path, field):
    argv = ["python"] + ["-B"] * 61 + ["-m", "vllm.entrypoints.openai.api_server"]
    source = _rows(tmp_path, [{"host": "box", field: argv if field == "argv" else " ".join(argv)}])
    findings, ctx = run_connector("runtime.processes", input=str(source))
    assert len(argv) == 64 and len(findings) == 1
    assert not ctx.stats.incomplete and not ctx.stats.warnings


@pytest.mark.parametrize("field", ["argv", "command_line"])
def test_offline_byte_limit_after_the_tool_is_recorded_but_complete(run_connector, tmp_path, field):
    # claude is read from argv[0]: the prompt the byte limit dropped cannot change what runs.
    argv = ["claude", "-p", "x" * 70_000]
    source = _rows(tmp_path, [{"host": "box", field: argv if field == "argv" else " ".join(argv)}])
    findings, ctx = run_connector("runtime.processes", input=str(source))
    assert not ctx.stats.incomplete and len(findings) == 1
    assert findings[0].metadata["command_lines_truncated"] == 1
    assert ctx.stats.warnings == [
        "runtime.processes: 1 command line(s) exceeded argument/byte limits (64 arguments, 65,536 bytes) "
        "or were truncated by their source export; each was classified from its leading complete arguments"
    ]


@pytest.mark.parametrize(
    "argv",
    [
        ["python"],
        ["python", "-W"],
        ["python", "-B", "-m"],
        ["node", "--require", "dotenv/config"],
        ["npx", "-y"],
        ["npx", "--registry", "https://registry.example"],
        ["npm", "exec"],
        ["uv", "run", "--with", "x"],
        ["uv", "tool"],
        ["/usr/bin/node", "/usr/bin/npx", "--yes"],
        ["ollama"],
    ],
)
def test_offline_truncation_before_the_executed_tool_is_incomplete(run_connector, tmp_path, argv):
    # The arguments the export cut could name the tool these launchers run.
    source = _rows(tmp_path, [{"host": "box", "argv": argv, "argv_truncated": True}])
    findings, ctx = run_connector("runtime.processes", input=str(source))
    assert not findings and ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "runtime.processes: 1 command line(s) exceeded argument/byte limits (64 arguments, 65,536 bytes) "
        "or were truncated by their source export; 1 could not be classified from their leading complete "
        "arguments"
    ]


@pytest.mark.parametrize(
    "argv",
    [
        ["/usr/lib/jvm/java-17/bin/java", "-cp", "/opt/app/lib/*"],
        ["gcc", "-I/usr/include"],
        ["python", "train.py", "--epochs"],
        ["python", "-c", "import torch"],
        ["node", "/srv/app/server.js", "--port"],
        ["npx", "-y", "some-wrapper", "--verbose"],
        ["npm", "install", "left-pad"],
        ["ollama", "list", "--verbose"],
    ],
)
def test_offline_truncation_after_the_launch_is_read_is_complete(run_connector, tmp_path, argv):
    # No AI tool runs whatever the cut arguments were: a program that is no launcher, or a
    # launcher whose target was read before the final argument, which the export may have cut.
    source = _rows(tmp_path, [{"host": "box", "argv": argv, "argv_truncated": True}])
    findings, ctx = run_connector("runtime.processes", input=str(source))
    assert not findings and not ctx.stats.incomplete
    assert len(ctx.stats.warnings) == 1 and "each was classified" in ctx.stats.warnings[0]


@pytest.mark.parametrize(
    "row",
    [
        {"argv": ["npx", "-y", "@modelcontextprotocol/s"]},
        {"command_line": "npx -y @modelcontextprotocol/s"},
        {
            "exe": "/usr/bin/node",
            "command_line": "node /usr/lib/node_modules/npm/bin/npx-cli.js -y @modelcontextprotocol/s",
        },
        # Complete, these would be another MCP server, or the same one under another name.
        {"argv": ["npx", "-y", "some-wrapper"]},
        {"argv": ["npx", "-y", "@modelcontextprotocol/server-gi"]},
        {"argv": ["python", "train.py"]},
        {"argv": ["node", "/srv/app/server.js"]},
        {"argv": ["npm", "install"]},
        {"argv": ["ollama", "list"]},
        {"command_line": "/home/u/.local/bin/cla"},
    ],
)
def test_offline_truncation_inside_the_launch_target_is_incomplete(run_connector, tmp_path, row):
    """Regression: a row an export marked argv_truncated had its final argument, which the cut
    may have shortened, classified as complete: a cut MCP server package left the scan complete
    and empty, and a cut `server-gi` was reported as an MCP server of that name."""
    source = _rows(tmp_path, [{"host": "box", "user": "dev", **row, "argv_truncated": True}])
    findings, ctx = run_connector("runtime.processes", input=str(source))
    assert not findings and ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "runtime.processes: 1 command line(s) exceeded argument/byte limits (64 arguments, 65,536 bytes) "
        "or were truncated by their source export; 1 could not be classified from their leading complete "
        "arguments"
    ]


@pytest.mark.parametrize("field", ["argv", "command_line"])
def test_offline_truncation_after_the_launch_target_keeps_the_tool(run_connector, tmp_path, field):
    argv = ["npx", "-y", "@modelcontextprotocol/server-github", "--toolsets=repos,iss"]
    value = argv if field == "argv" else " ".join(argv)
    source = _rows(tmp_path, [{"host": "box", "user": "dev", field: value, "argv_truncated": True}])
    findings, ctx = run_connector("runtime.processes", input=str(source))
    assert not ctx.stats.incomplete and "each was classified" in ctx.stats.warnings[0]
    [finding] = findings
    assert finding.metadata["mcp_packages"] == {"@modelcontextprotocol/server-github": 1}
    assert finding.metadata["command_lines_truncated"] == 1


def test_offline_long_command_lines_of_other_programs_do_not_flood_or_fail_the_scan(run_connector, tmp_path):
    """Regression: a process with more than 64 arguments (a JVM, a compiler, an Electron app) made
    the scan incomplete although it was no AI tool, and each such row added its own warning
    until the connector's diagnostic limit was reached."""
    java = ["/usr/lib/jvm/java-17/bin/java"] + [f"-Dprop{n}=v" for n in range(80)] + ["-cp", "lib/*", "Main"]
    gcc = ["gcc"] + [f"-I/usr/include/p{n}" for n in range(80)] + ["-c", "x.c"]
    rows = [{"host": "box", "user": "dev", "pid": n, "argv": java if n % 2 else gcc} for n in range(1500)]
    rows.append({"host": "box", "user": "dev", "pid": 9999, "argv": ["claude"]})
    findings, ctx = run_connector("runtime.processes", input=str(_rows(tmp_path, rows)))
    assert [f.metadata["tool"] for f in findings] == ["claude-code"]
    assert not ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "runtime.processes: 1500 command line(s) exceeded argument/byte limits (64 arguments, 65,536 bytes) "
        "or were truncated by their source export; each was classified from its leading complete arguments"
    ]


def test_offline_application_arguments_do_not_create_runtime_or_lifecycle_evidence(index, tmp_path):
    source = _rows(
        tmp_path,
        [
            {"host": "box", "argv": ["node", "audit.js", "@openai/codex"]},
            {"host": "box", "argv": ["python", "audit.py", "mcp-server-fetch"]},
        ],
    )
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("runtime.processes", {"input": str(source)})]), index
    ).run()
    assert result.complete and not result.findings


@pytest.mark.parametrize(
    ("exe", "argv", "tool"),
    [
        (None, ["node", "/usr/local/bin/npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
         "mcp:@modelcontextprotocol/server-filesystem"),
        ("C:\\Program Files\\nodejs\\node.exe",
         ["C:\\Program Files\\nodejs\\node.exe",
          "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npx-cli.js", "-y", "@playwright/mcp@latest"],
         "mcp:@playwright/mcp"),
        (None, ["node", "/usr/lib/node_modules/npm/bin/npm-cli.js", "exec", "@modelcontextprotocol/server-github"],
         "mcp:@modelcontextprotocol/server-github"),
        (None, ["node", "/usr/local/bin/pnpm", "dlx", "@openai/codex"], "codex"),
        (None, ["node", "/usr/local/lib/node_modules/pnpm/bin/pnpm.cjs", "dlx", "@openai/codex"], "codex"),
        (None, ["node", "/usr/lib/node_modules/yarn/bin/yarn.js", "dlx", "@openai/codex"], "codex"),
        ("/usr/bin/python3.12", ["/usr/bin/python3", "/usr/bin/pipx", "run", "--spec", "aider-chat", "aider"],
         "aider"),
        (None, ["python3", "/home/dev/.local/bin/uvx", "mcp-server-git"], "mcp:mcp-server-git"),
        (None, ["python3", "-m", "pipx", "run", "aider"], "aider"),
        (None, ["python3", "-m", "uv", "run", "aider"], "aider"),
        # npm's process title replaces the command line; the executable is still node.
        ("/usr/local/bin/node", ["npm", "exec", "@modelcontextprotocol/server-github"],
         "mcp:@modelcontextprotocol/server-github"),
        # /proc/<pid>/cmdline shows that title as one argument with spaces (live mode reads no
        # executable), ahead of any arguments `exec -a` kept.
        (None, ["npm exec @modelcontextprotocol/server-github"], "mcp:@modelcontextprotocol/server-github"),
        ("/usr/local/bin/node", ["npm exec @modelcontextprotocol/server-github"],
         "mcp:@modelcontextprotocol/server-github"),
        (None, ["npx -y mcp-server-fetch", "--port", "8080"], "mcp:mcp-server-fetch"),
        # A process title that names the tool itself.
        ("/usr/bin/node", ["claude"], "claude-code"),
    ],
)  # fmt: skip
def test_runners_run_by_an_interpreter_keep_their_target(exe, argv, tool):
    """Regression: a package runner is an interpreter script, so the kernel shows `node /usr/bin/npx
    ...`, `node.exe ...\\npx-cli.js ...` or `python3 /usr/bin/pipx run ...`; the interpreter's script
    was read as the target, and runtime scans missed the tools they ran while reporting complete."""
    match, undecided = classify_command(exe, argv)
    assert match is not None and match[0].tool == tool and not undecided


@pytest.mark.parametrize(
    "argv",
    [
        ["node", "/usr/local/bin/npx", "--package", "@openai/codex", "audit"],
        ["python3", "/usr/bin/pipx", "install", "aider-chat"],
        ["node", "/usr/lib/node_modules/npm/bin/npm-cli.js", "install", "@openai/codex"],
        ["python3", "-m", "pipx", "list"],
        ["node", "/usr/local/bin/npx-helper.js", "@openai/codex"],
        # Process titles and paths with spaces that run no tool.
        ["sshd: dev [priv]"],
        ["npx --package @openai/codex audit"],
        ["C:\\Program Files\\nodejs\\node.exe", "server.js"],
        ["/opt/My Tools/npx", "audit"],
    ],
)
def test_runners_run_by_an_interpreter_keep_their_grammar(argv):
    assert classify(None, argv) is None


def test_offline_interpreter_launcher_fixture(run_connector):
    """osquery, Defender and generic rows in which an interpreter runs a package runner."""
    findings, ctx = run_connector(
        "runtime.processes", input=str(FIXTURES / "runtime" / "interpreter_launchers.jsonl")
    )
    assert not ctx.stats.incomplete and not ctx.stats.warnings
    assert sorted(finding.metadata["tool"] for finding in findings) == [
        "aider",
        "mcp:@modelcontextprotocol/server-filesystem",
        "mcp:@modelcontextprotocol/server-github",
        "mcp:@playwright/mcp",
    ]
    assert sorted(pid for finding in findings for pid in finding.metadata["pids"]) == [101, 102, 201, 301]


@pytest.mark.parametrize(
    ("argv", "tool"),
    [
        (["deno", "run", "-A", "npm:@anthropic-ai/claude-code"], "claude-code"),
        (["deno", "run", "--allow-all", "npm:@anthropic-ai/claude-code"], "claude-code"),
        (["deno", "run", "--allow-net=api.anthropic.com", "-R", "npm:@anthropic-ai/claude-code"], "claude-code"),
        (["node", "--max-old-space-size=4096", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"],
         "claude-code"),
        (["node", "--inspect", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"], "claude-code"),
        (["node", "--inspect=127.0.0.1:9229", "/usr/lib/node_modules/@openai/codex/bin/codex.js"], "codex"),
        (["npx", "--prefer-offline", "@anthropic-ai/claude-code"], "claude-code"),
        (["npx", "--loglevel=silent", "-y", "@modelcontextprotocol/server-github"],
         "mcp:@modelcontextprotocol/server-github"),
        (["uv", "run", "--frozen", "aider"], "aider"),
        (["uv", "run", "-m", "aider"], "aider"),
        (["uv", "run", "--module=aider"], "aider"),
        (["uv", "run", "--locked", "--with", "aider-chat", "-m", "aider"], "aider"),
        (["python", "-P", "-m", "aider"], "aider"),
        (["python3", "-Im", "aider"], "aider"),
        (["python3", "-BIm", "vllm.entrypoints.openai.api_server"], "vllm"),
        (["python3", "-Wignore", "-Xutf8", "-m", "litellm"], "litellm"),
    ],
)  # fmt: skip
def test_common_launcher_options_do_not_hide_the_target(argv, tool):
    """Regression: options the launch grammar did not know (deno permissions, node V8 and inspector
    options, npx --prefer-offline, uv run --frozen and -m, python -P and combined -Im) stopped the
    target from being read."""
    result = classify(None, argv)
    assert result is not None and result[0].tool == tool


@pytest.mark.parametrize(
    "argv",
    [
        # Inline code runs, whatever follows.
        ["node", "--eval=require('x')", "@openai/codex"],
        ["node", "--print=1", "/usr/lib/node_modules/@openai/codex/bin/codex.js"],
        ["npx", "--call=claude", "@modelcontextprotocol/server-github"],
        ["python3", "-Ic", "import aider", "-m", "aider"],
        # An option that is not known is not guessed.
        ["uv", "run", "--unknown-flag", "aider"],
        ["deno", "run", "--unknown", "npm:@anthropic-ai/claude-code"],
        ["python3", "-K", "-m", "aider"],
    ],
)
def test_launcher_options_that_run_no_target_or_are_unknown(argv):
    assert classify(None, argv) is None


def test_offline_launcher_boundary_fixture(run_connector):
    findings, ctx = run_connector(
        "runtime.processes", input=str(FIXTURES / "runtime" / "launcher_boundaries.jsonl")
    )
    assert not ctx.stats.incomplete
    assert {finding.metadata["tool"] for finding in findings} == {"aider", "codex"}
    assert sorted(pid for finding in findings for pid in finding.metadata["pids"]) == [5, 6]


def test_live_argument_limit_marks_empty_scan_incomplete(run_connector, monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
    (proc / "11").mkdir(parents=True)
    argv = [b"python"] + [b"-B"] * 63 + [b"-m", b"vllm.entrypoints.openai.api_server"]
    (proc / "11" / "cmdline").write_bytes(b"\0".join(argv) + b"\0")
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert not findings and ctx.stats.incomplete
    assert any("argument/byte limits" in warning for warning in ctx.stats.warnings)


def test_live_long_command_line_of_another_program_is_complete(run_connector, monkeypatch, tmp_path):
    """Regression: a JVM with more than 64 arguments made a live scan incomplete with no AI process."""
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
    (proc / "21").mkdir(parents=True)
    argv = [b"/usr/lib/jvm/bin/java"] + [b"-Dk%d=v" % n for n in range(80)] + [b"-cp", b"/opt/lib/*", b"Main"]
    (proc / "21" / "cmdline").write_bytes(b"\0".join(argv) + b"\0")
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert not findings and not ctx.stats.incomplete
    assert ctx.stats.warnings == [
        "runtime.processes: 1 command line(s) exceeded argument/byte limits (64 arguments, 65,536 bytes); "
        "each was classified from its leading complete arguments"
    ]


def test_text_byte_limit_never_classifies_a_partial_package_name(run_connector, tmp_path):
    command = "npx " + " " * (64 * 1024 - 28) + "@anthropic-ai/claude-codex"
    source = _rows(tmp_path, [{"host": "box", "command_line": command}])
    findings, ctx = run_connector("runtime.processes", input=str(source))
    assert not findings and ctx.stats.incomplete


@pytest.mark.parametrize("field", ["host", "user"])
def test_runtime_identity_is_not_clipped_before_grouping(run_connector, tmp_path, field):
    prefix = "a" * 60 + "." + "b" * 59
    identities = [prefix + ".prod.example", prefix + ".dev.example"]
    rows = [
        {"host": "box", "user": "operator", field: value, "pid": number, "argv": ["claude"]}
        for number, value in enumerate(identities, 1)
    ]
    findings, ctx = run_connector("runtime.processes", input=str(_rows(tmp_path, rows)))
    assert not ctx.stats.incomplete and len(findings) == 2
    assert len({finding.id for finding in findings}) == 2
    assert {getattr(finding, "account" if field == "host" else "owner") for finding in findings} == set(
        identities
    )
    assert all(finding.metadata["processes"] == 1 for finding in findings)
    if field == "host":
        endpoint = Finding(
            surface=Surface.ENDPOINT,
            connector="endpoint.inventory",
            kind=Kind.AGENT_CONFIG,
            title="Claude configuration",
            resource="endpoint:configured",
            resource_type="agent-config",
            account=identities[0],
            owner="operator",
            frameworks=["coding-agent.claude-code"],
        )
        correlate_lifecycle([endpoint, *findings])
        assert "observed-running" in endpoint.tags
        assert endpoint.metadata["lifecycle"]["related"] == [
            next(f.id for f in findings if f.account == identities[0])
        ]
        endpoint.account = prefix
        correlate_lifecycle([endpoint, *findings])
        assert "observed-running" not in endpoint.tags


@pytest.mark.parametrize("field", ["host", "hostIdentifier", "user"])
@pytest.mark.parametrize("value", ["a" * 4097, "host\nother-host", {"name": "box"}, 0, False, [], {}])
def test_invalid_runtime_identity_is_incomplete_not_truncated(run_connector, tmp_path, field, value):
    rows = [{"host": "box", "user": "operator", field: value, "argv": ["claude"]}]
    findings, ctx = run_connector("runtime.processes", input=str(_rows(tmp_path, rows)))
    assert not findings and ctx.stats.incomplete
    assert any("host/user identity" in warning for warning in ctx.stats.warnings)


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
    ("cmdline", "found", "incomplete"),
    [
        # A long prompt passed with -p: the leading arguments are intact, and what runs
        # (claude, from argv[0]) cannot change with the prompt the limit dropped.
        (b"claude\0-p\0" + b"x" * 70_000 + b"\0", True, False),
        # The partial final argument is dropped: cut at the limit, the package
        # @anthropic-ai/claude-codex would read as @anthropic-ai/claude-code. It is npx's
        # target here, so what runs is unknown and coverage incomplete.
        (b"npx\0--registry\0" + b"y" * (64 * 1024 - 41) + b"\0@anthropic-ai/claude-codex\0", False, True),
        # The same cut package is only an argument of the command npx runs (the y run).
        (b"npx\0" + b"y" * (64 * 1024 - 30) + b"\0@anthropic-ai/claude-codex\0", False, False),
    ],
    ids=["long-prompt", "partial-final-argument", "argument-of-another-command"],
)
def test_live_mode_classifies_a_truncated_command_line(
    run_connector, monkeypatch, tmp_path, cmdline, found, incomplete
):
    """Regression (#220 review F3): a command line over the byte limit is truncated, not dropped."""
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
    (proc / "11").mkdir(parents=True)
    (proc / "11" / "cmdline").write_bytes(cmdline)
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert ctx.stats.incomplete is incomplete
    [warning] = ctx.stats.warnings
    assert warning.startswith(
        "runtime.processes: 1 command line(s) exceeded argument/byte limits (64 arguments, 65,536 bytes); "
    )
    if not found:
        assert findings == []
        return
    (finding,) = findings
    # The title ends with the account that runs the test, so pin only the product and host.
    assert finding.title.startswith("Claude Code running on box (")
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


def test_live_mode_drops_only_the_argument_the_byte_limit_cut(run_connector, monkeypatch, tmp_path):
    # The live record is already free of the cut argument: analyze() must not drop the package
    # before it as an export's cut row loses its final argument.
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
    (proc / "11").mkdir(parents=True)
    cmdline = b"npx\0-y\0@modelcontextprotocol/server-github\0" + b"x" * 70_000 + b"\0"
    (proc / "11" / "cmdline").write_bytes(cmdline)
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert not ctx.stats.incomplete and "each was classified" in ctx.stats.warnings[0]
    [finding] = findings
    assert finding.metadata["mcp_packages"] == {"@modelcontextprotocol/server-github": 1}
    assert finding.metadata["command_lines_truncated"] == 1


@pytest.mark.parametrize(
    "cmdline",
    [
        # npm sets its process title over the command line: one argument, padded with NULs.
        b"npm exec @modelcontextprotocol/server-github\0" + b"\0" * 24,
        # `exec -a "npm exec ..." sleep 300` keeps the arguments after the title.
        b"npm exec @modelcontextprotocol/server-github\0" + b"300\0",
    ],
    ids=["npm-title", "exec-a"],
)
def test_live_mode_reads_a_process_title_with_spaces(run_connector, monkeypatch, tmp_path, cmdline):
    """Regression: /proc shows npm's `npm exec <pkg>` process title as one argument with spaces.
    Its last path component (`server-github`) was read as the executable, so a live scan reported
    nothing and stayed complete."""
    proc = tmp_path / "proc"
    _proc_self(proc, monkeypatch)
    (proc / "11").mkdir(parents=True)
    (proc / "11" / "cmdline").write_bytes(cmdline)
    monkeypatch.setattr(runtime_processes, "_PROC", proc)
    monkeypatch.setattr(runtime_processes.platform, "system", lambda: "Linux")
    findings, ctx = run_connector("runtime.processes", label="box")
    assert not ctx.stats.warnings and not ctx.stats.incomplete
    [finding] = findings
    assert finding.metadata["tool"] == "mcp:@modelcontextprotocol/server-github"
    assert finding.metadata["executables"] == {"npm": 1}


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


def _no_such_process(monkeypatch, *sources):
    """Opening these per-process files fails with ESRCH, as /proc does for a process without an mm."""
    original = runtime_processes.os.open

    def esrch(path, flags, *args, **kwargs):
        if path in sources:
            raise ProcessLookupError(3, "No such process")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_processes.os, "open", esrch)


def test_kernel_threads_are_not_inspected(run_connector, monkeypatch, tmp_path):
    """Regression (#220 verifier): kernel threads made every live inspect_env_keys scan incomplete."""
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"")
    # PF_KTHREAD (0x00200000) in the flags field, as kthreadd reports 0x208040.
    (pid / "stat").write_text(
        "12 (kworker/0:1) "
        + " ".join(["S", "2", "0", "0", "0", "-1", "2129984"] + ["0"] * 12 + ["12345", "0"])
    )
    _no_such_process(monkeypatch, "environ", "maps", "fd")
    findings, ctx = run_connector(
        "runtime.processes", inspect_maps=True, inspect_fds=True, inspect_env_keys=["OLLAMA_MODELS"]
    )
    assert findings == [] and not ctx.stats.incomplete and not ctx.stats.warnings


def _stat(state: str, threads: int) -> str:
    """A synthetic /proc/<pid>/stat line: state is field 3, num_threads field 20, start time field 22."""
    return "12 (worker) " + " ".join([state, *(["0"] * 16), str(threads), "0", "12345", "0"])


def test_esrch_from_a_zombie_without_threads_is_not_applicable(run_connector, monkeypatch, tmp_path):
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    (pid / "stat").write_text(_stat("Z", 1))
    _no_such_process(monkeypatch, "environ")
    findings, ctx = run_connector("runtime.processes", inspect_maps=True, inspect_env_keys=["OLLAMA_MODELS"])
    assert len(findings) == 1 and not ctx.stats.incomplete and not ctx.stats.warnings
    (inspection,) = findings[0].metadata["runtime_inspection"]
    assert inspection["status"] == {"maps": "ok", "fds": "not_requested", "environ": "not_applicable"}
    assert inspection["environment_keys"] == []


@pytest.mark.parametrize("state", ["S", "R", "D"])
def test_esrch_from_a_process_that_is_not_a_zombie_is_unreadable(run_connector, monkeypatch, tmp_path, state):
    """Regression (security220-3): ESRCH was counted as not applicable whatever the process state."""
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    (pid / "stat").write_text(_stat(state, 1))
    _no_such_process(monkeypatch, "environ")
    findings, ctx = run_connector("runtime.processes", inspect_maps=True, inspect_env_keys=["OLLAMA_MODELS"])
    assert ctx.stats.incomplete
    assert "runtime.processes: environ inspection unreadable; scope incomplete" in ctx.stats.warnings
    (inspection,) = findings[0].metadata["runtime_inspection"]
    assert inspection["status"] == {"maps": "ok", "fds": "not_requested", "environ": "unreadable"}


def test_exited_leader_with_live_threads_is_not_a_complete_empty_inspection(
    run_connector, monkeypatch, tmp_path
):
    """Regression (security220-3): a process whose leader exited hid its live threads from inspection.

    Linux shows such a process as state Z with num_threads above one; its
    environ reports ESRCH and its maps and fd directory read empty, while a
    live thread still maps and holds a model file.
    """
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"")
    (pid / "stat").write_text(_stat("Z", 2))
    (pid / "maps").write_text("")
    (pid / "fd" / "7").unlink()
    _no_such_process(monkeypatch, "environ")
    findings, ctx = run_connector(
        "runtime.processes", inspect_maps=True, inspect_fds=True, inspect_env_keys=["OLLAMA_MODELS"]
    )
    assert findings == []
    assert ctx.stats.incomplete
    assert {
        f"runtime.processes: {source} inspection unreadable; scope incomplete"
        for source in ("maps", "fds", "environ")
    } <= set(ctx.stats.warnings)


def test_exited_leader_keeps_indicators_read_from_the_live_address_space(
    run_connector, monkeypatch, tmp_path
):
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"")
    (pid / "stat").write_text(_stat("Z", 3))
    (pid / "fd" / "7").unlink()
    findings, ctx = run_connector("runtime.processes", inspect_maps=True, inspect_fds=True)
    assert ctx.stats.incomplete
    (finding,) = findings
    (inspection,) = finding.metadata["runtime_inspection"]
    assert inspection["status"] == {"maps": "ok", "fds": "unreadable", "environ": "not_requested"}
    assert inspection["mapped_libraries"] == ["ggml"]


def test_esrch_when_the_process_changed_is_not_attributed(run_connector, monkeypatch, tmp_path):
    pid = _inspection_proc(tmp_path, monkeypatch, argv=b"claude\0")
    _no_such_process(monkeypatch, "environ")
    original = RuntimeProcessConnector._inspect

    def reuse(self, directory, budget):
        result = original(self, directory, budget)
        (pid / "stat").write_text((pid / "stat").read_text().replace("12345", "54321"))
        return result

    monkeypatch.setattr(RuntimeProcessConnector, "_inspect", reuse)
    findings, ctx = run_connector("runtime.processes", inspect_env_keys=["OLLAMA_MODELS"])
    assert findings == [] and any("identity changed" in warning for warning in ctx.stats.warnings)

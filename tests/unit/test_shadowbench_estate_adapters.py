"""Unit tests for the ShadowBench estate adapters (tools/shadowbench/estate/adapters).

The wrapper-script tests run each generated `run.sh` against a stub tool
binary under a temporary directory: the stub records its working directory
and arguments and prints a minimal valid report, so no real scanner and no
corpus content ever runs.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest

from tools.discovery_benchmark.runner import RunPolicy
from tools.shadowbench.estate.adapters import Adapter, ToolConfig
from tools.shadowbench.estate.adapters.agentsight_estate import AgentSightAdapter
from tools.shadowbench.estate.adapters.ai_infra_guard import AiInfraGuardAdapter
from tools.shadowbench.estate.adapters.cisco_mcp_scanner import CiscoMcpScannerAdapter
from tools.shadowbench.estate.adapters.code_wrappers import (
    AgentDiscoverEstateAdapter,
    AgenticRadarEstateAdapter,
    VetEstateAdapter,
)
from tools.shadowbench.estate.adapters.common import LAUNCHERS, client_slug, refuse_launchers
from tools.shadowbench.estate.adapters.mcp_scan import McpScanAdapter
from tools.shadowbench.estate.adapters.numbat import NumbatAdapter
from tools.shadowbench.estate.runner import RunResult, _slug, run_command, run_unit

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not Path("/bin/sh").exists(), reason="wrapper scripts need a POSIX /bin/sh"
)

# Estate unit names come from the corpus. Each name below runs a command if it
# reaches a shell unquoted or inside double quotes; every payload only creates
# a `pwned-*` marker file in the current directory.
HOSTILE_DEVICE = "lap$(touch pwned-1)\"$(touch pwned-2)\"`touch pwned-3`;touch pwned-4;'x'"
HOSTILE_USER = "u $HOME '\"$(touch pwned-5)"
HOSTILE_BIN_DIR = "bin $(touch pwned-6) `touch pwned-7`"

#: A Cisco MCP Scanner report with no rows.
EMPTY_SCAN = '{"scan_results": []}'


def _stub(
    path: Path,
    log: Path,
    *,
    stdout: str,
    exits: dict[str, int] | None = None,
    before: str = "",
) -> Path:
    """A fake tool: logs `$PWD` and its argv (NUL-separated, one call per line), runs
    `before`, prints `stdout` and exits with the code `exits` gives its subcommand."""
    cases = "".join(f"  *' {word} '*) code={code} ;;\n" for word, code in (exits or {}).items())
    lines = [
        "#!/bin/sh",
        f"{{ printf '%s\\0' \"$PWD\" \"$@\"; printf '\\n'; }} >> {shlex.quote(str(log))}",
        before,
        "code=0",
        f'case " $* " in\n{cases}esac' if cases else "",
        f"printf '%s' {shlex.quote(stdout)}",
        'exit "$code"',
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _calls(log: Path) -> list[list[str]]:
    """Each stub call as [cwd, *argv]."""
    if not log.exists():
        return []
    return [line.split("\0")[:-1] for line in log.read_text(encoding="utf-8").split("\n") if line]


def _home(tmp_path: Path, device: str = HOSTILE_DEVICE, user: str = HOSTILE_USER) -> tuple[Path, Path]:
    """An estate with one home unit; returns (estate, the user's fake $HOME)."""
    estate = tmp_path / "estate"
    home = estate / "home" / device / user
    home.mkdir(parents=True)
    (home / ".claude.json").write_text('{"mcpServers": {}}', encoding="utf-8")
    return estate, home


def _run(
    adapter: Adapter,
    tool_id: str,
    stub: Path,
    tmp_path: Path,
    estate: Path,
    unit: str,
    *,
    extra_path: tuple[str, ...] = (),
) -> tuple[RunResult, Path]:
    cfg = ToolConfig({"tools": {tool_id: {"bin": str(stub)}}})
    out_dir = tmp_path / "runs" / tool_id / _slug(unit)
    policy = RunPolicy(timeout=60, path="/usr/bin:/bin", extra_path=extra_path)
    return run_unit(adapter, cfg, unit, estate, out_dir, policy), out_dir


def _markers(tmp_path: Path) -> list[str]:
    return sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("pwned*"))


# --- wrapper scripts: corpus names never reach a shell as code ------------------------------------


@pytest.mark.parametrize(
    ("adapter", "tool_id", "stdout", "outputs"),
    [
        (McpScanAdapter(), "mcp_scan", "{}", ["inspect.json"]),
        (NumbatAdapter(), "numbat", "[]", ["agents.json", "scan.ndjson"]),
        (CiscoMcpScannerAdapter(), "cisco_mcp_scanner", EMPTY_SCAN, ["known.json", "config0.json"]),
        (AgentSightAdapter(), "agentsight", "[]", ["prompts.json", "audit.json"]),
    ],
    ids=["mcp_scan", "numbat", "cisco_mcp_scanner", "agentsight"],
)
def test_hostile_unit_and_binary_paths_stay_inert(
    tmp_path: Path, adapter: Adapter, tool_id: str, stdout: str, outputs: list[str]
) -> None:
    log = tmp_path / "calls.log"
    stub = _stub(tmp_path / HOSTILE_BIN_DIR / tool_id, log, stdout=stdout)
    estate, home = _home(tmp_path)
    unit = f"home:{HOSTILE_DEVICE}"

    result, out_dir = _run(adapter, tool_id, stub, tmp_path, estate, unit)

    assert _markers(tmp_path) == []
    assert result.status == "ok", (result.error, result.commands)
    calls = _calls(log)
    assert calls, "the stub tool never ran"
    for name in outputs:
        assert (out_dir / name).is_file(), name
    if tool_id == "cisco_mcp_scanner":
        config_args = [call[call.index("--config-path") + 1] for call in calls if "--config-path" in call]
        assert config_args == [str(home / ".claude.json")]


def test_generated_script_words_parse_as_literals(tmp_path: Path) -> None:
    estate, home = _home(tmp_path)
    out_dir = tmp_path / "runs" / "cisco_mcp_scanner" / _slug(f"home:{HOSTILE_DEVICE}")
    out_dir.mkdir(parents=True)
    binary = str(tmp_path / HOSTILE_BIN_DIR / "mcp-scanner")
    cfg = ToolConfig({"tools": {"cisco_mcp_scanner": {"bin": binary}}})

    (command,) = CiscoMcpScannerAdapter().commands(cfg, f"home:{HOSTILE_DEVICE}", estate, out_dir)

    words = [shlex.split(line) for line in Path(command.argv[1]).read_text(encoding="utf-8").splitlines()]
    steps = [line for line in words if line and line[0] == binary]
    assert [step[5] for step in steps] == ["known-configs", "config"]
    assert steps[1][7] == str(home / ".claude.json")
    assert steps[1][9] == str(out_dir / "config0.json")


def test_wrapper_scripts_use_absolute_paths_for_a_relative_run_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    log = tmp_path / "calls.log"
    stub = _stub(tmp_path / "bin" / "snyk-agent-scan", log, stdout="{}")
    estate, _ = _home(tmp_path, device="laptop", user="dana")
    cfg = ToolConfig({"tools": {"mcp_scan": {"bin": str(stub)}}})
    out_dir = Path("runs") / "mcp_scan" / "home__laptop"

    result = run_unit(McpScanAdapter(), cfg, "home:laptop", estate, out_dir, RunPolicy(timeout=60))

    assert result.status == "ok", (result.error, result.commands)
    assert (tmp_path / out_dir / "inspect.json").read_text(encoding="utf-8") == "{}"


# --- wrapper scripts: a failed step fails the unit ------------------------------------------------


@pytest.mark.parametrize(
    ("exits", "expected"),
    [({"known-configs": 3}, 3), ({"config": 5}, 5), ({"known-configs": 3, "config": 5}, 3)],
    ids=["first-step", "later-step", "first-failure-wins"],
)
def test_cisco_script_exits_with_the_first_failed_step(
    tmp_path: Path, exits: dict[str, int], expected: int
) -> None:
    log = tmp_path / "calls.log"
    stub = _stub(tmp_path / "bin" / "mcp-scanner", log, stdout=EMPTY_SCAN, exits=exits)
    estate, _ = _home(tmp_path, device="laptop", user="dana")

    result, _ = _run(CiscoMcpScannerAdapter(), "cisco_mcp_scanner", stub, tmp_path, estate, "home:laptop")

    assert result.status == "failed"
    assert result.commands[0].exit_code == expected
    assert len(_calls(log)) == 2, "every step still runs after a failure"


def test_agentsight_script_exits_with_the_first_failed_report(tmp_path: Path) -> None:
    log = tmp_path / "calls.log"
    stub = _stub(tmp_path / "bin" / "agentsight", log, stdout="[]", exits={"prompts": 4})
    estate, _ = _home(tmp_path, device="laptop", user="dana")

    result, _ = _run(AgentSightAdapter(), "agentsight", stub, tmp_path, estate, "home:laptop")

    assert result.status == "failed"
    assert result.commands[0].exit_code == 4
    assert [call[2:4] for call in _calls(log)] == [["prompts", "--json"], ["audit", "--json"]]


@pytest.mark.parametrize(
    ("prompts", "audit", "fragment"),
    [
        (None, None, "prompts.json missing or empty"),
        ("", "[]", "prompts.json missing or empty"),
        ("No sessions found\n", "[]", "prompts.json holds no JSON"),
        ("[]", '{"comm": "claude"', "audit.json unparseable"),
        ("[]", "42", "audit.json holds no JSON"),
        ('{"error": "Traceback: boom"}', "[]", "prompts.json holds no session record"),
        ("{}", "[]", "prompts.json holds no session record"),
        ("[]", '[{"pid": 7}]', "audit.json holds no session record"),
        ("[]", '[1, "two"]', "audit.json holds no session record"),
    ],
    ids=[
        "missing",
        "empty",
        "text-only",
        "truncated",
        "scalar",
        "error-object",
        "empty-object",
        "records-without-comm",
        "non-records",
    ],
)
def test_agentsight_unusable_report_is_an_error(
    tmp_path: Path, prompts: str | None, audit: str | None, fragment: str
) -> None:
    for name, text in (("prompts.json", prompts), ("audit.json", audit)):
        if text is not None:
            (tmp_path / name).write_text(text, encoding="utf-8")

    normalized = AgentSightAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is not None
    assert fragment in normalized.error


def test_agentsight_valid_reports_normalize_without_error(tmp_path: Path) -> None:
    (tmp_path / "prompts.json").write_text(
        'loaded 1 session\n[{"comm": "claude", "conversation_id": "c1", "model": "m"}]', encoding="utf-8"
    )
    (tmp_path / "audit.json").write_text("[]", encoding="utf-8")

    normalized = AgentSightAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is None
    assert [p.fact for p in normalized.predictions] == ["ai-client:claude-code"]


def test_agentsight_report_with_one_session_record_is_accepted(tmp_path: Path) -> None:
    (tmp_path / "prompts.json").write_text('{"comm": "codex", "conversation_id": "c2"}', encoding="utf-8")
    (tmp_path / "audit.json").write_text('[{"comm": "gemini"}, {"pid": 9}]', encoding="utf-8")

    normalized = AgentSightAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is None
    assert normalized.raw_count == 3
    assert [p.fact for p in normalized.predictions] == ["ai-client:codex", "ai-client:gemini-cli"]


@pytest.mark.parametrize(
    ("files", "fragment"),
    [
        ({"known.json": EMPTY_SCAN, "config0.json": "Traceback (most recent"}, "config0.json"),
        ({"config0.json": EMPTY_SCAN}, "known.json missing"),
        ({"known.json": "", "config0.json": EMPTY_SCAN}, "known.json empty"),
        ({"known.json": '{"scan_results": {"a": 1}}'}, "known.json scan_results is missing or not a list"),
        ({"known.json": "[]"}, "known.json is not an object"),
        # An object without a scan_results list is an error report, not zero servers.
        ({"known.json": "{}"}, "known.json scan_results is missing"),
        ({"known.json": '{"error": "Traceback: boom"}'}, "known.json scan_results is missing"),
        ({"known.json": '{"scan_results": null}'}, "known.json scan_results is missing"),
        ({"known.json": '{"scan_results": false}'}, "known.json scan_results is missing"),
        ({"known.json": '{"scan_results": 0}'}, "known.json scan_results is missing"),
        ({"known.json": '{"scan_results": ""}'}, "known.json scan_results is missing"),
        ({"known.json": EMPTY_SCAN, "config0.json": '{"scan_results": null}'}, "config0.json scan_results"),
    ],
    ids=[
        "one-step-crashed",
        "known-missing",
        "known-empty",
        "rows-not-list",
        "not-object",
        "rows-key-missing",
        "error-object",
        "rows-null",
        "rows-false",
        "rows-zero",
        "rows-empty-string",
        "config-rows-null",
    ],
)
def test_cisco_unusable_output_is_an_error(tmp_path: Path, files: dict[str, str], fragment: str) -> None:
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")

    normalized = CiscoMcpScannerAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is not None
    assert fragment in normalized.error


def test_cisco_valid_output_normalizes_without_error(tmp_path: Path) -> None:
    rows = [{"server_source": "~/.claude.json:github", "tool_name": "search"}]
    (tmp_path / "known.json").write_text(json.dumps({"scan_results": rows}), encoding="utf-8")
    (tmp_path / "config0.json").write_text(EMPTY_SCAN, encoding="utf-8")

    normalized = CiscoMcpScannerAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is None
    assert [p.text for p in normalized.predictions] == ["~/.claude.json:github search"]


# --- client names ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("Claude Desktop App", "claude-desktop"),
        ("claude_desktop", "claude-desktop"),
        ("CLAUDE_DESKTOP", "claude-desktop"),
        ("Cline (VS Code)", "cline"),
        ("Continue (VS Code)", "continue"),
        ("GitHub Copilot (VS Code)", "copilot"),
    ],
)
def test_client_slug_prefers_the_most_specific_client(name: str, slug: str) -> None:
    assert client_slug(name) == slug


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        # Names the 2026-10-11 run's tools printed; their mapping must not move.
        ("claude code", "claude-code"),
        ("Claude Code", "claude-code"),
        ("claude_code", "claude-code"),
        ("claude", "claude-code"),
        ("claude desktop", "claude-desktop"),
        ("cursor", "cursor"),
        ("windsurf", "windsurf"),
        ("vscode", "generic"),
        ("VS Code", "generic"),
        ("gemini cli", "gemini-cli"),
        ("gemini_cli", "gemini-cli"),
        ("Gemini CLI", "gemini-cli"),
        ("codex", "codex"),
        ("continue", "continue"),
        ("amazon_q", "amazon-q"),
        ("Amazon Q", "amazon-q"),
        # Other table rows and fallbacks.
        ("GitHub Copilot Chat", "copilot"),
        ("lm studio", "lm-studio"),
        ("Amazon Q Developer", "amazon-q"),
        ("cline", "cline"),
        ("decline-bot", "generic"),
        ("", "generic"),
        ("node", "generic"),
    ],
)
def test_client_slug_table(name: str, slug: str) -> None:
    assert client_slug(name) == slug


# --- wrapped code-surface commands keep their working directory -----------------------------------


def test_vet_code_command_runs_in_the_repository(tmp_path: Path) -> None:
    log = tmp_path / "calls.log"
    stub = _stub(tmp_path / "bin" / "vet", log, stdout="")
    estate = tmp_path / "estate"
    repo = estate / "code" / "repo-x"
    repo.mkdir(parents=True)
    out_dir = tmp_path / "runs" / "vet" / "code__repo-x"
    out_dir.mkdir(parents=True)
    cfg = ToolConfig({"tools": {"vet": {"bin": str(stub)}}})
    inner = VetEstateAdapter().inner.commands(cfg, repo, out_dir)

    (command,) = VetEstateAdapter().commands(cfg, "code:repo-x", estate, out_dir)
    result = run_command(command, index=0, policy=RunPolicy(timeout=60), out_dir=out_dir, home=tmp_path)

    assert result.ok
    (call,) = _calls(log)
    assert Path(call[0]).resolve() == repo.resolve()
    assert tuple(call[1:]) == inner[0].argv[1:]
    assert command.argv[-len(inner[0].argv) :] == inner[0].argv
    assert command.env == inner[0].env
    assert command.ok_exit_codes == inner[0].ok_exit_codes


@pytest.mark.parametrize("adapter", [AgenticRadarEstateAdapter(), AgentDiscoverEstateAdapter()])
def test_wrapped_commands_that_run_in_the_run_directory_are_unchanged(
    tmp_path: Path, adapter: AgenticRadarEstateAdapter | AgentDiscoverEstateAdapter
) -> None:
    repo = tmp_path / "estate" / "code" / "repo-x"
    repo.mkdir(parents=True)
    cfg = ToolConfig({"tools": {adapter.spec.id: {"bin": "/opt/tool"}}})
    inner = adapter.inner.commands(cfg, repo, tmp_path / "out")

    converted = adapter.commands(cfg, "code:repo-x", tmp_path / "estate", tmp_path / "out")

    assert [c.argv for c in converted] == [c.argv for c in inner]
    assert [c.ok_exit_codes for c in converted] == [c.ok_exit_codes for c in inner]


# --- AI-Infra-Guard: attribution comes from the tool's output only --------------------------------

_SCAN = (
    "\x1b[32mhttp://127.0.0.1:11434 [200] [ollama:0.3.9]\x1b[0m\n"
    "http://127.0.0.1:8000 [200] [openai-compatible] [vllm:0.6.3]\n"
    "scan finished\n"
)


def test_ai_infra_guard_predictions_never_carry_the_services_anchor(tmp_path: Path) -> None:
    services = {
        "services": [
            {"id": "a", "kind": "ollama", "port": 11434, "anchor": "dev-laptop-02:marcus:ollama"},
            {"id": "b", "kind": "vllm", "port": 8000, "anchor": "build-runner-3:ci:vllm"},
        ]
    }
    (tmp_path / "services.json").write_text(json.dumps(services), encoding="utf-8")
    (tmp_path / "scan.txt").write_text(_SCAN, encoding="utf-8")

    normalized = AiInfraGuardAdapter().normalize("sim", tmp_path)

    assert normalized.error is None
    assert [(p.fact, p.text) for p in normalized.predictions] == [
        ("agent-process:ollama", "http://127.0.0.1:11434 ollama:0.3.9"),
        ("agent-process:vllm", "http://127.0.0.1:8000 openai-compatible vllm:0.6.3"),
    ]


@pytest.mark.parametrize("text", ["", "scan finished\n", "error: dial tcp: connection refused\n"])
def test_ai_infra_guard_scan_without_target_lines_is_an_error(tmp_path: Path, text: str) -> None:
    (tmp_path / "scan.txt").write_text(text, encoding="utf-8")

    normalized = AiInfraGuardAdapter().normalize("sim", tmp_path)

    assert normalized.error == "scan.txt holds no target result line"


# --- MCP server launchers never run, whatever the host has installed ------------------------------


def _host_launchers(tmp_path: Path) -> Path:
    """A directory standing in for a host with npx, uvx and docker installed: each
    one leaves a marker when it runs."""
    host = tmp_path / "hostbin"
    host.mkdir()
    for name in ("npx", "uvx", "docker"):
        launcher = host / name
        launcher.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(tmp_path / f'pwned-{name}'))}\n")
        launcher.chmod(0o755)
    return host


def _launching_stub(tmp_path: Path, name: str, stdout: str) -> tuple[Path, Path]:
    """A fake scanner that tries to start configured MCP servers the way a client would."""
    launches = tmp_path / "launches.log"
    log = shlex.quote(str(launches))
    script = shlex.quote(f"open({str(tmp_path / 'pwned-python3')!r}, 'w')")
    before = "\n".join(
        [
            f"npx -y @modelcontextprotocol/server-github; echo npx=$? >> {log}",
            f"uvx mcp-server-fetch; echo uvx=$? >> {log}",
            f"docker run -i --rm mcp/server; echo docker=$? >> {log}",
            f"python3 -c {script}; echo python3=$? >> {log}",
        ]
    )
    stub = _stub(tmp_path / "bin" / name, tmp_path / "calls.log", stdout=stdout, before=before)
    return stub, launches


@pytest.mark.parametrize(
    ("adapter", "tool_id", "binary", "stdout"),
    [
        (CiscoMcpScannerAdapter(), "cisco_mcp_scanner", "mcp-scanner", EMPTY_SCAN),
        (McpScanAdapter(), "mcp_scan", "snyk-agent-scan", "{}"),
    ],
    ids=["cisco_mcp_scanner", "mcp_scan"],
)
def test_mcp_server_launchers_are_refused_even_when_the_host_has_them(
    tmp_path: Path, adapter: Adapter, tool_id: str, binary: str, stdout: str
) -> None:
    host = _host_launchers(tmp_path)
    stub, launches = _launching_stub(tmp_path, binary, stdout)
    estate, _ = _home(tmp_path, device="laptop", user="dana")

    result, _ = _run(adapter, tool_id, stub, tmp_path, estate, "home:laptop", extra_path=(str(host),))

    assert _markers(tmp_path) == []
    recorded = launches.read_text(encoding="utf-8").split()
    assert recorded and all(entry.endswith("=126") for entry in recorded), recorded
    assert result.status == "ok", (result.error, result.commands)


def test_launcher_shims_refuse_without_reading_arguments(tmp_path: Path) -> None:
    lines = refuse_launchers(tmp_path / "shims")

    assert lines[0].startswith("PATH=")
    for name in LAUNCHERS:
        proc = subprocess.run(
            [str(tmp_path / "shims" / name), "-c", f"touch {tmp_path / 'pwned-shim'}"],
            capture_output=True,
            text=True,
            check=False,
            cwd=tmp_path,
        )
        assert proc.returncode == 126, name
        assert f"refused to start {name}" in proc.stderr
    assert _markers(tmp_path) == []


def test_launcher_shim_directory_with_a_colon_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must not contain ':'"):
        refuse_launchers(tmp_path / "a:b")

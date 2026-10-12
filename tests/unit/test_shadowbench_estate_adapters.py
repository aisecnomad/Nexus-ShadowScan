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
from pathlib import Path

import pytest

from tools.discovery_benchmark.runner import RunPolicy
from tools.shadowbench.estate.adapters import ToolConfig
from tools.shadowbench.estate.adapters.ai_infra_guard import AiInfraGuardAdapter
from tools.shadowbench.estate.adapters.code_wrappers import (
    AgentDiscoverEstateAdapter,
    AgenticRadarEstateAdapter,
    VetEstateAdapter,
)
from tools.shadowbench.estate.adapters.common import client_slug
from tools.shadowbench.estate.runner import run_command

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not Path("/bin/sh").exists(), reason="wrapper scripts need a POSIX /bin/sh"
)


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

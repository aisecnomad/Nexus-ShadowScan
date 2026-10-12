"""Perplexity numbat ``agents`` inventory on the endpoint/home surface.

Build (checkout of github.com/perplexityai/numbat at commit 77ece3a76dce, go.mod
``go 1.26.6``; Go 1.24 fetches the 1.26.6 toolchain through the module proxy)::

    CGO_ENABLED=0 GOTOOLCHAIN=auto go build -trimpath -o <tool_root>/bin/numbat ./cmd/numbat

Invocation (``HOME`` is the case home; numbat resolves it with ``os.UserHomeDir``
and has no home or root flag)::

    numbat agents --format json

Output: a JSON array with one row per supported agent that has a local signal,
``{"agent", "present", "detected", "at_rest", "hook", "wired", "setup_hint",
"at_rest_scan_incomplete"}``; ``[]`` and exit 0 on an empty home. ``detected`` is
true when the agent's config directory exists under the home; ``present`` also
covers at-rest transcripts under the agent's session roots and numbat-owned
hook configuration. numbat prints agent display names only, never a path.

Mapping: every ``present`` row becomes ``artifact:<config dir>`` labelled
``agent``, where the config dir is the home-relative directory numbat's
descriptor table (``cmd/numbat/agents.go``, ``agentDescriptors[].configDirRel``)
checks for that agent: Claude Code ``.claude``, Codex ``.codex``, Gemini CLI
``.gemini``, Cursor ``.cursor``, Windsurf ``.windsurf``, GitHub Copilot CLI
``.copilot``, VS Code Copilot Chat ``.copilot/hooks``, OpenCode
``.config/opencode`` and so on (``CONFIG_DIRS``). The directory is numbat's
detection unit, so the key names the directory, not a file inside it; the
regular files directly under that directory are listed in the entity's
``files`` attribute for scorers that match by prefix. A display name missing
from the table is kept in ``raw`` and skipped. ``XDG_CONFIG_HOME`` from
``base_env`` points at ``<home>/.config``, so the ``.config/...`` entries resolve
to the same place numbat looks.

``numbat scan`` and ``numbat timeline`` are not used for inventory: on a home
without session transcripts they print a ``diagnostic`` record ("no agent
artifacts found under <home>") and exit 1.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path

from tools.shadowbench.synthetic.contract import (
    AdapterResult,
    Entity,
    Invocation,
    MaterializedCase,
    RunResult,
    ToolEnv,
    base_env,
    tail,
)

TOOL = "numbat"

# Display name printed by ``numbat agents`` -> home-relative config directories
# numbat tests for that agent (primary first, then alternates).
CONFIG_DIRS: Mapping[str, tuple[str, ...]] = {
    "Claude Code": (".claude",),
    "Claude Cowork": ("Library/Application Support/Claude/local-agent-mode-sessions",),
    "Codex": (".codex",),
    "Gemini CLI": (".gemini",),
    "Cursor": (".cursor",),
    "Windsurf / Devin Desktop": (".windsurf",),
    "GitHub Copilot CLI": (".copilot",),
    "VS Code Copilot Chat": (".copilot/hooks",),
    "OpenCode": (".config/opencode",),
    "OpenClaw": (".openclaw",),
    "Pi": (".pi/agent",),
    "Kimi Code": (".kimi-code",),
    "Qwen Code": (".qwen",),
    "Cline CLI": (".cline",),
    "Amp": (".config/amp",),
    "Auggie": (".augment",),
    "Kiro IDE / CLI v3": (".kiro",),
    "Goose": (".config/goose",),
    "Kilo Code": (".config/kilo",),
    "Crush": (".config/crush",),
    "Junie CLI (EAP)": (".junie",),
    "Antigravity": (".gemini/antigravity-cli", ".gemini/antigravity"),
    "Factory Droid": (".factory",),
    "Grok Build": (".grok",),
    "Devin CLI": (".config/devin",),
    "Hermes": (".hermes",),
}
# OpenHands has no home-level config directory in numbat (project-local hooks only).

_VERSION = re.compile(r"numbat\s+(\S+)")
_MAX_FILES = 16


class NumbatAdapter:
    name = TOOL
    display = "numbat agents (Perplexity)"
    surfaces: Mapping[str, frozenset[str]] = {"endpoint": frozenset({"home"})}

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        return None if env.binary(TOOL) else f"no 'bin' configured for {TOOL}"

    def version(self, env: ToolEnv) -> str:
        binary = env.binary(TOOL)
        if not binary:
            return "unknown"
        try:
            proc = subprocess.run(
                [binary, "--version"], capture_output=True, text=True, timeout=30, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return f"unknown ({exc})"
        match = _VERSION.search(proc.stdout + proc.stderr)
        return match.group(1) if match else (proc.stdout.strip() or "unknown")

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        home = case.home or work
        return [
            Invocation(
                argv=(env.binary(TOOL) or TOOL, "agents", "--format", "json"),
                cwd=work,
                env=base_env(home, work),
                timeout=120,
            )
        ]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="numbat did not run")
        run = runs[0]
        if run.timed_out:
            return AdapterResult(status="error", note="numbat agents timed out")
        if run.code != 0:
            return AdapterResult(status="error", note=f"numbat agents exit {run.code}: {tail(run.stderr)}")
        try:
            data = json.loads(run.stdout or "[]")
        except json.JSONDecodeError as exc:
            return AdapterResult(status="error", note=f"numbat agents output is not JSON: {exc}")
        if not isinstance(data, list):
            return AdapterResult(status="error", note="numbat agents output is not a JSON array")
        home = case.home or work
        entities: dict[str, Entity] = {}
        unmapped: list[str] = []
        for row in data:
            if not isinstance(row, dict) or not row.get("present"):
                continue
            display = str(row.get("agent") or "")
            candidates = CONFIG_DIRS.get(display)
            if not candidates:
                unmapped.append(display)
                continue
            rel = _choose_dir(home, candidates)
            key = f"artifact:{rel}"
            if key in entities:
                continue
            entities[key] = Entity(
                kind="artifact",
                key=key,
                label="agent",
                attributes={
                    "agent": display,
                    "detected": bool(row.get("detected")),
                    "at_rest": str(row.get("at_rest") or ""),
                    "wired": str(row.get("wired") or ""),
                    "files": _files_under(home / rel),
                },
            )
        note = f"unmapped agent names: {', '.join(sorted(set(unmapped)))}" if unmapped else ""
        return AdapterResult(
            status="ok", entities=list(entities.values()), note=note, raw={"agents": data[:200]}
        )


def _choose_dir(home: Path, candidates: tuple[str, ...]) -> str:
    """Pick the alternate that exists under the home (numbat accepts any of them)."""
    for rel in candidates:
        if (home / rel).is_dir():
            return rel
    return candidates[0]


def _files_under(directory: Path) -> list[str]:
    try:
        names = sorted(p.name for p in directory.iterdir() if p.is_file() and not p.is_symlink())
    except OSError:
        return []
    return names[:_MAX_FILES]


ADAPTER = NumbatAdapter()

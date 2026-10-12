"""Endpoint surface: the synthetic home-directory families of ``tools.benchmark``, with entity truth.

The families (and their conflict-of-interest caveat) are the ones the earlier
head-to-head benchmark pre-registered; this module only adds the artifact each
family plants, so tools can be scored on *which* artifact they found rather
than on a per-home verdict. Multi-file clients (Claude Code's ``.claude``
directory, OpenClaw's state directory) are keyed at the directory, so a tool
that cites any file inside it, or the directory itself, is credited.
"""

from __future__ import annotations

import fnmatch

from tools.benchmark import endpoint_cases
from tools.benchmark.common import Draft as BenchDraft
from tools.benchmark.common import Rand
from tools.shadowbench.synthetic.contract import TruthEntity
from tools.shadowbench.synthetic.families import Draft

# family -> (expected artifact globs, tolerated artifact globs, evidence).
# A glob without a wildcard that names a directory is a directory-level entity.
ARTIFACTS: dict[str, tuple[tuple[str, ...], tuple[str, ...], str]] = {
    "ep-claude-desktop-mcp": (
        (".config/Claude/claude_desktop_config.json",),
        (),
        "Claude Desktop mcpServers",
    ),
    "ep-cursor-mcp": ((".cursor/mcp.json",), (), "Cursor user mcpServers"),
    "ep-vscode-mcp": ((".config/Code/User/mcp.json",), (), "VS Code user-profile MCP servers"),
    "ep-windsurf-mcp": ((".codeium/windsurf/mcp_config.json",), (), "Windsurf mcpServers"),
    "ep-claude-code": (
        (".claude.json", ".claude"),
        (".claude/settings.json",),
        "Claude Code user configuration: mcpServers in .claude.json, or a subagent or skill under .claude/",
    ),
    "ep-gemini-cli": ((".gemini/settings.json",), (), "Gemini CLI mcpServers"),
    "ep-codex": ((".codex/config.toml",), (), "Codex mcp_servers tables"),
    "ep-openclaw": ((".openclaw",), (), "OpenClaw agent state directory (config, workspace, skills)"),
    "ep-cline": (
        (".vscode/extensions/saoudrizwan.claude-dev-*/package.json",),
        (
            ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            ".vscode/extensions/saoudrizwan.claude-dev-*",
        ),
        "Cline autonomous coding-agent extension",
    ),
    "ep-continue": ((".continue/config.yaml",), (), "Continue config with an MCP server"),
    "ep-aider": ((".aider.conf.yml",), ("src/*/.aider.chat.history.md",), "Aider configuration"),
    "ep-goose": ((".config/goose/config.yaml",), (), "Goose extensions configuration"),
    "ep-kiro": ((".kiro/settings/mcp.json",), (), "Kiro mcpServers"),
    "ep-amazonq": ((".aws/amazonq/mcp.json",), (), "Amazon Q Developer mcpServers"),
    "ep-copilot-ext": (
        (".vscode/extensions/github.copilot-*/package.json",),
        (
            ".vscode/extensions/github.copilot-chat-*/package.json",
            ".vscode/extensions/github.copilot-*",
            ".vscode/extensions/github.copilot-chat-*",
        ),
        "GitHub Copilot extension manifest",
    ),
    "ep-ollama-models": (
        (".ollama/models/manifests/*/*/*/*",),
        (".ollama", ".ollama/models", ".ollama/models/manifests"),
        "Ollama model store",
    ),
    "ep-lmstudio": (
        (".lmstudio/models/*/*/*.gguf",),
        (".lmstudio", ".lmstudio/models", ".lmstudio/settings.json"),
        "LM Studio GGUF model",
    ),
    "ep-browser-ai-ext": (
        (".config/google-chrome/Default/Extensions/*/*/manifest.json",),
        (".config/google-chrome/Default/Extensions/*",),
        "AI assistant browser extension",
    ),
    "ep-shell-history-ai": ((".zsh_history",), (), "AI CLI invocations in shell history"),
}


def _match(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(path, pat) for pat in patterns)


def _dirs(path: str) -> list[str]:
    parts = path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def truth_for(draft: BenchDraft) -> tuple[list[TruthEntity], list[str]]:
    """Expected and tolerated ``artifact:`` keys for one head-to-head endpoint draft."""
    if draft.label == "none":
        return [], []
    expected_globs, tolerated_globs, evidence = ARTIFACTS[draft.family]
    expected: dict[str, TruthEntity] = {}
    tolerated: set[str] = set()
    attrs = {"family": draft.family}
    for path in sorted(draft.files):
        if _match(path, expected_globs):
            expected[f"artifact:{path}"] = TruthEntity(
                "artifact", f"artifact:{path}", draft.label, attrs, evidence
            )
            tolerated.update(f"artifact:{d}" for d in _dirs(path))
        elif _match(path, tolerated_globs):
            tolerated.add(f"artifact:{path}")
            tolerated.update(f"artifact:{d}" for d in _dirs(path))
    for glob in expected_globs:
        # a directory-level entity: expected when any planted file lives under it
        if "*" not in glob and glob not in draft.files and any(p.startswith(glob + "/") for p in draft.files):
            expected[f"artifact:{glob}"] = TruthEntity(
                "artifact", f"artifact:{glob}", draft.label, attrs, evidence
            )
            tolerated.update(f"artifact:{d}" for d in _dirs(glob))
    if not expected:
        raise ValueError(f"{draft.family}: no expected artifact matched {sorted(draft.files)}")
    tolerated -= set(expected)
    return list(expected.values()), sorted(tolerated)


def endpoint_draft(rd: Rand, label: str) -> Draft:
    pool = {"agent": endpoint_cases.EP_AGENT, "llm": endpoint_cases.EP_LLM, "none": endpoint_cases.EP_NEG}[
        label
    ]
    bench = endpoint_cases.wrap(rd, rd.choice(pool)(rd))
    expected, tolerated = truth_for(bench)
    return Draft(
        bench.family,
        bench.label,
        bench.difficulty,
        bench.rationale,
        files={f"home/{k}": v for k, v in bench.files.items()},
        expected=expected,
        tolerated=tolerated,
    )

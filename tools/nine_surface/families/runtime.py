"""Runtime-surface families: processes on a host, as an osquery snapshot or spawned live.

Rubric. ``agent``: a coding-agent CLI, an MCP server process, an agent
framework run or an agent gateway. ``llm``: a model server, an AI desktop
application or AI editor without agent evidence in its command line. ``none``:
no AI, including infrastructure *agents* (ssh, gpg, Datadog, Jenkins, Puppet,
Elastic), game servers named *bedrock*, Minecraft Coder Pack tooling and
ordinary application processes.

Each process is a record with ``name`` (the executable's comm name), ``path``,
``cmdline`` (argv joined by spaces), ``username`` and ``uid``. A live case
spawns an inert binary under each ``name`` with that argv, so a tool reading
``/proc`` sees the same command lines a snapshot holds.
"""

from __future__ import annotations

from typing import Any

from tools.benchmark.common import OLLAMA_MODELS, OPENAI_MODELS, Rand
from tools.nine_surface.contract import TruthEntity
from tools.nine_surface.families import Draft, person

HOSTS = ("dev-laptop-07", "build-runner-3", "ml-box-12", "ops-bastion-2", "analyst-nb-19")


def proc(rd: Rand, name: str, path: str, argv: list[str], user: str | None = None) -> dict[str, Any]:
    user = user or person(rd)
    uid = 0 if user == "root" else rd.randint(1000, 1010)
    return {
        "name": name,
        "path": path,
        "cmdline": " ".join(argv),
        "argv": argv,
        "username": user,
        "uid": uid,
        "start_time": 1_759_100_000 + rd.randint(0, 40_000),
    }


def _draft(
    rd: Rand, family: str, label: str, difficulty: str, rationale: str, p: dict[str, Any], evidence: str
) -> Draft:
    expected = (
        [TruthEntity("process", "proc:0", label, {"name": p["name"]}, evidence)] if label != "none" else []
    )
    return Draft(family, label, difficulty, rationale, {"processes": [p]}, expected=expected)


def _node_pkg(rd: Rand, user: str, pkg: str, entry: str) -> str:
    root = rd.choice(
        (
            f"/home/{user}/.npm-global/lib/node_modules",
            "/usr/local/lib/node_modules",
            f"/home/{user}/.nvm/versions/node/v22.11.0/lib/node_modules",
        )
    )
    return f"{root}/{pkg}/{entry}"


# --- agents -------------------------------------------------------------------


def rt_claude_code(rd: Rand) -> Draft:
    user = person(rd)
    argv = ["node", _node_pkg(rd, user, "@anthropic-ai/claude-code", "cli.js")]
    if rd.chance(0.4):
        argv.append("--dangerously-skip-permissions")
    if rd.chance(0.3):
        argv += ["-p", "fix the failing test"]
    return _draft(
        rd,
        "rt-claude-code",
        "agent",
        "easy",
        "Claude Code CLI.",
        proc(rd, "node", "/usr/bin/node", argv, user),
        "cmdline runs @anthropic-ai/claude-code/cli.js",
    )


def rt_codex(rd: Rand) -> Draft:
    user = person(rd)
    if rd.chance(0.5):
        p = proc(
            rd,
            "node",
            "/usr/bin/node",
            [
                "node",
                _node_pkg(rd, user, "@openai/codex", "bin/codex.js"),
                rd.choice(("", "exec", "--full-auto")).strip(),
            ],
            user,
        )
        p["cmdline"] = p["cmdline"].strip()
        p["argv"] = [a for a in p["argv"] if a]
        ev = "cmdline runs @openai/codex/bin/codex.js"
    else:
        p = proc(
            rd, "codex", f"/home/{user}/.local/bin/codex", ["codex", "--full-auto", "run the migration"], user
        )
        ev = "codex CLI binary"
    return _draft(rd, "rt-codex", "agent", "easy", "OpenAI Codex CLI.", p, ev)


def rt_gemini_cli(rd: Rand) -> Draft:
    user = person(rd)
    argv = ["node", _node_pkg(rd, user, "@google/gemini-cli", "dist/index.js")] + (
        ["--yolo"] if rd.chance(0.4) else []
    )
    return _draft(
        rd,
        "rt-gemini-cli",
        "agent",
        "easy",
        "Gemini CLI.",
        proc(rd, "node", "/usr/bin/node", argv, user),
        "cmdline runs @google/gemini-cli",
    )


def rt_coding_agent_misc(rd: Rand) -> Draft:
    user = person(rd)
    name, path, argv, ev = rd.choice(
        (
            (
                "python3",
                "/usr/bin/python3",
                [
                    "python3",
                    f"/home/{user}/.local/bin/aider",
                    "--model",
                    rd.choice(("sonnet", "gpt-4o")),
                    "--yes",
                ],
                "aider coding agent",
            ),
            (
                "goose",
                f"/home/{user}/.local/bin/goose",
                ["goose", "session", "--name", "fix-ci"],
                "goose agent session",
            ),
            (
                "opencode",
                f"/home/{user}/.opencode/bin/opencode",
                ["opencode", "run", "add tests"],
                "opencode agent",
            ),
            (
                "node",
                "/usr/bin/node",
                ["node", _node_pkg(rd, user, "@github/copilot", "index.js"), "--allow-all-tools"],
                "GitHub Copilot CLI agent",
            ),
            (
                "cursor-agent",
                f"/home/{user}/.local/bin/cursor-agent",
                ["cursor-agent", "-p", "refactor module"],
                "Cursor background agent CLI",
            ),
            ("amp", f"/home/{user}/.local/bin/amp", ["amp", "--dangerously-allow-all"], "Amp coding agent"),
        )
    )
    return _draft(
        rd, "rt-coding-agent", "agent", "medium", "Coding agent CLI.", proc(rd, name, path, argv, user), ev
    )


def rt_mcp_server(rd: Rand) -> Draft:
    user = person(rd)
    choice = rd.choice(("npx", "node", "uvx", "python", "binary"))
    if choice == "npx":
        p = proc(
            rd,
            "npx",
            "/usr/bin/npx",
            [
                "npx",
                "-y",
                rd.choice(
                    (
                        "@modelcontextprotocol/server-github",
                        "@modelcontextprotocol/server-filesystem",
                        "@playwright/mcp@latest",
                    )
                ),
            ],
            user,
        )
    elif choice == "node":
        pkg = rd.choice(("@modelcontextprotocol/server-github", "@modelcontextprotocol/server-postgres"))
        p = proc(
            rd,
            "node",
            "/usr/bin/node",
            ["node", f"/home/{user}/.npm/_npx/{rd.hexid(12)}/node_modules/{pkg}/dist/index.js"],
            user,
        )
    elif choice == "uvx":
        p = proc(
            rd,
            "uvx",
            f"/home/{user}/.local/bin/uvx",
            ["uvx", rd.choice(("mcp-server-fetch", "mcp-server-sqlite", "mcp-server-git"))],
            user,
        )
    elif choice == "python":
        p = proc(
            rd,
            "python",
            f"/home/{user}/.cache/uv/archive-v0/{rd.hexid(10)}/bin/python",
            ["python", "-m", rd.choice(("mcp_server_fetch", "mcp_server_sqlite", "internal_mcp.server"))],
            user,
        )
    else:
        p = proc(
            rd, "github-mcp-server", "/usr/local/bin/github-mcp-server", ["github-mcp-server", "stdio"], user
        )
    return _draft(
        rd,
        "rt-mcp-server",
        "agent",
        "easy",
        "MCP server process.",
        p,
        f"cmdline {p['cmdline']!r} runs an MCP server",
    )


def rt_agent_framework(rd: Rand) -> Draft:
    user = person(rd)
    name, path, argv, ev = rd.choice(
        (
            ("python", f"/home/{user}/.venv/bin/python", ["python", "-m", "crewai", "run"], "crewai run"),
            ("crewai", f"/home/{user}/.venv/bin/crewai", ["crewai", "run"], "crewai run"),
            (
                "langgraph",
                f"/home/{user}/.venv/bin/langgraph",
                ["langgraph", "dev", "--port", "2024"],
                "langgraph dev server",
            ),
            (
                "python",
                "/srv/agents/.venv/bin/python",
                ["python", "-m", "openai_agents_runner", "--config", "/srv/agents/triage.yaml"],
                "agent runner module",
            ),
            (
                "uvicorn",
                "/srv/agents/.venv/bin/uvicorn",
                ["uvicorn", "agent_api:app", "--host", "0.0.0.0", "--port", "8000"],
                "agent API server",
            ),
        )
    )
    return _draft(
        rd,
        "rt-agent-framework",
        "agent",
        "medium",
        "Agent framework process.",
        proc(rd, name, path, argv, user),
        ev,
    )


def rt_agent_gateway(rd: Rand) -> Draft:
    user = person(rd)
    argv = ["node", _node_pkg(rd, user, "openclaw", "dist/gateway.js"), "--port", "18789"]
    return _draft(
        rd,
        "rt-openclaw-gateway",
        "agent",
        "medium",
        "OpenClaw personal agent gateway.",
        proc(rd, "node", "/usr/bin/node", argv, user),
        "openclaw gateway on port 18789",
    )


# --- LLM use without agent evidence ------------------------------------------


def rt_model_server(rd: Rand) -> Draft:
    name, path, argv, user, ev = rd.choice(
        (
            ("ollama", "/usr/local/bin/ollama", ["/usr/local/bin/ollama", "serve"], "ollama", "ollama serve"),
            (
                "ollama",
                "/usr/local/bin/ollama",
                [
                    "/usr/local/bin/ollama",
                    "runner",
                    "--model",
                    f"/usr/share/ollama/.ollama/models/blobs/sha256-{rd.hexid(16)}",
                    "--port",
                    str(rd.randint(30000, 50000)),
                ],
                "ollama",
                "ollama model runner",
            ),
            (
                "python",
                "/opt/vllm/bin/python",
                [
                    "python",
                    "-m",
                    "vllm.entrypoints.openai.api_server",
                    "--model",
                    "meta-llama/Llama-3.1-8B-Instruct",
                    "--port",
                    "8000",
                ],
                "ci",
                "vLLM OpenAI-compatible server",
            ),
            ("vllm", "/opt/vllm/bin/vllm", ["vllm", "serve", "Qwen/Qwen2.5-7B-Instruct"], "ci", "vllm serve"),
            (
                "llama-server",
                "/opt/llama.cpp/llama-server",
                ["./llama-server", "-m", f"models/{rd.choice(OLLAMA_MODELS)}.gguf", "--port", "8080"],
                person(rd),
                "llama.cpp server",
            ),
            (
                "lms",
                f"/home/{person(rd)}/.lmstudio/bin/lms",
                ["lms", "server", "start", "--port", "1234"],
                person(rd),
                "LM Studio server",
            ),
            (
                "text-generation-launcher",
                "/usr/local/bin/text-generation-launcher",
                ["text-generation-launcher", "--model-id", "mistralai/Mistral-7B-Instruct-v0.3"],
                "ci",
                "TGI launcher",
            ),
        )
    )
    return _draft(
        rd, "rt-model-server", "llm", "easy", "Local model server.", proc(rd, name, path, argv, user), ev
    )


def rt_ai_desktop(rd: Rand) -> Draft:
    user = person(rd)
    name, path, argv, ev = rd.choice(
        (
            (
                "cursor",
                "/opt/cursor/cursor",
                ["/opt/cursor/cursor", "--no-sandbox", f"/home/{user}/src/app"],
                "Cursor AI editor",
            ),
            (
                "windsurf",
                "/opt/windsurf/windsurf",
                ["/opt/windsurf/windsurf", f"/home/{user}/src/app"],
                "Windsurf AI editor",
            ),
            (
                "claude-desktop",
                "/usr/lib/claude-desktop/claude-desktop",
                ["/usr/lib/claude-desktop/claude-desktop"],
                "Claude desktop app",
            ),
            ("lm-studio", "/opt/LM Studio/lm-studio", ["/opt/LM Studio/lm-studio"], "LM Studio app"),
            (
                "open-webui",
                f"/home/{user}/.venv/bin/open-webui",
                ["open-webui", "serve", "--port", "3000"],
                "Open WebUI",
            ),
            ("python", "/opt/jan/python", ["python", "-m", "jan_server"], "Jan desktop backend"),
        )
    )
    return _draft(
        rd,
        "rt-ai-desktop",
        "llm",
        "medium",
        "AI desktop app or editor.",
        proc(rd, name, path, argv, user),
        ev,
    )


def rt_llm_script(rd: Rand) -> Draft:
    user = person(rd)
    argv = ["python", f"/home/{user}/src/{rd.ident()}/summarise.py", "--model", rd.choice(OPENAI_MODELS)]
    return _draft(
        rd,
        "rt-llm-script",
        "llm",
        "hard",
        "Script passing an LLM model name; no agent evidence.",
        proc(rd, "python", f"/home/{user}/.venv/bin/python", argv, user),
        "--model names an LLM",
    )


# --- negatives ----------------------------------------------------------------


def rt_infra_agent(rd: Rand) -> Draft:
    user = person(rd)
    name, path, argv = rd.choice(
        (
            ("ssh-agent", "/usr/bin/ssh-agent", ["ssh-agent", "-s"]),
            (
                "gpg-agent",
                "/usr/bin/gpg-agent",
                ["gpg-agent", "--homedir", f"/home/{user}/.gnupg", "--use-standard-socket", "--daemon"],
            ),
            (
                "agent",
                "/opt/datadog-agent/bin/agent/agent",
                ["/opt/datadog-agent/bin/agent/agent", "run", "-p", "/opt/datadog-agent/run/agent.pid"],
            ),
            (
                "java",
                "/usr/bin/java",
                [
                    "java",
                    "-jar",
                    "/home/jenkins/agent.jar",
                    "-url",
                    "http://jenkins.acme.example:8080/",
                    "-name",
                    "linux-agent-4",
                ],
            ),
            (
                "puppet",
                "/opt/puppetlabs/puppet/bin/ruby",
                ["/opt/puppetlabs/puppet/bin/puppet", "agent", "--no-daemonize"],
            ),
            (
                "elastic-agent",
                "/usr/share/elastic-agent/elastic-agent",
                ["/usr/share/elastic-agent/elastic-agent", "run"],
            ),
            ("amazon-ssm-agent", "/usr/bin/amazon-ssm-agent", ["/usr/bin/amazon-ssm-agent"]),
            (
                "buildkite-agent",
                "/usr/bin/buildkite-agent",
                ["buildkite-agent", "start", "--tags", "queue=default"],
            ),
        )
    )
    return _draft(
        rd,
        "rt-infra-agent",
        "none",
        "hard",
        "Infrastructure agent process.",
        proc(rd, name, path, argv, user),
        "",
    )


def rt_lookalike(rd: Rand) -> Draft:
    user = person(rd)
    name, path, argv = rd.choice(
        (
            ("bedrock_server", "/opt/minecraft/bedrock_server", ["./bedrock_server"]),
            ("java", "/usr/bin/java", ["java", "-jar", f"/home/{user}/mcp-9.42/runtime/bin/mcinjector.jar"]),
            (
                "python",
                f"/home/{user}/.venv/bin/python",
                ["python", "/srv/dispatch/field_agent_sync.py", "--region", "north"],
            ),
            ("node", "/usr/bin/node", ["node", "/srv/agent-portal/server.js", "--port", "3000"]),
            ("gemini", "/usr/local/bin/gemini-exchange-cli", ["gemini", "balances", "--account", "primary"]),
            ("copilot-seat-sync", "/usr/local/bin/copilot-seat-sync", ["copilot-seat-sync", "--org", "acme"]),
        )
    )
    return _draft(
        rd,
        "rt-lookalike",
        "none",
        "hard",
        "Process whose name sounds like AI; command line holds none.",
        proc(rd, name, path, argv, user),
        "",
    )


def rt_ordinary(rd: Rand) -> Draft:
    user = person(rd)
    name, path, argv = rd.choice(
        (
            ("node", "/usr/bin/node", ["node", "/srv/app/server.js"]),
            (
                "python",
                f"/home/{user}/.venv/bin/python",
                ["python", "manage.py", "runserver", "0.0.0.0:8000"],
            ),
            (
                "code",
                "/usr/share/code/code",
                ["/usr/share/code/code", "--type=renderer", "--enable-crash-reporter"],
            ),
            (
                "chrome",
                "/opt/google/chrome/chrome",
                ["/opt/google/chrome/chrome", "--type=renderer", "--lang=en-US"],
            ),
            (
                "postgres",
                "/usr/lib/postgresql/16/bin/postgres",
                ["postgres", "-D", "/var/lib/postgresql/16/main"],
            ),
            ("nginx", "/usr/sbin/nginx", ["nginx:", "worker", "process"]),
            ("dockerd", "/usr/bin/dockerd", ["/usr/bin/dockerd", "-H", "fd://"]),
            ("bash", "/bin/bash", ["-bash"]),
            ("sshd", "/usr/sbin/sshd", ["sshd:", f"{user}@pts/0"]),
        )
    )
    return _draft(
        rd, "rt-ordinary", "none", "easy", "Ordinary process.", proc(rd, name, path, argv, user), ""
    )


RT_AGENT = (
    rt_claude_code,
    rt_codex,
    rt_gemini_cli,
    rt_coding_agent_misc,
    rt_mcp_server,
    rt_agent_framework,
    rt_agent_gateway,
)
RT_LLM = (rt_model_server, rt_ai_desktop, rt_llm_script)
RT_NONE = (rt_infra_agent, rt_lookalike, rt_ordinary)

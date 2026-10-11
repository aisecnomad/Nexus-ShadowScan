"""Tencent AI-Infra-Guard ``scan`` (web fingerprinting of AI services) on network/active.

Build (checkout of github.com/Tencent/AI-Infra-Guard at commit d9f3aa481ba1,
banner version v4.6.5, go.mod ``go 1.23.2``)::

    CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -buildvcs=false \\
        -o <tool_root>/bin/ai-infra-guard ./cmd/cli/main.go

The fingerprint and advisory databases are plain directories the binary reads
at run time from the cwd-relative defaults ``data/fingerprints`` and
``data/vuln``; ``--fps`` and ``--vul`` take absolute paths, so the checkout's
``data/fingerprints``, ``data/vuln`` and ``data/vuln_en`` are copied to
``<tool_root>/share/ai-infra-guard/`` (165 YAML fingerprints + 1 built-in,
2440 advisories). The CLI performs no update check and no download: with the
directories present it runs fully offline (verified under ``unshare -n``).
The scan command has no JSON output flag (``Options.JSON`` is never wired).

Invocation (one ``-t`` per staged service; ``host:port`` targets are tried as
``http://`` then ``https://``; ``-f FILE`` takes one target per line and a bare
CIDR expands to its addresses)::

    ai-infra-guard scan -t <ip>:<port> ... --fps <share>/fingerprints --vul <share>/vuln_en \\
        --lang en --timeout 5 --limit 50 -o <work>/aig.txt

Output: one line per responding target on stdout (the same line is appended
to ``-o``, which opens with O_APPEND, so the adapter uses a fresh file)::

    http://127.0.0.1:18434 [\\x1b[32m200\\x1b[0m]  [] [ollama:0.5.1]
    http://127.0.0.1:18100 [\\x1b[31m404\\x1b[0m]  [] [openai-compatible]  [vllm:0.6.3]
    http://127.0.0.1:18080 [\\x1b[32m200\\x1b[0m]  []

i.e. ``<url> [<status>]  [<title>] [<name>[:<type>][:<version>]]...`` with ANSI
colour codes around the status (the tool ignores NO_COLOR), followed by
advisory text, an "Application Summary" table and a vulnerability table. A
target that answers neither scheme prints nothing. A target with no bracketed
fingerprint is reachable but unidentified and is not reported as an entity.

Mapping: each identified URL maps to ``service:<ip>:<port>`` (host and port
from the URL, 80/443 when absent) with the label of its strongest fingerprint
(``agent`` > ``llm`` > ``ai``) by the fingerprint ``info.name`` the tool prints
(lower-cased; see ``AGENT_PRODUCTS``, ``LLM_PRODUCTS``, ``NOT_AI_PRODUCTS``):

* ``agent``: MCP servers and hubs (any name containing ``mcp``, ``context7``,
  ``dbhub``), agent frameworks and platforms (``dify``, ``flowise``,
  ``langflow``, ``n8n``, ``crewai``, ``autogen-studio``, ``autogpt``,
  ``superagi``, ``devika``, ``suna``, ``langserve``, ``langroid``, ``langchain``,
  ``praisonai``, ``upsonic``, ``agentic-flow``, ``agenticmail``, ``astrbot``,
  ``langbot``, ``fastgpt``, ``maxkb``, ``ragflow``, ``hayhooks``, ``pipecat``,
  ``obot``, ``omnigent``, ``ruflo``, ``ai-agent-config``) and agent gateways
  (``openclaw``, ``clawdbot gateway``, ``junoclaw``, ``hermes``).
* ``llm``: model servers (``ollama``, ``vllm``, ``openai-compatible``, ``sglang``,
  ``lmdeploy``, ``llama-cpp``, ``localai``, ``koboldcpp``, ``huggingface-tgi``,
  ``triton-inference-server``, ``tensorrt-llm``, ``xinference``, ``lightllm``,
  ``aphrodite-engine``, ``fastchat``, ``mlc-llm``, ``tabbyapi``, ``powerinfer``,
  ``petals``, ``deepspeed-mii``, ``nvidia-nim``, ``lm-studio``, ``jan``,
  ``gpt4all``, ``lollms``), LLM chat UIs (``openwebui``, ``lobechat``,
  ``anythingllm``, ``librechat``, ``nextchat``, ``huggingface-chat-ui``,
  ``text-generation-webui``, ``fastchat-webui``, ``h2ogpt``, ``privategpt``,
  ``chuanhugpt``, ``betterchatgpt``, ``sillytavern``, ``ai-chatbot``,
  ``ai-copilot``, ``quivr``, ``qanything``, ``onyx``, ``weknora``) and LLM
  gateways or hosted model APIs (``litellm``, ``portkey-ai-gateway``,
  ``kong-proxy``, ``envoy-ai-gateway``, ``cloudflare-ai-gateway``, ``bifrost``,
  ``new-api``, ``sub2api``, ``9router``, ``omniroute``, ``helicone``,
  ``tensorzero``, ``aws-bedrock``, ``azure-openai``, ``vertex-ai``, ``groq``,
  ``together-ai``, ``fireworks-ai``, ``replicate``, ``databricks-model-serving``,
  ``baseten-truss``, ``bentoml``, ``kubeai``, ``dynamo``).
* skipped (not AI use): general infrastructure the fingerprint pack also
  covers (``clickhouse``, ``emlog``, ``kubepi``, ``nocobase``, ``memos``,
  ``blinko``, ``eclipse theia``, ``hatchet``, ``trigger.dev``, ``jupyter-*``,
  ``jupyterlab``, ``marimo``, ``dask``, ``ray``, ``tensorboard``, ``kubeflow``,
  ``feast``, ``modal``, ``gradio``).
* ``ai``: every other fingerprint (vector databases, MLOps, RAG and training
  tooling such as ``chroma``, ``milvus``, ``qdrant``, ``weaviate``, ``mlflow``,
  ``langfuse``, ``mem0``, ``lightrag``, ``crawl4ai``, ``axolotl``,
  ``llamafactory``, ``comfyui``): AI tooling without an agent or model-serving tier.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from tools.shadowbench.contract import (
    AdapterResult,
    Entity,
    Invocation,
    MaterializedCase,
    RunResult,
    ToolEnv,
    base_env,
    tail,
)

TOOL = "ai-infra-guard"
OUTPUT = "aig.txt"
SHARE = Path("share") / "ai-infra-guard"

AGENT_PRODUCTS = frozenset(
    {
        "mcp sse",
        "mcphub",
        "mcp-atlassian",
        "mcp-documentation-server",
        "mcp-searxng",
        "meta-ads-mcp",
        "n8n-mcp",
        "netlicensing-mcp",
        "notebooklm mcp",
        "context7",
        "dbhub",
        "dify",
        "flowise",
        "langflow",
        "n8n",
        "crewai",
        "autogen-studio",
        "autogpt",
        "superagi",
        "devika",
        "suna",
        "langserve",
        "langroid",
        "langchain",
        "praisonai",
        "upsonic",
        "agentic-flow",
        "agenticmail",
        "astrbot",
        "langbot",
        "fastgpt",
        "maxkb",
        "ragflow",
        "hayhooks",
        "pipecat",
        "obot",
        "omnigent",
        "ruflo",
        "ai-agent-config",
        "openclaw",
        "clawdbot gateway",
        "junoclaw",
        "hermes",
    }
)
LLM_PRODUCTS = frozenset(
    {
        "ollama",
        "vllm",
        "openai-compatible",
        "sglang",
        "lmdeploy",
        "llama-cpp",
        "localai",
        "koboldcpp",
        "huggingface-tgi",
        "triton-inference-server",
        "tensorrt-llm",
        "xinference",
        "lightllm",
        "aphrodite-engine",
        "fastchat",
        "mlc-llm",
        "tabbyapi",
        "powerinfer",
        "petals",
        "deepspeed-mii",
        "nvidia-nim",
        "lm-studio",
        "llmstudio",
        "jan",
        "gpt4all",
        "lollms",
        "openwebui",
        "lobechat",
        "anythingllm",
        "librechat",
        "nextchat",
        "huggingface-chat-ui",
        "text-generation-webui",
        "fastchat-webui",
        "h2ogpt",
        "privategpt",
        "chuanhugpt",
        "betterchatgpt",
        "sillytavern",
        "ai-chatbot",
        "ai-copilot",
        "ai-engine-wordpress",
        "quivr",
        "qanything",
        "onyx",
        "weknora",
        "litellm",
        "portkey-ai-gateway",
        "kong-proxy",
        "envoy-ai-gateway",
        "cloudflare-ai-gateway",
        "bifrost",
        "new-api",
        "sub2api",
        "9router",
        "omniroute",
        "helicone",
        "tensorzero",
        "aws-bedrock",
        "azure-openai",
        "vertex-ai",
        "groq",
        "together-ai",
        "fireworks-ai",
        "replicate",
        "databricks-model-serving",
        "baseten-truss",
        "bentoml",
        "kubeai",
        "dynamo",
        "open-generative-ai",
        "open genai stack",
        "network-ai",
        "salesforce-einstein",
        "qnabot-on-aws",
        "instructlab",
    }
)
NOT_AI_PRODUCTS = frozenset(
    {
        "clickhouse",
        "emlog",
        "kubepi",
        "nocobase",
        "memos",
        "blinko",
        "eclipse theia",
        "hatchet",
        "trigger.dev",
        "jupyter-notebook",
        "jupyter-server",
        "jupyterlab",
        "marimo",
        "dask",
        "ray",
        "tensorboard",
        "kubeflow",
        "feast",
        "modal",
        "gradio",
    }
)

_RANK = {"agent": 2, "llm": 1, "ai": 0}
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_LINE = re.compile(r"^(https?://\S+)\s+\[(\d{3})\]\s*(.*)$")
_BRACKET = re.compile(r"\[([^\[\]]*)\]")
_VERSION_TOKEN = re.compile(r"^\d+(\.\d+)*")
_BANNER_VERSION = re.compile(r"AI Infrastructure Guard System\s+(v\S+)")


def label_for(product: str) -> str | None:
    """Label for one fingerprint name as the tool prints it; ``None`` means not AI."""
    name = product.strip().lower()
    if not name:
        return None
    if name in AGENT_PRODUCTS or "mcp" in name:
        return "agent"
    if name in LLM_PRODUCTS:
        return "llm"
    if name in NOT_AI_PRODUCTS:
        return None
    return "ai"


class AIInfraGuardAdapter:
    name = TOOL
    display = "AI-Infra-Guard scan (Tencent Zhuque Lab)"
    surfaces: Mapping[str, frozenset[str]] = {"network": frozenset({"active"})}

    def _data_dirs(self, env: ToolEnv) -> tuple[Path, Path]:
        cfg = env.tool(TOOL)
        fps = cfg.get("fingerprints")
        vul = cfg.get("vuln")
        share = env.tool_root / SHARE
        return (
            Path(fps) if isinstance(fps, str) and fps else share / "fingerprints",
            Path(vul) if isinstance(vul, str) and vul else share / "vuln_en",
        )

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        if not env.binary(TOOL):
            return f"no 'bin' configured for {TOOL}"
        fps, vul = self._data_dirs(env)
        if not fps.is_dir():
            return f"fingerprint directory missing: {fps}"
        if not vul.is_dir():
            return f"advisory directory missing: {vul}"
        return None

    def version(self, env: ToolEnv) -> str:
        binary = env.binary(TOOL)
        if not binary:
            return "unknown"
        try:
            proc = subprocess.run([binary, "--help"], capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return f"unknown ({exc})"
        match = _BANNER_VERSION.search(_ANSI.sub("", proc.stdout + proc.stderr))
        return match.group(1) if match else "unknown"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        fps, vul = self._data_dirs(env)
        targets: list[str] = []
        for service in case.services:
            ip = str(service.get("ip") or "127.0.0.1")
            port = service.get("port")
            if port is None:
                continue
            targets.extend(("-t", f"{ip}:{port}"))
        argv = (
            env.binary(TOOL) or TOOL,
            "scan",
            *targets,
            "--fps",
            str(fps),
            "--vul",
            str(vul),
            "--lang",
            "en",
            "--timeout",
            "5",
            "--limit",
            "50",
            "-o",
            str(work / OUTPUT),
        )
        return [Invocation(argv=argv, cwd=work, env=base_env(case.home or work, work), timeout=600)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="ai-infra-guard did not run")
        run = runs[0]
        if run.timed_out:
            return AdapterResult(status="error", note="ai-infra-guard scan timed out")
        if run.code != 0:
            return AdapterResult(
                status="error", note=f"ai-infra-guard scan exit {run.code}: {tail(_ANSI.sub('', run.stderr))}"
            )
        text = run.stdout
        if not _LINE.search(_ANSI.sub("", text), re.MULTILINE):
            output = work / OUTPUT
            if output.exists():
                text = output.read_text(encoding="utf-8", errors="replace")
        results = parse_results(text)
        services = {f"{s.get('ip')}:{s.get('port')}" for s in case.services}
        entities: dict[str, Entity] = {}
        for result in results:
            label: str | None = None
            products: list[str] = []
            for fp in result["fingerprints"]:
                products.append(fp["name"])
                this = label_for(fp["name"])
                if this is not None and (label is None or _RANK[this] > _RANK[label]):
                    label = this
            if label is None:
                continue
            key = f"service:{result['host']}:{result['port']}"
            current = entities.get(key)
            if current is not None and _RANK[current.label] >= _RANK[label]:
                continue
            entities[key] = Entity(
                kind="service",
                key=key,
                label=label,
                attributes={
                    "url": result["url"],
                    "status": result["status"],
                    "products": products,
                    "fingerprints": result["fingerprints"],
                    "staged": f"{result['host']}:{result['port']}" in services,
                },
            )
        return AdapterResult(status="ok", entities=list(entities.values()), raw={"results": results[:400]})


def parse_results(text: str) -> list[dict[str, Any]]:
    """Parse the per-target result lines out of the scan's stdout or ``-o`` file."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in _ANSI.sub("", text).splitlines():
        match = _LINE.match(raw_line.strip())
        if not match:
            continue
        url, status, rest = match.group(1), int(match.group(2)), match.group(3)
        groups = _BRACKET.findall(rest)
        title = groups[0] if groups else ""
        fingerprints = [_fingerprint(token) for token in groups[1:] if token.strip()]
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        line_key = f"{url}|{status}|{rest}"
        if line_key in seen:
            continue
        seen.add(line_key)
        out.append(
            {
                "url": url,
                "host": host,
                "port": port,
                "status": status,
                "title": title,
                "fingerprints": fingerprints,
            }
        )
    return out


def _fingerprint(token: str) -> dict[str, str]:
    parts = [p.strip() for p in token.split(":")]
    fp = {"name": parts[0], "type": "", "version": ""}
    for extra in parts[1:]:
        if _VERSION_TOKEN.match(extra) and not fp["version"]:
            fp["version"] = extra
        elif not fp["type"]:
            fp["type"] = extra
    return fp


ADAPTER = AIInfraGuardAdapter()

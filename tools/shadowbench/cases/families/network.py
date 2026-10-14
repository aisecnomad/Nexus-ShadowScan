"""Network surface: passive Zeek logs from the ``tools.benchmark`` flow families, and active services.

Passive cases reuse the pre-registered network families (one workstation's
egress over a window) and render them as Zeek ``conn``, ``ssl``, ``dns`` and
``http`` logs plus the full flow records. The entity is the client address.

Active cases list services the runner serves on loopback inside the tool's
network namespace. The entity is ``service:<ip>:<port>``. ``agent``: MCP
servers, agent gateways and agent platforms. ``llm``: model servers, model
gateways and chat UIs. ``none``: ordinary services, including monitoring-agent
UIs, build servers and a Minecraft *Bedrock* panel.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from tools.benchmark import network_cases
from tools.benchmark.common import Rand
from tools.shadowbench.cases.contract import TruthEntity
from tools.shadowbench.cases.families import Draft

ZEEK_HEADER = (
    "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\t{path}\n"
    "#open\t2026-09-29-08-00-00\n#fields\t{fields}\n#types\t{types}\n"
)
_ID = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p")
_ID_TYPES = ("time", "string", "addr", "port", "addr", "port")
CONN_FIELDS = "\t".join((*_ID, "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state"))
CONN_TYPES = "\t".join((*_ID_TYPES, "enum", "string", "interval", "count", "count", "string"))
SSL_FIELDS = "\t".join(
    (
        *_ID,
        "version",
        "cipher",
        "curve",
        "server_name",
        "resumed",
        "last_alert",
        "next_protocol",
        "established",
        "ssl_history",
    )
)
SSL_TYPES = "\t".join(
    (*_ID_TYPES, "string", "string", "string", "string", "bool", "string", "string", "bool", "string")
)
DNS_FIELDS = "\t".join(
    (
        *_ID,
        "proto",
        "trans_id",
        "query",
        "qclass",
        "qclass_name",
        "qtype",
        "qtype_name",
        "rcode",
        "rcode_name",
        "answers",
        "TTLs",
    )
)
DNS_TYPES = "\t".join(
    (
        *_ID_TYPES,
        "enum",
        "count",
        "string",
        "count",
        "string",
        "count",
        "string",
        "count",
        "string",
        "vector[string]",
        "vector[interval]",
    )
)
HTTP_FIELDS = "\t".join(
    (
        *_ID,
        "trans_depth",
        "method",
        "host",
        "uri",
        "user_agent",
        "request_body_len",
        "response_body_len",
        "status_code",
    )
)
HTTP_TYPES = "\t".join(
    (*_ID_TYPES, "count", "string", "string", "string", "string", "count", "count", "count")
)


def _line(*fields: object) -> str:
    return "\t".join(str(f) for f in fields) + "\n"


def _epoch(ts: str) -> str:
    return f"{datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp():.6f}"


def _is_ip(host: str) -> bool:
    return host.replace(".", "").isdigit()


def zeek_logs(flows: list[dict[str, Any]], rd: Rand) -> dict[str, str]:
    conn = [ZEEK_HEADER.format(path="conn", fields=CONN_FIELDS, types=CONN_TYPES)]
    ssl = [ZEEK_HEADER.format(path="ssl", fields=SSL_FIELDS, types=SSL_TYPES)]
    dns = [ZEEK_HEADER.format(path="dns", fields=DNS_FIELDS, types=DNS_TYPES)]
    http = [ZEEK_HEADER.format(path="http", fields=HTTP_FIELDS, types=HTTP_TYPES)]
    seen_dns: set[str] = set()
    resolver = f"10.{flows[0]['src_ip'].split('.')[1]}.0.2" if flows else "10.0.0.2"
    for f in flows:
        uid = f"C{rd.hexid(16)}"
        ts = _epoch(str(f["ts"]))
        sport = rd.randint(40000, 65000)
        host = str(f["host"])
        https = f["scheme"] == "https"
        dur = f"{int(f['duration_ms']) / 1000:.3f}"
        ident = (ts, uid, f["src_ip"], sport, f["dst_ip"], f["port"])
        conn.append(
            _line(*ident, "tcp", "ssl" if https else "http", dur, f["bytes_out"], f["bytes_in"], "SF")
        )
        if https and not _is_ip(host):
            ssl.append(
                _line(*ident, "TLSv13", "TLS_AES_128_GCM_SHA256", "x25519", host, "F", "-", "h2", "T", "CsiI")
            )
        elif not https:
            http.append(
                _line(
                    *ident,
                    1,
                    f["method"],
                    host,
                    f["path"],
                    f["user_agent"],
                    f["bytes_out"],
                    f["bytes_in"],
                    f["status"],
                )
            )
        if not _is_ip(host) and host not in seen_dns:
            seen_dns.add(host)
            dts = f"{float(ts) - rd.randint(1, 30) / 1000:.6f}"
            dns.append(
                _line(
                    dts,
                    f"C{rd.hexid(16)}",
                    f["src_ip"],
                    rd.randint(40000, 65000),
                    resolver,
                    53,
                    "udp",
                    rd.randint(1000, 60000),
                    host,
                    1,
                    "C_INTERNET",
                    1,
                    "A",
                    0,
                    "NOERROR",
                    f["dst_ip"],
                    f"{rd.randint(30, 3600)}.000000",
                )  # fmt: skip
            )
    return {
        "zeek/conn.log": "".join(conn),
        "zeek/ssl.log": "".join(ssl),
        "zeek/dns.log": "".join(dns),
        "zeek/http.log": "".join(http),
    }


PASSIVE_EVIDENCE = {
    "agent": "programmatic burst of model or MCP calls from one process (agent loop shape)",
    "llm": "AI service contacted without loop or tool evidence",
}


def passive_draft(rd: Rand, label: str) -> Draft:
    pool = {"agent": network_cases.NET_AGENT, "llm": network_cases.NET_LLM, "none": network_cases.NET_NEG}[
        label
    ]
    bench = rd.choice(pool)(rd)
    flows = bench.flows
    files = zeek_logs(flows, rd)
    files["flows.json"] = json.dumps(flows, indent=1) + "\n"
    expected = (
        [
            TruthEntity(
                "client",
                f"client:{flows[0]['src_ip']}",
                bench.label,
                {"family": bench.family},
                PASSIVE_EVIDENCE[bench.label],
            )
        ]
        if bench.label != "none"
        else []
    )
    return Draft(bench.family, bench.label, bench.difficulty, bench.rationale, files=files, expected=expected)


# --- active services -----------------------------------------------------------

# product -> (label, evidence). Routes are rendered by tools/shadowbench/cases/mockserv.py.
SERVICE_PRODUCTS: dict[str, tuple[str, str]] = {
    "ollama": ("llm", "Ollama API: GET /api/tags and /api/version answer; root says 'Ollama is running'"),
    "vllm": ("llm", "vLLM OpenAI-compatible API: /v1/models lists a model, /version answers"),
    "open-webui": ("llm", "Open WebUI: /api/config names the product"),
    "litellm": ("llm", "LiteLLM proxy: /health/liveliness and /v1/models"),
    "tgi": ("llm", "Text Generation Inference: /info returns model_id"),
    "lmstudio": ("llm", "LM Studio server: /v1/models and /api/v0/models"),
    "mcp-streamable": ("agent", "MCP server over streamable HTTP: POST /mcp initialize returns serverInfo"),
    "mcp-sse": ("agent", "MCP server over SSE: GET /sse opens an event stream with an endpoint event"),
    "openclaw-gateway": ("agent", "OpenClaw gateway on 18789: root and /health name the gateway"),
    "langflow": ("agent", "Langflow: /api/v1/version and HTML title"),
    "flowise": ("agent", "Flowise: /api/v1/ping and HTML title"),
    "nginx-default": ("none", ""),
    "grafana": ("none", ""),
    "jenkins": ("none", ""),
    "datadog-agent-gui": ("none", ""),
    "minecraft-bedrock-panel": ("none", ""),
    "agent-portal-web": ("none", ""),
    "jupyter": ("none", ""),
}
AGENT_SERVICES = ("mcp-streamable", "mcp-sse", "openclaw-gateway", "langflow", "flowise")
LLM_SERVICES = ("ollama", "vllm", "open-webui", "litellm", "tgi", "lmstudio")
NONE_SERVICES = (
    "nginx-default",
    "grafana",
    "jenkins",
    "datadog-agent-gui",
    "minecraft-bedrock-panel",
    "agent-portal-web",
    "jupyter",
)
DEFAULT_PORTS = {
    "ollama": 11434, "vllm": 8000, "open-webui": 8080, "litellm": 4000, "tgi": 8081, "lmstudio": 1234,
    "mcp-streamable": 8931, "mcp-sse": 3001, "openclaw-gateway": 18789, "langflow": 7860, "flowise": 3000,
    "nginx-default": 8088, "grafana": 3030, "jenkins": 8082, "datadog-agent-gui": 5002,
    "minecraft-bedrock-panel": 8181, "agent-portal-web": 3100, "jupyter": 8888,
}  # fmt: skip


def active_draft(rd: Rand, label: str) -> Draft:
    """One service of the requested label. Cases compose several drafts on distinct ports."""
    product = str(rd.choice({"agent": AGENT_SERVICES, "llm": LLM_SERVICES, "none": NONE_SERVICES}[label]))
    port = DEFAULT_PORTS[product] if rd.chance(0.7) else rd.randint(20000, 29999)
    svc = {"ip": "127.0.0.1", "port": port, "product": product}
    lab, evidence = SERVICE_PRODUCTS[product]
    expected = (
        [TruthEntity("service", f"service:127.0.0.1:{port}", lab, {"product": product}, evidence)]
        if lab != "none"
        else []
    )
    difficulty = (
        "easy"
        if lab != "none"
        else (
            "hard"
            if product in ("datadog-agent-gui", "minecraft-bedrock-panel", "agent-portal-web")
            else "easy"
        )
    )
    return Draft(
        f"svc-{product}",
        lab,
        difficulty,
        f"Service {product} on 127.0.0.1:{port}.",
        services=[svc],
        expected=expected,
    )

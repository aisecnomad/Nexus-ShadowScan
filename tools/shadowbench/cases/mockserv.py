"""Loopback HTTP services for ``network/active`` cases.

Each product answers the routes a fingerprinting scanner probes, modelled on
the real software's responses (banners, version endpoints, product names), so
an active scanner can be scored on what it identifies. Nothing here contacts
the outside; the runner starts these inside the tool's network namespace, and
a service is only ever bound to ``127.0.0.1`` on a valid port, whatever the
case says, so a mistaken or altered corpus cannot expose one beyond loopback.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

Response = tuple[int, dict[str, str], bytes]
Router = Callable[[str, str, bytes], Response]


def _json(status: int, body: Any, **headers: str) -> Response:
    return status, {"Content-Type": "application/json", **headers}, json.dumps(body).encode()


def _html(status: int, title: str, body: str = "", **headers: str) -> Response:
    text = f"<!DOCTYPE html><html><head><title>{title}</title></head><body>{body}</body></html>"
    return status, {"Content-Type": "text/html; charset=utf-8", **headers}, text.encode()


def _text(status: int, body: str, **headers: str) -> Response:
    return status, {"Content-Type": "text/plain; charset=utf-8", **headers}, body.encode()


def _not_found(server: str = "") -> Response:
    headers = {"Server": server} if server else {}
    return _json(404, {"detail": "Not Found"}, **headers)


def ollama(method: str, path: str, body: bytes) -> Response:
    if path == "/":
        return _text(200, "Ollama is running")
    if path == "/api/version":
        return _json(200, {"version": "0.12.3"})
    if path == "/api/tags":
        return _json(
            200,
            {
                "models": [
                    {
                        "name": "llama3.1:latest",
                        "model": "llama3.1:latest",
                        "modified_at": "2026-08-12T09:10:11.000000000Z",
                        "size": 4661224676,
                        "digest": "46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e",
                        "details": {
                            "format": "gguf",
                            "family": "llama",
                            "parameter_size": "8.0B",
                            "quantization_level": "Q4_K_M",
                        },
                    }
                ]
            },
        )
    if path == "/api/ps":
        return _json(200, {"models": []})
    if path == "/v1/models":
        return _json(
            200,
            {"object": "list", "data": [{"id": "llama3.1:latest", "object": "model", "owned_by": "library"}]},
        )
    return _text(404, "404 page not found")


def vllm(method: str, path: str, body: bytes) -> Response:
    if path == "/v1/models":
        return _json(
            200,
            {
                "object": "list",
                "data": [
                    {
                        "id": "meta-llama/Llama-3.1-8B-Instruct",
                        "object": "model",
                        "created": 1757000000,
                        "owned_by": "vllm",
                        "root": "meta-llama/Llama-3.1-8B-Instruct",
                        "parent": None,
                        "max_model_len": 131072,
                        "permission": [],
                    }
                ],
            },
        )
    if path == "/version":
        return _json(200, {"version": "0.10.1"})
    if path == "/health":
        return 200, {"Content-Type": "application/json"}, b""
    if path in ("/docs", "/openapi.json"):
        return _html(200, "vLLM - Swagger UI", "<div id='swagger-ui'></div>")
    return _json(404, {"detail": "Not Found"})


def open_webui(method: str, path: str, body: bytes) -> Response:
    if path == "/api/config":
        return _json(
            200,
            {
                "status": True,
                "name": "Open WebUI",
                "version": "0.6.26",
                "default_locale": "en-US",
                "oauth": {"providers": {}},
                "features": {"auth": True, "enable_signup": False},
            },
        )
    if path == "/api/version":
        return _json(200, {"version": "0.6.26"})
    if path == "/health":
        return _json(200, {"status": True})
    if path.startswith("/api/"):
        return _json(401, {"detail": "Not authenticated"})
    return _html(
        200,
        "Open WebUI",
        "<div id='app'></div><script type='module' src='/_app/immutable/entry/start.js'></script>",
    )


def litellm(method: str, path: str, body: bytes) -> Response:
    if path == "/health/liveliness":
        return _json(200, "I'm alive!")
    if path == "/health/readiness":
        return _json(
            200,
            {
                "status": "connected",
                "db": "connected",
                "cache": None,
                "litellm_version": "1.77.3",
                "success_callbacks": [],
            },
        )
    if path in ("/v1/models", "/models"):
        return _json(
            200,
            {
                "data": [{"id": "gpt-4o", "object": "model", "created": 1677610602, "owned_by": "openai"}],
                "object": "list",
            },
        )
    if path == "/":
        return 307, {"Location": "/ui/"}, b""
    if path.startswith("/ui"):
        return _html(200, "LiteLLM Dashboard", "<div id='__next'></div>")
    return _json(
        401,
        {
            "error": {
                "message": "Authentication Error, No api key passed in.",
                "type": "auth_error",
                "code": "401",
            }
        },
    )


def tgi(method: str, path: str, body: bytes) -> Response:
    if path == "/info":
        return _json(
            200,
            {
                "model_id": "mistralai/Mistral-7B-Instruct-v0.3",
                "model_dtype": "torch.bfloat16",
                "model_device_type": "cuda",
                "max_input_tokens": 4095,
                "version": "3.3.4",
                "sha": "a1b2c3d",
                "docker_label": "sha-a1b2c3d",
            },
        )
    if path == "/health":
        return 200, {}, b""
    if path == "/v1/models":
        return _json(
            200,
            {
                "object": "list",
                "data": [
                    {"id": "tgi", "object": "model", "created": 0, "owned_by": "text-generation-inference"}
                ],
            },
        )
    return _json(404, {"error": "Not Found"})


def lmstudio(method: str, path: str, body: bytes) -> Response:
    if path == "/v1/models":
        return _json(
            200,
            {
                "data": [{"id": "qwen2.5-7b-instruct", "object": "model", "owned_by": "organization_owner"}],
                "object": "list",
            },
        )
    if path == "/api/v0/models":
        return _json(
            200,
            {
                "object": "list",
                "data": [
                    {
                        "id": "qwen2.5-7b-instruct",
                        "object": "model",
                        "type": "llm",
                        "publisher": "lmstudio-community",
                        "arch": "qwen2",
                        "compatibility_type": "gguf",
                        "quantization": "Q4_K_M",
                        "state": "loaded",
                        "max_context_length": 32768,
                    }
                ],
            },
        )
    return _text(404, "Unexpected endpoint or method. (GET " + path + ")")


def mcp_streamable(method: str, path: str, body: bytes) -> Response:
    if path.rstrip("/") not in ("/mcp", ""):
        return _json(404, {"error": "not found"})
    if method == "GET":
        return 405, {"Allow": "POST"}, b"Method Not Allowed"
    try:
        req = json.loads(body or b"{}")
    except ValueError:
        return _json(400, {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None})
    rid = req.get("id") if isinstance(req, dict) else None
    meth = req.get("method") if isinstance(req, dict) else None
    if meth == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": False}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "github-mcp-server", "version": "0.4.0"},
        }
        return _json(
            200, {"jsonrpc": "2.0", "id": rid, "result": result}, **{"Mcp-Session-Id": "s-bench-0001"}
        )
    if meth == "tools/list":
        tools = [
            {
                "name": "get_issue",
                "description": "Get details of a specific issue in a GitHub repository.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "issue_number": {"type": "number"},
                    },
                },
            },
            {
                "name": "create_pull_request",
                "description": "Create a new pull request.",
                "inputSchema": {"type": "object"},
            },
        ]
        return _json(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}})
    if meth in ("resources/list", "prompts/list"):
        return _json(200, {"jsonrpc": "2.0", "id": rid, "result": {meth.split("/")[0]: []}})
    if meth == "notifications/initialized":
        return 202, {}, b""
    return _json(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}})


def mcp_sse(method: str, path: str, body: bytes) -> Response:
    if path.startswith("/sse"):
        payload = "event: endpoint\ndata: /messages?sessionId=bench-0001\n\n"
        return 200, {"Content-Type": "text/event-stream", "Cache-Control": "no-cache"}, payload.encode()
    if path.startswith("/messages"):
        return 202, {}, b"Accepted"
    return _json(404, {"error": "not found"})


def openclaw_gateway(method: str, path: str, body: bytes) -> Response:
    if path == "/health":
        return _json(200, {"status": "ok", "service": "openclaw-gateway", "version": "2026.9.1", "agents": 1})
    if path == "/":
        return _html(200, "OpenClaw Gateway", "<h1>OpenClaw Gateway</h1><p>Connect your channels.</p>")
    return _html(404, "OpenClaw Gateway", "<h1>Not found</h1>")


def langflow(method: str, path: str, body: bytes) -> Response:
    if path == "/api/v1/version":
        return _json(200, {"version": "1.5.0", "main_version": "1.5.0", "package": "Langflow"})
    if path == "/health":
        return _json(200, {"status": "ok"})
    if path == "/":
        return _html(200, "Langflow", "<div id='root'></div>")
    return _json(404, {"detail": "Not Found"})


def flowise(method: str, path: str, body: bytes) -> Response:
    if path == "/api/v1/ping":
        return _text(200, "pong")
    if path == "/api/v1/version":
        return _json(200, {"version": "3.0.1"})
    if path.startswith("/api/"):
        return _json(404, {"message": "Not Found"})
    return _html(200, "Flowise - Low-code LLM apps builder", "<div id='root'></div>")


def nginx_default(method: str, path: str, body: bytes) -> Response:
    if path == "/":
        return _html(200, "Welcome to nginx!", "<h1>Welcome to nginx!</h1>", Server="nginx/1.27.0")
    return _html(
        404,
        "404 Not Found",
        "<center><h1>404 Not Found</h1></center><hr><center>nginx/1.27.0</center>",
        Server="nginx/1.27.0",
    )


def grafana(method: str, path: str, body: bytes) -> Response:
    if path == "/":
        return 302, {"Location": "/login"}, b""
    if path == "/api/health":
        return _json(200, {"commit": "0a4b8c2", "database": "ok", "version": "11.2.0"})
    if path.startswith("/api/"):
        return _json(401, {"message": "Unauthorized"})
    # the SPA serves its index for every other route
    return _html(200, "Grafana", "<grafana-app></grafana-app>")


def jenkins(method: str, path: str, body: bytes) -> Response:
    headers = {"X-Jenkins": "2.462.3", "X-Hudson": "1.395"}
    if path == "/login":
        return _html(200, "Sign in [Jenkins]", "<form name='login'></form>", **headers)
    return _html(403, "Jenkins", "Authentication required", **headers)


def datadog_agent_gui(method: str, path: str, body: bytes) -> Response:
    if path == "/":
        return _html(200, "Datadog Agent Manager", "<h1>Datadog Agent Manager</h1><p>Agent 7.58.0</p>")
    if path.startswith("/agent/"):
        return _json(401, {"error": "invalid session"})
    return _html(404, "Not Found")


def minecraft_bedrock_panel(method: str, path: str, body: bytes) -> Response:
    if path == "/":
        return _html(
            200,
            "Bedrock Server Manager",
            "<h1>Minecraft Bedrock Dedicated Server 1.21.44</h1><p>Players online: 2</p>",
        )
    if path == "/api/status":
        return _json(
            200,
            {"online": True, "players": 2, "max_players": 10, "version": "1.21.44", "level": "bedrock_level"},
        )
    return _html(404, "Not Found", "<h1>Not Found</h1><p>The requested URL was not found on the server.</p>")


def agent_portal_web(method: str, path: str, body: bytes) -> Response:
    if path == "/":
        return _html(
            200,
            "Agent Portal",
            "<h1>Agent Portal</h1><p>Commission dashboard for licensed real-estate agents.</p>",
        )
    if path == "/api/agents":
        return _json(
            200, [{"agent_id": "A-104", "name": "Jo Park"}, {"agent_id": "A-221", "name": "Sam Ruiz"}]
        )
    return _html(404, "Error", "<pre>Cannot GET " + path + "</pre>")


def jupyter(method: str, path: str, body: bytes) -> Response:
    if path == "/":
        return 302, {"Location": "/login?next=%2Ftree"}, b""
    if path.startswith("/login"):
        return _html(200, "Jupyter Server", "<div id='jupyter-main-app'></div>")
    if path == "/api":
        return _json(200, {"version": "2.14.2"})
    if path.startswith("/api/"):
        return _json(403, {"message": "Forbidden", "reason": None})
    return _html(
        404, "Jupyter Server", "<h1>404 : Not Found</h1><p>You are requesting a page that does not exist!</p>"
    )


PRODUCTS: dict[str, Router] = {
    "ollama": ollama,
    "vllm": vllm,
    "open-webui": open_webui,
    "litellm": litellm,
    "tgi": tgi,
    "lmstudio": lmstudio,
    "mcp-streamable": mcp_streamable,
    "mcp-sse": mcp_sse,
    "openclaw-gateway": openclaw_gateway,
    "langflow": langflow,
    "flowise": flowise,
    "nginx-default": nginx_default,
    "grafana": grafana,
    "jenkins": jenkins,
    "datadog-agent-gui": datadog_agent_gui,
    "minecraft-bedrock-panel": minecraft_bedrock_panel,
    "agent-portal-web": agent_portal_web,
    "jupyter": jupyter,
}


def _handler(router: Router, server_header: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = server_header
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            status, headers, payload = router(self.command, self.path, body)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = _serve

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return Handler


SERVER_HEADERS = {
    "nginx-default": "nginx/1.27.0",
    "jenkins": "Jetty(10.0.20)",
    "vllm": "uvicorn",
    "open-webui": "uvicorn",
    "litellm": "uvicorn",
    "langflow": "uvicorn",
    "jupyter": "TornadoServer/6.4.1",
    "grafana": "",
}


LOOPBACK = "127.0.0.1"


def checked_service(spec: dict[str, Any]) -> tuple[str, int, str]:
    """``(ip, port, product)`` of a service spec; only a known product on loopback is ever served."""
    product, ip, port = spec.get("product"), spec.get("ip"), spec.get("port")
    if not isinstance(product, str) or product not in PRODUCTS:
        raise ValueError(f"unknown mock service product {product!r}")
    if ip != LOOPBACK:
        raise ValueError(f"mock service {product} must listen on {LOOPBACK}, not {ip!r}")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError(f"mock service {product} has an invalid port {port!r}")
    return ip, port, product


class Services:
    """Start and stop the mock services of one case."""

    def __init__(self, services: list[dict[str, Any]]) -> None:
        self.specs = services
        self.servers: list[ThreadingHTTPServer] = []
        self.threads: list[threading.Thread] = []

    def start(self, timeout: float = 10.0) -> None:
        # Validate every spec before binding anything, so a bad one never leaves a partial set listening.
        checked = [checked_service(spec) for spec in self.specs]
        for ip, port, product in checked:
            handler = _handler(PRODUCTS[product], SERVER_HEADERS.get(product, "Werkzeug/3.0.3 Python/3.12"))
            server = ThreadingHTTPServer((ip, port), handler)
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
            thread.start()
            self.servers.append(server)
            self.threads.append(thread)
        deadline = time.monotonic() + timeout
        for ip, port, product in checked:
            while True:
                try:
                    with socket.create_connection((ip, port), timeout=0.5):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError(f"service {product} on {port} did not come up") from None
                    time.sleep(0.05)

    def stop(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()

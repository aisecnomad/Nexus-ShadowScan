"""Serve mock local AI services, run one command, then shut down.

Standalone script (stdlib only, no package imports) so the benchmark runner
can execute it from any working directory. The mock responses mirror the
estate's runtime entities: an Ollama daemon and a vLLM OpenAI-compatible
server, with bodies shaped to the services' real HTTP surfaces. Only
loopback is ever bound; nothing leaves the machine.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def _ollama_routes(service: dict[str, Any]) -> dict[str, tuple[str, str, dict[str, str]]]:
    version = str(service.get("version", "0.3.9"))
    models = service.get("models") or ["qwen2.5-coder:7b"]
    tags = json.dumps({"models": [{"name": str(m), "model": str(m)} for m in models]})
    return {
        "/": ("Ollama is running", "text/plain", {}),
        "/api/version": (f'{{"version":"{version}"}}', "application/json", {}),
        "/api/tags": (tags, "application/json", {}),
    }


def _vllm_routes(service: dict[str, Any]) -> dict[str, tuple[str, str, dict[str, str]]]:
    version = str(service.get("version", "0.6.3"))
    model = str(service.get("model", "qwen2.5-7b"))
    models = json.dumps({"object": "list", "data": [{"id": model, "object": "model"}]})
    headers = {"Server": "uvicorn"}
    return {
        "/version": (f'{{"version":"{version}"}}', "application/json", headers),
        "/v1/models": (models, "application/json", headers),
    }


_KINDS = {"ollama": _ollama_routes, "vllm": _vllm_routes}


def _make_handler(routes: dict[str, tuple[str, str, dict[str, str]]]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            route = routes.get(self.path.split("?", 1)[0])
            if route is None:
                self.send_response(404)
                self.end_headers()
                return
            body, content_type, headers = route
            payload = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--services", required=True, help="services.json path")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- command to run")
    args = parser.parse_args(argv)
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("no command given", file=sys.stderr)
        return 2
    with open(args.services, encoding="utf-8") as handle:
        services = json.load(handle).get("services", [])
    servers: list[ThreadingHTTPServer] = []
    for service in services:
        kind = str(service.get("kind", ""))
        builder = _KINDS.get(kind)
        if builder is None:
            print(f"unknown service kind {kind!r}", file=sys.stderr)
            return 2
        handler = _make_handler(builder(service))
        server = ThreadingHTTPServer(("127.0.0.1", int(service["port"])), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    try:
        completed = subprocess.run(command, check=False)
        return completed.returncode
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())

"""Serve mock local AI services, run one command, then shut down.

Standalone script (stdlib only, no package imports) so the benchmark runner
can execute it from any working directory. The mock responses mirror the
estate's runtime entities: an Ollama daemon and a vLLM OpenAI-compatible
server, with bodies shaped to the services' real HTTP surfaces. Only
loopback is ever bound; nothing leaves the machine.

The services' ports come from services.json (Ollama's 11434 and vLLM's 8000).
On a host that already runs one of those servers, `--port-offset N` moves
every mock service by N ports; the scanner's targets must move with it.
Every port is bound before the command starts, and a busy port stops the run
with a message naming it instead of letting the scanner probe the real server.
"""

from __future__ import annotations

import argparse
import errno
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

LOOPBACK = "127.0.0.1"
#: Exit status for a setup failure (bad services file, busy port): the command never ran.
EXIT_SETUP = 2


class SimhostError(Exception):
    """A setup failure reported to the caller instead of a traceback."""


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


def load_services(path: str, port_offset: int = 0) -> list[tuple[str, int, dict[str, Any]]]:
    """(kind, port, service) for every service in services.json, ports already offset."""
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        raise SimhostError(f"cannot read services file {path}: {exc}") from None
    services = payload.get("services") if isinstance(payload, dict) else None
    if not isinstance(services, list):
        raise SimhostError(f"{path}: 'services' must be a list")
    planned: list[tuple[str, int, dict[str, Any]]] = []
    taken: dict[int, str] = {}
    for service in services:
        if not isinstance(service, dict):
            raise SimhostError(f"{path}: every service must be an object")
        kind = str(service.get("kind", ""))
        if kind not in _KINDS:
            raise SimhostError(f"unknown service kind {kind!r}")
        port = service.get("port")
        if isinstance(port, bool) or not isinstance(port, int):
            raise SimhostError(f"the {kind} service needs an integer port")
        port += port_offset
        if not 1 <= port <= 65535:
            raise SimhostError(f"the {kind} service's port {port} is outside 1-65535 (check --port-offset)")
        if port in taken:
            raise SimhostError(f"the {taken[port]} and {kind} services both use port {port}")
        taken[port] = kind
        planned.append((kind, port, service))
    return planned


def bind(kind: str, port: int, handler: type[BaseHTTPRequestHandler]) -> ThreadingHTTPServer:
    """Bind one mock service to loopback, explaining a busy port."""
    try:
        return ThreadingHTTPServer((LOOPBACK, port), handler)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            raise SimhostError(
                f"{LOOPBACK}:{port} is already in use, so the mock {kind} service cannot start; "
                f"a real {kind} server is probably running on this host. Stop it, or rerun with "
                "--port-offset N to move every mock service (the scanner targets must move too)."
            ) from None
        raise SimhostError(f"cannot bind {LOOPBACK}:{port} for the mock {kind} service: {exc}") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--services", required=True, help="services.json path")
    parser.add_argument(
        "--port-offset",
        type=int,
        default=0,
        help="add N to every service port, for hosts where the real ports are taken",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- command to run")
    args = parser.parse_args(argv)
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("no command given", file=sys.stderr)
        return EXIT_SETUP
    servers: list[ThreadingHTTPServer] = []
    try:
        for kind, port, service in load_services(args.services, args.port_offset):
            servers.append(bind(kind, port, _make_handler(_KINDS[kind](service))))
    except SimhostError as exc:
        for server in servers:
            server.server_close()
        print(f"simhost: {exc}", file=sys.stderr)
        return EXIT_SETUP
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        completed = subprocess.run(command, check=False)
        return completed.returncode
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())

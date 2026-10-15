"""BBOT (Black Lantern Security) ``scan`` on network/active.

Build (checkout of github.com/blacklanternsecurity/bbot at a tagged release,
Python 3.10+; installed into a venv with ``pip install bbot``)::

    pip install --prefix <tool_root>/venv bbot

or a standalone install that places the ``bbot`` console script under
``<tool_root>/bin/bbot``.

Invocation (targets are the staged ``ip:port`` services; ``httpx`` is the
built-in module that performs HTTP fingerprinting on open ports;
``--json`` writes NDJSON to the output file)::

    bbot scan -t <ip>:<port> ... -m httpx -o <work>/bbot.json --json

Output: newline-delimited JSON, one object per event.  Each event has at
minimum ``{"type", "data", "module", "source", "tags"}``.  Events of type
``OPEN_TCP_PORT`` carry ``data`` as ``<ip>:<port>``.  Events of type
``HTTP_RESPONSE`` carry ``data`` as an object with ``host``, ``port``,
``status_code``, ``title``, ``header``, ``url`` and ``body`` fields.  Other
event types (``DNS_NAME``, ``TECHNOLOGY``, ``FINDING``, ``VULNERABILITY``)
are kept in raw but do not map to entities directly.

Fail closed: every staged service is an HTTP server that answers, so a
working scan produces at least one ``OPEN_TCP_PORT`` or ``HTTP_RESPONSE``
event per staged ``ip:port``.  A run with no output file, an empty output,
or missing events for staged targets is an error that names the missing
targets: an unanswered decoy is never credited as a clean negative.
``version()`` runs ``bbot --version`` through ``_probe`` (scrubbed
environment, throwaway home, timeout).

Mapping: each ``HTTP_RESPONSE`` event whose host and port match a staged
service maps to ``service:<ip>:<port>`` with label ``ai`` (BBOT does HTTP
fingerprinting but does not classify AI vs non-AI services; the presence
of an HTTP response on a staged AI-service port counts as a detection).
``OPEN_TCP_PORT`` events for staged targets that have no ``HTTP_RESPONSE``
also map to ``service:<ip>:<port>`` with label ``ai``.  The adapter does
not attempt to distinguish ``agent`` from ``llm`` (both are reported as
``ai``).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.shadowbench.cases.adapters._probe import cli_version
from tools.shadowbench.cases.contract import (
    AdapterResult,
    Entity,
    Invocation,
    MaterializedCase,
    RunResult,
    ToolEnv,
    base_env,
    tail,
)

TOOL = "bbot"
OUTPUT = "bbot.json"


class BBotAdapter:
    name = TOOL
    display = "BBOT network reconnaissance (Black Lantern Security)"
    surfaces: Mapping[str, frozenset[str]] = {"network": frozenset({"active"})}

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        return None if env.binary(TOOL) else f"no 'bin' configured for {TOOL}"

    def version(self, env: ToolEnv) -> str:
        binary = env.binary(TOOL)
        return cli_version(binary) if binary else "unknown"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        targets = staged_targets(case)
        if not targets:
            return []
        target_args = [part for target in targets for part in ("-t", target)]
        argv = (
            env.binary(TOOL) or TOOL,
            "scan",
            *target_args,
            "-m",
            "httpx",
            "-o",
            str(work / OUTPUT),
            "--json",
        )
        return [Invocation(argv=argv, cwd=work, env=base_env(case.home or work, work), timeout=600)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="bbot did not run")
        run = runs[0]
        if run.timed_out:
            return AdapterResult(status="error", note="bbot scan timed out")
        if run.code != 0:
            return AdapterResult(
                status="error", note=f"bbot scan exit {run.code}: {tail(run.stderr)}"
            )
        output = work / OUTPUT
        events = _parse_events(output, run.stdout)
        if not events:
            note = f"no events in bbot output: {tail(run.stderr or run.stdout)}"
            return AdapterResult(status="error", note=note)
        services = set(staged_targets(case))
        seen: set[str] = set()
        entities: dict[str, Entity] = {}
        for event in events:
            host_port = _event_host_port(event)
            if host_port is None or host_port not in services:
                continue
            seen.add(host_port)
            key = f"service:{host_port}"
            event_type = str(event.get("type") or "")
            # HTTP_RESPONSE is stronger evidence than OPEN_TCP_PORT.
            if key in entities and event_type != "HTTP_RESPONSE":
                continue
            entities[key] = Entity(
                kind="service",
                key=key,
                label="ai",
                attributes={
                    "event_type": event_type,
                    "module": str(event.get("module") or ""),
                    "tags": event.get("tags") or [],
                    "staged": True,
                },
            )
        missing = sorted(services - seen)
        if missing:
            note = f"no event for staged target(s) {', '.join(missing)}: the scan is partial"
            raw = {"events": events[:400], "missing": missing}
            return AdapterResult(status="error", note=note, raw=raw)
        return AdapterResult(status="ok", entities=list(entities.values()), raw={"events": events[:400]})


def staged_targets(case: MaterializedCase) -> list[str]:
    """The ``ip:port`` of every staged service, as the scan is given them with ``-t``."""
    targets: list[str] = []
    for service in case.services:
        port = service.get("port")
        if port is not None:
            targets.append(f"{service.get('ip') or '127.0.0.1'}:{port}")
    return targets


def _parse_events(output: Path, stdout: str) -> list[dict[str, Any]]:
    """Parse NDJSON events from the output file and stdout, de-duplicated."""
    lines: list[str] = []
    if output.is_file():
        try:
            lines.extend(output.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            pass
    lines.extend(stdout.splitlines())
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        event_type = obj.get("type")
        if not isinstance(event_type, str):
            continue
        # De-duplicate by type + data string representation.
        dedup_key = f"{event_type}|{json.dumps(obj.get('data'), sort_keys=True, default=str)}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        events.append(obj)
    return events


def _event_host_port(event: dict[str, Any]) -> str | None:
    """Extract ``ip:port`` from an event, or None if not applicable."""
    event_type = str(event.get("type") or "")
    data = event.get("data")
    if event_type == "OPEN_TCP_PORT" and isinstance(data, str):
        # data is "ip:port"
        return data.strip()
    if event_type == "HTTP_RESPONSE" and isinstance(data, dict):
        host = data.get("host")
        port = data.get("port")
        if isinstance(host, str) and port is not None:
            return f"{host}:{port}"
    return None


ADAPTER = BBotAdapter()

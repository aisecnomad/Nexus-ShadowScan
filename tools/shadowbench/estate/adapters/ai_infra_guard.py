"""AI-Infra-Guard: fingerprint the estate's running AI services.

The estate's runtime entities that represent live model servers are mirrored
as loopback mock services (see `tools/shadowbench/estate/simhost.py` and
`artifacts/services/services.json`); the scanner fingerprints those targets.
Fingerprint and CVE scanning needs no model key; the scan contacts only the
listed loopback targets.

Prediction text holds only what the scanner printed: the target URL it
reported and its fingerprints. The services file's `anchor` is the answer
key for which estate entity a mock mirrors, so it never reaches a
prediction.

Scan targets: every prediction also records which staged service the
scanner reported, as that service's `id` in services.json. The id comes
from the port in the target URL the scanner printed, less the port offset,
never from a fingerprint. A reported port no staged service listens on is
recorded as the reported URL, which names no service. The runner keeps four
fields per prediction, so the targets travel in the run's
`detail["scan_targets"]`, one per prediction and in the same order. The
scorer maps a service id to the entity whose primary anchor is that
service's `anchor` and counts the result as harness attribution, not the
tool's; a target that names no service is a false positive.

Reach: the run's unit is `sim`, and the scorer counts it as reaching only
the entities a service in the estate's services.json stands in for (the
frozen file under `score --estate`, not the staged copy). The live-sim
stages no mock for any other runtime entity, so those earn this tool no
true negative and their positives count as missed.

Port offset: on a host where a real server holds 11434 or 8000, tools.json
`ai_infra_guard.port_offset` (an integer, default 0) moves every mock
service, through simhost's `--port-offset`, and every `--target` by that
many ports. The services file staged in the run directory records the
offset, and normalize subtracts it from each reported port. With
`--as-user` the tool could rewrite that staged file; that gains it nothing
it lacks already by choosing which URL to print, and the scorer attributes
only ids the frozen services.json names.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tools.shadowbench.estate.adapters import (
    Command,
    Normalized,
    Prediction,
    ToolConfig,
    ToolSpec,
    run_version,
)
from tools.shadowbench.estate.corpus import EstateCorpus
from tools.shadowbench.estate.score import SCAN_TARGETS, SIM_UNIT

SPEC = ToolSpec(
    id="ai_infra_guard",
    name="AI-Infra-Guard",
    vendor="Tencent Zhuque Lab",
    surfaces=frozenset({"runtime"}),
    categories=frozenset({"agent-process"}),
    notes="scan --target over loopback mock services mirroring the runtime entities; "
    "fingerprint+CVE only, no model keys",
)

_SIMHOST = Path(__file__).resolve().parent.parent / "simhost.py"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_FP_SLUGS = {"ollama": "ollama", "vllm": "vllm"}
_TARGET_LINE = re.compile(r"^(http://127\.0\.0\.1:(\d+))\s+\[(\d+)\]\s*(.*)$")
#: The staged services file's record of the offset simhost was given; simhost itself ignores it.
_OFFSET_KEY = "port_offset"


def port_offset(cfg: ToolConfig) -> int:
    """tools.json `ai_infra_guard.port_offset`: how far every mock service and target moves."""
    value = cfg.tool("ai_infra_guard").get(_OFFSET_KEY, 0)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"ai_infra_guard port_offset must be an integer, not {value!r}")
    return value


def staged_ports(payload: Any) -> dict[int, str]:
    """Service id by services.json port; ValueError for a file that does not list them plainly."""
    services = payload.get("services") if isinstance(payload, dict) else None
    if not isinstance(services, list):
        raise ValueError("services.json: 'services' must be a list")
    ports: dict[int, str] = {}
    for service in services:
        if not isinstance(service, dict):
            raise ValueError("services.json: every service must be an object")
        service_id, port = service.get("id"), service.get("port")
        if not isinstance(service_id, str) or not service_id:
            raise ValueError("services.json: every service needs a string id")
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError(f"services.json: service {service_id} needs an integer port")
        if port in ports:
            raise ValueError(f"services.json: services {ports[port]} and {service_id} share port {port}")
        ports[port] = service_id
    return ports


class AiInfraGuardAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        tool = cfg.tool("ai_infra_guard")
        if not tool.get("bin"):
            return "no 'bin' configured for ai_infra_guard"
        if not tool.get("fps") or not tool.get("vul"):
            return "ai_infra_guard needs 'fps' and 'vul' data directories in tools.json"
        try:
            port_offset(cfg)
        except ValueError as exc:
            return str(exc)
        return None

    def version(self, cfg: ToolConfig) -> str:
        return run_version(
            [cfg.binary("ai_infra_guard") or "ai-infra-guard", "--help"],
            pattern=r"v(\d+\.\d+\.\d+)",
        )

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return [SIM_UNIT] if (estate / "services" / "services.json").exists() else []

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        offset = port_offset(cfg)
        payload = json.loads((estate / "services" / "services.json").read_text(encoding="utf-8"))
        ports = staged_ports(payload)
        targets: list[str] = []
        for port in ports:
            if not 1 <= port + offset <= 65535:
                raise ValueError(f"port_offset {offset} moves port {port} outside 1-65535")
            targets.extend(["--target", f"http://127.0.0.1:{port + offset}"])
        # simhost reads the services; normalize reads the recorded offset back.
        staged = {**payload, _OFFSET_KEY: offset}
        (out_dir / "services.json").write_text(json.dumps(staged, indent=1) + "\n", encoding="utf-8")
        tool = cfg.tool("ai_infra_guard")
        argv: list[str] = [
            "/usr/bin/python3",
            str(_SIMHOST),
            "--services",
            str(out_dir / "services.json"),
            "--port-offset",
            str(offset),
            "--",
            str(tool["bin"]),
            "scan",
            *targets,
            "--fps",
            str(tool["fps"]),
            "--vul",
            str(tool["vul"]),
            "--lang",
            "en",
            "--timeout",
            "5",
            "-o",
            str(out_dir / "scan.txt"),
        ]
        return [
            Command(
                argv=tuple(argv), env={"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"}
            )
        ]

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        scan = out_dir / "scan.txt"
        if not scan.exists():
            return Normalized(error="scan.txt missing")
        text = _ANSI.sub("", scan.read_text(encoding="utf-8", errors="replace"))
        result = Normalized()
        reported: list[tuple[str, int]] = []
        for line in text.splitlines():
            match = _TARGET_LINE.match(line)
            if not match:
                continue
            result.raw_count += 1
            url, port, _status, rest = match.groups()
            fingerprints = [group.strip() for group in re.findall(r"\[([^\]]*)\]", rest) if group.strip()]
            if not fingerprints:
                continue
            names = [fp.split(":", 1)[0].strip().lower() for fp in fingerprints]
            known = [name for name in names if name in _FP_SLUGS]
            slug = _FP_SLUGS[known[0]] if known else "generic"
            result.predictions.append(
                Prediction(
                    fact=f"agent-process:{slug}",
                    text=f"{url} {' '.join(fingerprints)}",
                    surface="runtime",
                )
            )
            reported.append((url, int(port)))
        if not result.raw_count:
            # Every target answers the mock host, so a report without one target
            # line is a failed or unreadable scan, not an empty estate.
            result.error = "scan.txt holds no target result line"
            return result
        if not reported:
            return result
        offset = 0
        ports: dict[int, str] = {}
        try:
            payload = json.loads((out_dir / "services.json").read_text(encoding="utf-8"))
            offset = payload.get(_OFFSET_KEY, 0) if isinstance(payload, dict) else 0
            if isinstance(offset, bool) or not isinstance(offset, int):
                raise ValueError(f"services.json: {_OFFSET_KEY} must be an integer")
            ports = staged_ports(payload)
        except (OSError, ValueError) as exc:
            # Every target is then recorded as the URL reported, which names no service.
            offset, ports = 0, {}
            result.error = f"cannot map scanned targets to staged services: {exc}"
        else:
            result.detail[_OFFSET_KEY] = offset
        result.detail[SCAN_TARGETS] = [ports.get(port - offset, url) for url, port in reported]
        return result

"""AI-Infra-Guard: fingerprint the estate's running AI services.

The estate's runtime entities that represent live model servers are mirrored
as loopback mock services (see `tools/estate_benchmark/simhost.py` and
`estate/services/services.json`); the scanner fingerprints those targets.
Fingerprint and CVE scanning needs no model key; the scan contacts only the
listed loopback targets.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from shutil import copyfile
from typing import Any

from tools.estate_benchmark.adapters import (
    Command,
    Normalized,
    Prediction,
    ToolConfig,
    ToolSpec,
    run_version,
)
from tools.estate_benchmark.corpus import EstateCorpus

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


class AiInfraGuardAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        tool = cfg.tool("ai_infra_guard")
        if not tool.get("bin"):
            return "no 'bin' configured for ai_infra_guard"
        if not tool.get("fps") or not tool.get("vul"):
            return "ai_infra_guard needs 'fps' and 'vul' data directories in tools.json"
        return None

    def version(self, cfg: ToolConfig) -> str:
        return run_version(
            [cfg.binary("ai_infra_guard") or "ai-infra-guard", "--help"],
            pattern=r"v(\d+\.\d+\.\d+)",
        )

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return ["sim"] if (estate / "services" / "services.json").exists() else []

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        services_path = estate / "services" / "services.json"
        copyfile(services_path, out_dir / "services.json")
        services = json.loads(services_path.read_text(encoding="utf-8")).get("services", [])
        tool = cfg.tool("ai_infra_guard")
        argv: list[str] = [
            "/usr/bin/python3",
            str(_SIMHOST),
            "--services",
            str(out_dir / "services.json"),
            "--",
            str(tool["bin"]),
            "scan",
        ]
        for service in services:
            argv.extend(["--target", f"http://127.0.0.1:{service['port']}"])
        argv.extend(
            [
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
        )
        return [
            Command(
                argv=tuple(argv), env={"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"}
            )
        ]

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        scan = out_dir / "scan.txt"
        if not scan.exists():
            return Normalized(error="scan.txt missing")
        services: dict[int, dict[str, Any]] = {}
        services_path = out_dir / "services.json"
        if services_path.exists():
            for service in json.loads(services_path.read_text(encoding="utf-8")).get("services", []):
                services[int(service["port"])] = service
        text = _ANSI.sub("", scan.read_text(encoding="utf-8", errors="replace"))
        result = Normalized()
        for line in text.splitlines():
            match = re.match(r"^(http://127\.0\.0\.1:(\d+))\s+\[(\d+)\]\s*(.*)$", line)
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
            service = services.get(int(port), {})
            anchor = str(service.get("anchor", ""))
            result.predictions.append(
                Prediction(
                    fact=f"agent-process:{slug}",
                    text=f"{url} {' '.join(fingerprints)} {anchor}",
                    surface="runtime",
                )
            )
        return result

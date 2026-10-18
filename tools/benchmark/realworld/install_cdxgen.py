"""Install the reviewed cdxgen dependency graph without npm lifecycle scripts.

Run with an isolated tool directory; this installs third-party executable code.
The receipt describes this installation only, not the historical benchmark run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

LOCK_ROOT = Path(__file__).resolve().parent / "cdxgen"


def _version(command: str) -> str:
    return subprocess.check_output([command, "--version"], text=True).strip()


def install(destination: Path, *, lock_root: Path = LOCK_ROOT) -> Path:
    """Use npm's frozen install and record the actual input bytes after success."""
    inputs = {name: (lock_root / name).read_bytes() for name in ("package.json", "package-lock.json")}
    manifest = json.loads(inputs["package.json"])
    expected = manifest["dependencies"]["@cyclonedx/cdxgen"]
    versions = {name: _version(name) for name in ("node", "npm")}
    destination.mkdir(parents=True, exist_ok=True)
    receipt = destination / "install-receipt.json"
    # Once replacement begins, a failure must not retain the old graph's success receipt.
    receipt.unlink(missing_ok=True)
    for name, contents in inputs.items():
        (destination / name).write_bytes(contents)
    subprocess.run(
        [
            "npm",
            "ci",
            "--prefix",
            str(destination.resolve()),
            "--ignore-scripts",
            "--engine-strict",
            "--no-audit",
            "--no-fund",
        ],
        check=True,
    )
    for name, contents in inputs.items():
        if (destination / name).read_bytes() != contents:
            raise ValueError(f"npm changed the frozen {name}")
    installed = json.loads(
        (destination / "node_modules/@cyclonedx/cdxgen/package.json").read_text(encoding="utf-8")
    )["version"]
    if installed != expected:
        raise ValueError("installed cdxgen version differs from the reviewed pin")
    record = {
        "schema": 1,
        "created": datetime.now(UTC).isoformat(),
        "tool": "@cyclonedx/cdxgen",
        "version": installed,
        "runtime": versions,
        "install": "npm ci",
        "lifecycle_scripts": "disabled",
        "overrides": manifest.get("overrides", {}),
        "inputs_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()},
        "note": "This installation only; not evidence of the historical benchmark dependency graph.",
    }
    with receipt.open("x", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(f"cdxgen install receipt: {install(args.destination)}")


if __name__ == "__main__":
    main()

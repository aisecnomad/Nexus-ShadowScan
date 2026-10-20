"""Generate a read-only maintenance inventory from built-ins and existing docs.

No connector is instantiated, plugin imported, credential read, or tenant API
called. The inventory records declarations and documentation, not live support
or independent acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import re
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any

from shadowscan.config import accepted_connector_keys
from shadowscan.connectors import builtin_connector_names, get_connector_class
from tools.connector_reference import REFERENCE, render

ROOT = Path(__file__).resolve().parents[1]
_FAILURE = re.compile(r"\bincomplete\b|\bfail[- ]closed\b|\bdenied\b|\brefus\w*\b", re.IGNORECASE)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sections(text: str) -> dict[str, tuple[str, str]]:
    headings = list(re.finditer(r"^### (`[^`\n]+`[^\n]*)$", text, re.MULTILINE))
    result = {}
    for index, heading in enumerate(headings):
        stop = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[heading.end() : stop]
        # A new surface/shared section is not part of the preceding connector.
        body = re.split(r"^## ", body, maxsplit=1, flags=re.MULTILINE)[0].strip()
        anchor = re.sub(r"[^\w\s-]", "", heading[1].lower()).strip().replace(" ", "-")
        for name in re.findall(r"`([a-z][a-z0-9.-]+)`", heading[1]):
            if name in result:
                raise ValueError(f"duplicate connector documentation: {name}")
            result[name] = (body, anchor)
    return result


def inventory(root: Path = ROOT) -> dict[str, Any]:
    """Track registry size, declared dependencies, permissions and failure notes."""
    guide = (root / "docs/connectors.md").read_text(encoding="utf-8")
    sections = _sections(guide)
    names = sorted(builtin_connector_names())
    missing = set(names) - sections.keys()
    if missing:
        raise ValueError(f"connector documentation missing: {sorted(missing)}")
    if "## Least privilege\n" not in guide:
        raise ValueError("connector permission reference missing")
    permissions = guide.split("## Least privilege\n", 1)[1].split("\n## ", 1)[0].strip()
    common = guide.split("## Modes and shared collection rules\n", 1)[1].split("\n## ", 1)[0].strip()
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    records = []
    for name in names:
        cls = get_connector_class(name)
        module = inspect.getmodule(cls)
        if module is None or module.__file__ is None:
            raise ValueError(f"connector source missing: {name}")
        source = Path(module.__file__).resolve().relative_to(ROOT).as_posix()
        text, anchor = sections[name]
        keys = dict(cls.config_keys)
        keys.update({key: value for key, value in cls.shared_config_keys.items() if key not in keys})
        records.append(
            {
                "name": name,
                "surface": cls.surface.value,
                "description": cls.description,
                "class": f"{cls.__module__}:{cls.__name__}",
                "source": source,
                "requires_modules": sorted(cls.requires),
                "offline_formats": cls.offline_formats,
                "config_keys": dict(sorted(keys.items())),
                "accepted_keys": sorted(accepted_connector_keys(name) or []),
                "documentation": {
                    "entry": f"docs/connectors.md#{anchor}",
                    "entry_sha256": _hash(text),
                    "permissions": "docs/connectors.md#least-privilege",
                    # Verbatim paragraphs; absence is not a claim of no failure modes.
                    "failure_mode_notes": [
                        paragraph for paragraph in text.split("\n\n") if _FAILURE.search(paragraph)
                    ],
                },
            }
        )
    return {
        "schema_version": 1,
        "scope": "built-in declarations and checked-in documentation; no plugins or live acceptance",
        "connector_count": len(records),
        "surface_counts": dict(sorted(Counter(record["surface"] for record in records).items())),
        "dependencies": {
            "core": project["dependencies"],
            "optional": project.get("optional-dependencies", {}),
            "runtime_lock_sha256": hashlib.sha256((root / "requirements.lock").read_bytes()).hexdigest(),
        },
        "permissions_reference": {"path": "docs/connectors.md#least-privilege", "text": permissions},
        "shared_collection_rules": {
            "path": "docs/connectors.md#modes-and-shared-collection-rules",
            "text": common,
        },
        "connectors": records,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true", help="also reject stale configuration reference")
    args = parser.parse_args()
    if args.check and REFERENCE.read_text(encoding="utf-8") != render():
        raise SystemExit(
            "connector configuration reference is stale; run python -m tools.connector_reference"
        )
    result = inventory()
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(
            f"{result['connector_count']} built-in connectors across {len(result['surface_counts'])} surfaces"
        )
    else:
        print(text, end="")


if __name__ == "__main__":
    main()

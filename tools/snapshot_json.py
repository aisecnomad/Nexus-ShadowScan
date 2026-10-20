"""Deterministic, diff-friendly JSON for the committed contract snapshots.

``tools.cli_surface`` and ``tools.public_api``
write their snapshots with :func:`dumps`: keys in the order the generator
built them, two-space indentation, and every object a ``leaf`` predicate
selects on one line, so the diff of one changed option, signature or
connector field is one line.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any


def _never(value: dict[str, Any]) -> bool:
    return False


def drift(old: dict[str, Any], new: dict[str, Any]) -> dict[str, list[str]]:
    """Keys of two flattened snapshots that were added, removed or changed, each sorted.

    An addition is usually additive. A removal or a change (a renamed option, a
    narrowed choice, a new required parameter) is a breaking change unless the
    reviewer can say why not; ``docs/reference/stability.md`` has the policy.
    """
    return {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "changed": sorted(key for key in set(old) & set(new) if old[key] != new[key]),
    }


def drift_report(path: str, command: str, changes: dict[str, list[str]], limit: int = 40) -> str:
    """The message a stale snapshot fails with: what moved, and what the contributor does next."""
    lines = [f"{path} is out of date with the code; run `{command}` and commit the result."]
    labels = {
        "removed": "removed (breaking)",
        "changed": "changed (breaking unless only optional parts were added)",
        "added": "added (additive)",
    }
    for kind in ("removed", "changed", "added"):
        keys = changes[kind]
        if keys:
            shown = keys[:limit] + ([f"... and {len(keys) - limit} more"] if len(keys) > limit else [])
            lines.append(f"{labels[kind]}:")
            lines += [f"  {key}" for key in shown]
    lines.append(
        "Classify the change in the pull request as additive or breaking; a breaking change needs "
        "a deprecation first (docs/reference/stability.md)."
    )
    return "\n".join(lines)


def dumps(value: Any, leaf: Callable[[dict[str, Any]], bool] = _never) -> str:
    """``value`` as indented JSON text ending in a newline; a ``leaf`` object stays on one line."""

    def render(item: Any, level: int) -> str:
        pad = "  " * level
        inner = "  " * (level + 1)
        if isinstance(item, dict):
            if not item or leaf(item):
                return json.dumps(item, ensure_ascii=False)
            members = [f"{inner}{json.dumps(key)}: {render(child, level + 1)}" for key, child in item.items()]
            return "{\n" + ",\n".join(members) + f"\n{pad}}}"
        if isinstance(item, list):
            if not item or all(not isinstance(child, dict | list) for child in item):
                return json.dumps(item, ensure_ascii=False)
            return "[\n" + ",\n".join(f"{inner}{render(child, level + 1)}" for child in item) + f"\n{pad}]"
        return json.dumps(item, ensure_ascii=False, allow_nan=False)

    return render(value, 0) + "\n"

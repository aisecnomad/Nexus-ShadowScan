"""Synthetic source fixture; scanned as text, never executed."""

from pathlib import Path

NOTES = Path("notes")
TOOL_SPECS = [{"type": "function", "function": {"name": "read_note"}}]


def read_note(version):
    return (NOTES / f"{version}.md").read_text()


def dispatch(name, args):
    handlers = {"read_note": read_note}
    return handlers[name](**args)

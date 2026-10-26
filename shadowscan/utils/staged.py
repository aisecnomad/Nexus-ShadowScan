"""Bounded, inert snapshots of changed Git index blobs for local pre-commit scans.

Only immutable object IDs from the index select content. Worktree files, checkout
filters, hooks and external diff drivers never run. The normal Git metadata
preflight also refuses linked worktrees, alternates and config includes.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO

from shadowscan.connectors.base import ConnectorContext
from shadowscan.utils.git import (
    MetadataOutputLimitError,
    MetadataTimeoutError,
    metadata_git_argv_prefix,
    metadata_git_env,
    require_local_git_metadata,
    run_bounded_git_bytes,
)

MAX_STAGED_FILES = 100
MAX_STAGED_BYTES = 8 * 1024 * 1024
MAX_STAGED_FILE_BYTES = 1024 * 1024
_HEADER = re.compile(rb":[0-7]{6} ([0-7]{6}) [0-9a-f]{40,64} ([0-9a-f]{40,64}) ([AMDTU])\Z")


class StagedScanError(ValueError):
    """A staged scan could not read its entire selected scope safely."""


@dataclass(frozen=True)
class StagedSnapshot:
    root: Path
    files: int
    deleted: int
    selection_sha256: str


def _require_ordinary_index(root: Path) -> None:
    """Refuse a commit's alternate index before the safe Git environment strips it."""
    inherited = os.environ.get("GIT_INDEX_FILE")
    if inherited is None:
        return
    # Interpret relative values against this process's cwd, just as Git does.
    # Do not resolve, open or follow an inherited foreign path. Only the exact
    # ordinary index under the already-validated canonical root is supported.
    if Path(inherited).absolute() != root / ".git" / "index":
        raise StagedScanError(
            "staged scan refuses an alternate Git index; run git add then plain git commit "
            "(without -a or path arguments)"
        )


def _safe_path(raw: bytes) -> str:
    name = raw.decode("utf-8", errors="strict")
    parts = name.split("/")
    if not name or "\\" in name or any(p in {"", ".", ".."} or p.lower() == ".git" for p in parts):
        raise StagedScanError("staged index contains an unsafe path")
    if PurePosixPath(name).is_absolute():
        raise StagedScanError("staged index contains an absolute path")
    return name


def _selection(raw: bytes) -> tuple[list[tuple[str, bytes]], int]:
    """Parse NUL-separated raw diff records; reject unsupported or ambiguous entries."""
    if not raw:
        return [], 0
    parts = raw.split(b"\0")
    if parts[-1] or len(parts) % 2 != 1:
        raise StagedScanError("staged index listing is malformed")
    if (len(parts) - 1) // 2 > MAX_STAGED_FILES:
        raise StagedScanError(f"staged scope exceeds {MAX_STAGED_FILES} changed files; split the commit")
    selected: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    deleted = 0
    for header, path in zip(parts[:-1:2], parts[1::2], strict=True):
        match = _HEADER.fullmatch(header)
        if match is None:
            raise StagedScanError("staged index listing is unsupported or has unresolved conflicts")
        name = _safe_path(path)
        if name.casefold() in seen:
            raise StagedScanError("staged paths differ only by case; use an unambiguous scoped scan")
        seen.add(name.casefold())
        mode, oid, status = match.groups()
        if status == b"D":
            deleted += 1
            continue
        if mode not in {b"100644", b"100755"} or status == b"U" or len(oid) not in {40, 64}:
            raise StagedScanError("staged links, submodules or unresolved conflicts require a full scan")
        selected.append((name, oid))
    return selected, deleted


def _git(
    root: Path, args: list[str], ctx: ConnectorContext, *, limit: int, stdin: IO[bytes] | None = None
) -> bytes:
    env = metadata_git_env()
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = run_bounded_git_bytes(
        [*metadata_git_argv_prefix(), "-C", str(root), *args],
        env,
        ctx,
        max_bytes=limit,
        timeout=10.0,
        stdin=stdin,
    )
    if result.returncode:
        raise StagedScanError("staged index read failed; use a local repository root and Git 2.45 or later")
    return result.stdout


def _materialize(root: Path, selected: list[tuple[str, bytes]], content: bytes) -> None:
    offset = 0
    for name, oid in selected:
        end = content.find(b"\n", offset)
        fields = content[offset:end].split(b" ")
        if end < offset or len(fields) != 3 or fields[:2] != [oid, b"blob"] or not fields[2].isdigit():
            raise StagedScanError("a staged blob is missing or its response is malformed")
        size = int(fields[2])
        if size > MAX_STAGED_FILE_BYTES:
            raise StagedScanError("a staged file exceeds 1 MiB; use a full scan with reviewed size limits")
        start, offset = end + 1, end + size + 2
        if offset > len(content) or content[offset - 1 : offset] != b"\n":
            raise StagedScanError("a staged blob was truncated")
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        # The destination is a private new directory, and entries are regular files only.
        # Exclusive creation also refuses case/Unicode aliases on the host filesystem.
        with path.open("xb") as stream:
            stream.write(content[start : offset - 1])
    if offset != len(content):
        raise StagedScanError("unexpected trailing staged blob data")


@contextmanager
def staged_snapshot(root: Path, ctx: ConnectorContext) -> Iterator[StagedSnapshot]:
    """Yield exact staged bytes or fail closed; never substitute working-tree content."""
    try:
        _require_ordinary_index(root)
        require_local_git_metadata(root)
        raw = _git(
            root,
            [
                "diff",
                "--cached",
                "--raw",
                "--no-abbrev",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                # Otherwise "ignore = all" in .gitmodules (tracked or worktree-only) or
                # diff.ignoreSubmodules drops a staged gitlink before _selection refuses it.
                "--ignore-submodules=none",
                "-z",
                "--",
            ],
            ctx,
            limit=256 * 1024,
        )
        selected, deleted = _selection(raw)
        with tempfile.TemporaryDirectory(prefix="shadowscan-staged-") as directory:
            # Native macOS temporary roots often begin with the /var -> /private/var alias.
            # Canonicalize our own newly created directory before the confined reader opens it.
            snapshot = Path(directory).resolve()
            if selected:
                with tempfile.TemporaryFile() as request:
                    request.write(b"\n".join(oid for _, oid in selected) + b"\n")
                    request.seek(0)
                    content = _git(root, ["cat-file", "--batch"], ctx, limit=MAX_STAGED_BYTES, stdin=request)
                _materialize(snapshot, selected, content)
            yield StagedSnapshot(snapshot, len(selected), deleted, hashlib.sha256(raw).hexdigest())
    except StagedScanError:
        raise
    except (MetadataOutputLimitError, MetadataTimeoutError):
        raise StagedScanError("staged Git read exceeded its byte or time budget; use a full scan") from None
    except (OSError, ValueError, subprocess.SubprocessError):
        raise StagedScanError(
            "staged metadata or content could not be read safely; use a full scan"
        ) from None

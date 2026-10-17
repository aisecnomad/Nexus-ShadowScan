"""Ownership of scanned code: CODEOWNERS matching and the filesystem connector's owner lookups.

``codeowners_match`` matches CODEOWNERS globs in bounded time, without backtracking
regular expressions. ``CodeOwnership`` is the ownership collaborator of
``FilesystemConnector`` (ADR-005): it reads the first selected CODEOWNERS file
through the scan root descriptor the walk opened, resolves the owner of each
evidence file within a per-lookup and a per-root step budget, and, with
``use_git``, reads a project's last commit from confined local Git metadata.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from shadowscan.connectors.base import ConnectorContext
from shadowscan.utils.files import link_in_path, open_confined_directory, open_confined_file
from shadowscan.utils.git import (
    MetadataOutputLimitError,
    MetadataTimeoutError,
    metadata_git_argv_prefix,
    metadata_git_env,
    require_local_git_metadata,
    run_bounded_metadata,
)
from shadowscan.utils.text import parse_timestamp, read_text

MAX_RULES = 10_000
MAX_PATTERN_LENGTH = 4_096
# Steps for one ownership lookup (one path against every rule). Ordinary
# monorepo files (2k rules, 6-part paths) need well under 100k steps.
MAX_OWNERSHIP_STEPS = 2_000_000
# Steps for every lookup under one scan root together.
MAX_ROOT_OWNERSHIP_STEPS = 20_000_000

# Git identities must not turn a small compressed commit into a large report.
_MAX_GIT_AUTHOR_CHARS = 1024
_MAX_GIT_EMAIL_CHARS = 1024
_MAX_GIT_TIMESTAMP_CHARS = 64


class OwnershipLimitError(ValueError):
    """Ownership cannot be resolved within its resource budget."""


@dataclass
class OwnershipBudget:
    remaining: int = MAX_OWNERSHIP_STEPS

    def consume(self, steps: int = 1) -> None:
        self.remaining -= steps
        if self.remaining < 0:
            raise OwnershipLimitError("CODEOWNERS processing budget exceeded")


def _component_match(pattern: str, name: str, budget: OwnershipBudget) -> bool:
    """Match * and ? in bounded O(len(pattern) * len(name)) time/constant space.

    Remember only the most recent star and extend its match if necessary. This
    avoids the exponential search caused by translating overlapping stars to .*.
    """
    p = n = 0
    star = -1
    retry = 0
    while n < len(name):
        budget.consume()
        if p < len(pattern) and pattern[p] == "*":
            star, retry = p, n
            p += 1
        elif p < len(pattern) and (pattern[p] == "?" or pattern[p] == name[n]):
            p += 1
            n += 1
        elif star >= 0:
            retry += 1
            n, p = retry, star + 1
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        budget.consume()
        p += 1
    return p == len(pattern)


def codeowners_match(pattern: str, path: str, budget: OwnershipBudget | None = None) -> bool:
    """Match GitHub/GitLab's supported component globs within a shared budget.

    Slash-containing rules are anchored. Bare names and trailing-slash directory
    rules match at any depth; literal directory rules own their descendants.
    The path-level dynamic program is iterative, including for ** components.
    """
    budget = budget if budget is not None else OwnershipBudget()
    if len(pattern) > MAX_PATTERN_LENGTH or len(path) > MAX_PATTERN_LENGTH:
        raise OwnershipLimitError("CODEOWNERS pattern or path exceeds length limit")
    budget.consume()
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    directory = pattern.endswith("/")
    pattern = pattern.strip("/")
    if not pattern or path == ".":
        return False
    parts = PurePosixPath(path).parts
    selectors = pattern.split("/")
    descendants = directory or not any(char in selectors[-1] for char in "*?")
    if not anchored:
        candidates = parts if descendants else parts[-1:]
        return any(_component_match(pattern, part, budget) for part in candidates)
    # Most anchored rules in a large CODEOWNERS file start with a literal
    # directory that differs from the path's first component; reject those
    # without running the dynamic program (the work is charged per step below).
    first = selectors[0]
    if first != "**" and not any(char in first for char in "*?") and parts and first != parts[0]:
        return False

    previous = [True] + [False] * len(parts)
    for selector in selectors:
        current = [False] * (len(parts) + 1)
        if selector == "**":
            current[0] = previous[0]
            for i in range(1, len(parts) + 1):
                budget.consume()
                current[i] = previous[i] or current[i - 1]
        else:
            for i, part in enumerate(parts, start=1):
                budget.consume()
                current[i] = previous[i - 1] and _component_match(selector, part, budget)
        previous = current
    return any(previous[1:]) if descendants else previous[-1]


class ScanRoot(Protocol):
    """The scan whose opened root directory the ownership reads go through."""

    @property
    def root(self) -> Path: ...

    @property
    def root_fd(self) -> int: ...  # the opened directory, or -1 when it could not be opened

    @property
    def base(self) -> Path | None: ...  # that directory: the scan root, or a single-file root's parent


class CodeOwnership:
    """Owners of the files the filesystem connector scans (its ownership collaborator, ADR-005).

    ``owner_for`` resolves one path, ``owners_for_files`` the files of one finding, and
    ``git_info`` a project's last commit. The connector brackets each scanned root with
    ``begin_scan`` and ``end_scan``; caches are kept per opened root.
    """

    def __init__(
        self,
        ctx: ConnectorContext,
        *,
        use_git: bool,
        owner: str | None,
        max_file_size: int,
        included: Callable[[str], bool],
    ) -> None:
        self.ctx = ctx
        self.use_git = use_git
        self.owner = owner  # the configured owner, which overrides CODEOWNERS
        self.max_file_size = max_file_size
        # Whether the connector's `include` option selects a path below the root.
        self._included = included
        self._codeowners_cache: dict[Path, list[tuple[str, list[str]]]] = {}
        self._ownership_exhausted: set[Path] = set()
        self._ownership_steps_remaining: dict[Path, int] = {}
        self._owner_cache: dict[tuple[Path, str], str | None] = {}
        self._ownership_scan: ScanRoot | None = None

    def begin_scan(self, scan: ScanRoot) -> ScanRoot | None:
        """Make ``scan`` the active scan and drop what is cached for its root; return the previous scan."""
        previous_scan = self._ownership_scan
        self._ownership_scan = scan
        # Ownership caches belong to this opened tree, not a pathname that a
        # later scan on the same connector instance may find replaced.
        root = scan.root
        self._codeowners_cache.pop(root, None)
        self._ownership_exhausted.discard(root)
        self._ownership_steps_remaining.pop(root, None)
        self._owner_cache = {key: value for key, value in self._owner_cache.items() if key[0] != root}
        return previous_scan

    def end_scan(self, previous_scan: ScanRoot | None) -> None:
        """Make the scan that ``begin_scan`` replaced the active one again."""
        self._ownership_scan = previous_scan

    def git_info(self, root: Path, rel_root: str) -> dict[str, Any]:
        if not self.use_git:
            return {}
        marker = root / ".git"
        if not os.path.lexists(marker):
            return {}
        deadline = time.monotonic() + 20
        if self.ctx.deadline is not None:
            deadline = min(deadline, self.ctx.deadline)
        try:
            require_local_git_metadata(root, timeout=deadline - time.monotonic())
        except ValueError:
            self.ctx.warn(
                "code.filesystem: git metadata must be a confined local .git directory; enrichment skipped"
            )
            return {}
        target = "." if rel_root == "." else rel_root
        try:
            out = run_bounded_metadata(
                [
                    *metadata_git_argv_prefix(),
                    "-C",
                    str(root),
                    "log",
                    "--no-show-signature",
                    "--no-ext-diff",
                    "--no-textconv",
                    "-1",
                    "--format=%an%x00%ae%x00%cI",
                    "--",
                    target,
                ],
                env=metadata_git_env(),
                ctx=self.ctx,
                timeout=deadline - time.monotonic(),
            )
            if out.returncode == 0 and out.stdout.strip():
                # NUL separators: an author name may itself contain "|".
                fields = out.stdout.strip("\r\n").split("\x00")
                if len(fields) != 3:
                    self.ctx.warn("code.filesystem: git metadata has invalid fields; enrichment skipped")
                    return {}
                an, ae, ci = fields
                if any(
                    len(value) > limit
                    for value, limit in zip(
                        fields,
                        (_MAX_GIT_AUTHOR_CHARS, _MAX_GIT_EMAIL_CHARS, _MAX_GIT_TIMESTAMP_CHARS),
                        strict=True,
                    )
                ):
                    self.ctx.warn("code.filesystem: git metadata field limit exceeded; enrichment skipped")
                    return {}
                if parse_timestamp(ci) is None:
                    self.ctx.warn(
                        "code.filesystem: git metadata has an unparseable commit timestamp; "
                        "enrichment skipped"
                    )
                    return {}
                return {"last_author": an, "last_author_email": ae, "last_commit": ci}
            if out.returncode == 0:
                return {}
        except MetadataOutputLimitError:
            self.ctx.warn("code.filesystem: git metadata output limit exceeded; enrichment skipped")
            return {}
        except MetadataTimeoutError:
            # A TimeoutError is an OSError: name the cause instead of blaming
            # the Git version below.
            self.ctx.warn(
                "code.filesystem: git metadata collection reached its time limit or the connector "
                "deadline; enrichment skipped"
            )
            return {}
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        self.ctx.warn(
            "code.filesystem: bounded offline git enrichment failed; Git 2.45+ and locally available history "
            "within the metadata output limit are required"
        )
        return {}

    @contextmanager
    def _codeowners_directory(self, root: Path) -> Iterator[int | None]:
        """Keep ownership reads on the same directory descriptor as source collection.

        Reopening the pathname only verifies that it still names that directory;
        candidate file reads always use the original descriptor. A replacement
        after this verification therefore cannot redirect ownership reads.
        """
        scan = self._ownership_scan
        if scan is not None:
            if scan.root != root:
                raise ValueError("ownership root differs from the active scan")
            if scan.root_fd < 0 or scan.base != root:
                # A failed root open has already been reported. Single-file
                # scans have never consulted their parent directory's owners.
                yield None
                return
            current = open_confined_directory(root)
            try:
                original, present = os.fstat(scan.root_fd), os.fstat(current)
                if (original.st_dev, original.st_ino) != (present.st_dev, present.st_ino):
                    raise ValueError("scan root changed before ownership lookup")
            finally:
                os.close(current)
            yield scan.root_fd
            return
        # Direct internal ownership callers have no collection descriptor.
        directory = open_confined_directory(root)
        try:
            yield directory
        finally:
            os.close(directory)

    def _codeowners(self, root: Path) -> list[tuple[str, list[str]]]:
        root = root.absolute()
        if root in self._codeowners_cache:
            return self._codeowners_cache[root]
        rules: list[tuple[str, list[str]]] = []
        try:
            with self._codeowners_directory(root) as directory:
                if directory is not None:
                    rules = self._read_codeowners(root, directory)
        except (OSError, RuntimeError, ValueError):
            self.ctx.error("code.filesystem: could not verify scan root for CODEOWNERS; ownership incomplete")
        self._codeowners_cache[root] = rules
        return rules

    def _read_codeowners(self, root: Path, directory: int) -> list[tuple[str, list[str]]]:
        """Read the first selected ownership file below the already anchored root."""
        rules: list[tuple[str, list[str]]] = []
        for cand in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS"):
            if not self._included(cand):
                continue
            try:
                # Distinguish a missing candidate from an unreadable one without
                # following a link, including links in its parent components.
                with open_confined_file(PurePosixPath(cand), dir_fd=directory):
                    pass
            except FileNotFoundError:
                continue
            except NotADirectoryError:
                # A file named like its parent (``docs``, ``.github``) leaves the
                # candidate absent. A link there fails the same way and is not
                # followed, so what it might name stays unread.
                if not link_in_path(cand, dir_fd=directory):
                    continue
                self.ctx.error(f"code.filesystem: could not read {cand}")
                break
            except (OSError, RuntimeError, ValueError):
                self.ctx.error(f"code.filesystem: could not read {cand}")
                break
            try:
                errors: list[str] = []
                read_notes: list[str] = []
                content = read_text(
                    PurePosixPath(cand),
                    self.max_file_size,
                    errors,
                    dir_fd=directory,
                    notes=read_notes,
                )
                # Ownership comes from names in this file: bytes that were replaced could change an owner.
                errors.extend(f"{note}; ownership may be wrong" for note in read_notes)
                for issue in errors:
                    self.ctx.error(f"code.filesystem: {cand}: {issue}")
                for line in (content or "").splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if parts:
                        if len(rules) >= MAX_RULES or len(parts[0]) > MAX_PATTERN_LENGTH:
                            self.ctx.error(
                                "code.filesystem: CODEOWNERS rule limit exceeded; ownership incomplete"
                            )
                            rules = []
                            self._ownership_exhausted.add(root)
                            break
                        rules.append((parts[0], parts[1:]))
            except (OSError, RuntimeError, ValueError):
                self.ctx.error(f"code.filesystem: could not read {cand}")
            break
        return rules

    def owner_for(self, root: Path, rel_root: str) -> str | None:
        if self.owner:
            return self.owner
        root = root.absolute()
        rules = self._codeowners(root)
        if root in self._ownership_exhausted:
            return None
        key = (root, rel_root)
        if key in self._owner_cache:
            return self._owner_cache[key]
        # Preserve the per-lookup cap and limit aggregate work across many
        # unique paths. Cache hits consume no steps. Exhaustion is reported as
        # incomplete ownership rather than assigning a potentially wrong owner.
        root_remaining = self._ownership_steps_remaining.get(root, MAX_ROOT_OWNERSHIP_STEPS)
        budget = OwnershipBudget(min(MAX_OWNERSHIP_STEPS, root_remaining))
        initial = budget.remaining
        try:
            # Last matching rule wins, including ownerless exclusions. Stop at
            # that rule instead of repeatedly re-evaluating overridden rules.
            for pattern, owners in reversed(rules):
                if codeowners_match(pattern, rel_root, budget):
                    self._owner_cache[key] = ", ".join(owners) if owners else None
                    return self._owner_cache[key]
        except OwnershipLimitError:
            self._ownership_exhausted.add(root)
            self.ctx.error("code.filesystem: CODEOWNERS processing budget exceeded; ownership incomplete")
        finally:
            remaining = max(0, root_remaining - (initial - budget.remaining))
            self._ownership_steps_remaining[root] = remaining
            if remaining == 0 and root not in self._ownership_exhausted:
                self._ownership_exhausted.add(root)
                self.ctx.error(
                    "code.filesystem: CODEOWNERS aggregate processing budget exceeded; ownership incomplete"
                )
        self._owner_cache[key] = None
        return None

    def owners_for_files(self, root: Path, files: Iterable[str]) -> tuple[str | None, dict[str, str]]:
        paths = sorted(set(files))
        by_file = {rel: owner for rel in paths if (owner := self.owner_for(root, rel))}
        owners = set(by_file.values())
        if len(owners) == 1 and len(by_file) == len(paths):
            return owners.pop(), by_file
        # A project finding summarizes many files. Do not name one file's owner
        # as the owner of unrelated files if CODEOWNERS has differing rules.
        return None, by_file

"""Fetch the code-surface repositories of the ShadowBench corpus at their pinned commits.

``python -m tools.shadowbench.cases.fetch_code DEST``, run from the repository root, creates
``DEST/<repo id>`` for every repository in :data:`tools.shadowbench.cases.generate.CODE_REPOS`,
at the commit the code corpus (``benchmarks/shadow-ai-discovery``) pins. Only ``git`` runs,
and the repositories are untrusted input, so every call is hardened:

* git reads none of the operator's system or global configuration or attributes
  (``GIT_CONFIG_NOSYSTEM``, ``GIT_CONFIG_GLOBAL=/dev/null``, ``GIT_ATTR_NOSYSTEM``,
  ``core.attributesFile=/dev/null``), and ``.git/info/attributes`` unsets ``filter`` for
  every path, so a repository's ``.gitattributes`` cannot select a filter driver (git-lfs,
  say) that then runs on checkout; an operator behind a TLS-inspecting proxy sets
  ``HTTPS_PROXY`` and ``GIT_SSL_CAINFO`` in the environment, since ``http.proxy`` or
  ``http.sslCAInfo`` in ``~/.gitconfig`` no longer apply;
* the remote must be an ``https://`` URL without credentials, and git may use no other
  transport (``protocol.allow=never`` plus ``protocol.https.allow=always``), so neither a
  redirect nor a submodule URL reaches ``ssh``, ``file`` or ``ext``;
* hooks are disabled (``core.hooksPath=/dev/null``, which also overrides a hooks path in
  the operator's configuration) and submodules are never fetched or checked out;
* the pinned commit is fetched by SHA (depth 1), falling back to the default branch only
  when its tip is that commit; the fetched commit is checked before anything is checked
  out, and ``rev-parse HEAD`` must equal the pinned SHA afterwards;
* ``DEST/<repo id>`` must not be a symbolic link: an existing link is refused, never
  followed, and a stale checkout is replaced only when it is a real directory;
* git gets the caller's environment without its ``GIT_*`` variables (only the TLS trust
  anchors ``GIT_SSL_CAINFO`` and ``GIT_SSL_CAPATH`` pass), so a ``GIT_DIR``,
  ``GIT_WORK_TREE``, ``GIT_INDEX_FILE`` or object directory set by a git hook or
  ``git bisect run`` cannot turn the fetch onto the operator's repository, and neither
  ``GIT_CONFIG_*`` nor ``GIT_SSL_NO_VERIFY`` can undo the settings above; repository
  discovery stops at ``DEST/<repo id>`` (``GIT_CEILING_DIRECTORIES``) and TLS
  verification is on (``http.sslVerify=true``).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from tools.discovery_benchmark.corpus import load_corpus
from tools.shadowbench.cases.generate import CODE_CORPUS, CODE_REPOS

GIT_CONFIG: tuple[str, ...] = (
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "core.attributesFile=/dev/null",
    "submodule.recurse=false",
    "fetch.recurseSubmodules=false",
    "protocol.allow=never",
    "protocol.https.allow=always",
    "http.sslVerify=true",
    "advice.detachedHead=false",
)
# The only GIT_* variables git inherits: CA settings an operator needs behind a TLS-inspecting proxy.
GIT_ENV_KEEP = frozenset({"GIT_SSL_CAINFO", "GIT_SSL_CAPATH"})
FETCH_TIMEOUT = 900
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")


class FetchError(RuntimeError):
    """A repository could not be fetched safely at its pinned commit."""


def git_env(checkout: Path) -> dict[str, str]:
    """The environment of every git call in ``checkout`` (see the module docstring)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") or k in GIT_ENV_KEEP}
    env["GIT_TERMINAL_PROMPT"] = "0"
    # The operator's own configuration may define filter drivers a fetched .gitattributes can select.
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_ATTR_NOSYSTEM"] = "1"
    # Without a .git of its own, the checkout must never resolve to a repository above it.
    env["GIT_CEILING_DIRECTORIES"] = str(checkout.resolve().parent)
    return env


def _git(args: list[str], cwd: Path, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    config = [part for item in GIT_CONFIG for part in ("-c", item)]
    return subprocess.run(
        ["git", *config, *args],
        cwd=cwd,
        env=git_env(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def _check(proc: subprocess.CompletedProcess[str], what: str) -> None:
    if proc.returncode != 0:
        raise FetchError(f"{what} failed: {proc.stderr.strip()[:300]}")


def https_remote(url: str) -> str:
    """Return ``url`` when it is a plain ``https://host/...`` URL; raise otherwise.

    The error names the scheme and host only, so a credential in the URL is never printed.
    """
    parts = urlsplit(url)
    where = f"scheme {parts.scheme or '(none)'!r}, host {parts.hostname or '(none)'!r}"
    if parts.scheme != "https" or not parts.hostname:
        raise FetchError(f"refusing a non-https remote ({where})")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise FetchError(f"refusing a remote with credentials, a query or a fragment ({where})")
    return url


def _head(checkout: Path) -> str:
    proc = _git(["rev-parse", "HEAD"], checkout)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def fetch_pinned(url: str, commit: str, branch: str, dest: Path) -> str:
    """Fetch ``url`` at ``commit`` into ``dest`` (detached) and return the verified HEAD."""
    https_remote(url)
    if not _SHA.match(commit):
        raise FetchError(f"pinned commit {commit!r} is not a 40-character lowercase SHA")
    if dest.is_symlink():
        raise FetchError(f"{dest} is a symbolic link; refusing to follow it")
    if dest.exists():
        if not dest.is_dir():
            raise FetchError(f"{dest} exists and is not a directory")
        git_dir = dest / ".git"
        if git_dir.is_dir() and not git_dir.is_symlink() and _head(dest) == commit:
            return commit
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    _check(_git(["init", "-q"], dest), "git init")
    # info/attributes overrides every .gitattributes in the tree: no path selects a filter driver.
    (dest / ".git" / "info").mkdir(parents=True, exist_ok=True)
    (dest / ".git" / "info" / "attributes").write_text("* !filter\n", encoding="utf-8")
    _check(_git(["remote", "add", "origin", url], dest), "git remote add")
    fetch = ["fetch", "-q", "--depth", "1", "--no-tags", "--no-recurse-submodules", "origin"]
    fetched = _git([*fetch, commit], dest, FETCH_TIMEOUT)
    if fetched.returncode != 0:
        # Hosts that refuse an unadvertised commit: the default branch, if its tip is still the pin.
        if not _BRANCH.match(branch) or ".." in branch:
            raise FetchError(f"fetch of {commit} failed and default branch {branch!r} is not a branch name")
        _check(_git([*fetch, f"refs/heads/{branch}"], dest, FETCH_TIMEOUT), "fetch by commit and branch")
    fetched_commit = _git(["rev-parse", "--verify", "FETCH_HEAD^{commit}"], dest).stdout.strip()
    if fetched_commit != commit:
        # A default branch that moved on: refuse before any of its content reaches the disk.
        raise FetchError(f"fetched {fetched_commit or '(nothing)'}, not the pinned commit {commit}")
    _check(
        _git(["checkout", "-q", "--detach", "--no-recurse-submodules", "FETCH_HEAD"], dest, FETCH_TIMEOUT),
        "git checkout",
    )
    head = _head(dest)
    if head != commit:
        raise FetchError(f"HEAD {head or '(none)'} is not the pinned commit {commit}")
    return head


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m tools.shadowbench.cases.fetch_code DEST", file=sys.stderr)
        return 2
    dest = Path(argv[0])
    corpus = load_corpus(CODE_CORPUS)
    failures = 0
    for rid in CODE_REPOS:
        try:
            repo = corpus.get(rid)
            head = fetch_pinned(repo.url, repo.commit, repo.default_branch, dest / rid)
            print(f"ok {rid} {head}", flush=True)
        except Exception as exc:  # noqa: BLE001 - report every repository, then fail at the end
            failures += 1
            print(f"FAIL {rid}: {exc}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

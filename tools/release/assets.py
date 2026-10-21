"""Verify and attach existing release evidence; never create a release or tag.

Only ``--upload`` writes to GitHub. Verification uses the runner's GitHub CLI,
the original Sigstore bundles, and the exact source/workflow identity. This
module uses only the standard library and never imports or executes a package
from the candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

_WHEEL = re.compile(r"nexusshadowscan-([0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?)-py3-none-any\.whl")
_SHA = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")


def _gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True, timeout=180).stdout


def _file(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular file: {path.name}")
    return path


def _digest(path: Path) -> str:
    with _file(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _json(text: str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def finite(_: str) -> Any:
        raise ValueError("non-finite JSON value")

    value = json.loads(text, object_pairs_hook=unique, parse_constant=finite)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def _read(path: Path) -> str:
    if _file(path).stat().st_size > 64 * 1024 * 1024:
        raise ValueError(f"oversized release evidence: {path.name}")
    return path.read_text(encoding="utf-8")


def _candidate_hashes(directory: Path) -> dict[str, str]:
    """Parse unambiguous portable names and check every candidate digest."""
    hashes: dict[str, str] = {}
    for line in _read(directory / "SHA256SUMS").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
        if match is None or match[2] in hashes:
            raise ValueError("ambiguous or unsafe SHA256SUMS")
        hashes[match[2]] = match[1]
        if _digest(directory / match[2]) != match[1]:
            raise ValueError(f"digest mismatch: {match[2]}")
    return hashes


def verified_assets(directory: Path, *, repository: str, commit: str, run_id: str) -> tuple[str, list[Path]]:
    """Verify hashes and signatures before any release mutation."""
    if not _REPOSITORY.fullmatch(repository) or not _SHA.fullmatch(commit):
        raise ValueError("invalid expected source identity")
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ValueError("invalid expected workflow run")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("candidate must be a real directory")
    bundles = directory / "attestations"
    if bundles.is_symlink() or not bundles.is_dir():
        raise ValueError("attestations must be a real directory")
    sums = directory / "SHA256SUMS"
    hashes = _candidate_hashes(directory)
    wheels = [name for name in hashes if name.endswith(".whl")]
    sdists = [name for name in hashes if name.endswith(".tar.gz")]
    if len(wheels) != 1 or (match := _WHEEL.fullmatch(wheels[0])) is None:
        raise ValueError("expected one universal release wheel")
    version = match[1]
    if sdists != [f"nexusshadowscan-{version}.tar.gz"]:
        raise ValueError("expected one matching release sdist")
    required = {"build-evidence.json", "runtime-sbom.cdx.json"}
    if not required <= hashes.keys():
        raise ValueError("missing release evidence or SBOM")
    if {"SHA256SUMS", "provenance.sigstore.json", "sbom.sigstore.json"} & hashes.keys():
        raise ValueError("reserved attachment name in candidate checksums")
    evidence = _json(_read(directory / "build-evidence.json"))
    if evidence.get("source") != {"repository": repository, "commit": commit}:
        raise ValueError("candidate source differs from the reviewed commit")
    if evidence.get("workflow_run") != f"https://github.com/{repository}/actions/runs/{run_id}":
        raise ValueError("candidate came from another workflow run")
    # Cryptographically bind the digest list, package bytes and SBOM. These
    # flags check certificate claims, rather than trusting decoded JSON.
    identity = [
        "--repo",
        repository,
        "--signer-workflow",
        f"{repository}/.github/workflows/release.yml",
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        commit,
        "--signer-digest",
        commit,
        "--deny-self-hosted-runners",
    ]
    provenance = _file(bundles / "provenance.sigstore.json")
    sbom = _file(bundles / "sbom.sigstore.json")
    package_paths = [directory / wheels[0], directory / sdists[0]]
    for path in [
        sums,
        directory / "build-evidence.json",
        directory / "runtime-sbom.cdx.json",
        *package_paths,
    ]:
        _gh("attestation", "verify", str(path), "--bundle", str(provenance), *identity)
    for path in package_paths:
        _gh(
            "attestation",
            "verify",
            str(path),
            "--bundle",
            str(sbom),
            "--predicate-type",
            "https://cyclonedx.org/bom",
            *identity,
        )
    # Retain every checksummed file so SHA256SUMS is usable after download.
    return f"v{version}", [directory / name for name in sorted(hashes)] + [sums, provenance, sbom]


def _release(repository: str, tag: str) -> dict[str, Any]:
    """The one maintainer-created release, draft or published, for ``tag``.

    ``releases/tags/{tag}`` serves published releases only, so a draft prepared
    for its evidence is found in the release listing, which includes drafts for
    a token with push access. Several releases naming the tag are ambiguous.
    """
    listing = _gh("api", "--paginate", f"repos/{repository}/releases?per_page=100", "--jq", ".[] | @json")
    entries = [_json(line) for line in listing.splitlines() if line]
    matches = [entry for entry in entries if entry.get("tag_name") == tag]
    if len(matches) != 1 or type(matches[0].get("id")) is not int:
        raise ValueError("expected exactly one existing maintainer-created release for the tag")
    release: dict[str, Any] = _json(_gh("api", f"repos/{repository}/releases/{matches[0]['id']}"))
    if release.get("tag_name") != tag or release.get("id") != matches[0]["id"]:
        raise ValueError("release changed while it was read")
    return release


def attach(
    directory: Path, *, repository: str, commit: str, run_id: str, upload: bool = False
) -> dict[str, Any]:
    """Require the existing tag/release, then upload missing assets without overwriting."""
    tag, paths = verified_assets(directory, repository=repository, commit=commit, run_id=run_id)
    tagged = _json(_gh("api", f"repos/{repository}/commits/refs/tags/{tag}"))
    if tagged.get("sha") != commit:
        raise ValueError("release tag does not resolve to the reviewed commit")
    release = _release(repository, tag)
    assets = release.get("assets")
    if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
        raise ValueError("invalid release asset listing")
    existing = {asset.get("name"): asset for asset in assets}
    if len(existing) != len(assets):
        raise ValueError("duplicate release asset names")
    pending = []
    for path in paths:
        digest = f"sha256:{_digest(path)}"
        if path.name in existing:
            if existing[path.name].get("digest") != digest:
                raise ValueError(f"existing asset has a different or unverifiable digest: {path.name}")
        else:
            pending.append(path)
    if pending and release.get("immutable") is True:
        raise ValueError("release is immutable; attach evidence to its draft before publication")
    if upload and pending:
        # No --clobber, create, edit, tag or index publishing. The CLI refuses
        # a name collision if another uploader races our read.
        _gh("release", "upload", tag, *(str(path) for path in pending), "--repo", repository)
        # Read back the server's SHA-256 digest for every attachment.
        readback = _json(_gh("api", f"repos/{repository}/releases/{release['id']}"))
        observed = {item["name"]: item.get("digest") for item in readback.get("assets", [])}
        if any(observed.get(path.name) != f"sha256:{_digest(path)}" for path in paths):
            raise ValueError("release attachment digest readback failed")
    return {
        "repository": repository,
        "commit": commit,
        "workflow_run": run_id,
        "tag": tag,
        "release_id": release["id"],
        "upload_requested": upload,
        "uploaded": bool(upload and pending),
        "assets": [{"name": path.name, "sha256": _digest(path)} for path in paths],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--upload", action="store_true")
    args = parser.parse_args()
    try:
        receipt = attach(
            args.directory,
            repository=args.repository,
            commit=args.commit,
            run_id=args.run_id,
            upload=args.upload,
        )
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        # gh diagnostics can contain API response text; avoid echoing it.
        raise SystemExit(f"release asset verification/attachment failed: {type(exc).__name__}") from None
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

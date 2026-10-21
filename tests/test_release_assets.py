"""Release attachments require the exact signed candidate and never replace assets."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tools.release import assets

REPOSITORY = "aisecnomad/Nexus-ShadowScan"
COMMIT = "a" * 40
RUN = "123"
WHEEL = "nexusshadowscan-0.1.3-py3-none-any.whl"
SDIST = "nexusshadowscan-0.1.3.tar.gz"


@pytest.fixture
def candidate(tmp_path: Path) -> Path:
    files = {
        WHEEL: b"synthetic wheel: never installed",
        SDIST: b"synthetic sdist: never extracted",
        "runtime-sbom.cdx.json": b'{"bomFormat":"CycloneDX"}',
        "requirements.lock": b"synthetic lock\n",
        "build-evidence.json": json.dumps(
            {
                "source": {"repository": REPOSITORY, "commit": COMMIT},
                "workflow_run": f"https://github.com/{REPOSITORY}/actions/runs/{RUN}",
            }
        ).encode(),
    }
    for name, content in files.items():
        (tmp_path / name).write_bytes(content)
    (tmp_path / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in files.items())
    )
    (tmp_path / "attestations").mkdir()
    for name in ("provenance.sigstore.json", "sbom.sigstore.json"):
        (tmp_path / "attestations" / name).write_text('{"synthetic":true}')
    return tmp_path


@pytest.fixture
def github(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {
        "calls": [],
        "tag": COMMIT,
        "verify_error": False,
        "release": {"id": 7, "tag_name": "v0.1.3", "draft": True, "assets": []},
        "extra_releases": [],
    }

    def gh(*args: str) -> str:
        state["calls"].append(args)
        if args[:2] == ("attestation", "verify"):
            expected = {
                "--repo": REPOSITORY,
                "--signer-workflow": f"{REPOSITORY}/.github/workflows/release.yml",
                "--source-ref": "refs/heads/main",
                "--source-digest": COMMIT,
                "--signer-digest": COMMIT,
            }
            assert "--deny-self-hosted-runners" in args
            for option, value in expected.items():
                assert args[args.index(option) + 1] == value
            if state["verify_error"]:
                raise subprocess.CalledProcessError(1, ["gh", *args])
            return "verified"
        if args == ("api", f"repos/{REPOSITORY}/commits/refs/tags/v0.1.3"):
            return json.dumps({"sha": state["tag"]})
        if args == ("api", "--paginate", f"repos/{REPOSITORY}/releases?per_page=100", "--jq", ".[] | @json"):
            # GitHub serves drafts only in this listing; releases/tags/{tag} finds published ones.
            listed = [{"id": 3, "tag_name": "v0.1.2", "draft": False, "assets": []}, *state["extra_releases"]]
            if state["release"]:
                listed.insert(0, state["release"])
            return "".join(json.dumps(entry) + "\n" for entry in listed)
        if args == ("api", f"repos/{REPOSITORY}/releases/7"):
            return json.dumps(state["release"])
        if args[:2] == ("release", "upload"):
            assert args[2] == "v0.1.3"
            assert args[-2:] == ("--repo", REPOSITORY)
            assert "--clobber" not in args
            for filename in args[3:-2]:
                path = Path(filename)
                state["release"]["assets"].append(
                    {
                        "name": path.name,
                        "digest": f"sha256:{assets._digest(path)}",
                    }
                )
            return ""
        raise AssertionError(f"unexpected command: {args}")

    monkeypatch.setattr(assets, "_gh", gh)
    return state


def attach(candidate: Path, **kwargs: Any) -> dict[str, Any]:
    return assets.attach(candidate, repository=REPOSITORY, commit=COMMIT, run_id=RUN, **kwargs)


def writes(github: dict[str, Any]) -> list[tuple[str, ...]]:
    return [call for call in github["calls"] if call[:2] == ("release", "upload")]


def test_verification_is_default_and_upload_is_explicit(candidate, github):
    receipt = attach(candidate)
    assert receipt["uploaded"] is False
    assert not writes(github)
    verification = [call for call in github["calls"] if call[:2] == ("attestation", "verify")]
    assert len(verification) == 7
    assert sum("--predicate-type" in call for call in verification) == 2
    receipt = attach(candidate, upload=True)
    assert receipt["uploaded"] is True
    assert len(writes(github)) == 1
    assert {asset["name"] for asset in receipt["assets"]} == {
        WHEEL,
        SDIST,
        "SHA256SUMS",
        "build-evidence.json",
        "runtime-sbom.cdx.json",
        "requirements.lock",
        "provenance.sigstore.json",
        "sbom.sigstore.json",
    }
    # A retry verifies the already attached server digests, without overwriting.
    attach(candidate, upload=True)
    assert len(writes(github)) == 1


@pytest.mark.parametrize(
    "problem", ["wrong-tag", "missing-release", "ambiguous-release", "immutable", "conflict", "signature"]
)
def test_remote_failure_never_uploads(candidate, github, problem):
    if problem == "wrong-tag":
        github["tag"] = "b" * 40
    elif problem == "missing-release":
        github["release"] = {}
    elif problem == "ambiguous-release":
        github["extra_releases"] = [{"id": 8, "tag_name": "v0.1.3", "draft": True, "assets": []}]
    elif problem == "immutable":
        github["release"]["immutable"] = True
    elif problem == "conflict":
        github["release"]["assets"] = [{"name": WHEEL, "digest": "sha256:" + "0" * 64}]
    else:
        github["verify_error"] = True
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        attach(candidate, upload=True)
    assert not writes(github)


@pytest.mark.parametrize("problem", ["tampered", "duplicate", "traversal", "symlink", "missing-bundle"])
def test_invalid_local_candidate_never_uploads(candidate, github, problem):
    if problem == "tampered":
        (candidate / WHEEL).write_bytes(b"substitution")
    elif problem == "duplicate":
        path = candidate / "SHA256SUMS"
        path.write_text(path.read_text() * 2)
    elif problem == "traversal":
        (candidate / "SHA256SUMS").write_text("0" * 64 + "  ../outside\n")
    elif problem == "symlink":
        (candidate / WHEEL).unlink()
        (candidate / WHEEL).symlink_to(candidate / SDIST)
    else:
        (candidate / "attestations/provenance.sigstore.json").unlink()
    with pytest.raises(ValueError):
        attach(candidate, upload=True)
    assert not writes(github)


@pytest.mark.parametrize(
    "field,value", [("commit", "b" * 40), ("run_id", "124"), ("repository", "other/repo")]
)
def test_candidate_must_match_exact_dispatch(candidate, github, field, value):
    args = {"repository": REPOSITORY, "commit": COMMIT, "run_id": RUN}
    args[field] = value
    with pytest.raises(ValueError):
        assets.attach(candidate, upload=True, **args)
    assert not writes(github)


def test_attachment_readback_failure_is_not_success(candidate, github, monkeypatch):
    original = assets._gh

    def corrupt(*args):
        result = original(*args)
        # Only the read-back after the upload loses the attachments.
        if args == ("api", f"repos/{REPOSITORY}/releases/7") and writes(github):
            return json.dumps({**github["release"], "assets": []})
        return result

    monkeypatch.setattr(assets, "_gh", corrupt)
    with pytest.raises(ValueError, match="readback"):
        attach(candidate, upload=True)

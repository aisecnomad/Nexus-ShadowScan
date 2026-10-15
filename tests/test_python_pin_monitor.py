"""The temporary interpreter-pin probe remains advisory on pull requests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _probe_step() -> dict:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["container-security"]["steps"]
    return next(step for step in steps if step.get("name", "").startswith("Check whether the temporary"))


def test_python_pin_probe_is_nonblocking_only_outside_schedule() -> None:
    step = _probe_step()
    assert step["continue-on-error"] == "${{ github.event_name != 'schedule' }}"
    assert "uses" not in step
    assert 'image="$(head -n 1 "$RUNNER_TEMP/base-images.txt" 2>/dev/null)"' in step["run"]
    assert 'hashlib.sha224(b\\"\\")' in step["run"]
    assert 'comparison="$(apk version -t "$candidate" "$1")"' in step["run"]
    assert "timeout 180s docker run --rm" in step["run"]


@pytest.mark.parametrize(
    ("status", "returncode", "message"),
    [
        (0, 0, "No newer Wolfi Python revision is available."),
        (42, 1, "::warning::A newer Wolfi Python revision supports SHA-224"),
        (43, 0, "::warning::The newer Wolfi Python revision still fails SHA-224"),
        (1, 1, "::error::The Wolfi Python pin probe could not complete."),
        (124, 1, "::error::The Wolfi Python pin probe could not complete."),
    ],
)
def test_python_pin_probe_outcomes(tmp_path: Path, status: int, returncode: int, message: str) -> None:
    (tmp_path / "Dockerfile").write_text((ROOT / "Dockerfile").read_text())
    image = "chainguard/wolfi-base@sha256:" + "a" * 64
    (tmp_path / "base-images.txt").write_text(image + "\n")
    docker = tmp_path / "docker"
    docker.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$PROBE_ARGUMENTS"\n'
        'echo "suppressed probe output" >&2\nexit "$PROBE_STATUS"\n'
    )
    docker.chmod(0o700)
    arguments = tmp_path / "arguments"
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "RUNNER_TEMP": str(tmp_path),
        "PROBE_STATUS": str(status),
        "PROBE_ARGUMENTS": str(arguments),
    }
    result = subprocess.run(
        ["bash", "-c", _probe_step()["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == returncode
    assert message in result.stdout
    assert not result.stderr
    assert "suppressed probe output" not in result.stdout
    assert image in arguments.read_text().splitlines()


@pytest.mark.parametrize(
    ("comparison", "hash_status", "returncode", "calls_hash"),
    [
        ("=", 0, 0, False),
        ("<", 0, 0, False),
        (">", 0, 1, True),
        (">", 1, 0, True),
        ("invalid", 0, 1, False),
    ],
)
def test_python_pin_probe_checks_newer_interpreter(
    tmp_path: Path, comparison: str, hash_status: int, returncode: int, calls_hash: bool
) -> None:
    (tmp_path / "Dockerfile").write_text((ROOT / "Dockerfile").read_text())
    (tmp_path / "base-images.txt").write_text("example.invalid/base@sha256:" + "a" * 64 + "\n")
    programs = {
        "docker": '#!/bin/sh\nwhile [ "$1" != "-ec" ]; do shift; done\nshift\nexec /bin/sh -ec "$1" -- "$3"\n',
        "apk": (
            '#!/bin/sh\ncase "$1" in\n'
            "info) echo python-3.12-3.12.15-r2 ;;\n"
            'version) printf "%s\\n" "$COMPARISON" ;;\n'
            "esac\n"
        ),
        "python3.12": '#!/bin/sh\nprintf "%s\\n" "$@" > "$HASH_ARGUMENTS"\nexit "$HASH_STATUS"\n',
    }
    for name, content in programs.items():
        program = tmp_path / name
        program.write_text(content)
        program.chmod(0o700)
    arguments = tmp_path / "hash-arguments"
    result = subprocess.run(
        ["bash", "-c", _probe_step()["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "RUNNER_TEMP": str(tmp_path),
            "COMPARISON": comparison,
            "HASH_STATUS": str(hash_status),
            "HASH_ARGUMENTS": str(arguments),
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == returncode
    assert arguments.exists() is calls_hash
    if calls_hash:
        assert arguments.read_text().splitlines() == ["-c", 'import hashlib; hashlib.sha224(b"")']


@pytest.mark.parametrize("missing", ["base-reference", "configuration"])
def test_python_pin_probe_configuration_errors_are_fixed(tmp_path: Path, missing: str) -> None:
    if missing != "base-reference":
        (tmp_path / "base-images.txt").write_text("example.invalid/base@sha256:" + "a" * 64 + "\n")
    result = subprocess.run(
        ["bash", "-c", _probe_step()["run"]],
        cwd=tmp_path,
        env={**os.environ, "RUNNER_TEMP": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1
    diagnostic = result.stdout + result.stderr
    assert str(tmp_path) not in diagnostic
    assert "Traceback" not in diagnostic
    assert "could not read" in diagnostic

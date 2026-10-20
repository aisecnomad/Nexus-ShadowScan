"""Frozen npm inputs and receipts for new benchmark-tool installations."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess

import pytest

from tools.benchmark.realworld import install_cdxgen


@pytest.fixture
def frozen_inputs(tmp_path):
    source = tmp_path / "reviewed"
    source.mkdir()
    for name in ("package.json", "package-lock.json"):
        (source / name).write_bytes((install_cdxgen.LOCK_ROOT / name).read_bytes())
    return source


def _fake_npm(monkeypatch, destination, *, failure=None):
    commands = []
    monkeypatch.setattr(
        install_cdxgen.subprocess,
        "check_output",
        lambda command, **kwargs: "v22.23.3\n" if command[0] == "node" else "10.9.9\n",
    )

    def run(command, **kwargs):
        commands.append(command)
        assert kwargs["check"] is True
        if failure == "npm":
            raise subprocess.CalledProcessError(1, command)
        package = destination / "node_modules/@cyclonedx/cdxgen/package.json"
        package.parent.mkdir(parents=True)
        version = "0.0.0" if failure == "version" else "12.8.5"
        package.write_text(json.dumps({"version": version}))
        if failure == "lock":
            (destination / "package-lock.json").write_text("{}\n")

    monkeypatch.setattr(install_cdxgen.subprocess, "run", run)
    return commands


def test_success_receipt_hashes_exact_frozen_inputs(tmp_path, monkeypatch, frozen_inputs):
    destination = tmp_path / "tools with spaces/cdxgen"
    commands = _fake_npm(monkeypatch, destination)
    receipt = install_cdxgen.install(destination, lock_root=frozen_inputs)
    assert commands == [
        [
            "npm",
            "ci",
            "--prefix",
            str(destination.resolve()),
            "--ignore-scripts",
            "--engine-strict",
            "--no-audit",
            "--no-fund",
        ]
    ]
    record = json.loads(receipt.read_text())
    assert record["version"] == "12.8.5"
    assert record["runtime"] == {"node": "v22.23.3", "npm": "10.9.9"}
    assert record["lifecycle_scripts"] == "disabled"
    for name, digest in record["inputs_sha256"].items():
        assert (destination / name).read_bytes() == (frozen_inputs / name).read_bytes()
        assert digest == hashlib.sha256((destination / name).read_bytes()).hexdigest()


@pytest.mark.parametrize("failure", ["npm", "lock", "version"])
def test_failed_install_cannot_retain_a_success_receipt(tmp_path, monkeypatch, frozen_inputs, failure):
    destination = tmp_path / "cdxgen"
    destination.mkdir()
    receipt = destination / "install-receipt.json"
    receipt.write_text('{"version":"old"}\n')
    _fake_npm(monkeypatch, destination, failure=failure)
    with pytest.raises((subprocess.CalledProcessError, ValueError)):
        install_cdxgen.install(destination, lock_root=frozen_inputs)
    assert not receipt.exists()


def test_reviewed_lock_pins_registry_tarballs_with_integrity():
    manifest = json.loads((install_cdxgen.LOCK_ROOT / "package.json").read_text())
    lock = json.loads((install_cdxgen.LOCK_ROOT / "package-lock.json").read_text())
    assert manifest["private"] is True
    assert manifest["dependencies"] == {"@cyclonedx/cdxgen": "12.8.5"}
    assert manifest["overrides"] == {"@cyclonedx/cdxgen": {"undici": "7.29.1"}}
    assert lock["lockfileVersion"] == 3
    assert lock["packages"][""]["dependencies"] == manifest["dependencies"]
    assert len(lock["packages"]) > 1
    assert lock["packages"]["node_modules/undici"]["version"] == "7.29.1"
    for path, package in lock["packages"].items():
        if path:
            assert package["resolved"].startswith("https://registry.npmjs.org/")
            algorithm, encoded = package["integrity"].split("-", 1)
            assert algorithm == "sha512"
            assert len(base64.b64decode(encoded, validate=True)) == 64


def test_preflight_failure_preserves_intact_previous_installation(tmp_path, monkeypatch, frozen_inputs):
    destination = tmp_path / "cdxgen"
    destination.mkdir()
    receipt = destination / "install-receipt.json"
    prior = '{"version":"previous","created":"earlier"}\n'
    receipt.write_text(prior)
    installed_manifest = destination / "package.json"
    installed_manifest.write_text('{"name":"previous"}\n')

    def unavailable(command, **kwargs):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(install_cdxgen.subprocess, "check_output", unavailable)
    with pytest.raises(FileNotFoundError):
        install_cdxgen.install(destination, lock_root=frozen_inputs)
    assert receipt.read_text() == prior
    assert installed_manifest.read_text() == '{"name":"previous"}\n'

"""Local scans start without the HTTP transport, which reads the one policy the engine sets.

Importing ``requests`` and ``urllib3`` cost about 140 ms of a fresh process on the
measured runner, a tenth of a staged pre-commit scan. A scan that opens no
connection must not pay for it, and moving the policy out of the transport must
not create a second policy that a client could read instead.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import shadowscan.engine as engine_module
from shadowscan.utils import http, http_scope
from shadowscan.utils.git import safe_git_env

_SCAN = """
import sys
from shadowscan.cli import main

try:
    main.main(args=sys.argv[1:], prog_name="shadowscan")
except SystemExit as exc:
    code = exc.code
else:
    code = 0
transport = sorted(
    name
    for name in sys.modules
    if name.split(".")[0] in {"requests", "urllib3"} or name == "shadowscan.utils.http"
)
print(code, *transport)
"""


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], env=safe_git_env(), capture_output=True, check=True)


@pytest.mark.parametrize(
    "quick", [False, pytest.param(True, marks=pytest.mark.requires_git_2_45)], ids=["path", "quick"]
)
def test_local_code_scans_never_import_the_http_transport(tmp_path: Path, quick: bool) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("from openai import OpenAI\n\nclient = OpenAI()\n")
    if quick:
        _git(repository, "init", "--quiet")
        _git(repository, "add", "app.py")
    report = tmp_path / "report.json"
    argv = ["code", *(["--quick"] if quick else [str(repository)]), "--format", "json", "-o", str(report)]
    result = subprocess.run(
        [sys.executable, "-c", _SCAN, *argv],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    # Exit 0 and nothing else: the scan completed and loaded no transport module.
    assert result.stdout.split() == ["0"], result.stdout
    # The signature matchers ran: the provider import was found.
    assert json.loads(report.read_text())["findings"]


def test_the_transport_reads_the_policy_the_engine_sets() -> None:
    assert http._allow_private_origin is http_scope._allow_private_origin
    assert http._request_limits is http_scope._request_limits
    for name in ("set_allow_private_origin", "reset_allow_private_origin"):
        assert getattr(http, name) is getattr(http_scope, name) is getattr(engine_module, name)
    for name in ("set_request_deadline", "reset_request_deadline"):
        assert getattr(http, name) is getattr(http_scope, name) is getattr(engine_module, name)
    token = engine_module.set_allow_private_origin(True)
    try:
        assert http._allow_private_origin.get() is True
    finally:
        engine_module.reset_allow_private_origin(token)
    assert http._allow_private_origin.get() is False
    with pytest.raises(TypeError, match="boolean"):
        http_scope.set_allow_private_origin("yes")  # type: ignore[arg-type]

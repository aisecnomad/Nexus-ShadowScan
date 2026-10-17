"""Coverage gaps that say nothing about what a scan established do not make it incomplete.

Ordinary repositories came back incomplete (exit 3), so a CI gate on a nonzero
exit failed on them for good: a JSON transcript or a workflow example that only
mentions MCP keys was parsed as an MCP configuration and rejected, and a
syntax-highlighting sample or a binary attachment under a test directory, test
code whose evidence the scan discounts, was a gap like product code. Each stays
a gap where it can hide something: a file named or shaped as an MCP
configuration, product code, a credential, and every case under
``strict_coverage``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.utils.text import BINARY_CONTENT_ERROR

RANDOM = "R4nd0m9Qx2Vb7Lp6"

TRANSCRIPT = (
    '[\n  {"type": "system", "subtype": "init", "tools": ["Bash", "mcp__github__get_issue"],\n'
    '   "mcp_servers": [{"name": "github", "status": "connected"}]}\n]\n'
)

WORKFLOW_EXAMPLE = """\
name: Issue triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Write the MCP configuration
        run: |
          cat > /tmp/mcp-servers.json << 'EOF'
          {
            "mcpServers": {
              "github": {"command": "docker", "args": ["run", "ghcr.io/github/github-mcp-server"]}
            }
          }
          EOF
"""


def _scan(tmp_path: Path, run_connector, files: dict[str, str | bytes], **options):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
    return run_connector("code.filesystem", path=str(tmp_path), use_git=False, **options)


# ------------------------------------------------------- guessed MCP configs
def test_a_transcript_that_lists_mcp_servers_is_not_an_mcp_configuration(tmp_path, run_connector):
    findings, ctx = _scan(tmp_path, run_connector, {"test/fixtures/sample-turns.json": TRANSCRIPT})
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert not [f for f in findings if f.kind.value == "mcp-server"]


def test_a_workflow_example_that_writes_an_mcp_configuration_is_not_one(tmp_path, run_connector):
    _, ctx = _scan(tmp_path, run_connector, {"examples/issue-triage.yml": WORKFLOW_EXAMPLE})
    assert not ctx.stats.incomplete and not ctx.stats.errors


@pytest.mark.parametrize(
    ("name", "text"),
    [
        # A dedicated MCP configuration name is one whatever it holds.
        (".mcp.json", TRANSCRIPT),
        # A document whose structure declares servers keeps the strict rules.
        ("agents/mcp.yaml", "mcpServers:\n  files:\n    command: npx\n  1: nope\n"),
    ],
)
def test_a_real_mcp_configuration_that_does_not_parse_stays_a_gap(tmp_path, run_connector, name, text):
    _, ctx = _scan(tmp_path, run_connector, {name: text})
    assert ctx.stats.incomplete


# ------------------------------------------------------ discounted test code
NUGET_FIXTURE = '<Project><PackageReference Include="Microsoft.Agents.AI"></Project>'
YAML_FIXTURE = "agents: {first: {}}\nagents: {}\n"


@pytest.mark.parametrize(
    "name",
    [
        "tests/syntax/highlighted/XML/console.csproj",
        "spec/fixtures/agents.yaml",
    ],
)
def test_a_malformed_fixture_in_test_code_is_a_warning(tmp_path, run_connector, name):
    text = NUGET_FIXTURE if name.endswith(".csproj") else YAML_FIXTURE
    _, ctx = _scan(tmp_path, run_connector, {name: text})
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert any(name in warning and "discounted" in warning for warning in ctx.stats.warnings)

    _, strict = _scan(tmp_path, run_connector, {}, strict_coverage=True)
    assert strict.stats.incomplete

    _, included = _scan(tmp_path, run_connector, {}, include_tests=True)
    assert included.stats.incomplete


@pytest.mark.parametrize("name", ["src/console.csproj", "config/agents.yaml"])
def test_a_malformed_file_in_product_code_stays_a_gap(tmp_path, run_connector, name):
    text = NUGET_FIXTURE if name.endswith(".csproj") else YAML_FIXTURE
    _, ctx = _scan(tmp_path, run_connector, {name: text})
    assert ctx.stats.incomplete


def test_ambiguous_source_in_test_code_is_a_warning(tmp_path, run_connector):
    source = "const A = () => <p>src/*.js files</p>;\nconst s = `open\n"
    _, ctx = _scan(tmp_path, run_connector, {"tests/highlighted/Component.js": source})
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert any("incomplete source lexical analysis" in warning for warning in ctx.stats.warnings)
    _, product = _scan(tmp_path / "product", run_connector, {"src/Component.js": source})
    assert product.stats.incomplete


def _binary(payload: str) -> bytes:
    # A PNG-like header puts NUL bytes in the first 8 KiB, so the file is binary.
    return b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00" + payload.encode() + b"\x00\xff\xfe"


def test_a_binary_test_fixture_is_read_for_credentials_and_leaves_the_scan_complete(tmp_path, run_connector):
    fixture = _binary(f'\nCUSTOM_API_KEY = "{RANDOM}"\n')
    findings, ctx = _scan(tmp_path, run_connector, {"tests/mail/attachments/file_png.txt": fixture})
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert any(BINARY_CONTENT_ERROR in warning for warning in ctx.stats.warnings)
    # Credentials are never discounted: the key in the fixture is still found.
    secrets = [f for f in findings if f.kind.value == "secret"]
    assert [f.metadata.get("path") for f in secrets] == ["tests/mail/attachments/file_png.txt"]
    assert RANDOM not in repr([f.to_dict() for f in secrets])


def test_a_binary_file_in_product_code_stays_a_gap(tmp_path, run_connector):
    _, ctx = _scan(tmp_path, run_connector, {"notes/examples.txt": _binary("plain")})
    assert ctx.stats.incomplete
    assert any(BINARY_CONTENT_ERROR in error for error in ctx.stats.errors)


def test_a_binary_test_fixture_stays_a_gap_under_strict_coverage(tmp_path, run_connector):
    _, ctx = _scan(
        tmp_path, run_connector, {"tests/examples/control.txt": _binary("plain")}, strict_coverage=True
    )
    assert ctx.stats.incomplete

"""Opaque multiline YAML secrets never survive source sanitization."""

from __future__ import annotations

import json
import time

import pytest

from shadowscan.utils.redaction import REDACTED, _redact_yaml_multiline_values, sanitize_text

SECRET = "opaque-synthetic-credential"
TAIL = "opaque-private-tail"


@pytest.mark.parametrize("marker", ["|", ">", "|-", ">+", "|2+", ">-2", ""])
@pytest.mark.parametrize("key", ["api_key", '"client_secret"', "'password'"])
def test_yaml_sensitive_block_values_are_redacted(marker, key):
    source = f"{key}: {marker}\n  {SECRET}\n\n  {TAIL}\nmodel: langchain\n"
    clean = sanitize_text(source)
    assert SECRET not in clean and TAIL not in clean
    assert REDACTED in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")
    assert sanitize_text(clean) == clean


@pytest.mark.parametrize("prefix", ["  ", "- ", "  - "])
def test_yaml_continued_plain_secret_respects_nested_mapping_boundary(prefix):
    body = " " * (len(prefix) + 2)
    peer = " " * len(prefix)
    source = f"{prefix}api_key: {SECRET}\n{body}{TAIL}\n{peer}model: langchain\n"
    clean = sanitize_text(source)
    assert SECRET not in clean and TAIL not in clean
    assert "model: langchain" in clean
    assert sanitize_text(clean) == clean


def test_yaml_block_redaction_preserves_unrelated_blocks_and_line_locations():
    source = (
        "description: |\r\n  ordinary documentation\r\n"
        f"password: | # comment\r\n  {SECRET}\r\nname: public\r\n"
    )
    clean = sanitize_text(source)
    assert "ordinary documentation" in clean and "name: public" in clean
    assert SECRET not in clean
    assert clean.count("\n") == source.count("\n")


@pytest.mark.parametrize("scan_secrets", [False, True])
def test_yaml_source_secret_body_is_redacted_before_evidence_selection(tmp_path, run_connector, scan_secrets):
    (tmp_path / "config.yaml").write_text(
        f"api_key: |\n  {SECRET} AgentExecutor(\n  {TAIL}\nmodel: public\n"
        'nodes:\n  - type: "@n8n/n8n-nodes-langchain.agent"\n    name: Researcher\n',
        encoding="utf-8",
    )
    findings, ctx = run_connector(
        "code.filesystem",
        path=str(tmp_path),
        use_git=False,
        scan_secrets=scan_secrets,
    )
    assert findings and not ctx.stats.incomplete
    # Real operational configuration still produces evidence; code-like text
    # inside a secret cannot establish a LangChain agent.
    assert any("platform.n8n" in finding.frameworks for finding in findings)
    assert all("framework.langchain" not in finding.frameworks for finding in findings)
    output = json.dumps([finding.to_dict() for finding in findings])
    assert SECRET not in output and TAIL not in output


# A name that carries a credential only when its value is opaque. The
# single-line 'key: <opaque>' assignment pass already withholds it; the block
# forms below must read the same value the same way.
OPAQUE = "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv"
WRAPPED = ("U3ludGhldGljT3Bh", "cXVlVmFsdWUxMjM0", "NTY3ODkwQWJDZEVm")


@pytest.mark.parametrize("marker", ["|", ">", "|-", ">+", "|2+", ">-2", ""])
@pytest.mark.parametrize("key", ["key", '"key"', "'key'"])
def test_yaml_conditional_name_block_withholds_an_opaque_value(marker, key):
    source = f"{key}: {marker}\n  {OPAQUE}\nmodel: langchain\n"
    clean = sanitize_text(source)
    assert OPAQUE not in clean
    assert REDACTED in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")
    assert sanitize_text(clean) == clean


def test_yaml_conditional_name_block_withholds_a_wrapped_opaque_value():
    """A base64 blob split across lines is one value, not three short tokens."""
    body = "".join(f"    {part}\n" for part in WRAPPED)
    source = f"data:\n  key: |\n{body}kind: Secret\n"
    clean = sanitize_text(source)
    assert all(part not in clean for part in WRAPPED)
    assert REDACTED in clean and "kind: Secret" in clean
    assert clean.count("\n") == source.count("\n")
    assert sanitize_text(clean) == clean


@pytest.mark.parametrize(
    "body",
    [
        "/etc/ssl/private/server.pem",
        "This is the signing key used by the agent service.",
        "CHANGEME",
        "my-agent",
    ],
)
def test_yaml_conditional_name_block_keeps_a_value_that_is_not_a_credential(body):
    """A path, a sentence, a placeholder and a plain name keep their text."""
    source = f"key: |\n  {body}\nmodel: langchain\n"
    clean = sanitize_text(source)
    assert body in clean and REDACTED not in clean
    assert sanitize_text(clean) == clean


def test_yaml_unrelated_name_block_keeps_an_opaque_value():
    """'data' does not name a credential, so its block is not read as one."""
    source = f"data: |\n  {OPAQUE}\nmodel: langchain\n"
    clean = sanitize_text(source)
    assert OPAQUE in clean and REDACTED not in clean


@pytest.mark.parametrize("note", ["# rotate quarterly", "rotated by the platform team"])
@pytest.mark.parametrize("after", [True, False])
def test_yaml_conditional_name_block_with_a_note_withholds_an_opaque_value(note, after):
    """A comment or a sentence beside the value does not make the block prose."""
    lines = [OPAQUE, note] if after else [note, OPAQUE]
    source = "key: |\n" + "".join(f"  {line}\n" for line in lines) + "model: langchain\n"
    clean = sanitize_text(source)
    assert OPAQUE not in clean
    assert REDACTED in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")
    assert sanitize_text(clean) == clean


def test_yaml_conditional_name_block_with_a_note_withholds_a_wrapped_value():
    body = "".join(f"    {part}\n" for part in WRAPPED) + "    # rotate quarterly\n"
    source = f"data:\n  key: |\n{body}kind: Secret\n"
    clean = sanitize_text(source)
    assert all(part not in clean for part in WRAPPED)
    assert REDACTED in clean and "kind: Secret" in clean
    assert clean.count("\n") == source.count("\n")
    assert sanitize_text(clean) == clean


@pytest.mark.parametrize("parent", ["key", "tlsKey"])
def test_yaml_conditional_name_over_a_mapping_leaves_each_entry_to_its_own_name(parent):
    """A bare 'key:' over nested entries is a mapping; its 'key: |' entry is read."""
    body = "".join(f"    {part}\n" for part in WRAPPED)
    source = f"{parent}:\n  algorithm: RS256\n  key: |\n{body}  use: sig\nmodel: langchain\n"
    clean = sanitize_text(source)
    assert all(part not in clean for part in WRAPPED)
    assert "algorithm: RS256" in clean and "use: sig" in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")


def test_yaml_conditional_name_reads_a_plain_scalar_holding_a_colon():
    """'sha256:<opaque>' has no blank after its colon, so it is a value, not a nested key."""
    source = f"key:\n  sha256:{OPAQUE}\nmodel: langchain\n"
    clean = sanitize_text(source)
    assert OPAQUE not in clean and "model: langchain" in clean


@pytest.mark.parametrize(
    ("header", "depth", "blank_lines"),
    [("key:", 1000, 0), ("key: |", 1000, 0), ("'key': x", 1000, 0), ("key:", 300, 50_000)],
)
def test_yaml_nested_conditional_names_are_read_in_linear_time(header, depth, blank_lines):
    # A kept 'key' block was read again from every 'key' line nested in it, and
    # blank lines below the deepest key were read once per key above them:
    # these inputs of 100 to 500 KB took five to twenty seconds.
    source = "".join(" " * level + header + "\n" for level in range(depth)) + "\n" * blank_lines
    started = time.perf_counter()
    assert _redact_yaml_multiline_values(source) == source
    assert time.perf_counter() - started < 1.0

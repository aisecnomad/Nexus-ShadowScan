"""Opaque multiline YAML secrets never survive source sanitization."""

from __future__ import annotations

import json
import time

import pytest

from shadowscan.utils.redaction import REDACTED, _redact_yaml_multiline_values, sanitize, sanitize_text

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


def test_yaml_conditional_name_over_a_bare_conditional_entry_keeps_its_siblings():
    """A nested 'key:' over an opaque line is read under its own name; 'use: sig' stays."""
    source = f"key:\n  key:\n    {OPAQUE}\n  use: sig\nmodel: langchain\n"
    clean = sanitize_text(source)
    assert OPAQUE not in clean and REDACTED in clean
    assert "use: sig" in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")


def _withheld_everywhere(source: str, *secrets: str) -> str:
    """``sanitize_text`` output, after checking that it and ``sanitize`` withhold every secret."""
    clean = sanitize_text(source)
    for output in (clean, sanitize({"evidence": source})["evidence"], sanitize(source)):
        assert not [secret for secret in secrets if secret in output], output
    return clean


# An opaque value on one line, and one a block scalar writes after a '#'.
LINE_OPAQUE = "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8"
HASHED = "Xy7Pq2Lm9Rt4Zz"


@pytest.mark.parametrize("eol", ["\n", "\r\n"])
@pytest.mark.parametrize(
    "lines",
    [
        ["signing:", "  key:", "    private:", f"      {LINE_OPAQUE}", "model: langchain"],
        ["jwtSecret:", "  stringData:", f"    {LINE_OPAQUE}", "model: langchain"],
        ["tlsKey:", "  value:", *(f"    {part}" for part in WRAPPED), "model: langchain"],
        ["tlsKey:", "  value: |", f"    {LINE_OPAQUE}", "model: langchain"],
        ["tlsKey:", "  value: # rotated", f"    {LINE_OPAQUE}", "model: langchain"],
    ],
    ids=["nested-key-private", "jwtSecret-stringData", "tlsKey-value-wrapped", "value-block", "value-note"],
)
def test_yaml_conditional_name_over_an_entry_read_by_nothing_withholds_its_value(lines, eol):
    """'private:', 'stringData:' and 'value:' name no credential, so their value is read here."""
    source = eol.join(lines) + eol
    clean = _withheld_everywhere(source, LINE_OPAQUE, *WRAPPED)
    assert REDACTED in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")
    assert sanitize_text(clean) == clean


def test_yaml_conditional_name_over_a_nested_key_after_a_lone_carriage_return_withholds_it():
    """The mapping pattern starts no line after a lone CR, so the nested 'key:' is not read again."""
    source = f"key:\r  key:\r    {LINE_OPAQUE}\rmodel: langchain\r"
    clean = _withheld_everywhere(source, LINE_OPAQUE)
    assert REDACTED in clean


@pytest.mark.parametrize(
    "source",
    [
        f"pwd: |\n  #{HASHED}\nmodel: langchain\n",
        f"data:\n  tls.key: |-\n    #{HASHED}\nkind: Secret\n",
        f"key: >-\n  #{HASHED}\nmodel: langchain\n",
    ],
)
def test_yaml_conditional_name_block_withholds_a_value_starting_with_a_hash(source):
    """In a block scalar '#' is content: the usual way to write a value that starts with one."""
    clean = _withheld_everywhere(source, HASHED)
    assert REDACTED in clean and ("model: langchain" in clean or "kind: Secret" in clean)
    assert clean.count("\n") == source.count("\n")


@pytest.mark.parametrize(
    "source",
    [
        f"tlsKey:\n  {LINE_OPAQUE}  # rotated 2026-01\nmodel: langchain\n",
        f"key: |\n  {LINE_OPAQUE}  # rotate quarterly\nmodel: langchain\n",
        f"key:\n  - {LINE_OPAQUE}\nmodel: langchain\n",
        f"key:\n  - {LINE_OPAQUE}  # primary\nmodel: langchain\n",
    ],
    ids=["plain-trailing-note", "block-trailing-note", "sequence-entry", "sequence-entry-note"],
)
def test_yaml_conditional_name_reads_a_value_beside_a_trailing_note_or_a_sequence_marker(source):
    clean = _withheld_everywhere(source, LINE_OPAQUE)
    assert REDACTED in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")


@pytest.mark.parametrize(
    "source",
    [
        # The outer block's lines are kept; the nested 'key' and 'pwd' blocks
        # inside it were then never read, and their wrapped value was joined
        # with an outer line that made it a placeholder or a URL.
        "key:\n  # signing material\n  key:\n    Ab1Cd2\n    Ef3Gh4\n  example:\n    a: b\nmodel: langchain\n",
        "key: |\n  rotated by the platform team\n  key: |\n    Ab1Cd2\n    Ef3Gh4\n"
        "  https://kms.internal/rotate\nmodel: langchain\n",
        "key: # signing material\n  pwd: |\n    Ab1Cd\n    2Ef3Gh\n  https://vault.internal/v1/kv\nmodel: langchain\n",
        # A path, a URL or a note beside the wrapped lines at their own indentation.
        "key: |\n  Ab1Cd2\n  Ef3Gh4\n  certs/tls.key\nmodel: langchain\n",
        "key: |\n  Ab1Cd2\n  Ef3Gh4\n  https://kms.internal/rotate\nmodel: langchain\n",
        "key: |\n  Ab1Cd2\n  # rotated by the platform team\n  Ef3Gh4\nmodel: langchain\n",
    ],
    ids=["outer-placeholder", "outer-url", "outer-note-url", "path-after", "url-after", "note-between"],
)
def test_yaml_wrapped_value_is_not_joined_with_a_line_beside_it(source):
    clean = _withheld_everywhere(source, "Ab1Cd", "Ef3Gh4", "2Ef3Gh")
    assert REDACTED in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")


@pytest.mark.parametrize(
    "body",
    [
        "description: |\n    The signing key used by the agent service.\n",
        "path:\n    /etc/ssl/private/server.pem\n",
        "- my-agent  # the agent's own name\n",
    ],
)
def test_yaml_conditional_name_over_text_that_is_not_a_credential_keeps_it(body):
    source = f"key:\n  {body}model: langchain\n"
    clean = sanitize_text(source)
    assert clean == source and REDACTED not in clean


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


@pytest.mark.parametrize(("size", "blank_lines"), [(1_000_000, 0), (200_000, 50_000)])
def test_yaml_alternating_conditional_staircase_is_read_in_linear_time(size, blank_lines):
    # 'x' names no credential, so a bare 'key:' over 'x:' is read whole, and
    # each 'key:' nested in that kept block must not read its subtree again.
    lines: list[str] = []
    written = 0
    while written < size:
        lines.append(" " * len(lines) + ("key:" if len(lines) % 2 == 0 else "x:") + "\n")
        written += len(lines[-1])
    source = "".join(lines) + "\n" * blank_lines
    started = time.perf_counter()
    assert _redact_yaml_multiline_values(source) == source
    assert time.perf_counter() - started < 1.0


@pytest.mark.parametrize(
    ("source", "secrets"),
    [
        # Short wrapped lines at another indentation, and a password with symbols
        # neither of whose lines has an opaque run of its own.
        ("pwd: |\n  b39f\n\t9fc2\nmodel: langchain\n", ("b39f", "9fc2")),
        ("stringData:\n  sshKey: |\n    q7Rk2Xw\n      9pLm4Tz\nmodel: langchain\n", ("q7Rk2Xw", "9pLm4Tz")),
        (
            "pwd: |\n  Kx7!mQ2#Lp9&aB3c\n    D4eF&Rt!9w\nmodel: langchain\n",
            ("Kx7!mQ2#Lp9&aB3c", "D4eF&Rt!9w"),
        ),
        # A '#'-led content line of a '|' or '>' block, joined with the next.
        ("pwd: |\n  #aXV5bY\n  g4Sy\nmodel: langchain\n", ("aXV5bY", "g4Sy")),
        ("tlsKey: >\n  #Kx7!mQ2&Lp9\n  aB3cD4e\nmodel: langchain\n", ("Kx7!mQ2&Lp9", "aB3cD4e")),
        # A line that ends the inner block, whose indentation holds a form feed: it
        # was joined into the inner block's lines in the outer read, made them a
        # placeholder there, and the kept outer block hid the inner one.
        (
            "key:\n  foo:\n    bar\n  key: |\n    Ab1cDe\n    2FgH3i\n  \x0c xxxx\nmodel: langchain\n",
            ("Ab1cDe", "2FgH3i"),
        ),
        # A line indented less than the first piece, inside the block.
        ("key: |+\n    FVM7J\n  9xsGX\n  EQ\nmodel: langchain\n", ("FVM7J", "9xsGX")),
        # The nested 'pwd' block's pieces are joined up to its end, never with the
        # outer placeholder line after it, which hid them when the outer block was kept.
        (
            "key: # material\n  pwd: |\n      Ab1Cd\n    2Ef3Gh\n  xxxxxxxx\nmodel: langchain\n",
            ("Ab1Cd", "2Ef3Gh"),
        ),
        # The same under a sequence entry, whose block ends past its '- ' marker.
        (
            "key: # material\n  - pwd: |\n        Ab1Cd\n      2Ef3Gh\n    xxxxxxxx\nmodel: langchain\n",
            ("Ab1Cd", "2Ef3Gh"),
        ),
    ],
    ids=[
        "tab-indent",
        "deeper-line",
        "symbols",
        "hash-pipe",
        "hash-folded",
        "form-feed",
        "dedent",
        "nested-dedent",
        "nested-entry-dedent",
    ],
)
def test_yaml_wrapped_value_across_indentation_is_withheld(source, secrets):
    clean = _withheld_everywhere(source, *secrets)
    assert REDACTED in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")
    assert sanitize_text(clean) == clean


@pytest.mark.parametrize(
    "properties", ["!!binary |", "&cert |", "!!str", "!secret &a >-", "!<tag:yaml.org,2002:binary> |"]
)
def test_yaml_conditional_name_over_an_entry_with_node_properties_withholds_its_value(properties):
    """A tag or an anchor before the block indicator leaves the value below, which nothing else reads."""
    value = "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2"
    source = f"jwtSecret:\n  value: {properties}\n    {value}\nmodel: langchain\n"
    clean = _withheld_everywhere(source, value)
    assert REDACTED in clean and "model: langchain" in clean
    assert clean.count("\n") == source.count("\n")


DIGEST = "28dbd25e63b229f1c4069545de11cc9dea959c212e9c82b1478c281d687c966c"


@pytest.mark.parametrize(
    ("name", "lines"),
    [
        ("cacheKey:", ["  - ipv4Addr6To4"]),
        ("cacheKey: |", ["  ipv4Addr6To4"]),
        ("sortKey:", ["  - createdAt  # newest first", "  - orderId2"]),
        ("sortKey: |", ["  used for sorting results", f"  sha256:{DIGEST}"]),
        ("key:", [f"  - sha256:{DIGEST}"]),
    ],
)
def test_yaml_conditional_name_keeps_a_line_its_single_line_form_keeps(name, lines):
    """One line under a conditional name is read as 'name: <line>': an identifier or a digest stays."""
    source = "\n".join([name, *lines, "model: langchain"]) + "\n"
    assert sanitize_text(source) == source
    assert sanitize({"evidence": source})["evidence"] == source
    key = name.split(":")[0]
    for line in lines:
        value = line.strip().removeprefix("- ").split("  #")[0]
        assert sanitize_text(f"{key}: {value}") == f"{key}: {value}"


@pytest.mark.parametrize(
    "line",
    ["#Kx7!mQ2&Lp9aB3cD4e", "Kx7!mQ2#Lp9&aB3cD4eF&Rt!9w", f"sha256:{OPAQUE}", f"- {LINE_OPAQUE}  # primary"],
)
def test_yaml_conditional_name_block_withholds_an_opaque_line_the_single_line_pass_never_reads(line):
    """A '#'-led line and one with symbols are block content no 'name: value' reading covers."""
    source = f"pwd: |\n  {line}\nmodel: langchain\n"
    secret = line.lstrip("#- ").split("  #")[0].removeprefix("sha256:")
    clean = _withheld_everywhere(source, secret)
    assert REDACTED in clean and "model: langchain" in clean

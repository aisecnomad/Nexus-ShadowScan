"""Credential call syntax uses bounded parsing and retains ordinary expressions."""

from __future__ import annotations

import time

import pytest

from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize_text

SYNTHETIC = "a8f3c91d7e2b4f6a9d0c2b3e4f5a6c7d"


@pytest.mark.parametrize(
    "template",
    [
        'AzureKeyCredential ("{value}")',
        'AzureKeyCredential\t ("{value}")',
        'AzureKeyCredential\n  ("{value}")',
        'AzureKeyCredential/*synthetic comment*/("{value}")',
        'AzureKeyCredential /*synthetic comment*/ ("{value}")',
        'AzureKeyCredential // synthetic comment\n  ("{value}")',
        'AzureKeyCredential # synthetic comment\n  ("{value}")',
        'AzureKeyCredential(("{value}"))',
        'AzureKeyCredential( ( /*synthetic comment*/ ("{value}") ) )',
        'new AzureKeyCredential($"{value}")',
        'new AzureKeyCredential($@"{value}")',
        'new AzureKeyCredential(@$"{value}")',
        'new AzureKeyCredential($@"first\n{value}")',
        'new AzureKeyCredential(@$"first\n{value}")',
        'new AzureKeyCredential(@"first\n{value}")',
        'new AzureKeyCredential(@"first""quoted\n{value}")',
        'new AzureKeyCredential($@"first""quoted\n{value}")',
        'new AzureKeyCredential($"{{{{literal}}}}{value}")',
        "AzureKeyCredential('''\n{value}\n''')",
        'AzureKeyCredential("""\n{value}\n""")',
        'AzureKeyCredential(r"""\n{value}\n""")',
        'AzureKeyCredential("""\n{value}\nsynthetic second line\n""")',
        'AzureKeyCredential credential = new ("{value}");',
        'builder().apiKey /*synthetic comment*/ ("{value}")',
        'builder()\n  .apiKey /*synthetic comment*/ ("{value}")',
        'AzureKeyCredential(key=("{value}"))',
    ],
)
def test_recognizable_credential_call_syntax_withholds_literal(template):
    source = template.format(value=SYNTHETIC) + '\nnext_call("ordinary")'
    safe = sanitize_text(source)
    assert SYNTHETIC not in safe
    assert REDACTED in safe
    assert safe.endswith('\nnext_call("ordinary")')
    assert source.count("\n") == safe.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "expression",
    [
        'Environment.GetEnvironmentVariable("K") ?? "{value}"',
        'Environment.GetEnvironmentVariable("K") ?? ("{value}")',
        '(Environment.GetEnvironmentVariable("K") ?? ("{value}"))',
        'Environment.GetEnvironmentVariable("K") /*synthetic comment*/ ?? "{value}"',
        'os.getenv("K") or "{value}"',
        'os.environ.get("K") or "{value}"',
        'System.getenv("K") ?: "{value}"',
        'os.Getenv("K") || "{value}"',
    ],
)
@pytest.mark.parametrize("value", [SYNTHETIC, "hunter2hunter"])
def test_constructor_context_withholds_environment_literal_fallback(expression, value):
    source = "new AzureKeyCredential(" + expression.format(value=value) + ")"
    safe = sanitize_text(source)
    assert value not in safe
    assert '"K"' in safe
    assert REDACTED in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "source",
    [
        f'ordinaryCall /*synthetic comment*/ (("{SYNTHETIC}"))',
        f'ordinaryCall (Environment.GetEnvironmentVariable("K") ?? "{SYNTHETIC}")',
        'new AzureKeyCredential($"{prefix}{suffix}")',
        'new AzureKeyCredential($@"first\n{prefix}{suffix}")',
        'new AzureKeyCredential(@$"first\n{prefix}{suffix}")',
        'AzureKeyCredential(f"{prefix}{suffix}")',
        'AzureKeyCredential(("${AZURE_OPENAI_KEY}"))',
        'AzureKeyCredential /*synthetic comment*/ ("YOUR_API_KEY")',
        'AzureKeyCredential("""\n<your-api-key>\n""")',
        'AzureKeyCredential("""\n<your api key>\n""")',
        'new AzureKeyCredential(@"\n<your api key>\n")',
        'new AzureKeyCredential($@"\n<your api key>\n")',
        'AzureKeyCredential(Environment.GetEnvironmentVariable("K") ?? "YOUR_API_KEY")',
        'AzureKeyCredential(Environment.GetEnvironmentVariable("K"))',
        "94 | Cosmetic | Spelling error on Login ('log|n')",
        'get_password ("admin")',
        'requireAuth /*synthetic comment*/ ("admin")',
        'HTTPBasicAuth (("user"), ("${PASSWORD}"))',
    ],
)
def test_noncredential_calls_names_references_and_computed_arguments_are_preserved(source):
    assert sanitize_text(source) == source


def test_a_key_inside_a_computed_argument_of_a_credential_callee_is_withheld():
    # The call pass keeps a computed argument's shape, but an opaque literal in
    # it is still the key the credential-named callee is given (the line-tail
    # pass reads a callee's arguments as it reads a credential's value).
    safe = sanitize_text(f'AzureKeyCredential(str("{SYNTHETIC}"))')
    assert safe == f'AzureKeyCredential(str("{REDACTED}"))'
    assert sanitize_text(safe) == safe


def test_authentication_pair_keeps_user_and_withholds_wrapped_password():
    source = 'HTTPBasicAuth (("user"), ("hunter2hunter"))'
    safe = sanitize_text(source)
    assert '"user"' in safe
    assert "hunter2hunter" not in safe
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("prefix", ["@", "$@", "@$"])
def test_unterminated_verbatim_credential_literal_is_withheld_to_eof(prefix):
    source = f'new AzureKeyCredential({prefix}"first\n{SYNTHETIC}'
    safe = sanitize_text(source)
    assert SYNTHETIC not in safe
    assert REDACTED in safe
    assert source.count("\n") == safe.count("\n")
    assert sanitize_text(safe) == safe


def test_excessively_nested_constructor_fails_closed():
    source = "AzureKeyCredential(" + "(" * 40 + f'"{SYNTHETIC}"' + ")" * 41
    with pytest.raises(SanitizationLimitError, match="credential call nesting limit"):
        sanitize_text(source)


def test_call_trivia_obeys_shared_work_budget(monkeypatch):
    monkeypatch.setattr(redaction, "_MAX_REDACTION_WORK", 8)
    with pytest.raises(SanitizationLimitError, match="credential call work limit"):
        redaction._redact_credential_calls("AzureKeyCredential" + " " * 16 + f'# note\n("{SYNTHETIC}")')


def test_dense_comment_callee_candidates_scale_linearly():
    # Each name used to seek the same comment end. Indexed line/block ends
    # make four times the candidates cost approximately four times the work.
    def best_time(repeats):
        source = "ordinary#" * repeats + '\n("ordinary")'
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            redaction._redact_credential_calls(source)
            best = min(best, time.perf_counter() - started)
        return best

    small = best_time(1000)
    assert best_time(4000) < max(small, 0.02) * 10


def _call_lexer_work(source: str, monkeypatch: pytest.MonkeyPatch) -> int:
    """The call lexer's work units (ticks) for ``source``: a count, not a clock."""
    ticks = 0
    tick = redaction._CallLexer.tick

    def counted(self: redaction._CallLexer) -> None:
        nonlocal ticks
        ticks += 1
        tick(self)

    monkeypatch.setattr(redaction._CallLexer, "tick", counted)
    redaction._redact_credential_calls(source)
    return ticks


@pytest.mark.parametrize(
    "line",
    [
        "# a comment line that ends with a word",
        "// a comment line that ends with a word",
        "/* a comment that ends with a word */",
        "-- a word",
    ],
)
def test_consecutive_comment_lines_are_skipped_once(line, monkeypatch):
    # A word before a line break or comment is a callee candidate, and each one
    # skipped the trivia after it to look for '('. In a block of comment lines
    # every line's last word did so again: n lines cost n * n / 2 skips, and a
    # 1 MB block reached the work limit after about two minutes.
    def work(lines):
        return _call_lexer_work('x = "a"\n' + (line + "\n") * lines + "main()\n", monkeypatch)

    small, large = work(1000), work(8000)
    assert large <= small * 12, (small, large)


def test_the_arguments_after_a_comment_block_are_lexed_once(monkeypatch):
    # Every word of the block reached the same '(' as a callee and lexed and
    # judged its argument list again: 8000 lines before a long call took 48 s.
    arguments = "(" + ",".join(["a"] * 2000) + ")"

    def work(call):
        return _call_lexer_work('x = "a"\n' + "# comment word\n" * 4000 + call + "\n", monkeypatch)

    assert work(arguments) - work("()") <= 4 * len(arguments)


@pytest.mark.parametrize("trivia", ["# note\n", "// note\n", "/* note */\n", "\n", " \\\n"])
def test_a_callee_many_comment_lines_before_its_parenthesis_is_still_read(trivia):
    source = "AzureKeyCredential\n" + trivia * 200 + f'("{SYNTHETIC}")\nnext_call("ordinary")'
    safe = sanitize_text(source)
    assert SYNTHETIC not in safe and REDACTED in safe
    assert safe.endswith('\nnext_call("ordinary")') and safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


def test_a_credential_callee_named_inside_a_comment_still_reads_the_call_after_it():
    # Every candidate whose trivia reaches the same '(' is still read as its callee.
    source = f'x = build  # wraps AzureKeyCredential\n# more\n("{SYNTHETIC}")'
    safe = sanitize_text(source)
    assert SYNTHETIC not in safe and REDACTED in safe


# The step bound cannot tell a long argument list from one that never closes.
# Prose naming a credential type ('`ClientSession(`' in markdown, a comment that
# quotes 'credential (') reached it and withheld every excerpt of the file.
_PROSE = "Prose (with an aside) and ordinary words follow here.\n" * 400


@pytest.mark.parametrize(
    "opening",
    [
        "Match `ClientSession(` and `Server(` here; a stray ` tick.\n",
        "# The rule read the operator as the credential ('bearer\n# [REDACTED]> S'), then.\n",
        "    # 'builder().apiKey(', '\\n    .apiKey(', 'client?.token('. The leading\n",
    ],
)
def test_an_unclosed_credential_named_call_in_prose_is_read_to_its_end(opening):
    # Read to its end, the call is unclosed: a leading literal of a credential
    # constructor ('bearer) is still withheld, the prose after it is not.
    source = opening + _PROSE
    safe = sanitize_text(source)
    assert safe.count("\n") == source.count("\n")
    assert safe.endswith(_PROSE)


def test_a_long_credential_constructor_still_withholds_its_literal():
    source = 'HTTPBasicAuth("user", ' + "a, " * 5000 + f'"{SYNTHETIC}")\nprint("visible")\n'
    safe = sanitize_text(source)
    assert SYNTHETIC not in safe and REDACTED in safe
    assert safe.splitlines()[1] == 'print("visible")'
    unclosed = sanitize_text(source.replace('")\nprint', '"\nprint'))
    assert SYNTHETIC not in unclosed and REDACTED in unclosed


def test_a_long_call_pairing_a_credential_key_still_withholds_its_value():
    source = 'os.environ.setdefault("OPENAI_API_KEY", (' + "a + " * 4000 + f'"{SYNTHETIC}"))\n'
    safe = redaction._redact_credential_calls(source)
    assert SYNTHETIC not in safe and REDACTED in safe


def test_reading_past_the_step_bound_shares_one_budget_and_fails_closed(monkeypatch):
    # Every credential call past the step bound draws on one budget per text,
    # linear in its length; once it is spent the call fails closed as before.
    monkeypatch.setattr(redaction, "_MAX_CALL_STEPS", 64)
    monkeypatch.setattr(redaction, "_CALL_EXTENSION_PER_CHAR", 2)
    tail = "plain line of 'text'\n" * 2000
    assert redaction._redact_credential_calls("#getToken(\n" + tail).endswith(tail)
    with pytest.raises(SanitizationLimitError, match="credential call length limit"):
        redaction._redact_credential_calls("#getToken(\n" * 3 + tail)


def test_reading_past_the_step_bound_stays_linear(monkeypatch):
    # Credential-named and ordinary callees cost the same up to the step bound;
    # the credential ones then read on only within the text's extension budget.
    tail = "plain line of text here\n" * 40_000
    ticks = 0
    tick = redaction._CallLexer.tick

    def counted(self: redaction._CallLexer) -> None:
        nonlocal ticks
        ticks += 1
        tick(self)

    monkeypatch.setattr(redaction._CallLexer, "tick", counted)

    def work(source):
        nonlocal ticks
        ticks = 0
        try:
            redaction._redact_credential_calls(source)
        except SanitizationLimitError:
            pass  # the budget ran out: the call fails closed
        return ticks

    source = "'x'\n" + "#getToken(\n" * 200 + tail
    extra = work(source) - work(source.replace("getToken", "getThing"))
    assert 0 < extra <= redaction._CALL_EXTENSION_PER_CHAR * len(source) + 64


def test_a_completed_call_that_never_closes_keeps_the_unclosed_call_rules():
    # Read to its end, the call is still open. It is redacted exactly as the
    # same call shorter than the step bound, whether its literal past the bound
    # is terminated or runs to the end of its line.
    def call(arguments: int, value: str) -> str:
        return 'HTTPBasicAuth("user", ' + "a, " * arguments + value + '\nafter = "trailing"\n'

    for value in (f'"{SYNTHETIC}",', f'"{SYNTHETIC}'):
        long_safe = sanitize_text(call(5000, value))
        short_safe = sanitize_text(call(50, value))
        assert SYNTHETIC not in long_safe and REDACTED in long_safe
        assert long_safe.endswith(short_safe[-100:])


def test_nesting_found_while_completing_a_call_still_fails_closed():
    # The completed reading keeps the nesting bound of the first one.
    source = 'HTTPBasicAuth("user", ' + "a, " * 5000 + "(" * 40 + f'"{SYNTHETIC}"' + ")" * 41 + "\n"
    with pytest.raises(SanitizationLimitError, match="credential call nesting limit"):
        redaction._redact_credential_calls(source)

"""Sensitive values in assignments, mappings and fallback defaults inside text.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. ``name=value`` and ``name: value`` pairs under sensitive names, whole
mapping expressions and indented YAML blocks under sensitive keys, opaque
literals given to names whose last word names a credential, and literal
defaults of credentials read from the environment.
"""

from __future__ import annotations

import bisect
import re
from typing import NamedTuple

from shadowscan.utils.redaction_rules import (
    _CALLEE_WORD,
    _CLI_WORD,
    _COMPARISONS,
    _FILE_PATH,
    _FINGERPRINT,
    _OPERATOR,
    _VALUE_SEMICOLON,
    REDACTED,
    SanitizationLimitError,
    _blanks_before,
    _credential_literal,
    _credential_name,
    _environment_lookup,
    _interpolated,
    _kept_value,
    _name_before,
    _redact_value,
    _sensitive_assignment_key,
    _withhold_spans,
    password_literal,
)

# A key must be consumed in full: truncating it to a fixed number of characters
# can leave an opaque credential in evidence when the sensitive suffix follows
# that limit. The left boundary includes every character accepted by the key
# lexer (including '.' and '-'), preventing retries at interior key segments.
# Text size and redaction work are bounded separately below. An unquoted
# key's colon stays on its line: a YAML parent ('openai:') must not consume the
# nested sensitive key on the next line as its own value. A quoted key may also
# be assigned with '=' (PowerShell hashtables, TOML quoted keys). An unquoted
# value stops at ']' unless that ']' closes a marker: cut inside the marker, a
# nested sensitive assignment ('Value: a.api_key=[REDACTED]') withheld
# '[REDACTED' again and grew the marker by one ']' on every pass. After such a
# marker it also stops at a query separator: 'sv=1&sig=[REDACTED]&Authorization:'
# must leave the next parameter's name to be read with its own value.
# Quotes may be escaped (JSON inside a string literal, up to eight levels), in
# which case the closing delimiter must repeat the opening one exactly. A ';'
# inside an unquoted value follows _VALUE_SEMICOLON.
_ESCAPED_QUOTE = re.compile(r"\\{1,8}[\"']")
# A quoted value reads past the quotes a backslash escapes: '"log": "password:
# \"v\""' is one string. Closed at the escaped quote, the string ended before
# its credential, which was then read outside it and shown. Each run is
# possessive and ends at a quote no backslash escapes, so a line is read once.
# On a line without such a quote, or where the text before it ends with an
# assignment operator (that quote opens the next value: 'k="a\" password="v"'),
# the value closes at its first quote, as the former rule (_FIRST_QUOTE) did.
_NOT_AFTER_OPERATOR = r"(?<![=:>~])(?<![=:>~][ \t])"
_ESCAPE_AWARE_QUOTE = (
    r"\"(?:\\[^\r\n]|[^\"\\\r\n])*+" + _NOT_AFTER_OPERATOR + r"\""
    r"|'(?:\\[^\r\n]|[^'\\\r\n])*+" + _NOT_AFTER_OPERATOR + "'"
)
_FIRST_QUOTE = r"\"[^\"\r\n]*\"|'[^'\r\n]*'"
# Each level of escaping doubles a backslash and adds one before a quote, so
# inside a value whose delimiter is k backslashes and a quote, the value's own
# quote is 2k + 1 of them ('\\\\\\"' for k = 1) and a backslash that ends the
# value adds 2k + 2 before the closing delimiter. A run of backslashes and
# that quote closes the value only when the run, read whole, is k plus a
# multiple of 2k + 2: read as the opener's tail, the value's own quote ended
# it early and the rest of the value was shown.
_ESCAPED_CLOSER = r"(?:(?P=run)(?P=run)\\\\)*+(?P=escaped)"


def _assignment_pattern(quoted: str) -> re.Pattern[str]:
    """The assignment lexer whose quoted values are read by ``quoted``."""
    return re.compile(
        r"(?P<key>(?<![\w.-])[A-Za-z_][A-Za-z0-9_.-]*)"
        r"(?P<sep>\\{0,8}[\"']\s*:(?!=)\s*|[\"'][ \t]*" + _OPERATOR + r"[ \t]*|\s*" + _OPERATOR + r"\s*"
        r"|:[ \t]+|:[ \t]*(?=\\{0,8}[\"']))"
        r"(?P<value>\[REDACTED\]|"
        + quoted
        + r"|(?P<escaped>(?P<run>\\{1,8})[\"'])(?:[^\\\r\n]++|\\++(?![\"'])|(?!"
        + _ESCAPED_CLOSER
        + r")\\++[\"'])*+"
        + _ESCAPED_CLOSER
        + r"|\\{1,8}[\"'][^\r\n]*"
        + r"|[^\s,;\}\]\)\"']+(?:"
        + _VALUE_SEMICOLON
        + r"[^\s,;\}\]\)\"']*|(?<=\[REDACTED)\][^\s,;\}\]\)\"'&]*)*)"
    )


_ASSIGNMENT = _assignment_pattern(_ESCAPE_AWARE_QUOTE + "|" + _FIRST_QUOTE)
# The former reading, run after _ASSIGNMENT on its result (see _redact_plain_assignments).
_FIRST_QUOTE_ASSIGNMENT = _assignment_pattern(_FIRST_QUOTE)


def _unquote(raw: str, escaped: str | None) -> tuple[str, str, str]:
    """Split a lexed value into its opening quote, content and closing quote."""
    if escaped:
        return escaped, raw[len(escaped) : -len(escaped)], escaped
    if raw[:1] in {'"', "'"}:
        closed = len(raw) > 1 and raw[-1] == raw[0]
        return raw[0], raw[1:-1] if closed else raw[1:], raw[0] if closed else ""
    unclosed = _ESCAPED_QUOTE.match(raw)
    if unclosed:
        return unclosed.group(0), raw[unclosed.end() :], ""
    return "", raw, ""


_MAPPING_VALUE = re.compile(
    r"(?<![\w.-])(?:(?P<quote>[\"'])(?P<quoted>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)"
    r"|(?P<plain>[A-Za-z_][A-Za-z0-9_.-]*))[ \t]*(?::|=>)[ \t]*"
    r"(?P<value>[\"'`\[\{(])"
)
_YAML_MAPPING_LINE = re.compile(
    r"^(?P<prefix>[ \t]*(?:-[ \t]+)*)(?:(?P<quote>[\"'])"
    r"(?P<quoted>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote)"
    r"|(?P<plain>[A-Za-z_][A-Za-z0-9_.-]*))[ \t]*:[ \t]*"
    r"(?P<value>[^\r\n]*)",
    re.MULTILINE,
)
_YAML_CONTINUATION_LINE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n|\Z)")
# A comment after a plain scalar on its line (' # rotated 2026-01') starts at
# the blank before its '#'. Searched as '[ \t]+#', a long run of blanks would
# be read again from each of its blanks. Then the markers of a block sequence
# entry ('- ', '- - ').
_YAML_TRAILING_NOTE = re.compile(r"[ \t]#")
_YAML_ENTRY_MARKERS = re.compile(r"(?:-[ \t]+)+")
# What follows 'name:' when the entry's value is on the lines below: nothing,
# a block scalar header ('|', '>-', '|2+') or only a comment, after any node
# properties: tags ('!!binary', '!secret', '!<tag:yaml.org,2002:str>') and an
# anchor ('&cert'). Each property and the blanks after it are read once
# (possessively), so a long run of blanks is not read again from each blank.
_YAML_VALUE_BELOW = re.compile(
    r"(?:(?:![^ \t\r\n]*+|&[^ \t\r\n]++)(?:[ \t]++|$))*+(?:[|>][0-9+-]*)?(?:[ \t]*#[^\r\n]*)?[ \t]*"
)


def _line_readings(line: str) -> list[str]:
    """A dedented block line, then the same line without a trailing note and sequence markers.

    The line itself is always read: in a '|' or '>' block a '#' is content.
    """
    readings = [line]
    note = _YAML_TRAILING_NOTE.search(line)
    if note is not None:
        line = line[: note.start()].rstrip()
        readings.append(line)
    markers = _YAML_ENTRY_MARKERS.match(line)
    if markers is not None:
        readings.append(line[markers.end() :])
    return readings


def _value_part(text: str) -> bool:
    """Whether a dedented block line can be part of a wrapped value.

    A line starting with '#', a sentence, a URL and a path cannot: joined
    into the value, each kept the credential beside it.
    """
    return not (
        text.startswith("#")
        or any(char.isspace() for char in text)
        or "://" in text
        or _FILE_PATH.fullmatch(text) is not None
    )


# A character outside the base64 and URL-safe alphabet of the value the
# single-line pass reads after 'key: ' (``_OPAQUE_VALUE``), and a digest
# written after its algorithm ('sha256:<hex>'), which keeps its text there.
_UNREAD_CHARACTER = re.compile(r"[^A-Za-z0-9+/_.~=\s-]")
_LABELLED_DIGEST = re.compile(r"[A-Za-z][A-Za-z0-9_.+-]*:[0-9A-Fa-f]+")


def _entry_depth(line: str) -> int | None:
    """Where the block of a block line that is a mapping entry ends, or None for any other line.

    An entry is a line with its value below or after a blank ('name:',
    'name: |', 'name: v'), or under a name this pass reads ('key:v'). A colon
    followed by text otherwise makes a plain scalar ('sha256:<hex>'). Its block
    ends at the first line indented no deeper than its key, sequence markers
    included ('- name: |'), as ``_redact_yaml_multiline_values`` measures it.
    """
    entry = _YAML_MAPPING_LINE.match(line)
    if entry is None:
        return None
    name = entry.group("quoted") or entry.group("plain")
    if (
        entry.group("value")
        and line[entry.start("value") - 1] not in " \t"
        and not (_credential_name(name) or _sensitive_assignment_key(name))
    ):
        return None
    return len(entry.group("prefix").expandtabs(8))


def _joined_values(groups: list[list[str]]) -> list[str]:
    """Each group of value lines joined, then all of them joined when there are several.

    A group of one line is left out: that line is tested on its own.
    """
    values = ["".join(group) for group in groups if len(group) > 1]
    if sum(1 for group in groups if group) > 1:
        values.append("".join("".join(group) for group in groups))
    return values


def _single_line_credential(text: str) -> bool:
    """Whether one block line, read on its own, is a credential.

    A line of base64 and URL-safe characters, or one with blanks, is read as
    the single-line pass reads the value of a conditional name ('key: <line>',
    see ``_redact_opaque_assignments``): its first token, quoted or a bare
    token that is not made of words (``_wordy``, unless digits split it into
    short fragments), is a credential when ``_credential_literal`` accepts it.
    An identifier ('ipv4Addr6To4') therefore keeps its text, as on one line.

    That pass reads no value from any other line without blanks, which is
    tested as it is, as a joined value is: one starting with '#', which in a
    '|' or '>' block is content, and one holding another character
    ('Kx7!mQ2&Lp9aB3cD4e', 'sha256:<opaque>'). A digest after its algorithm
    ('sha256:<hex>') keeps its text, as it does after 'key: '.
    """
    if not any(char.isspace() for char in text) and (
        text.startswith("#") or _UNREAD_CHARACTER.search(text) is not None
    ):
        return _LABELLED_DIGEST.fullmatch(text) is None and _credential_literal(text, positional=False)
    match = _OPAQUE_VALUE.match(": " + text)
    if match is None:
        return False
    if match.group("quoted") is not None:
        value = match.group("quoted")
        if _interpolated(match.group("prefix") or "", match.group("quote"), value):
            return False
    else:
        value = match.group("bare")
        if _wordy(value) and not _opaque_identifier(value):
            return False
    return _credential_literal(value, positional=False)


def _opaque_block_credential(lines: list[str]) -> bool:
    """Whether a block scalar's own content is an opaque credential.

    Read for a name that carries a credential only when its value is opaque
    ('key'), the way the single-line assignment pass reads one. ``lines`` are
    the block's non-blank lines with their indentation, the blanks and tabs
    before the text, as the block boundary measures it.

    Each line is tested on its own as the single-line pass reads a value
    (``_single_line_credential``): as it is, without a trailing ' # note' and
    without leading '- ' markers ('key:' over '- <opaque>').

    Lines are also joined without a separator, so that a wrapped base64 blob
    is tested as the one value it encodes, and a value joined from two lines
    or more is a credential when ``_credential_literal`` accepts it.
    Consecutive lines at one indentation that can be part of a value
    (``_value_part``: not a note, a sentence, a URL or a path, which hid the
    credential beside them) are joined, the groups on either side of such a
    line apart and together. Each maximal run of lines without whitespace is
    also joined across indentation ('b39f' over a tab-indented '9fc2'),
    '#'-led lines included ('#aXV5bY' over 'g4Sy'). A run ends at a line that
    cannot be joined, at a mapping entry (``_entry_depth``) and where the
    block of the innermost entry above its first line ends. A nested block
    therefore yields the lines, groups and runs it yields when read alone,
    and a kept outer block never shows a value that a nested 'key:' inside
    it would withhold.

    Joining can also read a few short lines as one opaque value ('Alpha1' over
    'Beta2'). That withholds a little more than a line-by-line test would under
    a name like 'key', which is the safer direction here: testing each line on
    its own would keep every wrapped credential, the case this pass exists for.
    """
    joined: list[str] = []
    # The value lines at the current indentation, in groups split by lines
    # that cannot be part of a value.
    groups: list[list[str]] = [[]]
    depth = -1
    # Where the blocks of the mapping entries above the current line end,
    # innermost last; the current run across indentation; and where the
    # block of the innermost entry above its first line ends, which ends it.
    entries: list[int] = []
    run: list[str] = []
    run_limit = -1
    for line in lines:
        text = line.lstrip(" \t")
        if any(_single_line_credential(reading) for reading in _line_readings(text)):
            return True
        indent = len(line[: len(line) - len(text)].expandtabs(8))
        while entries and entries[-1] >= indent:
            entries.pop()
        if indent != depth:
            joined.extend(_joined_values(groups))
            groups = [[]]
            depth = indent
        if _value_part(text):
            groups[-1].append(text)
        elif groups[-1]:
            groups.append([])
        entry = _entry_depth(line)
        continues = entry is None and _value_part(text.lstrip("#"))
        if not continues or indent <= run_limit:
            if len(run) > 1:
                joined.append("".join(run))
            run = []
        if continues:
            if not run:
                run_limit = entries[-1] if entries else -1
            run.append(text)
        if entry is not None:
            entries.append(entry)
    joined.extend(_joined_values(groups))
    if len(run) > 1:
        joined.append("".join(run))
    return any(_credential_literal(value, positional=False) for value in joined)


def _entry_read_on_its_own(text: str, line_start: int, content: str) -> bool:
    """Whether the first line under a bare conditional name is an entry read under its own name.

    A bare 'key:' over a nested mapping holds a collection, not an opaque
    scalar, and is left to its entries when each is read again: an entry with
    its value on its line by the line pass, one whose value is on the lines
    below ('id:', 'id: |') only when this pass reads its name. Otherwise the
    whole block is read here, as an entry like 'stringData:' over an opaque
    line is never read again. A colon followed by text ('sha256:<opaque>')
    makes a plain scalar, not an entry. The mapping pattern starts no line
    after a lone carriage return, so an entry there is never read again either.
    """
    nested = _YAML_MAPPING_LINE.match(content)
    if nested is None or (line_start > 0 and text[line_start - 1] != "\n"):
        return False
    value = nested.group("value")
    if value and content[nested.start("value") - 1] not in " \t":
        return False
    if not _YAML_VALUE_BELOW.fullmatch(value):
        return True
    name = nested.group("quoted") or nested.group("plain")
    return _credential_name(name) or _sensitive_assignment_key(name)


def _redact_yaml_multiline_values(text: str) -> str:
    """Withhold indented sensitive YAML values before line-based excerpting.

    Literal/folded blocks and continued plain scalars can contain opaque
    credentials with no recognizable token prefix. Consume their indentation
    boundary once, without loading or executing the untrusted source. Preserve
    newline counts for evidence locations and the following peer mapping.

    A name that always carries a credential ('password') withholds its block
    whatever it holds. A name that carries one only when the value is opaque
    ('key') withholds its block only then, so that a Kubernetes secret's
    'key: |' is read like the single-line 'key: <opaque>' the assignment pass
    already withholds, while 'key: |' over a path or a sentence keeps its text.
    """
    pieces: list[str] = []
    cursor = 0
    # The end of the last conditionally named block that was kept. A mapping
    # line inside it is that block's text, already read; reading it again from
    # every 'key' line nested in it took seconds on a few hundred kilobytes.
    kept_until = 0
    for match in _YAML_MAPPING_LINE.finditer(text):
        key = match.group("quoted") or match.group("plain")
        if match.start() < cursor:
            continue
        always_sensitive = _sensitive_assignment_key(key)
        # A conditionally sensitive name is decided by the block's content below.
        if not always_sensitive and (not _credential_name(key) or match.start() < kept_until):
            continue
        value = match.group("value").strip()
        # Quoted and flow-style values are consumed by the mapping lexer.
        if value.startswith(('"', "'", "`", "[", "{", "(")):
            continue
        start = match.start("value")
        end = match.end()
        position = end
        if text.startswith("\r\n", position):
            position += 2
        elif text.startswith(("\n", "\r"), position):
            position += 1
        else:
            continue
        indent = len(match.group("prefix").expandtabs(8))
        has_continuation = False
        content_lines: list[str] = []
        while position < len(text):
            line = _YAML_CONTINUATION_LINE.match(text, position)
            assert line is not None
            raw = line.group(0)
            content = raw.rstrip("\r\n")
            whitespace = len(content) - len(content.lstrip(" \t"))
            if content.strip() and len(content[:whitespace].expandtabs(8)) <= indent:
                break
            if (
                not always_sensitive
                and not value
                and not has_continuation
                and content.strip()
                and _entry_read_on_its_own(text, position, content)
            ):
                break
            has_continuation = has_continuation or bool(content.strip())
            if content.strip():
                content_lines.append(content.rstrip())
            end = line.end()
            position = end
        if not has_continuation:
            continue
        if not always_sensitive and not _opaque_block_credential(content_lines):
            kept_until = end
            continue
        pieces.append(text[cursor:start])
        pieces.append('"' + REDACTED + '"' + "\n" * text[start:end].count("\n"))
        cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


def _mapping_expression_end(text: str, start: int, *, owed: int = 0) -> int:
    """Find a mapping value's delimiter without evaluating source code.

    Quoted scalars, escaped/doubled quotes, concatenations and nested containers
    are consumed in full. Malformed expressions are withheld through EOF.
    Values are visited once and nesting is bounded before allocating more work.
    ``owed`` closing brackets (')' or ']') whose opener an earlier pass
    withheld are read as part of the value rather than as its end.
    """
    position = start
    brackets: list[str] = []
    while position < len(text):
        char = text[position]
        if char in "\"'`":
            delimiter = char
            if char != "`" and text.startswith(char * 3, position):
                delimiter = char * 3
            position += len(delimiter)
            while position < len(text):
                if text[position] == "\\":
                    position += 2
                elif text.startswith(delimiter, position):
                    # YAML escapes a single quote by doubling it. Consuming
                    # adjacent Python literals here is equally conservative.
                    if delimiter == "'" and text.startswith("''", position):
                        position += 2
                        continue
                    position += len(delimiter)
                    break
                else:
                    position += 1
            else:
                return len(text)
            continue
        if char in "([{":
            if len(brackets) >= 64:
                raise SanitizationLimitError("mapping expression nesting limit exceeded")
            brackets.append(char)
        elif char in ")]}":
            if not brackets and owed and char != "}":
                owed -= 1
            elif not brackets:
                return position
            elif brackets.pop() != {")": "(", "]": "[", "}": "{"}[char]:
                return len(text)
        elif not brackets and char in ",;\r\n#":
            return position
        position += 1
    return len(text)


def _line_quote(text: str, quote: str, start: int) -> int | None:
    """Position of the next ``quote`` on the line starting at ``start``, or None."""
    position = text.find(quote, start)
    if position == -1:
        return None
    line_end = min(
        (end for end in (text.find("\n", start), text.find("\r", start)) if end != -1), default=len(text)
    )
    return position if position < line_end else None


def _redact_mapping_values(text: str) -> str:
    """Withhold full sensitive mapping expressions before excerpt shortening."""
    pieces: list[str] = []
    cursor = 0
    for match in _MAPPING_VALUE.finditer(text):
        key = match.group("quoted") or match.group("plain")
        if match.start() < cursor or not _sensitive_assignment_key(key):
            continue
        start = match.start("value")
        if text.startswith(REDACTED, start) and match.start() > 0 and text[match.start() - 1] in "\"'":
            # An earlier pass left a bare marker inside a quoted string
            # ('-H "x-api-key:[REDACTED]" https://…'). The string's closing
            # quote ends the value: what sits between the marker and it is
            # withheld with the marker, and nothing there leaves the text as
            # it is. Read as a '[' expression, the quote would start a string
            # that runs to the end of the text, on every sanitization.
            after = start + len(REDACTED)
            close = _line_quote(text, text[match.start() - 1], after)
            if close is not None:
                kept = text[after:close].rstrip("\\")
                if not kept.replace(REDACTED, "").strip():
                    continue
                pieces.append(text[cursor:start])
                pieces.append(REDACTED + text[after + len(kept) : close])
                cursor = close
                continue
        # A marker before a quote stands for a read cut at its call or subscript
        # ('api_key: os.environ[' of "os.environ['K'] or '<key>'"): the bracket
        # it opened closes after the quoted argument, and the value goes on to
        # its fallback, which must not be shown.
        owed = int(
            text.startswith(REDACTED, start)
            and text[start + len(REDACTED) : start + len(REDACTED) + 1] in "\"'"
        )
        end = _mapping_expression_end(text, start, owed=owed)
        raw = text[start:end]
        bare = raw.strip()
        if len(bare) > 1 and bare[0] in "\"'" and bare[-1] == bare[0] and _FINGERPRINT.fullmatch(bare[1:-1]):
            continue
        pieces.append(text[cursor:start])
        trailing_space = raw[len(raw.rstrip(" \t")) :]
        pieces.append('"' + REDACTED + '"' + "\n" * raw.count("\n") + trailing_space)
        cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# Names whose last word names a credential (openaiKey, OPENAI-KEY, dbPass,
# stripe.secretKey, key) also name sort keys, page tokens and cache keys, so
# only a literal that looks like an opaque key is withheld from them. An
# unquoted value counts after '=' and, in the extended pass, as a YAML value
# after ': ' ('key:v' is a scalar or a URL part); a word-like one is an
# identifier or a type ('key: Ed25519PrivateKey'). Both patterns below start
# at the separator, which is rarer than a name, and the name before it is
# read backwards.
_OPAQUE_VALUE = re.compile(
    r"(?P<separator>:=|=(?![=>~])|:(?![:=])|===?|=>|=~|<<?-(?!-))[ \t]*"
    r"(?:(?P<prefix>[rRbBuUfF]{1,2}|@)?(?P<quote>[\"'`])(?P<quoted>[^\"'`\r\n]{8,})(?P=quote)"
    r"|(?P<bare>[A-Za-z0-9+/_.~-]{8,}={0,2})(?![^\s,;)}\]]))"
)
# An unquoted value made of words is an identifier (key = Ed25519PrivateKey).
# Random keys almost always have a one- or two-letter lowercase run. The
# value is read as runs of one character class, never as a pattern of
# repeated words: '(?:[A-Z][a-z]+|[a-z]{3,}|[A-Z]{2,}|[0-9]+|_)+' split a
# long run of one class every possible way before it failed, so
# 'key: ' + 'a' * 56 + '.' took minutes.
_WORD_RUN = re.compile(r"[A-Z]+|[a-z]+|[0-9_]+|[^A-Za-z0-9_]")
_IDENTIFIER_DIGITS = re.compile(r"[0-9]+")
_IDENTIFIER_LETTERS = re.compile(r"[A-Za-z]+")


def _opaque_identifier(value: str) -> bool:
    """A word-shaped key with repeated short fragments separated by digits.

    Types such as Ed25519PrivateKey and labels such as NextPage2 remain
    identifiers. Multiple short fragments with interleaved digit runs are
    stronger evidence of key material when the assigned name names a key.
    """
    return len(_IDENTIFIER_DIGITS.findall(value)) >= 3 and all(
        len(fragment) <= 3 for fragment in _IDENTIFIER_LETTERS.findall(value)
    )


def _wordy(value: str) -> bool:
    """Whether ``value`` is made of words, digits and underscores, as identifiers are.

    A word is capitalized ('Private'), lowercase of three letters or more
    ('key') or uppercase of two or more ('API'). A lowercase run shorter than
    three letters therefore needs the capital before it, which an uppercase
    run can give unless that leaves it one capital ('ABcd' is not a word; 'Ab',
    'ABCd' and 'ABcde' are), and an uppercase run needs two letters unless a
    lowercase run follows it. Reads the value once.
    """
    runs = _WORD_RUN.findall(value)
    for index, run in enumerate(runs):
        if "a" <= run[0] <= "z":
            before = runs[index - 1] if index else ""
            if len(run) < 3 and not ("A" <= before[0:1] <= "Z" and len(before) != 2):
                return False
        elif "A" <= run[0] <= "Z":
            after = runs[index + 1] if index + 1 < len(runs) else ""
            if len(run) < 2 and not "a" <= after[0:1] <= "z":
                return False
        elif not ("0" <= run[0] <= "9" or run[0] == "_"):
            return False
    return bool(runs)


# A sensitive key whose colon ends its line, then a lone word on the next,
# unindented line ('token:\n<value>' in notes and error text). An indented
# line is YAML nesting, which the multiline pass handles.
_NEXT_LINE_VALUE = re.compile(r":[ \t]*\r?\n(?P<value>[^\s\"'#()\[\]{}<>,;]+)[ \t]*(?=\r?\n|\Z)")
_NEXT_LINE_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")


def _assigned_name(text: str, separator: int, *, numbered: bool = False) -> str:
    """The name assigned at ``separator``, past a closing quote and a simple type annotation.

    A '?' before the separator is a nullable type ('String? =') or Make's '?='. The
    characters of a compound or comparison operator that come before its '=' ('||=',
    '+=', '.=', '!=', '<=') are not part of the name. ``numbered`` is passed on to
    ``_credential_name``.
    """
    end = separator
    for _ in range(2):
        if end > 0 and text[end - 1] in "|&?+-*/%^.!<>~":
            end -= 1
    end = _blanks_before(text, end)
    if end > 0 and text[end - 1] in "\"'":
        end -= 1
    elif end > 0 and text[end - 1] == "?":
        end = _blanks_before(text, end - 1)
    name = _name_before(text, end, "_$.-")
    colon = _blanks_before(text, end - len(name))
    typed = colon > 0 and text[colon - 1] == ":" and (colon < 2 or text[colon - 2] != ":")
    if name and typed and not _credential_name(name, numbered=numbered):
        return _name_before(text, _blanks_before(text, colon - 1), "_$.-")  # 'openaiKey: string = "..."'
    return name


def _marked_by_name(text: str, match: re.Match[str], name: str) -> bool:
    """Whether the sensitive ``name`` right before the colon at ``match`` marks the value after it.

    'key:v' is a scalar or a URL part, but 'password:<opaque>' is not; the shell's
    '${NAME:-v}' default and the annotation hop of 'credential:sha256:<hex>' (the name is
    then not the word before the colon) are read elsewhere.
    """
    return (
        _sensitive_assignment_key(name)
        and text.endswith(name, 0, match.start())
        and not text.startswith(("-", "+", "?"), match.end("separator"))
    )


def _redact_opaque_assignments(text: str, *, extended: bool = False) -> str:
    """Withhold opaque literals given to credential-like names, and a lone value after 'token:'.

    The ``extended`` pass, which runs after every established pass, also
    reads a name numbered by trailing digits ('KEY1=...') and an unquoted
    YAML value ('openaiKey: ...'); the lone value after 'token:' is the
    established pass's alone.
    """
    spans: list[tuple[int, int]] = []
    for match in _OPAQUE_VALUE.finditer(text):
        name = _assigned_name(text, match.start(), numbered=extended)
        if not _credential_name(name, numbered=extended):
            continue
        group = "quoted" if match.group("quoted") is not None else "bare"
        value = match.group(group)
        if group == "bare" and (
            (
                match.group("separator") == ":"
                and not (extended and text.startswith((" ", "\t"), match.end("separator")))
                and not _marked_by_name(text, match, name)
            )
            or (_wordy(value) and not (extended and _opaque_identifier(value)))
        ):
            continue
        if match.group("quote") and _interpolated(match.group("prefix") or "", match.group("quote"), value):
            continue  # interpolated text is assembled elsewhere
        if _credential_literal(value, positional=False):
            spans.append(match.span(group))
    if extended:
        return _withhold_spans(text, spans)
    for match in _NEXT_LINE_VALUE.finditer(text):
        key = _name_before(text, match.start(), "_.-")
        if not _NEXT_LINE_KEY.fullmatch(key) or not _sensitive_assignment_key(key):
            continue
        value = match.group("value")
        if not _CLI_WORD.fullmatch(value) and _credential_literal(value, positional=True):
            spans.append(match.span("value"))
    return _withhold_spans(text, spans)


# ODBC and ADO.NET connection strings spell the password 'Pwd': 'Server=h;Uid=u;Pwd=v;'.
# 'PWD' also names a shell's working directory and 'pwd' a command, so only a 'Pwd=' that
# follows a ';' is read, and its value stays when it is empty or only a reference.
# ODBC puts a value that holds ';' in braces and doubles a '}' inside them
# ('Pwd={a;b}}c}'); the value runs to its closing brace, and on to the next ';'
# past anything a malformed value has after it ('Pwd={a}b;'). A brace that does
# not close within 256 characters on its line, or opens a '{{' template, is
# read up to the ';' as before, which keeps each read bounded.
_CONNECTION_PASSWORD = re.compile(
    r"(?<=;)[ \t]*(?i:pwd)[ \t]*="
    r"(?P<value>[ \t]*+\{(?!\{)(?:[^}\r\n]|\}\}){0,256}+\}[^;\"'\r\n]*+|[^;\"'\r\n]+)"
)


def _redact_connection_passwords(text: str) -> str:
    """Withhold the value of a connection string's ``Pwd=`` member."""
    if ";" not in text:
        return text
    spans = [
        match.span("value")
        for match in _CONNECTION_PASSWORD.finditer(text)
        if not _kept_value(match.group("value"))
    ]
    return _withhold_spans(text, spans)


# A netrc entry, which curl, git, pip and ftp read from ~/.netrc or _netrc:
# 'machine <host>' or 'default', then tokens separated by any blanks and line
# breaks, all on one line or one per line: 'login <name>' ('user' too),
# 'password <string>' ('passwd' too) and 'account <string>', and the 'port'
# and 'protocol' that the netrc credential helper of Git reads. curl reads
# the keywords in any case ('MACHINE h LOGIN u PASSWORD v'), and so does this
# rule. The value after 'password', 'passwd' or 'account' is a secret
# whatever it looks like, so it is withheld unless it is only a reference
# ('password $NETRC_TOKEN'); a name is never read as one of those words, so
# a missing login cannot hide the password after it, and a value that is one
# ('login account password v', where clients read the login 'account') is
# withheld and read again as the token it names. A quoted value (curl) runs
# to its closing quote, or to the end of its line when it never closes.
# Blanks include the vertical tab and form feed. On a line written as an
# escaped string (``_NETRC_STRING``), JSON and shell '\n', '\r', '\t', '\v'
# and '\f' escapes and PowerShell's '`n' ones separate tokens as well
# ('"machine h\nlogin u\npassword v"'); on any other line, such as a netrc
# file's own, an escape is part of the token it is in, as clients read it
# ('login CORP\fred'). A value is withheld up to the next blank all the same,
# so a backslash in it never shows its tail. Once a 'machine', 'default',
# 'login' or 'user' token is read, a token the format does not define ends no
# entry on the line of the entry's last token: curl skips it, and the value
# after a 'password', 'passwd' or 'account' after it is withheld ('machine h
# force yes password v', 'default force yes password v'), as it is after a
# quoted word glued to a quoted name ('login "u""v"password v'). On a later
# line it ends no entry either while such a keyword follows it in the
# entry's region (``_NETRC_AHEAD``); past that, it ends the entry, as prose
# after 'machine learning' does. Adjacent string literals are one string
# ('"machine h\n" +', then '"login u\n"' on the next line): a closing quote,
# then blanks, line breaks or a '+', then an opening quote part tokens as a
# blank does (``_NETRC_JOIN``). A '#' after a blank, or after a line-break
# escape, starts a comment, which ends where its line does: at the end of a
# line of plain text, and at the next line-break escape where the comment is
# in an escaped string (``_NetrcLines.in_string``: '"machine h\n  # note\n
# password v"'), not merely on a line that holds an apostrophe ("# Bob's
# share is C:\new\data"). A comment, like a quoted name, is also read on its
# own, so an entry commented out in it is withheld; a commented-out token
# outside such an entry is not ('login u # was password v'). 'macdef <name>'
# starts a macro, whose lines up to the empty line that ends it, and the
# rest of its name's line, are withheld whole (see ``_netrc_macro``). An
# entry starts at 'machine' or 'default' anywhere a word starts or right
# after a comment's '#', and at 'macdef' only first on a line or after a
# quote, when its name ends that line: that is also an ordinary word.
# 'default' is one as well ('the default password is ...'), and the word
# after it is withheld then: a prose word is withheld rather than a password
# shown.
_NETRC_SPACE = r"[ \t\r\n\v\f]"
_NETRC_ESCAPE = r"[\\`][nrtvf]"
_NETRC_BREAK = rf"(?:{_NETRC_SPACE}|{_NETRC_ESCAPE})"
_NETRC_END = rf"(?={_NETRC_BREAK}|\Z)"
_NETRC_WORDS = r"(?ai:login|user|port|protocol|machine|macdef|default|password|passwd|account)"
_NETRC_WORD = re.compile(_NETRC_WORDS)
# A line written as an escaped string: one that holds a quote, as a string
# literal does, or an escape next to a keyword, also one that indentation
# parts from it ('machine h\nlogin u', 'machine h\n  login u' in an unquoted
# value). On a netrc file's own lines, which hold neither, a backslash before
# a letter is part of a name ('login CORP\nancy'). A keyword that is a
# directory of a Windows path is no such escape: one right after a path's
# backslash ('\\nas\user\fred', 'C:\Users\bob\default\new') or right before
# one that starts no escape ('C:\x\nlogin\y') reads the line as a netrc
# file's own, so a comment that holds the path runs to the end of its line.
_NETRC_KEYED = re.compile(
    rf"{_NETRC_ESCAPE}[ \t]*+{_NETRC_WORDS}(?![A-Za-z0-9_]|\\(?![nrtvf]))"
    rf"|(?<![A-Za-z0-9_\\]){_NETRC_WORDS}{_NETRC_ESCAPE}"
)
_NETRC_STRING = re.compile(rf"[\"'`]|{_NETRC_KEYED.pattern}")
# The characters of an unquoted value, up to the next blank or escape. A token
# stops at an escape on every line, since a name or value can start on a line
# of either kind. Where the escape is part of the token, the rest of its run is
# read as a token the format does not define (``_NETRC_UNKNOWN``) and skipped.
_NETRC_LEAD = r"(?:[^\s\\`]|[\\`](?![nrtvf]))"
# A value: quoted ('"v"', '\"v\"' inside a JSON string) up to its closing
# quote, or unquoted, up to the next blank or escape, where the next token can
# start. What is glued to a closing quote is the next token, as Python's netrc
# reads it ('login "u"password v'); a secret is withheld up to the next blank
# all the same. A secret whose quote never closes runs to the end of its line;
# a name, to the next blank, so that it hides no token after it.
_NETRC_QUOTED = (
    r"\"(?:[^\"\\\r\n]|\\.)*+(?:\"{unclosed})"
    r"|\\\"(?:[^\\\r\n]|\\(?!\"))*+(?:\\\"{unclosed})"
)
_NETRC_VALUE = _NETRC_QUOTED.format(unclosed=r"|[^\r\n]*+") + rf"|{_NETRC_LEAD}++"
# The optional name after 'login', 'machine' and the like, never one of the words.
_NETRC_NAME = (
    rf"(?:{_NETRC_BREAK}++(?!{_NETRC_WORDS}{_NETRC_END})"
    rf"(?P<name>{_NETRC_QUOTED.format(unclosed='')}|{_NETRC_LEAD}++))?"
)
# A macro's name, which may be one of the words.
_NETRC_MACRO_NAME = rf"(?:{_NETRC_QUOTED.format(unclosed='')}|{_NETRC_LEAD}++)"
_NETRC_HEAD = re.compile(
    rf"(?:(?<![^\s\"'`(=#])|(?<={_NETRC_ESCAPE}))(?P<machine>(?ai:machine){_NETRC_BREAK}|(?ai:default){_NETRC_END})"
    rf"|(?:\A|(?<=[\r\n\"'`])|(?<={_NETRC_ESCAPE}))[ \t\v\f]*+(?P<word>(?ai:macdef)"
    rf"(?=[ \t\v\f]++(?:[^\s\\]|\\(?![nrtvf]))++(?:[ \t\v\f]*+(?:\r?\n|\Z)|{_NETRC_ESCAPE})))"
)
# Before a token: blanks, escapes, and a '#' comment after a blank or a line-break escape.
_NETRC_BLANKS = re.compile(r"[ \t\r\n\v\f]++")
_NETRC_ESCAPES = tuple(escape + letter for escape in "\\`" for letter in "nrtvf")
_NETRC_LINE_BREAKS = ("\\n", "\\r", "`n", "`r")
_NETRC_QUOTES = ('"', '\\"')
_NETRC_TOKEN = re.compile(
    rf"(?P<secret>(?ai:password|passwd|account)){_NETRC_BREAK}++(?P<value>{_NETRC_VALUE})"
    rf"|(?P<keyword>(?ai:login|user|port|protocol|machine)){_NETRC_END}{_NETRC_NAME}"
    rf"|(?P<macdef>(?ai:macdef)){_NETRC_END}(?:{_NETRC_BREAK}++{_NETRC_MACRO_NAME})?"
    rf"|(?P<default>(?ai:default)){_NETRC_END}"
)
# A token the format does not define, on a line of plain text and on an escaped
# string's, where an escape ends it, and a quoted word, which holds no escape,
# ends at its closing quote ('"v"' in 'login "u""v"password w'; '"`npassword`n"'
# is a quote, an escape and a keyword); and the tokens that start an entry,
# after which one need not end it.
_NETRC_UNKNOWN = (
    re.compile(r"\S++"),
    re.compile(rf"\"[^\s\"\\`]*+\"|\\\"[^\s\"\\`]*+\\\"|{_NETRC_LEAD}++"),
)
_NETRC_KNOWN = frozenset({"machine", "default", "login", "user"})
# Where two adjacent string literals meet: a closing quote, then blanks, line
# breaks, a '+' or a line continuation, then an opening quote; and the quotes
# that open a literal.
_NETRC_JOIN = re.compile(r"[\"'](?:[ \t\r\n\v\f+]|\\(?=[\r\n]))*+[\"']")
_NETRC_OPENING = ('"', "'")
# What follows a token the format does not define on a later line than the
# entry's last token: a 'password', 'passwd' or 'account' keyword, before
# which it ends no entry, or the next head, where the entry's region ends.
# The region is also bounded to the eight lines from that of the entry's last
# token, and ends before at a blank line (``_NETRC_WINDOW``).
_NETRC_AHEAD = re.compile(
    rf"(?P<secret>(?:(?<![^\s\"'`])|(?<={_NETRC_ESCAPE}))(?ai:password|passwd|account){_NETRC_BREAK})"
    rf"|{_NETRC_HEAD.pattern}"
)
_NETRC_AHEAD_WORD = re.compile(r"(?ai:password|passwd|account|machine|default|macdef)")
_NETRC_WINDOW = re.compile(r"(?:[^\r\n]*+(?:\r\n?+|\n)(?![ \t\v\f]*+[\r\n])){0,7}[^\r\n]*+")
# Where a head may start inside such a token ('force "machine h').
_NETRC_HEAD_WORD = re.compile(r"(?ai:machine|default|macdef)")
# The rest of a run of non-blank characters, and of a comment: on a line of
# plain text, its line; on an escaped string's, up to the next line-break
# escape ('"machine h\n  # c\npassword v"').
_NETRC_RUN = re.compile(r"\S*+")
_NETRC_LINES = (re.compile(r"[^\r\n]*+"), re.compile(r"(?:[^\r\n\\`]|[\\`](?![nr]))*+"))
_NETRC_LINE_END = re.compile(r"[\r\n]")
# How much of its run past an escape a value may have and still be read as a
# reference ('password $NETRC_TOKEN\n'); a value with more is withheld.
_NETRC_TAIL = 64
_NETRC_HINTS = ("machine", "default", "macdef")


def _redact_netrc_entries(text: str) -> str:
    """Withhold the passwords, accounts and macros of netrc entries (see ``_NETRC_TOKEN``)."""
    if not any(hint in text for hint in _NETRC_HINTS):
        lowered = text.lower()  # the keywords in any case
        if not any(hint in lowered for hint in _NETRC_HINTS):
            return text
    spans: list[tuple[int, int]] = []
    ranges: list[tuple[int, int, bool | None]] = [(0, len(text), None)]
    lines = _NetrcLines(text)
    while ranges:
        start, end, escapes = ranges.pop()
        _NetrcReader(text, end, spans, ranges, lines, escapes).read(start)
    return _withhold_spans(text, _union(spans))


def _union(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The spans that ``spans`` cover, overlapping ones merged."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


class _NetrcLines:
    """The physical lines of a text, each searched once by whichever reader of it asks first.

    The readers ask in text order (the reader of the whole text) and in
    reverse (the queued ranges, read last first, each on one line), so the
    line asked about last answers most questions, and a line asked about
    again is found by where it starts. Nothing is kept in order: a sorted
    list of line starts took each new line at its front in the reverse
    order, which cost quadratic time.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        # By where each line starts: where it ends, where its first line-break
        # escape starts, whether it holds an escape next to a keyword, and
        # where its first and last quote of each kind are.
        self.lines: dict[int, tuple[int, int, bool, tuple[tuple[int, int], ...]]] = {}
        # The line asked about last: where it starts and what ``lines`` holds for it.
        self.last: tuple[int, tuple[int, int, bool, tuple[tuple[int, int], ...]] | None] = (0, None)

    def in_string(self, position: int) -> bool:
        """Whether the comment at ``position``, on an escaped string's line, is in that string.

        It is when its line holds an escape next to a keyword, as escaped text
        does ('machine h # c\\nlogin u'), or a line-break escape before it
        ('machine h\\nlogin u # c\\npassword v'), or the same quote both
        before and after it ('"machine h\\n  # c\\npassword v"'). A netrc
        file's own comment that merely holds an apostrophe or quotes and a
        path ("# Bob's share is C:\\new\\data") is in none: its line-break
        escapes are part of the path, and the comment runs to the end of its
        line.
        """
        _, escape, keyed, quotes = self._line(position)
        return keyed or escape < position or any(first < position < last for first, last in quotes)

    def _line(self, position: int) -> tuple[int, int, bool, tuple[tuple[int, int], ...]]:
        start, known = self.last
        if known is not None and start <= position < known[0]:
            return known
        text = self.text
        newline = text.rfind("\n", 0, position)
        start = max(newline, text.rfind("\r", max(newline, 0), position)) + 1
        line = self.lines.get(start)
        if line is None:
            line_end = _NETRC_LINE_END.search(text, position)
            end = line_end.start() if line_end is not None else len(text)
            found = [at for at in (text.find(escape, start, end) for escape in _NETRC_LINE_BREAKS) if at >= 0]
            quotes = tuple((text.find(quote, start, end), text.rfind(quote, start, end)) for quote in "\"'`")
            keyed = _NETRC_KEYED.search(text, start, end) is not None
            line = (end, min(found, default=end), keyed, quotes)
            self.lines[start] = line
        self.last = (start, line)
        return line


class _NetrcReader:
    """Collect in ``spans`` the secrets of the netrc entries that start in ``text[start:end]``.

    Each character is read a bounded number of times, so a text is read in
    linear time. An entry's tokens are read once from its head, and a head
    inside an entry already read is skipped. Where an entry ends at a token
    the format does not define, the next head is searched for from its last
    token, so an entry commented out after it is read. A comment between two
    tokens that an entry reads past, and a quoted name, is queued in
    ``ranges`` with the kind of its line and read on its own, up to its end.
    The blanks and comments between two tokens are read once whichever entry
    reaches them (``gaps``), a token that is not one is read once (``dead``),
    and so are the run of a value, which the values in it share, the line of
    a comment, and each line's kind (``_escapes``). The physical lines are
    read once for all readers (``_NetrcLines``).
    """

    def __init__(
        self,
        text: str,
        end: int,
        spans: list[tuple[int, int]],
        ranges: list[tuple[int, int, bool | None]],
        lines: _NetrcLines,
        escapes: bool | None = None,
    ) -> None:
        self.text = text
        self.end = end
        self.spans = spans
        self.ranges = ranges
        self.physical = lines
        self.withheld = 0  # where the last value withheld ends
        # Where a gap read from each of its pieces ends, and its comments no entry has queued.
        self.gaps: dict[int, tuple[int, list[tuple[int, int, bool | None]]]] = {}
        self.dead: set[int] = set()  # where no token starts after a gap
        self.run = (-1, -1)  # the run read last, from the end of its first value
        self.quotes: dict[str, int] = {}  # the last of each quote in that run
        self.comment = [(-1, -1), (-1, -1)]  # the comment of each kind read last, from its first piece
        # The line read last and whether it is an escaped string, and each line
        # read, by where it starts. A queued range lies on one line, whose kind it is given.
        self.line = (0, 0, False) if escapes is None else (0, end + 1, escapes)
        self.starts: list[int] = []
        self.lines: dict[int, tuple[int, bool]] = {}
        # The region bound of each line an entry's last token was on, and the
        # stretch searched last for what follows a token the format does not
        # define: from where, to where the first match starts, and whether it
        # is a 'password', 'passwd' or 'account' keyword (see ``_NETRC_AHEAD``).
        self.windows: dict[int, int] = {}
        self.ahead = (-1, -1, False)

    def read(self, start: int) -> None:
        position = start
        while (head := _NETRC_HEAD.search(self.text, position, self.end)) is not None:
            entry = head.start("machine") if head.group("machine") else head.start("word")
            before = self.text[head.start() - 1] if head.start() else ""
            quote = before if before in "\"'`" else ""
            position = max(self._entry(entry, quote), head.end())

    def _entry(self, start: int, quote: str) -> int:
        """Collect the secrets of the netrc tokens read from ``start``; return where they end.

        ``quote`` is the quote an entry is written in ('echo "machine h login u
        password v" > ~/.netrc'): the last one in a value closes that string, so
        the value is withheld up to it.

        Once a 'machine', 'default', 'login' or 'user' token is read, a token
        the format does not define is skipped, as curl skips it, on the line
        of the entry's last token and before a 'password', 'passwd' or
        'account' in the entry's region (see ``_skip``): an entry that ended
        there left the password after it unread ('machine h force yes password
        v', 'default force yes password v', 'login CORP\\fred password v',
        whose name an escape ended, and the rest of a comment cut at a
        line-break escape).
        """
        position = start
        line = -1  # where the line of the entry's last token starts, once the entry has started
        while True:
            gap, comments = self._gap(position)
            token = self._token(gap)
            following = self._skip(gap, line) if token is None else self._read(token, quote)
            if following is None:
                return position  # the head search reads the gap's comments from here
            # Read past, a gap's comments are read on their own.
            self.ranges.extend(comments)
            comments.clear()
            position = following
            if token is not None and (line >= 0 or _netrc_starts(token)):
                self._escapes(token.end() - 1)
                line = self.line[0]

    def _read(self, token: re.Match[str], quote: str) -> int:
        """Collect the secret of ``token`` and queue its quoted name; return where the next token starts."""
        if token.group("secret"):
            value = token.start("value")
            self._secret(value, token.end("value"), quote)
            # A keyword as the value is a name to clients ('login account password v'):
            # the value is withheld and read again as that keyword.
            keyword = _NETRC_WORD.fullmatch(self.text, value, token.end("value"))
            return value if keyword is not None else token.end()
        if token.group("macdef"):
            return _netrc_macro(self.text, token.end(), self.end, self.spans)
        name = token.start("name")
        if name >= 0 and self.text.startswith(_NETRC_QUOTES, name):
            # A quoted name can hold what reads as an entry: it is read on its own too.
            self.ranges.append((name + 1, token.end("name"), self._escapes(name)))
        return token.end()

    def _gap(self, position: int) -> tuple[int, list[tuple[int, int, bool | None]]]:
        """Where the blanks, escapes and comments from ``position`` end, and the comments not yet queued.

        Escapes, and where two adjacent string literals meet, are read only
        on a line that is an escaped string. The pieces of a gap share its
        list of comments, which an entry that reads past the gap queues and
        empties, so a gap read again from one of its pieces gives only those
        no entry has queued.
        """
        text, end = self.text, self.end
        pieces: list[int] = []
        comments: list[tuple[int, int, bool | None]] = []
        known: tuple[int, list[tuple[int, int, bool | None]]] | None = None
        while position < end and (known := self.gaps.get(position)) is None:
            pieces.append(position)
            blanks = _NETRC_BLANKS.match(text, position, end)
            escapes = blanks is None and self._escapes(position)
            line_break = escapes and text.startswith(_NETRC_LINE_BREAKS, position, end)
            if blanks is not None or line_break:
                position = blanks.end() if blanks is not None else position + 2
                if text.startswith("#", position, end):
                    # In an escaped string, a comment ends where that string's line does, at an escape.
                    escaped = self._escapes(position)
                    comment = self._comment_end(position, escaped and self.physical.in_string(position))
                    comments.append((position + 1, comment, escaped))
                    position = comment
            elif escapes and text.startswith(_NETRC_ESCAPES, position, end):
                position += 2
            elif escapes and (join := _NETRC_JOIN.match(text, position, end)) is not None:
                position = join.end()
            else:
                pieces.pop()
                break
        stop = position
        if known is not None:
            stop, rest = known
            comments.extend(rest)
            rest.clear()
        for piece in pieces:
            self.gaps[piece] = (stop, comments)
        return stop, comments

    def _token(self, position: int) -> re.Match[str] | None:
        if position >= self.end or position in self.dead:
            return None
        token = _NETRC_TOKEN.match(self.text, position, self.end)
        if token is None:
            self.dead.add(position)
        return token

    def _skip(self, position: int, line: int) -> int | None:
        """Where the token at ``position``, which the format does not define, ends, or None if the entry does.

        ``line`` is where the line of the entry's last token starts, or -1
        before the entry has started. The token is skipped on that line,
        and on a later one before a 'password', 'passwd' or 'account' in the
        entry's region (see ``_secret_ahead``): so a comment that a line-break
        escape seemed to end costs at most a word withheld, never a password
        shown. Past them, the token ends the entry: on a later line it starts
        prose as often as it interrupts an entry, and skipped there, 'machine
        learning' withheld the word after each 'account' of a document. A
        head inside the token ('force "machine h') starts an entry of its
        own, which the entry ends before. An opening quote right before a
        token is skipped alone, as where a comment parts two string literals
        ('"machine h\\n"  # c', then '"login u\\n"').
        """
        if line < 0 or position >= self.end:
            return None
        escapes = self._escapes(position)
        if self.line[0] != line and not self._secret_ahead(position, line):
            return None
        run = _NETRC_UNKNOWN[escapes].match(self.text, position, self.end)
        end = run.end() if run is not None else position + 1
        for word in _NETRC_HEAD_WORD.finditer(self.text, position, end):
            if _NETRC_HEAD.match(self.text, word.start(), self.end) is not None:
                return None
        opening = escapes and self.text.startswith(_NETRC_OPENING, position)
        return position + 1 if opening and self._token(position + 1) is not None else end

    def _secret_ahead(self, position: int, line: int) -> bool:
        """Whether a 'password', 'passwd' or 'account' follows ``position`` in the entry's region.

        The region runs from the line of the entry's last token, which starts
        at ``line``, for eight lines, and ends before that at a blank line or
        at the next head, which starts an entry of its own. A line is read for
        a region at most eight times, and each stretch searched once: a search
        from inside the last one finds what it found. Only the words that may
        start a match are tried (``_NETRC_AHEAD_WORD``).
        """
        limit = self.windows.get(line)
        if limit is None:
            window = _NETRC_WINDOW.match(self.text, line, self.end)
            limit = self.windows[line] = window.end() if window is not None else line
        if position >= limit:
            return False
        first, found, secret = self.ahead
        if not first <= position <= found:
            found, secret = self.end, False
            for word in _NETRC_AHEAD_WORD.finditer(self.text, position, self.end):
                match = _netrc_ahead(self.text, word, self.end)
                if match is not None:
                    found, secret = word.start(), match.group("secret") is not None
                    break
            self.ahead = (position, found, secret)
        return secret and found < limit

    def _escapes(self, position: int) -> bool:
        """Whether the line at ``position`` is an escaped string (see ``_NETRC_STRING``).

        Each line is read once: the reader reaches positions in order, so the
        line before the one read last is not searched for its start again.
        """
        start, end, escapes = self.line
        if start <= position < end:
            return escapes
        index = bisect.bisect_right(self.starts, position)
        floor = 0
        if index:
            start = self.starts[index - 1]
            end, escapes = self.lines[start]
            if position < end:
                self.line = (start, end, escapes)
                return escapes
            floor = end
        text = self.text
        newline = text.rfind("\n", floor, position)
        start = max(newline, text.rfind("\r", max(newline, floor), position)) + 1
        line_end = _NETRC_LINE_END.search(text, position)
        end = line_end.start() if line_end is not None else len(text) + 1
        escapes = _NETRC_STRING.search(text, start, end) is not None
        self.starts.insert(index, start)
        self.lines[start] = (end, escapes)
        self.line = (start, end, escapes)
        return escapes

    def _comment_end(self, position: int, escaped: bool) -> int:
        """Where the comment at ``position``, on an ``escaped`` string's line or not, ends.

        See ``_NETRC_LINES``. Each comment is read once: one that starts
        inside the last of its kind ends where that one does.
        """
        first, last = self.comment[escaped]
        if not first <= position <= last:
            line = _NETRC_LINES[escaped].match(self.text, position, self.end)
            self.comment[escaped] = (position, line.end() if line is not None else position)
        return self.comment[escaped][1]

    def _secret(self, start: int, end: int, quote: str) -> None:
        """Withhold the value ``text[start:end]`` up to the end of its run, unless it is a reference."""
        stop = self._run_end(end)
        closing = self._last(quote, start, end) if quote else -1
        if closing >= 0:
            stop = closing
        if stop <= max(start, self.withheld):
            return  # empty, or inside the last value withheld
        if stop - end > _NETRC_TAIL or not _kept_value(self.text[start:stop]):
            self.spans.append((max(start, self.withheld), stop))
            self.withheld = stop

    def _run_end(self, position: int) -> int:
        """Where the run of non-blank characters at ``position`` ends, each run read once."""
        first, last = self.run
        if not first <= position <= last:
            run = _NETRC_RUN.match(self.text, position, self.end)
            self.run = (position, run.end() if run is not None else position)
            self.quotes = {}
        return self.run[1]

    def _last(self, quote: str, start: int, end: int) -> int:
        """The last ``quote`` in the value ``text[start:end]`` or the rest of its run, or -1."""
        first, last = self.run
        if quote not in self.quotes:
            self.quotes[quote] = self.text.rfind(quote, first, last)
        found = self.quotes[quote]
        return found if found >= end else self.text.rfind(quote, start, end)


def _netrc_ahead(text: str, word: re.Match[str], end: int) -> re.Match[str] | None:
    """The match of ``_NETRC_AHEAD`` that ``word`` starts, a 'macdef' head from the blanks before it."""
    match = _NETRC_AHEAD.match(text, word.start(), end)
    if match is None and word.group().lower() == "macdef":
        blanks = word.start()
        while blanks and text[blanks - 1] in " \t\v\f":
            blanks -= 1
        match = _NETRC_AHEAD.match(text, blanks, end)
    return match


def _netrc_starts(token: re.Match[str]) -> bool:
    """Whether ``token`` starts an entry: 'machine', 'default', 'login' or 'user'."""
    return (token.group("keyword") or token.group("default") or "").lower() in _NETRC_KNOWN


def _netrc_macro(text: str, start: int, end: int, spans: list[tuple[int, int]]) -> int:
    """Withhold the lines of the macro whose name ends at ``start``; return where the macro ends.

    Its lines follow the line of its name, up to the first empty line (a
    line of blanks does not end it) or ``end``, and the rest of that line is
    withheld as well. A macro written on the line of its name (in a string
    with '\\n' escapes) is that line's rest. Line breaks stay, so excerpt
    lines keep their numbers.
    """
    line_end = text.find("\n", start, end)
    stop = end if line_end < 0 else line_end
    rest = text[start:stop].rstrip()
    if rest.strip():
        spans.append((start + len(rest) - len(rest.lstrip()), start + len(rest)))
        if any(escape in rest for escape in _NETRC_LINE_BREAKS):
            return stop
    position = stop + 1
    while position < end:
        line_end = text.find("\n", position, end)
        stop = end if line_end < 0 else line_end
        line = text[position:stop]
        if not line.rstrip("\r"):
            return position
        if line.strip():
            spans.append((position + len(line) - len(line.lstrip()), position + len(line.rstrip())))
        position = stop + 1
    return end


# Yarn 1's .yarnrc writes a setting as 'name value', either one optionally
# quoted: '"//registry.yarnpkg.com/:_authToken" "v"', '_auth v'. npm names a
# registry credential '_authToken', '_auth' or '_password', alone or after
# the registry's '//host/path/:' prefix, first on its line; the value runs to
# the end of the line. A bare unquoted name is also a word ('_auth helpers
# ...'), so only a lone value follows it. '_authToken=v' and '_auth = v'
# (.npmrc) are assignments, read before.
_RC_CREDENTIAL = re.compile(
    r"(?m)^[ \t]*+(?:(?P<quote>\"?)//[^\s\"]*+(?:(?<=:_authToken)|(?<=:_auth)|(?<=:_password))(?P=quote)"
    r"|\"(?:_authToken|_auth|_password)\""
    r"|(?:_authToken|_auth|_password)(?=[ \t]++(?:\"[^\"\r\n]*+\"|[^\s\"]\S*+)[ \t]*+\r?$))"
    r"[ \t]++(?P<value>[^\s=:][^\r\n]*+)"
)


def _redact_rc_credentials(text: str) -> str:
    """Withhold the registry credentials of a Yarn 1 ``.yarnrc`` (see ``_RC_CREDENTIAL``)."""
    if "_auth" not in text and "_password" not in text:
        return text
    spans = [
        match.span("value")
        for match in _RC_CREDENTIAL.finditer(text)
        if not _kept_value(match.group("value"))
    ]
    return _withhold_spans(text, spans)


# A literal default for a credential read from the environment or a
# credential-named field: 'process.env.OPENAI_API_KEY || "v"',
# 'Environment.GetEnvironmentVariable("AZURE_OPENAI_KEY") ?? "v"',
# 'os.getenv("OPENAI_API_KEY") or "v"', 'getenv("X") ?: "v"' and the shell's
# '${OPENAI_API_KEY:-v}'. The pattern starts at the operator; the name before
# it is a name, or the short string literal that ends a call or subscript.
# Every operator starts with a literal, which lets the regex engine skip
# ahead quickly; the word boundary before 'or' is checked after it.
_FALLBACK_DEFAULT = re.compile(
    r"(?:\|\||\?[?:]|or(?<![\w.$]or))[ \t]*(?P<prefix>[rRbBuUfF]{1,2}|@)?(?P<quote>[\"'`])"
    r"(?P<value>[^\"'`\r\n]*)(?P=quote)"
)
_SHELL_DEFAULT = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*):?[-=](?P<value>[^{}\r\n]*)\}")
_FALLBACK_NAME_LITERAL = 256
# Operators ending in ':' or '=' that assign nothing ('==', '!=', '<=', a C++ scope).
_OPERATOR_PAIRS = frozenset({"==", "!=", "<=", ">=", "::"})


def _fallback_name(text: str, operator: int) -> str:
    """The name whose value the operator at ``operator`` falls back from.

    After a call or subscript that reads a name ('os.environ["K"] or "v"')
    it is the name read, unless that names no credential and the read is
    assigned to a name that does ('azureKey: process.env["K"] ?? "v"').
    """
    end = _blanks_before(text, operator)
    if end == 0 or text[end - 1] not in ")]":
        return _name_before(text, end, "_$.").rsplit(".", 1)[-1]
    end = _blanks_before(text, end - 1)
    if end == 0 or text[end - 1] not in "\"'":
        return ""
    opening = text.rfind(text[end - 1], max(0, end - 1 - _FALLBACK_NAME_LITERAL), end - 1)
    if opening < 0:
        return ""
    read = text[opening + 1 : end - 1]
    if _sensitive_assignment_key(read) or _credential_name(read, numbered=True):
        return read
    return _read_target(text, opening) or read


def _read_target(text: str, opening: int) -> str:
    """The name a call or subscript read is assigned to, given the quote that opens its argument, or ''."""
    bracket = _blanks_before(text, opening)
    if bracket == 0 or text[bracket - 1] not in "([":
        return ""
    callee = _name_before(text, bracket - 1, "_$.")
    separator = _blanks_before(text, bracket - 1 - len(callee))
    if (
        not callee
        or separator == 0
        or text[separator - 1] not in ":="
        or text[separator - 2 : separator] in _OPERATOR_PAIRS
    ):
        return ""
    end = _blanks_before(text, separator - 1)
    if end > 0 and text[end - 1] in "\"'":
        end -= 1
    return _name_before(text, end, "_$.-")


def _redact_fallback_defaults(text: str, *, extended: bool = False) -> str:
    """Withhold literal defaults given to credential names by fallback operators.

    A lowercase word ('default', 'none') and the values a credential
    literal never is (placeholders, URLs, environment names) stay visible.
    The ``extended`` pass, which runs after every established pass, also
    reads a name numbered by trailing digits ('process.env.KEY1 || "..."').
    """
    spans: list[tuple[int, int]] = []
    for match in _FALLBACK_DEFAULT.finditer(text):
        name = _fallback_name(text, match.start())
        value = match.group("value")
        if not name or _interpolated(match.group("prefix") or "", match.group("quote"), value):
            continue
        sensitive = _sensitive_assignment_key(name)
        if not (sensitive or _credential_name(name, numbered=extended)) or _CLI_WORD.fullmatch(value):
            continue
        if _credential_literal(value, positional=sensitive):
            spans.append(match.span("value"))
    if "${" in text and not extended:
        for match in _SHELL_DEFAULT.finditer(text):
            value = match.group("value")
            if not _sensitive_assignment_key(match.group("name")) or _CLI_WORD.fullmatch(value):
                continue
            if _credential_literal(value, positional=True):
                spans.append(match.span("value"))
    return _withhold_spans(text, spans)


_TEXT_LINE = re.compile(r"[^\r\n]++")
# What a scan of a line's string literals and comment stops at: a quote, which
# opens a string literal, and the comment markers of code and of XML or HTML.
_LINE_PIECE = re.compile(r"[\"'`]|//|/\*|#|<!--")
# A name joined to a value on a line ('apiKey:', 'api_key =', '"token":', and
# the "'api_key' =>" of a PHP or Ruby array).
_LINE_NAME = re.compile(r"(?<![\w$.-])(?P<name>[A-Za-z_$][\w$.-]*+)[\"']?[ \t]*+(?::(?!:)|=(?![=~]))")
# A callee given its arguments ('sgMail.setApiKey(', '.apiKey('): one whose last
# word names a credential takes it as an argument.
_LINE_CALLEE = re.compile(r"(?<![\w$])(?P<name>[A-Za-z_$][\w$]*+)\(")
# The next entry of a mapping or an object on the line ('{ dbPassword: ..., model: ...'),
# which ends the value before it at its own depth (see ``_password_values``).
_NEXT_ENTRY = re.compile(r"[,{;][ \t]*+[\"']?[A-Za-z_$][\w$.-]*+[\"']?[ \t]*+(?::(?!:)|=(?![=~]))")
_BRACKET = re.compile(r"[()\[\]{}]")
_BRACKET_CLOSERS = {"(": ")", "[": "]", "{": "}"}
# A line that goes on with the value of the line before it: it starts with a
# fallback operator, as Black and styles that break before an operator write
# ('    or "<key>",', '  || "<key>"'), or the line before ends with one
# ('setApiKey(cfg("a", "b") ||'). A comment line between keeps the value going.
_CONTINUED_LINE = re.compile(r"[ \t]*+(?:(?:or|else)\b|\|\||\?\?|\?:|[?:+])")
_OPEN_OPERATOR = re.compile(r"(?:\|\||\?\?|\?:|[?:+]|(?<![\w$.])(?:or|else))[ \t]*+\Z")
_COMMENT_LINE = re.compile(r"[ \t]*+(?://|#|/\*|<!--)")
# The end of a block comment that may run past its line.
_COMMENT_CLOSERS = {"/*": "*/", "<!--": "-->"}
# The last words of a password's name, whose value a person chose: any literal
# of it is withheld, not only one that looks like an opaque key. A secret's
# (a client secret, a webhook or signing secret) is read the same way: its
# fallback is reported whatever its shape, as a password's is
# (``shadowscan.signatures.matcher._PASSWORD_FALLBACK_NAMES``), so evidence
# must withhold it whatever its shape too. The matcher reads a name's end
# whatever its case, so a last word that runs words together ('dbpassword',
# 'CLIENTSECRET') names one too when it ends in one of the longer words.
_PASSWORD_WORDS = frozenset({"pass", "passphrase", "passwd", "password", "pwd", "secret"})
_PASSWORD_ENDS = ("passphrase", "passwd", "password", "secret")
# A run of a comment that could be key material: the base64 and URL-safe alphabet.
_COMMENT_TOKEN = re.compile(r"[A-Za-z0-9+/_.~=-]{8,}+")
# The same in a string literal, where '=' joins a name to its value
# ('"sid=<key>"') unless it pads a base64 key's end.
_LITERAL_TOKEN = re.compile(r"[A-Za-z0-9+/_.~-]{8,}+={0,2}")
# What may come before a string literal's quote and make it a template.
_LITERAL_PREFIX = re.compile(r"(?:[rRbBuUfF]{1,2}|[@$]{1,2})\Z")


def _closing_quote(line: str, quote: str, start: int) -> int | None:
    """Where the string literal that ``quote`` opened before ``start`` closes, or None."""
    position = line.find(quote, start)
    while position != -1:
        # A quote after an odd run of backslashes is escaped. Each run is
        # counted once, since the next search starts past this quote.
        backslashes = 0
        while position - backslashes > start and line[position - backslashes - 1] == "\\":
            backslashes += 1
        if backslashes % 2 == 0:
            return position
        position = line.find(quote, position + 1)
    return None


def _line_regions(line: str) -> tuple[list[tuple[int, int]], int | None]:
    """The spans of a line's string literal bodies, and where its comment starts, or None.

    A '//' or '#' starts a comment at the line's start or after a blank, ','
    or ';' ('https://h/#x' and 'this.#k' hold none); a '/*' or an XML or
    HTML '<!--' starts one anywhere. A string literal that does not close on the line runs to its
    end, and no comment follows it. A template that assembles its text from
    expressions ('f"{x}..."', '`${prefix}...`') is left out, as the
    assignment passes leave it.
    """
    literals: list[tuple[int, int]] = []
    position = 0
    while (piece := _LINE_PIECE.search(line, position)) is not None:
        mark, start = piece.group(), piece.start()
        if mark in "\"'`":
            close = _closing_quote(line, mark, piece.end())
            end = len(line) if close is None else close
            prefix = _LITERAL_PREFIX.search(line, max(0, start - 2), start)
            if not _interpolated(prefix.group() if prefix else "", mark, line[piece.end() : end]):
                literals.append((piece.end(), end))
            if close is None:
                return literals, None
            position = close + 1
        elif mark in {"/*", "<!--"} or start == 0 or line[start - 1] in " \t,;":
            return literals, start
        else:
            position = piece.end()
    return literals, None


class _Join(NamedTuple):
    """A credential's name joined to its value: where the value starts, the name, if a callee names it."""

    start: int
    name: str
    callee: bool


def _credential_joins(line: str, end: int) -> list[_Join]:
    """Every place on a line before ``end`` where a credential's name is joined to its value, in line order.

    A name joined by ':', '=' or '=>' names a credential as the assignment
    passes read it (``_sensitive_assignment_key``, or ``_credential_name``:
    its last word names one); a callee does when its last word names one
    ('setApiKey(', 'apiKey('). Each of them is read, not only the first: a
    password's entry after an 'apiKey:' entry or a 'setApiKey(...)' call on
    the same line is a password's value too.
    """
    joins = [
        _Join(match.end(), match["name"], False)
        for match in _LINE_NAME.finditer(line, 0, end)
        if _sensitive_assignment_key(match["name"]) or _credential_name(match["name"])
    ]
    joins.extend(
        _Join(match.end(), match["name"], True)
        for match in _LINE_CALLEE.finditer(line, 0, end)
        if _credential_name(match["name"])
    )
    return sorted(joins)


def _password_name(name: str) -> bool:
    """Whether a credential's name names a password or a secret ('dbPassword', 'DB_PASS', 'clientsecret').

    The name is read as a whole too, as the detector reads it: 'dbPassWord' splits into the
    words 'db', 'Pass' and 'Word', but its letters end in 'password', and the detector reports
    its fallback literal as the password.
    """
    segment = name.rsplit(".", 1)[-1]
    words = _CALLEE_WORD.findall(segment)
    if not words:
        return False
    last = words[-1].lower()
    joined = segment.replace("_", "").replace("-", "").lower()
    return last in _PASSWORD_WORDS or last.endswith(_PASSWORD_ENDS) or joined.endswith(_PASSWORD_ENDS)


def _inside(starts: list[int], literals: list[tuple[int, int]], position: int) -> bool:
    """Whether ``position`` is inside one of a line's string literals (in line order, not overlapping)."""
    inside = bisect.bisect_right(starts, position) - 1
    return inside >= 0 and position < literals[inside][1]


class _LineDepths:
    """The bracket depth of a line's code outside its string literals, read once.

    A closer that closes no opener on the line, or one of another kind
    ('{ password: "[REDACTED]"), ...'), is unmatched: the assignment passes
    withheld its opener with the value it started ('password:
    env("DB_PASSWORD", default_value="<password>")' reaches this pass as
    'password: "[REDACTED]", default_value="<password>")'), or it was opened
    on a line before.
    """

    def __init__(self, line: str, end: int, literals: list[tuple[int, int]]) -> None:
        starts = [left for left, _ in literals]
        self.positions: list[int] = []
        self.depths: list[int] = []
        self.unmatched: list[int] = []
        stack: list[str] = []
        for bracket in _BRACKET.finditer(line, 0, end):
            position, mark = bracket.start(), bracket.group()
            if _inside(starts, literals, position):
                continue
            if mark in _BRACKET_CLOSERS:
                stack.append(_BRACKET_CLOSERS[mark])
            elif stack and stack[-1] == mark:
                stack.pop()
            else:
                self.unmatched.append(position)
            self.positions.append(position)
            self.depths.append(len(stack))

    def depth(self, position: int) -> int:
        """The depth after every bracket before ``position``."""
        before = bisect.bisect_left(self.positions, position) - 1
        return self.depths[before] if before >= 0 else 0

    def entry_depth(self, separator: int) -> int:
        """The depth of an entry whose separator is at ``separator``, counting each unmatched closer after it.

        Each unmatched closer stands for an opener withheld at the start of
        the value it closes, so an entry before it lies inside that value.
        """
        later = len(self.unmatched) - bisect.bisect_right(self.unmatched, separator)
        return self.depth(separator + 1) + later


def _password_values(
    line: str, end: int, literals: list[tuple[int, int]], joins: list[_Join]
) -> list[tuple[int, int]]:
    """The spans of the values of the password names ``joins`` on a line, before ``end``.

    A value runs to the next entry of its own mapping, object or argument list
    (``_NEXT_ENTRY`` outside a literal, at its depth or below), so a keyword
    argument of its read ('cfg.get("db", "password", fallback="<password>")',
    'env("P", default_value=...)', '{ fallback: ... }') is part of it, and to
    the end of the code when no entry ends it. A callee's value is its
    arguments. Each entry is read once for all the joins.
    """
    shape = _LineDepths(line, end, literals)
    starts = [left for left, _ in literals]
    entries = [
        (match.start(), shape.entry_depth(match.start()))
        for match in _NEXT_ENTRY.finditer(line, joins[0].start, end)
        if not _inside(starts, literals, match.start())
    ]
    regions: list[tuple[int, int, int]] = []
    following = 0
    for join in joins:
        depth = shape.depth(join.start) - join.callee
        nested = bool(regions) and join.start < regions[-1][1]
        if nested and depth >= regions[-1][2]:
            continue  # its value ends inside the value it is part of
        if not nested:
            while following < len(entries) and entries[following][0] < join.start:
                following += 1
        # In a value it is nested in, every entry before that value's end is deeper than this one.
        while following < len(entries) and entries[following][1] > depth:
            following += 1
        value_end = entries[following][0] if following < len(entries) else end
        if nested:
            regions[-1] = (regions[-1][0], value_end, depth)
        else:
            regions.append((join.start, value_end, depth))
    return [(start, stop) for start, stop, _ in regions]


def _comment_closer(line: str, comment: int) -> str | None:
    """The closer of a block comment that starts at ``comment`` and stays open past its line, or None."""
    for opener, closer in _COMMENT_CLOSERS.items():
        if line.startswith(opener, comment):
            return closer if line.find(closer, comment + len(opener)) < 0 else None
    return None


def _token_spans(
    line: str, offset: int, start: int, end: int, tokens: re.Pattern[str]
) -> list[tuple[int, int]]:
    """The spans of the tokens in ``line[start:end]`` that ``_credential_literal`` takes for opaque keys."""
    return [
        (offset + token.start(), offset + token.end())
        for token in tokens.finditer(line, start, end)
        if _credential_literal(token.group(), positional=False)
    ]


def _carried_name(line: str, carried: tuple[str, bool] | None) -> str | None:
    """The credential name whose value ``line`` goes on with, or None (``_CONTINUED_LINE``).

    ``carried`` is the name of the line before and whether that line ended
    with a fallback operator.
    """
    if carried is None:
        return None
    name, open_operator = carried
    return name if open_operator or _CONTINUED_LINE.match(line) or _COMMENT_LINE.match(line) else None


def _line_tail(
    line: str, offset: int, carried: tuple[str, bool] | None
) -> tuple[list[tuple[int, int]], tuple[str, bool] | None, str | None]:
    """What ``_redact_line_tails`` withholds on one line.

    Returns the spans, the credential name whose value the next line may go
    on with and whether this line ends with a fallback operator, and the
    closer of a block comment the line leaves open. A line can go on with the
    value of the credential named on the line before (``_carried_name``).
    """
    literals, comment = _line_regions(line)
    code_end = len(line) if comment is None else comment
    joins = _credential_joins(line, code_end)
    if not joins:
        name = _carried_name(line, carried)
        if name is None:
            return [], None, None
        if _COMMENT_LINE.match(line) and carried is not None:
            # A comment line between the operator and its operand keeps the value going.
            closer = None if comment is None else _comment_closer(line, comment)
            return _token_spans(line, offset, 0, len(line), _COMMENT_TOKEN), carried, closer
        joins = [_Join(0, name, False)]
    spans: list[tuple[int, int]] = []
    for start, end in literals:
        if start >= joins[0].start:
            spans.extend(_token_spans(line, offset, start, end, _LITERAL_TOKEN))
    # The next line goes on with the value of the last name, or of a password whose value runs to the end.
    name = joins[-1].name
    passwords = [join for join in joins if _password_name(join.name)]
    if passwords:
        values = _password_values(line, code_end, literals, passwords)
        cursor = 0
        for start, end in literals:
            while cursor < len(values) and values[cursor][1] < end:
                cursor += 1
            if cursor < len(values) and values[cursor][0] <= start and password_literal(line[start:end]):
                spans.append((offset + start, offset + end))
        if values[-1][1] == code_end:
            name = next(join.name for join in reversed(passwords) if join.start >= values[-1][0])
    closer = None
    if comment is not None:
        spans.extend(_token_spans(line, offset, comment, len(line), _COMMENT_TOKEN))
        closer = _comment_closer(line, comment)
    return spans, (name, _OPEN_OPERATOR.search(line, 0, code_end) is not None), closer


def _redact_line_tails(text: str) -> str:
    """Withhold key material after a credential's name on its line: in later string literals and the comment.

    The assignment passes withhold a value to its end (',', ';', a blank, a
    closing bracket or quote), so text after that end kept its literals and
    its comment: 'apiKey: process.env.KEY, // old: <key>' and 'api_key =
    os.environ["KEY"]; # <key>' showed the old key, and a fallback after a
    read the value lexer cut at a quote or bracket ('azureApiKey:
    process.env.K?.trim() || "<key>"', "os.environ[ 'K' ] if PROD else
    '<key>'", 'os.getenv("K", "<key>")', 'cfg("a", "b") || "<key>"') was
    shown in 'name: value' form. On a line where a name the assignment passes
    read as a credential's (``_sensitive_assignment_key``, or
    ``_credential_name``: its last word names one) is joined to a value by
    ':', '=' or '=>', or where a callee whose last word names one is given
    arguments ('sgMail.setApiKey(process.env.K?.trim() ?? "<key>")'), each
    token of a string literal after that name, and of the comment, that
    ``_credential_literal`` takes for an opaque key is withheld; words,
    references, model names and placeholders stay. The value of each
    password's name on the line (``_password_name``), not only the first
    credential name's, is withheld whole up to the next entry of its own
    mapping, object or argument list (``_password_values``: a keyword
    argument of its read, 'fallback="<password>"', is part of it), whatever
    its shape ('dbPassword: process.env.P?.trim() || "<password>"', as
    'db_password = os.getenv("P", "<password>")' is), unless it is a
    variable's name, a path, a URL, a placeholder or shorter than six
    characters (``password_literal``, which the credential detector shares).
    The next line goes on with the value when it
    starts with a fallback operator (Black's '    or "<key>",') or the line
    before ends with one, through comment lines, and a block comment a
    credential's line leaves open ('<!--', '/*') is read to its end. A line
    is read once.
    """
    if not any(mark in text for mark in "\"'`#/<"):
        return text
    spans: list[tuple[int, int]] = []
    carried: tuple[str, bool] | None = None
    closer: str | None = None
    for line in _TEXT_LINE.finditer(text):
        body = line.group()
        if closer is not None:
            close = body.find(closer)
            inside = len(body) if close < 0 else close
            spans.extend(_token_spans(body, line.start(), 0, inside, _COMMENT_TOKEN))
            if close < 0:
                continue
        found, carried, closer = _line_tail(body, line.start(), carried)
        spans.extend(found)
    return _withhold_spans(text, spans)


def _redact_plain_assignments(value: str, depth: int = 0, *, former: bool = False) -> str:
    """Withhold values assigned to sensitive names in ``name=value`` and ``name: value`` form.

    A quoted value under an ordinary name is searched again, so it cannot
    carry a nested credential ('config = "api_key=opaque-value"'); nesting
    past eight levels is withheld.

    Quoted values are read past the quotes a backslash escapes (see
    _ESCAPE_AWARE_QUOTE). The result is then read once more with every quoted
    value closed at its first quote, as the former rule read it. Where a
    backslash escapes nothing ('path = "C:\\x\\" ; password = "v"'), the longer
    reading took the next name into its value, and the former one still finds
    that name's value. A value that is only the backslashes of an escaped quote
    is kept in that reading (``former``), nested values included: the first
    reading withheld what follows it.
    """

    def assignment(m: re.Match[str], second: bool = False) -> str:
        reread = former or second
        full: str = m.group(0)
        if _FINGERPRINT.fullmatch(full):
            return full
        raw: str = m.group("value")
        opener, bare, closer = _unquote(raw, m.group("escaped"))
        key: str = m.group("key")
        sep: str = m.group("sep")
        operator = sep.strip(" \t\r\n\"'")
        if _sensitive_assignment_key(key):
            if reread and not bare.strip("\\"):
                return full
            if not opener and _environment_lookup(m.string, m.start("value")):
                # 'apiKey = process.env.OPENAI_API_KEY', 'api_key = os.getenv("OPENAI_API_KEY")':
                # the value reads a variable by name and holds no credential.
                return full
            if operator in _COMPARISONS:
                # Only a literal that could be a credential is withheld from a comparison:
                # a quoted word ('token == "v"', also in backticks), not "(" or "/*", and a
                # bare opaque value, not an operand ('token == other', 'token != None').
                template = len(bare) > 1 and bare[0] == bare[-1] == "`"
                literal = bare[1:-1] if template else bare
                if not _credential_literal(literal, positional=bool(opener) or template):
                    return full
            if not opener and operator == "=>" and bare.startswith(("{", "[", "(")):
                # A hash entry's nested mapping is withheld whole by the mapping pass; this
                # is an arrow function's body ('token => {').
                return full
            clean: str = _redact_value(bare)
        elif "=" in bare or ":" in bare:
            # Do not let an ordinary assignment swallow a nested credential,
            # e.g. config = "api_key=opaque-value" in a source-code excerpt.
            clean = _redact_plain_assignments(bare, depth + 1, former=reread) if depth < 8 else REDACTED
        else:
            return full
        return key + sep + opener + clean + closer

    text = _ASSIGNMENT.sub(assignment, value)
    if depth == 0 and "\\" in text:
        # Only a backslash makes the two readings differ. Nested values are read
        # once (by _ASSIGNMENT), so each level costs one pass, not two per level.
        text = _FIRST_QUOTE_ASSIGNMENT.sub(lambda m: assignment(m, second=True), text)
    return text

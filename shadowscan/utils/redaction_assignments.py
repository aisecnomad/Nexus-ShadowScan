"""Sensitive values in assignments, mappings and fallback defaults inside text.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. ``name=value`` and ``name: value`` pairs under sensitive names, whole
mapping expressions and indented YAML blocks under sensitive keys, opaque
literals given to names whose last word names a credential, and literal
defaults of credentials read from the environment.
"""

from __future__ import annotations

import re

from shadowscan.utils.redaction_rules import (
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


def _mapping_expression_end(text: str, start: int) -> int:
    """Find a mapping value's delimiter without evaluating source code.

    Quoted scalars, escaped/doubled quotes, concatenations and nested containers
    are consumed in full. Malformed expressions are withheld through EOF.
    Values are visited once and nesting is bounded before allocating more work.
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
            if not brackets:
                return position
            if brackets.pop() != {")": "(", "]": "[", "}": "{"}[char]:
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
        end = _mapping_expression_end(text, start)
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
# and 'protocol' that the netrc credential helper of Git reads. The value after
# 'password', 'passwd' or 'account' is a secret whatever it looks like, so it
# is withheld unless it is only a reference ('password $NETRC_TOKEN'); a name
# is never read as one of those words, so a missing login cannot hide the
# password after it. A quoted value (curl) runs to its closing quote, or to
# the end of its line when it never closes. JSON and shell '\n', '\r' and '\t'
# escapes separate tokens as well ('"machine h\nlogin u\npassword v"'), but a
# value is withheld up to the next blank all the same, so a backslash in it
# never shows its tail. 'macdef <name>' starts a macro, whose lines up to the
# empty line that ends it are withheld whole (see ``_netrc_macro``). An entry
# starts at 'machine' anywhere a word starts, and at 'default' or 'macdef'
# only first on a line or after a quote, and 'macdef' only when its name ends
# that line: those are also ordinary words.
_NETRC_BREAK = r"(?:[ \t\r\n]|\\[nrt])"
_NETRC_END = r"(?=[ \t\r\n]|\\[nrt]|\Z)"
_NETRC_WORDS = r"(?:login|user|port|protocol|machine|macdef|default|password|passwd|account)"
# A value: quoted ('"v"', '\"v\"' inside a JSON string) up to the next blank, or
# unquoted up to the next blank or '\n', '\r' or '\t' escape, where the next
# token can start.
_NETRC_VALUE = (
    r"\"(?:[^\"\\\r\n]|\\.)*+(?:\"\S*+|[^\r\n]*+)"
    r"|\\\"(?:[^\\\r\n]|\\(?!\"))*+(?:\\\"\S*+|[^\r\n]*+)"
    r"|(?:[^\s\\]|\\(?![nrt]))++"
)
# The optional name after 'login', 'machine' and the like, never one of the words.
_NETRC_NAME = rf"(?:{_NETRC_BREAK}++(?!{_NETRC_WORDS}{_NETRC_END})(?:{_NETRC_VALUE}))?"
_NETRC_HEAD = re.compile(
    rf"(?:(?<![^\s\"'`(=])|(?<=\\[nrt]))(?P<machine>machine){_NETRC_BREAK}"
    rf"|(?:\A|(?<=[\r\n\"'`])|(?<=\\[nrt]))[ \t]*+(?P<word>default{_NETRC_END}"
    r"|macdef(?=[ \t]++(?:[^\s\\]|\\(?![nrt]))++(?:[ \t]*+(?:\r?\n|\Z)|\\[nrt])))"
)
# Before a token: blanks, '\n', '\r' and '\t' escapes, and a '#' comment after a blank.
_NETRC_BLANKS = re.compile(r"[ \t\r\n]++")
_NETRC_ESCAPES = ("\\n", "\\r", "\\t")
_NETRC_TOKEN = re.compile(
    rf"(?P<secret>password|passwd|account){_NETRC_BREAK}++(?P<value>{_NETRC_VALUE})"
    rf"|(?P<keyword>login|user|port|protocol|machine|macdef){_NETRC_END}{_NETRC_NAME}"
    rf"|default{_NETRC_END}"
)
# The rest of a run of non-blank characters, or of a line.
_NETRC_RUN = re.compile(r"\S*+")
_NETRC_LINE = re.compile(r"[^\r\n]*+")
# How much of its run past an escape a value may have and still be read as a
# reference ('password $NETRC_TOKEN\n'); a value with more is withheld.
_NETRC_TAIL = 64


def _redact_netrc_entries(text: str) -> str:
    """Withhold the passwords, accounts and macros of netrc entries (see ``_NETRC_TOKEN``)."""
    if "machine" not in text and "default" not in text and "macdef" not in text:
        return text
    return _withhold_spans(text, _NetrcReader(text).read())


class _NetrcReader:
    """Collect the spans of the secrets of a text's netrc entries.

    Each character is read a bounded number of times, so a text is read in
    linear time. An entry's tokens are read once from its head, and a head
    inside an entry already read is skipped. Where an entry ends at a token
    the format does not define, the next head is searched for from its last
    token, so an entry commented out after it is read; the blanks and
    comments between two tokens are read once whichever entry reaches them
    (``gaps``), a token that is not one is read once (``dead``), and so are
    the run of a value, which the values in it share, and the line of a
    comment.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.spans: list[tuple[int, int]] = []
        self.withheld = 0  # where the last value withheld ends
        self.gaps: dict[int, int] = {}  # where a gap read from each of its pieces ends
        self.dead: set[int] = set()  # where no token starts after a gap
        self.run = (-1, -1)  # the run read last, from the end of its first value
        self.quotes: dict[str, int] = {}  # the last of each quote in that run
        self.line = (-1, -1)  # the line read last, from its first comment

    def read(self) -> list[tuple[int, int]]:
        position = 0
        while (head := _NETRC_HEAD.search(self.text, position)) is not None:
            start = head.start("machine") if head.group("machine") else head.start("word")
            before = self.text[head.start() - 1] if head.start() else ""
            quote = before if before in "\"'`" else ""
            position = max(self._entry(start, quote), head.end())
        return self.spans

    def _entry(self, start: int, quote: str) -> int:
        """Collect the secrets of the netrc tokens read from ``start``; return where they end.

        ``quote`` is the quote an entry is written in ('echo "machine h login u
        password v" > ~/.netrc'): the last one in a value closes that string, so
        the value is withheld up to it.
        """
        position = start
        while True:
            token = self._token(self._gap(position))
            if token is None:
                return position
            if token.group("secret"):
                self._secret(token.start("value"), token.end("value"), quote)
                position = token.end()
            elif token.group("keyword") == "macdef":
                position = _netrc_macro(self.text, token.end(), self.spans)
            else:
                position = token.end()

    def _gap(self, position: int) -> int:
        """Where the blanks, escapes and comments from ``position`` end."""
        text = self.text
        pieces = []
        while (known := self.gaps.get(position)) is None:
            blanks = _NETRC_BLANKS.match(text, position)
            if blanks is not None:
                pieces.append(position)
                position = blanks.end()
                if text.startswith("#", position):
                    position = self._line_end(position)
            elif text.startswith(_NETRC_ESCAPES, position):
                pieces.append(position)
                position += 2
            else:
                known = position
                break
        for piece in pieces:
            self.gaps[piece] = known
        return known

    def _token(self, position: int) -> re.Match[str] | None:
        if position in self.dead:
            return None
        token = _NETRC_TOKEN.match(self.text, position)
        if token is None:
            self.dead.add(position)
        return token

    def _line_end(self, position: int) -> int:
        """Where the line of the comment at ``position`` ends, each line read once."""
        first, last = self.line
        if not first <= position <= last:
            line = _NETRC_LINE.match(self.text, position)
            self.line = (position, line.end() if line is not None else position)
        return self.line[1]

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
            run = _NETRC_RUN.match(self.text, position)
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


def _netrc_macro(text: str, start: int, spans: list[tuple[int, int]]) -> int:
    """Withhold the lines of the macro whose name ends at ``start``; return where the macro ends.

    Its lines follow the line of its name, up to the first empty line (a
    line of blanks does not end it). A macro written on the line of its name
    (in a string with '\\n' escapes) is that line's rest. Line breaks stay,
    so excerpt lines keep their numbers.
    """
    line_end = text.find("\n", start)
    end = len(text) if line_end < 0 else line_end
    rest = text[start:end].rstrip()
    if rest.strip():
        spans.append((start + len(rest) - len(rest.lstrip()), start + len(rest)))
        return end
    position = end + 1
    while position < len(text):
        line_end = text.find("\n", position)
        end = len(text) if line_end < 0 else line_end
        line = text[position:end]
        if not line.rstrip("\r"):
            return position
        if line.strip():
            spans.append((position + len(line) - len(line.lstrip()), position + len(line.rstrip())))
        position = end + 1
    return len(text)


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


def _fallback_name(text: str, operator: int) -> str:
    """The name whose value the operator at ``operator`` falls back from."""
    end = _blanks_before(text, operator)
    if end == 0 or text[end - 1] not in ")]":
        return _name_before(text, end, "_$.").rsplit(".", 1)[-1]
    end = _blanks_before(text, end - 1)
    if end == 0 or text[end - 1] not in "\"'":
        return ""
    opening = text.rfind(text[end - 1], max(0, end - 1 - _FALLBACK_NAME_LITERAL), end - 1)
    return text[opening + 1 : end - 1] if opening >= 0 else ""


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

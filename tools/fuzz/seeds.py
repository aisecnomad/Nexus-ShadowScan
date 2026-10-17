"""Seed inputs for the fuzz targets, built in code and written to a corpus directory on demand.

A coverage-guided fuzzer starts from inputs that already reach deep code and mutates them. The seeds
here are small, ordinary texts: the configuration, shell and log lines that carry credentials, and
the string, comment and template syntax of every language the lexer reads. Each is wrapped in the
bytes its target reads as decisions (see :mod:`tools.fuzz.targets`).

They are built here rather than kept as files so that no credential-shaped file is committed: the
credentials come from ``targets.PLANTS``, which assembles them from parts. ``--fixtures`` adds the
repository's own test fixtures, which are small real-looking files, as more seeds. Nothing is read
from outside the checkout or the directory named, and nothing is written outside the corpus directory.

    python -m tools.fuzz.seeds TARGET DIRECTORY [--fixtures DIRECTORY]
"""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Final

from tools.fuzz.targets import (
    LEXERS,
    MAX_INPUT_BYTES,
    PLANTS,
    TARGETS,
    encode_node,
    encode_planted_leaf,
    redaction_record_input,
    redaction_text_input,
    selector,
)

# Texts a credential is planted in: where credentials are found in practice.
REDACTION_CONTEXTS: Final[tuple[str, ...]] = (
    "NAME=value\nDEBUG=1\nREGION=eu-west-1\n",
    '{"id": 7, "tags": ["a", "b"], "nested": {"enabled": true, "limit": null}}\n',
    "service:\n  name: worker\n  replicas: 2\n  env:\n    - name: MODE\n      value: batch\n",
    'curl -sS -H "Accept: application/json" https://example.test/api/v1/items --max-time 30\n',
    'client = Client(base_url="https://example.test")\nresult = client.run(task="summarize")\n',
    "2026-01-01T00:00:00Z INFO request id=7 status=200 path=/v1/items user=svc\n",
    "https://example.test/callback?next=%2Fv1%2Fitems&state=abc123&page=2\n",
    "first line\\nsecond line \\x41 \\u0041 %41 %2F\n",
    "worker --port 8080 --workers 4 --log-level debug --config /etc/worker.toml\n",
)

# Source snippets by file extension: strings, comments, templates and the syntax that is easy to
# mistake for them, in the languages the lexer reads.
LEXING_SNIPPETS: Final[dict[str, tuple[str, ...]]] = {
    ".py": (
        'x = f"{a!r:>{w}} {b}"  # note\ny = """doc\nstring""" + \'\'\'more\'\'\'\n',
        'import os\nname = f"{f\'{os.sep}\'}-{1 + 2}"\nraw = rb"\\d+\\n"\n',
        "def f(a, *, b=1):\n    '''doc'''\n    return lambda: (yield)\n\t\n# trailing",
        'value = "unterminated\nnext = 1\n',
        'text = """never closed\n# not a comment\nimport secret_module\n',
        "a = 1\r\nb = '\\\r\ncontinued'\rc = 3\r",
        "# -*- coding: latin-1 -*-\nx = 'caf\xe9'\n",
    ),
    ".js": (
        "const a = `x ${ `y ${z}` } w`;\nconst b = a / 2 / 3; const r = /ab+c/gi.test(s) // note\n",
        'const el = <div className="a">{items.map(i => <li key={i}>{i}</li>)}</div>;\n',
        "x = y\n/re/.test(z)\nlet s = 'it\\'s'; /* block */ let t = \"a\\\nb\";\n",
        "if (a < b && c > d) { f<T>(x); a << b > c }\n// end\n",
        "const open = `never closed ${\n",
        "const re = /[/]\\/(?:)/u; const d = a /b/ c;\n",
    ),
    ".ts": (
        "const f = <T,>(x: T) => x;\ntype A = Array<Record<string, number>>;\nenum E { A = 'a' }\n",
        "@Component({ selector: 'app' })\nclass C { m<T extends object>(x: T): T { return x } }\n",
        'declare module "x" { export const y: number }\nlet v = <number>w; // cast\n',
        '<?xml version="1.0"?>\n<TS version="2.1"><context><name>X</name></context></TS>\n',
    ),
    ".tsx": (
        "export const A = <T extends object>(p: P<T>) => <Select<Option> value={v} />;\n",
        "const e = <>\n  <Item title='x' {...props}>text {a} / {b}</Item>\n</>;\n",
    ),
    ".jsx": ("const E = () => <p>{'}'} // not a comment {/* nor this */}</p>;\n",),
    ".go": (
        'package main\n\nimport (\n\t"fmt"\n)\n\n'
        "func main() {\n\tfmt.Println(`raw\n\\n`, '\\'', \"\\\"esc\")\n}\n",
        "/* block */ // line\nvar r = '\\x41' + \"a\\u00e9\"\n",
        "var s = `unterminated\n",
    ),
    ".rs": (
        'let r = r#"raw "quoted" "#; let b = b\'x\'; let l: &\'a str = "s\\\n   t";\n',
        "/* outer /* nested */ still */ fn f<'a>(x: &'a str) -> char { '\\u{1F600}' }\n",
        "'outer: loop { break 'outer; } // end\n",
    ),
    ".java": (
        'class A {\n  String t = """\n    text\n    """;\n  char c = \'\\\'\';\n  /** doc */\n}\n',
        'String s = "\\u0022; // not a comment";\n// \\u000a import x;\n',
        '@Annotation("v") public void m() { /* open',
    ),
    ".kt": ('val s = """raw ${x} text"""\nval c = \'c\'\n/* /* nested */ */ // end\n',),
    ".scala": ('val s = s"x ${y}"; val r = """raw"""\n/* nested /* c */ */\n',),
    ".cs": (
        'var a = @"a""b"; var b = $"{x}"; var c = $@"{y}\\";\nvar d = """\n  raw\n  """;\n',
        "#region r\nchar c = '\\''; // line\n/* block */\n#endregion\n",
    ),
    ".fs": ('(* comment (* nested *) *)\nlet s = """triple"""\nlet c = \'a\'\nlet f (x: \'T) = @"verb"\n',),
    ".rb": (
        "# comment\n=begin\nblock\n=end\nputs <<~EOS\n  text #{x}\nEOS\nputs %q(a (b) c), %w[a b]\n",
        'puts "#{x} #{ "nested" }"; r = /re/i; c = ?x\n',
    ),
    ".php": (
        "<?php // c ?>text<?= $x ?>\n<?php $a = <<<EOT\nline {$b}\nEOT;\n$n = <<<'EOT'\nraw\nEOT;\n",
        "<?php #[Attribute]\nclass A { /* block */ # hash\n}\n",
    ),
    ".swift": ('let r = #"raw "quoted""#\nlet m = """\n  multi \\(x)\n  """\n/* /* nested */ */\n',),
    ".dart": (
        "var r = r'raw'; var m = '''multi\nline'''; var i = \"${a + \"b\"}\";\n/* /* nested */ */ // end\n",
    ),
    ".c": ('char *s = "a\\"b"; /* c */ // d\n',),
    ".lua": ("local s = [[long\nstring]] -- comment\n",),
}


def _lexer_for(extension: str) -> tuple[str | None, str, bool]:
    return next(entry for entry in LEXERS if entry[1] == extension)


def lexing_input(extension: str, source: str) -> bytes:
    """The input that makes ``check_lexing`` read ``source`` as a file with ``extension``."""
    return selector(LEXERS, _lexer_for(extension)) + source.encode("utf-8")


def redaction_text_seeds() -> Iterator[bytes]:
    for plant in PLANTS:
        for context in REDACTION_CONTEXTS:
            # At the start, in the middle (the default cut) and at the end of the text.
            for cut in (0, 128, 255):
                yield redaction_text_input(plant, context, cut=cut)
        # Separators on both sides of a format credential.
        yield redaction_text_input(plant, "key", before='"', after='"')
        yield redaction_text_input(plant, "key", before="=", after="\\n")


def redaction_record_seeds() -> Iterator[bytes]:
    payloads = (
        None,
        {"name": "worker", "env": {"id": "7"}, "args": ["--port", "8080"]},
        {"headers": {"note": "x"}, "data": [1, True, None, "text"]},
        [{"command": "run", "value": "v"}, ["nested", ["deeper"]]],
    )
    for plant in PLANTS:
        for payload in payloads:
            for flags in (0, 1, 2, 3):
                yield redaction_record_input(plant, encode_node(payload), "x", flags=flags)
        leaves = [encode_planted_leaf("key", before=" ", after=" "), encode_planted_leaf("")]
        yield redaction_record_input(plant, bytes([5, len(leaves)]) + b"".join(leaves), "")


def lexing_seeds() -> Iterator[bytes]:
    for extension, sources in LEXING_SNIPPETS.items():
        for source in sources:
            yield lexing_input(extension, source)


SEEDS: Final[dict[str, Callable[[], Iterator[bytes]]]] = {
    "redaction-text": redaction_text_seeds,
    "redaction-record": redaction_record_seeds,
    "lexing": lexing_seeds,
}


def fixture_seeds(target: str, root: Path) -> Iterator[bytes]:
    """Seeds from the files under ``root``: source files for the lexer, small texts for the redactor."""
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if not raw or len(raw) >= MAX_INPUT_BYTES:
            continue
        if target == "lexing":
            if any(entry[1] == path.suffix for entry in LEXERS if entry[1]):
                yield selector(LEXERS, _lexer_for(path.suffix)) + raw
        elif target == "redaction-text" and len(raw) < 4096:
            text = raw.decode("utf-8", errors="replace")
            # Rotate the credential family so the fixtures between them reach every one.
            index = int.from_bytes(hashlib.sha256(raw).digest()[:2], "big") % len(PLANTS)
            yield redaction_text_input(PLANTS[index], text)


def write_corpus(target: str, directory: Path, fixtures: Path | None = None) -> int:
    """Write the seeds of ``target`` into ``directory``, one file each, and return how many."""
    seeds = list(SEEDS[target]())
    if fixtures is not None:
        seeds.extend(fixture_seeds(target, fixtures))
    directory.mkdir(parents=True, exist_ok=True)
    unique = {hashlib.sha256(seed).hexdigest()[:20]: seed for seed in seeds}
    for name, seed in unique.items():
        (directory / f"seed-{name}").write_bytes(seed)
    return len(unique)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.fuzz.seeds", description=__doc__.split("\n\n")[0])
    parser.add_argument("target", choices=sorted(TARGETS))
    parser.add_argument("directory", type=Path, help="corpus directory to write the seed files into")
    parser.add_argument("--fixtures", type=Path, help="also seed from the small files below this directory")
    args = parser.parse_args(argv)
    count = write_corpus(args.target, args.directory, args.fixtures)
    print(f"{args.target}: wrote {count} seeds to {args.directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

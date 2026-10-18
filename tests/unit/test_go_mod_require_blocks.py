"""go.mod ``require ( ... )`` blocks are read in linear time, as the lazy pattern read them.

``require\\s*\\((.*?)\\)`` read from each unclosed ``require(`` to the end of the
file before failing, so a file of them cost time quadratic in its length; Python
3.14's engine took that past the module-level linearity check, which is how the
3.14 CI legs failed. The blocks are now found by searching for each opening and
the next ``)``, and must be exactly the blocks the old pattern found.
"""

from __future__ import annotations

import random
import time

import regex

from shadowscan.connectors.code.manifests import _go_require_blocks, parse_go_mod

_OLD = regex.compile(r"require\s*\((.*?)\)", regex.S)

_GO_MOD = """module example.com/agent

go 1.22

require (
\tgithub.com/sashabaranov/go-openai v1.20.4
\tgithub.com/tmc/langchaingo v0.1.8 // indirect
)

require github.com/anthropics/anthropic-sdk-go v0.2.0

require(
\tgolang.org/x/net v0.24.0
)
"""


def test_a_go_mod_reads_every_requirement_once():
    # The one-line pattern used to read a block's "require (" too, as a
    # dependency named "(" whose version was the first module of the block.
    deps = [(dep.name, dep.spec) for dep in parse_go_mod(_GO_MOD).deps]
    assert deps == [
        ("github.com/sashabaranov/go-openai", "v1.20.4"),
        ("github.com/tmc/langchaingo", "v0.1.8"),
        ("golang.org/x/net", "v0.24.0"),
        ("github.com/anthropics/anthropic-sdk-go", "v0.2.0"),
    ]


def test_the_blocks_are_the_ones_the_lazy_pattern_found():
    pieces = ["require", "require ", "require\n", "(", ")", "x v1.0.0\n", " ", "\t", "re", "quire("]
    rng = random.Random(260)
    texts = [_GO_MOD, "", "require(", "require()", ")require(", "require(a)require(b", "require (\nx v1\n"]
    texts += ["".join(rng.choice(pieces) for _ in range(rng.randrange(1, 40))) for _ in range(3000)]
    for text in texts:
        assert list(_go_require_blocks(text)) == _OLD.findall(text), repr(text)


def _best_cpu(work, repeats: int = 3) -> float:
    best = float("inf")
    for _ in range(repeats):
        started = time.process_time()
        work()
        best = min(best, time.process_time() - started)
    return best


def test_unclosed_openings_are_read_in_linear_time():
    def parse(count: int) -> float:
        text = ("require(" + "'") * count
        return _best_cpu(lambda: parse_go_mod(text))

    small, large = parse(20_000), parse(80_000)
    # Four times the input; the quadratic pattern took about sixteen times as long.
    assert large < max(small, 0.002) * 10, (small, large)

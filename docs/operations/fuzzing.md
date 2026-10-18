# Fuzzing

The redactor keeps credentials out of reports and logs, and the source lexer decides which
parts of a file are code. Both read text the scanner does not control, so both are fuzzed: a
coverage-guided engine mutates inputs, watches which code each one reaches and keeps the ones
that reach more, while a check after every run decides whether a guarantee still holds. This
page says what each target checks, what it has found, how to run it and what it leaves out.
It is assurance evidence next to the unit tests, the regular-expression linearity test and the
[evaluation](../evaluation.md) corpora. It is not a security guarantee.

## What is fuzzed

| Target | Code under test | The fuzzer chooses | What fails a run |
|---|---|---|---|
| `redaction-text` | `sanitize_text` | the text, where one of 14 synthetic credentials is planted in it, and the characters on either side of it | a result that is not a `str`; the secret part of the credential still in the result; a different number of line breaks than the input had |
| `redaction-record` | `sanitize` | a record of mappings, lists, strings, numbers, booleans and `None`, with the credential planted in a string and under the `note` key, and the `redact_short_secrets` and `env_values_are_secrets` options | the record passed in changed; a result that is not JSON; the secret part of the credential still in the serialized result |
| `lexing` | `noncode_ranges`, `nul_reading_ranges` | one of 35 language and extension readings (JSX included) and the source text | spans that are not integer pairs inside the text, sorted by start; incompleteness that is not a bool; two answers for one text; spans out of bounds on the NUL-reading path |

A target accepts the code's own fail-closed errors, because they are the documented answer to
hostile input: `SanitizationLimitError` from the redactor's work budget and `MatchTimeoutError`
from the lexer's match budget. Any other exception is a finding. A scan must end in a report or in
a recorded coverage gap, never in an arbitrary exception.

The 14 credentials are a GitHub token, an AWS key ID, a Slack token, an OpenAI key, a Google API
key, a JWT, a PEM private key block, a bearer header, a basic-auth header, a password in a URL, a
key in a query string, a quoted assignment, a shell `export` and a JSON member. Each is synthetic
and assembled from parts in `tools/fuzz/targets.py`, so no credential-shaped value is stored in
the repository and [`make secrets`](../testing.md#other-gates) has nothing to approve. A violation
message names the invariant and the input's SHA-256 digest and length, and never quotes the input.

## One set of checks, three ways to run it

The checks are plain functions of bytes, in
[`tools/fuzz/targets.py`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/fuzz/targets.py).

* **Atheris** (`python -m tools.fuzz`) is the fuzzer proper. It runs on Linux x86_64 from the
  hash-locked engine described [below](#the-engine-lock) and instruments only the `shadowscan`
  modules.
* **Hypothesis** runs the same functions in the ordinary suite
  ([`tests/unit/test_fuzz_targets.py`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tests/unit/test_fuzz_targets.py)),
  on every platform and Python version CI covers. A change that breaks a target, or a refactor that
  leaves it testing nothing, fails `make test` instead of waiting for the next scheduled run.
* **The seeds** are replayed as ordinary tests too, so every starting input is known to pass.

The same test module proves each check can fail. It swaps in a redactor that keeps the credential,
drops a line break, returns the wrong type or mutates its argument, and a lexer that returns bad
spans or two answers, and requires the matching check to raise.

## What it has found

Three weaknesses, all fixed with regression tests, and a fourth place hardened with them. None
exposed a credential. The tokenizer faults raised exceptions, which the filesystem connector's
per-file isolation already turned into a recorded "file analysis incomplete" diagnostic (an
incomplete scan, never a clean result); the fixes make the outcome deterministic and the failure the
documented one.

1. **A JavaScript-family string that ends in a backslash.** For a text such as `"\`, the lexer
   returned a span one character longer than the text, which breaks its contract that spans lie
   inside it. Spans are clamped to the text.
2. **A fault in CPython 3.12's tokenizer, in the lexer.** For a NUL byte after an indented or
   malformed line the C tokenizer hands back a token while an exception is still set
   ([python/cpython#140576](https://github.com/python/cpython/issues/140576)). The exception that
   surfaces varies from process to process: a `SystemError`, or an `AttributeError` for a name that
   exists. 3.11 reads such text and 3.13 raises `TokenError`. 3.12 receives security fixes only, and
   3.12.13 still has the fault.
3. **The same fault, in the redactor's Python assignment scanner.** It surfaced from
   `sanitize_text` for a two-line input.
4. **The same fault, in the re-export prefilter.** The fuzzer did not reach this one; it was fixed
   with the other two because it calls the same tokenizer.

All three call sites now read the tokenizer through
[`shadowscan/utils/python_tokens.py`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/shadowscan/utils/python_tokens.py).
It turns any failure the tokenizer does not document into one `TokenizerFault`. The lexer then
masks the rest of the file and reports itself incomplete, the redactor treats the rest of the text
as undecided and withholds it, and the prefilter calls the module no import-only shim. An exception
raised by the caller's own `readline`, such as the redactor's work budget, passes through unchanged:
the guard never reads it as a fault. The first fix, matching `SystemError` alone, was not enough; a
short seeded run found the `AttributeError` form afterwards.

As a check on the harness itself, the three targets were run against the code as it stood before
these fixes. Each failed from its seeds in about a minute or less (6, 10 and 62 seconds in one run
on a shared two-core machine). An engine that found nothing in code with known defects would
prove nothing about clean code.

## What it does not show

* **A clean run is not a proof.** A fuzzer finds inputs that break a guarantee; it cannot show there
  are none. The scheduled run is 15 minutes per target on a hosted runner, and no corpus carries
  over between runs: every run starts again from the seeds.
* **Three targets only.** The redactor and the lexer are fuzzed. The matcher, the format parsers,
  the connectors' parsers and the HTTP client are not.
* **Python-level coverage only.** Atheris instruments the `shadowscan` modules. The compiled `regex`
  module and the interpreter are not instrumented, so what the fuzzer sees of a regular expression
  is the Python code around it. The linearity test and the per-input match budget are the controls
  for regular-expression cost, not this.
* **A narrow oracle.** The redaction targets check that 14 known credential shapes do not survive.
  They say nothing about a credential the redactor has no rule for, and nothing about recall on
  real data, which the [evaluation](../evaluation.md) corpora measure (they are written by the
  authors, see their limits).
* **Inputs of at most 8 KiB.** Larger files run the same code with more of it. The size limits
  themselves are unit-tested, not fuzzed.
* **Linux x86_64 only.** PyPI publishes Atheris wheels for nothing else, so `make fuzz` does not
  run on macOS or Windows. Hypothesis runs everywhere.
* **Not OSS-Fuzz or ClusterFuzzLite.** The OpenSSF Scorecard `Fuzzing` check recognizes those and a
  few native fuzzers; it does not recognize Atheris or Hypothesis for Python, so this harness
  does not move that score. Adding ClusterFuzzLite would need a reviewed, digest-pinned builder
  image and action, and that review has not been done.

## Run it

You need Linux x86_64 and a supported CPython that Atheris publishes a wheel for
(`requirements-fuzz.lock` pins the hashes); the harness has not been run on every one of them. Install the engine on top of the runtime, from the hash locks and never from
source:

```bash
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock -r requirements-fuzz.lock
make fuzz                      # every target for 60 seconds
make fuzz FUZZ_SECONDS=600     # longer
```

`make fuzz` writes each target's seeds, corpus and any failing input into a new temporary
directory, printed on its first line, so nothing lands in the checkout. It is not part of
`make check`: fuzzing has no end, and `make install` does not install the engine.

One target by hand:

```bash
work="$(mktemp -d)"
python -m tools.fuzz.seeds lexing "$work/corpus" --fixtures tests/fixtures
python -m tools.fuzz lexing -max_total_time=300 -artifact_prefix="$work/crashes/" "$work/corpus"
```

`python -m tools.fuzz.seeds` builds the starting corpus in code, from the credentials and source
snippets in
[`tools/fuzz/seeds.py`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/fuzz/seeds.py),
and `--fixtures` adds the small files under `tests/fixtures`. Everything after the target name goes
to libFuzzer. Unless you pass the same flag, `-max_len=8192`, `-timeout=30` (a hang) and
`-rss_limit_mb=2048` apply, and a failing input goes to a new temporary directory.

## The Fuzz workflow

[`fuzz.yml`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/workflows/fuzz.yml)
runs each target on its own runner:

* Sundays at 03:37 UTC for 900 seconds per target;
* on demand for 1 to 3000 seconds (the `seconds` input is checked as a number before it reaches
  the shell);
* for 60 seconds per target on a pull request that changes `tools/fuzz/**`, the engine lock or the
  workflow, so a broken harness is found before the weekly run.

It has a read-only token and no secrets, installs the engine from the hash lock, caches nothing and
writes nothing to the repository. A fork's pull request runs with the same read-only token.

**A failing run keeps the lexing input and withholds the redaction inputs.** A redaction input is a
text that gets a credential past the redactor, [SECURITY.md](../security.md) takes redaction
failures through the private advisory, and a public repository's job logs and artifacts are public.
The workflow therefore sends the engine's output to a file and prints only what comes before the
line where the engine dumps the input: the traceback and the violation message, which names the
input by digest. The lexing input contains no credential, so it is uploaded as the
`fuzz-crash-lexing` artifact for 14 days.

## When a run fails

1. **Lexing.** Download the artifact and replay it. Run it on the same Python minor version the job
   used (3.12): the tokenizer fault above depends on the interpreter.

   ```bash
   python -m tools.fuzz lexing path/to/crash-file        # runs the one input; exit status 77 if it still fails
   python -m tools.fuzz lexing -minimize_crash=1 -runs=2000 \
       -exact_artifact_path=minimal path/to/crash-file   # shrinks it; interrupt when it stops getting smaller
   ```

2. **Redaction.** The input is not kept, so rediscover it: run `make fuzz FUZZ_SECONDS=900` or the
   one target for as long as the job did. A run is not repeatable from its seed, because the engine
   and the interpreter's memory layout both vary, but the digest in the job log tells you when you
   have the same input. Handle a redaction failure as SECURITY.md describes for a report: in a
   private advisory until the fix lands, with its regression test.
3. **Fix it with a regression test** that builds the case in code, as the tests for the findings
   above do. Do not commit the fuzzer's input file as a binary corpus entry, and do not paste it into
   a public issue before you have read it: fixture-derived seeds can carry synthetic credentials,
   and fuzzed text can be anything.
4. Run `make test` (it runs the same checks through Hypothesis) and, if the change is to the lexer
   or redactor, `make evaluate`.

## Add a target

1. Write `check_<name>(data: bytes) -> None` in `tools/fuzz/targets.py`. Decode the case from the
   bytes with `Cursor`, call one public API and raise `_violation(data, "...")` when a guarantee
   fails. Let the API's own documented errors pass and nothing else.
2. Add it to `TARGETS` there and to `TARGET_NAMES` in `tools/fuzz/harness.py`, write its seeds in
   `tools/fuzz/seeds.py`, and add its name to the `fuzz` target in the Makefile and to the matrix in
   `fuzz.yml`. The repository tests fail until all five agree.
3. Add a Hypothesis test and one "a broken implementation is caught" test in
   `tests/unit/test_fuzz_targets.py`, and a row to the table above.

## The engine lock

[`requirements-fuzz.lock`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/requirements-fuzz.lock)
pins Atheris 3.1.0 with the SHA-256 of every file PyPI lists for it (three wheels, no source
distribution; Atheris has no dependencies). It is installed with `--require-hashes
--only-binary=:all:`, so pip never compiles libFuzzer or resolves the package from the live index.
The wheel, the worker image and the other locks do not depend on it. `make audit` and the weekly
audit workflow audit it with the others. Dependabot does not read it, so refresh it by hand as its
header describes.

The workflow runs CPython 3.12. When the harness was written its targets also ran under 3.12.3 for
several minutes each and under 3.13.16 for 20 seconds each, and the tokenizer guard's tests pass on
3.11.17, 3.12.3, 3.12.13 and 3.13.16.

# Local readiness and staged-file checks

Start an incomplete-scan investigation with `summary.incomplete_reasons` and
the affected connector's errors and coverage ledger. On 2026-10-20, scanner
package code matching candidate
[`423ef281361bc0b610274ebede0186e15942ddab`](https://github.com/aisecnomad/Nexus-ShadowScan/commit/423ef281361bc0b610274ebede0186e15942ddab)
on macOS arm64 / Python 3.11.16 completed these default offline scans with
exit 0, no incomplete reasons and no coverage gaps:

| Input | Files | Source bytes | Findings |
|---|---:|---:|---:|
| Bundled `tests/fixtures/sample_repo` | 24 | 6,996 | 12 |
| First eight `realistic_corpus.json` projects, combined | 49 | 43,245 | 11 |
| Requests 2.34.2 Python sources | 19 | 217,284 | 0 |
| Click 8.5.0 Python sources | 17 | 441,955 | 0 |
| Rich 15.0.0 Python sources | 100 | 1,218,165 | 0 |
| aiohttp 3.14.5 Python sources | 54 | 994,558 | 0 |

The first two are authored fixtures; the library inputs are installed Python
source files, not full upstream repositories. They were read as data, never
executed. These six cases establish neither field reliability nor a guarantee
that an arbitrary repository completes.

A default scan of the clean scanner checkout with its benchmark companion
uninitialized still exited 3: three `analysis-limit`, three `sanitization-limit`
and one `unresolved-link`. Initializing companion commit
`e027b98fdfbfdc242a4c89ee7c62f41b2dbacc5e` changed those counts to five
`analysis-limit`, three `sanitization-limit` and three `oversize-file`.
The extra limits came from retained benchmark JSON, not ordinary application
source. A separate discounted sanitization gap cost 0.25 weighted entries and
was tolerated in both scans; increasing the gap budget would not resolve the
other failures. The explicitly scoped `examples/shadowscan.self-scan.yaml`
completed with exit 0 and 23 findings in both companion states.

Common causes include oversized JSON or generated files, undecodable source,
malformed configuration, AST or credential-analysis quotas, and expired
matching or connector deadlines. A larger coverage budget cannot make an
unbounded gap complete. [The remediation table below](#acting-on-incomplete-scans)
maps the reason categories to actions without disabling redaction or confinement.

`shadowscan code --quick` scans the exact changed blobs in the Git index.
It does not substitute unstaged working-tree edits. Run it at the repository
root, or pass one or more local repository roots:

```bash
shadowscan code --quick --preflight
shadowscan code --quick --fail-on high
shadowscan code . --format json -o full-report.json
```

The last command performs the full follow-up scan. Quick mode reads only
changed staged files: unchanged manifests, settings, local imports and other
cross-file context are absent unless they are staged too. That reduced context
can change both detection and classification. Use the full scan for an
inventory, cross-file proofs, release review or a baseline comparison.

## Scope and exits

Quick findings carry `staged-scan` and `metadata.staged_scan`. A warning names
the staged-file and deletion counts even when there are no findings. The
report's `collection_scope.comparable` is false: missing findings cannot be
treated as resolved by `shadowscan diff`. The incremental cache is bypassed.

An explicitly selected staged scope can finish with exit 0. Exit 2 means
`--fail-on` was reached, exit 3 means that scope could not be scanned completely,
and exit 1 is an invocation or setup error. Deletions have no new content to
scan; deletion-only and empty staged scopes are explicitly reported. The
normal excludes and coverage policy still apply; `--max-coverage-gap 0`
requires strict accounting within the chosen scope.

The snapshot accepts at most 100 changed files, 1 MiB per file and 8 MiB of
combined Git output. Each Git read has a ten-second ceiling, additionally
bounded by the connector deadline. A missing blob, unresolved conflict,
staged symbolic link or submodule, unsupported path or exceeded limit leaves
the scan incomplete. Split a large commit or run a full scan; quick mode never
falls back to unstaged content or silently truncates the selection.

Git 2.45 or later and a local `.git` directory are required. Linked worktrees,
alternate object stores and Git configuration includes are refused by the
existing metadata confinement policy. Git hooks, filters, external diff
drivers, filesystem monitors and lazy network fetches do not run. Source
content and MCP commands are inspected as data, never executed.

Only the ordinary `.git/index` is supported. Git can select a temporary index
for `git commit -a` or commits with explicit path arguments. Quick scans and
quick preflight refuse such an index with exit 3, instead of checking a
different selection. Use `git add PATH...` followed by plain `git commit`;
an inherited `GIT_INDEX_FILE` must be unset or name the ordinary index of the
selected root. Foreign index paths are never opened.

The scanner and the preflight do not offer a 500 ms latency guarantee. Fresh
process startup, signature loading, Git metadata checks, file count and source
complexity all contribute to elapsed time. Measure the installed version on
the target runner before setting a commit-hook latency budget.

On 2026-10-20, seven fresh-process runs of the development version on macOS
arm64 with Python 3.11.16 and a three-file synthetic repository measured
877 ms median for `--quick` (795–1101 ms) and 252 ms for
`--quick --preflight` (245–309 ms), with warm filesystem caches.
A follow-up seven-process comparison on the same fixture reduced the quick
median from 835 ms to 616 ms (26%) by using LibYAML for signature-pack events
when available. The bounded Python composer and constructors still enforce
the same input, alias, node, nesting, expansion and unique-key checks; platforms
without LibYAML retain the Python parser. The optimized runs ranged from
588–824 ms. The requested sub-500 ms target remains unmet. Preflight skips
signature loading and source analysis, so its time is not a scan result.

## Install the pre-commit hook

The source repository ships the `shadowscan-staged` hook in
`.pre-commit-hooks.yaml`. Quick mode and this hook are unreleased; the published
PyPI 0.1.2 package does not provide them. Select a reviewed full 40-character
commit SHA containing the hook, then add this to the consumer repository's
`.pre-commit-config.yaml`, replacing the placeholder:

```yaml
repos:
  - repo: https://github.com/aisecnomad/Nexus-ShadowScan
    rev: REPLACE_WITH_REVIEWED_40_CHARACTER_SHA
    hooks:
      - id: shadowscan-staged
```

Use Python 3.11 or later, Git 2.45 or later and a POSIX host. Install pre-commit
in your development environment, then run these commands at the consumer
repository root:

```bash
pre-commit validate-config
pre-commit install
pre-commit run shadowscan-staged
```

Pre-commit installs the pinned scanner source in its own Python environment.
Its first run includes environment setup and may download dependencies; it
does not meet a sub-500 ms startup budget. Subsequent scans also exceeded
500 ms in the local measurements above. The source SHA pins the scanner, but
pre-commit's normal Python installation resolves its dependencies from the
package index; it does not apply this repository's hash locks.

For a separately [hash-locked source installation](../getting-started/install.md#from-a-reviewed-revision-hash-locked),
install the reviewed scanner in the environment on pre-commit's `PATH` and use
this local hook instead:

```yaml
repos:
  - repo: local
    hooks:
      - id: shadowscan-staged
        name: ShadowScan staged files
        entry: shadowscan code --quick --fail-on high --max-coverage-gap 0
        language: system
        pass_filenames: false
        always_run: true
        stages: [pre-commit]
```

Both forms use `pass_filenames: false`: filenames cannot become command
arguments, and the scanner selects and reads the index itself. `always_run`
keeps deletion-only and empty staged scopes visible. The shipped hook runs
serially and blocks on high findings or incomplete coverage. Pre-commit
reports hook failure for a nonzero scanner exit; it must not translate exit 3
into success. `--all-files` does not expand this hook's staged-only scope.
Keep a full scan in CI; this hook does not replace it.

## What preflight checks

`shadowscan code PATH --preflight` checks that a local root can be opened
safely and reports its estimated connector deadline. For an ordinary root it
then runs the scanner's walk with content analysis left out and lists, under
`static_gaps`, the files over `max_file_size`, unfollowed links and other
static coverage gaps a full scan would record
([incomplete scans](../getting-started/incomplete-scans.md)). With `--quick`, it also
checks the bounded staged snapshot and reports file and deletion counts.
It supports table output or `--format json`; `-o` saves private JSON.

Preflight emits `shadowscan.code-preflight/v1` with `scan_performed: false`.
Quick preflight enforces the snapshot's file-count and byte limits, but does
not simulate the scanner's separate static budgets. Neither form analyzes
source, detects credentials or validates inventory, so neither can promise that
the eventual scan will be complete: content can still fail to parse or exhaust a
budget. Its exit 0 means those checks passed, not that the repository is clean.
Exit 3 means a readiness check was blocked or a static gap would leave the full
scan incomplete. Run the same
command without `--preflight` to obtain an actual scan report.

## Acting on incomplete scans

The default coverage budget already permits bounded losses of 2% of examined
entries, capped at 100 weighted entries per root. Unbounded losses, including
timeouts and unread directory scopes, always fail closed. The CLI names reason
categories and prints one remediation line per category; JSON retains the diagnostics
and coverage ledger. Start with those details instead of suppressing exit 3.

| Reason | First action |
|---|---|
| `oversize-file` | Review the named input and the connector's `max_file_size`; split or deliberately raise its bounded size limit. |
| `unparsed-input` | Check syntax, encoding and the documented input/export shape. |
| `unresolved-link` | Supply a regular file inside the intended scan root; do not disable confinement. |
| `timeout` | Narrow the selected roots or increase the bounded connector timeout after measuring the workload. |
| `analysis-limit` | Split unusually complex source or review the documented per-file limit. |
| `sanitization-limit` | Split oversized inputs and keep redaction enabled. |
| `access-denied` / `upstream-error` | Verify read-only permissions or provider availability, then retry the affected source. |
| `subset-scan` | Run without `--triage` for full source analysis. |

See the [coverage policy](../scanning.md#coverage-policy) and
[code connector limits](../connectors/code.md) for the exact scope of defaults,
strict accounting and the explicit CI profile.

# Scan semantics

## Coverage policy

A code scan is *complete* when every file it was asked to assess was assessed.
Situations that are deliberately outside a repository's own content, and gaps
that are never silent:

* **Symbolic links** are never followed. A link is skipped silently when its
  own name is one the scanner never reads (a lockfile, generated bundle or
  image), or when it is a source file whose target is analyzed at its real path
  in the same project, with the same test classification, extension and
  file-name signals. A coding-agent instruction document (`AGENTS.md`,
  `AGENT.md`, `CLAUDE.md`, `CLAUDE.local.md`, `GEMINI.md`,
  `copilot-instructions.md`) that links to another instruction document in the
  same project with the same test classification is also covered: the target is
  scanned at its real path, so the alias is not a second agent definition and
  its alias-only file name is not reported separately. With
  `inspect_model_artifacts`, a model or packaged-binary artifact link with an
  artifact suffix (`.gguf`, `.safetensors`, `.onnx`, `.exe`, `.bin`, `.pkg`)
  to a scanned artifact with the same suffix, in the same project and test
  classification (`latest.gguf` linking to `model-q4.gguf`), is covered the
  same way: artifacts are inspected by suffix and content, and the target is
  inventoried at its real path. Every other link is a
  [coverage gap](#coverage-budget-and-strict-accounting): other configuration
  and document aliases, whose parsing can depend on their path; aliases into
  another project or test directory; links into excluded or unread content;
  links outside the root; and unresolved links. A dangling link, or one to a
  single regular file, costs one entry of the coverage budget, and so does an
  alias of a directory the walk scans whole at its real path inside the root
  (`lib_alias` linking to `lib`, `docs/_static` to `../assets`): its files are
  read and counted there, and only the paths below the alias are not
  assessed. Any other link to a directory (outside the root, into an excluded
  or unselected directory, or reading test code as product code), which can
  stand for any number of files, makes the scan incomplete (exit code 3) at
  once, and so does a link to a directory, or a dangling one, whose path names
  a directory a coding agent or MCP client reads its configuration from
  (`.claude`, `.cursor`, `.vscode`, `.roo`, `.continue`, `.github` and the
  others the coding-agent and MCP file signatures name), even an alias of a
  scanned directory: under that path its files are configuration, at their
  real path they are not. The `ci` profile never declares such a link. So does a
  dangling link or one to a single file whose own name makes it agent
  configuration, as an oversize copy of that file does, under a test path
  too: an MCP configuration by a dedicated name in any letter case
  (`.mcp.json`, `.MCP.JSON`), a coding-agent instruction, rule or settings
  file (`CLAUDE.md`, `.claude/settings.json`), a file a coding-agent or MCP
  file signature selects, directory-wide globs included
  (`.roo/rules/deploy.md`, `.continue/mcpServers/x.yaml`), or an agent
  manifest or card. A link named like a manifest or build file (`Dockerfile`,
  `package.json`, `requirements.txt`, `.env`, `*.tf`) or like a shared client
  file (`config.json`, `settings.json`), which is MCP configuration only by its
  content, costs one entry like any other.
  Files are read relative to the opened scan root without following a link in
  any path component, so a directory replaced by a link after the walk listed it
  fails that file's read (incomplete) instead of reading content outside the
  root. Like a read by path, this needs only search permission on the
  directories above each file.
* **Oversize files** (`max_file_size`, default 1,000,000 bytes) that the scanner would
  inspect are a coverage gap when skipped: one entry of the
  [budget](#coverage-budget-and-strict-accounting), or an immediate exit 3 for
  agent configuration (as the links above), for a JSON, TOML or YAML file
  the MCP parser decides by its content (`deploy/tools.json`,
  `.vscode/settings.json`) whose bytes may name a server table key
  (`mcpServers`, `mcp_servers`, an `mcp` key however quoted, spaced or
  escaped, read behind any padding up to 128 MiB, and taken to name one past
  that), for an MCP registry `server.json`, and, while `scan_secrets` is on,
  for a dotenv or tool credential file (`.env`, `.npmrc`, `.netrc`), which
  exists to hold a credential. Known generated, binary and
  lockfile names in `oversize_skip_globs` are declared omissions and remain
  warnings, including when `strict_coverage` is enabled.
* **Binary or undecodable content.** Text with a UTF-8, UTF-16 or UTF-32
  byte-order mark is decoded and the mark removed. A Python source is decoded
  with the codec its `# coding:` cookie declares. Text that is not valid UTF-8
  and has no NUL byte (Latin-1 or Windows-1252 prose, Shift-JIS comments) is
  read with each byte that is not valid replaced by U+FFFD, except in a Python
  source or a notebook, whose own runtime rejects it: everything the
  scanner looks for is ASCII, which such an encoding writes the same way, so the
  file is analyzed in full and the scan stays complete; the warning `is not
  valid UTF-8, the bytes that are not were replaced` records it (one warning
  per kind, listing the first files; [strict accounting](#coverage-budget-and-strict-accounting) makes each file a gap
  instead). Content in which any 8 KiB window has more than four characters,
  and more than a tenth of the window, that are not valid UTF-8, or that holds a
  control character other than tab, line break or form feed anywhere, is not
  text and stays a gap. A file of at
  least 512 bytes that is valid UTF-8, has at most one NUL byte in 200 and holds
  no other control character in its first 8 KiB (a TypeScript cache key joined
  with a literal NUL) is read as text too, with the warning `stray NUL bytes in
  text, read as text`. Names are matched in it without its NUL bytes, as bash
  removes them from a script, so a NUL cannot split a host or variable name
  (`api.open<NUL>ai.com` is matched as `api.openai.com`). Node and PHP keep NUL
  bytes, and removing one can join two characters into a comment opener
  (`/<NUL>*`) or a PHP closing tag (`?<NUL>>`), so a source file is lexed both
  with and without them: only text that both readings take for a comment or a
  string is masked, and the file's lexing is incomplete (exit code 3) unless
  both readings agree. Any other file the scanner
  analyzes by name (source, configuration, documents, `.env`, extensionless
  files) that has a NUL byte in its first 8 KiB, or that its declared codec
  cannot decode or does not read as ASCII where the bytes are ASCII (UTF-16 or
  UTF-32 without a byte-order mark, UTF-7, HZ, EBCDIC code pages), makes the
  scan incomplete (exit code 3) with `binary or
  undecodable content in analyzable file`, outside the test-code exception
  below; it is never silently treated as empty. A compiled or packed artifact with no file extension and a known
  header (ELF, Mach-O, WebAssembly, gzip, zip, bzip2, xz, zstd, 7z, PNG, JPEG,
  GIF, PDF) is skipped quietly, as are names the scanner never analyzes
  (images, archives, fonts, lockfiles, minified bundles). Exclude a directory
  of binary data that carries an analyzed extension.
* **Default-excluded directories.** The walk skips a built-in list of directory
  names (see `default_excludes` in the [code connector](connectors/code.md)).
  Tool metadata, caches, virtualenvs and dependency trees are skipped without
  comment. A skipped `bin`, `build`, `dist`, `out`, `target`, `obj`, `coverage`,
  `vendor`, `third_party`, `thirdparty` or `external` directory that holds a
  file is a warning (the scan stays complete) naming each such directory name
  with its count, because projects also keep their own code there.
  `default_excludes: false` (`--no-default-excludes`) scans them.
* **Submodules** are never initialized or fetched. Bounded `.gitmodules`
  declarations identify missing, empty or unsafe source directories as coverage
  gaps, including declarations inside materialized nested directories. Ordinary
  files in materialized submodule directories are scanned by the same confined
  walker. GitHub/GitLab clone collection additionally inventories gitlinks in
  the committed `HEAD` tree (this needs Git 2.45 or newer); local scans do so only with `use_git: true` and a
  local `.git` directory. Malformed declarations or a failed authorized Git
  inventory make coverage incomplete. Explicitly excluded submodule paths are
  outside the declared scan scope. A nonempty directory establishes only that
  source is available to scan, not that it matches an authentic remote commit.
* **Undecodable or binary content** in a file whose name the scanner would
  analyze (source, manifests, `.env`, configuration, MCP and agent files,
  notebooks) that is not text in a supported encoding makes the scan incomplete
  with `binary or undecodable content in analyzable file`; the rules above say
  which invalid UTF-8 and NUL-bearing files are read instead. Under a test or
  fixture path, with `include_tests` false, such a file (a syntax-highlighting
  sample, a PNG attachment saved as `.txt`) is read for credentials only, its
  bytes as Latin-1 without NUL bytes and without excerpts, and is then charged
  to the [coverage budget](#coverage-budget-and-strict-accounting) as one whole
  entry: its other evidence would be discounted, and credentials never are.
  [Strict accounting](#coverage-budget-and-strict-accounting) reads it for
  credentials all the same and then reports its gap as an error, so it never
  finds fewer keys than the default accounting. That exception
  does not cover a file whose findings keep their full weight under a test
  path: an MCP configuration (by a dedicated name such as `.mcp.json`, or a
  JSON, TOML or YAML file, `settings.json` included, whose text declares
  servers, which is read for that check even with `scan_secrets` off), a
  coding-agent instruction, rule or settings file (`CLAUDE.md`,
  `AGENTS.md`, `.cursor/rules/`, `.claude/settings.json`, …) and an agent
  manifest or card make the scan incomplete there as anywhere else, under
  either profile. For the check, the text without its NUL bytes is parsed as
  the client parses the file, so a quoted, spaced, explicit or escaped key, a
  TOML inline table or literal key counts, and the servers it declares are
  reported; text that does not parse counts when any spelling of a server
  table key appears in it. Text with a UTF-8, UTF-16 or UTF-32 byte-order mark is
  decoded and analyzed (the mark is removed, so a BOM-prefixed `.mcp.json`
  parses). A file with a NUL byte in its first 8 KiB and no byte-order mark is
  not text in any supported encoding, yet interpreters such as Node and `sh`
  still run a script with a NUL in a comment, so it is a gap, not an empty file;
  this includes UTF-16 without a byte-order mark and NUL-dense content. Mostly-invalid UTF-8, a Python
  source or notebook that is not valid UTF-8, and malformed
  BOM-declared content also make coverage incomplete, with a fixed diagnostic
  that does not expose the rejected bytes. Names the scanner
  never reads (images, archives, `.bin`, compiled artifacts) stay silent, and so
  does a recognised binary artifact (an executable, archive, image, PDF or
  SQLite database, by its header) that has no file extension, that only a
  directory-wide signature glob such as `.cursor/rules/**` selected.
  Unrecognised binary content stays a gap in those places too. An operator can
  exclude a known binary with an `exclude` file glob.
* **Entries that are not regular files** (a directory, FIFO, socket or device)
  named like a file the scanner analyzes are a coverage gap of one entry
  each, as a symbolic link of the same name to a single file is. A FIFO,
  socket or device in place of agent configuration (`.mcp.json`,
  `.claude/settings.json`, `.roo/rules/deploy.md`) makes the scan incomplete
  at once, under a test path too, as a link or an oversize copy of it does;
  one named like a manifest or build file (`requirements.txt`, `.env`,
  `Dockerfile`) costs one entry. A directory is only reported when its name is an MCP configuration
  file name such as `.mcp.json`, and costs one entry: its contents are still
  scanned. Directories that agent tools read as directories (`.roo/rules/`,
  `.clinerules/`, `.cursor/rules/`) are not reported.
* **Directory nesting** of any depth is walked on an explicit stack, so a tree
  deeper than the Python runtime's recursion limit loses no findings.

Default directory excludes are part of the documented scope and never make a
scan incomplete, but they are not silent. The names in `DEFAULT_EXCLUDES` are
skipped at any depth (`bin`, `build`, `dist`, `external`, `obj`, `out`, `target`,
`vendor`, `third_party`, `coverage` and others, plus version-control metadata,
dependency trees and tool caches). For each scan root one warning lists the
non-empty first-party-capable directories that were skipped, with how many
carried each name (`default-excluded directories not scanned: build (2),
vendor (1); set default_excludes: false to scan them`). Version-control
metadata, dependency trees, virtual environments and tool caches (`.git`,
`node_modules`, `venv`, `__pycache__`, `.idea` and similar) are not listed, and
neither is a name the operator listed in `exclude`. Code under a listed name was
not assessed; `default_excludes: false` (`--no-default-excludes`) scans it, or
scan that directory as its own root.

Default local scans do not execute Git: an undeclared gitlink without a
`.gitmodules` file is therefore not discoverable in that mode. The opt-in Git
inventory reads committed `HEAD`, not staged-only index entries; an undeclared,
staged-only gitlink is likewise outside that check. Use a reviewed committed
checkout and declared submodule paths when completeness matters.

Which of these gaps exits 3 on its own, and which only once enough of them
accumulate, is decided by the [coverage budget](#coverage-budget-and-strict-accounting).
Raise `max_file_size`, explicitly exclude known data, or review
`oversize_skip_globs` for the intended scope.

Every diagnostic that leaves a scan incomplete is also counted by reason in
`stats[].incomplete_reasons` and, summed over the connectors, in
`summary.incomplete_reasons`; the CLI names the counts on stderr when it exits 3
(`scan incomplete (exit 3): oversize-file 2, unresolved-link 1`). A connector
names the reason when it records the diagnostic, as `code.filesystem` does for
its oversize, undecodable, link, non-regular, Git LFS pointer, parser and
analysis-limit gaps and for its credential limit (`more than 5 credentials
matched` is `analysis-limit`), and `endpoint.ebpf` for records it could not
read (`unparsed-input`) or cut at its list limit (`analysis-limit`); one
recorded without a reason is classified from its text, the connectors' own
message vocabulary, with the path the diagnostic names left out where the
connector passes it (`code.filesystem` does for every coverage gap), so a file
called `src/http_client.py` or a directory called `deadline` does not choose
the category. Each gap in `stats[].coverage.details` keeps the `reason` it was
recorded with, and when the coverage budget leaves the scan incomplete each
partial gap is counted under it. The categories are `oversize-file` (a file
over `max_file_size` or `max_notebook_size`), `unresolved-link` (a symbolic
link, gitlink or submodule not followed), `unparsed-input` (content that did
not parse or could not be decoded, or an input defect, including a structured
document whose excerpts were withheld because it did not parse),
`sanitization-limit` (a sanitizer or parser resource limit that left the
credential-redaction context unestablished, so excerpts were withheld),
`timeout` (a file's matching budget, a connector deadline or a job deadline,
including a connector left unstarted because timed-out calls hold every worker
slot, and findings an overrun produced that could not be reported),
`access-denied`, `upstream-error` (a live API, network or
rate-limit failure),
`analysis-limit` (a per-file budget such as `max_ast_nodes` or the model
literal limit), `subset-scan` (a `triage` scan), `unscanned-input` and `other`.
Counts read back from a source report (`shadowscan merge`) or a plugin worker
keep their totals, but a key that is not one of these categories is counted as
`other`, so the table banner and the stderr line never print a source's own
text there. A connector that failed or was skipped before it recorded a diagnostic has no
entry; the summary's `status` still says `incomplete`.

### The coverage budget

A gap the scanner cannot bound is *blinding*: the walk stopped early, a page
was refused, a deadline expired, a link names a directory the walk does not
scan whole or an agent's configuration directory, a sanitizer limit
was reached. It marks the scan incomplete at once. A *partial* gap costs a
known number of entries (a dangling link is one) and is charged against a
budget: `max_coverage_gap` (`--max-coverage-gap`), by default 2% of the entries
the connector examined and at most 100 weighted entries. A gap under a
dependency, cache or test path (`node_modules`, `vendor`, `tests`, `fixtures`
and similar) is charged a quarter of its entries, unless the scanner could not
read or decode the content or, while `scan_secrets` is on, read no byte of it
for credentials (a file over `max_file_size`). Within the budget the scan stays complete and the
gaps' diagnostics remain warnings; over it the scan is incomplete and every
partial gap is counted under its reason in `stats[].incomplete_reasons`.
`strict_coverage: true` or `--max-coverage-gap 0` sets the budget to zero.

A connector that recorded any gap publishes its ledger in the JSON report as
`stats[].coverage`, which is `null` when there was none. When a gap was
partial it also adds one verdict line to its warnings, or to its errors when
the scan is incomplete.

| Key | Meaning |
|---|---|
| `examined` | Entries the connector reached, summed over its roots (for a code scan, the entries the walk examined): the budget's denominator |
| `gaps` | Gaps recorded, blinding and partial |
| `blinding_gaps` | How many of them were blinding |
| `gap_entries` | Entries the partial gaps cost, before weighting |
| `weighted_gap_entries` | The same after path weighting: what is charged against the budget |
| `allowance` | Weighted entries the scan could lose: `max_gap_ratio` times `examined`, at most 100, and 0 under strict accounting |
| `within_budget` | Whether `weighted_gap_entries` stayed within `allowance` |
| `max_gap_ratio` | The ratio in force |
| `details` | The first 50 gaps (`MAX_PUBLISHED_GAPS`): a root's blinding gaps first, then its partial ones, each in the order they were recorded |
| `details_truncated` | Present only when more than 50 gaps were recorded: how many `details` leaves out. Every gap is still counted in `gaps` and `gap_entries`. |
| `parts` | Present only when the connector was judged in parts (several roots or repositories): how many parts recorded a gap |
| `parts_over_budget` | Present with `parts`: how many of them went over their own allowance, so `within_budget` is false exactly when it is above 0 |
| `tolerated_gap_entries` | Present with `parts`: the entries of the parts that stayed within their own allowance, which `summary.tolerated_gaps` counts even when another part went over |

Each entry of `details` has `detail` (the diagnostic), `path`, `kind`
(`blinding` or `partial`), `entries`, `full_weight` (true when the path discount
was not applied), `reason` (the `incomplete_reasons` category the gap counts
under if it leaves the scan incomplete), `relevance` (`low` for a dependency,
cache or test path, otherwise `high`) and `part`, the scan root's label (its
path unless `label` names it) or the repository (`github:<repo>`) the gap lies
in, so the gap a verdict line names can be found when several roots share a
path; a report written before `part` existed has none. `shadowscan merge` and a process-mode plugin's result are
checked against this shape (`shadowscan.coverage.validate_coverage_summary`), and
a ledger that does not match is refused rather than republished.

Only the JSON report carries `stats[].coverage`. SARIF has no coverage block:
its `invocations[].toolExecutionNotifications` hold each connector's warnings
and errors, among them the verdict line and the diagnostic of each gap that
was reported, but not the counts, nor the gaps that one representative
diagnostic stands for (a tree's further unread links). The verdict line names
the JSON report for that reason. To read the ledger from a SARIF run, write a
JSON report of the same scan as well (`--format json`).

### Coverage budget and strict accounting

A coverage gap is *blinding* when the scanner cannot bound what it lost: the
walk stopped early (`max_files`, `max_entries`, a deadline), a page was
refused, a symbolic link names a directory the walk does not scan whole
inside the root or an agent's configuration directory, undecodable bytes, padding past
`max_file_size`, a link or a FIFO, socket or device hide agent configuration
(padding also hides a dotenv or tool credential file), or a sanitizer limit
was hit. A blinding gap marks the scan
incomplete at once. A *partial* gap costs a known number of entries: any other
dangling link or link to a single file, any other non-regular entry, an
incidental file over `max_file_size`. Partial gaps
accumulate against the gap budget, `options.max_coverage_gap`
(`--max-coverage-gap`; `code.filesystem` also takes its own
`max_coverage_gap`): 2% of examined entries by default, at most 100 weighted
entries. A gap weighs a quarter of an entry when its path cannot hold
deployed code as the scan reads it: under a dependency tree or tool cache
(`node_modules`, `vendor`, `third_party`, …), or under a test path while
`include_tests` is off (the test paths of
[test and fixture code](#test-and-fixture-code), test file names such as
`test_*.py`, `*.test.ts` and `conftest.py` included), unless no byte of the
file was read for credentials while `scan_secrets` is on: an oversize fixture
or cassette, or one the scanner could not read, weighs a whole entry wherever
it lies, since a key in it is missed. With `include_tests` a
test path is source and its gaps weigh in full, and so does a file whose
findings keep their full weight under a test path (an MCP configuration such
as `tests/.mcp.json`, a coding-agent instruction, rule or settings file, an
agent manifest or card), as the discount and the declaration read it. A
`__snapshots__/` directory is not a test path to the scan, so its gaps weigh
in full too. Within the budget the scan
stays complete; every gap is still listed in `stats[].coverage.details`, with
its path, reason and `relevance` (`low` for a quarter-weight gap).

The budget is judged per scan root, and per repository for `code.github` and
`code.gitlab`, never over a summed run: a scan of several roots is complete
only if every root would be complete scanned alone. The 2% ratio and the
100-entry ceiling apply to each root's own examined entries, so several roots
may each lose up to their own allowance, and the verdict line names each root
or repository that went over its budget. Summing them would let one large
clean root dilute a small root's gaps, and would make an organisation of
ordinary repositories exit 3 with no setting to fix it. The published
`stats[].coverage` combines the roots that recorded a gap: counts add, the
`allowance` is the sum of their allowances, and `within_budget` is true only
if every root was. Because each root was judged against its own allowance, a
combined `weighted_gap_entries` below the summed `allowance` can sit beside
`within_budget: false`; the combined summary therefore also states `parts`
(the roots or repositories that recorded a gap), `parts_over_budget` and
`tolerated_gap_entries` (the entries the roots within their own budget
tolerated), and lists in `details` the gaps of the roots that left the scan
incomplete first, so the gaps the verdict line points to are never crowded
out of the 50 published by a larger root's tolerated ones. A single root's
summary has none of these three keys. An incremental scan (`--incremental`),
which runs and caches each root on its own, reaches the same verdict and
publishes the same summary.

`summary.tolerated_gaps` counts the entries left unread in every root or
repository whose own budget tolerated them (the `gap_entries` of each
`stats[].coverage` within budget, or a combined summary's
`tolerated_gap_entries`), so a complete scan that skipped content says so
beside `summary.declared_omissions`, and so does a scan another root put over
its budget: the table banner shows both, and the stderr line of an exit 3
names them as gaps and omissions that did not count, as the verdict line
does. A report written before the field existed has none; `shadowscan merge`
recomputes it from the stats and treats a source whose summary states a
different value as inconsistent (incomplete). A ledger summary that claims to
be within budget while losing more than it allows, or whose part counts its
own counts refute, is refused, and one over budget or blinded marks its
connector incomplete whatever the report or a plugin worker says.

Every gap a `code.filesystem` scan records (and every gap in a `code.github`
or `code.gitlab` checkout, which that connector scans) is decided by one rule,
applied in this order:

1. **Strict accounting.** `strict_coverage: true` (`--strict-coverage`) and a
   gap budget of 0 (`max_coverage_gap: 0`, `options.max_coverage_gap: 0` or
   `--max-coverage-gap 0`) are both strict accounting, the accounting from
   before the budget: every gap marks the scan incomplete and is counted under
   its reason, no gap is discounted as test code, and none is declared by the
   `ci` profile. The profile is therefore refused with either setting: a
   configuration error before anything is read, and a usage error for
   `--profile ci --strict-coverage` or `--profile ci --max-coverage-gap 0`.
   The two settings differ only in where a gap the budget would charge (a
   link, a non-regular entry, an incidental oversize file) is reported:
   `strict_coverage` records each as an error where it happens, while a
   budget of 0 charges each to the budget, so those gaps stay listed in
   `stats[].coverage` and the verdict that leaves the scan incomplete is one
   error line. Every other gap is a diagnostic at the file under either
   setting, counted under its reason and absent from `stats[].coverage`: a
   test-code gap the default accounting discounts (a malformed fixture, or a
   binary one after its credential-only read) is an error, and content the
   default accounting only notes (invalid structured syntax, a test file over
   the binder's budget, text that is not valid UTF-8) is an error or a warning
   that marks the scan incomplete and ends in `coverage incomplete`.
2. **Credentials.** A credential limit is never declared, discounted or
   budgeted: a file holding more matches of one credential format than the
   matcher reports (`more than 5 credentials matched`) marks the scan
   incomplete under every profile, in test code too. No file is declared
   without a credential read: a gap that left a file's bytes unread by
   credential detection while `scan_secrets` is on (a file over
   `max_file_size`, a notebook's saved outputs, a file that could not be
   opened or read) is recorded as without the
   profile, an oversize file as one whole entry of the budget wherever it
   lies (never a quarter under a test path), or blinding when it is agent
   configuration or a dotenv or tool credential file. Oversize content is not
   read for credentials at all: a key in an oversize fixture is missed while
   the budget tolerates the entry, the trade-off
   [SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md#what-can-remain)
   records; raise `max_file_size` to read such files. A binary or undecodable file whose gap would be discounted
   or declared (a test fixture, or a documentation, example or generated file
   under `profile: ci`) is read for credentials before its gap is recorded,
   under every accounting, so `profile: ci` declares it only after that read.
3. **Declared omissions.** Under `profile: ci`, a gap in a path the
   [profile](#the-ci-profile) names is declared: counted in
   `declared_omissions`, every entry of it, never charged to the budget. A
   file whose findings keep their full weight wherever it lies (an MCP
   configuration, a coding-agent instruction, rule or settings file, an agent
   manifest or card) is never declared.
4. **Discounted test code.** With `include_tests` off, a gap in a test or
   fixture file whose evidence the scan discounts (a malformed fixture, a
   structured parse that withheld excerpts, test source the lexer cannot
   settle) is charged to the budget as a partial gap at a quarter weight, and
   a binary or undecodable fixture, read for credentials first, at a whole
   entry. Its warning and its `stats[].coverage.details` entry say `test code
   is discounted evidence`. Against the default 2% budget a root therefore
   tolerates malformed fixtures up to about 8% of its entries, but binary
   ones only up to about 2%, fewer beside other gaps: a 200-file service with
   four binary fixtures and one dangling certificate link exits 3 (see
   [test and fixture code](#test-and-fixture-code)).
5. **Budget.** Every other partial gap is charged to the budget; a blinding
   one marks the scan incomplete.

### The `ci` profile

A gate on a repository's source does not read the certificate links in its test
suite, its malformed fixtures or its generated code, yet by default each of
those is a coverage gap: a few are tolerated by the
[budget](#coverage-budget-and-strict-accounting) and enough of them exit 3.
`profile: ci` (`--profile ci`) declares such gaps in advance: an unread symbolic
link, a non-regular entry, content that did not parse or an analysis limit under
a test, fixture, documentation, example or generated path is recorded as a
warning that names it and ends in `declared omission (profile ci)`, counted in
`stats[].declared_omissions` and `summary.declared_omissions` and listed by path
in `stats[].declared_paths` (the first 200 of each connector), and the scan
stays complete. So is a file over `max_file_size` under a documentation, example
or generated path, but only while `scan_secrets` is off (an oversize test
fixture is then skipped with a warning under every profile): with credential
detection on (the default) a recorded cassette or fixture over the limit may
hide a key, and credentials are never declared without a read, so its gap is
charged to the budget as without the profile. For the same reason an
undecodable file under those paths is read for credentials, its bytes as
Latin-1 without NUL bytes, before it is declared, and a key in it is reported.
Every declared entry is counted:
of a run of skipped links,
one warning per root names the first and the rest are counted without one, as
the budget counts every undeclared link. Test paths are declared only while
`include_tests` is false, when their evidence is discounted; with it set they
are source like any other. A file whose findings keep their full weight under
any path is never declared, wherever it lies: an MCP configuration (by a
dedicated name such as `.mcp.json`, or a structure that declares servers), a
coding-agent instruction, rule or settings file (`CLAUDE.md`, `.cursor/rules/`,
`.claude/settings.json`, …) and an agent manifest or card, since a client
started in `tests/` or `docs/` reads it there. Nor is a credential limit
(`more than 5 credentials matched`): it marks the scan incomplete under the
profile too.
Documentation and example directories count only below the file's project
root, as they do for evidence: a directory that holds its own manifest
(`demo/pyproject.toml`, `examples/svc/package.json`) is a deployable project
reported at full weight, whatever it is called, so a gap in it still marks
the scan incomplete. That holds for any directory with a manifest, not only
`demo/` and `examples/`: a documentation site that is its own package
(`docs/package.json` in a Docusaurus or VitePress layout) is a project, so an
oversize blog post, a generated search index or a binary page directly in it
exits 3 under the profile. The `docs/` and `examples/` directories below such a
project, and test paths anywhere, are still declared (`docs/docs/` in that
layout); its own content is not. A template is not such a project: a directory
with template syntax in its path (`templates/crew/{{cookiecutter.slug}}/`, a
`{%` or `${` segment), or one none of whose JSON or TOML manifests parses (a
templated `package.json`), is judged by the project around it, so the template's
own unparsed manifest and sources are declared. Every other gap, in `src/`, at
the repository root or in a path the profile does not name, is judged as without
the profile: charged to the budget, or marking the scan incomplete when it is
blinding, as a connector deadline, a `max_files` or `max_entries` limit and a
triage scan always do. The profile
is refused under [strict accounting](#coverage-budget-and-strict-accounting)
(`strict_coverage`, or a gap budget of 0). The report of a
profile scan is not the report of a scan that read everything: read
`declared_omissions` before treating its exit 0 as full coverage. `diff` reads
them too: while the current report counts declared omissions, a missing
finding under a test, documentation, example or generated path is not resolved,
nor is a missing project with a declared omission inside or above its directory
(see [comparing reports](#comparing-reports)).

Analysis limits are reported with their reason, for example
`file analysis incomplete (MatchTimeoutError: source binding call limit exceeded)`.
The import binder only counts calls into modules that a signature describes,
so large ordinary files (test suites, HTTP clients) no longer hit the limit.
Its node budget (`max_ast_nodes`) and nesting limit likewise apply only to a
Python module with an import that can resolve to a signature. The binder is
skipped for any other module, of any size, because it could not contribute
evidence there. Deciding that is linear in the module and matches at most
4,096 distinct import statements, so it cannot exhaust a file's matching budget.
A large module that does import such a library, or has more imports than that,
still reports
`import-bound analysis skipped (source binding AST limit exceeded); lexical evidence retained`.
Before the module's tree is walked, one bounded pass over its `import` and
`from ... import` statements checks whether any names a module that a signature's
import pattern can bind (directly, or through an attribute of the imported
module); a module whose imports cannot is parsed but not walked, so a syntax
error in it is still reported as `import-bound analysis skipped (source did not
parse); lexical evidence retained`. A JavaScript or TypeScript file whose
imports and `require` calls resolve to no signature skips the call scan the
same way (its lexer still runs, since the regex passes need the comment and
string spans it produces). The bound evidence and the diagnostics are identical
either way; a test compares both paths over every fixture source.

The JavaScript and TypeScript lexer that masks comments, strings and JSX text
has a look-ahead allowance of its own: a fixed floor plus four characters of
look-ahead per character of the file. Real components use under one percent of
it. A JSX file that exhausts it, such as tens of thousands of repeated `<A>(`,
ends in well under a second with
`file analysis incomplete (MatchTimeoutError: JavaScript lexical analysis look-ahead budget exceeded)`
instead of stalling the scan until the connector deadline. Other files are
unaffected and the scan exits 3.

## Test and fixture code

Library test suites often construct agents to exercise integrations. Evidence
found only under test or fixture paths (`tests/`, `fixtures/`, `cassettes/`,
`__mocks__/`, `test_*.py`, `*_test.go`, `*.spec.ts`, …) has half weight and cannot
promote a project to an *agent*; a project whose evidence is entirely test code
is tagged `test-code-only`. Exported low-code workflows found under those paths
follow the same rule.

Documentation, example and generated code is discounted the same way, but never
judged by a project's own location. Evidence under a documentation directory
(`docs/`, `doc/`, `documentation/`, `wiki/`, `guides/`, `tutorials/`) or an
example directory (`examples/`, `samples/`, `demos/`, `quickstart/`, `starter/`,
`templates/`, `boilerplate/`, `cookbook/`, `recipes/`, and their singular or
plural forms) has half weight only when that directory lies inside the file's
project, below the directory holding its manifest. A directory that is itself a
project root, such as `services/templates/` with its own `requirements.txt`, is a
deployable unit and is not discounted. Generated code is recognized by file name
only (`*_pb2.py`, `*_pb2_grpc.py`, `*.generated.*`) and has 0.4 weight; a
directory named `generated/` or `codegen/` is ordinary source. When all non-test
evidence of a project is discounted, the finding is tagged `docs-only`,
`example-code-only` or `generated-code-only` and its confidence is capped at
0.85, 0.85 or 0.7 (`metadata.confidence_cap`); `metadata.negative_contexts` lists
the contexts seen and each discounted evidence item carries
`attributes.negative_context`. Discounted evidence keeps the capabilities it
implies.

Set `include_tests: true` (`--include-tests`) to treat test, documentation,
example and generated code like any other source. A real-format credential under a test,
fixture or `cassettes/` path is still reported as a `secret` finding, because
recorded cassettes capture real traffic and a committed key is exposed wherever
it lives; without `include_tests` it has half weight and the `test-code-only`
tag. A credential under a documentation, example or generated path outside the
test paths is likewise reported with that context's weight and confidence cap
and the `docs-only`, `example-code-only` or `generated-code-only` tag. Recognisable
placeholders (repeated characters, marker words such as `EXAMPLE` or their
Portuguese, Spanish, French, German, Italian, Dutch, Indonesian and Turkish
equivalents, a possessive followed by words such as `sua_chave_openai`, or
very low character diversity) are never reported, and neither is an assigned
value shaped like the name of another variable (`api_key = resolved_api_key`,
`ENV_API_KEY = "ANTHROPIC_API_KEY"`, `settings.openai_api_key_v2`): the
generic assigned-credential rule accepts an unquoted value because `.env` and
shell assignments carry none, so it requires a token's shape, digits or evenly
mixed cases, rather than an identifier's.
Evidence that only names a coding agent in a test path (an environment variable,
a display name, a dependency or a code pattern) likewise does not establish a
coding-agent configuration; instruction documents and coding-agent config
files still do. A mention in a test path (a provider host in a fixture JSON,
a variable name, a display name, a model identifier, a CI job image) anchors
no project finding at all without `include_tests`; imports, dependencies and
code patterns there still do. An oversize file under a test path is skipped
with the warning `skipped oversize test fixture` and leaves the scan complete
only when `scan_secrets` is off, `include_tests` is not set and the
accounting is not strict ([strict accounting](#coverage-budget-and-strict-accounting)); otherwise it is read for credentials below the
limit and a coverage gap above it (see
[large and generated files](#large-and-generated-files)).

## Incremental scans

Incremental mode reuses a completed connector result when the fingerprint of its
inputs, connector options, signature definitions and scanner implementation is
unchanged. The fingerprint is a SHA-256 digest over the content of every file the
scanner can read plus the size, modification and change times, mode, device and
inode of every file and directory, so a fresh checkout at a new inode does not hit
the cache. Files over `max_file_size` contribute only that metadata: the scanner
never opens them, so their bytes cannot change the result. Inventory approval,
risk scoring and runtime correlation always run again. New, edited and deleted
files invalidate the affected repository.

```bash
shadowscan code ./repo-a ./repo-b --incremental
shadowscan run cloud.aws --input ./exports/aws.jsonl --incremental
shadowscan scan -c shadowscan.yaml --no-incremental
```

Equivalent YAML:

```yaml
options:
  incremental: true
  state_dir: ../private-scan-state
connectors:
  - name: code.filesystem
    paths: [./repo-a, ./repo-b]
  - name: cloud.aws
    input: ./exports/aws.jsonl
```

Each `code.filesystem.paths` root is a separate cache unit. A `code.filesystem`
scan with `diff_base` is never cached or reused: its result depends on HEAD and
the base ref's merge base, which the working-tree fingerprint does not cover.
Offline local directory inputs to `code.github` / `code.gitlab` and static
exports to the four `cloud.*`
connectors are also eligible. Live remote repositories, live cloud APIs, gateway
logs, identity, SaaS inputs and third-party connectors are collected anew: unchanged configuration cannot
establish that remote state is unchanged. Hashing still reads eligible inputs;
the saving is avoiding repeated parsing and signature evaluation.

When a shared `label` is set for multiple `code.filesystem.paths`, add
`root_ids: [repo-a, repo-b]` in the same order as `paths`. This keeps each root's
finding identity stable when the checkout location or list length changes.
Without `root_ids`, the canonical local path determines a distinct root suffix.
Using a scalar `path` with its own connector `label` preserves the older ID.

The default state location is `$XDG_STATE_HOME/shadowscan`, or
`~/.local/state/shadowscan` when `XDG_STATE_HOME` is unset, empty or relative
(as the XDG specification requires). `--state-dir` overrides it; YAML relative paths are
resolved against the configuration file. Keep the directory outside every scan
input. State uses a private 0700 directory and atomic 0600 JSON files containing
sanitized, unscored findings, not source content or raw credentials. Protect the
state as local security data; a checksum detects corruption, not a malicious user
who controls the scanner account. Remove the state directory to clear it.

Incomplete scans are never cached; a complete scan whose only diagnostics are
warnings, such as skipped oversize generated files, is cached and replays those
warnings on every hit. Corrupt, incompatible or unsafe state and
symlink-bearing eligible inputs cause a full scan. Hashing has conservative limits:
512 MiB total, 200,000 entries, 30 seconds per snapshot, and 64 MiB per hashed
file; code files over `max_file_size` (default 1,000,000 bytes) are tracked by
metadata rather than hashed. Exceeding a
limit falls back to normal scanning. Git replacement refs, grafts or externally
overridden history also disable reuse; HEAD and shallow boundaries are tracked.
Symlinked roots and ancestor path components are also ineligible for reuse.
Input changes detected between hashing and collection make the result
incomplete and require a rerun. `--dump-records` disables cache reuse to ensure the
requested export is actually collected. JSON connector statistics expose `cached`;
the private cache fingerprint stays in the access-restricted state directory.
Cached connectors examine zero objects during analysis.
Pre/post hashes do not form an atomic snapshot: inputs must remain immutable
throughout the scan to exclude changes that occur and revert between reads.

## Offline input limits

Offline connectors skip symlinks and bound directory walks and file parsing. The
defaults are 10,000 files, 32 MiB per file, and 256 MiB total per connector input.
JSONL, CSV and gateway text logs are streamed; individual lines are capped at
4 MiB. Gzip gateway logs are limited by expanded size as well as compressed file
size. JSON and YAML documents are parsed only after their file and aggregate byte
limits pass.

Set `max_input_files`, `max_input_file_bytes` or `max_input_bytes` on a connector
to change these limits. Gateway scans also honor `max_records` (default 5,000,000)
while analyzing streamed events. If any limit is reached, ShadowScan retains the
findings already collected and marks the connector incomplete; check the warnings
and rerun with an appropriate limit to claim full coverage. The existing hard
ceilings remain 200,000 directory entries, 64 MiB per file and 512 MiB total.
`options.min_confidence` must be a finite number from 0 through 1, inclusive.

YAML also has structural limits before object construction: 100,000 composed or
expanded nodes, 1,000 aliases, depth 64 and 64 MiB of expanded scalar content.
Recursive aliases and excessive merge expansion are rejected. Sanitization uses
separate structure and work budgets; rejected records mark collection incomplete
while valid neighboring records remain available. CODEOWNERS matching has a
bounded per-lookup work budget; an exhausted lookup marks the root's ownership
coverage incomplete.

Record dumps use a private directory and distinct filenames per configured
connector instance. `manifest.json` maps configuration ordinals to committed
export files and records each instance's completion status. Use only entries
marked `exported: true`; a failed attempt may leave an older file in place.
`gateway.logs` does not export source records through `--dump-records`: provider
key IDs and arbitrary log payloads can be sensitive even when a generic field
sanitizer does not recognize them. Its manifest entry has `exported: false`;
gateway findings and scan completion are unaffected.
See [deployment and migration](production.md) for explicit plugin, signature
override and private-endpoint policies, output changes and rollout checks.

## Large and generated files

`code.filesystem.max_file_size` (default 1,000,000 bytes) bounds every file the
scanner reads. A larger file is never analyzed. Whether that makes the scan
incomplete depends on what the file could hide:

* A file whose name matches `oversize_skip_globs` is skipped with a warning and
  the scan stays complete. The default list names lockfiles (`package-lock.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`,
  `Gemfile.lock`, `composer.lock`, `go.sum`, `gradle.lockfile`,
  `Package.resolved`, `Cartfile.resolved`, `deno.lock`, `pubspec.lock`,
  `mix.lock`, `bun.lock`, `*.lockb`, `flake.lock`), logs and recordings
  (`*.log`, `*.har`, `*.snap`), minified bundles and source maps (`*.min.js`,
  `*.min.css`, `*.map`), data and vector graphics (`*.svg`, `*.csv`, `*.parquet`), compiled
  or packaged artifacts (`*.wasm`, `*.so`, `*.dylib`, `*.dll`, `*.jar`,
  `*.pyc`, `*.class`), documents, images and fonts (`*.pdf`, `*.png`, `*.jpg`,
  `*.jpeg`, `*.gif`, `*.woff`, `*.woff2`, `*.ttf`) and archives (`*.zip`,
  `*.gz`, `*.tar`). Such content is generated from sources the scanner does
  inspect, or is binary, so no agent configuration, framework usage or
  credential evidence is lost by skipping it. The warning still names each file
  so the omission is visible. Lockfiles, minified bundles, source maps and
  bytecode below the limit are skipped silently because they are never analyzed.
  A coding-agent settings file that an operator's glob matches (a
  `.claude/settings.json` under `*.json`) is still recorded as unread for its
  project's approval gate, which then covers only some actions (see
  [approval gating](concepts/autonomy.md#approval-gating-evidence)).
* With `scan_secrets: false`, an oversize documentation file (`.md`, `.mdc`,
  `.mdx`, `.txt`, not a manifest name) is skipped with a warning and the scan
  stays complete: its body is matched by file name only, so no technology
  evidence is lost and nothing would have read it for credentials. With
  credential detection on (the default) its text is read for credentials below
  the limit, so an oversize copy is a coverage gap like any other unread file.
  A coding-agent instruction document (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
  …), an agent definition under `.claude/agents/`, `.github/agents/`,
  `.cursor/rules/` or `.windsurf/rules/`, and a file a file-name signature
  selects are parsed, so an oversize copy stays a gap in every mode.
* With `scan_secrets: false` and `include_tests` unset, an oversize file under
  a test or fixture path (`tests/cassettes/*.yaml`, `pkg/fixtures/*.json`,
  `test_*.py`) is skipped with the warning `skipped oversize test fixture` and
  the scan stays complete: test code is discounted evidence that cannot
  establish a deployment, so its omission is disclosed and counted (one
  summary warning per root) rather than treated as a gap. Agent configuration
  is not discounted test code, so an oversize `tests/.mcp.json`,
  `tests/CLAUDE.md`, coding-agent rule or settings file, or a JSON, TOML or
  YAML fixture whose bytes name an MCP server table, makes the scan
  incomplete under such a path too. With credential
  detection on, or `include_tests: true`, the file is analyzable like any
  other and the gap returns; strict accounting keeps it a gap too, and
  `strict_coverage` records it as an error.
* With `include_tests` unset and the accounting not strict, a file under a
  test or fixture path that is read but cannot be fully analyzed (manifest XML
  that does not parse, YAML that fails the integrity checks, source the lexer
  cannot settle, a parser input defect) is a warning ending `test code is
  discounted evidence (include_tests is false)`, charged to the coverage
  budget at a quarter weight, so a root tolerates such files up to about 8%
  of its entries (2% at a quarter each), fewer beside other gaps. Its
  credentials were scanned on the text as read. The
  same file outside a test path is a gap, and `include_tests: true` or
  [strict accounting](#coverage-budget-and-strict-accounting) keeps it one.
  An MCP configuration (by a dedicated name or by the structure that
  declares its servers), a coding-agent instruction, rule or settings file
  and an agent manifest or card are reported at full weight under a test
  path, so a defect in one (`tests/.mcp.json` with a syntax error,
  `testing/CLAUDE.md` with a NUL byte) is a gap there too.
* Every other oversize file, for example a 2 MiB Python module, JSON or YAML
  document, is skipped and makes the scan incomplete (exit 3). With
  `strict_coverage: true` (`--strict-coverage`) it is recorded as an error
  instead of a warning. Raise `max_file_size`,
  exclude the directory, or add the name to `oversize_skip_globs` after
  confirming it carries no agent evidence.

`oversize_skip_globs` replaces the default list with case-insensitive file-name
globs; a pattern containing `/` is matched against the path relative to the scan
root. A matching file stays a warning even under `strict_coverage`; an empty
list makes every oversize file that the scanner would read incomplete. Oversize files that are never read at any size, such as executables or
media in other formats, are skipped silently as before.

The per-file matching budget also grows with size. `scan_timeout` (default 2
seconds) covers files up to 256 KiB; each further 256 KiB adds one more budget,
with the final 64 KiB of the first band receiving the next budget early. This
avoids a sharp timeout cliff for mid-sized source files just below the first
boundary while remaining capped at 10 seconds, or at `scan_timeout` when that
is higher. A 900 KB JSON index gets 8 seconds by default and a pathological
file still fails fast. An exhausted budget marks the file's analysis incomplete
and the scan incomplete.

The budget is CPU time of the thread analyzing the file, not elapsed time: a
scanner descheduled behind other processes on a busy host (a benchmark running
several scans on four CPUs) has not spent it, so ordinary files no longer fail
with `MatchTimeoutError` under contention alone. Elapsed time still ends the
file once it reaches four times the budget (8 seconds for a 2-second budget),
clipped to the remaining connector deadline less its safety margin, so hostile
input and the connector deadline fail fast as before. The diagnostic reports
both: `file analysis incomplete (MatchTimeoutError: signature matching exceeded
the input execution budget (cpu 2.01s of 2.00s, wall 2.40s of 8.00s))`; a wall
figure far above the CPU figure says the host was contended, not the file
expensive.

Excerpts are cut at emit time, for the evidence a report keeps, from the
file's redacted lines. Whether redaction exceeds a sanitization limit is known
only by redacting, so every file that recorded excerpted evidence is still
redacted when its analysis ends, and a `structured sanitization incomplete ...;
excerpts withheld` error marks the scan incomplete even when none of that
file's matches reaches the report. The file's text is then dropped; nothing is
written anywhere.

The JavaScript and TypeScript lexer runs on every such file, whether or not
its imports can bind a signature: the comment and string spans it produces are
the ignore ranges of the regex passes.

The scan is single-process. A process pool (an opt-in `workers` option) is not
implemented: findings must be applied in submission order so deduplication and
emit order stay deterministic; each worker would need its own signature index
and its own confined root descriptor; a crashed worker must fail its file
closed while the connector deadline stays in the parent; and credential values
would cross process pipes. No speedup is claimed for it.

IAM wildcard and agent-definition front-matter parsing use this same bounded
matching mechanism. The matching budget does not replace an external process
or job timeout for the complete worker.

## Connector deadlines and parallelism

`options.connector_timeout_seconds` (or `--connector-timeout-seconds`) sets a
positive, finite completion deadline for each connector, defaulting to 120 seconds.
It starts when the connector worker begins; split filesystem roots share that
connector's deadline. Legacy `options.connector_timeout` and `--connector-timeout`
are deprecated compatibility aliases; the YAML alias logs a deprecation warning
once per process. Configure only one YAML key; supplying both is rejected.
Legacy YAML `connector_timeout: null` uses the 120-second default; it does not
disable the deadline. Left unset, the default is raised for a large input
when the connector can measure it: `code.filesystem` counts up to 20,000
entries and scales the deadline above 12,000, to at most 200 seconds. An
explicit value, 120 included, is honoured unchanged, so a configuration that
sets `connector_timeout_seconds: 120` turns that scaling off; a larger tree
needs an explicit, larger deadline.

Leaving the option out and setting it are not the same. Left out (or given as
legacy `connector_timeout: null`), the 120 seconds is where a connector starts,
and a connector may raise its own deadline to fit its input: `code.filesystem`
counts up to 20,000 entries of the tree it is about to walk and, above 12,000,
scales its deadline in proportion, to at most 200 seconds, and reports
`input is large; deadline raised to ...` in its progress output. The engine caps
any connector's proposal at 30 minutes. A value you set, from a configuration
file, `--connector-timeout-seconds` or `ScanConfig`, is used as it is and never
raised, and that includes 120: a configuration that spells out
`connector_timeout_seconds: 120` gives a large repository 120 seconds and
reports it incomplete. The sample configurations therefore leave the option
out. Set it for a fixed bound, or for a tree larger than the probe can measure.

Setup failures that name only paths, option names and positions are printed
verbatim by the CLI: a missing inventory path or signature directory, a
malformed signature pack (file and document number), an unknown connector key,
and YAML syntax errors in the configuration (line and column, never the source
line). Any other exception raised while a scan is being set up is masked as
`scan setup failed` with its type name, because third-party error text can
echo credentials.

The filesystem scanner stops cooperatively before the deadline: it never starts a
file whose matching budget could run into a safety margin (5% of the budget that
remained when the walk began, at least 250 ms), records one error naming how many
files it examined and how many remain (`connector deadline reached after N of M
files ... results incomplete`), and returns the findings collected so far. The
engine keeps those findings and reports the scan incomplete (exit 3), so a large
tree yields partial inventory rather than nothing. Split roots share the deadline.
Each root's entries are listed first and scanned in priority order (manifests and
agent or MCP configuration first, source last, smaller files before larger).
Listing stops after half of the time in which a file can still start and records
`connector deadline: listing stopped after N entries`, so a large tree or a slow
filesystem still scans the entries it listed. A root that starts when no file can
start any more lists nothing (`listing stopped after 0 entries`), so it cannot run
the connector past the deadline into an expiry, which reports the findings
already produced but none of the connector's own diagnostics.
A tree whose listing alone takes more than that half is reported incomplete even
when listing and scanning together would have finished; raise
`connector_timeout_seconds` or narrow the root with `exclude` for such a tree.

On expiry, the engine reports the findings that connector had already produced
and sanitized, and discards the rest of its result: its statistics, any later
finding and any artifact it publishes afterwards. For a job split into
repository roots that is every root's findings, those reused from the
incremental cache included. The surrendered findings are copies taken from the
abandoned worker and prepared as a completed job's are: a plugin's get the id
its own name derives and lose any registry record. Preparing them stops after 5
seconds; the findings left then, and any the worker changed into something that
is not plain data, are omitted and counted in the connector's errors. A plugin
in its own worker process (the default) surrenders nothing: the process is
killed and its result discarded. The entry is marked incomplete with the
timeout diagnostic and the reason `timeout`, a warning says that the findings
are a subset of what a full run would find, other completed connectors'
findings are retained, and the scan is incomplete (CLI exit 3). Cancellation is
cooperative: Python
cannot forcibly interrupt a thread blocked in a vendor SDK call, or in a plugin
call under `plugin_execution: thread` (a plugin in its default spawned worker is
killed). Such a call may outlive `Engine.run()`; once timeout handling returns,
the CLI writes the incomplete report and exits 3 without joining the abandoned
thread, or exits 1 if the report could not be written. Without a job deadline it
gives that output 30 seconds; output still unfinished then is cut off and the
CLI exits 3 ([resource limits](production.md#resource-limits-and-incomplete-scans)). A worker
already publishing a cache or record artifact can delay timeout handling while
its filesystem replacement finishes. Embedded callers must supervise their
process, and a reusable Engine refuses another scan while an abandoned worker
remains active. No replacement
workers are created beyond the configured parallelism; if all slots remain
occupied by timed-out calls, queued connectors are skipped with incomplete
coverage. Enforce an external process or CI job deadline for a hard runtime limit.

`options.parallel` (default 4) is the maximum number of worker threads. Additional
workers can improve throughput when connectors wait on network APIs. Offline
exports and repository scans also perform CPU-intensive parsing and matching;
extra threads can add contention. The offline example uses two workers as a
starting point; measure representative workloads before increasing parallelism.

## Link code to gateway activity

A static dependency alone cannot establish runtime use. Configure a binding
between a specific code `resource` and gateway caller from your own inventory:

```yaml
connectors:
  - name: code.filesystem
    path: ./ops-agent
    label: github:acme/ops-agent
  - name: gateway.logs
    input: ./gateway.jsonl
    correlation_bindings:
      - code_resource: github:acme/ops-agent
        caller: principal:svc-ops
        scope: {tenant: tenant-a}
```

An example generic gateway record:

```json
{"service":"svc-ops","tenant_id":"tenant-a","user_agent":"langchain/0.3","model":"gpt-4o","timestamp":"2026-09-22T10:00:00Z","environment":"production"}
```

In this example, `service` and `environment` are assertions made by the export.
An operator should verify that the log producer supplies a trustworthy workload
identity and deployment label before using the result as production evidence.

`scope` is required. It must exactly match all detected canonical `tenant`,
`account`, `project` and `workspace` fields. Use `{}` only for an unscoped export.
Names, shared providers, shared frameworks and pre-existing `related` links do
not establish workload identity. User-agent/IP address, anonymous, and shared
gateway or workspace fallback callers cannot be bound to a code resource,
even when the string is an exact match. A duplicated code resource across
distinct accounts, providers or connectors is ambiguous and remains unknown.
The gateway must also identify an LLM transaction by model or compatible
endpoint/host. Access logs with a path require a recognized LLM/API route;
a framework user agent or model field on `/favicon.ico` does not qualify as
execution evidence.

API-key callers use a private, connector-local `credential:hmac-sha256:<64 hex
digits>` report identifier. A public SHA-256 fingerprint of a short key or key
ID is recoverable by guessing it offline. An operator can still configure an
exact `api-key:credential:sha256:...` binding computed privately from the raw
key, which the connector checks in memory without writing that public digest to
findings. Keep binding configuration private: publishing a public digest of a
guessable key would itself disclose the key. The exported HMAC is scan-local
unless a stable identity key is set (below), and in either case cannot be
pasted into a binding. Other caller names changed by
credential redaction remain `unverified` for runtime attribution. Do not put
raw API keys into bindings.

If a gateway scope label overlaps a credential or uses an opaque scope prefix,
the report contains a `scope:hmac-sha256:…` value instead. The connector uses
an ephemeral private key so these values preserve distinct tenant groups within
one connector instance without exposing short labels to offline guessing. They
change across independent scans and cannot serve as cross-run identifiers or
correlation binding values. Gateway source IDs always use a private scan-local
key because configuration can include short labels or bindings even if no
accepted event uses that scope. The configured gateway label itself is written
to findings; do not put secrets in labels. The engine shares that key across gateway
jobs in one report, so duplicate sources retain one identity, and creates a new
key for each scan. Direct connector instances use independent keys. Redacted scope scans are
marked incomplete; gateway exports are noncomparable across independent runs.
Resolve the scope/credential overlap before interpreting a report comparison
as evidence that a finding was resolved.

To compare gateway callers across scans, set `SHADOWSCAN_IDENTITY_KEY` to at
least 32 random bytes in the environment of every scan that should be
comparable. Encode it explicitly as `hex:<value>` or `base64:<value>` (for
example, prefix the output of `openssl rand -hex 32` with `hex:`). Bare
encodings are accepted only when exactly one canonical encoding is valid;
ambiguous bare values stop the scan and require one of these prefixes.
Prefix names are case-insensitive. The engine then uses this key instead of a
new key per scan: identical inputs and
configuration give identical caller, scope and source pseudonyms and finding
IDs, findings carry `metadata.identity_scope: keyed`, and the `collection_scope` fingerprint covers
the gateway configuration through an HMAC under the key. The key is read only
from the environment, never from a configuration file, and is never logged or
written to reports, caches or record exports. A set value that does not decode
to at least 32 bytes stops the command before any collection (exit 1). Treat
the key as a secret: with it and a report, anyone can test guesses of short API
keys, labels and bindings against the pseudonyms, and reports made under one key
can be linked to each other. A different key changes every gateway ID and the
collection scope, so `diff` never resolves findings across keys; rotating the key
requires a fresh baseline. A caller that is missing from a complete export of
the same source under the same key is reported resolved: the new export has no
requests from it, which does not prove that the workload was removed.

Code findings with frameworks gain `metadata.runtime_activity`:

| Field | Meaning |
|---|---|
| `status: observed` | The bound gateway export contains timestamped, LLM-classified requests bearing a matching framework fingerprint. |
| `status: unobserved` | Linked telemetry exists but contains no matching framework fingerprint within the export window. |
| `status: unknown` | No eligible binding, ambiguous code identity, or missing matching-event timestamps. |
| `window`, `last_seen`, `events` | Time bounds and counts of matching timestamped events. |
| `production_observed` | At least one matching event carries `prod`/`production` in `environment` or `deployment_environment` (including event metadata). This is a label in the supplied data, not independently established deployment state. |
| `production_label_verified` | `false`: ShadowScan cannot establish the origin or accuracy of deployment labels in imported logs. |
| `sources` | Gateway finding IDs, export provenance, scope, identity and environment assurance, and per-observation details. |

Timestamp, framework and production label must belong to the same event. A caller
named `prod-agent` is insufficient. Generic service or principal fields carry
`operator-asserted` identity assurance. A recognized provider field can carry
`provider-authenticated-field` assurance when it originates from a trusted
provider export, but ShadowScan does not cryptographically verify that provenance.
Framework fingerprints in user agents can be spoofed. Inspect the source
assurance and validate the export's trust chain before claiming an identified
workload is executing in production. Missing logs do not prove inactivity, and
old events do not establish current execution. Correlation does not increase
static confidence or reduce risk.

Gateway finding IDs include the canonical input path and relevant connector
configuration (label, format, filters and bindings). This changes IDs from older
reports. Repeating an identical configured source within one connector instance
is idempotent for nonredacted principal/service callers; API-key callers and
redacted scopes use connector-local HMAC IDs. Without `SHADOWSCAN_IDENTITY_KEY`,
gateway exports are noncomparable across independent scans to avoid claiming
that a missing scan-local ID is a resolved finding: their findings carry
`metadata.identity_scope: run`, and `diff` lists them as not comparable (see
[comparing reports](#comparing-reports)). Distinct exports retain
separate provenance. Overlapping exports count observations from each source,
so aggregate counts are not guaranteed to represent unique requests.

OpenAI organization usage exports with `data[].results[]` are supported.
`metadata.events` counts requests and `metadata.records` counts exported rows;
`usage_intervals` preserves bucket boundaries and counts. A bucket is not a
per-request timestamp: it cannot establish hourly continuous activity or confirm
timestamped framework execution for runtime correlation.

## Precision safeguards

Constructing an agent and defining a tool in the same project does not prove
that the agent can invoke that tool. Python and JavaScript source execution
helpers and unused tool declarations remain zero-weight evidence with
`capability_basis: contextual-unlinked-source`; their features appear in
`metadata.contextual_capabilities` and unproven features in
`metadata.potential_capabilities`. They do not raise confidence or risk.
Supported literal tool registrations connect local Python tool bodies and
direct unshadowed same-scope helpers; registered SDK execution tools and
MCP sinks retain their connected capabilities. Rebinding, parameters that
shadow helper names, mutable aliases and dynamic collections cannot establish
that connection. Configured opaque tools can establish `tool-use`, while an
unresolved implementation cannot establish its execution capability.
Registration is source evidence, not proof that a deployed workload ran it.

JavaScript/TypeScript binding skips only provably constant-dead literal
`if`/`else` and `while` branches, including supported parentheses and negation,
and preserves executed alternatives. Hoisted-name shadow uncertainty remains
conservative. Dynamic guards, comparisons, compound expressions and ambiguous
statement boundaries are outside this narrow recognition; the scanner does
not claim complete control-flow or data-flow analysis.

Responses API tool dispatch requires linked source evidence from the SDK client,
request, returned output and function-call guard to the dispatch. A single
verified dispatch establishes `tool-use`; `autonomous` requires a verified
iterative feedback loop. JavaScript recognition is deliberately conservative:
it accepts a small, complete top-level program with static imports and request
options. Extra statements, nested scopes, mutations and dynamic options cannot
establish this proof. Unsupported shapes, including files longer than such a
program can be, still produce ordinary SDK evidence and leave coverage complete.

Several rules keep weak observations from producing strong or high-risk
findings. A credential whose value looks like a documentation placeholder
(`REPLACE_ME`, `<your-key>`, `sua_chave_openai`, `xxxx`, all zeros, `abcdef...`
or `1234567890` sequences after the provider prefix) is never a `secret`
finding; it is listed on the project finding as low-weight `example-credential`
evidence. An assigned value shaped like an identifier (`api_key = resolved_api_key`)
is not a credential at all. A key alone
does not establish LLM usage, a coding-agent configuration needs more than an
environment-variable or display-name mention (`GOOSE_PROVIDER` in a detector
list is not "Goose configured"; a config file, instruction document,
dependency or workflow step still is), MCP parsing skips
`*.lock.yml` / `*.lock.yaml` files (compiled agentic workflows) and cookiecutter
`{{...}}` template paths, and vendor-neutral heuristics (agent loops,
`subprocess.run`, auto-approve flags) only count in a project that also matches
a framework, provider, platform, protocol or cloud-service signature. When every
observation for a project other than those heuristics is an environment-variable
or display-name reference, the heuristics are dropped and the finding is built
from the name references alone: it is tagged `env-names-only`, its evidence
weights are halved and its confidence is capped at 0.8 (`likely`), however many
names appear. A data or prose file that only lists four or more products by
domain, variable name or model identifier (a proxy blocklist, a vendor policy,
a leaderboard, a copy of the signature packs) is a catalog, as is a shorter list
whose file name spells `blocklist`, `denylist` or `blacklist` as one word or two
(`deny_list.json`); an allowlist, an egress policy or a firewall or WAF rule set
permits what it names and is not one. A catalog's mentions count only for a
product with an import, dependency or code pattern elsewhere in the project, and
the discounted files are listed in `metadata.catalog_mentions`.
A lexical code pattern without the library's import, dependency, bound call,
configuration shape, image, IaC, model id or a host or variable name of weight
0.3 or more anywhere in the project (a Rust `create_agent(`, a C#
`AgentType.Validate(`, a Java `new MCPClient()`) and a
signature known only from mentions below weight 0.3 (the bare `huggingface.co`
host) are kept as evidence but establish nothing: they are listed under
`metadata.potential_frameworks` / `metadata.potential_providers` instead of
`frameworks[]` / `model_providers[]`, and a project with nothing else yields a
note naming the files rather than a finding. Model identifiers in source and
configuration are medium-weight evidence (at most 0.5 each); a project known
only from them is tagged `model-ids-only` and capped at 0.6, and a model id in
a data file is a mention that anchors nothing. A container image in a CI
pipeline is a mention at 0.3 of its weight and yields no `infra` finding.
Configuration is never a catalog, however many products it names: deployment
and CI documents, files under `.devcontainer/` or a top-level `config/`,
`conf/` or `settings/` directory, files that assign the variables they name
(`OPENAI_API_KEY=...`), and data files that code of the same project loads by
name, outside documentation and website directories; a deny-list file name
outweighs the directory and the reference, not an assignment (see
[Code connectors](connectors/code.md)). MCP servers
for files and databases carry the `data-access` capability, browser servers
`browsing`, and shells `code-exec`; a project that implements an MCP server
(an import-bound `FastMCP(` or `new McpServer(`, or a Go, Java, .NET or Rust
server idiom corroborated by the SDK) carries `mcp-server`, the capability of
exposing tools to other agents, and is titled `MCP server in ...` with the
server described under `metadata.mcp_server`. In gateway logs, round-the-clock
activity keeps the informational `always-on` tag but only marks a caller as agentic,
with the `autonomous` capability, when tool use, an agent-framework user agent,
a service or principal identity, or missing end-user attribution corroborates
it. `tools/evaluation/corpus.json` carries regression cases for each rule.

## Developer endpoints

`shadowscan endpoint` scans a workstation profile at the well-known locations
of AI client configuration instead of walking the home directory: Claude
Desktop and Claude Code (`~/.claude.json`, `~/.claude/settings*.json`,
`~/.claude/CLAUDE.md`, skills, agents, commands, hooks), Cursor (`~/.cursor/mcp.json`,
rules), Windsurf, VS Code and VS Code Insiders with the Cline and Roo
extensions (also inside Cursor), Gemini CLI, Codex CLI, Kiro, Amazon Q, GitHub
Copilot CLI, Zed, Continue, Goose, OpenCode, LM Studio, Aider, OpenClaw and a
generic `~/.mcp.json`. macOS, Linux and Windows paths are all checked; the
Windows ones are the profile's own `AppData/Roaming`, never the scanning
process's `%APPDATA%`, so `--home` on a mounted Windows profile reads that
profile's Claude Desktop and VS Code configuration. Without `--home`, a
`%APPDATA%` redirected outside the profile (folder redirection to a file
share) makes the scan incomplete (exit 3), because the clients' configuration
there is not read. Scan the share separately, for example with `--home` set to
the directory that holds the redirected `AppData\Roaming`. The full list is
`shadowscan.endpoint.LOCATIONS`; it includes every configuration file the
`endpoint.inventory` connector reads.

The profile is read through the `code.filesystem` connector with its
`include` option, walked only along the known locations, so a profile scan has
the connector's limits, credential detection and symlink policy. The include
list is the same for every profile, so the collection scope of a workstation
stays comparable when clients are configured or removed: `shadowscan diff`
reports them as new or resolved findings. A location that is a link, sits
below one, or cannot be inspected is not read and makes the scan incomplete
(exit 3); every other location is still read and reported. A linked directory
holding none of the locations (a stow-folded `~/.config` without client
configuration) is passed over and does not make the scan incomplete. The
default profile is the current user's home with symbolic links resolved
(`$HOME` is trusted as `--home` is), so a home below a linked `/home` works.
`--home DIR` inspects another profile (a mounted image, a fleet collection
directory); `--list` prints the locations that exist and exits (exit 3 if one
could not be inspected). Findings carry the resource prefix `endpoint:<hostname>`; `--label`
replaces it, for example with an asset tag, so that merged fleet reports stay
attributable. A profile with none of the locations is a complete, empty scan
whose stats carry a warning, not a setup error (exit 0 unless `--fail-on`
applies). `--incremental` does not apply: fingerprinting the profile would
read every file in it, so an endpoint scan always runs in full.

The same client configuration inside a repository (`.mcp.json`,
`.cursor/mcp.json`, `.claude/`) is found by `shadowscan code`; the endpoint
command exists for the user-level copies that no repository scan sees.

`shadowscan endpoint` and the [`endpoint.inventory`](connectors/endpoint.md#endpointinventory)
connector read the same configuration files for different purposes, and their
findings have different identities, so one profile scanned both ways is not
deduplicated in a merged report. `endpoint.inventory` is the device
inventory: endpoint-surface findings per client and MCP configuration, editor
and browser extensions, local models and shell history, linked to
`runtime.processes`. It also reports a client whose directory exists
(`~/.copilot`, `~/.kiro`, the OpenClaw workspace); `shadowscan endpoint` does
not walk those directories, which hold session logs, caches and agent memory,
and reads only the configuration files in them. `shadowscan endpoint` is a
code scan of the configuration and instruction files themselves: code-surface
findings with the code connector's MCP, coding-agent and credential
signatures and the instruction-content checks. Use the inventory for asset
and lifecycle tracking, and the endpoint command to review what the
configured agents are told to do and can reach.

## Fleet merge

`shadowscan merge laptop-a.json laptop-b.json -o fleet.json` combines JSON
reports from several machines or scans into one. Findings with the same
identity (the same object seen by the same connector, such as one workstation
scanned twice) merge exactly as repeated observations do inside a scan:
evidence and technologies union, the earliest `first_seen` and latest
`last_seen` survive, the first report's metadata wins. Findings from
different machines keep their own resources because the endpoint label
prefixes every resource. Every finding records the reports it came from in
`metadata.merged_from`, and `collection_scope.fleet.sources`
(`shadowscan.fleet-merge/v2`) lists each source with its completion state,
finding count, scope fingerprint, `started_at` and `finished_at`, whether it
supplied an inventory (`inventory_present`), and the status of each of its
connector runs (`connectors`: `complete`, `cached`, `incomplete` or
`skipped`). A source is named by its path below the reports' common directory
(`host-a/report.json` for reports collected as `<host>/report.json`), or by
its file name when the reports share a directory.

Registration counts only from sources that had an inventory
(`inventory_present: true`: `--inventory`, the configuration's `inventory:`
key or `trusted_registries`). Whatever the order of the sources, a merged
finding is `shadow: true` when any such source found it unregistered, `false`
when such sources matched it to the same agent, and `null` when none of the
sources that reported it had an inventory. Sources that matched it to
different agents make it ambiguous, as two matching inventory entries are in
one scan: it is `shadow: true` with
`registry_match_reason: ambiguous-resource-approval` and the candidates in
`registry_suggestions`. The `shadow` and `registry_match` of a source without
an inventory, and a `shadow: false` that names no `registry_match`, are
ignored. The match state written beside a verdict follows the verdict the
merged finding adopts: a shadow finding keeps the candidate reason, suggestions,
identity assurance and `registry-identity-unverified` tag of the sources that
found it unregistered (the first such source's value of each key). A registered
finding keeps only the match diagnostics of the sources that approved it;
neither carries the other's diagnostics. Scans made without
an inventory never make a finding look unregistered: in a mixed fleet, a
finding seen only on machines scanned without one stays `null` although the
merged `inventory_present` is true. The terminal table, CSV, Markdown and HTML
reports label it `unassessed` (the table, Markdown and HTML reports also count
such findings in the summary). A scan configured with
`options.trusted_registries` reconciles its findings even when none of its
connectors produced registry records, so it reports every unmatched finding
as unregistered, and in a merge that wins over another source's match. Give
such scans the same inventory files as the rest of the fleet, or configure
trusted registries only on scans that run the connector that reads them.
The merged `inventory_present` is true when any source had an inventory,
even an empty one, and `inventory_size` is the largest source inventory.

Report files are untrusted input. A finding id that another report already
uses for a finding with another identity (resource, connector, account and
the other identity fields) is refused (exit 1) rather than merged, as is a
report whose `inventory_present` is not a boolean. A report without
`inventory_present`, such as one written by the v0.1.x releases, merges as
inventory-less only when it records no registration (no `shadow` verdict, no
`registry_match` and an `inventory_size` of 0); otherwise it is refused
(exit 1) rather than having its shadow verdicts dropped to `unassessed`.
Rescan such sources with this version before merging. Machines that share a host
name and home directory, such as clones of one VM image, produce the same
identities and merge as one machine scanned twice; give each a distinct
`--label`, such as its asset tag. A registered finding whose reports carry
different [declared governance facts](inventory.md#declared-governance-facts)
is refused too, so the result never depends on the order of the reports.

The merged report is comparable with `shadowscan diff` only when every source
was complete and carried a comparable collection scope; its fingerprint is
then derived from the sources' fingerprints, so two fleet reports of the same
machines with the same scanner and signatures compare. Otherwise the report
says why it is not comparable. Completion follows the sources: one incomplete
source makes the merged report incomplete (exit 3). Reports with another
finding identity schema are refused; rescan them first.

## Fleet dashboard

`shadowscan dashboard fleet.json -o dashboard.html --inventory-json inventory.json`
writes a static page and a `shadowscan.inventory/v1` JSON document from one
fleet report or several reports. Coverage per source and connector comes
first; a source that was not collected reads "not collected", never 0.
`--baseline` adds drift and `--history DIR` adds trends over earlier reports.
An incomplete input exits 3. See [Fleet dashboard](operations/dashboard.md).

## Live collection scope

`cloud.aws`, `cloud.azure`, `cloud.gcp` and `identity.entra` attest the scope of
a live collection, so that two live scans can be compared
([comparing reports](#comparing-reports)). Each records, during collection, what
its provider reported rather than what the configuration asked for:

| Connector | Principal (reported by the provider) | Partitions | Enumerations |
|---|---|---|---|
| `cloud.aws` | the account STS `GetCallerIdentity` returns, never the caller ARN; `role_arn` is a requested option | the resolved `regions` (`all` resolves through `DescribeRegions`) | each selected service's listings per region, `GetAccountAuthorizationDetails`, CloudTrail `LookupEvents`, registry listings per region and per `registry_arns` registry |
| `identity.entra` | the tenant `GET /organization` returns, for app-only credentials only (delegated listings, and those of an `access_token` that is not a decodable app-only token, are scoped to one user and are never attested); a `tenant_id` GUID that differs stops the scan | none: the tenant | the service principal, consent grant and application listings, and the opted-in agent identity and Agent 365 package listings |
| `cloud.gcp` | the configured `projects`, each verified by its enabled-services listing; without `projects`, the set of projects a complete `projects.list` returned | configured `projects` and the resolved `locations` | for configured projects, every per-project and per-location listing; in discovery mode only `projects.list` |
| `cloud.azure` | the configured `subscriptions`, each read with `GET /subscriptions/{id}`; without `subscriptions`, those `GET /subscriptions` lists | subscriptions | `GET /subscriptions` when listing, the Resource Graph query and each subscription's role assignments |

The fingerprint covers, for each live entry, the principal, the requested
options, the partitions and every enumeration with its outcome, together with
the signatures, scanner and version that cover every scope. Requested options
are the non-secret keys each connector lists, as resolved (environment
fallbacks and defaults included; lists of names compare as sets): `account_id`,
`role_arn`, `regions`, `services`, `cloudtrail_days`, `max_lambda`,
`max_ecs_api_calls`, `max_registry_records` and `registry_arns` for AWS;
`tenant_id`, `auth_mode`, `include_first_party`, `max_app_role_lookups`,
`include_agent_identities`, `include_agent_registry`, `agent_registry_api` and
`max_package_lookups` for Entra; `projects`, `locations`, `audit_days`,
`max_projects`, `max_pages`, `agent_registry`, `agent_registry_version`,
`agent_registry_locations`, `gemini_enterprise` and `discovery_collections` for
GCP; `subscriptions` and `include_app_settings` for Azure. Credentials, profile
names and credential files never enter it. Calls made once per discovered
resource (an agent's aliases, a principal's app role assignments, a package's
details, a service account's keys) are details: they are recorded per
operation template and outcome and never fingerprinted, and neither are page
or item counts, resource identifiers or timestamps. More pages, more resources
and a new agent therefore keep the scope; the new agent is a new finding.

A live entry attests nothing, and a comparison with it is incomplete (exit 3),
when:

- any listing was denied, throttled, truncated, unavailable or failed, or the
  connector was otherwise incomplete or timed out: `live collection was not
  verified or was incomplete`;
- the provider did not confirm the principal, for example an Entra application
  without `Organization.Read.All` or `Directory.Read.All`, or a configured
  Azure subscription that could not be read: `live principal could not be
  verified`. The scan itself completes, with an advisory warning;
- an option holds a value the sanitizer would change, which would be a
  credential: `configuration contains private comparison values`.

Other live connectors (`code.github` and `code.gitlab` without `input`, the
`saas.*` and `lowcode.*` connectors, and the other `identity.*` and `cloud.*`
connectors) still report `live collection scope is not attested`, and plugins
`third-party connector scope is not attested`. Changing the scope makes the
next comparison incomplete, including enabling an API in a configured GCP
project or a region under `regions: all`; collect a new baseline then.

`collection_scope.live` lists each live entry's record: the principal and the
call that verified it, the requested options, partitions, enumerations and
details with their outcomes, and `complete`. It is outside the fingerprint,
explains a `scope differs` or incomplete comparison, and is sanitized like the
rest of the report; its account, tenant, project and subscription identifiers
are ones findings already carry. A fleet merge of complete, attested live
reports is comparable like any other merge; the merged report does not copy
the sources' `live` records.

Attestation shows which principal, partitions and operations a scan enumerated
successfully, under which options. It does not show that the account or
tenant has no agents outside the enumerated APIs, services, regions, locations
or projects, or that a listing returned every object rather than those the
credentials may read: Resource Graph and delegated Graph listings return only
what the caller can see, without failing. For that reason a delegated
`identity.entra` scan, or one whose `access_token` is not a decodable app-only
token, is never attested: another user in the same tenant could see less
without any error. In GCP discovery mode, and when
`cloud.azure` lists its subscriptions, the principal is the discovered project
or subscription set, so a project or subscription the credentials can no
longer see changes the scope (exit 3) instead of resolving its findings, and a
new one needs a reviewed re-baseline. Set `projects` or `subscriptions` to keep
the scope stable.

### Record export replay

Comparing replays of record exports is the alternative for any built-in
connector: collect live with `--dump-records` (or `options.dump_records`),
replay each export with `input`, and diff the replays. Three pitfalls apply. The
scope digest of an offline entry includes the absolute resolved `input` path,
so stage every replay at the same path under the same label, or the comparison
reports `scope differs`. An export is published even when the live run
behind it was incomplete (a denied listing is a warning, not an export
failure), while the replay of that export can complete: check the export's
`manifest.json` (`complete` for the run and `exported` for the entry) and
replay only complete runs. And an export is sanitized before it is written:
a credential the live run recognized in a record, by its shape or by the name
of the field holding it, is already redacted there, so a replay cannot observe
it. Findings that rest on a plaintext credential in a resource's
configuration (the `plaintext-credential` tag of a Lambda, AgentCore or
container environment, and the evidence, confidence and risk it adds) appear
in the live report and not in the replay of its own export, and the replay
reports neither a warning nor incomplete coverage for the difference. Compare
such findings between live runs, or between a live run and its replay only
after discounting them. A replay attests the export's contents, not the
tenant's completeness or the live run's credential evidence.

## Comparing reports

`shadowscan diff baseline.json current.json` reports new findings and substantive
changes, including permissions, classification, ownership, registration and risk
score/factors within the same risk band. Each changed item includes
`changed_fields`. Missing findings count as resolved only when both reports
completed, declare the same supported finding-identity schema, carry a
`summary` whose `total` (and `by_surface`/`by_kind` counts) match their
`findings` array, and have the same `collection_scope` fingerprint. A truncated
or filtered report is therefore unknown (exit 3), not a resolution.

A complete report can still have left content unread: the omissions a `ci`
profile scan declared and the coverage gaps its budget tolerated
(`stats.coverage`). A finding missing from such content may only have gone
unread, so it is not resolved. When a missing finding's file (its
`metadata.path` or the file an evidence location names) is, or lies below, a
gap path that `stats[].coverage.details` lists, or lies under a test,
documentation, example or generated path while the current report counts
declared omissions, the comparison is incomplete with the reason `absence
there is not resolution`: every missing finding is `unknown` and diff exits 3.
A project finding is held back by a gap or a declared omission
(`stats[].declared_paths`) inside its directory or above it, since its
evidence can come from any file in it; removing an agent project in `src/`
still resolves while a cassette under `tests/` is declared. When a connector
declared more omissions than it lists (over 200, or a report from before the
list), every missing project finding of that connector is held back. A finding missing from content the scan
did read still resolves, so a `--profile ci` gate keeps reporting resolutions.
When the report cannot say where a connector stopped reading (a gap list cut at
50 entries, a malformed ledger or count, a summary counting declared omissions
that no connector record holds, or declared omissions from a connector without
the `ci` profile), every missing finding of that connector is held back. A
connector record names the connector its findings carry in `stats[].name`
(`stats[].connector` is the label when one is set), and that is how a finding
is matched to its record's unread content; a record without a name, in an older
report, applies to every connector's findings. Only
the current report's unread content counts: the baseline's could only make a
finding look new, which diff reports anyway. Unread content means what the
report records as such, declared omissions and `stats[].coverage`: a gap the
default profile discounts in test code (a warning ending "test code is
discounted evidence (include_tests is false)") is in neither, so a finding
missing from such a file, such as a test notebook that stopped parsing, still
resolves.

The fingerprint is an opaque digest that covers
selected source paths, connector settings, filters, confidence threshold,
signatures and scanner implementation. File contents and inventory approvals
are excluded so real removals and approval changes can be compared. A public
digest does not hide guessable paths or labels; keep these settings nonsecret.
With `options.mcp_registries` set, the digest also covers each registry's id,
pinned SHA-256 and approval flag (not the snapshot's path): a different pinned
snapshot changes tags and scores, so baselines taken with it are not comparable.
Scans without the option keep the digest they had.
Credential-bearing configurations omit the digest. Gateway exports attest
comparable scope only when `SHADOWSCAN_IDENTITY_KEY` is set: an HMAC under that
key stands in for their configuration, which can hold guessable labels and
bindings. Without the key their private caller/scope identities change between
scans.

Incomplete scans, changed scope, older reports without provenance, live
collections that could not attest their scope and third-party connectors cannot
establish equivalent coverage. Their missing findings are reported as
`unknown`, and diff exits 3. New and changed findings remain visible. Local
repositories, offline exports from built-in connectors and live collections by
`cloud.aws`, `cloud.azure`, `cloud.gcp` and `identity.entra` can attest
comparable scope ([live collection scope](#live-collection-scope)),
`gateway.logs` only when both scans were keyed with the same identity key. Every
other live connector and every third-party connector cannot. The digest
covers the resolved absolute scan paths, so compare scans of the same checkout
location; a label does not stand in for the path, because a narrower scan under
the same label would otherwise make out-of-scope findings look resolved.

By default `diff` exits 0 when the comparison is complete, whatever it finds.
`--fail-on-new` exits 2 when there are new findings or a finding's risk level
rose; an incomplete comparison still exits 3.

`--shadow-only` narrows the displayed records to findings whose `shadow`
field is true (unmatched against the supplied inventory; findings from
inventory-less scans have `shadow: null` and are not shown). It is a view:
the summary counts, incompleteness reasons, `--fail-on-new` gating and exit
codes are always computed over the full comparison, and `--json` always
carries the complete document plus a `shadow_only_view` id list.

Connectors that were disabled or left out by `--only` do not make a scan
incomplete (that is operator intent), but the JSON report lists them as
`collection_scope.not_run` with the reason. The list is not part of the scope
digest.

A finding with `metadata.identity_scope: run`, which `gateway.logs` findings
and `saas.generic` findings whose resource a credential redacted carry unless
`SHADOWSCAN_IDENTITY_KEY` is set, has an ID derived from a key that is random
for each scan: the same caller or app has a different ID in the next report.
Diff therefore never reports such a finding as new, resolved or unknown because
the other report lacks its ID. It lists it under `not_comparable` (`baseline` or
`current`; marked `<` or `>` in text output), states the reason and exits 3. A
finding whose ID appears in both reports is compared as usual. Any declared
`identity_scope` other than `keyed`, the scope of findings made under
`SHADOWSCAN_IDENTITY_KEY`, is treated the same way.

Finding IDs do not depend on inferred kind. Stable resource-type families (or an
explicit plugin `identity_discriminator`) separate distinct observations on a
resource. Regenerate comparison baselines after upgrading from legacy IDs;
cross-schema comparisons retain missing findings as unknown. Incompatible cache
entries cause a full rescan.

### Drift classes and baseline lifecycle

Every changed finding lists its `drift` in addition to its `changed_fields`.
Each drift entry names a class:

- `inventory`: new and resolved findings, kind and resource type;
- `capability`: permissions, capabilities, frameworks, model providers,
  models, tags, and an MCP tool's `metadata.tool_definition_sha256`;
- `autonomy`: the floor, ceiling, oversight and initiation of
  `metadata.autonomy`;
- `governance`: owner, shadow status, registry match,
  `metadata.registry_reconciliation.status` and the `autonomy-understated`
  tag;
- `coverage`: the reasons a comparison is incomplete.

Each entry also says whether the change is adverse, for example an added
permission, a higher autonomy floor or a lost owner.
`--fail-on-drift inventory,capability,autonomy,governance` exits 2 on adverse
drift in a listed class, and an incomplete comparison still exits 3. The JSON
document adds `drift_summary` and `adverse` per class. No other metadata is
compared, and a finding without these keys compares as before. A malformed
value makes the report invalid input rather than unchanged. Risk changes are
not classified; `--fail-on-new` gates on risk level rises.

`--baseline-sha256 HEX` refuses (exit 1) a baseline file whose raw bytes do
not have that SHA-256, before anything is printed. `--max-baseline-age-days N`
makes the comparison incomplete (exit 3) in these cases:

- the baseline scan started more than N days ago;
- its `started_at` is missing, invalid, without a timezone or in the future;
- it started after the current scan.

[Scheduled drift detection](operations/drift.md) describes each class's
adverse changes and the baseline review process.

## Completion and migration

| CLI exit | Meaning |
|---|---|
| `0` | Scan completed and the configured risk threshold was not reached. |
| `1` | Usage, setup or configuration error (unknown option or command, invalid config, missing inventory or signature path, unwritable report); no scan result. |
| `2` | Completed scan reached `--fail-on`. |
| `3` | Collection or analysis was incomplete, including empty or partly invalid connector selection. |

An incomplete scan that also reaches `--fail-on` exits 3. In CI, fail on any
non-zero exit rather than only on 2 and 3.

`--min-confidence` and YAML `options.min_confidence` accept finite values in
`[0, 1]`; invalid thresholds stop the scan instead of silently clearing the gate.

Incomplete results preserve valid findings, set `summary.complete` to false and
SARIF `invocations[].executionSuccessful` to false, and include diagnostics.
An incomplete CSV report starts with a `SCAN-INCOMPLETE` status row
(`kind` = `scan-status`, the unfinished connectors in `connector`) right after the
header, so it cannot be mistaken for a complete scan with no findings.
Failed or denied live collection for an enabled source marks coverage incomplete;
review per-connector diagnostics and rerun after restoring access.
Malformed files are isolated, so one bad manifest cannot suppress neighboring
findings. Regex matches have time budgets; exhausted budgets mark the scan
incomplete. Configure `code.filesystem.scan_timeout` in seconds to adjust the
shared per-file regex budget (default 2 seconds for files up to 256 KiB, growing
with file size as described under [large and generated files](#large-and-generated-files));
manifest parsers additionally cap each pattern at one second within that budget.

Denied or failed API requests and exhausted pagination mark collection incomplete.
Offline exports require valid objects or arrays of objects; scalar records,
invalid envelopes and malformed rows are errors. Use `[]` in JSON/YAML or
`{"records": []}` in JSONL for an explicitly empty inventory; an empty file does
not establish successful collection. Valid neighboring records are retained.
Export files are capped at 64 MiB each, 512 MiB total and 200,000 filesystem
entries; symlinks and special files are rejected. Gateway gzip input is bounded
before and after decompression. These limits also apply to custom gateway and
JWT loaders.

Cloud offline inputs use ShadowScan's normalized record format, including a
recognized `_kind` discriminator (see `tests/fixtures/cloud/`). Arbitrary raw
provider responses need conversion to that format. Missing or unsupported
record kinds and malformed resource identifiers make collection incomplete;
they are never treated as a successfully scanned empty inventory.

Existing inventory entries that rely on names alone must add reviewed `resources`
bindings. Names now offer review suggestions without approving a finding or
reducing risk. Surface, provider and account restrictions are enforced; multiple
matching approvals remain ambiguous. See [inventory](inventory.md).

Signature files are validated before use and in CI. Unknown fields (including
`severity`), malformed regexes, duplicate definitions and invalid weights fail
validation. Severity is computed centrally by the risk engine rather than set in
a signature. See [signature authoring](signatures.md).

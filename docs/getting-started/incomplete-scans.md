# Incomplete scans (exit 3)

ShadowScan fails closed. When it cannot read or judge part of its input, it
says so and exits 3 instead of returning a report that looks clean. An
incomplete scan still carries every finding it made; what it cannot promise is
that nothing else is there. This page explains how to find out why a scan is
incomplete and how to get a complete result, usually on the first or second
run.

## Read what the scan tells you

On exit 3 the last lines on stderr name the reason categories and what to do
about each one:

```text
scan incomplete (exit 3): oversize-file 2; see the report's warnings, errors and stats
to resolve:
  oversize-file: files over max_file_size (1,000,000 bytes unless set) were not read: exclude
    generated data with --exclude GLOB, or raise the limit with --max-file-size BYTES;
    `shadowscan code PATH --preflight` lists them without scanning
  guide: https://aisecnomad.github.io/Nexus-ShadowScan/getting-started/incomplete-scans/
```

These lines never name a path or a value, so they are safe in a CI log that the
report itself does not reach. The paths are in the report: the terminal table
lists them under *Connector errors* and *Warnings*, and the JSON report lists
every gap under `stats[].coverage.details` with its `path`, `reason`, `kind`
(`blinding` gaps always fail the scan; `partial` ones are charged to the
coverage budget) and `relevance`:

```bash
shadowscan code . --format json -o report.json
jq -r '.stats[].coverage.details[]? | "\(.reason)\t\(.kind)\t\(.path)"' report.json
```

## Check the static limits first: `--preflight`

`shadowscan code PATH --preflight` first checks that the root can be opened
safely, then runs the scanner's own walk, exclusions,
size limits and coverage accounting, and records the gaps that need no file
content to decide: files over `--max-file-size`, symbolic links and submodules
that leave the tree, non-regular entries, and the walk's own limits. It reads
no other content, so it finishes in seconds on trees that take minutes to
scan.

```bash
shadowscan code . --preflight                              # exit 3: these files would be gaps
shadowscan code . --preflight --exclude 'data/**/*.json'   # exit 0: none left
shadowscan code . --exclude 'data/**/*.json'               # the full scan
```

The preflight exits 0 when the root is ready and it found no static gap, and 3
when a root is blocked or a full scan would be incomplete because of a static
gap; the files are listed under `roots[].static_gaps` in `--format json`. It
reports no finding and its `shadowscan.code-preflight/v1` document says
`scan_performed: false`, so its output cannot be mistaken for a scan result. A
clean preflight does not promise a complete scan:
content can still fail to parse, a matching budget or deadline can still run
out.

## What each reason means and what to do

| Reason | Typical cause | What to do |
|--------|---------------|------------|
| `oversize-file` | Generated data, fixtures or specs over `max_file_size` (1,000,000 bytes). One whose bytes may name MCP servers is *blinding*: unread, it could hide agent configuration; a JSON file of up to 8 MiB is then parsed to decide by its structure, so an OpenAPI schema that describes an `mcp_servers` field is one budgeted gap. A notebook made large by saved images is read for credentials with that base64 data left out; one whose text outputs alone are over the limit is one budgeted gap. | `--exclude` generated data that is not deployed; raise `--max-file-size` (config key `max_file_size`); list them with `--preflight`. Lockfiles, logs, images, archives and minified bundles are skipped without a gap (`oversize_skip_globs`). |
| `timeout` | The connector deadline ended the walk, or one file exhausted its matching budget. Unset, the deadline grows with the tree from 120 s up to 1800 s. | `--connector-timeout-seconds`; narrow the tree with `--exclude`; a file that times out on its own is named in the report. |
| `unresolved-link` | A symbolic link, gitlink or submodule that points outside the scanned tree, or is dangling, and is named like agent configuration. | Scan the target as another PATH, check out submodules, or exclude the link. |
| `unparsed-input` | A file the scanner selects (a manifest, an MCP or agent configuration, source) that does not parse or decode: an unrendered template, a deliberately malformed test fixture, JSON with duplicate keys. A notebook in which only some cells do not parse (tutorial placeholders such as `<YOUR API KEY>`) is one budgeted gap; its other cells are analyzed. | Fix or exclude it. `--profile ci` declares these under test, example, documentation and generated paths as counted omissions, and judges a directory as a template when its path or its manifest's project name holds template syntax (`{{`, `{%`, `${`); agent configuration is never declared. Under a directory whose name holds template syntax (cookiecutter's `{{cookiecutter.package_name}}/`), a file that does not parse is unrendered template source: one partial gap charged to the coverage budget, not an outright failure. So is a Python, TOML or JSON file that parses once its `{{ }}` placeholders are filled in, and a JSON data file whose repeated key neither reading makes MCP configuration. An empty or whitespace-only manifest, agent manifest or MCP configuration is a note, not a gap, and a Continue `uses:` block reference is an MCP server, not a defect. |
| `sanitization-limit` | A file's credential-redaction context could not be established, so its excerpts were withheld. Detection still ran. | Exclude the file if it is not deployed content. |
| `analysis-limit` | A per-file or per-scan analysis budget: the credential quota (more distinct credentials of one format in one file than are reported), model-identifier literals, syntax-tree nodes (200,000 per Python file, `max_ast_nodes`) or bound calls (2,048). | Review the named files. `--profile ci` declares analysis limits under test, example, documentation and generated paths, never credential limits. |
| `subset-scan` | `--triage`: a subset by design. | Run without it for a full result. |
| `unscanned-input` | Selected input that was not read, such as a Git LFS pointer in place of its file. | `git lfs pull`, or exclude it. |
| `access-denied`, `upstream-error` | Live connectors: missing scopes, API or network failures. | Grant the scopes in the connector's guide; re-run. |

## Profiles and budgets

* The coverage budget (`--max-coverage-gap`, default 0.02) tolerates partial
  gaps up to 2% of the examined entries; blinding gaps always fail.
* `--profile ci` declares, as counted omissions, the gaps a source gate accepts
  in advance under test, fixture, documentation, example and generated paths
  ([details](../scanning.md#the-ci-profile)).
* `--strict-coverage` (or `--max-coverage-gap 0`) is the opposite: every gap is
  an error.

## Scanning this repository

The ShadowScan checkout holds deliberately limit-tripping test vectors and
multi-megabyte benchmark data. `make self-scan` scans it with
`examples/shadowscan.self-scan.yaml`, which excludes exactly those paths, each
with its reason, and still fails on any new gap.

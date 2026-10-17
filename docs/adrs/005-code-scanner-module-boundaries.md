# ADR-005: Code scanner module boundaries

**Status:** Accepted
**Date:** 2026-10-01

## Context

`FilesystemConnector` (`connectors/code/filesystem.py`, lines 776–2799) is one
class of about 2,000 lines and 77 methods. It walks the tree, accounts for
coverage, reads and redacts files, dispatches them by type, resolves ownership
and builds every kind of code finding. The `github` and `gitlab` connectors
reuse it for cloned repositories, so any defect or change in it reaches three
connectors.

The methods already fall into four groups with few calls between them:

| Group | Methods (current lines) | Responsibility |
|---|---|---|
| Walk | `_excluded` … `_walk_entries` (948–1292) | Root opening, exclusions, links, oversize files, deadlines and coverage accounting |
| File scan | `_scan_file` … `_record_special_files` (1293–1754) | Reading, redacted excerpts, and dispatch to the manifest, IaC, config, source and secret paths |
| Ownership | `_git_info` … `_owners_for_files` (1980–2127) | Git history and CODEOWNERS (next to the existing `code/ownership.py`) |
| Findings | `_emit_findings` … `_parse_agent_definition` (1755–1979, 2128–2799) | Projects, coding agents, MCP servers, cards, manifests, workflows, IaC and secret findings |

Tests depend on the current layout: 23 `monkeypatch.setattr` calls target
filesystem internals and 6 test modules import private names from it.

The earlier split of `utils/redaction.py` into `redaction_*` modules kept such
patches working by replacing the module's class so that one assignment writes
to every module (`redaction.py`, end of file). That kept the tests unchanged,
but patched names now behave differently depending on which module they are
set on. This split should not repeat that pattern.

## Decision

Split along the four groups into collaborator classes, not mixins:

- `code/walk.py` — a tree walker that yields entries and coverage events.
- `code/file_scan.py` — a file scanner that reads, redacts and dispatches one
  file.
- `code/ownership.py` — gains git-history and CODEOWNERS resolution.
- `code/project_findings.py` — builds findings from project and file
  observations.

`FilesystemConnector` stays the façade that implements `collect()` and
`analyze()`, owns the `ConnectorContext`, and wires the collaborators
together.

Rules for the migration:

1. **Sequence after #107.** That pull request changes `filesystem.py` in
   several places; moving code first would make it unmergeable.
2. **One pull request per group,** moving code without changing behaviour.
3. **Prove "no behaviour change" with output equality:** identical JSON reports
   (ignoring timestamps) on every evaluation corpus, the offline demo, and a
   fixed list of public repositories like the one used for the 2026-10-01
   field scan.
4. **Migrate test seams in the same pull request:** patch the collaborator or
   inject it, rather than adding forwarding or module-class tricks.

## Consequences

**Positive:**

- Each module can be read, owned and tested on its own; the coverage and
  fail-closed accounting in particular becomes reviewable in isolation.
- Defects in one area, such as tree walking, cannot silently change finding
  construction.

**Negative:**

- Four pull requests of pure code movement, each needing the output-equality
  check.
- Test changes in the same pull requests as the moves.

## Status (2026-10-12)

Still proposed; none of the four moves has been made. `FilesystemConnector`
has grown to about 3,860 lines and 118 methods, so the split is larger than
the context above describes. The line ranges above are those of 2026-10-01
and are kept as recorded.

New code has gone into bounded helper modules beside the class rather than
into the proposed collaborators:

- `code/walk.py` (added 2026-10-06) holds the walk budget, project-root
  markers and the non-recursive, link-free directory walk. The tree walker
  that the decision proposes, with the coverage accounting it would own, is
  still in the class.
- Narrow, single-construct analyses live in their own modules, for example
  `tool_attribution.py` and `instruction_content.py`, added after this ADR,
  beside earlier ones such as `source_ranges.py` and `provider_loops.py`
  (see [code scanner internals](../architecture.md#code-scanner-internals)).

`code/file_scan.py` and `code/project_findings.py` do not exist yet, and
`code/ownership.py` still holds only CODEOWNERS matching.

## Status (2026-10-15)

The module-level helpers that sat beside the class in `filesystem.py` moved
into five bounded helper modules — `path_context.py`, `project_evidence.py`,
`model_identifiers.py`, `source_text.py` and `excerpts.py` (about 1,000
lines; see [code scanner internals](../architecture.md#code-scanner-internals)) —
continuing the beside-the-class pattern above, with behaviour checked by the
evaluation corpora and the offline demo. `filesystem.py` re-imports every name
that was importable from it before the move, including those it no longer uses
itself, which stay for importers only (patch them in their defining module);
`tests/unit/test_negative_context.py` pins that list. The only monkeypatched
moved name (`_redacted_source`) is called solely from `filesystem.py`, so
existing test seams keep their meaning; the forwarding-pattern caveat above
still applies to any further move of a patched name. The four collaborator-class moves of the decision remain open,
and the class itself is unchanged.

## Status (2026-10-17)

Accepted and implemented step by step: one commit per group in the order
ownership, walk, file scan, findings, then a fifth that moved the records the
collaborators share out of `file_scan.py`, each moving code without changing it
apart from renaming the methods other classes now call; the collaborators are
classes the façade constructs and wires, not mixins. The line ranges above are
those of 2026-10-01; the groups were derived again from the current call graph,
and a method that served two groups went where it needed the fewest calls
across them. Rule 2 asked for one pull request per group; the groups are
commits of one pull request here, each with the test changes its move needs
(rule 4).

1. **Ownership** moved into `ownership.CodeOwnership`: `git_info` (was
   `_git_info`), `owner_for` (`_owner_for`), `owners_for_files`
   (`_owners_for_files`) and the private `_codeowners_directory`, `_codeowners`
   and `_read_codeowners`, with their per-root caches, step budgets
   (`MAX_ROOT_OWNERSHIP_STEPS`) and git identity limits. `scan_tree` brackets
   every root with `begin_scan` and `end_scan`; CODEOWNERS is still read
   through the scan root descriptor the walk opened.
2. **Walk** moved into `walk.TreeWalker`: everything from `_excluded` to
   `_walk_entries` (root opening, exclusions and `include`, links, oversize and
   non-regular entries, submodules, deadline scheduling and the fail-closed
   coverage accounting), with the module-level limits, name tables and helpers
   it uses (the other groups import those they share from `walk.py`).
   `walk(scan, scan_file, unread_settings)` replaces `_walk`; the walker calls
   `scan_file` for each file it schedules. `included`, `model_artifact_name`,
   `size_limit`, `note_file`, `lockfile_gap`, `check_gitlink_coverage`,
   `root_listing_incomplete` and `skipped_oversize_test_fixtures` are its
   interface to the other collaborators and to `remote.py`. Failure isolation
   (`isolated`) became a function of `walk.py`, the lowest collaborator module.
   `_root_prefix`, which names the root in a diagnostic when the connector
   scans several, reads the connector's configuration, so it stays on the
   façade (configuration reads outside the connector class cannot be attributed
   to its `config_keys`, `tests/unit/test_connector_config_keys.py`); the
   walker receives the bound method.
3. **File scan** moved into the new `file_scan.FileScanner`: `scan_file` (was
   `_scan_file`) to `_record_special_files`, the record helpers the passes
   share (`_record`, `_handle_artifact`, `_looks_like_mcp_config` and the
   others), `_parse_agent_definition`, `_note_ua_mentions` and the post-walk
   binding of Python re-export consumers (`resolve_reexport_sources`), with the
   `_Project`, `_SourceFile` and `_MatchedSource` records. `file_errors` (was
   `_file_errors`) is also used by the findings code.
4. **Findings** moved into the new `project_findings.ProjectFindings`:
   `emit_findings` (was `_emit_findings`) and every project, source-agent,
   coding-agent, MCP, agent-manifest, workflow, IaC and credential finding
   builder. Like the file scan it receives `_base`, and like the walker
   `_root_prefix`.
5. **Shared records** moved out of `file_scan.py` (2,136 lines after step 3)
   into the new `scan_records.py`, so that no module of the split exceeds 2,000
   lines: the `_Project`, `_SourceFile` and `_MatchedSource` records,
   `FindingBase`, `_MCP_TRANSPORTS` (read by the file scan and the findings
   collaborator) and the file scan's helpers that need no scanner state,
   `_document_declares_mcp` with `_DEDICATED_MCP_CONFIG_NAMES`,
   `_bundled_signature` with `_BUNDLED_PACKS` and `_local_module_predicate`
   with `_on_disk_project`. The module imports none of the collaborators, so
   `walk.py` imports `_Project` from it rather than from `filesystem.py` under
   `TYPE_CHECKING`.

`FilesystemConnector` is the façade: configuration and its validation, the
engine hooks, `collect()`/`analyze()`/`load_offline()`, `scan_tree` with the
per-root `_ScanState`, label and diff resolution, `_base`, which stamps the
connector's identity on every finding and is handed to the file scan and the
findings collaborators (both build findings), and `_root_prefix`, handed to the
walker and the findings collaborator. The collaborators receive the validated
options they read when the connector is constructed; `unread_settings` and
`tree_listing_incomplete`, which `remote.py` sets after construction, are still
read per root. `tests/unit/test_filesystem_collaborator_wiring.py` checks that
every collaborator received every option it reads, set to a value that is not
its default, and that `scan_tree` hands the walker those two settings.

`filesystem.py` still re-exports every name that was importable from it before
(patch a name in its defining module): those it no longer uses are explicit
`name as name` imports, pinned with the earlier ones in
`tests/unit/test_negative_context.py`. Tests patch the collaborator class or
its module instead of `FilesystemConnector` or `filesystem.py`, with no
forwarding or module-class replacement.

Verification of the finished split against the unchanged code (main, 8c72467),
both run with Git 2.47, in three ways.

The command line gave the same JSON reports, exit codes and console output on
165 inputs: the offline demo; the nine corpora `make evaluate` runs;
`shadowscan code` on `tests/fixtures/sample_repo`, the ten ShadowBench code
repositories, `docs/`, `tools/` and the repository root, each with no option,
`--include-tests`, `--no-secrets`, `--triage`, `--strict-coverage` and
`--inventory agent-card.yaml` (the root and a Git tree also with `--diff-base
HEAD~1`); and hand-made trees for CODEOWNERS ownership, links, oversize,
special and non-regular entries, nested project roots, lockfiles, submodules
and Git metadata, scanned through `code.filesystem` (with limit, `include`,
exclusion, multi-root and source-granularity options), `code.github` and
`code.gitlab`. The only fields ignored are those that differed between two
runs of the unchanged code: start and finish times, the evaluation reports'
timings and their digest of the scanner's own source, and the connector-run
window in `endpoint.inventory` lifecycle metadata (the demo's console lines,
logged by connectors running in parallel, were compared regardless of order).

`code.filesystem` called directly, with the contract `code.github` and
`code.gitlab` use on a downloaded checkout, gave the same findings,
diagnostics and log messages, and left the same state on the connector for
`remote.py`, on 1,500 folders and 60 invalid configurations, in two orders of
the cases (5,706 findings, 1,561 warnings, 796 errors). The folders were made
from the repository's fixtures and altered a few times each (truncated,
NUL-containing, re-encoded, renamed or duplicated files, links that loop,
dangle or leave the root, FIFOs, empty, oversize or very long files, very deep
paths) and scanned with random combinations of the connector's options, over
Git repositories (`use_git`, `diff_base`), several roots and cancellation
after a set number of deadline checks.

Compared function by function with the original (comments, blank lines and
indentation ignored), 116 of the 166 functions of the three original modules
are the same. Of the other 50, 45 differ only in the names of the calls and
attributes that now go through a collaborator, and five are the wiring:
`__init__` and `scan_tree` of the façade, the `scan_file` and
`unread_settings` parameters of `walk` and `_walk_entries`, and `isolated`,
which takes the context instead of `self`. No module-level name of the three
modules is missing. Of their string literals only five docstrings differ (two
module docstrings, and three function docstrings that mention renamed methods
or were re-indented); of their 600 comment lines, 13 were re-wrapped, renamed
along with the methods they mention or (three section headings) dropped. The
eleven definitions that step 5 moved have the same syntax trees as before.

To see what these checks can tell apart, 24 deliberate breakages of the
finished code (one changed condition, constant, tag or hand-off each, in every
module of the split and in the options the connector passes on) were run
through them. The direct comparison, on 300 of the folders and the 60 invalid
configurations, flagged 11 of them. The function comparison flagged all 11 that
change a function or table of a module, and the wiring test
(`tests/unit/test_filesystem_collaborator_wiring.py`) the 12 that change what
the connector hands to a collaborator, so every breakage was flagged by at
least one of the three; the direct comparison alone would have missed 13.

Not verified: the public repositories of the 2026-10-01 field scan (nothing
was cloned), the live clone and API modes of `code.github` and `code.gitlab`
against real hosts (their handling of a downloaded checkout was compared), and
permission-denied reads (the runner was root).

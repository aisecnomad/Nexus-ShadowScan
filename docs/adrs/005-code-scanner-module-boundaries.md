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

The first of the four moves is made: the ownership group. `_git_info`,
`_codeowners_directory`, `_codeowners`, `_read_codeowners`, `_owner_for` and
`_owners_for_files`, with the five attributes that held their state, are now
`OwnershipResolver` in `code/ownership.py` (the module the decision named for
them), a collaborator the connector constructs once and tells which scan is
open so ownership reads stay on the collection's descriptor. The connector
calls `self.ownership.owner_for(...)`, `owners_for_files(...)` and
`git_info(...)`; nothing forwards the old names, and the constants the methods
used (`MAX_ROOT_OWNERSHIP_STEPS`, the git field limits) moved with them and
are re-exported as the defining module's objects, as rule 4 and the 2026-10-15
status describe. So are the ten names `filesystem.py` imported only for those
methods and no longer uses (`subprocess`, `link_in_path`,
`open_confined_file`, `parse_timestamp`, `run_bounded_metadata`,
`require_local_git_metadata`, `metadata_git_argv_prefix`, `metadata_git_env`,
`MetadataTimeoutError` and `MetadataOutputLimitError`), which the move first
dropped; `tests/unit/test_negative_context.py` pins them with the others.
Patching one of them on `filesystem` changes nothing the resolver does.

The test seams moved in the same change, as rule 4 asks: the eight test
modules that called `connector._git_info`, patched
`FilesystemConnector._git_info` or `_read_codeowners`, read
`_ownership_scan` or `_ownership_steps_remaining`, or patched
`filesystem.run_bounded_metadata`, `OwnershipBudget`, `MAX_RULES` and
`MAX_ROOT_OWNERSHIP_STEPS` now address `OwnershipResolver` and the
`ownership` module; the descriptor-confinement test records the resolver's
`open_confined_directory` and `read_text` beside the connector's. Behaviour
was checked by the ownership, confinement, git-metadata and gitlink tests, the
evaluation corpora and the offline demo. The walk, file-scan and
project-findings moves remain open; the class is about 4,100 lines and 121
methods, down from 4,250 and 127.

1. **Ownership** moved into `ownership.OwnershipResolver` first, as the paragraph
   above records: `git_info`, `owner_for` and `owners_for_files` with the
   private CODEOWNERS readers, their per-root caches, step budgets and git
   identity limits. `scan_tree` tells the resolver which scan is open
   (`ownership.scan`) and forgets the root's caches before each walk;
   CODEOWNERS is still read through the scan root descriptor the walk opened.
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
   into the new `scan_records.py`: the `_Project`, `_SourceFile` and `_MatchedSource` records,
   `FindingBase`, `_MCP_TRANSPORTS` (read by the file scan and the findings
   collaborator) and the file scan's helpers that need no scanner state,
   `_document_declares_mcp` with `_DEDICATED_MCP_CONFIG_NAMES`,
   `_bundled_signature` with `_BUNDLED_PACKS` and `_local_module_predicate`
   with `_on_disk_project`. The module imports none of the collaborators, so
   `walk.py` imports `_Project` from it rather than from `filesystem.py` under
   `TYPE_CHECKING`.

The split did not get every module under the 2,000-line mark the ratchet
uses for new modules: redone on the review-fix code of #252–#258, `walk.py`
holds 2,192 lines and `file_scan.py` 2,259 (`project_findings.py` 1,268,
`scan_records.py` 272, the façade 1,188). `tools/complexity_baseline.json`
records those sizes and the complexity gate fails closed when either grows;
a rise a review accepts is recorded with `--rebaseline` and explained in the
pull request, as [CONTRIBUTING](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#quality-gates) says. Getting both
below the mark is a further step, not a precondition of this split.

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

On this branch the four later moves were made again on the integrated code,
which the review fixes of #254 to #258 had changed in the same functions:
each definition #259 moved was merged three ways (the original, this
branch's version, #259's moved copy), so every fix landed in the module the
split chose, and the 41 definitions the fixes added were placed by the
collaborator that reads them. Verification is the repository's own: the
full test suite on every supported CPython (the collaborator wiring test, the
coverage, credential-oracle and filesystem suites among them), ruff, mypy,
the complexity gate, the nine evaluation corpora and the self-scan, as the
engineering log entry for the split records. Not verified: the live clone
and API modes of `code.github` and `code.gitlab` against real hosts, and the
public repositories of the 2026-10-01 field scan.

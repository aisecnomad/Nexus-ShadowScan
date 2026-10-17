# ADR-005: Code scanner module boundaries

**Status:** Proposed
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

## Decision (proposed)

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

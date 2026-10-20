# Interactive triage in the terminal

Status: proposal, drafted 2026-10-20; not implemented. Recommendation: defer
until after the 1.0.0 contract freeze, then ship as an optional extra.

## The ask

Security engineers triaging a scan move between the terminal table, the JSON
report and the HTML report. An interactive terminal UI (for example built on
[Textual](https://textual.textualize.io/)) could list findings, filter them by
risk, surface, owner and tag, show each finding's evidence, and record a
decision (accept into the sanctioned inventory, mark a false positive, assign
an owner) without leaving the terminal.

## What it would cost

**Dependencies.** Textual 8.2 requires `rich`, `markdown-it-py[linkify]`,
`mdit-py-plugins`, `platformdirs`, `pygments` and `typing-extensions`. The
runtime lock already pins `rich`, `markdown-it-py`, `mdurl`, `pygments` and
`typing-extensions`, so the extra adds five packages: `textual`,
`mdit-py-plugins`, `platformdirs`, `linkify-it-py` and `uc-micro-py`. The
footprint is modest, but each is another hash-locked, audited and
Dependabot-tracked artifact, and Textual is a large framework from one vendor.

**Untrusted text on screen.** Finding titles, evidence descriptions, resource
names and owners are derived from scanned repositories and remote APIs, which
the [trust model](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/AGENTS.md)
treats as untrusted. Rich and Textual interpret console markup (`[bold]`,
`[link=...]`) in strings they render. A repository could name a file so that
its finding title restyles the screen, hides a neighbouring row or renders a
link. Every string would have to go through the same escaping the table
reporter applies (`terminal_text`, `rich.markup.escape`), and a test would have
to plant markup in every rendered field. The HTML report already solves the
equivalent problem for browsers.

**Contract surface.** A new command, key bindings and a decision file format
become public behaviour. Adding them while the CLI and Python API are being
frozen for 1.0.0 (`docs/reference/stability.md`) would freeze an unproven UI
alongside them.

**Write path.** Recording a decision writes files the scanner later trusts:
the sanctioned inventory (Agent Capability Cards) and any suppression list. A
TUI must write only to a path the operator names, through the existing
private-file writer, and never into the scanned repository.

## Recommendation

1. Do not add Textual to the core dependencies.
2. After 1.0.0, ship `shadowscan triage-ui REPORT.json` behind an optional
   `NexusShadowScan[tui]` extra with its own hash lock
   (`requirements-tui.lock`), so the scanner's runtime and its audit stay
   unchanged for everyone who does not install it.
3. Read-only first (browse, filter, inspect evidence). Add decisions in a
   second step that writes Agent Capability Cards through the inventory
   module, so the TUI produces exactly what `shadowscan inventory` validates.
4. Test with Textual's headless `Pilot`, including a markup-injection test
   over every rendered field.

Until then, the supported workflows are the terminal table
(`--max-rows`, `-v`), `--format html` for a browsable report, the fleet
dashboard, and `shadowscan diff` between reports.

## Size

M: one to two weeks for the read-only browser with its tests and lock, and
another week for decisions written as capability cards.

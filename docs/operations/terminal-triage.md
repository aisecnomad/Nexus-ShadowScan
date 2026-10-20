# Terminal triage

Browse an existing JSON report offline with the installed scanner:

```bash
shadowscan code ./service --format json -o scan.json
shadowscan triage scan.json
shadowscan triage scan.json --level high --search agent
shadowscan triage scan.json --list
```

The terminal browser uses the existing Rich dependency, so it needs no
additional UI package or web server. It is part of the Python CLI distribution,
not a separately compiled single-file executable.

Use `n` / `p` for pages, `/text` to search, `all` to clear the search,
`1`–`10` to inspect a visible finding, and `q` to quit. Redirected input prints
one page without prompting; `--list` does the same explicitly.

Every page shows whether the input is complete. Filtering never changes that
status, and quitting an incomplete report returns exit 3. Reports are loaded
through the same bounded, symlink-refusing reader and completion validation as
fleet import. Displayed values are sanitized and terminal control characters
are made visible.

The view does not contact a provider, execute remediation, modify the report or
mark findings resolved. Validate the evidence and make changes in the owning
system, then rescan and use `shadowscan diff` to assess the result. Keep reports
private even after credential redaction.

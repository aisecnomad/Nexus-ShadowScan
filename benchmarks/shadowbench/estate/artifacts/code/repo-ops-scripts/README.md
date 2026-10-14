# repo-ops-scripts

Small Go tools for the Adatum Logistics ops channel.

Internal clone: `git@git.adatum.example:platform/repo-ops-scripts.git`

| Command | Purpose |
| --- | --- |
| `cmd/logsummary` | Condenses nightly dispatch logs into a five-bullet digest |
| `cmd/etabot` | Answers ETA questions from a local Ollama model on the build network |

Build with `go build ./...` (Go 1.22). The committed `.cursor/mcp.json`
gives Cursor read-only access to the ops database when editing these
tools.

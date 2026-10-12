# eta-graph

LangGraph service that replans linehaul ETAs when trailer telemetry drifts
from the plan: fetch telemetry, draft a revised ETA, notify dispatch.

Internal clone: `git@git.vantor.example:platform/repo-eta-graph.git`

## Run

    pip install -e .
    export ANTHROPIC_API_KEY=...
    python -c "from eta_graph.graph import build_graph; build_graph()"

The committed `.mcp.json` wires the read-only ETA database and the
telemetry gateway into Claude Code for local debugging.

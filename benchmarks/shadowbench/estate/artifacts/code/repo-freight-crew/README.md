# freight-crew

Carrier quote triage crew for the Adatum Logistics freight desk. Scores
inbound spot quotes against the rate card and proposes next week's lane
assignments.

Internal clone: `git@git.adatum.example:platform/repo-freight-crew.git`

## Run

    pip install -e .
    export OPENAI_API_KEY=...
    python -m freight_crew.main < quotes.json

Agent and task definitions live in `src/freight_crew/config/`.

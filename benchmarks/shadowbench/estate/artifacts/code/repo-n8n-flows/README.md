# repo-n8n-flows

Version-controlled exports of the freight-desk n8n workflows. The n8n
instance at flows.vantor.example is the runtime; this repository is the
reviewed source of truth. Export with
`n8n export:workflow --all --separate` and commit the JSON files under
`workflows/`.

| Workflow | File | Purpose |
| --- | --- | --- |
| Quote triage agent | workflows/quote-triage-agent.json | Labels inbound spot quotes against the rate card |
| POD summary agent | workflows/pod-summary-agent.json | Summarises proof-of-delivery emails to the dispatch log |
| Carrier rate sheet sync | workflows/carrier-sync.json | Plain ETL, no AI steps |

Credentials stay in the n8n credential store; exports reference them by id
only.

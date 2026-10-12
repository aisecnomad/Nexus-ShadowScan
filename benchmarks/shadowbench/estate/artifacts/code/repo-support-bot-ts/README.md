# support-bot

Customer support assistant for Adatum Logistics: answers shipment, quote
and delivery-window questions over HTTP, exposes its shipment tools as an
MCP server, and publishes an A2A agent card for partner integrations.

Internal clone: `git@git.adatum.example:platform/repo-support-bot-ts.git`

## Run

    npm install
    npm run build
    OPENAI_API_KEY=... node lib/index.js

The agent card served at `/.well-known/agent.json` comes from `public/`.

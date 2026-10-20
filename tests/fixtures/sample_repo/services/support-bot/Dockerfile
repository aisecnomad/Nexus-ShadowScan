# Synthetic scanner fixture; this is not ShadowScan's production image.
# Docker Hub library/node:22-slim multi-platform digest, observed 2026-10-20.
FROM node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
ENV OPENAI_API_KEY=""
ENV ANTHROPIC_BASE_URL=https://api.anthropic.com
COPY claude-cli/package.json claude-cli/package-lock.json /opt/claude-cli/
# Retain dependency evidence without running the package's postinstall or CLI.
RUN npm ci --prefix /opt/claude-cli --ignore-scripts --engine-strict --no-audit --no-fund
COPY . .
CMD ["node", "dist/index.js"]

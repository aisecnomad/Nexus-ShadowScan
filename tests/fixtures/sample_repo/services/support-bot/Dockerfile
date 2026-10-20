# Synthetic scanner fixture; this is not ShadowScan's production image.
# Docker Hub library/node:20-slim multi-platform digest, observed 2026-10-20.
FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0
ENV OPENAI_API_KEY=""
ENV ANTHROPIC_BASE_URL=https://api.anthropic.com
RUN npm install -g @anthropic-ai/claude-code
COPY . .
CMD ["node", "dist/index.js"]

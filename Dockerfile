# Glama-ready container for the web-exposure-mcp server (stdio transport).
FROM node:20-slim
WORKDIR /app
COPY package.json ./
COPY scripts ./scripts
# Zero runtime dependencies — install is a no-op but keeps the layer explicit.
RUN npm install --omit=dev --no-audit --no-fund || true
ENTRYPOINT ["node", "scripts/mcp.js"]

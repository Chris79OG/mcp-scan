# ── Stage 1: builder ────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy manifests first for layer caching
COPY package.json package-lock.json ./

# Install all deps (including devDeps needed for build)
RUN npm ci

# Copy source
COPY tsconfig.json ./
COPY src ./src

# Compile TypeScript → dist/
RUN npm run build

# Prune dev dependencies so only production deps are copied
RUN npm prune --production


# ── Stage 2: runner ──────────────────────────────────────────────────────────
FROM node:20-alpine AS runner

# Non-root user for least-privilege operation
RUN addgroup -S mcp && adduser -S mcp -G mcp

WORKDIR /app

# Copy compiled artefacts and production deps
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

# Health-check: verify the CLI binary responds
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node dist/cli.js --help > /dev/null 2>&1 || exit 1

USER mcp

# Default: run the server mode (exposes /health and /metrics)
# Override to "cli" for one-shot scan invocations
ENTRYPOINT ["node", "dist/server.js"]
CMD []

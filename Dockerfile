# syntax=docker/dockerfile:1

FROM oven/bun:1.4.0 AS build
WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY . .
RUN bun run build

FROM oven/bun:1.4.0-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    PORT=3100 \
    DATABASE_PATH=/app/data/usage.db

COPY --from=build --chown=bun:bun /app/package.json /app/bun.lock ./
COPY --from=build --chown=bun:bun /app/node_modules ./node_modules
COPY --from=build --chown=bun:bun /app/src ./src
COPY --from=build --chown=bun:bun /app/dist ./dist

RUN mkdir -p /app/data && chown bun:bun /app/data

VOLUME ["/app/data"]
EXPOSE 3100
USER bun

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD bun -e 'const r = await fetch("http://127.0.0.1:3100/health"); if (!r.ok) process.exit(1); const j = await r.json(); if (j.status !== "ok" || j.integrity !== true) process.exit(1);'

ENTRYPOINT ["bun", "run", "src/index.ts"]

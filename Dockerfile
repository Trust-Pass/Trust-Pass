# syntax=docker/dockerfile:1
# TrustPass: one container serves the API and the built web app over a single origin.

# Override to use a registry mirror, e.g. public.ecr.aws/docker/library/node:22-bookworm-slim
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
COPY e2e/package.json e2e/
RUN pnpm install --frozen-lockfile --filter @trustpass/api... --filter @trustpass/web...
COPY apps ./apps
COPY packages ./packages
RUN pnpm --filter @trustpass/api exec prisma generate \
 && pnpm --filter @trustpass/web build \
 && pnpm --filter @trustpass/api build

FROM ${NODE_IMAGE} AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV NODE_ENV=production
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
COPY e2e/package.json e2e/
RUN pnpm install --frozen-lockfile --prod --filter @trustpass/api
COPY --from=build /app/apps/api/dist apps/api/dist
COPY --from=build /app/apps/api/prisma apps/api/prisma
COPY --from=build /app/apps/web/dist apps/web/dist
RUN pnpm --filter @trustpass/api exec prisma generate

USER node
WORKDIR /app/apps/api
ENV WEB_DIST_DIR=/app/apps/web/dist \
    PORT=10000 \
    HOST=0.0.0.0
EXPOSE 10000
# Apply pending migrations (non-destructive), register the demo issuer and the
# admin account (idempotent), then start the server.
CMD ["sh", "-c", "npx prisma migrate deploy && (node dist/seed.js || echo 'seed skipped') && exec node dist/server.js"]

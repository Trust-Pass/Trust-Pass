# syntax=docker/dockerfile:1
# TrustPass release rehearsal image: the RELEASE's own API build (same Dockerfile steps as
# production) on top of PostgreSQL 18 with 7-Zip, to rehearse the release on a restored backup.
# Build from the repository root, on the branch you want to rehearse:
#   docker build -f scripts/rehearsal/Dockerfile --build-arg RELEASE=$(git rev-parse --short HEAD) -t trustpass-rehearsal:release .
# Run: see scripts/rehearsal/README.md (always with --network none).
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
COPY e2e/package.json e2e/
RUN pnpm install --frozen-lockfile --filter @trustpass/api...
COPY apps/api ./apps/api
COPY packages ./packages
# A Windows checkout may have CRLF line endings. Migrations must be byte-identical to what
# production applied (Prisma stores their checksums), so normalise them to LF like the repository.
RUN find apps/api/prisma/migrations -name '*.sql' -exec sed -i 's/\r$//' {} + \
 && pnpm --filter @trustpass/api exec prisma generate \
 && pnpm --filter @trustpass/api build \
 && test -f apps/api/dist/rehearsal.js

FROM ${NODE_IMAGE} AS node

FROM postgres:18
ARG RELEASE=unknown
LABEL trustpass.tools="release-rehearsal-v1"
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates 7zip-standalone openssl libstdc++6 \
 && rm -rf /var/lib/apt/lists/* \
 && command -v 7zz
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=build /app /app
COPY scripts/rehearsal/trustpass-release-rehearsal.sh /usr/local/bin/trustpass-release-rehearsal.sh
# Same for the script (bash refuses "set -o pipefail\r"); then check it parses.
RUN sed -i 's/\r$//' /usr/local/bin/trustpass-release-rehearsal.sh \
 && bash -n /usr/local/bin/trustpass-release-rehearsal.sh \
 && ! grep -rlq "$(printf '\r')" /app/apps/api/prisma/migrations /usr/local/bin/trustpass-release-rehearsal.sh \
 && echo "$RELEASE" > /app/RELEASE && node --version && /app/apps/api/node_modules/.bin/prisma --version >/dev/null
ENV CHECKPOINT_DISABLE=1 PRISMA_HIDE_UPDATE_MESSAGE=1
ENTRYPOINT ["bash", "/usr/local/bin/trustpass-release-rehearsal.sh"]

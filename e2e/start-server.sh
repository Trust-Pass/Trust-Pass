#!/usr/bin/env bash
# Starts TrustPass for end-to-end tests: a fresh database, the production web
# build served by the API, and simulated geolocation (127.0.0.1 = Saudi Arabia).
set -euo pipefail
cd "$(dirname "$0")/../apps/api"
export NODE_ENV=development
export PORT=3100
export APP_URL=http://localhost:3100
export DATABASE_URL="${E2E_DATABASE_URL:-postgresql://trustpass:trustpass_dev@localhost:5432/trustpass_e2e}"
# Keys come from the fake KMS (random root key in a local file, like production's Cloud KMS).
# MASTER_KEY stays as a legacy key so data from earlier local runs still opens.
export KEY_PROVIDER=fake-kms
export FAKE_KMS_KEY_FILE=./data/e2e-fake-kms.key
export MASTER_KEY=e2e-master-key-0123456789-abcdefghijklmnopqrstuvwxyz
export IP_HASH_SECRET=e2e-ip-hash-secret-0123456789-abcdefghijklmnop
export ISSUER_SIGNING_SEED=e2e-issuer-seed-0123456789-abcdefghijklmnopq
export STORAGE_DRIVER=database
export GEO_PROVIDER=simulated
export GEO_SIMULATED_DEFAULT=SA
export MAIL_TRANSPORT=console
export WEB_DIST_DIR=../web/dist
export LOG_LEVEL=warn
export ADMIN_EMAIL=admin@e2e.test
export ADMIN_PASSWORD=E2E-Admin-Password-2026
# Non-destructive: applies pending migrations only. Tests use unique data, so no reset is needed.
npx prisma migrate deploy >/dev/null
npx tsx src/scripts/seed.ts
exec npx tsx src/server.ts

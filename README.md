# TrustPass

**Your Documents. Your Control.**

TrustPass is a secure document-sharing and verification platform. People upload certificates and other documents, which are encrypted before storage. They then share only the fields a recipient needs, through links that expire, can be revoked, can be limited to an organization or to countries, and are logged for the owner.

> Share only what is necessary. Verify what matters. Stay in control.

Built for a cybersecurity training camp demonstration. Phase 1 (core platform) is complete; Phase 2, QR Shield (a QR Security Scanner), is described in [docs/qr-shield.md](docs/qr-shield.md).

## What it does

| Area | What is implemented |
| --- | --- |
| Accounts | Individual and organization accounts, Argon2id passwords, server-side sessions in HttpOnly cookies, CSRF protection, lockout after 5 failed sign-ins, password reset, session list with remote sign-out, admin role |
| Documents | PDF/PNG/JPEG upload checked by content (magic bytes), images re-encoded to strip EXIF and hidden data, PDFs with scripts or embedded files rejected, 10 MB limit |
| Encryption | AES-256-GCM per document with its own data key, wrapped by a key-encryption key (envelope encryption). File, field values, **titles, field labels, recipient names and the file's SHA-256** are all encrypted with the document's key; logs and notifications store ids only. With `KEY_PROVIDER=gcp-kms` the key-encryption keys are protected by Google Cloud KMS, so the database (ciphertext and wrapped keys) and the root key are in different places. With the legacy `KEY_PROVIDER=env` the key comes from `MASTER_KEY` in the server's environment, which is separate from the database but not from the server |
| Selective sharing | Structured claims; issuer credentials use SD-JWT so a recipient sees, and can verify, a single signed field without the rest of the certificate |
| Verification | A simulated trusted university signs credentials with Ed25519. Files and credentials verify as **Verified**, **Invalid** (modified, expired or issuer revoked) or **Unverified** (no trusted signature) |
| QR Shield | QR Security Scanner: camera, photo or pasted link. Codes are decoded on the device; the address is checked offline (never visited) for phishing, look-alike names, disguised or hidden destinations, risky downloads and scripts. Genuine TrustPass share links are recognised and their status shown |
| Share links | 256-bit tokens stored only as hashes, expiry (1 h to 30 days), instant revocation, organization-only recipients, view-only access |
| Country rules | Allowed-country lists enforced on the server from the visitor's IP using an offline database. Unknown locations are denied. Raw IPs are never stored |
| Watermarks | Every shared view is re-rendered with the recipient, time and link ID burned into each page |
| Analytics | Attempts granted and denied, expired-link attempts, approximate countries, distinct visitors, per-document breakdown, alerts and full access history |
| Logs | Append-only `access_logs` and `security_events`: a database trigger rejects edits and deletes; only the retention job may purge old rows |
| Admin | Users, organizations, platform security events, issuer trust, system settings and health checks |

## Architecture

```
Browser (React SPA, no keys)  ──HTTPS──▶  Fastify API (one origin, also serves the SPA)
                                           ├─ auth, documents, sharing, access gate, verification,
                                           │  issuer simulator, analytics, notifications, admin
                                           └─ crypto service (AES-256-GCM envelope, Ed25519, hashing)
                                                │            │              │             │
                                           PostgreSQL   Ciphertext     Master key     IP→country DB
                                           (metadata,   storage        and secrets    (offline)
                                           wrapped keys, (disk or DB)  (environment)
                                           logs)
```

- `apps/api`: Fastify 5, Prisma 6, PostgreSQL. Each feature lives in `src/modules/*`.
- `apps/web`: React 19, Vite, Tailwind CSS 4, TanStack Query, pdf.js (canvas rendering), Recharts.
- `packages/shared`: Zod validation schemas and constants used by both sides.
- `e2e`: Playwright tests on a phone and a desktop viewport.

More detail: [docs/architecture.md](docs/architecture.md) · [docs/security.md](docs/security.md) · [docs/test-report.md](docs/test-report.md) · [docs/demo-script.md](docs/demo-script.md)

## Run it locally

Requirements: Node.js 22, pnpm 10, PostgreSQL 16 (or Docker).

```bash
pnpm install
docker compose up -d            # PostgreSQL + Mailpit (or use your own PostgreSQL)
cp .env.example .env            # then replace every "replace-with-..." value
pnpm --filter @trustpass/api exec prisma migrate deploy
pnpm db:seed                    # demo issuer + admin from ADMIN_EMAIL / ADMIN_PASSWORD
pnpm dev                        # API on :3000, web app on http://localhost:5173
```

Generate secrets with `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`.

In development, `GEO_PROVIDER=simulated` treats every visitor as coming from `GEO_SIMULATED_DEFAULT` (Saudi Arabia by default). The server refuses to start with the simulated provider in production.

## Tests

```bash
pnpm typecheck
pnpm test        # 123 API tests: unit, integration (real PostgreSQL) and security
pnpm build
pnpm e2e         # 16 Playwright runs: 8 scenarios on iPhone 13 and desktop Chrome
```

The API tests use `TEST_DATABASE_URL` (default `postgresql://trustpass:trustpass_dev@localhost:5432/trustpass_test`). End-to-end tests start their own server on port 3100 against `trustpass_e2e`. See [docs/test-report.md](docs/test-report.md) for the latest results.

## Deploy (Render)

The repository contains a Render Blueprint (`render.yaml`) that creates the web service and a PostgreSQL database together.

1. Create a Render account and connect the GitHub organization.
2. In Render choose **New > Blueprint** and select this repository.
3. Enter `ADMIN_EMAIL` and `ADMIN_PASSWORD` (12+ characters) when asked. Everything else is set by the blueprint; `MASTER_KEY`, `IP_HASH_SECRET` and `ISSUER_SIGNING_SEED` are generated by Render and never leave it.
4. After the first deploy, sign in as the admin, change the admin password in **Settings**, and open **Admin > Health** to confirm database, storage and geolocation. Every user can also see the country TrustPass detects for them in **Settings > Your connection**.

Maintenance without a shell: the free plan has no shell for `pnpm keys:*`. Set `STARTUP_MAINTENANCE=encrypt-metadata` (or `rewrap` after a key change) on the service; the task runs once after the next start, logs counts only and shows its result in **Admin > Health > Last start-up maintenance**. Running it again is harmless. Remove the variable afterwards.

Notes: the free web service sleeps after inactivity (first request takes about a minute), and the free database has a limited lifetime. Upgrade both before a live demo. Password-reset emails need an SMTP provider (`MAIL_TRANSPORT=smtp`, `SMTP_URL`).

## Honest limitations

- Encryption is server-side at rest, not end-to-end: the server must decrypt to watermark files and show chosen fields. What this does and does not protect against: [docs/server-side-decryption.md](docs/server-side-decryption.md).
- In production the master key is an environment secret. A cloud KMS would be stronger and fits behind the same interface.
- IP geolocation is approximate. VPNs, proxies and mobile carriers can change the detected country.
- No website can block screenshots or cameras. Watermarks make leaks traceable, not impossible.
- The issuing university is simulated. There is no integration with real universities or government systems.
- Database triggers stop the application from editing logs, but a database superuser could still bypass them.

Geolocation data: [IP Geolocation by DB-IP](https://db-ip.com) (CC BY 4.0).

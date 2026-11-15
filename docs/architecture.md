# TrustPass architecture

TrustPass Phase 1 is a TypeScript monorepo. One Fastify service serves both the API and the built React app from a single origin, which keeps cookies, CSRF protection and the Content-Security-Policy simple. Every security decision is made on the server.

## Repository layout

```
apps/api            Fastify API
  prisma/           schema.prisma and migrations (with hand-written triggers and CHECKs)
  src/config.ts     environment validation and key derivation (fails fast)
  src/plugins/      sessions (auth.ts), headers/CSRF/rate limits (security.ts)
  src/lib/          crypto, storage drivers, geolocation, SD-JWT, PDF rendering and watermarking, upload validation
  src/services/     documents (envelope encryption), issuer, verification, audit, settings, retention
  src/modules/      HTTP routes per feature: auth, documents, sharing, access (the gate), verification,
                    organizations, insights (analytics, activity, notifications, dashboard), admin
  test/             unit, integration and security tests
apps/web            React app (pages/, components/, lib/)
packages/shared     Zod schemas, enums, country list
e2e                 Playwright tests (phone and desktop)
```

Each module owns its routes and its access policy, so team members can work on separate modules.

## Request flow for a share link

1. `GET /api/share/:token` hashes the token and looks the link up.
2. The access gate (`modules/access.ts`) checks, in order: revoked, expired, recipient organization, allowed countries. The first failure wins.
3. Every attempt is written to `access_logs` with the outcome, approximate country, a keyed hash of the IP and a coarse client label.
4. On success the server unwraps the document key, decrypts only the permitted claims, builds an SD-JWT presentation with only those disclosures, verifies it, and returns the verified values.
5. If the file is shared, `GET /api/share/:token/file` repeats the gate, decrypts the file and burns a watermark into every page before sending it with `Cache-Control: no-store`.

## Data model

19 PostgreSQL tables: `users`, `sessions`, `password_reset_tokens`, `organizations`, `organization_members`, `documents`, `document_keys`, `document_claims`, `issuers`, `credentials`, `sharing_links`, `sharing_permissions`, `allowed_countries`, `verification_records`, `access_logs`, `security_events`, `notifications`, `system_settings`, `stored_objects` (ciphertext for the database storage driver). See `apps/api/prisma/schema.prisma`.

Hand-written SQL in the initial migration adds:
- lower-case email, link expiry after creation, organization recipient consistency and country-code format CHECKs;
- a trigger ensuring a link only discloses claims of its own document;
- append-only triggers on `access_logs` and `security_events` (UPDATE, DELETE and TRUNCATE rejected unless the retention job enables purging in its transaction).

## Credentials

The simulated "TrustPass Demo University" derives an Ed25519 key from `ISSUER_SIGNING_SEED` and registers its public key in `issuers`. Each credential is an SD-JWT: six salted claim disclosures whose SHA-256 digests are signed, plus the SHA-256 of the issued PDF certificate. The PDF carries its credential id in its metadata, so a modified copy is recognised as **Invalid** rather than merely unknown.

## Deployment

Production runs as one Docker container (see `Dockerfile`) on Render with a managed PostgreSQL database (`render.yaml`). The container applies migrations (non-destructive), seeds the issuer and admin account, then starts the server. Encrypted files are stored in PostgreSQL because the free web service has no persistent disk. Render terminates TLS; the app sets HSTS and `__Host-` cookies in production.

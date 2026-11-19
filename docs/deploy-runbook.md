# Release runbook: `claude/release` to production

Production today: Render service `trustpass` (auto-deploys every commit on `main`) and database
`trustpass-db` (PostgreSQL 18, free plan). Nothing in this runbook runs without Reham's explicit
approval at the step marked **APPROVAL**.

## What the release contains

| Area | Change |
|---|---|
| E2 key management | Key provider abstraction (`env` default, `gcp-kms`, `fake-kms` for dev only), keyring table, start-up checks, `keys` CLI |
| E3–E5 metadata | Titles, field labels, recipient names and file hashes sealed with the document key; logs and notifications hold ids only |
| QR Security Scanner | `/app/scan`: live camera, image upload, paste; offline analysis; dangerous links cannot be opened |
| Operations | `STARTUP_MAINTENANCE` (backfill without a shell), integrity alerts to owner and admins, new Admin > Health checks |
| UI | Top navigation with sidebar, Midnight dark theme on phone and desktop |

Database migrations applied automatically on start (`prisma migrate deploy`):
`20261117160000_key_encryption_keys`, `20261117190000_keyring_production_guard`,
`20261119090000_encrypt_metadata`, `20261119180000_recipient_download`. All four only add tables/columns or make columns nullable; no
data is removed by a migration.

## Pre-flight (no production change)

1. CI green on the release head: API tests, e2e (phone and desktop), secrets scan, dependency audit.
2. A fresh encrypted backup exists from the same day (the existing drill script; the backup
   procedure itself is already proven, so this is a normal run, not a new drill).
3. Reham confirms her password manager holds `MASTER_KEY`, `IP_HASH_SECRET`,
   `ISSUER_SIGNING_SEED` and the admin password (done 19 Nov).
4. No environment variable changes are needed: the release defaults to `KEY_PROVIDER=env` and keeps
   using the existing `MASTER_KEY`.

## Rollout

1. **APPROVAL**: merge `claude/release` into `main` (one PR). Render deploys it automatically.
   PR #5 and PR #6 are included in the release branch; they are closed by this merge only if
   Reham chooses so.
2. Watch the deploy in Render until it is live; then open `/api/health` (must be `ok`).
3. Sign in as admin, open **Admin > Health**:
   - "Encryption keys" OK
   - "Metadata encryption" will show existing titles still in clear. This is expected.
4. Smoke test (2 minutes): open an existing document, view its file, open one existing share
   link in a private window, run one QR check.
5. **APPROVAL**: set `STARTUP_MAINTENANCE=encrypt-metadata` on the Render service. Render restarts
   the service; the task seals existing titles, labels, recipients and hashes and rewrites old
   log rows and notifications.
6. **Admin > Health** must now show "Metadata encryption" OK and "Last start-up maintenance:
   encrypt-metadata OK". Repeat the smoke test.
7. **APPROVAL**: remove `STARTUP_MAINTENANCE` from the service (running it again is harmless,
   but it should not stay set).

## Rollback

- Before step 5 **and before anyone uploads or shares after the deploy**: redeploy the previous `main`
  commit in Render. Existing rows still have their plain columns, so the old code reads them. Documents
  and links created by the new code have encrypted titles only, which the old code cannot read; after
  the first new upload, fix forward instead (see `docs/release-checklist.md`).
- After step 5: the old code cannot read sealed titles. Do not roll back the code; fix forward on
  a branch. If data itself is damaged, restore from the backup taken in pre-flight (documented in
  `docs/recovery.md`), which needs the same `MASTER_KEY`.

## Database network access

The app connects through Render's private network (internal host `dpg-…-a`, confirmed in the
start-up logs), which the IP allow list does not affect. Only connections through the external
URL (Reham's backups) use it.

- Normal state: allow list **empty** (no external access).
- For a backup: add "My IP" (`<your IP>/32`), run the backup, remove it again.

## Later: Google Cloud KMS (needs Google Cloud setup and billing)

One script does steps 2–5 in Google Cloud Shell: `scripts/gcp/setup-kms.sh <PROJECT_ID> [BILLING_ACCOUNT_ID]`.

Cost: about $0.12 per month for two key versions plus $0.03 per 10,000 operations.

1. Reham: project `trustpass-kms`, billing account, $1 budget alert.
2. Reham: enable the Cloud KMS API.
3. Reham: key ring `trustpass` in `europe-west3` with keys `trustpass-prod-kek` and
   `trustpass-test-kek`.
4. Reham: service accounts `trustpass-ci` (test key only) and `trustpass-app` (prod key only),
   role *Cloud KMS CryptoKey Encrypter/Decrypter* on that one key.
5. Reham: JSON key for `trustpass-ci` into GitHub secrets `GCP_TEST_KMS_KEY_NAME` and
   `GCP_TEST_SERVICE_ACCOUNT_JSON`. CI then runs the live KMS tests (must be 0 skipped).
6. **APPROVAL**: on Render set `KEY_PROVIDER=gcp-kms`, `GCP_KMS_KEY_NAME`, the
   `trustpass-app` key JSON, and `STARTUP_MAINTENANCE=rewrap`. Keep `MASTER_KEY` set until
   Admin > Health shows all data keys on the KMS key, then follow `docs/security.md` to retire it.

## Known risks that stay open after the release

| Risk | Why it matters | Action |
|---|---|---|
| Free database expires 16 Dec 2026 | All data is lost when it expires | Upgrade to a paid plan or move the data before 16 Dec |
| Live KMS tests skipped | KMS code path tested with the fake KMS only | Run after the Google Cloud steps above |
| Real-phone camera test | CI uses a simulated camera | Scan a QR code on Reham's phone after deploy |
| Server-side encryption, not end-to-end | The server can decrypt while serving | See `docs/server-side-decryption.md` |

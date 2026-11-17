# TrustPass security design

This page maps the security requirements to the code that implements them and the tests that try to break them.

## Threats considered

| Threat | Control | Where | Tested in |
| --- | --- | --- | --- |
| Database leak exposes documents | AES-256-GCM per document; data keys wrapped by a master key kept outside the database; claim values and credentials encrypted with the document key | `services/documents.ts`, `lib/crypto.ts` | `documents.test.ts`, `crypto.test.ts` |
| Database leak exposes working links | Share tokens (256-bit) stored as SHA-256 hashes; an encrypted copy lets the owner copy the link again | `modules/sharing.ts` | `sharing.test.ts` |
| Ciphertext swapped between records | Additional authenticated data binds ciphertext to document and owner ids | `lib/crypto.ts` | `crypto.test.ts` |
| Stored file tampered with | GCM tag check plus SHA-256 comparison; failure logs a high-severity event and returns a generic error | `services/documents.ts` | `documents.test.ts` |
| Forged or edited certificate | Ed25519 signature over SD-JWT digests and the PDF hash; issuer registry with revocation; expiry | `lib/sd-jwt.ts`, `services/verification.ts` | `sd-jwt.test.ts`, `verification.test.ts`, e2e |
| Recipient sees more than intended | Only selected disclosures leave the server; the file is served only if explicitly included | `modules/access.ts` | `sharing.test.ts`, e2e |
| Link used after expiry or revocation | Checked on every request in one gate; first failing check wins and is logged | `modules/access.ts` | `sharing.test.ts`, e2e |
| Link forwarded to the wrong organization | Organization-only links require a signed-in member | `modules/access.ts` | `sharing.test.ts`, e2e |
| Access from unexpected countries | Server-side country check; unknown location fails closed; client headers ignored; trusted proxies configurable; behind Cloudflare the edge-set `CF-Connecting-IP` is used (Cloudflare overwrites any client value) | `modules/access.ts`, `lib/geo.ts`, `app.ts` | `geo.test.ts`, e2e |
| IDOR / broken access control | Ownership is part of every query; other users' ids return 404; admin routes require the admin role | all modules | `documents.test.ts`, `security.test.ts`, e2e |
| SQL injection | Prisma parameterised queries; raw SQL only through tagged templates | all modules | `security.test.ts` |
| XSS | React escaping, no raw HTML rendering, strict CSP (`script-src 'self'`, no inline, no eval) | `plugins/security.ts` | `security.test.ts`, e2e |
| CSRF | SameSite=Lax cookies, Origin check, per-session CSRF token header on every state change | `plugins/security.ts` | `auth.test.ts` |
| Credential stuffing / guessing | Argon2id (19 MiB, 2 passes), identical errors for unknown emails (with dummy hash timing), lockout after 5 failures, rate limits per IP+email | `modules/auth.ts` | `auth.test.ts` |
| Session theft or fixation | Random tokens stored hashed, HttpOnly, Secure and `__Host-` in production, new token at sign-in, idle (1 h) and absolute (12 h) expiry, all sessions ended on password reset | `plugins/auth.ts` | `auth.test.ts` |
| Malicious uploads | Content-based type detection, images re-encoded (strips EXIF and appended payloads), PDFs with JavaScript/launch/embedded files rejected, size and page limits, random storage names | `lib/upload-validation.ts` | `upload-validation.test.ts`, `documents.test.ts` |
| Log tampering | Database triggers reject UPDATE, DELETE and TRUNCATE on audit tables; only the retention job enables purging inside its own transaction | migration SQL, `services/retention.ts` | `analytics.test.ts` |
| Privacy of visitors | No raw IPs stored (keyed HMAC only), user agent reduced to "Browser on OS", access logs deleted after 90 days, IPs and share tokens redacted from request logs | `modules/access.ts`, `app.ts` | `geo.test.ts` |
| Secret leakage | Secrets only from environment variables, validated at startup; no key material in any response | `config.ts` | `security.test.ts` |

## Key management

```text
KMS root key (Google Cloud KMS; never leaves the KMS, every use is logged by Google)
  └─ encrypts → key-encryption keys (KEKs) and link-token keys: random 32 bytes,
       stored only as KMS ciphertext in key_encryption_keys
       └─ KEK wraps → one random data key per document (document_keys)
            └─ data key encrypts → file, field values, credential (AES-256-GCM)
```

- `KEY_PROVIDER` chooses where KEKs come from: `gcp-kms` (production target), `fake-kms` (a local stand-in with a random root key in a file; development and tests only, refused in production) or `env` (legacy: derived from `MASTER_KEY` with HKDF-SHA256).
- With a KMS, the KEKs are decrypted once at start-up and kept only in memory. KMS is not called per document. Google Cloud KMS is called over its REST API with a service account that should hold only *Cloud KMS CryptoKey Encrypter/Decrypter* on the one key; requests and responses carry CRC32C checksums and the key's purpose and version as additional authenticated data.
- **Start-up refuses** a key setup that does not match the data: a KEK the KMS cannot decrypt, a different KMS key or provider, a key version used by stored documents but not configured, or a KEK that does not open the stored document keys.
- **Key separation:** link tokens are sealed with their own key, never with the KEK.
- **Version numbers are shared** by every key purpose and the legacy `MASTER_KEY` versions, so two keys can never have the same version. Start-up checks everything it can **before writing anything** (wrong provider or KMS key, a key version in use but not configured, a version clash) and only then creates the first keys.
- **Rotation while servers are running:** a running server checks for a newer active key at most every `KEY_REFRESH_SECONDS` (default 30) before wrapping new data, and reloads its keys once when it meets a version it has not loaded. No restart is needed. `keys rotate` waits that long before re-wrapping; anything a server wrapped with the old key in the meantime stays readable (retired keys are still loaded) and is moved by the next `keys rewrap`.
- **Retired keys:** a retired key the KMS can no longer decrypt is skipped with a warning when no document uses it; start-up stops only if documents still need it. `keys destroy-retired --confirm` deletes retired keys once no document or link copy uses them and they were retired at least 10 minutes ago (re-checked under a lock); after that their KMS key versions can be disabled. To retire a Google KMS key version: `keys rotate`, `keys rewrap`, `keys destroy-retired --confirm`, then disable the version in Google Cloud.
- **Dry runs and `status` run inside a READ ONLY transaction**, so PostgreSQL itself rejects any write. A re-wrap only reports success when every data key and every link copy opens and is on the current keys.
- **The fake KMS can never write to production's database:** it only accepts a local database host (or one host named in `FAKE_KMS_ALLOW_DATABASE_HOST`), production marks its database at start-up (`system_settings.environment = "production"`), the app and every key command refuse the fake KMS on a marked database before writing, and the database itself rejects fake-KMS keys and protects the marker.
- **Commands** (none print key material). Production image: `node apps/api/dist/keys.js <status|rewrap|rotate|destroy-retired> [--dry-run]`; development: `pnpm keys:<command>`.
- **The database protects stored keys against mistakes:** rows in `key_encryption_keys` cannot be deleted, truncated or altered (only `status` can change, and only from active to retired) unless a transaction explicitly sets `trustpass.allow_key_destroy`. **Limit:** this guards against application errors, not against someone with the app's own database login, which owns the tables and can disable triggers or drop the table (the same single-role limit as the audit tables). The real protection is the KMS: without it, stored keys cannot be decrypted, and nobody can create keys the app would accept. The length check only rejects a raw 32-byte key stored by mistake, not every possible plaintext form.
- **Fail-closed start-up:** if a key that documents need is really lost, the whole app refuses to start (before E2 only those documents failed). Run the E0 read-only check before each deploy that changes keys.
- Deleting a document deletes its wrapped key, claims and ciphertext (crypto-shredding). A backup taken before the deletion still holds both and stays readable while its keys exist. Backup, restore and the restore drill are described in [recovery.md](recovery.md).

## Known limits

See the README "Honest limitations" section. In addition: rate limits are in memory per server instance, and the app uses a single database role, so the audit-table triggers protect against application bugs and misuse rather than a database administrator.

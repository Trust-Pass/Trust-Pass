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

- `MASTER_KEY` is never used directly: HKDF-SHA256 derives the key-encryption key (`kek:v<version>`). Other secrets derive their own keys with different labels.
- Rotation: set a new `MASTER_KEY` and `MASTER_KEY_VERSION`, move the old secret to `PREVIOUS_MASTER_KEYS`, then run `pnpm keys:rewrap`. Files are not re-encrypted.
- Deleting a document deletes its wrapped key, claims and ciphertext (crypto-shredding).

## Known limits

See the README "Honest limitations" section. In addition: rate limits are in memory per server instance, and the app uses a single database role, so the audit-table triggers protect against application bugs and misuse rather than a database administrator.

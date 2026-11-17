# TrustPass implementation test report

Date: 15 November 2026 · Scope: Phase 1 core platform · Environment: Linux container, Node.js 22.23, PostgreSQL 16.15, Chromium (Playwright 1.63)

Every number below comes from an actual run. Nothing here is estimated.

## Summary

| Check | Result |
| --- | --- |
| Type check (shared, API, web) | Pass, 0 errors |
| API unit tests | 36 / 36 pass |
| API integration tests (real PostgreSQL) | 72 / 72 pass |
| API security tests | 15 / 15 pass |
| End-to-end (Playwright, iPhone 13 + desktop Chrome) | 16 / 16 pass (8 scenarios × 2 viewports) |
| Production build (web + API bundle) | Pass |
| Docker image build and start on an empty database | Pass (migrations, seed, health, admin sign-in, runs as non-root user) |
| Dependency audit (`pnpm audit --prod`) | No known vulnerabilities (after upgrades, see below) |
| OWASP ZAP baseline scan (production container) | 0 failures, 61 checks passed, 1 informational warning |
| GitHub Actions CI (type check, tests, build, end-to-end, audit, gitleaks) | All 4 jobs pass on GitHub ([run 43882092323](https://github.com/Trust-Pass/Trust-Pass/actions/runs/43882092323)) |
| Secret scan of the git history (gitleaks 8.30.1) | No leaks |
| Deployment to a public URL | **Not done yet**: needs a Render account (see README) |

## Unit tests (36)

- `crypto.test.ts` (15): AES-256-GCM round trip, fresh IVs, tamper detection on ciphertext, tag, AAD and key; envelope wrap/unwrap; master-key rotation; token hashing; production config refuses simulated geo, plain http and trust-all proxies; `__Host-` secure cookie.
- `sd-jwt.test.ts` (11): signed payload holds no claim values; one-claim presentation verifies; forged claim, modified payload, wrong key, unknown key, revoked issuer, expiry, file-hash mismatch, malformed input and duplicate disclosures are all rejected.
- `upload-validation.test.ts` (10): PDF/PNG/JPEG accepted; EXIF removed; appended HTML removed from images; renamed executable, HTML, SVG, ZIP, GIF, PDF with JavaScript, truncated PDF and empty files rejected.

## Integration tests (72)

- Auth (20): registration (individual and organization), Argon2id storage, cookie flags, duplicate and invalid input, no self-promotion to admin, identical errors for unknown email and wrong password, lockout after 5 failures and unlock after 15 minutes, per-IP+email rate limit, logout, idle expiry, suspension, CSRF token and Origin checks, password reset (hash-only storage, single use, expiry, all sessions ended), password change, remote sign-out.
- Documents (11): only ciphertext on disk, wrapped key and encrypted claims in the database, byte-exact decryption for the owner, image handling, dangerous and oversized files rejected, metadata validation, stored-ciphertext tampering detected and logged as high severity, IDOR on every document route returns 404, session required, malformed ids, deletion destroys key, claims and ciphertext and revokes links.
- Sharing (13): recipient receives only the selected claim, verified; hidden claims absent from the response; self-declared claims marked unverified; foreign claim ids refused; token stored hashed and encrypted; automatic expiry logged; revocation immediate and permanent with de-duplicated alerts; custom expiry limits; owner-only link management; generic 404 for bad tokens; organization-only links (anonymous 401, other organization 403, member 200, inbox, verification records); membership changes take effect; file not served unless shared; watermarked PDF; images wrapped in a watermarked PDF.
- Geography (9): allowed countries pass; others blocked without revealing the list and logged with the country; unknown location fails closed; no rule when none set; forged `X-Forwarded-For`, `X-Real-IP`, `CF-IPCountry` and similar headers ignored; owner edits take effect at once and are logged; invalid codes rejected; no raw IP stored; behind a trusted proxy, client-prepended addresses are ignored.
- Verification (10): genuine certificate verified; one-byte change and editor re-save invalid; ordinary upload unverified; revoked issuer invalid and cannot issue; expired credential invalid; records kept; downloaded credential verifies; Latin-only certificate names and known programs; per-user credential limit.
- Analytics and logs (9): every summary number matches the recorded attempts; document and date filters; access log filters with no IP addresses; alerts never call attempts attacks; users cannot see each other's analytics, logs, activity or notifications; activity events recorded; audit rows cannot be updated, deleted or truncated; only the retention job purges old logs; notifications can be marked read.

## Security tests (15)

SQL injection payloads in login, search and filter parameters (no extra rows, no `pg_sleep` delay); stored XSS payloads returned only as JSON text; strict CSP without `unsafe-inline` or `unsafe-eval`; security headers; HSTS in production; admin routes refused to users (403) and visitors (401); organization role rules; immediate effect of suspension; mass assignment ignored; generic errors without stack traces; JSON body size limit; client request ids ignored; no master key, seeds, derived keys or wrapped data keys in any API response; issuer private key never stored.

## End-to-end tests (16)

Each scenario runs on an iPhone 13 viewport and on desktop Chrome against the production web build:

1. Share one verified field, open it on another device, revoke it, see both attempts in analytics.
2. Upload a PDF (encrypted), share it view-only, recipient sees the watermarked canvas render.
3. A UAE-only link is refused from Saudi Arabia without revealing the allowed list.
4. Organization-only link: a stranger must sign in; the organization finds it, verified, in its inbox.
5. Another user's document URL shows "not found" and its file API returns 404.
6. A script in a document title is displayed as text and never runs; CSP header present.
7. The Verification page shows Verified, Invalid and Unverified for genuine, modified and unsigned PDFs.
8. Revoking the issuer in Admin makes shared credentials verify as Invalid (trust restored afterwards).

A separate manual browser check on iPhone 13, Pixel 7 and a 1366 px desktop reported no console errors and no CSP violations, including PDF rendering.

## OWASP ZAP baseline

Run against the production Docker image (`NODE_ENV=production`) with `zap-baseline.py`: 0 failures, 61 passive checks passed, 1 informational "Modern Web Application" notice (the site is a single-page app). The crawler reached 7 URLs because pages are rendered client-side; API behaviour is covered by the security tests above. Report: [reports/zap-baseline-2026-11-15.html](reports/zap-baseline-2026-11-15.html).

## Encryption hardening E0–E1 (17 November 2026)

Branch `claude/encryption-hardening`, commit `239a969`. Plan: [`docs/encryption-plan.md`](encryption-plan.md).

| Check | Result |
| --- | --- |
| API tests on GitHub CI | 153 / 153 pass (23 new); e2e, dependency audit and gitleaks pass |
| AES-256-GCM known-answer tests (GCM spec test cases 15 and 16) | 4 / 4 pass: the wrapper is real AES-256-GCM, not only self-consistent |
| File content and field values at rest, `local` driver | Not found in any table or stored file |
| File content and field values at rest, `database` driver (production) | Not found in any table, including `stored_objects` |
| Stored objects | 12-byte IV, 16-byte tag, 32-byte wrapped key, no `%PDF-` signature, same length as the plaintext |
| One changed byte in storage (both drivers) | Detected: 500 `integrity_error`, no content returned |
| Recipient response (raw JSON) | Contains the selected field only; the unselected value is absent; file refused when not shared |
| Deletion (both drivers) | Wrapped key, fields and ciphertext removed; markers gone from every table |
| Server with a different master key | Every request fails; no marker, stack trace or key error text in any response |
| Titles, field labels, recipient names (expected failure, `it.fails`) | **Found in clear**: title in `documents`, `notifications`, `security_events`; label in `document_claims`; recipient name in `sharing_links`, `notifications`, `security_events` (to be fixed by E3/E4) |
| Older at-rest test | Could not fail: `samplePdf()` does not contain its marker as raw bytes (`false` in CI), so "marker absent from storage" was always true. The new suite checks presence first |

E0 (`docs/security/e0-readonly-check.sql`) was run against a local PostgreSQL 16 with the real schema and planted good and bad rows; it detected every planted problem.

### E0 on the live database (17 November 2026)

Run with `docs/security/e0-readonly-check-single.sql` through the Render connector's `query_render_postgres` tool (wrapped in a read-only transaction by Render) against `trustpass-db` (PostgreSQL 18, free plan, Frankfurt). Only aggregate counts were returned; no data was changed.

| Area | Result |
| --- | --- |
| Session | `transaction_read_only` = on (PASS) |
| Data | 2 active and 2 deleted documents, 2 wrapped keys, 2 stored objects, 6 field values, 1 credential, 8 links, 1 master-key version |
| Keys | Every active document has a wrapped key and a stored object; deleted documents have no key or ciphertext left; no orphans (all PASS) |
| AES-256-GCM shapes | IVs 12 bytes, tags 16 bytes, wrapped keys 32 bytes, no repeated IVs (all PASS) |
| At rest | No stored file starts like a PDF, PNG or JPEG or contains `endobj` / `%%EOF`; sizes match; 256 distinct byte values in the first 4 KB (PASS) |
| Field values, credential, link copies | All sealed, none readable as text (PASS) |
| Known gaps (E3–E5) | Titles in clear: 2 · field labels: 6 · recipient names: 8 · unkeyed SHA-256 hashes: 4 (including the 2 deleted documents) · log rows with a title: 6 · deleted documents whose title is still in logs: 2 |

Seen in the database settings (not part of the SQL check): the free database expires on 16 December 2026 (plan item D2), and its IP allow list is `0.0.0.0/0` (anyone on the internet can reach the login prompt).

## E2: key management with a KMS (17 November 2026)

Branch `claude/encryption-hardening`, commit `540aa9e`. Only the fake KMS was used: no Google Cloud account, no billing, no deploy, no production change.

| Check | Result |
| --- | --- |
| GitHub CI: type check, API tests, build | 184 / 184 API tests pass (31 new since E1); build passes |
| End-to-end (Playwright, iPhone 13 + desktop, now on the fake KMS) | 16 / 16 pass |
| Dependency audit, gitleaks | Pass (E2 adds no dependency) |
| All integration suites | Now run with `KEY_PROVIDER=fake-kms` and no `MASTER_KEY`, the same path as production with Cloud KMS |
| Fake KMS (unit) | Round trip, context binding, tamper detection, different root key refused, key file created once with mode 0600 |
| Google Cloud KMS provider (unit, mocked network) | Correct RS256 JWT, token caching and renewal, CRC32C on every request and response, retries on 429/5xx only, one re-sign-in on 401, corruption and unconfirmed checksums rejected, unsafe service-account files refused without echoing them |
| First start | Creates a random KEK and link-token key, stored only KMS-encrypted; a second instance loads the same keys; two instances starting together create exactly one |
| Refuses to start | KMS cannot decrypt the stored key; different KMS key or provider; key version in use but missing; wrong legacy `MASTER_KEY` |
| Migration from `MASTER_KEY` | Old file, field, credential and link keep working with both keys configured, after a dry run (nothing changed), after the re-wrap (file ciphertext untouched), and after `MASTER_KEY` is removed |
| Rotation | New KEK v2, v1 kept retired for reading, re-wrap moves everything to v2; a damaged row is reported, not skipped silently |
| Database guards | Stored keys cannot be deleted, truncated or altered; a plaintext-length key is rejected |
| Secrets | No KEK, link-token key, fake root key or `MASTER_KEY` in any table (as text or hex), API response or log line |

## E2 independent review fixes (17 November 2026)

Branch `claude/encryption-hardening`, commit `d90678c`. Fake KMS only; nothing deployed or merged; production untouched.

| Check | Result |
| --- | --- |
| GitHub CI: type check, API tests, build | 199 / 199 API tests pass (15 new regression tests); build passes |
| End-to-end (Playwright, iPhone 13 + desktop) | 16 / 16 pass |
| A: rotation with an old server still running | The old server serves documents, fields, "Copy link" and shared files after `keys rotate` without a restart, and new uploads and links use the new keys; an upload made before it checks stays readable and the next rewrap moves it |
| B: version clash | One numbering for all keys; a refused start writes nothing; adding `MASTER_KEY` afterwards starts cleanly |
| C: retired keys | An undecryptable retired key is skipped when unused and stops start-up only when documents need it; `destroy-retired` keeps needed or recently retired keys, needs `--confirm`, and leaves every document and link working |
| E: dry runs | `rewrap`, `rotate` and `destroy-retired` dry runs and `status` leave every table byte-identical (hash of every row), including before the first KMS key exists and when a key is wrong |
| F: fake KMS vs production | Refused for non-local database hosts (no password in the error); production marks its database; app and every command refuse before writing (database byte-identical); the database rejects fake keys and protects the marker; refused when real-KMS keys exist |
| G: production commands | `keys` is built into the image; documented as `node apps/api/dist/keys.js` |
| H: link copies | An unreadable copy fails the rewrap (exit 1) and is listed; the link itself still works |
| Secrets | No key bytes in logs through start-up, upload, sharing, rotation, reload and rewrap |

## Issues found and fixed during testing

| Found by | Problem | Fix |
| --- | --- | --- |
| Integration test | Alert de-duplication compared database time with application time, so repeated attempts could send duplicate alerts | All alert and event timestamps now come from the application clock |
| Integration test | Two views from the same country within one millisecond each triggered "first view from this country" | The check now excludes the current log row by id instead of by time |
| Integration test | Rate limits keyed only by IP would lock out a whole classroom sharing one Wi-Fi | Signed-in requests are limited per user; sign-in is limited per IP + email |
| Browser test | Anonymous visitors produced a 401 console error on every page | New `/api/auth/session` endpoint answers 200 for visitors |
| Browser test | Watermark text was cut off at page edges | Stamps are sized and spaced to fit the page |
| GitHub CI | Three accesses with the same timestamp made "last access" arbitrary | Time-ordered queries break ties by insertion order |
| GitHub CI | The gitleaks GitHub Action requires a paid licence for organizations | CI runs the open-source gitleaks CLI instead |
| Screenshot review | Long titles made pages wider than phone screens | Grid columns use minmax(0, 1fr); every page measured at 390 px and 360 px |
| Live deployment check | On Render, the visitor's country resolved as unknown: TRUST_PROXY=1 picked an internal proxy's private address, so country-restricted links refused everyone (fail closed) | TRUST_PROXY accepts trusted private ranges; the visitor is the right-most public address. Added connection diagnostics in Admin > Health and Settings |
| Live deployment check | After the first fix, visitors resolved to Germany: onrender.com sits behind Cloudflare, so the right-most public hop is the Cloudflare server near Render's Frankfurt region | `CLIENT_IP_HEADER=cf-connecting-ip` takes the visitor address set by Cloudflare; per-IP rate limits use it too |
| Browser test | 1.3 MB main JavaScript bundle on phones | pdf.js and charts load on demand; main bundle 145 KB gzipped |
| Production boot | Empty environment variables (common in hosting dashboards) failed validation | Empty values are treated as unset |
| Dependency audit | 23 known vulnerabilities, including a pdf.js script-execution flaw (high), nodemailer SMTP injection and zod memory exhaustion | Upgraded pdf.js 6.5, nodemailer 10.6, zod 4.6; forced patched deepmerge-ts in the Prisma CLI. Audit now clean and all tests re-run |

Earlier test failures caused by the tests themselves (ambiguous selectors, a session expiring after a simulated one-hour jump) were corrected in the tests; they are not listed as product fixes.

## Not yet tested

- The live deployment and production geolocation behind Render's proxy (pending a Render account).
- Real email delivery (no SMTP provider configured).
- Load and performance testing.
- Real VPN traffic (VPN and proxy scenarios are simulated with forged headers and a trusted-proxy configuration).

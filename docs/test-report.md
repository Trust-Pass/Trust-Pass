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

## Issues found and fixed during testing

| Found by | Problem | Fix |
| --- | --- | --- |
| Integration test | Alert de-duplication compared database time with application time, so repeated attempts could send duplicate alerts | All alert and event timestamps now come from the application clock |
| Integration test | Two views from the same country within one millisecond each triggered "first view from this country" | The check now excludes the current log row by id instead of by time |
| Integration test | Rate limits keyed only by IP would lock out a whole classroom sharing one Wi-Fi | Signed-in requests are limited per user; sign-in is limited per IP + email |
| Browser test | Anonymous visitors produced a 401 console error on every page | New `/api/auth/session` endpoint answers 200 for visitors |
| Browser test | Watermark text was cut off at page edges | Stamps are sized and spaced to fit the page |
| Browser test | 1.3 MB main JavaScript bundle on phones | pdf.js and charts load on demand; main bundle 145 KB gzipped |
| Production boot | Empty environment variables (common in hosting dashboards) failed validation | Empty values are treated as unset |
| Dependency audit | 23 known vulnerabilities, including a pdf.js script-execution flaw (high), nodemailer SMTP injection and zod memory exhaustion | Upgraded pdf.js 6.5, nodemailer 10.6, zod 4.6; forced patched deepmerge-ts in the Prisma CLI. Audit now clean and all tests re-run |

Earlier test failures caused by the tests themselves (ambiguous selectors, a session expiring after a simulated one-hour jump) were corrected in the tests; they are not listed as product fixes.

## Not yet tested

- The live deployment and production geolocation behind Render's proxy (pending a Render account).
- Real email delivery (no SMTP provider configured).
- Load and performance testing.
- Real VPN traffic (VPN and proxy scenarios are simulated with forged headers and a trusted-proxy configuration).

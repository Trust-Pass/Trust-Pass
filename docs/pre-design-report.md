# Pre-design milestone report (19 Nov 2026)

Branch `claude/release` (draft PR #7, not merged). Production untouched: `main` @ `f95599b`, no
deploy, no production data, keys or settings changed (except the database network rule Reham
closed herself on 19 Nov). PR #5 and #6 stay open.

## Verdict

**Ready for the UI redesign.** Every pre-design security, recovery, QR and quality item that can be
done in code is done and tested. What remains needs Reham's account, money or approval (list below).

## Completed and verified

| Area | What was done | Evidence |
|---|---|---|
| Upload encryption (E1) | Per-document AES-256-GCM key, AAD bound to document + owner, wrapped key, sealed SHA-256 | API tests; rehearsal on the real backup |
| Key management (E2) | Keyring, rotation, rewrap, retired keys, start-up refusal on wrong keys, production guard; Google Cloud KMS provider | API tests; **KMS live scenarios run on every CI run against a strict Google API emulator** (signed service-account sign-in, scope, permissions, CRC32C, AAD); provider now also refuses an answer naming another key |
| Metadata (E3–E5) | Titles, field labels, recipient names, file hashes encrypted; logs/notifications ids only; inventory of what stays in clear and why (`docs/security.md`) | API tests; rehearsal: 5 titles, 7 labels, 8 recipients, 17 log rows, 6 notifications converted, 0 left |
| Backfill safety | Read-back check before clearing any plain value; failing documents untouched and reported; now also removes member emails from old log rows | 6 failure-case tests + 1 email test; rehearsal |
| Sharing + recipient download | Per-link rules; download off by default, full gate before every download, separate watermarked PDF, original never written | 13 API + 4 browser tests; rehearsal recipient probe in CI |
| Security review | Auth, sessions, CSRF, authorization of every route, org roles, admin, headers, rate limits reviewed. **Fixed:** reset links now single-use under races and cancelled by a password change or another reset; member emails no longer logged; malformed session ids answer 404. One suspected escalation was a false positive (schema already blocks it); a second guard was added anyway | `test/security/hardening.test.ts` (7) |
| Backup and recovery | Encrypted backup, restore drill, recovery check with saved keys, **release rehearsal on the real backup: PASSED**; procedures in `docs/recovery.md` and `scripts/rehearsal/README.md` | Reports in `C:\TrustPass-Backups\*-reports`; CI job `release-rehearsal` runs the script end to end every push |
| QR Security Scanner | Camera-first scanner, offline analysis, never auto-opens. **Fixed:** a real brand address in front of another site (e.g. `alrajhibank.com.sa.secure-login.example`) was only "caution" and openable, now "dangerous"; double encoding now "caution" | 66 unit tests (+20 new phishing-trick cases), 8 API tests, 9 browser scenarios |
| Dependencies | vitest 4.1.12, tsup 9 | Full audit, dev tools included: **no known vulnerabilities** (was 2 critical, 3 moderate, 1 low, all dev-only) |
| Migrations | 4 additive migrations; rollback window documented | Rehearsal: existing data identical; CI proves the test fixture equals production's schema |

## Test results (CI on `claude/release`, last commit)

| Suite | Result |
|---|---|
| API (unit, integration, security) | **340 passed**, 5 skipped (4 = real Google Cloud KMS, no credentials yet; 1 = fixture builder used by the rehearsal job) |
| Browser (Playwright, phone + desktop) | **40 / 40** |
| Release rehearsal end to end (Windows-style checkout, no network) | **PASSED** |
| Secrets scan (full history) | passed (one reviewed test-password false positive recorded in `.gitleaksignore`) |
| Dependency audit | production and development: no known vulnerabilities |

## Remaining blockers (need Reham)

| # | Item | Why it needs you | Cost |
|---|---|---|---|
| 1 | Google Cloud project + billing, run `scripts/gcp/setup-kms.sh` in Cloud Shell, add 2 GitHub secrets | Your Google account and payment card | ≈ $0.12/month |
| 2 | Run the release rehearsal once more (one command) before the release | The code changed after the 19 Nov run (recipient probe, review fixes); needs your backup and keys | $0 |
| 3 | Approve the release: merge PR #7, then `STARTUP_MAINTENANCE=encrypt-metadata`, then remove it | Production change | $0 |
| 4 | Decide on the database before **16 Dec 2026** (upgrade to Basic-256mb for automatic backups, or keep manual backups and move data) | Payment / production | $6/month if upgraded |
| 5 | After deploy: scan a real QR code with your phone | Real camera | $0 |
| 6 | Later, after #1: switch production to `KEY_PROVIDER=gcp-kms` + `STARTUP_MAINTENANCE=rewrap` | Production keys | included in #1 |

## Known, accepted limits

- Server-side decryption, not end-to-end (`docs/server-side-decryption.md`).
- Downloaded copies cannot be recalled; non-Latin recipient names print as "the recipient of link …" on copies.
- Registration says when an email is already used; five wrong passwords lock an account for 15 minutes (anyone who knows the email can trigger that). Common trade-offs, kept.
- Rate limits are per server instance (one instance on Render free).

## Next

UI/UX redesign, after Reham's approval, on a branch from `claude/release`.

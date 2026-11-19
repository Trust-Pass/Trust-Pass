# Security checklist and release steps (19 Nov 2026)

Release branch: `claude/release` (includes PR #5 UI, PR #6 QR Shield, E1–E5, backups, recipient
download). Production: `main` @ `f95599b`, auto-deployed by Render. **Nothing here runs without
Reham's explicit approval at each APPROVAL step.**

## 1. Security checklist

✅ = done and verified · ⏳ = built, waiting on a step · ⬜ = not done

### Code (on `claude/release`, CI green: API 294 passed + 4 skipped, e2e 40/40, secrets scan, audit)
- ✅ Upload encryption: per-document AES-256-GCM key, AAD bound to document + owner, wrapped key, random storage name
- ✅ Upload validation: PDF/PNG/JPEG by content; images re-encoded; PDFs with scripts, embedded files or form actions refused
- ✅ Titles, field labels, recipient names, file hashes encrypted (E3/E5); logs and notifications hold ids only (E4)
- ✅ Key management: keyring, rotation, rewrap, retired keys, start-up refusal on wrong/missing keys
- ✅ Sharing: per-link fields, person or organization, expiry, countries (fail closed), revoke, token stored as hash
- ✅ Recipient view: only permitted fields decrypted; watermarked view-only PDF
- ✅ Recipient download: off by default, full gate before every download, separate PDF per download, copy reference logged, original never written
- ✅ Integrity: GCM + sealed SHA-256; tampered files refused, owner and admins alerted
- ✅ Web hardening: CSRF, rate limits, no-store on all API answers, sandbox CSP on files
- ✅ QR Shield: offline analysis, dangerous links never auto-opened
- ✅ Start-up maintenance for a host without a shell (`STARTUP_MAINTENANCE`)
- ✅ Backfill read-back: no plain value is cleared unless its encrypted copy opens to the same value;
  a failing document is left untouched and reported
- ✅ Release rehearsal script + CI end-to-end test on a backup in production's current schema
- ⏳ Release rehearsal on the real production backup (Reham, on the laptop)

### Operations
- ✅ Production secrets saved in the password manager
- ✅ Encrypted backup + restore drill + recovery check with saved keys (3/3 keys, 3/3 files, 7/7 fields, 1/1 credential)
- ✅ Database network access closed (19 Nov): PostgreSQL inbound rules empty; app uses the internal host
- ⏳ Real Google Cloud KMS: code and live tests ready; needs Google Cloud project + billing
- ⬜ Release deployed to production (blocker A)
- ⬜ Old metadata encrypted in production (blocker B)
- ⬜ Automatic backups (paid plan) — not needed for the demo; manual encrypted backup before the demo instead

## 2. Remaining blockers

| | Blocker | Needed for demo? | Cost |
|---|---|---|---|
| A | Deploy `claude/release` (live site still runs old code) | **Yes** | $0 |
| B | Encrypt old titles/labels in production (6 documents in clear) | **Yes** | $0 |
| C | Database expires 16 Dec 2026 | Only if demo/use after 16 Dec | $6/month, or move to a new free database |
| D | Master key in Render settings instead of Cloud KMS | No (state as limitation + next step) | ≈ $0.12/month + billing account |
| E | Automatic backups | No | $6/month (same upgrade as C) |
| F | Real-phone camera test of QR Shield | Recommended | $0 |

Accepted limits (documented, not blockers): server-side decryption (`docs/server-side-decryption.md`);
non-Latin recipient names print as "the recipient of link <ref>" on downloaded copies; a downloaded
copy cannot be recalled.

## 3. Exact steps before and during the release

### Pre-flight (no production change)
0. **Release rehearsal PASSED on a copy of the latest production backup** (`scripts/rehearsal/README.md`;
   on the laptop, no network, RAM only). Required before asking for any production approval.
1. CI green on the `claude/release` head (all five jobs, including `release-rehearsal`). Re-check right
   before the merge.
2. Fresh encrypted backup the same day:
   a. Render > trustpass-db > Info > PostgreSQL Inbound IP Rules > Add source: `<your IP>/32` > **Save**
   b. Run the usual backup command on the laptop (normal run, not a new drill)
   c. Remove the rule > **Save**; Claude confirms `ipAllowList: []`
3. No environment variables change: the release keeps `KEY_PROVIDER=env` and the existing `MASTER_KEY`.
4. Pick a quiet time; nobody should upload during steps 1–4 of the rollout.

### Rollout
1. **APPROVAL** — Merge `claude/release` into `main` (one PR). Render deploys automatically. On start it
   applies four schema-only migrations (add tables/columns, make columns nullable, add an enum value);
   no data is removed.
2. Watch the deploy until live. `/api/health` must return `{"status":"ok"}`.
3. Admin > Health: "Encryption keys" OK; "Metadata encryption" shows old titles still in clear (expected).
4. Smoke test (≈2 min): open an existing document and its file; open an existing share link in a private
   window; create one link with download allowed and download the copy; run one QR check.
5. **APPROVAL** — Render > trustpass > Environment: add `STARTUP_MAINTENANCE=encrypt-metadata`. The
   service restarts and seals old titles, labels, recipients and hashes.
6. Admin > Health: "Metadata encryption" OK and "Last start-up maintenance: encrypt-metadata OK".
   Repeat the smoke test.
7. **APPROVAL** — Remove `STARTUP_MAINTENANCE` (running it again is harmless, but it should not stay set).

### Rollback
- **Clean only before any new upload or link after step 1.** The old code needs a plain title on every
  document; documents and links created by the new code have encrypted titles only, and the old code
  fails to read them. So: if step 2–4 fails, redeploy `f95599b` in Render **immediately**, before anyone
  uses the site.
- After new uploads or after step 5: do not roll back the code; fix forward on a branch. If data is
  damaged, restore the pre-flight backup (`docs/recovery.md`; needs the same `MASTER_KEY`).

### After the release (separate approvals)
- C/E: upgrade the database to Basic-256mb ($6/month) before 16 Dec if it must stay online.
- D: Google Cloud KMS (`docs/deploy-runbook.md`, "Later: Google Cloud KMS"): setup script, GitHub secrets,
  live tests with 0 skipped, then `KEY_PROVIDER=gcp-kms` + `STARTUP_MAINTENANCE=rewrap`, keep `MASTER_KEY`
  until Admin > Health shows every data key on the KMS key.
- F: scan a real QR code with a phone on the live site.

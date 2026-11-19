# Release rehearsal (on a copy of the production backup)

Runs exactly what the release will do to production (the four database migrations, the start-up
key checks and the metadata backfill) on a throw-away restore of an existing encrypted backup,
then checks every document, field, credential, share link and recipient download.

Nothing in production is read or changed. The container has **no network**, the backup folder is
**read-only**, and the restored copy lives **only in RAM**. Secrets are typed at hidden prompts.

CI runs this same script on every commit, on a backup of a database built in production's current
format (job `release-rehearsal`).

## Steps on Windows (PowerShell, Docker Desktop running)

1. **Get the release code** (once; afterwards `git pull` in that folder):

   ```powershell
   cd C:\
   git clone --branch claude/release https://github.com/Trust-Pass/Trust-Pass.git TrustPass-release
   cd C:\TrustPass-release
   git log -1 --oneline
   ```

2. **Build the rehearsal image** from that folder (about 3–5 minutes the first time; needs internet
   for the build only):

   ```powershell
   docker build -f scripts/rehearsal/Dockerfile --build-arg RELEASE=$(git rev-parse --short HEAD) -t trustpass-rehearsal:release .
   ```

3. **Run it on your backup folder** (the same folder as the recovery check):

   ```powershell
   cd C:\TrustPass-Backups
   mkdir rehearsal-reports -Force
   docker run --rm -it --network none --tmpfs /work:rw,size=1g,mode=0711 `
     -v "${PWD}:/backup:ro" -v "${PWD}\rehearsal-reports:/out" `
     trustpass-rehearsal:release
   ```

   Without a file name it uses the newest backup that has its `.sha256` and `-report.txt`. To pick
   one, add its name at the end, e.g. `trustpass-2026-11-19.7z`.

4. **Answer the four hidden prompts** from your password manager: backup passphrase, then
   `MASTER_KEY`, `IP_HASH_SECRET`, `ISSUER_SIGNING_SEED`.

5. **Read the result.** The last lines say `REHEARSAL PASSED` or `REHEARSAL FAILED`. The report is
   saved in `C:\TrustPass-Backups\rehearsal-reports\` (counts and yes/no answers only).

## What the report proves

| Line | Meaning |
|---|---|
| `Existing data identical after the migrations: yes` | Every existing table, row and value has the same fingerprint before and after the 4 migrations |
| `startupChecks: passed` | The release accepts your `MASTER_KEY` and it opens the stored document keys |
| `before` / `after` counts equal, `unchangedDocuments` = active documents, `changedDocuments: []` | Every file (with its SHA-256), field, label, credential and recipient name reads the same after the backfill, also in a freshly started server |
| `dryRun.readBackFailures: 0`, `backfill.ok: true`, `plainMetadataAfter` all 0, `secondRunChanges: 0` | The backfill passes its read-back checks, leaves nothing in clear, and is safe to run twice |
| `links.failures: []`, `endedRefused`, `expiredRefusedToday`, `viewsOk`, `filesOk`, `downloadsOk` | Every link copy opens; revoked/expired links stay refused; every link opens with the right title and fields; shared files and a watermarked download work |
| `downloadsOffByDefault: true` | No existing link gets downloads after the release |
| `ciphertextUnchanged: true` | No stored file or document key was changed |

If it fails, nothing happened to production; send me the report (it contains no secrets).

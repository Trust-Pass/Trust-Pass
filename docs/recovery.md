# TrustPass backup and recovery

Last reviewed: 17 November 2026 · Applies to branch `claude/encryption-hardening` (E2 key management)

This runbook says what to back up, how to take a safe backup, how to restore it, and how to prove that restored documents still decrypt. Every command here is read-only on production unless a step says otherwise.

---

## 1. Where things stand today

| Fact | Consequence |
| --- | --- |
| Production uses Render's **free** PostgreSQL (version 18, Frankfurt). Render makes **no automatic backups and offers no point-in-time recovery** on the free plan. | Nothing is backed up unless someone does it by hand. |
| Render's dashboard export (**Recovery** > **Create export**) is **not available on the free plan**; on paid plans it is kept 7 days. | Back up with `scripts/backup/trustpass-backup-drill.sh` (section 3, option A). |
| The free database **expires on 16 December 2026**. | Take a backup, and practise a restore, before that date. |
| `STORAGE_DRIVER=database`: encrypted files live in the database (`stored_objects`). | One database dump contains every encrypted file. |
| Keys come from `MASTER_KEY` today (`KEY_PROVIDER=env`); a KMS is planned. | The dump alone is not enough to read documents, and must never be stored with the keys. |
| Before this change no backup had been taken and no restore had ever been tested. | — |

---

## 2. What must be backed up

A document can only be read again when **all** of the parts it depends on come back together. The secrets are **never** in the database dump, by design.

| Part | Where it lives | In the database dump? | How to keep it |
| --- | --- | --- | --- |
| Encrypted files | `stored_objects` (database driver) | ✅ | Database dump |
| Encrypted files | `STORAGE_DIR` on disk (local driver only) | ❌ | Copy the directory at the same time as the dump |
| Per-document wrapped keys | `document_keys` | ✅ | Database dump |
| KMS-protected key-encryption keys, link-token keys, key versions and status | `key_encryption_keys` | ✅ | Database dump |
| Fields, credentials, share links, users, sessions, logs | their tables | ✅ | Database dump |
| Schema version | `_prisma_migrations` | ✅ | Database dump |
| `MASTER_KEY`, `MASTER_KEY_VERSION`, `PREVIOUS_MASTER_KEYS` (legacy keys) | Render environment | ❌ | Password manager. Without them, every document on a legacy key is lost |
| KMS key (after the KMS switch) | Google Cloud KMS | ❌ | Cannot be exported. **Never destroy or disable a KMS key version while a backup you keep still needs it** |
| KMS access (service account key) | Render environment | ❌ | Can be re-created in Google Cloud; keep the key name in the password manager |
| `ISSUER_SIGNING_SEED` | Render environment | ❌ | Password manager. A different seed makes issued credentials verify as invalid |
| `IP_HASH_SECRET` | Render environment | ❌ | Password manager. A different one breaks the visitor hashes in the access log |
| Settings: `KEY_PROVIDER`, `STORAGE_DRIVER`, `GCP_KMS_KEY_NAME`, `APP_URL` | Render environment | ❌ | A note in the password manager (not secret) |
| Backup manifest | made by `backup manifest` | — | Next to the encrypted dump. It holds no secret |

**The backup manifest** (`node apps/api/dist/backup.js manifest --out manifest.json`) records, without any secret or document content:
- the schema version and the row counts;
- which key versions the data uses, and whether each is a legacy key or KMS-protected;
- the stored key rows (purpose, version, status, KMS key name; never the encrypted key);
- one SHA-256 fingerprint per encrypted file (of the ciphertext, never the plaintext);
- 16-character **key check values** for each legacy key, `ISSUER_SIGNING_SEED` and `IP_HASH_SECRET`. A check value tells a restore whether it was given the right secret, but cannot be turned back into the secret.

---

## 3. Taking a backup

You do not need PostgreSQL installed.

> **Render's "Create export" does not work on the free plan.** Render's documentation says exports are not available on the Free instance type (checked 17 Nov 2026). Use option A below; option C is only for a paid database.

### Option A (recommended): one-command encrypted backup and restore drill
`scripts/backup/trustpass-backup-drill.sh` does the whole job inside one temporary container, and **the unencrypted dump never touches the disk** (it only exists in a RAM disk that disappears with the container):

1. read-only `pg_dump` over TLS **verify-full** (certificate and host name checked), session forced to `default_transaction_read_only=on`;
2. 7-Zip AES-256 encryption with encrypted file names; it refuses to save the archive if a wrong passphrase can still list it;
3. saves only `trustpass-<time>.7z`, its `.sha256` and a report;
4. decrypts the saved archive back into RAM and checks it is byte-identical;
5. restores it into a throw-away PostgreSQL in RAM (no network, local socket only) with `--exit-on-error` and compares row counts.

At the host prompt, press Enter to use trustpass-db's external host (`dpg-dbthlre7bikc73cmpuvg-a.frankfurt-postgres.render.com`), or paste another **external** Render host (`dpg-<id>-a.<region>-postgres.render.com`). The internal host (`dpg-<id>-a`, no domain) only works inside Render and is refused, as is anything that is not a bare host name, so a pasted connection string (with its password) is never sent anywhere. Passwords are only typed at hidden prompts: the database password once (pg_dump's prompt), then the backup passphrase twice (the script compares them), then once more pasted **from the password manager** (proves the saved copy is right before anything is written to disk). 7-Zip itself never prompts: on Linux its prompt shows the passphrase on screen, and for extraction a bare `-p` means an *empty* password (the cause of the first failed run on 18 Nov 2026). The passphrase must be at least 16 characters of English letters, digits and symbols, so it opens identically in 7-Zip on Windows.

One-time setup (local, does not touch Render), from the repository root:
```powershell
Get-Content scripts/backup/Dockerfile -Raw | docker build --no-cache -t trustpass-pgtools:18 -
```
Each backup, from the folder that keeps backups (for example `C:\TrustPass-Backups`, outside OneDrive and outside this repository), with the script copied into it:
```powershell
docker run --rm -it --tmpfs /work:rw,size=512m,mode=0711 -v "${PWD}:/backup" trustpass-pgtools:18 bash /backup/trustpass-backup-drill.sh
```
It must end with `RESTORE DRILL OK`. Then do section 4 steps 2–3 and 5 (passphrase in the password manager, copy the `.7z` off this computer). This drill checks structure and data; the full decryption check (`backup verify`, section 5 step 6) additionally needs the secrets and the branch's migrations, and is done separately.

### Document recovery check on an existing backup (no new backup)
`scripts/backup/trustpass-recovery-check.sh` proves that an existing `.7z` plus the secrets in the password manager recover every document. It runs with **no network**, the backup folder **read-only**, everything decrypted **in RAM**; it decrypts the backup, restores it into a temporary PostgreSQL in RAM, then with the saved `MASTER_KEY` decrypts every document key, file (SHA-256 and file type checked), field, credential and share-link copy, and checks `ISSUER_SIGNING_SEED` against the stored issuer key (`verify-secrets.mjs`). The only output is a report in `recovery-reports/` with counts and yes/no answers. Copy both scripts next to the backups, then from that folder:
```powershell
docker run --rm -it --network none --tmpfs /work:rw,size=512m,mode=0711 -v "${PWD}:/backup:ro" -v "${PWD}/recovery-reports:/out" trustpass-pgtools:18 bash /backup/trustpass-recovery-check.sh
```
It must end with `RECOVERY OK`. `MASTER_KEY WRONG` means the saved key is not production's; `BACKUP DAMAGED` means the key is right but a stored file is altered or missing.

### Option B: plain `pg_dump` through Docker
Use the same major version as the server (18). Only when option A is not possible: this writes an **unencrypted** file, so encrypt it straight away (section 4) and delete the plain file.
```bash
docker run --rm -it -e PGSSLMODE=verify-full -e PGSSLROOTCERT=system -v "$PWD:/backup" trustpass-pgtools:18 \
  pg_dump --host <external host> --username trustpass --dbname <database> --password --format=custom --file /backup/trustpass-YYYY-MM-DD.dump
```
The host, user and database name are on the database's **Info** page in Render. Type the password at the prompt; never put it in the command, an environment variable, chats, tickets or scripts. `PGSSLMODE=require` is **not** a safe fallback: it encrypts but does not check that the server is Render, so someone in between could capture the password.

### Option C: Render dashboard export (paid plans only)
1. **Manifest first** (optional): `node apps/api/dist/backup.js manifest --out manifest-YYYY-MM-DD.json` with production's settings (Render Shell on paid plans, or a computer with the repository and the production environment).
2. Render dashboard > **trustpass-db** > **Recovery** > **Create export**, then **Download** it (`.dir.tar.gz`). Render keeps it 7 days.
3. Go straight to section 4 (encrypt) and delete the unencrypted download afterwards.

### Never in a backup
Do not copy `.env` files, the Render environment or the password manager into the backup folder. Keep the dump and the secrets in **different places**.

---

## 4. Encrypting and storing the backup

The dump must always be encrypted. It contains account emails, password hashes (Argon2id), document titles, field names and recipient names, which are still stored in plain text (encryption plan E3–E5). Under today's `env` provider it also contains every wrapped key, so `MASTER_KEY` is the only missing piece.

1. Encrypt with a long passphrase, using either:
   - `age -p -o trustpass-YYYY-MM-DD.dump.age trustpass-YYYY-MM-DD.dump` ([age](https://age-encryption.org), audited, tiny), or
   - 7-Zip: format 7z, encryption **AES-256**, tick **Encrypt file names**.
2. Store the passphrase in the password manager, in a different entry from `MASTER_KEY`.
3. Store the encrypted file off Render (for example your own cloud drive), together with its manifest.
4. Delete the unencrypted dump.
5. Keep a few: for example the last 4 weekly and 3 monthly backups. Delete older ones (see section 8 for why this also matters for deleted documents).

---

## 5. Restoring

Restore into a **new, empty database**, prove it works, and only then point the app at it.

1. **Create** a new PostgreSQL database with the same or a newer major version (18).
2. **Decrypt** the backup on your computer.
3. **Load it** (the password goes in an environment variable, as in section 3):
   ```bash
   # custom-format dump (option B):
   docker run --rm -e PGPASSWORD -v "$PWD:/backup" postgres:18 \
     pg_restore --no-owner --no-privileges --exit-on-error --host <new host> --username <user> --dbname <new database> /backup/trustpass-YYYY-MM-DD.dump
   # Render export (option A): extract the .dir.tar.gz first, then pass the extracted directory with --format=directory
   ```
   The database protections (append-only logs, protected keys, production marker) are triggers. pg_restore creates them after loading the data, so they never block a restore.
4. **Local file storage only:** copy the backed-up `STORAGE_DIR` back.
5. **Configure** the app for the new database with the **same** secrets as at backup time: `MASTER_KEY` (and `PREVIOUS_MASTER_KEYS`), `KEY_PROVIDER` and KMS access, `ISSUER_SIGNING_SEED`, `IP_HASH_SECRET`, `STORAGE_DRIVER`.
6. **Run the restore check before switching traffic**, with `DATABASE_URL` set to the new database:
   ```bash
   node apps/api/dist/backup.js verify --manifest manifest-YYYY-MM-DD.json
   ```
   It runs read-only and must end with `RESTORE OK`. It:
   - first compares every configured secret with the manifest's check values, and names any that is missing or different (`SECRET MISMATCH: ...`) without printing it;
   - then decrypts every file (AES-GCM tag and SHA-256), every field value and disclosure, every credential and every share-link copy;
   - compares every encrypted file with the manifest, and lists missing or changed documents by id.
7. **Switch:** set the web service's `DATABASE_URL` to the new database and redeploy. Start-up checks the keys again and refuses to start if anything does not match.
8. **Smoke test:** sign in, open a document, open a share link, look at Admin > Health. Then run the E0 read-only check (`docs/security/e0-readonly-check-single.sql`).

If anything fails, the old database is untouched: keep using it, fix the cause, try again.

---

## 6. Restore drill (practice)

A backup only counts once a restore from it has worked. Practise:
- before the free database expires (before 16 December 2026);
- before and after any key change (switching to the KMS, `keys rotate`, `keys destroy-retired`);
- once a month.

Quick drill: option A in section 3 restores every backup it takes and must end with `RESTORE DRILL OK`. Full drill: restore the latest backup into a temporary database (steps 1–6 of section 5), check for `RESTORE OK`, write the result into `docs/test-report.md`, then delete the temporary database.

---

## 7. What cannot be recovered

These are deliberate consequences of the encryption design.
- **A lost `MASTER_KEY`** (or a lost entry from `PREVIOUS_MASTER_KEYS`): every document on that legacy key version is unreadable, in every backup.
- **A destroyed KMS key version**: every backup whose KEKs it protects becomes unreadable. Before running `keys destroy-retired` or disabling a KMS key version, check the manifests of the backups you keep (`keys.storedKeys`, `keys.kekVersionsInUse`).
- **Data created after the last backup** is not in it.

---

## 8. Deleted documents and backups

Deleting a document removes its wrapped key and its encrypted file from the database (crypto-shredding). A backup taken **before** the deletion still holds both. Restoring that backup brings the document back, as long as its keys are still configured. An automated test shows this happening.

A deleted document becomes truly unrecoverable once both of these are true:
- every backup older than the deletion has been deleted (section 4, step 5); or
- the key version that protects it is destroyed (with a KMS).

Tell users this honestly: "Deleted documents are removed at once, and disappear from backups within N weeks."

---

## 9. Restoring a production backup on another machine

A production database is marked as production's (`system_settings.environment`). A restored copy keeps that mark, so the development fake KMS refuses to work with it. That is intended: production data must never get fake-KMS keys. Restore drills of production backups use the real keys, `KEY_PROVIDER=env` with `MASTER_KEY` today, or the real KMS later.

---

## 10. How this is tested

Automated tests run on every push (`apps/api/test/integration/backup-restore.test.ts`, `apps/api/test/unit/backup.test.ts`). They:
- write data under a legacy key **and** a KMS-protected key;
- create the manifest, `pg_dump` the database, and `pg_restore` it into a brand-new database;
- check that the restore drill passes and writes nothing (every row of every table hashed before and after);
- check that the app on the restored database serves every file byte for byte, with its fields, issuer-verified credential and share links;
- check that the backup holds the state at backup time (deleted-before stays gone, created-after is absent, deleted-after comes back);
- check that the manifest contains no secret and no document content;
- check that a wrong or missing `MASTER_KEY`, a wrong `ISSUER_SIGNING_SEED` or a different KMS key is refused, with the secret named and never printed;
- check that a damaged or missing encrypted file is reported by document id.

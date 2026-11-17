# TrustPass backup and recovery

Last reviewed: 17 November 2026 · Applies to branch `claude/encryption-hardening` (E2 key management)

This runbook says what to back up, how to take a safe backup, how to restore it, and how to prove that restored documents still decrypt. Every command here is read-only on production unless a step says otherwise.

---

## 1. Where things stand today

| Fact | Consequence |
| --- | --- |
| Production uses Render's **free** PostgreSQL (version 18, Frankfurt). Render makes **no automatic backups and offers no point-in-time recovery** on the free plan. | Nothing is backed up unless someone does it by hand. |
| A manual export (database > **Recovery** > **Create export**) is kept by Render for **7 days**. | A backup only lasts if it is downloaded and stored elsewhere. |
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

You do not need PostgreSQL installed. Use one of the two options.

### Option A: Render dashboard (simplest)
1. **Manifest first** (optional but recommended): run `node apps/api/dist/backup.js manifest --out manifest-YYYY-MM-DD.json` with production's settings. This needs a place where the app runs: Render Shell (paid plans), or a computer with the repository and the production environment. Skip it if neither is available; the restore check still works without it, it just cannot compare file by file.
2. Render dashboard > **trustpass-db** > **Recovery** > **Create export**. Wait until it is ready, then **Download** it (`.dir.tar.gz`).
3. Go straight to section 4 (encrypt) and delete the unencrypted download afterwards.

### Option B: `pg_dump` through Docker (no PostgreSQL installation)
Use the same major version as the server (18):
```bash
read -s PGPASSWORD && export PGPASSWORD      # paste the database password; it is not shown or saved in history
docker run --rm -e PGPASSWORD -v "$PWD:/backup" postgres:18 \
  pg_dump --format=custom --host <external host> --username trustpass --dbname <database> --file /backup/trustpass-YYYY-MM-DD.dump
unset PGPASSWORD
```
The host, user and database name are on the database's **Info** page in Render. Never paste the full connection string into chats, tickets or scripts.

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

Restore the latest backup into a temporary database (steps 1–6 of section 5), check for `RESTORE OK`, write the result into `docs/test-report.md`, then delete the temporary database.

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

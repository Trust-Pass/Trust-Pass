# TrustPass: encryption audit and implementation plan

Audit date: 17 November 2026 · Repository: `Trust-Pass/Trust-Pass`, branch `main` at `f95599b` · Method: read-only code review (no code changed, nothing deployed). PR #5 (navigation) is untouched and stays unmerged.

Item IDs here start with **E** so they don't clash with the main plan (B, S, F, D). All E items go on their own branch, `claude/encryption-hardening`, never on the navigation branch.

---

## 1. Short answer

| Question | Answer |
| --- | --- |
| Are files really encrypted at rest? | **Yes.** Every uploaded file is encrypted with **AES-256-GCM** using its own random 256-bit key before it is stored. Only ciphertext reaches storage. This is real cryptography (`node:crypto`), not a label. |
| Are the typed fields encrypted? | **Yes, the values are.** Each field value, each SD-JWT disclosure and each issued credential is sealed with the same per-document key. **Field names (labels) are not.** |
| Key management | **Envelope encryption.** Per-document data key (DEK) → wrapped with AES-256-GCM by a key-encryption key (KEK) → KEK derived with HKDF-SHA256 from the `MASTER_KEY` environment variable. Key versions and a re-wrap script exist. |
| Who can decrypt? | Only the server, on behalf of (a) the owner with a valid session or (b) a recipient who passes the share gate (not revoked, not expired, right organization, allowed country). Admins have no route that decrypts documents. |
| Can users choose what to encrypt? | **No, and they shouldn't.** Everything is always encrypted. Users choose what to **disclose** (which fields, and whether the file is included). That's the right model; section 5 explains why. |
| Is it production-grade? | **The core is sound; the surroundings aren't yet.** Metadata leaks, the master key lives next to the app, production stores keys and files in the same database, some public claims are inaccurate, and the production storage path has no tests. Details in section 4. |

---

## 2. Document lifecycle, traced through the code

```text
UPLOAD  POST /api/documents  (modules/documents.ts)
  multipart → validateUpload()            lib/upload-validation.ts
     magic-byte type check (PDF/PNG/JPEG); images re-encoded (EXIF stripped);
     PDFs: no encryption, no JavaScript/Launch/EmbeddedFiles/XFA, ≤50 pages
  → storeEncryptedDocument()              services/documents.ts
     documentId = randomUUID()                (chosen first: it goes into the AAD)
     DEK = randomBytes(32)
     file  → AES-256-GCM(DEK, iv=12 random bytes, AAD="file|docId|ownerId")
     DEK   → AES-256-GCM(KEK, AAD="dek|docId")         → document_keys row
     fields→ seal(DEK, value, AAD="claim|docId|key|value")  → document_claims
     ciphertext → storage.put(random 64-hex name)
         local driver:    ./data/storage/xx/<name>.bin (mode 0600)
         database driver: stored_objects.data  ← production (render.yaml)
     documents row: title, category, mimeType, sizeBytes, plaintextSha256,
                    enc_iv, enc_tag (all in clear)
     audit: document_uploaded {title,…}, document_encrypted {algorithm,…}
     DEK zero-filled in `finally`

OWNER VIEW  GET /api/documents/:id
  getOwnedDocument (ownerId in the WHERE clause, so no IDOR)
  → loadDataKey (unwrap with KEK of that version) → decryptClaims → DEK zeroed

OWNER DOWNLOAD  GET /api/documents/:id/file
  → readDocumentFile: storage.get → GCM decrypt (tag check) → SHA-256 compare
    failure → security event integrity_check_failed (high) + generic 500
  → headers: no-store, nosniff, CSP sandbox

SHARE  POST /api/documents/:id/links  (modules/sharing.ts)
  token = 32 random bytes (base64url); DB stores SHA-256(token)
  + tokenEncrypted = seal(KEK directly, token, "link-token|linkId")
  permissions = chosen claim ids; includeFile flag; expiry; countries

RECIPIENT  GET /api/share/:token  and  /file  (modules/access.ts)
  findByToken (hash lookup) → evaluateAccess:
     revoked/deleted → expired → organization membership → country (fails closed)
     every attempt → access_logs (country, keyed IP HMAC, UA family)
  details: unwrap DEK → decrypt ALL claims → filter to permitted → for
           credentials build an SD-JWT presentation with only those disclosures
  file:    only if includeFile → decrypt → watermark → PDF to the browser

DELETE  DELETE /api/documents/:id
  transaction: revoke links, delete claims, credential, document_keys row,
               soft-delete document (title → "[deleted document]")
  then storage.delete (failure only logged)

KEY ROTATION  pnpm keys:rewrap  (scripts/rewrap-keys.ts)
  re-wraps every DEK with the current KEK; file ciphertext untouched
```

---

## 3. What is already done well (keep it)

| Control | Evidence |
| --- | --- |
| Correct AEAD use | AES-256-GCM, 96-bit random IV per encryption, 128-bit tag, key length asserted (`lib/crypto.ts`) |
| Context binding | AAD binds ciphertext to document id, owner id, field key and purpose, so swapped ciphertext fails to decrypt |
| Envelope encryption + versioning | Per-document DEK, versioned KEK, `PREVIOUS_MASTER_KEYS`, re-wrap script |
| Key derivation and separation | HKDF-SHA256 with distinct labels for KEK, IP HMAC and issuer seed (`config.ts`) |
| Key hygiene | DEKs zero-filled after use; no key material in responses |
| Integrity | GCM tag + SHA-256 re-check; tamper → high-severity event + generic error (tested) |
| Access control | Ownership inside every query; one share gate; country check fails closed; tokens stored hashed |
| Upload safety | Content-based type detection, image re-encoding, active-PDF rejection |
| Tests that prove encryption | `crypto.test.ts` (15 tests: round trip, fresh IVs, tamper on ciphertext/tag/AAD/key, wrap/unwrap, rotation); `documents.test.ts` checks the stored bytes do not contain a plaintext marker and the claim value is not in its column |

---

## 4. Findings: vulnerabilities and missing components

Severity is for this app's threat model (database leak, server compromise, malicious user, curious recipient).

| ID | Severity | Finding | Where |
| --- | --- | --- | --- |
| **A1** | High | **Master key lives next to the app.** `MASTER_KEY` is a Render environment variable of the same web service. Anyone with code execution on the server, or access to the Render dashboard, can unwrap every DEK. There is no KMS or HSM, and the key is in app memory for its whole lifetime. | `config.ts`, `render.yaml` |
| **A2** | High | **Production stores ciphertext and wrapped keys in the same database.** `STORAGE_DRIVER=database` puts files in `stored_objects` beside `document_keys`. A database dump plus the env var is everything an attacker needs. The landing page says "Keys, files and the master key live in three separate places"; in production that is **not true** (two places). | `render.yaml`, `Landing.tsx` |
| **A3** | High | **Crypto-shredding claim is wrong once backups exist.** The delete route says "the document can never be decrypted again, even from a backup of the database". A backup holds both the wrapped DEK and the ciphertext, and the KEK is still live, so a restored backup decrypts a "deleted" document. | `modules/documents.ts:242`, `docs/security.md:33` |
| **A4** | Medium | **Sensitive metadata stored in plain text.** `documents.title` (e.g. "Ahmed's passport"), `document_claims.label` ("National ID number"), `sharing_links.recipient_label`, `mime_type`, `size_bytes`. A database reader learns what each person stores and shares without breaking any encryption. | `schema.prisma` |
| **A5** | Medium | **Titles survive deletion for up to a year.** Upload and delete events write `metadata.title` into the append-only `security_events` table (365-day retention), and notification bodies contain the title. Deleting a document does not remove its name. | `services/documents.ts:101`, `modules/documents.ts:255`, `modules/access.ts` (`notify` bodies) |
| **A6** | Medium | **Unkeyed plaintext hash of every file.** `documents.plaintext_sha256` is SHA-256 of the original file. Anyone with the database can confirm whether a specific known file (a leaked ID scan, a known certificate) is stored, and by whom. It is also redundant: GCM already authenticates the file. | `services/documents.ts:73` |
| **A7** | Medium | **The production storage path is untested.** Every integration test runs with `STORAGE_DRIVER: 'local'`; the `database` driver used on Render is never exercised with real uploads, tamper tests or deletes. | `test/helpers.ts:34` |
| **A8** | Medium | **Suspended owners' documents stay decryptable through their links** (plan item B4). The gate never checks owner status. | `modules/access.ts` |
| **A9** | Medium | **Field selection does not limit the file.** A user can share only "Enrollment status", but if "Include the file" is ticked, the recipient receives the full original with every detail on it. The server enforces exactly what was chosen, but the UI does not warn that the file reveals everything. | `modules/access.ts`, `pages/Share.tsx` |
| **A10** | Low | **Key separation:** the KEK (meant only for wrapping DEKs) also seals link tokens directly. | `modules/sharing.ts` |
| **A11** | Low | **Rotation is incomplete:** `keys:rewrap` re-wraps DEKs but not `tokenEncrypted`. After an old master key is removed, "Copy link" on older links fails with `token_unavailable`. No dry run, no batching, no verification pass. | `scripts/rewrap-keys.ts` |
| **A12** | Low | **Weak key-format validation:** `MASTER_KEY` only needs 32 characters, so a human-typed phrase passes. HKDF does not stretch low-entropy input. Render's generated value is strong, but nothing enforces it for other deployments. | `config.ts:13` |
| **A13** | Low | **No startup key check:** if `MASTER_KEY` changes by mistake (redeploy, copy error), the app starts normally and every document fails later with an "integrity" error. A boot-time canary would catch it immediately. | `server.ts` |
| **A14** | Low | **Orphaned ciphertext:** `storage.delete` runs after the transaction and failures are only logged. The key is gone so the data is unreadable, but it stays stored. | `modules/documents.ts:258` |
| **A15** | Info | **Decrypts more than needed:** the share view decrypts all fields, then filters. Safe (filtering is server-side) but wider than necessary. | `modules/access.ts:205` |
| **A17** | Medium | **The original at-rest test could not fail** (found in E1). `documents.test.ts` checks that `PLAINTEXT_MARKER` is absent from storage, but `samplePdf()` never contains the marker as raw bytes (pdf-lib writes page text as hex in a compressed stream, and the subject as UTF-16 hex). CI printed `samplePdf() contains PLAINTEXT_MARKER as raw bytes: false`. The new E1 suite checks that each marker is present in the plaintext first. | `test/helpers.ts`, `test/integration/documents.test.ts` |
| **A16** | Info | **Not end-to-end:** the server sees plaintext during upload, view and share. This is stated honestly in the UI and README; keep it that way (section 5). | — |

**Not verified live:** I could not inspect the production database. Step E0 below checks it.

---

## 5. Design decisions (why the plan looks like this)

**"Selective encryption": encrypt everything, disclose selectively.** Letting users choose which fields to encrypt means some fields would be stored in clear, which is a downgrade. The production-minded version of the requirement is:
1. every file, field value, field label and title is always encrypted;
2. the owner selects what to **disclose** per link (exists today; server-enforced);
3. the owner can mark a field **restricted**, and the server refuses to put restricted fields in "anyone with the link" shares (new, E6);
4. issuer credentials already use SD-JWT, so undisclosed fields are cryptographically hidden from the recipient, not just hidden in the UI;
5. for the **file itself**, the owner can create a **protected sharing copy** in which the selected information is destroyed, not hidden (Smart Selective Protection, E9, section 6 Phase E-F).

Why removal and not "encrypt that part of the PDF": a recipient never gets a key, so a region that is encrypted inside the shared file is either unreadable to them (then it can just as well be gone) or decryptable by them (then it is not protected). Anything in between, like a black box drawn over text that is still in the file, is exactly the visual-hiding mistake behind real-world redaction leaks. So the original stays fully encrypted and untouched, and the recipient gets a separately encrypted copy whose sensitive pixels and text no longer exist.

**Server-side encryption stays (no end-to-end for now).** End-to-end encryption in the browser would break the features that make TrustPass useful: server-side field filtering, SD-JWT presentations, watermarking and the country gate all need the server to read the document. The right fix for "the server can read everything" is to protect the **master key** (KMS, E2), not to move encryption to the browser. A future "private vault" mode with no sharing could be end-to-end; out of scope here.

**KMS is optional but designed in.** Render's free plan has no KMS. The plan adds a `KeyProvider` interface with the current `env` provider as the default and a `kms` provider (AWS KMS, Google Cloud KMS or HashiCorp Vault Transit) you can switch on later without migrating data again.

---

## 6. Implementation plan

Same rules as `docs/implementation-plan.md`: new Prisma migration for every schema change (never edit the init migration), shared Zod schemas, `pnpm typecheck && pnpm test && pnpm build` (+ `pnpm e2e` for web changes), commit messages start with the item ID. Branch: `claude/encryption-hardening`, one PR per phase.

### Phase E-A: prove the current state (no behaviour change)

**E0. Live check of the production database (P1, S).** Needs Reham (Render dashboard > database > PSQL; Claude never types database credentials).
- Run read-only queries: `SELECT key, length(data), encode(substr(data,1,16),'hex') FROM stored_objects LIMIT 3;` plus a check that a known word from an uploaded test PDF is absent (`position(convert_to('Demo University','UTF8') in data)` = 0); `SELECT kek_version, count(*) FROM document_keys GROUP BY 1;` and a count of documents with no key row (must be 0).
- **Done when:** results are recorded in `docs/test-report.md` under "Encryption at rest (live)".
- **Status (17 Nov):** script written as `docs/security/e0-readonly-check.sql` (READ ONLY transaction, counts and yes/no answers only, ends with ROLLBACK). Tested on a local PostgreSQL 16 with the real schema: all zeros for a correctly encrypted row, and it flagged a planted plaintext PDF, a missing key, a readable field value and a title in the logs. **Done 17 Nov** on the live `trustpass-db` through the Render connector's read-only query tool (`e0-readonly-check-single.sql`): read-only confirmed; every encryption check PASS; known gaps confirmed (titles 2, labels 6, recipient names 8, unkeyed hashes 4 including deleted documents, titles in logs 6, deleted documents' titles still in logs 2). Also seen: the database expires 16 Dec 2026 and accepts connections from any IP (`0.0.0.0/0`).

**E1. Tests that prove encryption, written first (P1, M).**
- Known-answer test: AES-256-GCM against a published NIST test vector, so the wrapper is proven correct, not just self-consistent.
- Run the documents, sharing and verification integration suites **for both storage drivers** (`describe.each(['local','database'])`), fixing A7.
- **Plaintext canary test:** upload a file, title, field label and field value that each contain a unique marker, create a link, then read **every row of every table** (`stored_objects`, `documents`, `document_claims`, `credentials`, `sharing_links`, `notifications`, `security_events`, `access_logs`) as raw bytes and assert no marker appears. It will fail today (A4, A5); it is the acceptance test for E3.
- Wrong-key test: start a second app instance with a different `MASTER_KEY` against the same database → every decrypt fails safely, nothing is returned.
- Recipient tests: response bodies contain only the permitted fields (raw JSON check, not UI), and the file endpoint returns 403 when the file is not included.
- **Done when:** the suite runs in CI; failing canary assertions are marked `it.fails` with a link to E3 so CI stays green and the gap is visible.
- **Status (17 Nov): done** on `claude/encryption-hardening` (commit `239a969`). CI: 153/153 API tests pass (23 new), e2e, audit and secret scan pass. Running the whole older suites under both drivers is moved into E3 (it needs a small refactor of `documents.test.ts`); the new suite already covers the `database` driver for upload, decrypt, tamper, sharing, delete and wrong-key cases.

### Phase E-B: key management

**E2. Key provider, key separation and startup check (P1, M).** Fixes A1 (structure), A10, A12, A13.
- `lib/keys.ts`: `interface KeyProvider { wrap(dek, ctx): Promise<WrappedKey>; unwrap(w, ctx): Promise<Buffer>; selfTest(): Promise<void> }`. `EnvKeyProvider` = today's behaviour. `KmsKeyProvider` behind `KEY_PROVIDER=kms` (Vault Transit or a cloud KMS; DEKs are wrapped remotely, the master key never enters app memory).
- Derive a **separate** `link-token` key with HKDF; stop sealing tokens with the KEK.
- Production config: `MASTER_KEY` must decode to ≥32 random bytes (base64 or hex); document `openssl rand -base64 32`.
- Boot canary: `system_settings.key_check` holds a value sealed at first start; on boot, unwrap it, and refuse to start with a clear log line if that fails.
- **Done when:** unit tests for both providers (KMS with a fake); app refuses to boot with a wrong key; existing data still decrypts (no data migration needed for DEKs).

**E3a. Complete rotation (P2, S).** Fixes A11.
- `keys:rewrap` also re-seals `tokenEncrypted`; adds `--dry-run`, batches of 100, and a final verification pass that unwraps every key. Admin > Health shows "Keys on old version: n".
- **Done when:** integration test rotates v1 → v2, removes v1 from config, and every document, field and "Copy link" still works.

### Phase E-C: close the metadata leaks

**E3. Encrypt titles, labels and recipient labels (P1, M).** Fixes A4.
- Migration 1 adds `title_encrypted`, `label_encrypted`, `recipient_label_encrypted` (nullable). A backfill script (`pnpm keys:encrypt-metadata`) encrypts existing rows with each document's DEK, with AAD such as `title|docId`. Migration 2 makes them required and drops the plain columns.
- Listing endpoints unwrap one DEK per document (cheap at ≤50 documents per user; S4 caps it).
- Organization inbox and share view decrypt after the gate, as today.
- **Done when:** the E1 canary passes for title, label and recipient label; documents, links and inbox pages look unchanged in e2e.

**E4. Keep titles out of logs and notifications (P1, S).** Fixes A5.
- `security_events` metadata: drop `title` (keep `documentId`). Notification bodies: a generic text plus `documentId`/`linkId`; the web app shows the current (decrypted) title when the notification is opened.
- Existing rows: a one-off purge transaction (`set_config('trustpass.allow_log_purge','on',true)`) rewrites by deleting and re-inserting without titles, or leaves them to expire. Decide with Reham.
- **Done when:** canary passes for `security_events` and `notifications`.

**E5. Replace the plain file hash (P2, S).** Fixes A6.
- Uploaded files: store `HMAC-SHA256(deriveKey(MASTER_KEY,'doc-hmac'), file)` instead of SHA-256, or drop it (GCM already authenticates). The owner-facing "SHA-256" display becomes a value computed on demand after decryption.
- Issued credentials keep `credentials.document_hash`: public verification of certificates needs it, and those PDFs are designed to be checked.
- **Done when:** no unkeyed hash of an uploaded file remains in the database; verification tests still pass.

### Phase E-D: authorized decryption and sharing

**E6. One decryption guard and restricted fields (P1, M).** Fixes A8, A9, A15.
- `services/decrypt.ts`: `decryptFor(principal, document, purpose)` is the **only** caller of `loadDataKey`. It checks owner active (B4), document not deleted and the principal/purpose pair (`owner_view`, `owner_file`, `share_details`, `share_file`, `issuer`), then decrypts **only** the permitted fields. A lint rule or test forbids `loadDataKey` imports elsewhere.
- Field sensitivity: `document_claims.sensitivity` (`normal` | `restricted`); restricted fields can only go to organization-only links; the API rejects the rest with a clear message.
- Share page: when "Include the file" is ticked, show "The file shows everything on it, not only the fields you picked." and require a second confirmation.
- Owner file download logs `document_downloaded` (security event).
- **Done when:** tests prove a suspended owner's links return 410; a restricted field cannot be added to an "anyone" link; share responses never contain non-permitted values (raw JSON); every decrypt path goes through the guard.

**E7. Optional step-up for downloading originals (P3, S).** Re-enter password (or TOTP once S3 exists) if the last sign-in is older than 10 minutes, before `GET /api/documents/:id/file`. Ask Reham whether the extra step is worth it for the demo.

### Phase E-E: deletion and honesty

**E8. Reliable deletion and correct claims (P2, S).** Fixes A2 (wording), A3, A14.
- Outbox table `pending_object_deletions`: written in the delete transaction, processed by a retry job (and on start-up), so ciphertext is always removed.
- Correct the wording: delete-route comment, `docs/security.md` and the landing page. Production text: "Each file has its own key. Keys are wrapped by a master key kept outside the database." State that backups keep deleted documents recoverable until they expire (link to D4 backup retention).
- Optional (with KMS): keep files in object storage (S3/R2) instead of PostgreSQL, so files, keys and master key really are in three places; then the original claim can return.
- **Done when:** a test kills storage delete once and the retry removes the object; docs and landing copy match the deployment.

### Phase E-F: Smart Selective Protection (core feature)

**Goal.** The owner shares a file, but chosen information (ID numbers, IBAN, date of birth, a photo) is **irreversibly removed** from what the recipient receives. The original stays fully encrypted and is never sent on that link.

**How it fits the existing architecture**

```text
                 owner session + decryption guard (E6, purpose "owner_redact")
                                        │
 documents (original)  ── DEK₁ ──►  decrypt in memory
 AES-256-GCM, unchanged                 │
                                        ▼
                      1. DETECT   text layer (pdf.js positions) + detectors
                                  [optional OCR for scans]  → suggestions
                      2. SELECT   owner ticks checkboxes / draws boxes in the UI
                      3. REDACT   rasterize pages → paint solid boxes on pixels
                                  → rebuild an image-only PDF (no text layer,
                                    no metadata, no annotations, no old objects)
                      4. VERIFY   automatic checks (below); any failure = no copy
                      5. ENCRYPT  new DEK₂ → AES-256-GCM → storage
                                        │
 redacted_copies (new) ◄── DEK₂ wrapped by the KEK (same key provider as E2)
   parent document_id, storage_key, iv, tag, size,
   manifest_encrypted (what was removed: types, pages, boxes), created_at
                                        │
 sharing_links.copy_id (new, nullable)  │  include file?
   null      → original (today's behaviour; restricted fields block this, E6)
   copy_id   → the redacted copy only, watermarked at view time as today
```

- **Key model.** Each copy has its **own** data key, wrapped by the same KEK as documents, so it rotates (E3a), gets shredded and is scanned by the canary like any document. Deleting the original deletes its copies; deleting a copy revokes links that use it.
- **Gate unchanged.** `evaluateAccess` still decides revoked, expired, organization and country. Only `sendWatermarkedFile` changes: it reads the copy named by the link, never the original, when `copy_id` is set.
- **Fields.** Typed fields keep using selective disclosure. Detection also checks typed values and suggests marking them **restricted** (E6), so an ID number typed as a field cannot be put on an "anyone" link either.
- **Policy (server-enforced).** If the original contains detected or owner-marked sensitive items, an "anyone with the link" share that includes the file must use a redacted copy, unless the owner explicitly overrides after a warning.

**Why it can't be undone (what "not visual hiding" means here)**

| Common redaction failure | How E9 avoids it |
| --- | --- |
| Black box drawn as an annotation over text that is still there (copy/paste reveals it) | The output has **no text layer at all**: pages are images; the box is painted into the pixels |
| Hidden or white text, optional-content layers, form fields | The output PDF is rebuilt from scratch: only `Page` + one image `XObject` per page |
| Incremental save keeps the old content | New file, never an edit of the original |
| Metadata, XMP, thumbnails, embedded fonts, attachments | None are copied; the verify step rejects any such object |
| Blur or pixelation (reversible) | Solid opaque fill with a margin; never blur |
| Box drawn in the wrong place on rotated/cropped pages | Detection, preview and rasterization use the **same** renderer and coordinate system (pdf.js on server and web); tests cover `/Rotate` and `CropBox` |

**Automatic verification (runs on every copy; failure = the copy is not created)**
1. Text extraction of the output (pdf.js) returns **no text**.
2. Raw bytes **and every inflated stream** of the output contain none of the selected strings, in UTF-8, UTF-16BE, hex and digits-only forms.
3. Object inventory: only allowed types; no `Annots`, `Metadata`, `EmbeddedFiles`, `JavaScript`, `OCProperties`, `AcroForm`.
4. Every redaction box is solid black in the rendered output (pixel check), and the area outside the boxes still matches the original (so the rest stays readable).
5. If OCR is enabled: OCR of each redacted box finds nothing.

**Detection (server-side only, nothing sent to outside services)**
- Text PDFs: pdf.js `getTextContent()` gives each string with its position.
- Detectors with validation, not just patterns: Saudi national ID / Iqama (10 digits, starts with 1 or 2, checksum), Saudi IBAN (`SA` + 22, mod-97), card numbers (Luhn; flagged as "must remove"), phone numbers (`+9665…`, `05…`), email, dates near "Date of birth / تاريخ الميلاد", passport-style numbers near "Passport / جواز". Arabic-Indic digits (٠–٩) are normalised first.
- Scans and photos: optional OCR (`tesseract.js`, self-hosted English + Arabic data, worker thread, `OCR_ENABLED`). Render's free plan has little memory, so OCR starts off; without it, scans use manual boxes and the UI says so.
- Suggestions are returned only to the owner, never logged, and stored only encrypted (inside the manifest).
- Honest copy in the UI: "Automatic detection can miss things. Check every page of the protected copy before you share it."

**Items**

**E9a. Copy model and sharing (P1, M).** Migration for `redacted_copies` and `sharing_links.copy_id`; encrypt/decrypt through the E6 guard; gate serves the copy; delete and rotation cover copies; canary scan includes copies.
- **Done when:** a link with `copy_id` returns bytes whose hash differs from the original and never the original; deleting the original removes the copies' keys and objects; rotation re-wraps copy keys.

**E9b. Redaction engine and verifier (P1, L).** Server-side `services/redaction.ts`: `pdfjs-dist` + `@napi-rs/canvas` to rasterize at 200 DPI (images used directly), paint boxes with `sharp`, rebuild an image-only PDF with `pdf-lib`, then run the five checks. Limits: 20 pages per copy at first, one job at a time, time limit.
- **Done when:** recovery tests pass on canary files with a text layer (PDF with ID, IBAN and phone in text, hex strings, a compressed stream and metadata; a rotated page; a cropped page; a PNG and a JPEG). The selected strings are unrecoverable by text extraction, by byte and stream search, or by rendering, and unselected text is still visible.

**E9c. Detection API (P2, M).** `POST /api/documents/:id/redaction/suggestions` (owner only, rate-limited) returns `{ id, type, page, boxes, preview: "1•••••••89", confidence }`. Unit tests for every detector, with valid and invalid checksums, Arabic digits, and false-positive cases.

**E9d. Protect step in the Share page (P2, L).** Page previews with highlighted suggestions; checkboxes grouped by type ("National ID (2)", "Phone (1)") with select all; draw, move and delete boxes manually; "Redact whole page"; **review the final protected copy** (the real output, rendered from the server) before the link is created. Phone layout: one page at a time, boxes adjustable by touch. e2e test of the full flow.

**E9e. OCR for scans (P3, M, optional).** Behind `OCR_ENABLED`, with memory and time limits; adds verification check 5.

**E9f. Sensitive typed fields (P2, S).** Run the detectors on typed field values at upload and suggest `restricted` (E6).

---

## 7. Suggested order

| Step | Items | Why |
| --- | --- | --- |
| 1 | E0, E1 | Know the live state and get tests that prove encryption before changing anything |
| 2 | E2, E3a | Key management is the foundation; nothing else should be built on a key that can't be rotated or checked |
| 3 | E3, E4, E5 | Close the metadata leaks the canary test exposes |
| 4 | E6 | Authorized decryption in one place; restricted fields (E9 depends on it) |
| 5 | E9a, E9b | The secure core of Smart Selective Protection: copy model, redaction engine, recovery tests |
| 6 | E9c, E9d, E9f | Detection and the checkbox/drawing UI on top of a proven engine |
| 7 | E8, then E7 and E9e if wanted | Correct claims, reliable deletion; optional step-up and OCR |

Sizes: S ≈ 1 hour, M ≈ half a day, L ≈ 1–2 days of Claude sessions. E3 needs two deploys (add + backfill, then drop the old columns). E9b adds two dependencies (`pdfjs-dist` on the server, `@napi-rs/canvas`), which must pass the dependency audit in CI.

## 8. Definition of done (encryption work)

- Canary test passes: no marker from a file, title, label, value or recipient name appears in any table.
- Both storage drivers are covered by the integration suites; the NIST vector test passes.
- Key rotation end-to-end test passes with the old key removed.
- Wrong master key → app refuses to start; no partial data is ever returned.
- `docs/security.md`, the README and the landing page describe exactly what the deployment does.
- No keys, tokens, titles or IP addresses in logs or responses.
- Smart Selective Protection: every protected copy passes the five verification checks, and the recovery tests prove selected information cannot be recovered by text extraction, byte or stream search, or rendering.

## Checklist

- [ ] E0 · [ ] E1 · [ ] E2 · [ ] E3a · [ ] E3 · [ ] E4 · [ ] E5 · [ ] E6 · [ ] E7 · [ ] E8
- [ ] E9a · [ ] E9b · [ ] E9c · [ ] E9d · [ ] E9e · [ ] E9f

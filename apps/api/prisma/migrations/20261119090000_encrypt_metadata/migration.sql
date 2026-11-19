-- E3/E5: titles, field labels, recipient labels and the file's SHA-256 are stored encrypted
-- with the document's own data key (AES-256-GCM, AAD bound to the row).
-- Step 1 of 2: add the encrypted columns and allow the plain ones to be empty. New rows only
-- fill the encrypted columns. Existing rows are encrypted, and their plain values erased, by
-- `pnpm keys:encrypt-metadata` (run once, explicitly). A later migration drops the plain columns.
-- Schema only: this migration reads and changes no data.

ALTER TABLE "documents"
  ADD COLUMN "title_encrypted" BYTEA,
  ADD COLUMN "sha256_encrypted" BYTEA,
  ALTER COLUMN "title" DROP NOT NULL,
  ALTER COLUMN "plaintext_sha256" DROP NOT NULL;

ALTER TABLE "document_claims"
  ADD COLUMN "label_encrypted" BYTEA,
  ALTER COLUMN "label" DROP NOT NULL;

ALTER TABLE "sharing_links"
  ADD COLUMN "recipient_label_encrypted" BYTEA,
  ALTER COLUMN "recipient_label" DROP NOT NULL;

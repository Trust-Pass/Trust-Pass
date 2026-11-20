-- Sensitive information hiding: the owner's saved choice of what to hide in shared copies of a
-- document (chosen at upload or later). Schema only: adds one nullable column; reads and changes no
-- existing row. The plan (areas, categories, styles) is sealed with the document's own key
-- (AES-256-GCM, AAD bound to the document). The original file is never modified.
ALTER TABLE "documents" ADD COLUMN "redaction_plan_encrypted" BYTEA;

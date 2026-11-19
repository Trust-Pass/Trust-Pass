-- Smart Selective Encryption: a link can share a REDACTED copy of the file instead of the original.
-- Schema only: reads and changes no existing row. Existing links keep file_mode NULL, read as
-- "original" when include_file is true (exactly what they share today).
ALTER TABLE "sharing_links"
  ADD COLUMN "file_mode" TEXT,
  ADD CONSTRAINT "sharing_links_file_mode_check" CHECK ("file_mode" IS NULL OR "file_mode" IN ('original', 'redacted'));

-- One row per page of a link's redacted copy. The page image (black boxes already burned in) is
-- stored as AES-256-GCM ciphertext with the document's own key (AAD binds document, link and page);
-- only its size is in clear. Deleting the document destroys the key, so these become unreadable.
CREATE TABLE "redacted_pages" (
    "id" UUID NOT NULL,
    "link_id" UUID NOT NULL,
    "document_id" UUID NOT NULL,
    "page_index" INTEGER NOT NULL,
    "storage_key" TEXT NOT NULL,
    "enc_iv" BYTEA NOT NULL,
    "enc_tag" BYTEA NOT NULL,
    "width" INTEGER NOT NULL,
    "height" INTEGER NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "redacted_pages_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "redacted_pages_link_id_fkey" FOREIGN KEY ("link_id") REFERENCES "sharing_links"("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "redacted_pages_document_id_fkey" FOREIGN KEY ("document_id") REFERENCES "documents"("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "redacted_pages_page_check" CHECK ("page_index" >= 0 AND "width" > 0 AND "height" > 0)
);
CREATE UNIQUE INDEX "redacted_pages_link_id_page_index_key" ON "redacted_pages"("link_id", "page_index");
CREATE INDEX "redacted_pages_document_id_idx" ON "redacted_pages"("document_id");

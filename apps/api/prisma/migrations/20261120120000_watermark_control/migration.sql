-- Watermark control: the owner chooses, per link, whether recipient copies carry a watermark and
-- how it looks. Schema only: reads and changes no existing row. Existing links get
-- watermark_enabled = true and no settings, which means the standard watermark they show today.
-- The settings (style, colour, strength and stamp text) are sealed with the document's own key
-- (AES-256-GCM, AAD bound to document and link), like the recipient label.
ALTER TABLE "sharing_links"
  ADD COLUMN "watermark_enabled" BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN "watermark_encrypted" BYTEA;

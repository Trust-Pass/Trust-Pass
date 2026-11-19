-- Recipient download of a separate watermarked PDF.
-- Schema only: reads and changes no data. Every existing link keeps downloads OFF.
ALTER TYPE "AccessResource" ADD VALUE IF NOT EXISTS 'download';

ALTER TABLE "sharing_links"
  ADD COLUMN "allow_download" BOOLEAN NOT NULL DEFAULT false;

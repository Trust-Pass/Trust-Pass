# Recipient download (watermarked copy)

The owner can let a recipient download a PDF copy of a shared file. It is **off by default** and
can be switched on or off per link (Share page, or Sharing links > Activity) while the link is active.

## What happens on every download

1. `GET /api/share/:token/download` (or `/api/inbox/:id/download` for organization links).
2. The link must share the file **and** allow downloads, otherwise `403` and nothing is decrypted.
3. The same gate as every other request runs again: revoked or deleted → `410`, expired → `410`,
   organization members only, allowed countries (unknown location is refused). Each attempt is
   written to `access_logs` with `resource = download`.
4. The stored original is decrypted **in memory only**. Storage, ciphertext, IV, tag and the wrapped
   key are read, never written. The original's SHA-256 is checked; a tampered file is refused
   (`integrity_error`) and the owner and admins are alerted.
5. A **new** PDF is built for this download (`buildRecipientCopy` in `lib/pdf.ts`): pages are copied
   into a fresh document (the original's metadata is not carried over; link actions are removed),
   images are wrapped in a new page. Every page gets:
   - top band: `CONFIDENTIAL - Downloaded for: <recipient>` (organization links add the member's name)
   - top and bottom: download time, a unique 10-character **copy reference**, the link reference
   - diagonal `CONFIDENTIAL` stamps
6. A `recipient_downloaded` event stores the copy reference, the access-log id and the country
   (no title, no recipient name). The owner gets at most one notification per link per hour.
7. Response: `Content-Disposition: attachment`, `Cache-Control: no-store, private`, sandbox CSP.
   Limit: 20 downloads per address (or per signed-in user) per 10 minutes.

A leaked copy can be traced: its copy reference (printed on every page and in the PDF keywords)
matches exactly one logged download.

## Limits (honest)

- A downloaded copy cannot be recalled. Revoking or expiring the link stops **future** downloads only.
- The standard PDF fonts cover Latin letters only. A recipient name in Arabic or another script is
  printed as "the recipient of link <ref>"; the copy reference still identifies the download.
- The PDF is not password-protected; protection comes from the visible, per-download watermark.

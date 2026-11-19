# Smart Selective Encryption (selective sharing and redacted copies)

Every document is always encrypted at rest with its own AES-256-GCM key; there is nothing to
switch on. What the owner chooses, per link, is **what the recipient receives**:

| Share option | Recipient gets |
|---|---|
| Details only | Only the fields the owner ticked (issuer-signed fields stay verifiable through SD-JWT). No file. |
| Original file | The original document, watermarked for the recipient; plus the ticked fields. |
| Redacted copy | A new PDF made only of page images, with the owner's black boxes burned in; plus the ticked fields. The original is never sent. |
| View / download | For both file options the owner decides whether the recipient may download a watermarked copy (off by default). |

## How a redacted copy is made

1. On the Share page the owner picks **Redacted copy** and drags black boxes over anything the
   recipient must not see. The pages are rendered in the owner's browser with pdf.js (PDFs); images
   are rendered on the server from the decrypted original.
2. The server checks the page images (one per page, each with its page's shape, PNG or JPEG, size
   limits), **burns the boxes into the pixels as opaque black**, flattens transparency, and re-encodes
   each page as a new PNG **without any metadata** (EXIF, XMP, text chunks).
3. Each page is stored as AES-256-GCM ciphertext with the document's key, bound to the document, the
   link and the page number. Deleting the document destroys them with the key.
4. The recipient's view and download are built from scratch from those images: **no text layer, no
   fonts or content streams of the original, no annotations, forms, attachments, outline, XMP or
   original document information**. The watermark (recipient, time, link, copy reference) is added.

So what was under a box is not hidden behind something: it is not in the recipient's file at all.

## Evidence (tests)

- `apps/api/test/integration/selective-sharing.test.ts`: decodes every image in the recipient's view
  and download and finds **zero** pixels of the hidden areas; finds none of the hidden text (plain or
  hex-encoded) in any stream; checks title, subject, author, keywords, creator, producer, fonts
  (watermark only), annotations, forms, attachments, outline, XMP; checks the JSON answers; checks
  the stored pages are ciphertext, bound to their page, PNG without EXIF; server-side rendering of
  images (browser input ignored); view-only vs download; refusal of incomplete or mismatched copies;
  destruction with the document.
- `e2e/tests/selective-sharing.spec.ts`: in Chromium (phone and desktop), pdf.js renders the page, the
  owner drags a box with the mouse, and the recipient's view and download contain neither the secret
  text nor its pixels.
- `apps/api/test/integration/recovery-checker.test.ts`: the backup recovery checker decrypts every
  redacted page from a backup and reports a damaged one.

## Limits

- The owner decides what to hide. Anything not covered by a box is visible in the copy.
- A redacted copy of an issuer-signed certificate is no longer the signed file: its fields remain
  verifiable through the SD-JWT presentation, not through the image.
- PDF pages are rendered by the owner's browser; the server cannot render PDFs itself. The server
  checks the page count and shape, and burns the boxes in itself.

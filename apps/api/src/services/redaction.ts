import { randomUUID } from 'node:crypto';
import { PDFDocument } from 'pdf-lib';
import sharp, { type Sharp } from 'sharp';
import { REDACTION_MAX_EDGE, type Redaction } from '@trustpass/shared';
import { decrypt, encrypt, toBytes } from '../lib/crypto';
import { AppError } from '../lib/errors';
import { newStorageKey } from '../lib/storage';
import type { AppDeps } from '../types';
import { readDocumentFile } from './documents';

/**
 * Smart Selective Encryption: the redacted recipient copy.
 *
 * A redacted copy contains NOTHING of the original file except pixels:
 *  - every page becomes a flat image (images: rendered here from the decrypted original; PDFs:
 *    rendered by the owner's browser with pdf.js, because the server has no PDF renderer);
 *  - the owner's boxes are burned into those pixels here, as opaque black, so what was under a box
 *    is replaced, not covered;
 *  - each page is re-encoded as a new PNG with no metadata (EXIF, XMP, text chunks, ICC comments);
 *  - the recipient's PDF is built from scratch from those images only: no text layer, no fonts, no
 *    original content streams, annotations, outline or document info.
 * Redacted pages are stored per link as AES-256-GCM ciphertext under the document's own key (AAD
 * binds document, link and page), so they are encrypted at rest and die with the document's key.
 */

export interface RedactedPageImage {
  data: Buffer; // PNG, boxes burned in
  width: number;
  height: number;
}

const MIN_EDGE = 200;
const MAX_PAGE_BYTES = 12 * 1024 * 1024;
const ASPECT_TOLERANCE = 0.03;

export function redactedPageAad(documentId: string, linkId: string, pageIndex: number): string {
  return `redacted|${documentId}|${linkId}|${pageIndex}`;
}

const reject = (message: string) => new AppError(400, 'redaction_invalid', message);

/** Normalises any accepted page image to a flat (no alpha), metadata-free raster within limits. */
async function flatten(input: Buffer): Promise<Sharp> {
  try {
    const image = sharp(input, { failOn: 'error', limitInputPixels: 40_000_000 }).rotate();
    const meta = await image.metadata();
    if (!meta.width || !meta.height) throw new Error('no size');
    if (meta.format !== 'png' && meta.format !== 'jpeg') throw new Error('format');
    return image
      .resize({ width: REDACTION_MAX_EDGE, height: REDACTION_MAX_EDGE, fit: 'inside', withoutEnlargement: true })
      .flatten({ background: '#ffffff' });
  } catch {
    throw reject('A page image of the redacted copy could not be read');
  }
}

/** Burns opaque black rectangles into one page. Boxes are rounded outwards to whole pixels. */
export async function burnBoxes(page: Sharp, boxes: Redaction[]): Promise<RedactedPageImage> {
  const raw = await page.png().toBuffer();
  const meta = await sharp(raw).metadata();
  const width = meta.width!;
  const height = meta.height!;
  const overlays = boxes.map((b) => {
    const left = Math.max(0, Math.floor(b.x * width));
    const top = Math.max(0, Math.floor(b.y * height));
    const right = Math.min(width, Math.ceil((b.x + b.w) * width));
    const bottom = Math.min(height, Math.ceil((b.y + b.h) * height));
    const w = Math.max(1, right - left);
    const h = Math.max(1, bottom - top);
    return { input: { create: { width: w, height: h, channels: 3 as const, background: { r: 0, g: 0, b: 0 } } }, left, top };
  });
  // A fresh PNG from the composited pixels: sharp writes no metadata unless asked to keep it.
  const data = await sharp(raw).composite(overlays).removeAlpha().png({ compressionLevel: 9 }).toBuffer();
  return { data, width, height };
}

/**
 * Builds the page images of a redacted copy for one document.
 * `uploaded` are the owner's browser renderings, required for PDFs (one per page, in order).
 */
export async function buildRedactedPages(
  deps: AppDeps,
  document: Parameters<typeof readDocumentFile>[1],
  dek: Buffer,
  redactions: Redaction[],
  uploaded: Buffer[],
): Promise<RedactedPageImage[]> {
  const original = await readDocumentFile(deps, document, dek);
  try {
    let sources: Sharp[];
    if (document.mimeType === 'application/pdf') {
      const pdf = await PDFDocument.load(original, { updateMetadata: false });
      const pages = pdf.getPages();
      if (uploaded.length !== pages.length) {
        throw reject(`The redacted copy needs one image per page: the document has ${pages.length}, ${uploaded.length} were sent`);
      }
      sources = [];
      for (let i = 0; i < pages.length; i++) {
        const buf = uploaded[i]!;
        if (buf.length > MAX_PAGE_BYTES) throw reject(`Page ${i + 1} of the redacted copy is too large`);
        const image = await flatten(buf);
        const { width, height } = await sharp(await image.clone().png().toBuffer()).metadata();
        if (!width || !height || Math.max(width, height) < MIN_EDGE) throw reject(`Page ${i + 1} of the redacted copy is too small`);
        // Each image must have the shape of its page (rotation included).
        const p = pages[i]!;
        const rotated = ((p.getRotation().angle % 360) + 360) % 180 === 90;
        const pw = rotated ? p.getHeight() : p.getWidth();
        const ph = rotated ? p.getWidth() : p.getHeight();
        if (Math.abs(width / height - pw / ph) > ASPECT_TOLERANCE * (pw / ph)) {
          throw reject(`Page ${i + 1} of the redacted copy does not have the shape of the document's page`);
        }
        sources.push(image);
      }
    } else {
      // Images are rendered here, from the decrypted original; anything sent is ignored.
      sources = [await flatten(original)];
    }
    if (redactions.some((r) => r.page >= sources.length)) throw reject('An area to hide is on a page the document does not have');
    const out: RedactedPageImage[] = [];
    for (let i = 0; i < sources.length; i++) {
      out.push(await burnBoxes(sources[i]!, redactions.filter((r) => r.page === i)));
    }
    return out;
  } finally {
    original.fill(0);
  }
}

/** Encrypts and stores the pages; returns the rows to create (inside the caller's transaction). */
export async function storeRedactedPages(deps: AppDeps, documentId: string, linkId: string, dek: Buffer, pages: RedactedPageImage[]) {
  const rows = [];
  const written: string[] = [];
  try {
    for (let i = 0; i < pages.length; i++) {
      const sealed = encrypt(dek, pages[i]!.data, redactedPageAad(documentId, linkId, i));
      const storageKey = newStorageKey();
      await deps.storage.put(storageKey, sealed.ciphertext);
      written.push(storageKey);
      rows.push({
        id: randomUUID(),
        linkId,
        documentId,
        pageIndex: i,
        storageKey,
        encIv: toBytes(sealed.iv),
        encTag: toBytes(sealed.tag),
        width: pages[i]!.width,
        height: pages[i]!.height,
      });
    }
  } catch (err) {
    await Promise.all(written.map((k) => deps.storage.delete(k).catch(() => undefined)));
    throw err;
  }
  return { rows, written };
}

/** Decrypts a link's redacted pages, in order. */
export async function loadRedactedPages(deps: AppDeps, link: { id: string; documentId: string }, dek: Buffer): Promise<RedactedPageImage[]> {
  const rows = await deps.prisma.redactedPage.findMany({ where: { linkId: link.id }, orderBy: { pageIndex: 'asc' } });
  if (rows.length === 0) throw new AppError(500, 'redacted_copy_missing', 'The redacted copy of this link is not available.');
  const out: RedactedPageImage[] = [];
  for (const row of rows) {
    try {
      const data = decrypt(
        dek,
        { ciphertext: await deps.storage.get(row.storageKey), iv: Buffer.from(row.encIv), tag: Buffer.from(row.encTag) },
        redactedPageAad(link.documentId, link.id, row.pageIndex),
      );
      out.push({ data, width: row.width, height: row.height });
    } catch {
      throw new AppError(500, 'integrity_error', 'The redacted copy failed its integrity check and cannot be shown.');
    }
  }
  return out;
}

/** A brand-new PDF holding only the page images (no text, fonts or original objects). */
export async function pagesToPdf(pages: RedactedPageImage[]): Promise<PDFDocument> {
  const pdf = await PDFDocument.create({ updateMetadata: false });
  for (const p of pages) {
    const image = await pdf.embedPng(p.data);
    // About 150 dpi: an A4 page rendered at 1240 px wide comes out A4 sized.
    const scale = 72 / 150;
    const page = pdf.addPage([p.width * scale, p.height * scale]);
    page.drawImage(image, { x: 0, y: 0, width: p.width * scale, height: p.height * scale });
  }
  return pdf;
}

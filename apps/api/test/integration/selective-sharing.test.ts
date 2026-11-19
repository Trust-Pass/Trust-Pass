import { inflateSync } from 'node:zlib';
import { PDFDocument, PDFName, PDFRawStream, StandardFonts } from 'pdf-lib';
import sharp from 'sharp';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { decrypt } from '../../src/lib/crypto';
import { loadDataKey } from '../../src/services/documents';
import { redactedPageAad } from '../../src/services/redaction';
import { as, createTestContext, documentClaims, IPS, multipart, registerUser, resetDatabase, uploadDocument, type Session, type TestContext } from '../helpers';

/**
 * Smart Selective Encryption: a redacted copy must not contain what the owner hid, in ANY form:
 * pixels, text, content streams, fonts, annotations, attachments, document info, XMP, EXIF, or the
 * JSON answers. The original stays encrypted and unchanged, and the pages are encrypted at rest.
 */

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestContext();
});
afterAll(async () => {
  await ctx.app.close();
});
beforeEach(async () => {
  ctx.clock.now = new Date();
  await resetDatabase(ctx.prisma);
});

const HIDDEN = ['SECRET', '1029384756', 'SALARY'];
const RED = [230, 20, 20] as const;
const BLUE = [20, 60, 230] as const;

/** A 2-page PDF whose text, title, subject, author and keywords all carry hidden values. */
async function secretPdf(): Promise<Buffer> {
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const p1 = pdf.addPage([400, 300]);
  p1.drawText('Visible: Reham Alkhamees', { x: 20, y: 260, size: 14, font });
  p1.drawText('SECRET-NATIONAL-ID-1029384756', { x: 20, y: 30, size: 14, font });
  const p2 = pdf.addPage([400, 300]);
  p2.drawText('SECRET-PAGE-TWO-SALARY-25000', { x: 20, y: 150, size: 14, font });
  pdf.setTitle('SECRET-TITLE');
  pdf.setSubject('SECRET-SUBJECT');
  pdf.setAuthor('SECRET-AUTHOR');
  pdf.setKeywords(['SECRET-KEYWORD']);
  return Buffer.from(await pdf.save({ useObjectStreams: false }));
}

const rect = (left: number, top: number, width: number, height: number, c: readonly number[]) => ({
  input: { create: { width, height, channels: 3 as const, background: { r: c[0]!, g: c[1]!, b: c[2]! } } },
  left,
  top,
});

/** What the owner's browser sends for secretPdf(): page renderings, 800x600 (the pages' 4:3 shape). */
async function browserRenderings() {
  // Page 1: visible name (blue) at the top, the national ID (red) at the bottom.
  const page1 = await sharp({ create: { width: 800, height: 600, channels: 3, background: '#ffffff' } })
    .composite([rect(0, 0, 800, 150, BLUE), rect(0, 450, 800, 150, RED)])
    .png()
    .withMetadata()
    .toBuffer();
  // Page 2: the salary (red) in the middle, as a JPEG carrying hidden EXIF text.
  const page2 = await sharp({ create: { width: 800, height: 600, channels: 3, background: '#ffffff' } })
    .composite([rect(0, 200, 800, 200, RED)])
    .jpeg({ quality: 95 })
    .withExif({ IFD0: { ImageDescription: 'SECRET-EXIF-1029384756' } })
    .toBuffer();
  return [page1, page2];
}

const REDACTIONS = [
  { page: 0, x: 0, y: 0.74, w: 1, h: 0.26 },
  { page: 1, x: 0, y: 0.32, w: 1, h: 0.36 },
];

async function createRedactedLink(owner: Session, documentId: string, link: Record<string, unknown>, pages: Buffer[]) {
  const form = multipart([
    {
      name: 'link',
      value: JSON.stringify({ includeFile: true, fileMode: 'redacted', recipientType: 'anyone', recipientLabel: 'Example Company', expiresIn: '24h', allowedCountries: [], claimIds: [], ...link }),
    },
    ...pages.map((content, i) => ({ name: 'page', filename: `page-${i + 1}.png`, content, contentType: 'image/png' })),
  ]);
  return as(ctx, owner, { method: 'POST', url: `/api/documents/${documentId}/links`, payload: form.payload, headers: form.headers });
}

/** Decode every Flate stream of a PDF and return all text-ish content. */
function pdfContent(pdf: Buffer): string {
  const raw = pdf.toString('latin1');
  let out = raw;
  const re = /stream\r?\n/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    const start = m.index + m[0].length;
    const end = raw.indexOf('endstream', start);
    if (end < 0) break;
    try {
      out += inflateSync(pdf.subarray(start, end)).toString('latin1');
    } catch {
      /* not a Flate stream */
    }
  }
  return out;
}
const hexOf = (t: string) => Buffer.from(t, 'latin1').toString('hex').toUpperCase();

/** Every image in a PDF, decoded to RGB pixels (pdf-lib stores PNG pages as Flate RGB). */
async function imagesOf(pdfBytes: Buffer) {
  const pdf = await PDFDocument.load(pdfBytes);
  const images: Array<{ width: number; height: number; pixels: Buffer }> = [];
  for (const [, obj] of pdf.context.enumerateIndirectObjects()) {
    if (obj instanceof PDFRawStream && obj.dict.get(PDFName.of('Subtype'))?.toString() === '/Image') {
      const width = Number(obj.dict.get(PDFName.of('Width'))!.toString());
      const height = Number(obj.dict.get(PDFName.of('Height'))!.toString());
      expect(obj.dict.get(PDFName.of('ColorSpace'))?.toString()).toBe('/DeviceRGB');
      images.push({ width, height, pixels: inflateSync(Buffer.from(obj.contents)) });
    }
  }
  return images;
}

function countPixels(pixels: Buffer, test: (r: number, g: number, b: number) => boolean) {
  let n = 0;
  for (let i = 0; i + 2 < pixels.length; i += 3) if (test(pixels[i]!, pixels[i + 1]!, pixels[i + 2]!)) n++;
  return n;
}
const isRed = (r: number, g: number, b: number) => r > 150 && g < 90 && b < 90;
const isBlue = (r: number, g: number, b: number) => b > 150 && r < 90 && g < 120;
const isBlack = (r: number, g: number, b: number) => r < 10 && g < 10 && b < 10;

/** Asserts a recipient PDF holds nothing of the hidden content and nothing of the original file. */
async function expectNothingHidden(pdfBytes: Buffer, original: Buffer) {
  expect(pdfBytes.equals(original)).toBe(false);
  const content = pdfContent(pdfBytes);
  for (const secret of HIDDEN) {
    expect(content).not.toContain(secret);
    expect(content).not.toContain(hexOf(secret));
  }
  const pdf = await PDFDocument.load(pdfBytes, { updateMetadata: false });
  for (const field of [pdf.getTitle(), pdf.getSubject(), pdf.getAuthor(), pdf.getKeywords(), pdf.getCreator(), pdf.getProducer()]) {
    expect(field ?? '').not.toMatch(/SECRET/);
  }
  // Nothing but page images and the watermark: no annotations, forms, attachments, outline, XMP.
  for (const key of ['/Annots', '/AcroForm', '/EmbeddedFiles', '/Outlines', '/Metadata', '/JavaScript', '/OpenAction']) {
    expect(content).not.toContain(key);
  }
  const fonts = [...content.matchAll(/\/BaseFont\s*\/([A-Za-z-]+)/g)].map((m) => m[1]).sort();
  expect(fonts).toEqual(['Helvetica', 'Helvetica-Bold']); // the watermark only
  // Pixels: not one red (hidden) pixel left; the visible part is still there.
  const images = await imagesOf(pdfBytes);
  expect(images).toHaveLength(2);
  for (const img of images) expect(countPixels(img.pixels, isRed)).toBe(0);
  expect(countPixels(images[0]!.pixels, isBlue)).toBeGreaterThan(800 * 140);
  expect(countPixels(images[0]!.pixels, isBlack)).toBeGreaterThanOrEqual(800 * 150);
  expect(countPixels(images[1]!.pixels, isBlack)).toBeGreaterThanOrEqual(800 * 200);
}

describe('Smart Selective Encryption: redacted copies', () => {
  it('view and download hide every marked area: no hidden pixels, text, fonts or metadata; the original is untouched', async () => {
    const owner = await registerUser(ctx);
    const original = await secretPdf();
    const id = (await uploadDocument(ctx, owner, { file: original, title: 'Passport', claims: [{ label: 'Name', value: 'Reham Alkhamees' }, { label: 'National ID', value: '1029384756' }] })).json().document.id as string;
    const claims = await documentClaims(ctx, owner, id);
    const name = claims.find((c) => c.label === 'Name')!;

    const created = await createRedactedLink(owner, id, { claimIds: [name.id], allowDownload: true, redactions: REDACTIONS }, await browserRenderings());
    expect(created.statusCode, created.body).toBe(201);
    expect(created.json().link.fileMode).toBe('redacted');
    const token = (created.json().url as string).split('/s/')[1]!;

    const view = await ctx.app.inject({ method: 'GET', url: `/api/share/${token}`, remoteAddress: IPS.SA });
    expect(view.statusCode).toBe(200);
    expect(view.json().document).toMatchObject({ fileShared: true, fileMode: 'redacted', downloadAllowed: true });
    expect(view.json().fields).toEqual([{ label: 'Name', value: 'Reham Alkhamees', source: 'self_declared' }]);
    expect(view.body).not.toContain('1029384756');

    const file = await ctx.app.inject({ method: 'GET', url: `/api/share/${token}/file`, remoteAddress: IPS.SA });
    expect(file.statusCode).toBe(200);
    await expectNothingHidden(file.rawPayload, original);
    expect(pdfContent(file.rawPayload)).toContain(hexOf('Shared with: Example Company'));

    const dl = await ctx.app.inject({ method: 'GET', url: `/api/share/${token}/download`, remoteAddress: IPS.SA });
    expect(dl.statusCode).toBe(200);
    expect(dl.headers['content-disposition']).toMatch(/^attachment/);
    await expectNothingHidden(dl.rawPayload, original);
    expect(pdfContent(dl.rawPayload)).toContain(hexOf(`Copy ${dl.headers['x-trustpass-copy']}`));

    // The owner still has the exact original.
    expect((await as(ctx, owner, { method: 'GET', url: `/api/documents/${id}/file` })).rawPayload.equals(original)).toBe(true);
  });

  it('redacted pages are encrypted at rest with the document key, bound to their link and page', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { file: await secretPdf() })).json().document.id as string;
    const created = await createRedactedLink(owner, id, { redactions: REDACTIONS }, await browserRenderings());
    const linkId = created.json().link.id as string;
    const rows = await ctx.prisma.redactedPage.findMany({ where: { linkId }, orderBy: { pageIndex: 'asc' } });
    expect(rows).toHaveLength(2);
    const dek = await loadDataKey(ctx.app.deps, id);
    for (const row of rows) {
      const stored = await ctx.app.deps.storage.get(row.storageKey);
      expect(stored.subarray(1, 4).toString('latin1')).not.toBe('PNG'); // ciphertext, not an image
      expect(stored.includes(Buffer.from('IHDR'))).toBe(false);
      const page = decrypt(dek, { ciphertext: stored, iv: Buffer.from(row.encIv), tag: Buffer.from(row.encTag) }, redactedPageAad(id, linkId, row.pageIndex));
      const meta = await sharp(page).metadata();
      expect([meta.format, meta.width, meta.height]).toEqual(['png', 800, 600]);
      // Re-encoded without metadata: the EXIF text of page 2 is gone.
      expect(meta.exif).toBeUndefined();
      expect(page.includes(Buffer.from('SECRET'))).toBe(false);
      // Bound to its row: the same ciphertext does not open as another page.
      expect(() => decrypt(dek, { ciphertext: stored, iv: Buffer.from(row.encIv), tag: Buffer.from(row.encTag) }, redactedPageAad(id, linkId, row.pageIndex + 1))).toThrow();
    }
    dek.fill(0);
  });

  it('images are rendered and redacted on the server from the original; anything the browser sends is ignored', async () => {
    const owner = await registerUser(ctx);
    const photo = await sharp({ create: { width: 640, height: 480, channels: 3, background: '#ffffff' } })
      .composite([rect(0, 0, 640, 120, BLUE), rect(100, 300, 400, 120, RED)])
      .png()
      .toBuffer();
    const id = (await uploadDocument(ctx, owner, { file: photo, filename: 'id.png' })).json().document.id as string;
    const fakePage = await sharp({ create: { width: 640, height: 480, channels: 3, background: '#00ff00' } }).png().toBuffer();
    const created = await createRedactedLink(owner, id, { allowDownload: true, redactions: [{ page: 0, x: 0.15, y: 0.62, w: 0.65, h: 0.27 }] }, [fakePage]);
    expect(created.statusCode, created.body).toBe(201);
    const token = (created.json().url as string).split('/s/')[1]!;
    const dl = await ctx.app.inject({ method: 'GET', url: `/api/share/${token}/download`, remoteAddress: IPS.SA });
    const [img] = await imagesOf(dl.rawPayload);
    expect(countPixels(img!.pixels, isRed)).toBe(0);
    expect(countPixels(img!.pixels, isBlue)).toBeGreaterThan(640 * 110);
    expect(countPixels(img!.pixels, (r, g, b) => g > 200 && r < 60 && b < 60)).toBe(0); // the fake page was not used
  });

  it('view-only redacted links cannot be downloaded; details-only links send no file; full links keep the original', async () => {
    const owner = await registerUser(ctx);
    const original = await secretPdf();
    const id = (await uploadDocument(ctx, owner, { file: original })).json().document.id as string;
    const viewOnly = await createRedactedLink(owner, id, { allowDownload: false, redactions: REDACTIONS }, await browserRenderings());
    const t1 = (viewOnly.json().url as string).split('/s/')[1]!;
    expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${t1}/file`, remoteAddress: IPS.SA })).statusCode).toBe(200);
    const blocked = await ctx.app.inject({ method: 'GET', url: `/api/share/${t1}/download`, remoteAddress: IPS.SA });
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json().error.code).toBe('download_not_allowed');

    const full = await as(ctx, owner, {
      method: 'POST',
      url: `/api/documents/${id}/links`,
      payload: { includeFile: true, fileMode: 'original', recipientType: 'anyone', recipientLabel: 'Full', expiresIn: '24h', allowedCountries: [], claimIds: [] },
    });
    const t2 = (full.json().url as string).split('/s/')[1]!;
    expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${t2}`, remoteAddress: IPS.SA })).json().document.fileMode).toBe('original');
    // The full copy is the original content, watermarked (its text is still there).
    expect(pdfContent((await ctx.app.inject({ method: 'GET', url: `/api/share/${t2}/file`, remoteAddress: IPS.SA })).rawPayload)).toContain(hexOf('SECRET-NATIONAL-ID-1029384756'));
    expect(await ctx.prisma.redactedPage.count({ where: { linkId: full.json().link.id } })).toBe(0);
  });

  it('refuses incomplete or mismatched redacted copies, and stores nothing', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { file: await secretPdf() })).json().document.id as string;
    const pages = await browserRenderings();
    const square = await sharp({ create: { width: 600, height: 600, channels: 3, background: '#ffffff' } }).png().toBuffer();
    const cases: Array<[string, Record<string, unknown>, Buffer[]]> = [
      ['one page missing', { redactions: REDACTIONS }, [pages[0]!]],
      ['a page of the wrong shape', { redactions: REDACTIONS }, [pages[0]!, square]],
      ['no area marked', { redactions: [] }, pages],
      ['an area on a page that does not exist', { redactions: [{ page: 5, x: 0, y: 0, w: 0.5, h: 0.5 }] }, pages],
      ['an area outside the page', { redactions: [{ page: 0, x: 0.8, y: 0, w: 0.5, h: 0.5 }] }, pages],
      ['not an image', { redactions: REDACTIONS }, [Buffer.from('%PDF-1.7 not an image'), pages[1]!]],
      ['hidden areas without a redacted copy', { fileMode: 'original', redactions: REDACTIONS }, []],
    ];
    for (const [label, link, files] of cases) {
      const res = await createRedactedLink(owner, id, link, files);
      expect(res.statusCode, label).toBe(400);
    }
    expect(await ctx.prisma.sharingLink.count()).toBe(0);
    expect(await ctx.prisma.redactedPage.count()).toBe(0);
  });

  it('deleting the document destroys its redacted copies too', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { file: await secretPdf() })).json().document.id as string;
    const created = await createRedactedLink(owner, id, { redactions: REDACTIONS }, await browserRenderings());
    const token = (created.json().url as string).split('/s/')[1]!;
    const keys = (await ctx.prisma.redactedPage.findMany()).map((r) => r.storageKey);
    expect((await as(ctx, owner, { method: 'DELETE', url: `/api/documents/${id}` })).statusCode).toBe(200);
    expect(await ctx.prisma.redactedPage.count()).toBe(0);
    for (const key of keys) await expect(ctx.app.deps.storage.get(key)).rejects.toThrow();
    expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${token}/file`, remoteAddress: IPS.SA })).statusCode).toBe(410);
  });
});

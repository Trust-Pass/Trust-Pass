import { inflateSync } from 'node:zlib';
import { PDFDocument } from 'pdf-lib';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { as, createLink, createTestContext, IPS, registerUser, resetDatabase, samplePdf, samplePng, uploadDocument, type TestContext } from '../helpers';

/**
 * Owner controls added in the final round:
 *  - watermark control per link (on/off, style, colour, strength, stamp text), sealed at rest
 *  - the server-built preview of exactly what a recipient gets (never stored, never shared)
 *  - "Check encryption": a read-only proof of what is stored for a document
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

const MARK = 'OWNER-CONTROLS-BODY-TEXT';

/** Every Flate stream of a PDF decoded, plus the raw bytes: where drawn text can be found. */
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
const drawn = (pdf: Buffer, text: string) => pdfContent(pdf).includes(hexOf(text));
const fontsOf = (pdf: Buffer) => [...pdfContent(pdf).matchAll(/\/BaseFont\s*\/([A-Za-z-]+)/g)].map((m) => m[1]).sort();

async function fileLink(owner: Awaited<ReturnType<typeof registerUser>>, documentId: string, extra: Record<string, unknown> = {}) {
  return createLink(ctx, owner, documentId, { includeFile: true, allowDownload: true, recipientLabel: 'Example Company', ...extra });
}
const recipientFile = (token: string) => ctx.app.inject({ method: 'GET', url: `/api/share/${token}/file`, remoteAddress: IPS.SA });
const recipientDownload = (token: string) => ctx.app.inject({ method: 'GET', url: `/api/share/${token}/download`, remoteAddress: IPS.SA });

describe('Watermark control', () => {
  it('is on by default: view and download carry the stamp and the recipient name', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { file: await samplePdf(MARK) })).json().document.id as string;
    const link = await fileLink(owner, id);
    const view = await recipientFile(link.token);
    expect(view.statusCode).toBe(200);
    expect(drawn(view.rawPayload, 'CONFIDENTIAL')).toBe(true);
    expect(drawn(view.rawPayload, 'CONFIDENTIAL - Shared with: Example Company')).toBe(true);
    const dl = await recipientDownload(link.token);
    expect(drawn(dl.rawPayload, 'CONFIDENTIAL - Downloaded for: Example Company')).toBe(true);
    const shared = (await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA })).json();
    expect(shared.document.watermarked).toBe(true);
    expect(shared.notice).toMatch(/A watermark identifies this view/);
  });

  it('off: no watermark is drawn on the view or the download (no stamp, no bands, no fonts added)', async () => {
    const owner = await registerUser(ctx);
    const original = await samplePdf(MARK);
    const id = (await uploadDocument(ctx, owner, { file: original })).json().document.id as string;
    const link = await fileLink(owner, id, { watermark: { enabled: false } });

    const shared = (await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA })).json();
    expect(shared.document.watermarked).toBe(false);
    expect(shared.notice).toMatch(/chose no watermark/);

    for (const res of [await recipientFile(link.token), await recipientDownload(link.token)]) {
      expect(res.statusCode).toBe(200);
      expect(drawn(res.rawPayload, MARK)).toBe(true); // the document itself is there
      expect(drawn(res.rawPayload, 'CONFIDENTIAL')).toBe(false);
      expect(drawn(res.rawPayload, 'Shared with')).toBe(false);
      expect(drawn(res.rawPayload, 'Downloaded for')).toBe(false);
      // Only the original's own font: nothing was drawn on top.
      expect(fontsOf(res.rawPayload)).toEqual(['Helvetica']);
    }
    // Downloads stay logged and traceable by their reference, as the owner is told.
    const events = await ctx.prisma.securityEvent.findMany({ where: { linkId: link.id, eventType: 'recipient_downloaded' } });
    expect(events).toHaveLength(1);
    expect(events[0]!.metadata).toMatchObject({ watermark: false });
    // The owner's original is unchanged.
    expect((await as(ctx, owner, { method: 'GET', url: `/api/documents/${id}/file` })).rawPayload.equals(original)).toBe(true);
  });

  it('custom look: own stamp text, diagonal only, stronger; images are covered too', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { file: await samplePng(), filename: 'photo.png' })).json().document.id as string;
    const link = await fileLink(owner, id, { watermark: { enabled: true, style: 'diagonal', text: 'INTERNAL REVIEW', color: 'crimson', strength: 'strong' } });
    const view = await recipientFile(link.token);
    expect(view.statusCode).toBe(200);
    expect(drawn(view.rawPayload, 'INTERNAL REVIEW')).toBe(true);
    expect(drawn(view.rawPayload, 'CONFIDENTIAL')).toBe(false);
    expect(drawn(view.rawPayload, 'Shared with')).toBe(false); // diagonal only: no name bands
    expect(pdfContent(view.rawPayload)).toMatch(/\/ca 0\.26/); // the "strong" opacity
  });

  it('settings are sealed with the document key: the stamp text is not in the database in clear', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id as string;
    const link = await fileLink(owner, id, { watermark: { text: 'SEALED STAMP TEXT' } });
    const row = await ctx.prisma.sharingLink.findUniqueOrThrow({ where: { id: link.id } });
    expect(row.watermarkEnabled).toBe(true);
    expect(row.watermarkEncrypted).not.toBeNull();
    expect(Buffer.from(row.watermarkEncrypted!).toString('latin1')).not.toContain('SEALED STAMP TEXT');
    const dump = await ctx.prisma.$queryRawUnsafe<Array<{ t: string }>>(`SELECT row_to_json(s)::text AS t FROM sharing_links s`);
    expect(dump.map((r) => r.t).join('')).not.toContain('SEALED STAMP TEXT');
    const events = await ctx.prisma.securityEvent.findMany({ where: { linkId: link.id } });
    expect(JSON.stringify(events)).not.toContain('SEALED STAMP TEXT');
    // The owner sees their own settings.
    const detail = (await as(ctx, owner, { method: 'GET', url: `/api/links/${link.id}` })).json().link;
    expect(detail.watermark).toMatchObject({ enabled: true, text: 'SEALED STAMP TEXT', style: 'full' });
  });

  it('fails toward a watermark: flipping only the clear flag in the database does not remove it', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { file: await samplePdf(MARK) })).json().document.id as string;
    const link = await fileLink(owner, id);
    await ctx.prisma.sharingLink.update({ where: { id: link.id }, data: { watermarkEnabled: false } });
    expect(drawn((await recipientFile(link.token)).rawPayload, 'CONFIDENTIAL')).toBe(true);
    // A link made before watermark control (no sealed settings) keeps the standard watermark.
    await ctx.prisma.sharingLink.update({ where: { id: link.id }, data: { watermarkEnabled: true, watermarkEncrypted: null } });
    expect(drawn((await recipientFile(link.token)).rawPayload, 'CONFIDENTIAL - Shared with: Example Company')).toBe(true);
  });

  it('the owner can change it on an active link; it applies to the next view, and is logged', async () => {
    const owner = await registerUser(ctx);
    const stranger = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { file: await samplePdf(MARK) })).json().document.id as string;
    const link = await fileLink(owner, id);
    const off = { watermark: { enabled: false } };
    expect((await as(ctx, stranger, { method: 'PUT', url: `/api/links/${link.id}/watermark`, payload: off })).statusCode).toBe(404);
    const res = await as(ctx, owner, { method: 'PUT', url: `/api/links/${link.id}/watermark`, payload: off });
    expect(res.statusCode, res.body).toBe(200);
    expect(drawn((await recipientFile(link.token)).rawPayload, 'CONFIDENTIAL')).toBe(false);
    expect(await ctx.prisma.securityEvent.count({ where: { linkId: link.id, eventType: 'link_watermark_updated' } })).toBe(1);
    // Fields-only links have no file to watermark; revoked links cannot be changed.
    const fieldsOnly = await createLink(ctx, owner, id, { includeFile: false, claimIds: [] }).catch(() => null);
    expect(fieldsOnly).toBeNull(); // nothing to share: refused at creation already
    await as(ctx, owner, { method: 'POST', url: `/api/links/${link.id}/revoke` });
    expect((await as(ctx, owner, { method: 'PUT', url: `/api/links/${link.id}/watermark`, payload: off })).statusCode).toBe(409);
  });

  it('refuses stamp text the PDF fonts cannot draw, and unknown styles', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id as string;
    for (const watermark of [{ text: 'سري' }, { text: 'X'.repeat(25) }, { style: 'sideways' }, { color: 'pink' }]) {
      const res = await as(ctx, owner, {
        method: 'POST',
        url: `/api/documents/${id}/links`,
        payload: { includeFile: true, recipientType: 'anyone', recipientLabel: 'A', expiresIn: '24h', allowedCountries: [], claimIds: [], watermark },
      });
      expect(res.statusCode, JSON.stringify(watermark)).toBe(400);
    }
    expect(await ctx.prisma.sharingLink.count()).toBe(0);
  });
});

describe('Recipient copy preview', () => {
  it('builds exactly the recipient copy in memory: nothing is created, logged as access, or stored', async () => {
    const owner = await registerUser(ctx);
    const stranger = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { file: await samplePdf(MARK) })).json().document.id as string;
    const objectsBefore = await ctx.prisma.storedObject.count().catch(() => null);
    const body = { fileMode: 'original', recipientLabel: 'Example Company', watermark: { text: 'PREVIEW STAMP' } };

    const res = await as(ctx, owner, { method: 'POST', url: `/api/documents/${id}/links/preview`, payload: body });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['cache-control']).toBe('no-store, private');
    expect(drawn(res.rawPayload, MARK)).toBe(true);
    expect(drawn(res.rawPayload, 'PREVIEW STAMP - Shared with: Example Company')).toBe(true);
    expect((await PDFDocument.load(res.rawPayload)).getPageCount()).toBe(1);

    const off = await as(ctx, owner, { method: 'POST', url: `/api/documents/${id}/links/preview`, payload: { watermark: { enabled: false } } });
    expect(drawn(off.rawPayload, 'Shared with')).toBe(false);

    const dl = await as(ctx, owner, { method: 'POST', url: `/api/documents/${id}/links/preview`, payload: { copy: 'download' } });
    expect(drawn(dl.rawPayload, 'Copy PREVIEW')).toBe(true);

    expect((await as(ctx, stranger, { method: 'POST', url: `/api/documents/${id}/links/preview`, payload: body })).statusCode).toBe(404);
    expect((await ctx.app.inject({ method: 'POST', url: `/api/documents/${id}/links/preview`, payload: body })).statusCode).toBe(401);

    expect(await ctx.prisma.sharingLink.count()).toBe(0);
    expect(await ctx.prisma.accessLog.count()).toBe(0);
    expect(await ctx.prisma.redactedPage.count()).toBe(0);
    if (objectsBefore !== null) expect(await ctx.prisma.storedObject.count()).toBe(objectsBefore);
  });
});

describe('Check encryption', () => {
  it('proves the stored object is AES-256-GCM ciphertext that authenticates and matches the sealed hash', async () => {
    const owner = await registerUser(ctx);
    const stranger = await registerUser(ctx);
    const file = await samplePdf(MARK);
    const id = (await uploadDocument(ctx, owner, { file, title: 'Contract', claims: [{ label: 'Salary', value: '25000' }] })).json().document.id as string;

    const res = await as(ctx, owner, { method: 'POST', url: `/api/documents/${id}/encryption-check` });
    expect(res.statusCode, res.body).toBe(200);
    const check = res.json().check;
    expect(check).toMatchObject({
      ok: true,
      file: { algorithm: 'AES-256-GCM', keyBits: 256, ivBytes: 12, tagBytes: 16, authenticated: true, sha256Matches: true, storedLooksLikePlainFile: false, originalBytes: file.length },
      key: { perDocument: true, wrapping: 'AES-256-GCM', provider: 'env' },
      metadata: { titleEncrypted: true, sha256Encrypted: true, fieldLabelsEncrypted: 1, fields: 1 },
    });
    expect(check.key.providerLabel).toMatch(/Google Cloud KMS is not active/);
    expect(check.file.sha256).toBe((await import('node:crypto')).createHash('sha256').update(file).digest('hex'));
    // The response says how it was checked, never what is in the file.
    expect(res.body).not.toContain(MARK);
    expect(res.body).not.toContain('25000');
    expect(await ctx.prisma.securityEvent.count({ where: { documentId: id, eventType: 'document_encryption_checked' } })).toBe(1);

    expect((await as(ctx, stranger, { method: 'POST', url: `/api/documents/${id}/encryption-check` })).statusCode).toBe(404);
    expect((await ctx.app.inject({ method: 'POST', url: `/api/documents/${id}/encryption-check` })).statusCode).toBe(401);
  });

  it('reports a failure, and alerts, when one stored byte was changed', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { file: await samplePdf(MARK) })).json().document.id as string;
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id } });
    const stored = Buffer.from(await ctx.app.deps.storage.get(doc.storageKey));
    stored[20]! ^= 0x01;
    await ctx.app.deps.storage.put(doc.storageKey, stored);

    const res = await as(ctx, owner, { method: 'POST', url: `/api/documents/${id}/encryption-check` });
    expect(res.statusCode).toBe(200);
    expect(res.json().check).toMatchObject({ ok: false, file: { authenticated: false, sha256Matches: false, sha256: null } });
    expect(await ctx.prisma.securityEvent.count({ where: { documentId: id, eventType: 'integrity_check_failed' } })).toBe(1);
  });
});

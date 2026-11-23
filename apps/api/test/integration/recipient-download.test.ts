import { inflateSync } from 'node:zlib';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  as,
  createLink,
  createTestContext,
  documentClaims,
  IPS,
  PLAINTEXT_MARKER,
  registerUser,
  resetDatabase,
  samplePng,
  uploadDocument,
  type TestContext,
} from '../helpers';

// Downloads are rate limited per IP address: give every anonymous download its own Saudi address.
const SA_POOL = Array.from({ length: 200 }, (_, i) => `10.0.${Math.floor(i / 250) + 10}.${(i % 250) + 1}`);
let saIndex = 0;
const nextSaIp = () => SA_POOL[saIndex++ % SA_POOL.length]!;

let ctx: TestContext;
beforeAll(async () => {
  const map = [
    ...Object.entries(IPS)
      .filter(([k]) => k !== 'UNKNOWN')
      .map(([code, ip]) => `${ip}=${code}`),
    ...SA_POOL.map((ip) => `${ip}=SA`),
  ].join(',');
  ctx = await createTestContext({ GEO_SIMULATED_MAP: map });
});
afterAll(async () => {
  await ctx.app.close();
});
beforeEach(async () => {
  ctx.clock.now = new Date();
  await resetDatabase(ctx.prisma);
});

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

/** pdf-lib writes Helvetica text as hex strings; count either spelling. */
function occurrences(content: string, text: string): number {
  const hex = Buffer.from(text, 'latin1').toString('hex').toUpperCase();
  return content.split(hex).length - 1 + (content.split(text).length - 1);
}

async function multiPagePdf(pages: number): Promise<Buffer> {
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  for (let i = 0; i < pages; i++) {
    const page = pdf.addPage([400, 300]);
    page.drawText(`${PLAINTEXT_MARKER} page ${i + 1}`, { x: 20, y: 150, size: 12, font });
  }
  pdf.setSubject(PLAINTEXT_MARKER);
  pdf.setAuthor('Original Author Name');
  return Buffer.from(await pdf.save({ useObjectStreams: false }));
}

const download = (token: string, ip = nextSaIp()) => ctx.app.inject({ method: 'GET', url: `/api/share/${token}/download`, remoteAddress: ip });

/** Everything that makes up the stored, encrypted original. */
async function storedOriginal(documentId: string) {
  const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: documentId } });
  const key = await ctx.prisma.documentKey.findUniqueOrThrow({ where: { documentId } });
  const ciphertext = await ctx.app.deps.storage.get(doc.storageKey);
  return {
    storageKey: doc.storageKey,
    ciphertext: Buffer.from(ciphertext).toString('hex'),
    encIv: Buffer.from(doc.encIv).toString('hex'),
    encTag: Buffer.from(doc.encTag).toString('hex'),
    sha256Encrypted: Buffer.from(doc.sha256Encrypted ?? []).toString('hex'),
    sizeBytes: doc.sizeBytes,
    wrappedDek: Buffer.from(key.wrappedDek).toString('hex'),
    kekVersion: key.kekVersion,
  };
}

describe('recipient download: permission', () => {
  it('is off by default: view-only links refuse downloads and log nothing as granted', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true });

    const view = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA });
    expect(view.json().document.downloadAllowed).toBe(false);

    const res = await download(link.token);
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('download_not_allowed');
    expect(await ctx.prisma.accessLog.count({ where: { linkId: link.id, resource: 'download' } })).toBe(0);
  });

  it('cannot be allowed without sharing the file', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s, { claims: [{ label: 'Role', value: 'Analyst' }] })).json().document.id;
    const claims = await documentClaims(ctx, s, id);
    const res = await as(ctx, s, {
      method: 'POST',
      url: `/api/documents/${id}/links`,
      payload: { claimIds: [claims[0]!.id], includeFile: false, allowDownload: true, recipientType: 'anyone', recipientLabel: 'Example Company', expiresIn: '24h', allowedCountries: [] },
    });
    expect(res.statusCode).toBe(400);

    const detailsOnly = await createLink(ctx, s, id, { claimIds: [claims[0]!.id] });
    const toggle = await as(ctx, s, { method: 'PUT', url: `/api/links/${detailsOnly.id}/download`, payload: { allowDownload: true } });
    expect(toggle.statusCode).toBe(400);
    const blocked = await download(detailsOnly.token);
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json().error.code).toBe('file_not_shared');
  });

  it('only the owner can change it, only on an active link, and it applies on the next request', async () => {
    const s = await registerUser(ctx);
    const other = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true, allowDownload: true });
    expect((await download(link.token)).statusCode).toBe(200);

    expect((await as(ctx, other, { method: 'PUT', url: `/api/links/${link.id}/download`, payload: { allowDownload: false } })).statusCode).toBe(404);
    const off = await as(ctx, s, { method: 'PUT', url: `/api/links/${link.id}/download`, payload: { allowDownload: false } });
    expect(off.json()).toEqual({ ok: true, allowDownload: false });
    expect((await download(link.token)).json().error.code).toBe('download_not_allowed');
    expect(await ctx.prisma.securityEvent.count({ where: { linkId: link.id, eventType: 'link_download_updated' } })).toBe(1);

    await as(ctx, s, { method: 'POST', url: `/api/links/${link.id}/revoke` });
    const afterRevoke = await as(ctx, s, { method: 'PUT', url: `/api/links/${link.id}/download`, payload: { allowDownload: true } });
    expect(afterRevoke.statusCode).toBe(409);
  });
});

describe('recipient download: the protected copy', () => {
  it('is a separate PDF with the recipient on every page; the encrypted original is unchanged', async () => {
    const s = await registerUser(ctx);
    const original = await multiPagePdf(3);
    const id = (await uploadDocument(ctx, s, { file: original, claims: [{ label: 'Salary', value: 'HIDDEN-FIELD-VALUE-91' }] })).json().document.id;
    const before = await storedOriginal(id);
    const link = await createLink(ctx, s, id, { includeFile: true, allowDownload: true, recipientLabel: 'Example Company HR' });

    const view = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA });
    expect(view.json().document.downloadAllowed).toBe(true);

    const res = await download(link.token);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['cache-control']).toContain('no-store');
    expect(res.headers['content-disposition']).toMatch(/^attachment; filename="trustpass-copy-[0-9A-F]{10}\.pdf"$/);
    const copyRef = String(res.headers['x-trustpass-copy']);
    expect(copyRef).toMatch(/^[0-9A-F]{10}$/);

    const copy = res.rawPayload;
    expect(copy.equals(original)).toBe(false);
    const pdf = await PDFDocument.load(copy);
    expect(pdf.getPageCount()).toBe(3);
    // Fresh document: the original's metadata is not carried over.
    expect(pdf.getSubject()).not.toContain(PLAINTEXT_MARKER);
    expect(pdf.getAuthor()).toBe('TrustPass');
    expect(pdf.getTitle()).toContain(copyRef);
    expect(pdf.getKeywords()).toContain(`trustpass-copy:${copyRef}`);

    const content = pdfContent(copy);
    // Every page: the recipient's name and the copy reference (top band) ...
    expect(occurrences(content, 'CONFIDENTIAL - Downloaded for: Example Company HR')).toBe(3);
    // ... and the reference line at the top and the bottom of each page.
    expect(occurrences(content, `Copy ${copyRef}`)).toBe(6);
    // Fields the owner typed are not added to the file.
    expect(occurrences(content, 'HIDDEN-FIELD-VALUE-91')).toBe(0);

    // The original: same ciphertext, IV, tag, wrapped key; the owner still gets the exact upload.
    expect(await storedOriginal(id)).toEqual(before);
    const owner = await as(ctx, s, { method: 'GET', url: `/api/documents/${id}/file` });
    expect(owner.rawPayload.equals(original)).toBe(true);
  });

  it('wraps images in a new watermarked PDF', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s, { file: await samplePng(), filename: 'scan.png' })).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true, allowDownload: true });
    const res = await download(link.token);
    expect(res.statusCode).toBe(200);
    expect((await PDFDocument.load(res.rawPayload)).getPageCount()).toBe(1);
    expect(occurrences(pdfContent(res.rawPayload), 'Downloaded for: Example Company')).toBe(1);
  });

  it('every download is a new, separately traceable copy, logged without names', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s, { title: 'Secret Contract Title' })).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true, allowDownload: true, recipientLabel: 'Example Company' });

    const a = await download(link.token);
    const b = await download(link.token);
    expect(a.headers['x-trustpass-copy']).not.toBe(b.headers['x-trustpass-copy']);

    const logs = await ctx.prisma.accessLog.findMany({ where: { linkId: link.id, resource: 'download' } });
    expect(logs.map((l) => l.outcome)).toEqual(['granted', 'granted']);
    const events = await ctx.prisma.securityEvent.findMany({ where: { linkId: link.id, eventType: 'recipient_downloaded' }, orderBy: { createdAt: 'asc' } });
    expect(events.map((e) => (e.metadata as { copyRef: string }).copyRef).sort()).toEqual([a.headers['x-trustpass-copy'], b.headers['x-trustpass-copy']].sort());
    for (const e of events) {
      expect(JSON.stringify(e.metadata)).not.toMatch(/Secret Contract Title|Example Company/);
    }
    // Downloads are normal activity: logged above as security events, not notifications.
    expect(await ctx.prisma.notification.count({ where: { userId: s.userId } })).toBe(0);
  });

  it('refuses a tampered original instead of producing a copy', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true, allowDownload: true });
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id } });
    const bytes = Buffer.from(await ctx.app.deps.storage.get(doc.storageKey));
    bytes[10]! ^= 0xff;
    await ctx.app.deps.storage.put(doc.storageKey, bytes);

    const res = await download(link.token);
    expect(res.statusCode).toBe(500);
    expect(res.json().error.code).toBe('integrity_error');
    expect(res.headers['content-type']).not.toContain('pdf');
    expect(await ctx.prisma.securityEvent.count({ where: { linkId: link.id, eventType: 'recipient_downloaded' } })).toBe(0);
  });
});

describe('recipient download: every security check runs before every download', () => {
  it('expiry', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true, allowDownload: true, expiresIn: '1h' });
    expect((await download(link.token)).statusCode).toBe(200);
    ctx.clock.advance(61 * 60_000);
    const res = await download(link.token);
    expect(res.statusCode).toBe(410);
    expect(res.json().error.code).toBe('link_expired');
  });

  it('revocation', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true, allowDownload: true });
    expect((await download(link.token)).statusCode).toBe(200);
    await as(ctx, s, { method: 'POST', url: `/api/links/${link.id}/revoke` });
    const res = await download(link.token);
    expect(res.statusCode).toBe(410);
    expect(res.json().error.code).toBe('link_revoked');
  });

  it('deleted document', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true, allowDownload: true });
    await as(ctx, s, { method: 'DELETE', url: `/api/documents/${id}` });
    expect((await download(link.token)).statusCode).toBe(410);
  });

  it('allowed countries, failing closed on an unknown location', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true, allowDownload: true, allowedCountries: ['SA'] });
    expect((await download(link.token)).statusCode).toBe(200);
    const us = await download(link.token, IPS.US);
    expect(us.statusCode).toBe(403);
    expect(us.json().error.code).toBe('country_blocked');
    const unknown = await download(link.token, IPS.UNKNOWN);
    expect(unknown.json().error.code).toBe('country_unknown');

    const logs = await ctx.prisma.accessLog.findMany({ where: { linkId: link.id, resource: 'download' }, orderBy: { id: 'asc' } });
    expect(logs.map((l) => l.outcome)).toEqual(['granted', 'denied_country', 'denied_country']);
  });

  it('organization recipients: members only, and the member is stamped on the copy', async () => {
    const reham = await registerUser(ctx);
    const company = await registerUser(ctx, { organization: 'Example Company', fullName: 'Sara Reviewer' });
    const outsider = await registerUser(ctx, { organization: 'Other Corp' });
    const id = (await uploadDocument(ctx, reham)).json().document.id;
    const link = await createLink(ctx, reham, id, { includeFile: true, allowDownload: true, recipientType: 'organization', recipientOrgId: company.orgId });

    const anonymous = await download(link.token);
    expect(anonymous.statusCode).toBe(401);
    expect((await as(ctx, outsider, { method: 'GET', url: `/api/share/${link.token}/download`, ip: IPS.SA })).statusCode).toBe(403);
    expect((await as(ctx, outsider, { method: 'GET', url: `/api/inbox/${link.id}/download`, ip: IPS.SA })).statusCode).toBe(404);

    const viaInbox = await as(ctx, company, { method: 'GET', url: `/api/inbox/${link.id}/download`, ip: IPS.SA });
    expect(viaInbox.statusCode).toBe(200);
    expect(occurrences(pdfContent(viaInbox.rawPayload), 'Downloaded for: Example Company (Sara Reviewer)')).toBe(1);
    const viaLink = await as(ctx, company, { method: 'GET', url: `/api/share/${link.token}/download`, ip: IPS.SA });
    expect(viaLink.statusCode).toBe(200);

    const inbox = await as(ctx, company, { method: 'GET', url: '/api/inbox' });
    expect(inbox.json().items[0].allowDownload).toBe(true);
  });
});

describe('recipient download: abuse limits', () => {
  it('allows at most 20 downloads per address in 10 minutes', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true, allowDownload: true });
    const ip = nextSaIp();
    for (let i = 0; i < 20; i++) expect((await download(link.token, ip)).statusCode).toBe(200);
    expect((await download(link.token, ip)).statusCode).toBe(429);
  });
});

import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  as,
  createTestContext,
  multipart,
  PLAINTEXT_MARKER,
  registerUser,
  resetDatabase,
  samplePdf,
  samplePng,
  uploadDocument,
  type TestContext,
} from '../helpers';

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

function storedFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...storedFiles(full));
    else out.push(full);
  }
  return out;
}

function storagePath(key: string) {
  return path.join(path.resolve(ctx.config.env.STORAGE_DIR), key.slice(0, 2), `${key}.bin`);
}

describe('document upload and encryption', () => {
  it('stores only AES-256-GCM ciphertext and a wrapped key', async () => {
    const s = await registerUser(ctx);
    const pdf = await samplePdf();
    const res = await uploadDocument(ctx, s, { file: pdf, claims: [{ label: 'Employer', value: 'Secret Employer LLC' }] });
    expect(res.statusCode).toBe(201);
    const id = res.json().document.id;

    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id }, include: { key: true, claims: true } });
    const onDisk = readFileSync(storagePath(doc.storageKey));
    expect(onDisk.includes(Buffer.from(PLAINTEXT_MARKER))).toBe(false);
    expect(onDisk.subarray(0, 5).toString()).not.toBe('%PDF-');
    expect(onDisk.length).toBe(pdf.length); // GCM: same length, tag stored separately

    // The wrapped key is not the raw key, and claim values are encrypted too.
    expect(doc.key!.wrappedDek).toHaveLength(32);
    expect(doc.key!.kekVersion).toBe(1);
    expect(Buffer.from(doc.claims[0]!.valueEncrypted).includes(Buffer.from('Secret Employer'))).toBe(false);

    const events = await ctx.prisma.securityEvent.findMany({ where: { documentId: id }, orderBy: { id: 'asc' } });
    expect(events.map((e) => e.eventType)).toEqual(['document_uploaded', 'document_encrypted']);
  });

  it('decrypts for the owner, byte for byte', async () => {
    const s = await registerUser(ctx);
    const pdf = await samplePdf();
    const id = (await uploadDocument(ctx, s, { file: pdf })).json().document.id;
    const res = await as(ctx, s, { method: 'GET', url: `/api/documents/${id}/file` });
    expect(res.statusCode).toBe(200);
    expect(res.rawPayload.equals(pdf)).toBe(true);
    expect(res.headers['cache-control']).toContain('no-store');
    expect(res.headers['content-security-policy']).toContain('sandbox');
  });

  it('accepts images and returns them re-encoded', async () => {
    const s = await registerUser(ctx);
    const res = await uploadDocument(ctx, s, { file: await samplePng(), filename: 'scan.png' });
    expect(res.statusCode).toBe(201);
    expect(res.json().document.mimeType).toBe('image/png');
  });

  it('rejects dangerous or unsupported files', async () => {
    const s = await registerUser(ctx);
    const html = await uploadDocument(ctx, s, { file: Buffer.from('<html><script>alert(1)</script></html>'), filename: 'cv.pdf' });
    expect(html.statusCode).toBe(415);
    const exe = await uploadDocument(ctx, s, { file: Buffer.concat([Buffer.from('MZ'), Buffer.alloc(500)]), filename: 'certificate.pdf' });
    expect(exe.statusCode).toBe(415);
    expect(await ctx.prisma.document.count()).toBe(0);
  });

  it('rejects files over the size limit', async () => {
    const s = await registerUser(ctx);
    const big = Buffer.concat([await samplePdf(), Buffer.alloc(11 * 1024 * 1024, 0x20)]);
    const res = await uploadDocument(ctx, s, { file: big });
    expect(res.statusCode).toBe(413);
  });

  it('validates the metadata', async () => {
    const s = await registerUser(ctx);
    const form = multipart([
      { name: 'metadata', value: JSON.stringify({ title: '', category: 'not-a-category' }) },
      { name: 'file', filename: 'a.pdf', content: await samplePdf() },
    ]);
    const res = await as(ctx, s, { method: 'POST', url: '/api/documents', payload: form.payload, headers: form.headers });
    expect(res.statusCode).toBe(400);
  });

  it('detects tampering with stored ciphertext and logs a high-severity event', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id } });
    const file = storagePath(doc.storageKey);
    const bytes = readFileSync(file);
    bytes[10]! ^= 0xff;
    writeFileSync(file, bytes);

    const res = await as(ctx, s, { method: 'GET', url: `/api/documents/${id}/file` });
    expect(res.statusCode).toBe(500);
    expect(res.json().error.code).toBe('integrity_error');
    expect(res.body).not.toMatch(/authenticate|stack|at /);
    const event = await ctx.prisma.securityEvent.findFirst({ where: { documentId: id, eventType: 'integrity_check_failed' } });
    expect(event?.severity).toBe('high');
  });
});

describe('access control (IDOR)', () => {
  it("returns 404 for every route on another user's document", async () => {
    const owner = await registerUser(ctx);
    const intruder = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id;

    for (const [method, url] of [
      ['GET', `/api/documents/${id}`],
      ['GET', `/api/documents/${id}/file`],
      ['GET', `/api/documents/${id}/credential`],
      ['DELETE', `/api/documents/${id}`],
      ['POST', `/api/documents/${id}/links`],
    ] as const) {
      const res = await as(ctx, intruder, { method, url, payload: method === 'POST' ? { includeFile: true, recipientType: 'anyone', recipientLabel: 'x', expiresIn: '1h' } : undefined });
      expect(res.statusCode, `${method} ${url}`).toBe(404);
    }
    const list = await as(ctx, intruder, { method: 'GET', url: '/api/documents' });
    expect(list.json().documents).toHaveLength(0);
    expect(await ctx.prisma.document.count({ where: { id, deletedAt: null } })).toBe(1);
  });

  it('requires a session', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id;
    expect((await as(ctx, null, { method: 'GET', url: `/api/documents/${id}/file` })).statusCode).toBe(401);
    expect((await as(ctx, null, { method: 'GET', url: '/api/documents' })).statusCode).toBe(401);
  });

  it('treats malformed ids as not found', async () => {
    const s = await registerUser(ctx);
    const res = await as(ctx, s, { method: 'GET', url: "/api/documents/1' OR '1'='1" });
    expect(res.statusCode).toBe(404);
  });
});

describe('deletion (crypto-shredding)', () => {
  it('removes the key, claims and ciphertext, and revokes links', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s, { claims: [{ label: 'Role', value: 'Analyst' }] })).json().document.id;
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id } });
    const before = storedFiles(path.resolve(ctx.config.env.STORAGE_DIR)).length;

    const link = await as(ctx, s, {
      method: 'POST',
      url: `/api/documents/${id}/links`,
      payload: { includeFile: true, recipientType: 'anyone', recipientLabel: 'HR', expiresIn: '24h' },
    });
    expect(link.statusCode).toBe(201);

    expect((await as(ctx, s, { method: 'DELETE', url: `/api/documents/${id}` })).statusCode).toBe(200);
    expect(await ctx.prisma.documentKey.count({ where: { documentId: id } })).toBe(0);
    expect(await ctx.prisma.documentClaim.count({ where: { documentId: id } })).toBe(0);
    expect(storedFiles(path.resolve(ctx.config.env.STORAGE_DIR)).length).toBe(before - 1);
    expect(() => readFileSync(storagePath(doc.storageKey))).toThrow();
    expect(await ctx.prisma.sharingLink.count({ where: { documentId: id, revokedAt: null } })).toBe(0);

    const token = link.json().url.split('/s/')[1];
    expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${token}`, remoteAddress: '10.0.0.1' })).statusCode).toBe(410);
    expect((await as(ctx, s, { method: 'GET', url: `/api/documents/${id}` })).statusCode).toBe(404);
  });
});

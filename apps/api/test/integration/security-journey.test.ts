import { inflateSync } from 'node:zlib';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { as, createLink, createTestContext, documentClaims, IPS, registerUser, resetDatabase, samplePdf, uploadDocument, type TestContext } from '../helpers';

/**
 * The whole secure-sharing journey in one test, against the real server, database and
 * encryption: the sender uploads, the file is stored only as AES-256-GCM ciphertext, the sender
 * shares one field and the file with one organization, the recipient signs in, is authorized and
 * receives the decrypted content, and everyone else is refused at every step.
 */

const MARK = 'zqjourneycanary7f3a';
const HIDDEN = 'zqhiddensalary9b1c';
const hex = (s: string) => Buffer.from(s, 'latin1').toString('hex').toUpperCase();

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
const hasText = (pdf: Buffer, text: string) => {
  const c = pdfContent(pdf);
  return c.includes(text) || c.includes(hex(text));
};

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestContext({ STORAGE_DRIVER: 'database' }); // production's storage driver
});
afterAll(async () => {
  await ctx.app.close();
});
beforeEach(async () => {
  ctx.clock.now = new Date();
  await resetDatabase(ctx.prisma);
});

describe('end-to-end secure sharing journey', () => {
  it('upload → encrypted at rest → share → recipient signs in, is authorized and decrypts → everyone else refused', async () => {
    // 1. The sender uploads a PDF that contains a marker, with one field to share and one to keep.
    const sender = await registerUser(ctx, { fullName: 'Reham Alkhamees' });
    const file = await samplePdf(MARK);
    expect(hasText(file, MARK), 'precondition: the marker is in the plaintext file').toBe(true);
    const upload = await uploadDocument(ctx, sender, {
      file,
      title: 'Employment letter',
      claims: [
        { label: 'Job title', value: 'Security Analyst' },
        { label: 'Salary', value: HIDDEN },
      ],
    });
    expect(upload.statusCode).toBe(201);
    const documentId = upload.json().document.id as string;

    // 2. At rest: only ciphertext. Every stored object is AES-256-GCM output, no PDF header, no marker
    //    (raw or hex), and no field value anywhere in the database.
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: documentId } });
    const stored = await ctx.prisma.storedObject.findUniqueOrThrow({ where: { key: doc.storageKey } });
    const cipher = Buffer.from(stored.data);
    expect(cipher.length).toBeGreaterThanOrEqual(file.length);
    expect(cipher.subarray(0, 5).toString('latin1')).not.toBe('%PDF-');
    expect(cipher.includes(Buffer.from(MARK))).toBe(false);
    expect(cipher.toString('hex').toUpperCase().includes(hex(MARK))).toBe(false);
    expect(cipher.equals(file)).toBe(false);
    const tables = await ctx.prisma.$queryRaw<Array<{ table_name: string }>>`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name <> '_prisma_migrations'`;
    for (const { table_name } of tables) {
      for (const secret of [MARK, HIDDEN, 'Security Analyst']) {
        // table_name comes from information_schema, not from user input.
        const rows = await ctx.prisma.$queryRawUnsafe<Array<{ hits: bigint }>>(
          `SELECT count(*)::bigint AS hits FROM "${table_name}" x WHERE x::text ILIKE $1 OR x::text ILIKE $2`,
          `%${secret}%`,
          `%${Buffer.from(secret).toString('hex')}%`,
        );
        expect(Number(rows[0]!.hits), `"${secret}" stored in clear in ${table_name}`).toBe(0);
      }
    }

    // The sender decrypts the original byte for byte.
    const original = await as(ctx, sender, { method: 'GET', url: `/api/documents/${documentId}/file` });
    expect(original.statusCode).toBe(200);
    expect(original.rawPayload.equals(file)).toBe(true);

    // 3. The sender shares ONE field and the file (download allowed) with one organization.
    const company = await registerUser(ctx, { organization: 'Example Company', fullName: 'Sara Reviewer' });
    const outsider = await registerUser(ctx, { organization: 'Other Corp' });
    const stranger = await registerUser(ctx);
    const jobTitle = (await documentClaims(ctx, sender, documentId)).find((c) => c.label === 'Job title')!;
    const link = await createLink(ctx, sender, documentId, {
      claimIds: [jobTitle.id],
      includeFile: true,
      allowDownload: true,
      recipientType: 'organization',
      recipientOrgId: company.orgId,
    });

    // 4. Unauthorized: no session, another organization, another user, a made-up link, other routes.
    const anonymous = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA });
    expect(anonymous.statusCode).toBe(401);
    expect(anonymous.body).not.toContain('Security Analyst');
    for (const who of [outsider, stranger]) {
      for (const path of ['', '/file', '/download']) {
        const res = await as(ctx, who, { method: 'GET', url: `/api/share/${link.token}${path}`, ip: IPS.SA });
        expect(res.statusCode, `${path || 'view'} for a non-member`).toBe(403);
        expect(res.body).not.toContain('Security Analyst');
        expect(res.rawPayload.includes(Buffer.from('%PDF-'))).toBe(false);
      }
      expect([403, 404]).toContain((await as(ctx, who, { method: 'GET', url: `/api/inbox/${link.id}`, ip: IPS.SA })).statusCode);
      expect((await as(ctx, who, { method: 'GET', url: `/api/documents/${documentId}/file` })).statusCode).toBe(404);
    }
    const forged = `${link.token.slice(0, -2)}${link.token.endsWith('AA') ? 'BB' : 'AA'}`;
    expect((await as(ctx, company, { method: 'GET', url: `/api/share/${forged}`, ip: IPS.SA })).statusCode).toBe(404);

    // 5. The authorized recipient signs in and sees exactly the shared field, verified, nothing else.
    const view = await as(ctx, company, { method: 'GET', url: `/api/share/${link.token}`, ip: IPS.SA });
    expect(view.statusCode).toBe(200);
    expect(view.json().fields).toEqual([{ label: 'Job title', value: 'Security Analyst', source: 'self_declared' }]);
    expect(view.body).not.toContain(HIDDEN);
    expect(view.body).not.toContain('Salary');

    // 6. ...and receives the decrypted document as a watermarked copy naming them: the original page
    //    text is there (decryption worked), the recipient's name is stamped, the bytes differ.
    const viewCopy = await as(ctx, company, { method: 'GET', url: `/api/share/${link.token}/file`, ip: IPS.SA });
    expect(viewCopy.statusCode).toBe(200);
    expect(viewCopy.headers['content-type']).toBe('application/pdf');
    expect(hasText(viewCopy.rawPayload, MARK), 'decrypted page content reaches the recipient').toBe(true);
    const download = await as(ctx, company, { method: 'GET', url: `/api/inbox/${link.id}/download`, ip: IPS.SA });
    expect(download.statusCode).toBe(200);
    expect(hasText(download.rawPayload, MARK)).toBe(true);
    expect(hasText(download.rawPayload, 'Example Company (Sara Reviewer)')).toBe(true);
    expect(download.rawPayload.equals(file)).toBe(false);

    // 7. Tampering with one stored byte is detected: no content for anyone.
    const bytes = Buffer.from(stored.data);
    bytes[24]! ^= 0x01;
    await ctx.prisma.storedObject.update({ where: { key: doc.storageKey }, data: { data: new Uint8Array(bytes) } });
    const tampered = await as(ctx, company, { method: 'GET', url: `/api/share/${link.token}/file`, ip: IPS.SA });
    expect(tampered.statusCode).toBe(500);
    expect(tampered.json().error.code).toBe('integrity_error');
    expect(hasText(tampered.rawPayload, MARK)).toBe(false);
    await ctx.prisma.storedObject.update({ where: { key: doc.storageKey }, data: { data: new Uint8Array(stored.data) } });

    // 8. The sender revokes: the recipient is refused at once, on every route.
    const revoke = await as(ctx, sender, { method: 'POST', url: `/api/links/${link.id}/revoke` });
    expect(revoke.statusCode).toBe(200);
    for (const path of ['', '/file', '/download']) {
      const res = await as(ctx, company, { method: 'GET', url: `/api/share/${link.token}${path}`, ip: IPS.SA });
      expect(res.statusCode, `${path || 'view'} after revoke`).toBe(410);
      expect(res.rawPayload.includes(Buffer.from('%PDF-'))).toBe(false);
    }

    // Every attempt is in the sender's log: granted for the member, refused for the rest.
    const outcomes = (await ctx.prisma.accessLog.findMany({ where: { linkId: link.id } })).map((l) => l.outcome);
    expect(outcomes).toContain('granted');
    expect(outcomes).toContain('denied_recipient');
    expect(outcomes).toContain('denied_revoked');
  });
});

import { PDFDocument } from 'pdf-lib';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  as,
  createTestContext,
  issueCredential,
  loginUser,
  makeAdmin,
  multipart,
  registerUser,
  resetDatabase,
  samplePdf,
  type Session,
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

async function verifyFile(session: Session, file: Buffer) {
  const form = multipart([{ name: 'file', filename: 'check.pdf', content: file }]);
  const res = await as(ctx, session, { method: 'POST', url: '/api/verify/file', payload: form.payload, headers: form.headers });
  expect(res.statusCode).toBe(200);
  return res.json().verification;
}

async function certificate(session: Session) {
  const id = await issueCredential(ctx, session);
  const res = await as(ctx, session, { method: 'GET', url: `/api/documents/${id}/file` });
  return { id, pdf: res.rawPayload };
}

describe('document authenticity', () => {
  it('verifies an untouched issuer certificate', async () => {
    const s = await registerUser(ctx);
    const { pdf } = await certificate(s);
    const v = await verifyFile(s, pdf);
    expect(v.result).toBe('verified');
    expect(v.issuer).toMatchObject({ name: 'TrustPass Demo University', simulated: true });
    expect(v.checks.find((c: { name: string }) => c.name === 'Document integrity').passed).toBe(true);
  });

  it('marks a certificate changed by one byte as invalid', async () => {
    const s = await registerUser(ctx);
    const { pdf } = await certificate(s);
    const modified = Buffer.from(pdf);
    // Flip one byte inside the first content stream (the visible certificate text).
    const at = modified.indexOf('stream\n') + 'stream\n'.length + 10;
    modified[at] = modified[at]! ^ 0x01;
    const v = await verifyFile(s, modified);
    expect(v.result).toBe('invalid');
    expect(v.reason).toMatch(/modified/);
  });

  it('marks a certificate edited and re-saved in a PDF editor as invalid', async () => {
    const s = await registerUser(ctx);
    const { pdf } = await certificate(s);
    const doc = await PDFDocument.load(pdf);
    doc.setTitle('Edited');
    const v = await verifyFile(s, Buffer.from(await doc.save()));
    expect(v.result).toBe('invalid');
  });

  it('reports an ordinary uploaded file as unverified', async () => {
    const s = await registerUser(ctx);
    const v = await verifyFile(s, await samplePdf('A self-made certificate'));
    expect(v.result).toBe('unverified');
  });

  it('cannot verify credentials of a revoked issuer', async () => {
    const s = await registerUser(ctx);
    const admin = await registerUser(ctx);
    await makeAdmin(ctx, admin);
    const { pdf } = await certificate(s);
    const issuers = (await as(ctx, admin, { method: 'GET', url: '/api/admin/issuers' })).json().issuers;
    const revoke = await as(ctx, admin, { method: 'PATCH', url: `/api/admin/issuers/${issuers[0].id}`, payload: { status: 'revoked' } });
    expect(revoke.statusCode).toBe(200);
    const v = await verifyFile(s, pdf);
    expect(v.result).toBe('unverified');
    expect(v.reason).toMatch(/revoked/);
    // A revoked issuer cannot issue new credentials either.
    const issue = await as(ctx, s, { method: 'POST', url: '/api/issuer/credentials', payload: { nameOnCertificate: 'Reham Test', program: 'BSc Cybersecurity' } });
    expect(issue.statusCode).toBe(409);
  });

  it('reports an unchanged, validly signed certificate past its validity period as expired', async () => {
    const s = await registerUser(ctx);
    const { id, pdf } = await certificate(s);
    ctx.clock.advance(366 * 24 * 3600_000);
    const fresh = await loginUser(ctx, s.email);
    const v = await verifyFile(fresh, pdf);
    expect(v.result).toBe('expired');
    expect(v.reason).toMatch(/signature is valid/);
    expect(v.checks.find((c: { name: string }) => c.name === 'Digital signature').passed).toBe(true);
    expect(v.checks.find((c: { name: string }) => c.name === 'Document integrity').passed).toBe(true);

    // The same expired certificate changed by one byte is invalid, not expired.
    const modified = Buffer.from(pdf);
    const at = modified.indexOf('stream\n') + 'stream\n'.length + 10;
    modified[at] = modified[at]! ^ 0x01;
    expect((await verifyFile(fresh, modified)).result).toBe('invalid');

    // The pasted credential of an expired certificate is expired as well.
    const cred = await as(ctx, fresh, { method: 'GET', url: `/api/documents/${id}/credential` });
    const pasted = await as(ctx, fresh, { method: 'POST', url: '/api/verify/presentation', payload: { presentation: cred.body } });
    expect(pasted.json().verification.result).toBe('expired');

    // Records show "Expired" (stored without any database change) and the document badge agrees.
    const records = (await as(ctx, fresh, { method: 'GET', url: '/api/verify/records' })).json().records;
    expect(records.map((r: { result: string }) => r.result).sort()).toEqual(['expired', 'expired', 'invalid']);
    const doc = (await as(ctx, fresh, { method: 'GET', url: `/api/documents/${id}` })).json().document;
    expect(doc.trust).toMatchObject({ status: 'expired', label: 'Credential expired' });
    const stored = await ctx.prisma.verificationRecord.findMany({ select: { result: true } });
    expect(stored.map((r) => r.result).sort()).toEqual(['invalid', 'unverified', 'unverified']);
  });

  it('a look-alike PDF naming a real credential is invalid only because that credential is genuinely signed', async () => {
    const s = await registerUser(ctx);
    const { pdf } = await certificate(s);
    const real = await PDFDocument.load(pdf);
    const pointer = real.getKeywords()!;
    expect(pointer).toMatch(/trustpass-credential:/);
    // A self-made PDF with the same look and the real credential id in its properties.
    const fake = await PDFDocument.load(await samplePdf('TrustPass Demo University - Enrollment Certificate'));
    fake.setKeywords([pointer]);
    const v = await verifyFile(s, Buffer.from(await fake.save()));
    expect(v.result).toBe('invalid');
    expect(v.checks.find((c: { name: string }) => c.name === 'Digital signature').passed).toBe(true);
    expect(v.checks.find((c: { name: string }) => c.name === 'Document integrity').passed).toBe(false);
    expect(v.claims).toEqual([]);

    // An id that matches no credential, or a credential of a revoked issuer: unable to verify.
    const unknown = await PDFDocument.load(await samplePdf('TrustPass Demo University - Enrollment Certificate'));
    unknown.setKeywords(['trustpass-credential:00000000-0000-4000-8000-000000000000']);
    expect((await verifyFile(s, Buffer.from(await unknown.save()))).result).toBe('unverified');
    const admin = await registerUser(ctx);
    await makeAdmin(ctx, admin);
    const issuers = (await as(ctx, admin, { method: 'GET', url: '/api/admin/issuers' })).json().issuers;
    await as(ctx, admin, { method: 'PATCH', url: `/api/admin/issuers/${issuers[0].id}`, payload: { status: 'revoked' } });
    expect((await verifyFile(s, Buffer.from(await fake.save()))).result).toBe('unverified');
  });

  it('a self-made PDF that shows the issuer name and look is unable to verify, never verified', async () => {
    const s = await registerUser(ctx);
    const v = await verifyFile(s, await samplePdf('TrustPass Demo University | Enrollment Certificate | VERIFIED'));
    expect(v.result).toBe('unverified');
    expect(v.issuer).toBeNull();
  });

  it('a PDF with its own (PAdES) signature is reported as a signature TrustPass cannot check', async () => {
    const s = await registerUser(ctx);
    const base = (await samplePdf('Signed elsewhere')).toString('latin1');
    const signed = base.replace('%%EOF', '9 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 10 20 30] /Contents <00> >>\nendobj\n%%EOF');
    const v = await verifyFile(s, Buffer.from(signed, 'latin1'));
    expect(v.result).toBe('unverified');
    expect(v.reason).toMatch(/format TrustPass cannot check/);
  });

  it('pasted credentials: garbage is unable to verify; a changed signature is invalid', async () => {
    const s = await registerUser(ctx);
    const check = async (presentation: string) =>
      (await as(ctx, s, { method: 'POST', url: '/api/verify/presentation', payload: { presentation } })).json().verification;
    expect((await check('hello, this is my certificate')).result).toBe('unverified');
    const id = await issueCredential(ctx, s);
    const cred = await as(ctx, s, { method: 'GET', url: `/api/documents/${id}/credential` });
    expect(cred.statusCode).toBe(200);
    const sdJwt = cred.body;
    const jwt = sdJwt.split('~')[0]!;
    const [h, p, sig] = jwt.split('.');
    const flipped = Buffer.from(sig!, 'base64url');
    flipped[0]! ^= 0x01;
    expect((await check(`${h}.${p}.${flipped.toString('base64url')}~`)).result).toBe('invalid');
    expect((await check(`${jwt}~`)).result).toBe('verified');
  });

  it('keeps a verification record per check', async () => {
    const s = await registerUser(ctx);
    const { pdf } = await certificate(s);
    await verifyFile(s, pdf);
    await verifyFile(s, await samplePdf());
    const records = (await as(ctx, s, { method: 'GET', url: '/api/verify/records' })).json().records;
    expect(records.map((r: { result: string }) => r.result).sort()).toEqual(['unverified', 'verified']);
  });

  it('owners can download their credential and it verifies as a presentation', async () => {
    const s = await registerUser(ctx);
    const { id } = await certificate(s);
    const cred = await as(ctx, s, { method: 'GET', url: `/api/documents/${id}/credential` });
    expect(cred.statusCode).toBe(200);
    const v = await as(ctx, s, { method: 'POST', url: '/api/verify/presentation', payload: { presentation: cred.body } });
    expect(v.json().verification.result).toBe('verified');
    expect(v.json().verification.claims).toHaveLength(6);
  });
});

describe('demo issuer', () => {
  it('requires Latin letters for the certificate name and a known program', async () => {
    const s = await registerUser(ctx);
    const arabic = await as(ctx, s, { method: 'POST', url: '/api/issuer/credentials', payload: { nameOnCertificate: 'رهام', program: 'BSc Cybersecurity' } });
    expect(arabic.statusCode).toBe(400);
    const program = await as(ctx, s, { method: 'POST', url: '/api/issuer/credentials', payload: { nameOnCertificate: 'Reham', program: 'Hacking 101' } });
    expect(program.statusCode).toBe(400);
  });

  it('limits demo credentials per user', async () => {
    const s = await registerUser(ctx);
    for (let i = 0; i < 3; i++) await issueCredential(ctx, s);
    const fourth = await as(ctx, s, { method: 'POST', url: '/api/issuer/credentials', payload: { nameOnCertificate: 'Reham Test', program: 'BSc Cybersecurity' } });
    expect(fourth.statusCode).toBe(409);
  });
});

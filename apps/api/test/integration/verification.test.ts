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

  it('marks credentials of a revoked issuer as invalid', async () => {
    const s = await registerUser(ctx);
    const admin = await registerUser(ctx);
    await makeAdmin(ctx, admin);
    const { pdf } = await certificate(s);
    const issuers = (await as(ctx, admin, { method: 'GET', url: '/api/admin/issuers' })).json().issuers;
    const revoke = await as(ctx, admin, { method: 'PATCH', url: `/api/admin/issuers/${issuers[0].id}`, payload: { status: 'revoked' } });
    expect(revoke.statusCode).toBe(200);
    const v = await verifyFile(s, pdf);
    expect(v.result).toBe('invalid');
    expect(v.reason).toMatch(/revoked/);
    // A revoked issuer cannot issue new credentials either.
    const issue = await as(ctx, s, { method: 'POST', url: '/api/issuer/credentials', payload: { nameOnCertificate: 'Reham Test', program: 'BSc Cybersecurity' } });
    expect(issue.statusCode).toBe(409);
  });

  it('marks expired credentials as invalid', async () => {
    const s = await registerUser(ctx);
    const { pdf } = await certificate(s);
    ctx.clock.advance(366 * 24 * 3600_000);
    const fresh = await loginUser(ctx, s.email);
    const v = await verifyFile(fresh, pdf);
    expect(v.result).toBe('invalid');
    expect(v.reason).toMatch(/expired/);
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

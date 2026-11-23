import { inflateSync } from 'node:zlib';
import { PDFDocument } from 'pdf-lib';

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
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  as,
  createLink,
  createTestContext,
  documentClaims,
  IPS,
  issueCredential,
  registerUser,
  resetDatabase,
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

const share = (token: string, ip = IPS.SA) => ctx.app.inject({ method: 'GET', url: `/api/share/${token}`, remoteAddress: ip });

describe('selective disclosure through a share link', () => {
  it('shows only the selected claim, verified by the issuer signature', async () => {
    const reham = await registerUser(ctx);
    const docId = await issueCredential(ctx, reham);
    const claims = await documentClaims(ctx, reham, docId);
    expect(claims.map((c) => c.key)).toEqual(['full_name', 'student_id', 'university', 'program', 'enrollment_status', 'academic_year']);
    const status = claims.find((c) => c.key === 'enrollment_status')!;

    const link = await createLink(ctx, reham, docId, { claimIds: [status.id], recipientLabel: 'Example Company' });
    const res = await share(link.token);
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.fields).toEqual([{ label: 'Enrollment status', value: 'Active', source: 'issuer' }]);
    expect(body.verification.result).toBe('verified');
    expect(body.document.fileShared).toBe(false);
    // Hidden claims are not anywhere in the response, not even hidden in markup.
    expect(res.body).not.toContain('Reham Alkhamees');
    expect(res.body).not.toContain(claims.find((c) => c.key === 'student_id')!.value);

    // The presentation is independently verifiable and discloses one claim only.
    const verify = await as(ctx, reham, { method: 'POST', url: '/api/verify/presentation', payload: { presentation: body.presentation } });
    expect(verify.json().verification.result).toBe('verified');
    expect(verify.json().verification.claims).toEqual([{ key: 'enrollment_status', label: 'Enrollment status', value: 'Active' }]);
  });

  it('labels self-declared claims of uploaded files as unverified', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s, { claims: [{ label: 'Job title', value: 'Analyst' }, { label: 'Salary', value: '9000' }] })).json().document.id;
    const claims = await documentClaims(ctx, s, id);
    const link = await createLink(ctx, s, id, { claimIds: [claims[0]!.id] });
    const body = (await share(link.token)).json();
    expect(body.fields).toEqual([{ label: 'Job title', value: 'Analyst', source: 'self_declared' }]);
    expect(body.verification.result).toBe('unverified');
    expect(JSON.stringify(body)).not.toContain('9000');
  });

  it('refuses claims that belong to another document', async () => {
    const s = await registerUser(ctx);
    const a = (await uploadDocument(ctx, s, { claims: [{ label: 'A', value: '1' }] })).json().document.id;
    const b = (await uploadDocument(ctx, s, { claims: [{ label: 'B', value: '2' }] })).json().document.id;
    const bClaims = await documentClaims(ctx, s, b);
    const res = await as(ctx, s, {
      method: 'POST',
      url: `/api/documents/${a}/links`,
      payload: { claimIds: [bClaims[0]!.id], includeFile: false, recipientType: 'anyone', recipientLabel: 'X', expiresIn: '1h' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('stores only a hash of the token', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true });
    const row = await ctx.prisma.sharingLink.findUniqueOrThrow({ where: { id: link.id } });
    expect(row.tokenHash).not.toContain(link.token);
    expect(Buffer.from(row.tokenEncrypted).includes(Buffer.from(link.token))).toBe(false);
    const again = await as(ctx, s, { method: 'GET', url: `/api/links/${link.id}/url` });
    expect(again.json().url).toBe(link.url);
  });
});

describe('expiry and revocation', () => {
  it('expires automatically and logs the attempt', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true, expiresIn: '1h' });
    expect((await share(link.token)).statusCode).toBe(200);
    ctx.clock.advance(61 * 60_000);
    const res = await share(link.token);
    expect(res.statusCode).toBe(410);
    expect(res.json().error.code).toBe('link_expired');
    const file = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}/file`, remoteAddress: IPS.SA });
    expect(file.statusCode).toBe(410);
    const outcomes = (await ctx.prisma.accessLog.findMany({ where: { linkId: link.id }, orderBy: { id: 'asc' } })).map((l) => l.outcome);
    expect(outcomes).toEqual(['granted', 'denied_expired', 'denied_expired']);
  });

  it('stops working immediately when revoked, and cannot be reused', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true });
    expect((await share(link.token)).statusCode).toBe(200);
    expect((await as(ctx, s, { method: 'POST', url: `/api/links/${link.id}/revoke` })).statusCode).toBe(200);
    for (let i = 0; i < 3; i++) {
      const res = await share(link.token);
      expect(res.statusCode).toBe(410);
      expect(res.json().error.code).toBe('link_revoked');
    }
    const notes = await ctx.prisma.notification.findMany({ where: { userId: s.userId, type: 'alert_after_end' } });
    expect(notes).toHaveLength(1); // de-duplicated
    const burst = await ctx.prisma.notification.count({ where: { userId: s.userId, type: 'alert_denied_burst' } });
    expect(burst).toBe(1);
  });

  it('enforces custom expiry limits', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const tooLong = new Date(ctx.clock.now.getTime() + 40 * 24 * 3600_000).toISOString();
    const res = await as(ctx, s, {
      method: 'POST',
      url: `/api/documents/${id}/links`,
      payload: { includeFile: true, recipientType: 'anyone', recipientLabel: 'X', expiresIn: 'custom', expiresAt: tooLong },
    });
    expect(res.statusCode).toBe(400);
    const past = await as(ctx, s, {
      method: 'POST',
      url: `/api/documents/${id}/links`,
      payload: { includeFile: true, recipientType: 'anyone', recipientLabel: 'X', expiresIn: 'custom', expiresAt: new Date(ctx.clock.now.getTime() - 1000).toISOString() },
    });
    expect(past.statusCode).toBe(400);
  });

  it('only the owner can revoke or read a link', async () => {
    const s = await registerUser(ctx);
    const other = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true });
    expect((await as(ctx, other, { method: 'POST', url: `/api/links/${link.id}/revoke` })).statusCode).toBe(404);
    expect((await as(ctx, other, { method: 'GET', url: `/api/links/${link.id}/url` })).statusCode).toBe(404);
    expect((await as(ctx, other, { method: 'PUT', url: `/api/links/${link.id}/countries`, payload: { allowedCountries: [] } })).statusCode).toBe(404);
    expect((await share(link.token)).statusCode).toBe(200);
  });

  it('answers a generic 404 for unknown or malformed tokens', async () => {
    expect((await share('A'.repeat(43))).statusCode).toBe(404);
    expect((await share("x' OR 1=1 --")).statusCode).toBe(404);
  });
});

describe('recipient restrictions', () => {
  it('limits an organization link to that organization’s members', async () => {
    const reham = await registerUser(ctx);
    const company = await registerUser(ctx, { organization: 'Example Company' });
    const outsider = await registerUser(ctx, { organization: 'Other Corp' });
    const docId = await issueCredential(ctx, reham);
    const status = (await documentClaims(ctx, reham, docId)).find((c) => c.key === 'enrollment_status')!;
    const link = await createLink(ctx, reham, docId, { claimIds: [status.id], recipientType: 'organization', recipientOrgId: company.orgId });

    const anonymous = await share(link.token);
    expect(anonymous.statusCode).toBe(401);
    expect(anonymous.json().error.code).toBe('login_required');
    expect(anonymous.body).not.toContain('Example Company');

    const wrongOrg = await as(ctx, outsider, { method: 'GET', url: `/api/share/${link.token}`, ip: IPS.SA });
    expect(wrongOrg.statusCode).toBe(403);

    const member = await as(ctx, company, { method: 'GET', url: `/api/share/${link.token}`, ip: IPS.SA });
    expect(member.statusCode).toBe(200);
    expect(member.json().fields).toEqual([{ label: 'Enrollment status', value: 'Active', source: 'issuer' }]);

    // It is in the organization inbox, and a verification record is kept for the organization.
    const inbox = await as(ctx, company, { method: 'GET', url: '/api/inbox' });
    expect(inbox.json().items).toHaveLength(1);
    const viaInbox = await as(ctx, company, { method: 'GET', url: `/api/inbox/${link.id}`, ip: IPS.SA });
    expect(viaInbox.statusCode).toBe(200);
    expect(await ctx.prisma.verificationRecord.count({ where: { verifiedByOrgId: company.orgId } })).toBe(2);
    expect((await as(ctx, outsider, { method: 'GET', url: `/api/inbox/${link.id}`, ip: IPS.SA })).statusCode).toBe(404);
    // Sharing is normal activity: no notification for the organization (security alerts only).
    expect(await ctx.prisma.notification.count({ where: { userId: company.userId, type: 'link_received' } })).toBe(0);

    const logs = await ctx.prisma.accessLog.findMany({ where: { linkId: link.id }, orderBy: { id: 'asc' } });
    expect(logs.map((l) => l.outcome)).toEqual(['denied_recipient', 'denied_recipient', 'granted', 'granted', 'denied_recipient']);
    expect(logs[2]!.accessorOrgId).toBe(company.orgId);
  });

  it('a member added later gains access; a removed member loses it', async () => {
    const reham = await registerUser(ctx);
    const company = await registerUser(ctx, { organization: 'Example Company' });
    const colleague = await registerUser(ctx);
    const id = (await uploadDocument(ctx, reham)).json().document.id;
    const link = await createLink(ctx, reham, id, { includeFile: true, recipientType: 'organization', recipientOrgId: company.orgId });

    expect((await as(ctx, colleague, { method: 'GET', url: `/api/share/${link.token}`, ip: IPS.SA })).statusCode).toBe(403);
    const add = await as(ctx, company, { method: 'POST', url: `/api/organizations/${company.orgId}/members`, payload: { email: colleague.email, role: 'member' } });
    expect(add.statusCode).toBe(201);
    expect((await as(ctx, colleague, { method: 'GET', url: `/api/share/${link.token}`, ip: IPS.SA })).statusCode).toBe(200);
    await as(ctx, company, { method: 'DELETE', url: `/api/organizations/${company.orgId}/members/${colleague.userId}` });
    expect((await as(ctx, colleague, { method: 'GET', url: `/api/share/${link.token}`, ip: IPS.SA })).statusCode).toBe(403);
  });
});

describe('view-only file with watermark', () => {
  it('serves a watermarked PDF only when the file is shared', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s, { claims: [{ label: 'Role', value: 'Analyst' }] })).json().document.id;
    const claims = await documentClaims(ctx, s, id);

    const detailsOnly = await createLink(ctx, s, id, { claimIds: [claims[0]!.id] });
    const blocked = await ctx.app.inject({ method: 'GET', url: `/api/share/${detailsOnly.token}/file`, remoteAddress: IPS.SA });
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json().error.code).toBe('file_not_shared');

    const withFile = await createLink(ctx, s, id, { includeFile: true, recipientLabel: 'Example Company' });
    const res = await ctx.app.inject({ method: 'GET', url: `/api/share/${withFile.token}/file`, remoteAddress: IPS.SA });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['cache-control']).toContain('no-store');
    const pdf = await PDFDocument.load(res.rawPayload);
    expect(pdf.getTitle()).toBe('TrustPass - authorized viewing only');
    // Watermark text is drawn into the page content (hex-encoded Helvetica text).
    const content = pdfContent(res.rawPayload);
    const hex = (s: string) => Buffer.from(s, 'latin1').toString('hex').toUpperCase();
    expect(content.includes(hex('CONFIDENTIAL')) || content.includes('CONFIDENTIAL')).toBe(true);
    expect(content.includes(hex('Example Company')) || content.includes('Example Company')).toBe(true);
  });

  it('wraps shared images in a watermarked PDF', async () => {
    const s = await registerUser(ctx);
    const { samplePng } = await import('../helpers');
    const id = (await uploadDocument(ctx, s, { file: await samplePng(), filename: 'scan.png' })).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true });
    const res = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}/file`, remoteAddress: IPS.SA });
    expect(res.statusCode).toBe(200);
    expect(res.rawPayload.subarray(0, 5).toString()).toBe('%PDF-');
  });
});

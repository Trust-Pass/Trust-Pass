import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { as, createLink, createTestContext, registerUser, resetDatabase, uploadDocument, type Session, type TestContext } from '../helpers';

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

const checkQr = (s: Session | null, content: string, source = 'paste') =>
  as(ctx, s, { method: 'POST', url: '/api/qr/check', payload: { content, source } });

async function sharedLink(s: Session, body: Record<string, unknown> = {}) {
  const id = (await uploadDocument(ctx, s)).json().document.id as string;
  return createLink(ctx, s, id, { includeFile: true, ...body });
}

describe('POST /api/qr/check', () => {
  it('requires sign-in', async () => {
    const res = await checkQr(null, 'https://example.com');
    expect(res.statusCode).toBe(401);
  });

  it('validates the input', async () => {
    const s = await registerUser(ctx);
    expect((await checkQr(s, '')).statusCode).toBe(400);
    expect((await checkQr(s, 'x'.repeat(4097))).statusCode).toBe(400);
    expect((await checkQr(s, 'https://example.com', 'telepathy')).statusCode).toBe(400);
  });

  it('returns a verdict with findings, and never fetches the address', async () => {
    const s = await registerUser(ctx);
    // .invalid is reserved and never resolves: a fetch attempt would fail or hang.
    const res = await checkQr(s, 'https://paypal-login.invalid/verify', 'camera');
    expect(res.statusCode).toBe(200);
    const { analysis } = res.json();
    expect(analysis).toMatchObject({ kind: 'web_link', verdict: 'danger', canOpen: false });
    expect(analysis.findings.map((f: { id: string }) => f.id)).toContain('brand_lookalike');
    expect(analysis).not.toHaveProperty('trustpassToken');
  });

  it('logs dangerous results without storing the content', async () => {
    const s = await registerUser(ctx);
    await checkQr(s, 'javascript:alert("secret-marker")', 'image');
    await checkQr(s, 'https://www.google.com/', 'paste');
    const events = await ctx.prisma.securityEvent.findMany({ where: { userId: s.userId, eventType: 'qr_threat_detected' } });
    expect(events).toHaveLength(1);
    expect(events[0]!.metadata).toMatchObject({ source: 'image', kind: 'script' });
    expect(JSON.stringify(events[0]!.metadata)).not.toContain('secret-marker');
  });

  it('confirms a genuine, active TrustPass link without counting a view', async () => {
    const owner = await registerUser(ctx);
    const scanner = await registerUser(ctx);
    const link = await sharedLink(owner);
    const res = await checkQr(scanner, link.url, 'camera');
    expect(res.json().trustpassLink).toEqual({ status: 'active' });
    expect(res.json().analysis).toMatchObject({ kind: 'trustpass_link', verdict: 'safe', canOpen: true });
    const row = await ctx.prisma.sharingLink.findUniqueOrThrow({ where: { id: link.id } });
    expect(row.viewCount).toBe(0);
    expect(await ctx.prisma.accessLog.count({ where: { linkId: link.id } })).toBe(0);
    // Nothing about the document or its owner is revealed.
    expect(res.body).not.toContain(owner.email);
    expect(res.body).not.toContain(link.token);
  });

  it('flags expired and revoked TrustPass links', async () => {
    const s = await registerUser(ctx);
    const expiring = await sharedLink(s, { expiresIn: '1h' });
    const revoked = await sharedLink(s);
    await as(ctx, s, { method: 'POST', url: `/api/links/${revoked.id}/revoke` });
    ctx.clock.advance(61 * 60_000);

    const exp = (await checkQr(s, expiring.url)).json();
    expect(exp.trustpassLink.status).toBe('expired');
    expect(exp.analysis.verdict).toBe('caution');
    const rev = (await checkQr(s, revoked.url)).json();
    expect(rev.trustpassLink.status).toBe('revoked');
    expect(rev.analysis.verdict).toBe('caution');
  });

  it('marks a fake TrustPass link on the official address as dangerous', async () => {
    const s = await registerUser(ctx);
    const fake = `${ctx.config.appOrigin}/s/${'A'.repeat(43)}`;
    const res = (await checkQr(s, fake)).json();
    expect(res.trustpassLink.status).toBe('not_found');
    expect(res.analysis).toMatchObject({ verdict: 'danger', canOpen: false });
    expect(res.analysis.findings[0].id).toBe('link_not_found');
  });

  it('allows the camera for our own pages only', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/health' });
    expect(res.headers['permissions-policy']).toContain('camera=(self)');
    expect(res.headers['permissions-policy']).toContain('microphone=()');
  });
});

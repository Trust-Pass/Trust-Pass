import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { as, createLink, createTestContext, IPS, registerUser, resetDatabase, uploadDocument, type TestContext } from '../helpers';

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

async function gulfOnlyLink() {
  const s = await registerUser(ctx);
  const id = (await uploadDocument(ctx, s)).json().document.id;
  const link = await createLink(ctx, s, id, { includeFile: true, allowedCountries: ['SA', 'AE'] });
  return { s, link };
}

describe('country restrictions', () => {
  it('allows listed countries', async () => {
    const { link } = await gulfOnlyLink();
    for (const ip of [IPS.SA, IPS.AE]) {
      expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: ip })).statusCode).toBe(200);
    }
  });

  it('blocks other countries without revealing the allowed list, and logs the country', async () => {
    const { link } = await gulfOnlyLink();
    const res = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.US });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('country_blocked');
    expect(res.body).not.toMatch(/Saudi|SA|AE|Emirates/);
    const file = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}/file`, remoteAddress: IPS.GB });
    expect(file.statusCode).toBe(403);

    const logs = await ctx.prisma.accessLog.findMany({ where: { linkId: link.id }, orderBy: { id: 'asc' } });
    expect(logs.map((l) => [l.outcome, l.countryCode])).toEqual([
      ['denied_country', 'US'],
      ['denied_country', 'GB'],
    ]);
  });

  it('fails closed when the location is unknown', async () => {
    const { link } = await gulfOnlyLink();
    const res = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.UNKNOWN });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('country_unknown');
  });

  it('applies no geographic rule when no countries are chosen', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, id, { includeFile: true });
    expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.UNKNOWN })).statusCode).toBe(200);
  });

  it('ignores forged X-Forwarded-For and country headers from the client', async () => {
    const { link } = await gulfOnlyLink();
    const res = await ctx.app.inject({
      method: 'GET',
      url: `/api/share/${link.token}`,
      remoteAddress: IPS.US,
      headers: { 'x-forwarded-for': IPS.SA, 'x-real-ip': IPS.SA, 'cf-ipcountry': 'SA', 'x-country': 'SA' },
    });
    expect(res.statusCode).toBe(403);
  });

  it('owners can change the allowed countries and the change applies at once', async () => {
    const { s, link } = await gulfOnlyLink();
    expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.US })).statusCode).toBe(403);
    const update = await as(ctx, s, { method: 'PUT', url: `/api/links/${link.id}/countries`, payload: { allowedCountries: ['us', 'SA'] } });
    expect(update.statusCode).toBe(200);
    expect(update.json().countries).toEqual(['US', 'SA']);
    expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.US })).statusCode).toBe(200);
    expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.AE })).statusCode).toBe(403);
    const event = await ctx.prisma.securityEvent.findFirst({ where: { linkId: link.id, eventType: 'link_countries_updated' } });
    const meta = event?.metadata as { before: string[]; after: string[] };
    expect([...meta.before].sort()).toEqual(['AE', 'SA']);
    expect(meta.after).toEqual(['US', 'SA']);
  });

  it('rejects invalid country codes', async () => {
    const s = await registerUser(ctx);
    const id = (await uploadDocument(ctx, s)).json().document.id;
    const res = await as(ctx, s, {
      method: 'POST',
      url: `/api/documents/${id}/links`,
      payload: { includeFile: true, recipientType: 'anyone', recipientLabel: 'X', expiresIn: '1h', allowedCountries: ['XX', "SA'; DROP TABLE users;--"] },
    });
    expect(res.statusCode).toBe(400);
  });

  it('never stores raw IP addresses', async () => {
    const { link } = await gulfOnlyLink();
    await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA });
    const row = await ctx.prisma.accessLog.findFirstOrThrow({ where: { linkId: link.id } });
    expect(JSON.stringify(row, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))).not.toContain(IPS.SA);
    expect(row.ipHmac).toMatch(/^[a-f0-9]{32}$/);
  });
});

describe('behind a trusted proxy', () => {
  let proxied: TestContext;
  beforeAll(async () => {
    proxied = await createTestContext({ TRUST_PROXY: '1' });
  });
  afterAll(async () => {
    await proxied.app.close();
  });

  it('uses the address added by the proxy, not addresses the client prepended', async () => {
    const s = await registerUser(proxied);
    const id = (await uploadDocument(proxied, s)).json().document.id;
    const link = await createLink(proxied, s, id, { includeFile: true, allowedCountries: ['SA'] });
    // Client is really in the US; it prepends a Saudi address hoping to be trusted.
    const spoofed = await proxied.app.inject({
      method: 'GET',
      url: `/api/share/${link.token}`,
      remoteAddress: '127.0.0.1',
      headers: { 'x-forwarded-for': `${IPS.SA}, ${IPS.US}` },
    });
    expect(spoofed.statusCode).toBe(403);
    const real = await proxied.app.inject({
      method: 'GET',
      url: `/api/share/${link.token}`,
      remoteAddress: '127.0.0.1',
      headers: { 'x-forwarded-for': IPS.SA },
    });
    expect(real.statusCode).toBe(200);
  });
});

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { as, createLink, createTestContext, IPS, loginUser, makeAdmin, registerUser, resetDatabase, uploadDocument, type TestContext } from '../helpers';

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

const open = (token: string, ip: string) => ctx.app.inject({ method: 'GET', url: `/api/share/${token}`, remoteAddress: ip });

async function scenario() {
  const owner = await registerUser(ctx);
  const docId = (await uploadDocument(ctx, owner, { title: 'University Certificate' })).json().document.id;
  const link = await createLink(ctx, owner, docId, { includeFile: true, allowedCountries: ['SA', 'AE'], expiresIn: '1h' });
  await open(link.token, IPS.SA); // granted SA
  await open(link.token, IPS.SA); // granted SA
  await open(link.token, IPS.AE); // granted AE
  await open(link.token, IPS.US); // denied country
  await open(link.token, IPS.UNKNOWN); // denied unknown
  ctx.clock.advance(61 * 60_000);
  await open(link.token, IPS.SA); // denied expired
  // The hour that passed also ended the owner's idle session: sign in again.
  return { owner: await loginUser(ctx, owner.email), docId, link };
}

describe('access analytics', () => {
  it('reports exactly the recorded attempts', async () => {
    const { owner, docId } = await scenario();
    const res = await as(ctx, owner, { method: 'GET', url: '/api/analytics' });
    expect(res.statusCode).toBe(200);
    const { summary, byCountry, byDocument, daily } = res.json();
    expect(summary).toMatchObject({
      totalAttempts: 6,
      granted: 3,
      denied: 3,
      expiredAttempts: 1,
      countryBlocked: 2,
      countriesDetected: 3,
      activeLinks: 0,
      expiredLinks: 1,
      revokedLinks: 0,
    });
    expect(summary.lastAccess.country).toBe('AE');
    const sa = byCountry.find((c: { country: string | null }) => c.country === 'SA');
    expect(sa).toEqual({ country: 'SA', granted: 2, denied: 1 });
    expect(byCountry.find((c: { country: string | null }) => c.country === null)).toEqual({ country: null, granted: 0, denied: 1 });
    expect(byDocument).toEqual([{ documentId: docId, title: 'University Certificate', granted: 3, denied: 3 }]);
    expect(daily.reduce((n: number, d: { granted: number; denied: number }) => n + d.granted + d.denied, 0)).toBe(6);
  });

  it('filters by document and by date', async () => {
    const { owner, docId } = await scenario();
    const other = (await uploadDocument(ctx, owner, { title: 'Other' })).json().document.id;
    const byDoc = await as(ctx, owner, { method: 'GET', url: `/api/analytics?documentId=${other}` });
    expect(byDoc.json().summary.totalAttempts).toBe(0);
    const mine = await as(ctx, owner, { method: 'GET', url: `/api/analytics?documentId=${docId}` });
    expect(mine.json().summary.totalAttempts).toBe(6);
    const old = await as(ctx, owner, { method: 'GET', url: '/api/analytics?from=2020-01-01&to=2020-01-31' });
    expect(old.json().summary.totalAttempts).toBe(0);
  });

  it('lists the access log with outcome filters', async () => {
    const { owner } = await scenario();
    const all = await as(ctx, owner, { method: 'GET', url: '/api/analytics/access-log' });
    expect(all.json().total).toBe(6);
    const denied = await as(ctx, owner, { method: 'GET', url: '/api/analytics/access-log?outcome=denied_country' });
    expect(denied.json().rows.map((r: { country: string | null }) => r.country).sort()).toEqual(['US', null].sort());
    expect(JSON.stringify(all.json())).not.toMatch(/10\.0\.0\.|192\.168/);
  });

  it('raises "worth a look" alerts without calling them attacks', async () => {
    const { owner } = await scenario();
    const notes = await ctx.prisma.notification.findMany({ where: { userId: owner.userId }, orderBy: { createdAt: 'asc' } });
    const types = notes.map((n) => n.type);
    expect(types.filter((t) => t === 'alert_new_country')).toHaveLength(2); // SA and AE
    // Only 2 denials fall inside any 10-minute window here, below the burst threshold of 3.
    expect(types).not.toContain('alert_denied_burst');
    expect(types).toContain('alert_after_end');
    for (const n of notes) expect(`${n.title} ${n.body}`).not.toMatch(/attack|hacker|malicious/i);
  });

  it("never shows one user another user's analytics, logs or activity", async () => {
    const { docId } = await scenario();
    const intruder = await registerUser(ctx);
    expect((await as(ctx, intruder, { method: 'GET', url: `/api/analytics?documentId=${docId}` })).statusCode).toBe(404);
    const a = (await as(ctx, intruder, { method: 'GET', url: '/api/analytics' })).json();
    expect(a.summary.totalAttempts).toBe(0);
    expect((await as(ctx, intruder, { method: 'GET', url: '/api/analytics/access-log' })).json().total).toBe(0);
    const activity = (await as(ctx, intruder, { method: 'GET', url: '/api/activity' })).json();
    expect(activity.events.every((e: { type: string }) => ['account_created'].includes(e.type))).toBe(true);
    const notes = (await as(ctx, intruder, { method: 'GET', url: '/api/notifications' })).json();
    expect(notes.notifications).toHaveLength(0);
  });

  it('records the activity log for the owner', async () => {
    const { owner } = await scenario();
    const events = (await as(ctx, owner, { method: 'GET', url: '/api/activity' })).json().events.map((e: { type: string }) => e.type);
    expect(events).toEqual(expect.arrayContaining(['account_created', 'document_uploaded', 'document_encrypted', 'link_created', 'login_succeeded']));
  });
});

describe('audit log integrity', () => {
  it('rejects updates and deletes of log rows at the database level', async () => {
    await scenario();
    await expect(ctx.prisma.accessLog.updateMany({ data: { outcome: 'granted' } })).rejects.toThrow(/append-only/);
    await expect(ctx.prisma.accessLog.deleteMany({})).rejects.toThrow(/append-only/);
    await expect(ctx.prisma.securityEvent.deleteMany({})).rejects.toThrow(/append-only/);
    await expect(ctx.prisma.$executeRawUnsafe('TRUNCATE access_logs')).rejects.toThrow(/append-only/);
    expect(await ctx.prisma.accessLog.count()).toBe(6);
  });

  it('only the retention job deletes old access logs', async () => {
    const { owner } = await scenario();
    const admin = await registerUser(ctx);
    await makeAdmin(ctx, admin);
    ctx.clock.advance(91 * 24 * 3600_000);
    const fresh = await loginUser(ctx, admin.email);
    const res = await as(ctx, fresh, { method: 'POST', url: '/api/admin/retention/run' });
    expect(res.statusCode).toBe(200);
    expect(res.json().result.accessLogsDeleted).toBe(6);
    expect(await ctx.prisma.accessLog.count({ where: { ownerId: owner.userId } })).toBe(0);
  });
});

describe('notifications', () => {
  it('can be marked read', async () => {
    const { owner } = await scenario();
    const list = (await as(ctx, owner, { method: 'GET', url: '/api/notifications' })).json();
    expect(list.unread).toBeGreaterThan(0);
    await as(ctx, owner, { method: 'POST', url: `/api/notifications/${list.notifications[0].id}/read` });
    expect((await as(ctx, owner, { method: 'GET', url: '/api/notifications' })).json().unread).toBe(list.unread - 1);
    await as(ctx, owner, { method: 'POST', url: '/api/notifications/read-all' });
    expect((await as(ctx, owner, { method: 'GET', url: '/api/notifications' })).json().unread).toBe(0);
  });
});

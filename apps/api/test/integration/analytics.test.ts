import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { as, createLink, createTestContext, freshIp, IPS, issueCredential, loginUser, makeAdmin, registerUser, resetDatabase, uploadDocument, type TestContext } from '../helpers';

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

  it('dashboard: 14-day series matches the attempts, and key protection is reported without secrets', async () => {
    const { owner } = await scenario();
    const res = await as(ctx, owner, { method: 'GET', url: '/api/dashboard' });
    expect(res.statusCode).toBe(200);
    const { daily, protection, counts } = res.json();
    expect(daily).toHaveLength(14);
    expect(daily.reduce((n: number, d: { granted: number; denied: number }) => n + d.granted + d.denied, 0)).toBe(6);
    expect(daily.reduce((n: number, d: { granted: number }) => n + d.granted, 0)).toBe(3);
    expect(daily.at(-1).date).toBe(new Date(ctx.clock.now).toISOString().slice(0, 10));
    expect(counts.attempts7d).toBe(6);
    expect(Object.keys(protection).sort()).toEqual(['keyProvider', 'kms']);
    expect(protection.kms).toBe(protection.keyProvider === 'gcp-kms');
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
    expect(types).toContain('alert_expired_link');
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

describe('activity log: hide sign-in history', () => {
  it('hides sign-ins and sign-outs from the view only; every record stays in the log', async () => {
    const { owner } = await scenario();
    await as(ctx, owner, { method: 'POST', url: '/api/auth/logout' });
    const again = await loginUser(ctx, owner.email);
    // A failed sign-in stays visible: it is a security warning, not history.
    await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: again.email, password: 'Wrong-Password-123!' }, remoteAddress: freshIp() });
    const storedBefore = await ctx.prisma.securityEvent.count({ where: { userId: again.userId } });

    const all = (await as(ctx, again, { method: 'GET', url: '/api/activity' })).json();
    const types = all.events.map((e: { type: string }) => e.type);
    expect(types).toEqual(expect.arrayContaining(['login_succeeded', 'logout', 'login_failed', 'link_created', 'document_uploaded']));
    expect(all.hiddenSignIns).toBe(0);

    const hidden = (await as(ctx, again, { method: 'GET', url: '/api/activity?hideSignIns=1' })).json();
    const hiddenTypes = hidden.events.map((e: { type: string }) => e.type);
    for (const t of ['login_succeeded', 'logout', 'session_revoked']) expect(hiddenTypes).not.toContain(t);
    expect(hiddenTypes).toEqual(expect.arrayContaining(['login_failed', 'link_created', 'document_uploaded']));
    const signIns = all.events.filter((e: { type: string }) => ['login_succeeded', 'logout', 'session_revoked'].includes(e.type)).length;
    expect(hidden.hiddenSignIns).toBe(signIns);
    expect(hidden.total).toBe(all.total - signIns);
    // A sign-in type filter while hidden shows nothing; shown again, it is all there.
    expect((await as(ctx, again, { method: 'GET', url: '/api/activity?hideSignIns=1&type=login_succeeded' })).json().events).toEqual([]);
    expect((await as(ctx, again, { method: 'GET', url: '/api/activity?hideSignIns=0' })).json().total).toBe(all.total);

    // Nothing was deleted or changed: the append-only log still has every row.
    expect(await ctx.prisma.securityEvent.count({ where: { userId: again.userId } })).toBe(storedBefore);
    await expect(ctx.prisma.securityEvent.deleteMany({ where: { userId: again.userId, eventType: 'login_succeeded' } })).rejects.toThrow(/append-only/);
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
  const REPEATED = { title: 'Repeated access attempts', body: 'Someone tried to access your document multiple times.' };
  const EXPIRED = { title: 'Expired link access blocked', body: 'Someone tried to open your document after the link expired. Access was blocked.' };

  it('are security alerts only: an expired-link attempt, with the document name and time', async () => {
    const { owner } = await scenario();
    const list = (await as(ctx, owner, { method: 'GET', url: '/api/notifications' })).json();
    // First views from SA and AE are not notifications any more...
    expect(list.notifications).toHaveLength(1);
    expect(list.notifications[0]).toMatchObject({ kind: 'expired_link', ...EXPIRED, document: 'University Certificate', read: false });
    expect(new Date(list.notifications[0].at).getTime()).toBeGreaterThan(0);
    expect(list.unread).toBe(1);
    const session = (await as(ctx, owner, { method: 'GET', url: '/api/auth/session' })).json();
    expect(session.user?.unreadNotifications ?? session.unreadNotifications).toBe(1);
    // Analytics "Security alerts" shows exactly the same alerts as the bell...
    const alerts = (await as(ctx, owner, { method: 'GET', url: '/api/analytics' })).json().alerts;
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ id: list.notifications[0].id, kind: 'expired_link', ...EXPIRED, document: 'University Certificate' });
    // ...while the first-view records are still stored, and access is still logged.
    expect(await ctx.prisma.notification.count({ where: { userId: owner.userId, type: 'alert_new_country' } })).toBe(2);
    expect(await ctx.prisma.accessLog.count({ where: { ownerId: owner.userId } })).toBe(6);
  });

  it('repeated blocked attempts raise one "Repeated access attempts" alert', async () => {
    const owner = await registerUser(ctx);
    const docId = (await uploadDocument(ctx, owner, { title: 'Payslip' })).json().document.id;
    const link = await createLink(ctx, owner, docId, { includeFile: true, allowedCountries: ['SA'] });
    for (let i = 0; i < 5; i++) await open(link.token, IPS.US);
    const list = (await as(ctx, owner, { method: 'GET', url: '/api/notifications' })).json();
    expect(list.notifications).toHaveLength(1);
    expect(list.notifications[0]).toMatchObject({ kind: 'repeated_attempts', ...REPEATED, document: 'Payslip', read: false });
    const alerts = (await as(ctx, owner, { method: 'GET', url: '/api/analytics' })).json().alerts;
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ kind: 'repeated_attempts', ...REPEATED, document: 'Payslip' });
    // Detection and logging are untouched.
    expect(await ctx.prisma.securityEvent.count({ where: { linkId: link.id, eventType: 'repeated_denied_access' } })).toBe(1);
    expect(await ctx.prisma.accessLog.count({ where: { linkId: link.id, outcome: 'denied_country' } })).toBe(5);
  });

  it('normal activity raises no notification: views, downloads, revoked links, certificates, sharing', async () => {
    const owner = await registerUser(ctx);
    const member = await registerUser(ctx);
    const docId = (await uploadDocument(ctx, owner, { title: 'Contract' })).json().document.id;
    const link = await createLink(ctx, owner, docId, { includeFile: true, allowDownload: true });
    await open(link.token, IPS.SA); // first view
    expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}/download`, remoteAddress: IPS.SA })).statusCode).toBe(200);
    await as(ctx, owner, { method: 'POST', url: `/api/links/${link.id}/revoke` });
    await open(link.token, IPS.SA); // a revoked link: blocked, recorded, not a notification
    await issueCredential(ctx, owner);
    // An organization adds a member, and the owner shares a document with that organization.
    const orgOwner = await registerUser(ctx, { organization: 'Example Co' });
    const added = await as(ctx, orgOwner, { method: 'POST', url: `/api/organizations/${orgOwner.orgId}/members`, payload: { email: member.email, role: 'member' } });
    expect(added.statusCode).toBe(201);
    await createLink(ctx, owner, docId, { recipientType: 'organization', recipientOrgId: orgOwner.orgId, includeFile: true });

    for (const who of [owner, member, orgOwner]) {
      const list = (await as(ctx, who, { method: 'GET', url: '/api/notifications' })).json();
      expect(list).toMatchObject({ unread: 0, notifications: [] });
    }
    const stored = (await ctx.prisma.notification.findMany({ select: { type: true } })).map((n) => n.type);
    for (const gone of ['link_downloaded', 'credential_issued', 'link_received', 'org_member_added']) expect(stored).not.toContain(gone);
    // Analytics shows no alert for any of it (revoked-link attempts and first views included)...
    expect((await as(ctx, owner, { method: 'GET', url: '/api/analytics' })).json().alerts).toEqual([]);
    expect(await ctx.prisma.notification.count({ where: { userId: owner.userId, type: { in: ['alert_after_end', 'alert_new_country'] } } })).toBeGreaterThan(0);
    // ...and the security events are still logged.
    const events = (await ctx.prisma.securityEvent.findMany({ where: { userId: owner.userId }, select: { eventType: true } })).map((e) => e.eventType);
    expect(events).toEqual(expect.arrayContaining(['recipient_downloaded', 'link_revoked']));
    expect(await ctx.prisma.accessLog.count({ where: { linkId: link.id, outcome: 'denied_revoked' } })).toBe(1);
  });

  it('older stored notifications: expired-link alerts still show, other kinds stay hidden and uncounted', async () => {
    const owner = await registerUser(ctx);
    const docId = (await uploadDocument(ctx, owner, { title: 'Lease' })).json().document.id;
    const link = await createLink(ctx, owner, docId, { includeFile: true });
    const base = { userId: owner.userId, linkId: link.id, documentId: docId };
    await ctx.prisma.notification.createMany({
      data: [
        { ...base, type: 'alert_after_end', title: 'Someone tried a expired link', body: 'x' },
        { ...base, type: 'alert_after_end', title: 'Someone tried a revoked link', body: 'x' },
        { ...base, type: 'link_downloaded', title: 'A recipient downloaded your document', body: 'x' },
        { ...base, type: 'credential_issued', title: 'New credential', body: 'x' },
      ],
    });
    const list = (await as(ctx, owner, { method: 'GET', url: '/api/notifications' })).json();
    expect(list.unread).toBe(1);
    expect(list.notifications).toHaveLength(1);
    expect(list.notifications[0]).toMatchObject({ kind: 'expired_link', ...EXPIRED, document: 'Lease' });
  });

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

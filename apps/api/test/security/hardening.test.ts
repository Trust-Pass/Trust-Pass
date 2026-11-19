import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { countPlainMetadata, encryptLegacyMetadata } from '../../src/services/metadata-migration';
import { as, createTestContext, freshIp, loginUser, PASSWORD, registerUser, resetDatabase, type TestContext } from '../helpers';

/** Findings of the pre-design security review (19 Nov 2026) and their fixes. */

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestContext();
});
afterAll(async () => {
  await ctx.app.close();
});
beforeEach(async () => {
  ctx.clock.now = new Date();
  ctx.mail.length = 0;
  await resetDatabase(ctx.prisma);
});

const NEW_PASSWORD = 'Another-Strong-Passw0rd-42';

describe('organization roles', () => {
  it('an organization admin can neither add an owner nor promote themselves', async () => {
    const owner = await registerUser(ctx, { organization: 'Example Company' });
    const admin = await registerUser(ctx);
    const friend = await registerUser(ctx);
    const add = (by: typeof owner, email: string, role: string) =>
      as(ctx, by, { method: 'POST', url: `/api/organizations/${owner.orgId}/members`, payload: { email, role } });

    expect((await add(owner, admin.email, 'admin')).statusCode).toBe(201);
    expect((await add(admin, friend.email, 'owner')).statusCode).toBe(400);
    expect(await ctx.prisma.organizationMember.count({ where: { orgId: owner.orgId, userId: friend.userId } })).toBe(0);
    const promote = await as(ctx, admin, { method: 'PATCH', url: `/api/organizations/${owner.orgId}/members/${admin.userId}`, payload: { role: 'owner' } });
    expect(promote.statusCode).toBe(403);
    expect((await ctx.prisma.organizationMember.findFirstOrThrow({ where: { orgId: owner.orgId, userId: admin.userId } })).role).toBe('admin');
    expect((await add(admin, friend.email, 'member')).statusCode).toBe(201);
  });

  it('the security log stores the added member as a user id, not an email address', async () => {
    const owner = await registerUser(ctx, { organization: 'Example Company' });
    const member = await registerUser(ctx);
    await as(ctx, owner, { method: 'POST', url: `/api/organizations/${owner.orgId}/members`, payload: { email: member.email, role: 'member' } });
    const event = await ctx.prisma.securityEvent.findFirstOrThrow({ where: { eventType: 'org_member_added' } });
    expect(event.metadata).toMatchObject({ member: member.userId });
    expect(JSON.stringify(event.metadata)).not.toContain('@');
  });

  it('the backfill removes member emails from older log rows, keeping the row and its id', async () => {
    const owner = await registerUser(ctx, { organization: 'Example Company' });
    const old = await ctx.prisma.securityEvent.create({
      data: { userId: owner.userId, eventType: 'org_member_added', metadata: { orgId: owner.orgId, member: 'someone@example.test', role: 'member' } },
    });
    expect((await countPlainMetadata(ctx.prisma)).logRows).toBe(1);
    await encryptLegacyMetadata({ config: ctx.config, prisma: ctx.prisma });
    const after = await ctx.prisma.securityEvent.findUniqueOrThrow({ where: { id: old.id } });
    expect(after.metadata).toEqual({ orgId: owner.orgId, role: 'member' });
    expect((await countPlainMetadata(ctx.prisma)).logRows).toBe(0);
  });
});

describe('password reset links', () => {
  async function requestReset(email: string) {
    const res = await ctx.app.inject({ method: 'POST', url: '/api/auth/password-reset/request', payload: { email }, remoteAddress: freshIp() });
    expect(res.statusCode).toBe(200);
    const text = ctx.mail[ctx.mail.length - 1]!.text;
    return text.match(/#token=([A-Za-z0-9_-]+)/)![1]!;
  }
  const confirm = (token: string, password = NEW_PASSWORD) =>
    ctx.app.inject({ method: 'POST', url: '/api/auth/password-reset/confirm', payload: { token, password }, remoteAddress: freshIp() });

  it('using one reset link cancels every other open link of the account', async () => {
    const user = await registerUser(ctx);
    const first = await requestReset(user.email);
    const second = await requestReset(user.email);
    expect((await confirm(second)).statusCode).toBe(200);
    const stale = await confirm(first, 'Yet-Another-Passw0rd-77');
    expect(stale.statusCode).toBe(400);
    expect(stale.json().error.code).toBe('invalid_reset_token');
    await loginUser(ctx, user.email, NEW_PASSWORD);
  });

  it('changing the password cancels reset links requested before', async () => {
    const user = await registerUser(ctx);
    const token = await requestReset(user.email);
    const change = await as(ctx, user, { method: 'POST', url: '/api/me/password', payload: { currentPassword: PASSWORD, newPassword: NEW_PASSWORD } });
    expect(change.statusCode).toBe(200);
    expect((await confirm(token, 'Attacker-Chosen-Passw0rd-9')).statusCode).toBe(400);
    await loginUser(ctx, user.email, NEW_PASSWORD);
  });

  it('two simultaneous uses of the same link: exactly one succeeds', async () => {
    const user = await registerUser(ctx);
    const token = await requestReset(user.email);
    const [first, second] = [`${NEW_PASSWORD}-first`, `${NEW_PASSWORD}-second`];
    const results = await Promise.all([confirm(token, first), confirm(token, second)]);
    expect(results.map((r) => r.statusCode).sort()).toEqual([200, 400]);
  });
});

describe('sessions', () => {
  it('a malformed session id answers 404, not a server error', async () => {
    const user = await registerUser(ctx);
    const res = await as(ctx, user, { method: 'DELETE', url: '/api/me/sessions/not-a-uuid' });
    expect(res.statusCode).toBe(404);
  });
});

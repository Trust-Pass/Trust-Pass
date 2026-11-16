import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  as,
  createTestContext,
  freshIp,
  loginUser,
  PASSWORD,
  registerUser,
  resetDatabase,
  uniqueEmail,
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
  ctx.mail.length = 0;
});

describe('registration', () => {
  it('creates an individual account with an Argon2id hash and a session', async () => {
    const email = uniqueEmail();
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { accountType: 'individual', fullName: 'Reham', email, password: PASSWORD },
      remoteAddress: freshIp(),
    });
    expect(res.statusCode).toBe(201);
    expect(res.json().user).not.toHaveProperty('passwordHash');
    const user = await ctx.prisma.user.findUniqueOrThrow({ where: { email } });
    expect(user.passwordHash).toMatch(/^\$argon2id\$/);
    expect(user.passwordHash).not.toContain(PASSWORD);

    const cookie = res.cookies.find((c) => c.name === 'tp_session')!;
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.sameSite).toBe('Lax');
    expect(cookie.path).toBe('/');
    const session = await ctx.prisma.session.findFirstOrThrow({ where: { userId: user.id } });
    expect(session.tokenHash).not.toBe(cookie.value);
  });

  it('creates an organization account owned by the registering user', async () => {
    const s = await registerUser(ctx, { organization: 'Example Company' });
    const me = await as(ctx, s, { method: 'GET', url: '/api/auth/me' });
    expect(me.json().organizations).toEqual([expect.objectContaining({ name: 'Example Company', role: 'owner' })]);
    expect(me.json().user.accountType).toBe('organization');
  });

  it('normalises email case and rejects duplicates', async () => {
    const email = uniqueEmail();
    await registerUser(ctx, { email });
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { accountType: 'individual', fullName: 'Copy', email: email.toUpperCase(), password: PASSWORD },
      remoteAddress: freshIp(),
    });
    expect(res.statusCode).toBe(409);
  });

  it('validates input on the server', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { accountType: 'individual', fullName: 'x', email: 'not-an-email', password: 'short' },
      remoteAddress: freshIp(),
    });
    expect(res.statusCode).toBe(400);
    expect(Object.keys(res.json().error.details.fields)).toEqual(expect.arrayContaining(['email', 'password', 'fullName']));
  });

  it('cannot self-register as an admin', async () => {
    const email = uniqueEmail();
    await ctx.app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { accountType: 'individual', fullName: 'Mallory', email, password: PASSWORD, role: 'admin' },
      remoteAddress: freshIp(),
    });
    const user = await ctx.prisma.user.findUniqueOrThrow({ where: { email } });
    expect(user.role).toBe('user');
  });
});

describe('login and logout', () => {
  it('signs in with the right password and records the event', async () => {
    const s = await registerUser(ctx);
    const login = await loginUser(ctx, s.email);
    expect(login.token).not.toBe(s.token); // a fresh session every login
    const events = await ctx.prisma.securityEvent.findMany({ where: { userId: s.userId, eventType: 'login_succeeded' } });
    expect(events).toHaveLength(1);
  });

  it('gives the same error for a wrong password and an unknown email', async () => {
    const s = await registerUser(ctx);
    const wrong = await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: s.email, password: 'Wrong-Password-123' }, remoteAddress: freshIp() });
    const unknown = await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: uniqueEmail(), password: 'Wrong-Password-123' }, remoteAddress: freshIp() });
    expect(wrong.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(wrong.json().error.message).toBe(unknown.json().error.message);
  });

  it('locks the account for 15 minutes after 5 wrong passwords and notifies the owner', async () => {
    const s = await registerUser(ctx);
    for (let i = 0; i < 5; i++) {
      await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: s.email, password: `Wrong-Password-${i}` }, remoteAddress: freshIp() });
    }
    const locked = await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: s.email, password: PASSWORD }, remoteAddress: freshIp() });
    expect(locked.statusCode).toBe(429);
    expect(locked.json().error.code).toBe('account_locked');
    expect(await ctx.prisma.notification.count({ where: { userId: s.userId, type: 'account_locked' } })).toBe(1);

    ctx.clock.advance(16 * 60_000);
    const after = await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: s.email, password: PASSWORD }, remoteAddress: freshIp() });
    expect(after.statusCode).toBe(200);
  });

  it('rate-limits repeated login attempts from one address for one email', async () => {
    const s = await registerUser(ctx);
    const ip = freshIp();
    const codes: number[] = [];
    for (let i = 0; i < 12; i++) {
      const res = await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: s.email, password: `nope-${i}-xxxxxxxx` }, remoteAddress: ip });
      codes.push(res.statusCode);
    }
    expect(codes.slice(-2)).toEqual([429, 429]);
  });

  it('logs out and the old session no longer works', async () => {
    const s = await registerUser(ctx);
    expect((await as(ctx, s, { method: 'GET', url: '/api/auth/me' })).statusCode).toBe(200);
    expect((await as(ctx, s, { method: 'POST', url: '/api/auth/logout' })).statusCode).toBe(200);
    expect((await as(ctx, s, { method: 'GET', url: '/api/auth/me' })).statusCode).toBe(401);
  });

  it('expires sessions after one hour idle', async () => {
    const s = await registerUser(ctx);
    ctx.clock.advance(61 * 60_000);
    expect((await as(ctx, s, { method: 'GET', url: '/api/auth/me' })).statusCode).toBe(401);
  });

  it('suspended users cannot sign in and lose their sessions', async () => {
    const s = await registerUser(ctx);
    await ctx.prisma.user.update({ where: { id: s.userId }, data: { status: 'suspended' } });
    expect((await as(ctx, s, { method: 'GET', url: '/api/auth/me' })).statusCode).toBe(401);
    const res = await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: s.email, password: PASSWORD }, remoteAddress: freshIp() });
    expect(res.statusCode).toBe(403);
  });
});

describe('CSRF protection', () => {
  it('rejects a signed-in state change without the CSRF token', async () => {
    const s = await registerUser(ctx);
    const res = await ctx.app.inject({
      method: 'PATCH',
      url: '/api/me',
      cookies: { tp_session: s.token },
      payload: { fullName: 'Changed By Attacker' },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('csrf_failed');
  });

  it('rejects a request from another origin even with a token', async () => {
    const s = await registerUser(ctx);
    const res = await as(ctx, s, { method: 'PATCH', url: '/api/me', payload: { fullName: 'X Y' }, headers: { origin: 'https://evil.example' } });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('bad_origin');
  });

  it('accepts same-origin requests with the token', async () => {
    const s = await registerUser(ctx);
    const res = await as(ctx, s, { method: 'PATCH', url: '/api/me', payload: { fullName: 'Reham Updated' }, headers: { origin: 'http://localhost:5173' } });
    expect(res.statusCode).toBe(200);
    expect(res.json().user.fullName).toBe('Reham Updated');
  });
});

describe('password reset and change', () => {
  it('resets the password with a one-time emailed token and ends all sessions', async () => {
    const s = await registerUser(ctx);
    const req = await ctx.app.inject({ method: 'POST', url: '/api/auth/password-reset/request', payload: { email: s.email }, remoteAddress: freshIp() });
    expect(req.statusCode).toBe(200);
    expect(ctx.mail).toHaveLength(1);
    const token = ctx.mail[0]!.text.match(/token=([A-Za-z0-9_-]+)/)![1]!;
    expect(await ctx.prisma.passwordResetToken.count({ where: { tokenHash: token } })).toBe(0); // only the hash is stored

    const newPassword = 'Brand-New-Password-42';
    const confirm = await ctx.app.inject({ method: 'POST', url: '/api/auth/password-reset/confirm', payload: { token, password: newPassword }, remoteAddress: freshIp() });
    expect(confirm.statusCode).toBe(200);
    expect((await as(ctx, s, { method: 'GET', url: '/api/auth/me' })).statusCode).toBe(401);
    await loginUser(ctx, s.email, newPassword);

    const reuse = await ctx.app.inject({ method: 'POST', url: '/api/auth/password-reset/confirm', payload: { token, password: 'Another-Password-77' }, remoteAddress: freshIp() });
    expect(reuse.statusCode).toBe(400);
  });

  it('answers the same for unknown emails and sends nothing', async () => {
    const res = await ctx.app.inject({ method: 'POST', url: '/api/auth/password-reset/request', payload: { email: uniqueEmail() }, remoteAddress: freshIp() });
    expect(res.statusCode).toBe(200);
    expect(ctx.mail).toHaveLength(0);
  });

  it('rejects expired reset tokens', async () => {
    const s = await registerUser(ctx);
    await ctx.app.inject({ method: 'POST', url: '/api/auth/password-reset/request', payload: { email: s.email }, remoteAddress: freshIp() });
    const token = ctx.mail[0]!.text.match(/token=([A-Za-z0-9_-]+)/)![1]!;
    ctx.clock.advance(31 * 60_000);
    const res = await ctx.app.inject({ method: 'POST', url: '/api/auth/password-reset/confirm', payload: { token, password: 'Brand-New-Password-42' }, remoteAddress: freshIp() });
    expect(res.statusCode).toBe(400);
  });

  it('changes the password only with the current one, and signs out other sessions', async () => {
    const s = await registerUser(ctx);
    const other = await loginUser(ctx, s.email);
    const wrong = await as(ctx, s, { method: 'POST', url: '/api/me/password', payload: { currentPassword: 'nope', newPassword: 'Another-Long-Password-1' } });
    expect(wrong.statusCode).toBe(400);
    const ok = await as(ctx, s, { method: 'POST', url: '/api/me/password', payload: { currentPassword: PASSWORD, newPassword: 'Another-Long-Password-1' } });
    expect(ok.statusCode).toBe(200);
    expect((await as(ctx, other, { method: 'GET', url: '/api/auth/me' })).statusCode).toBe(401);
    expect((await as(ctx, s, { method: 'GET', url: '/api/auth/me' })).statusCode).toBe(200);
  });

  it('lists sessions and can sign out another device', async () => {
    const s = await registerUser(ctx);
    const other = await loginUser(ctx, s.email);
    const list = await as(ctx, s, { method: 'GET', url: '/api/me/sessions' });
    const sessions = list.json().sessions as Array<{ id: string; current: boolean }>;
    expect(sessions).toHaveLength(2);
    const target = sessions.find((x) => !x.current)!;
    expect((await as(ctx, s, { method: 'DELETE', url: `/api/me/sessions/${target.id}` })).statusCode).toBe(200);
    expect((await as(ctx, other, { method: 'GET', url: '/api/auth/me' })).statusCode).toBe(401);
  });
});

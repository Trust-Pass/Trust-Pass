/**
 * Safe, authorised security tests against TrustPass itself, using test data
 * only: injection, XSS, access control, headers, error handling and key
 * management.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  as,
  createLink,
  createTestContext,
  freshIp,
  IPS,
  issueCredential,
  makeAdmin,
  registerUser,
  resetDatabase,
  TEST_SECRETS,
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

const SQLI = ["' OR '1'='1", "admin'--", "'; DROP TABLE users; --", '" OR ""="', "1; SELECT pg_sleep(5)--", "%' UNION SELECT password_hash FROM users --"];

describe('SQL injection', () => {
  it('login treats injection payloads as plain data', async () => {
    const victim = await registerUser(ctx);
    for (const payload of SQLI) {
      const res = await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: victim.email, password: payload }, remoteAddress: freshIp() });
      // 401, or 429 once the account lockout (5 failures) kicks in. Never 200.
      expect([401, 429]).toContain(res.statusCode);
      const asEmail = await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: payload, password: payload }, remoteAddress: freshIp() });
      expect([400, 401]).toContain(asEmail.statusCode);
    }
    expect(await ctx.prisma.user.count()).toBe(1);
  });

  it('search and filter parameters are parameterised', async () => {
    const admin = await registerUser(ctx);
    await makeAdmin(ctx, admin);
    for (const payload of SQLI) {
      const q = encodeURIComponent(payload);
      const started = Date.now();
      expect((await as(ctx, admin, { method: 'GET', url: `/api/organizations/directory?q=${q}` })).statusCode).toBe(200);
      const users = await as(ctx, admin, { method: 'GET', url: `/api/admin/users?q=${q}` });
      expect(users.statusCode).toBe(200);
      expect(users.json().users).toHaveLength(0);
      expect(Date.now() - started).toBeLessThan(3000); // no pg_sleep executed
      expect([400, 200]).toContain((await as(ctx, admin, { method: 'GET', url: `/api/analytics?from=${q}` })).statusCode);
      expect([400, 200]).toContain((await as(ctx, admin, { method: 'GET', url: `/api/activity?type=${q}` })).statusCode);
    }
    expect(await ctx.prisma.user.count()).toBe(1);
  });
});

describe('cross-site scripting', () => {
  const XSS = '<img src=x onerror=alert(document.cookie)><script>alert(1)</script>';

  it('stores script payloads as inert text and serves JSON, never HTML', async () => {
    const s = await registerUser(ctx, { fullName: 'Reham <b>bold</b>' });
    const upload = await uploadDocument(ctx, s, { title: XSS, claims: [{ label: '<svg onload=alert(1)>', value: XSS }] });
    expect(upload.statusCode).toBe(201);
    const id = upload.json().document.id;
    const res = await as(ctx, s, { method: 'GET', url: `/api/documents/${id}` });
    expect(res.headers['content-type']).toContain('application/json');
    expect(res.json().document.title).toBe(XSS); // returned exactly; the React UI renders it as text
    const link = await createLink(ctx, s, id, { includeFile: true, recipientLabel: XSS });
    const shared = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA });
    expect(shared.headers['content-type']).toContain('application/json');
  });

  it('sends a strict Content-Security-Policy with no inline scripts', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/health' });
    const csp = res.headers['content-security-policy'] as string;
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
  });
});

describe('security headers', () => {
  it('sets protective headers on every response', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/health' });
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    // Camera only for our own pages (QR scanner); microphone and location never.
    expect(res.headers['permissions-policy']).toContain('camera=(self)');
    expect(res.headers['permissions-policy']).toContain('microphone=()');
    expect(res.headers['permissions-policy']).toContain('geolocation=()');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('API answers with decrypted data are never cached', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { title: 'Cache probe' })).json().document.id as string;
    for (const url of ['/api/documents', `/api/documents/${id}`, '/api/auth/me', '/api/notifications']) {
      const res = await as(ctx, owner, { method: 'GET', url });
      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('no-store, private');
    }
  });

  it('enables HSTS in production mode', async () => {
    // The fake KMS is refused in production, so this instance uses the legacy env key.
    const prod = await createTestContext({
      KEY_PROVIDER: 'env',
      MASTER_KEY: TEST_SECRETS.MASTER_KEY,
      // A version no stored test key uses (stored keys and legacy keys share one numbering).
      MASTER_KEY_VERSION: '100',
      NODE_ENV: 'production',
      APP_URL: 'https://trustpass.example',
      GEO_PROVIDER: 'mmdb',
      GEO_SIMULATED_MAP: undefined,
    });
    const res = await prod.app.inject({ method: 'GET', url: '/api/health' });
    expect(res.headers['strict-transport-security']).toContain('max-age=31536000');
    await prod.app.close();
    // The production instance marked the test database as production's; clear it so later
    // instances can use the fake KMS again.
    await resetDatabase(ctx.prisma);
  });
});

describe('broken access control', () => {
  it('admin endpoints are refused to regular users and anonymous visitors', async () => {
    const user = await registerUser(ctx);
    const routes: Array<[string, string]> = [
      ['GET', '/api/admin/overview'],
      ['GET', '/api/admin/users'],
      ['GET', '/api/admin/organizations'],
      ['GET', '/api/admin/security-events'],
      ['GET', '/api/admin/issuers'],
      ['GET', '/api/admin/settings'],
      ['GET', '/api/admin/health'],
      ['POST', '/api/admin/retention/run'],
    ];
    for (const [method, url] of routes) {
      expect((await as(ctx, user, { method: method as 'GET', url })).statusCode, url).toBe(403);
      expect((await as(ctx, null, { method: method as 'GET', url })).statusCode, url).toBe(401);
    }
  });

  it('organization management requires membership and the right role', async () => {
    const owner = await registerUser(ctx, { organization: 'Example Company' });
    const stranger = await registerUser(ctx);
    const member = await registerUser(ctx);
    await as(ctx, owner, { method: 'POST', url: `/api/organizations/${owner.orgId}/members`, payload: { email: member.email, role: 'member' } });

    expect((await as(ctx, stranger, { method: 'GET', url: `/api/organizations/${owner.orgId}` })).statusCode).toBe(404);
    expect((await as(ctx, stranger, { method: 'POST', url: `/api/organizations/${owner.orgId}/members`, payload: { email: stranger.email, role: 'admin' } })).statusCode).toBe(404);
    // A plain member cannot promote themselves or add people.
    expect((await as(ctx, member, { method: 'PATCH', url: `/api/organizations/${owner.orgId}/members/${member.userId}`, payload: { role: 'owner' } })).statusCode).toBe(403);
    expect((await as(ctx, member, { method: 'POST', url: `/api/organizations/${owner.orgId}/members`, payload: { email: stranger.email, role: 'member' } })).statusCode).toBe(403);
    // The last owner cannot be removed.
    expect((await as(ctx, owner, { method: 'DELETE', url: `/api/organizations/${owner.orgId}/members/${owner.userId}` })).statusCode).toBe(409);
  });

  it('suspending a user takes effect immediately', async () => {
    const admin = await registerUser(ctx);
    await makeAdmin(ctx, admin);
    const user = await registerUser(ctx);
    expect((await as(ctx, admin, { method: 'PATCH', url: `/api/admin/users/${user.userId}`, payload: { status: 'suspended' } })).statusCode).toBe(200);
    expect((await as(ctx, user, { method: 'GET', url: '/api/documents' })).statusCode).toBe(401);
  });

  it('mass assignment of protected fields is ignored', async () => {
    const s = await registerUser(ctx);
    await as(ctx, s, { method: 'PATCH', url: '/api/me', payload: { fullName: 'New Name', role: 'admin', status: 'active', email: 'x@evil.test' } });
    const user = await ctx.prisma.user.findUniqueOrThrow({ where: { id: s.userId } });
    expect(user.role).toBe('user');
    expect(user.email).toBe(s.email);
  });
});

describe('API hardening', () => {
  it('returns generic JSON errors without stack traces', async () => {
    const s = await registerUser(ctx);
    const bad = await as(ctx, s, { method: 'POST', url: '/api/documents/not-json/links', payload: '{"broken"', headers: { 'content-type': 'application/json' } });
    expect(bad.statusCode).toBeGreaterThanOrEqual(400);
    expect(bad.body).not.toMatch(/at .*\.ts|node_modules|stack/);
    const missing = await ctx.app.inject({ method: 'GET', url: '/api/does-not-exist' });
    expect(missing.statusCode).toBe(404);
    expect(missing.json().error.code).toBe('not_found');
  });

  it('limits JSON body size', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email: 'a@b.co', password: 'x'.repeat(400_000) },
      remoteAddress: freshIp(),
    });
    expect(res.statusCode).toBe(413);
  });

  it('ignores client-supplied request ids', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/auth/me', headers: { 'request-id': 'attacker-chosen' } });
    expect(res.json().requestId).not.toBe('attacker-chosen');
  });
});

describe('encryption and key management', () => {
  it('never sends key material to the client', async () => {
    const s = await registerUser(ctx);
    const credId = await issueCredential(ctx, s);
    const fileId = (await uploadDocument(ctx, s)).json().document.id;
    const link = await createLink(ctx, s, credId, { includeFile: true });
    const keys = await ctx.prisma.documentKey.findMany();
    const forbidden = [
      TEST_SECRETS.MASTER_KEY,
      TEST_SECRETS.ISSUER_SIGNING_SEED,
      TEST_SECRETS.IP_HASH_SECRET,
      ctx.config.masterKeys.current.key.toString('base64'),
      ctx.config.masterKeys.current.key.toString('hex'),
      ctx.config.linkTokenKeys.current.key.toString('base64'),
      ctx.config.linkTokenKeys.current.key.toString('hex'),
      ctx.config.issuerSeed.toString('base64url'),
      ...keys.flatMap((k) => [Buffer.from(k.wrappedDek).toString('base64'), Buffer.from(k.wrappedDek).toString('hex')]),
    ];
    const responses = await Promise.all([
      as(ctx, s, { method: 'GET', url: '/api/documents' }),
      as(ctx, s, { method: 'GET', url: `/api/documents/${credId}` }),
      as(ctx, s, { method: 'GET', url: `/api/documents/${fileId}` }),
      as(ctx, s, { method: 'GET', url: '/api/links' }),
      as(ctx, s, { method: 'GET', url: `/api/links/${link.id}` }),
      as(ctx, s, { method: 'GET', url: '/api/issuer' }),
      as(ctx, s, { method: 'GET', url: '/api/auth/me' }),
      ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA }),
    ]);
    for (const res of responses) {
      for (const secret of forbidden) expect(res.body.includes(secret)).toBe(false);
      expect(res.body).not.toMatch(/wrappedDek|wrapIv|encIv|encTag|tokenHash|passwordHash|csrf_token|ipHmac/);
    }
  });

  it('issuer public key is published, private key never', async () => {
    const s = await registerUser(ctx);
    const info = (await as(ctx, s, { method: 'GET', url: '/api/issuer' })).json();
    expect(info.issuer.keyId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const issuer = await ctx.prisma.issuer.findFirstOrThrow();
    expect(issuer.publicKeyJwk).not.toHaveProperty('d');
  });
});

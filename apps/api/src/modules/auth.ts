import argon2 from 'argon2';
import type { FastifyInstance } from 'fastify';
import {
  changePasswordSchema,
  loginSchema,
  passwordResetConfirmSchema,
  passwordResetRequestSchema,
  registerSchema,
  updateProfileSchema,
} from '@trustpass/shared';
import { hashToken, randomToken } from '../lib/crypto';
import { AppError, notFound, parse } from '../lib/errors';
import { describeConnection } from '../lib/connection';
import { userAgentFamily } from '../lib/user-agent';
import { clearSessionCookie, requireUser, startSession } from '../plugins/auth';
import { logEvent, notify } from '../services/audit';
import { publicUser, userOrganizations } from '../services/users';

// OWASP-recommended Argon2id parameters (19 MiB, 2 iterations).
const ARGON_OPTIONS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;
const MAX_FAILED_LOGINS = 5;
const LOCK_MINUTES = 15;
const RESET_TOKEN_MINUTES = 30;

let dummyHash: Promise<string> | null = null;
/** Verify against a dummy hash for unknown emails so response time does not reveal which accounts exist. */
function getDummyHash() {
  dummyHash ??= argon2.hash(randomToken(16), ARGON_OPTIONS);
  return dummyHash;
}

export function hashPassword(password: string) {
  return argon2.hash(password, ARGON_OPTIONS);
}

function slugify(name: string) {
  const base = name
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return `${base || 'org'}-${randomToken(4).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 5)}`;
}

export async function authRoutes(app: FastifyInstance) {
  const { prisma, config, mailer, now } = app.deps;
  const genericLoginError = () => new AppError(401, 'invalid_credentials', 'Incorrect email or password');

  app.post(
    '/api/auth/register',
    // Generous per-IP limit: a whole classroom may share one public IP.
    { config: { rateLimit: { max: 100, timeWindow: '1 hour' } } },
    async (request, reply) => {
      const input = parse(registerSchema, request.body);
      const existing = await prisma.user.findUnique({ where: { email: input.email } });
      if (existing) throw new AppError(409, 'email_taken', 'An account with this email already exists. Try signing in.');

      const passwordHash = await hashPassword(input.password);
      const user = await prisma.$transaction(async (tx) => {
        const created = await tx.user.create({
          data: { email: input.email, passwordHash, fullName: input.fullName, accountType: input.accountType },
        });
        if (input.accountType === 'organization') {
          const org = await tx.organization.create({
            data: { name: input.organizationName, type: input.organizationType, slug: slugify(input.organizationName) },
          });
          await tx.organizationMember.create({ data: { orgId: org.id, userId: created.id, role: 'owner' } });
        }
        await logEvent(tx, {
          userId: created.id,
          actorUserId: created.id,
          eventType: 'account_created',
          metadata: { accountType: input.accountType },
        });
        return created;
      });

      const { csrfToken } = await startSession(app, request, reply, user);
      return reply.status(201).send({
        user: publicUser(user),
        organizations: await userOrganizations(prisma, user.id),
        csrfToken,
      });
    },
  );

  app.post(
    '/api/auth/login',
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: '15 minutes',
          // Per IP and email, so one person's typos never lock out a shared Wi-Fi.
          keyGenerator: (req) => {
            const email = (req.body as { email?: unknown } | undefined)?.email;
            return `${req.clientIp}|${typeof email === 'string' ? email.toLowerCase().slice(0, 254) : ''}`;
          },
        },
      },
    },
    async (request, reply) => {
      const input = parse(loginSchema, request.body);
      const user = await prisma.user.findUnique({ where: { email: input.email } });
      if (!user) {
        await argon2.verify(await getDummyHash(), input.password).catch(() => false);
        throw genericLoginError();
      }

      const current = now();
      if (user.lockedUntil && user.lockedUntil > current) {
        const minutes = Math.ceil((user.lockedUntil.getTime() - current.getTime()) / 60000);
        throw new AppError(429, 'account_locked', `Too many failed attempts. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`);
      }

      const valid = await argon2.verify(user.passwordHash, input.password).catch(() => false);
      if (!valid) {
        const failed = user.failedLogins + 1;
        const lock = failed >= MAX_FAILED_LOGINS;
        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLogins: lock ? 0 : failed,
            lockedUntil: lock ? new Date(current.getTime() + LOCK_MINUTES * 60_000) : user.lockedUntil,
          },
        });
        await logEvent(prisma, {
          userId: user.id,
          eventType: lock ? 'account_locked' : 'login_failed',
          severity: lock ? 'high' : 'warning',
          metadata: { client: userAgentFamily(request.headers['user-agent']), attempt: failed },
        });
        if (lock) {
          await notify(prisma, {
            userId: user.id,
            type: 'account_locked',
            title: 'Your account was temporarily locked',
            body: `${MAX_FAILED_LOGINS} wrong passwords were entered in a row. Sign-in is paused for ${LOCK_MINUTES} minutes. If this was not you, change your password afterwards.`,
          });
        }
        throw genericLoginError();
      }

      if (user.status !== 'active') throw new AppError(403, 'account_suspended', 'This account is suspended. Contact the administrator.');

      if (argon2.needsRehash(user.passwordHash, ARGON_OPTIONS)) {
        await prisma.user.update({ where: { id: user.id }, data: { passwordHash: await hashPassword(input.password) } });
      }
      await prisma.user.update({ where: { id: user.id }, data: { failedLogins: 0, lockedUntil: null } });
      // Session fixation defence: always issue a brand-new session token.
      const { csrfToken } = await startSession(app, request, reply, user);
      await logEvent(prisma, {
        userId: user.id,
        actorUserId: user.id,
        eventType: 'login_succeeded',
        metadata: { client: userAgentFamily(request.headers['user-agent']) },
      });
      return { user: publicUser(user), organizations: await userOrganizations(prisma, user.id), csrfToken };
    },
  );

  app.post('/api/auth/logout', async (request, reply) => {
    if (request.auth) {
      await prisma.session.deleteMany({ where: { id: request.auth.session.id } });
      await logEvent(prisma, { userId: request.auth.user.id, actorUserId: request.auth.user.id, eventType: 'logout' });
    }
    clearSessionCookie(app, reply);
    return { ok: true };
  });

  // Same as /api/auth/me, but answers 200 { authenticated: false } for visitors,
  // so public pages do not log a 401 on every load.
  app.get('/api/auth/session', async (request) => {
    if (!request.auth) return { authenticated: false };
    const { user, session } = request.auth;
    const unread = await prisma.notification.count({ where: { userId: user.id, readAt: null } });
    return {
      authenticated: true,
      user: publicUser(user),
      organizations: await userOrganizations(prisma, user.id),
      csrfToken: session.csrfToken,
      unreadNotifications: unread,
    };
  });

  app.get('/api/auth/me', async (request) => {
    const { user, session } = requireUser(request);
    const unread = await prisma.notification.count({ where: { userId: user.id, readAt: null } });
    return {
      user: publicUser(user),
      organizations: await userOrganizations(prisma, user.id),
      csrfToken: session.csrfToken,
      unreadNotifications: unread,
    };
  });

  app.post(
    '/api/auth/password-reset/request',
    {
      config: {
        rateLimit: {
          max: 5,
          timeWindow: '1 hour',
          keyGenerator: (req) => {
            const email = (req.body as { email?: unknown } | undefined)?.email;
            return `reset:${req.clientIp}|${typeof email === 'string' ? email.toLowerCase().slice(0, 254) : ''}`;
          },
        },
      },
    },
    async (request) => {
      const { email } = parse(passwordResetRequestSchema, request.body);
      const user = await prisma.user.findUnique({ where: { email } });
      // Same response whether or not the account exists (no account enumeration).
      if (user && user.status === 'active') {
        const token = randomToken(32);
        await prisma.passwordResetToken.create({
          data: { userId: user.id, tokenHash: hashToken(token), expiresAt: new Date(now().getTime() + RESET_TOKEN_MINUTES * 60_000) },
        });
        await logEvent(prisma, { userId: user.id, eventType: 'password_reset_requested', severity: 'warning' });
        const link = `${config.env.APP_URL}/reset-password#token=${token}`;
        await mailer.send({
          to: user.email,
          subject: 'Reset your TrustPass password',
          text: `Hello ${user.fullName},\n\nUse this link within ${RESET_TOKEN_MINUTES} minutes to choose a new password:\n${link}\n\nIf you did not ask for this, you can ignore this email. Your password has not changed.\n\nTrustPass`,
        });
      }
      return { ok: true, message: 'If an account exists for that email, a reset link is on its way.' };
    },
  );

  app.post(
    '/api/auth/password-reset/confirm',
    { config: { rateLimit: { max: 20, timeWindow: '1 hour' } } },
    async (request) => {
      const input = parse(passwordResetConfirmSchema, request.body);
      const record = await prisma.passwordResetToken.findUnique({ where: { tokenHash: hashToken(input.token) } });
      if (!record || record.usedAt || record.expiresAt <= now()) {
        throw new AppError(400, 'invalid_reset_token', 'This reset link is invalid or has expired. Request a new one.');
      }
      const passwordHash = await hashPassword(input.password);
      const used = await prisma.$transaction(async (tx) => {
        // Consume the token atomically: of two simultaneous requests with the same link, one wins.
        const claimed = await tx.passwordResetToken.updateMany({ where: { id: record.id, usedAt: null }, data: { usedAt: now() } });
        if (claimed.count === 0) return false;
        // Every other reset link of this account stops working too.
        await tx.passwordResetToken.updateMany({ where: { userId: record.userId, usedAt: null }, data: { usedAt: now() } });
        await tx.user.update({ where: { id: record.userId }, data: { passwordHash, failedLogins: 0, lockedUntil: null } });
        // Every existing session ends: whoever knew the old password is signed out.
        await tx.session.deleteMany({ where: { userId: record.userId } });
        return true;
      });
      if (!used) throw new AppError(400, 'invalid_reset_token', 'This reset link is invalid or has expired. Request a new one.');
      await logEvent(prisma, { userId: record.userId, eventType: 'password_reset_completed', severity: 'warning' });
      return { ok: true };
    },
  );

  // ---- Profile and sessions -------------------------------------------------

  app.patch('/api/me', async (request) => {
    const { user } = requireUser(request);
    const input = parse(updateProfileSchema, request.body);
    const updated = await prisma.user.update({ where: { id: user.id }, data: { fullName: input.fullName } });
    await logEvent(prisma, { userId: user.id, actorUserId: user.id, eventType: 'profile_updated' });
    return { user: publicUser(updated) };
  });

  app.post(
    '/api/me/password',
    { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } },
    async (request) => {
      const { user, session } = requireUser(request);
      const input = parse(changePasswordSchema, request.body);
      const valid = await argon2.verify(user.passwordHash, input.currentPassword).catch(() => false);
      if (!valid) throw new AppError(400, 'wrong_password', 'Your current password is incorrect');
      await prisma.$transaction([
        prisma.user.update({ where: { id: user.id }, data: { passwordHash: await hashPassword(input.newPassword) } }),
        prisma.session.deleteMany({ where: { userId: user.id, id: { not: session.id } } }),
        // A reset link requested earlier must not undo this change.
        prisma.passwordResetToken.updateMany({ where: { userId: user.id, usedAt: null }, data: { usedAt: now() } }),
      ]);
      await logEvent(prisma, { userId: user.id, actorUserId: user.id, eventType: 'password_changed', severity: 'warning' });
      return { ok: true };
    },
  );

  // Where TrustPass believes the signed-in user is connecting from (no IP addresses returned).
  app.get('/api/me/connection', async (request) => {
    requireUser(request);
    return describeConnection(request, app.deps.geo, app.deps.config.clientIpHeader);
  });

  app.get('/api/me/sessions', async (request) => {
    const { user, session } = requireUser(request);
    const sessions = await prisma.session.findMany({ where: { userId: user.id }, orderBy: { lastSeenAt: 'desc' } });
    return {
      sessions: sessions.map((s) => ({
        id: s.id,
        client: s.userAgentFamily,
        createdAt: s.createdAt,
        lastSeenAt: s.lastSeenAt,
        current: s.id === session.id,
      })),
    };
  });

  app.delete<{ Params: { id: string } }>('/api/me/sessions/:id', async (request) => {
    const { user, session } = requireUser(request);
    if (!/^[0-9a-f-]{36}$/i.test(request.params.id)) throw notFound('Session');
    if (request.params.id === session.id) throw new AppError(400, 'current_session', 'Use Sign out to end the current session');
    const result = await prisma.session.deleteMany({ where: { id: request.params.id, userId: user.id } });
    if (result.count === 0) throw notFound('Session');
    await logEvent(prisma, { userId: user.id, actorUserId: user.id, eventType: 'session_revoked' });
    return { ok: true };
  });
}

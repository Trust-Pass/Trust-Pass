import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { User } from '@prisma/client';
import { hashToken, randomToken } from '../lib/crypto';
import { AppError, forbidden, unauthorized } from '../lib/errors';
import { userAgentFamily } from '../lib/user-agent';
import type { AuthContext } from '../types';

/**
 * Session authentication: a 256-bit random token in an HttpOnly cookie. The
 * database stores only its SHA-256 hash. Sessions end after 1 hour idle or
 * 12 hours in total, whichever comes first.
 */
export async function authPlugin(app: FastifyInstance) {
  app.decorateRequest('auth', null);

  app.addHook('onRequest', async (request) => {
    request.auth = null;
    const { config, prisma, now } = app.deps;
    const token = request.cookies[config.cookieName];
    if (!token || token.length > 100) return;

    const session = await prisma.session.findUnique({ where: { tokenHash: hashToken(token) }, include: { user: true } });
    if (!session) return;

    const current = now();
    const idleExpired = current.getTime() - session.lastSeenAt.getTime() > config.sessionIdleMs;
    if (session.expiresAt <= current || idleExpired || session.user.status !== 'active') {
      await prisma.session.deleteMany({ where: { id: session.id } });
      return;
    }
    // Refresh the idle timer at most once a minute.
    if (current.getTime() - session.lastSeenAt.getTime() > 60_000) {
      await prisma.session.update({ where: { id: session.id }, data: { lastSeenAt: current } });
    }
    const { user, ...sessionOnly } = session;
    request.auth = { user, session: sessionOnly };
  });
}

export function requireUser(request: FastifyRequest): AuthContext {
  if (!request.auth) throw unauthorized();
  return request.auth;
}

export function requireAdmin(request: FastifyRequest): AuthContext {
  const auth = requireUser(request);
  if (auth.user.role !== 'admin') throw forbidden('Administrator access is required');
  return auth;
}

export async function startSession(app: FastifyInstance, request: FastifyRequest, reply: FastifyReply, user: User) {
  const { config, prisma, now } = app.deps;
  const token = randomToken(32);
  const csrfToken = randomToken(32);
  const current = now();
  const expiresAt = new Date(current.getTime() + config.sessionAbsoluteMs);
  await prisma.session.create({
    data: {
      userId: user.id,
      tokenHash: hashToken(token),
      csrfToken,
      userAgentFamily: userAgentFamily(request.headers['user-agent']),
      createdAt: current,
      lastSeenAt: current,
      expiresAt,
    },
  });
  reply.setCookie(config.cookieName, token, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'lax',
    path: '/',
    expires: expiresAt,
  });
  return { csrfToken };
}

export function clearSessionCookie(app: FastifyInstance, reply: FastifyReply) {
  const { config } = app.deps;
  reply.clearCookie(config.cookieName, { path: '/', httpOnly: true, secure: config.cookieSecure, sameSite: 'lax' });
}

export function assertActiveAccount(user: User) {
  if (user.status !== 'active') throw new AppError(403, 'account_suspended', 'This account is suspended');
}

import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import type { FastifyInstance } from 'fastify';
import { safeEqual } from '../lib/crypto';
import { AppError } from '../lib/errors';

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export async function securityPlugin(app: FastifyInstance) {
  const { config } = app.deps;

  await app.register(helmet, {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        fontSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        workerSrc: ["'self'", 'blob:'],
        objectSrc: ["'none'"],
        frameSrc: ["'self'", 'blob:'],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        ...(config.isProduction ? { upgradeInsecureRequests: [] } : {}),
      },
    },
    // Share tokens live in URLs, so never leak them through the Referer header.
    referrerPolicy: { policy: 'no-referrer' },
    hsts: config.isProduction ? { maxAge: 31536000, includeSubDomains: true } : false,
    crossOriginEmbedderPolicy: false,
  });

  app.addHook('onSend', async (_request, reply) => {
    reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  });

  // Limits are per route (see each route's config.rateLimit); nothing global.
  // Signed-in requests are counted per user, so a classroom sharing one
  // public IP address does not lock itself out.
  await app.register(rateLimit, {
    global: false,
    keyGenerator: (request) => (request.auth ? `user:${request.auth.user.id}` : `ip:${request.clientIp}`),
  });

  /**
   * CSRF protection for every state-changing API request:
   *  1. If the browser sends an Origin header it must be our own origin.
   *  2. Signed-in requests must echo the session's CSRF token in X-CSRF-Token.
   * Session cookies are also SameSite=Lax.
   */
  app.addHook('preHandler', async (request) => {
    if (!MUTATING.has(request.method) || !request.url.startsWith('/api/')) return;

    const origin = request.headers.origin;
    if (origin && origin !== config.appOrigin) {
      throw new AppError(403, 'bad_origin', 'Request blocked: it did not come from the TrustPass website');
    }
    if (request.auth) {
      const sent = request.headers['x-csrf-token'];
      if (typeof sent !== 'string' || !safeEqual(sent, request.auth.session.csrfToken)) {
        throw new AppError(403, 'csrf_failed', 'Your session security check failed. Reload the page and try again.');
      }
    }
  });
}

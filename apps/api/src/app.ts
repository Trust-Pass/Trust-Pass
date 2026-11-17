import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import cookie from '@fastify/cookie';
import multipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import type { PrismaClient } from '@prisma/client';
import Fastify, { type FastifyServerOptions } from 'fastify';
import type { AppConfig } from './config';
import { resolveClientIp } from './lib/connection';
import { errorHandler } from './lib/errors';
import { createGeoProvider, type GeoProvider } from './lib/geo';
import { initKeyring } from './lib/keyring';
import { createKmsProvider, type KmsProvider } from './lib/kms';
import { createMailer, type Mailer } from './lib/mail';
import { createStorage, type ObjectStorage } from './lib/storage';
import { accessRoutes } from './modules/access';
import { adminRoutes } from './modules/admin';
import { authRoutes } from './modules/auth';
import { documentRoutes } from './modules/documents';
import { insightRoutes } from './modules/insights';
import { organizationRoutes } from './modules/organizations';
import { sharingRoutes } from './modules/sharing';
import { verificationRoutes } from './modules/verification';
import { authPlugin } from './plugins/auth';
import { securityPlugin } from './plugins/security';
import type { AppDeps } from './types';

export interface BuildOptions {
  config: AppConfig;
  prisma: PrismaClient;
  storage?: ObjectStorage;
  geo?: GeoProvider;
  mailer?: Mailer;
  now?: () => Date;
  logger?: FastifyServerOptions['logger'];
  /** Overrides the KMS chosen by KEY_PROVIDER (tests). */
  kms?: KmsProvider | null;
}

/** Share tokens appear in URLs; keep them out of logs. */
export function redactUrl(url: string): string {
  return url.replace(/\/(api\/share|s)\/[^/?#]+/g, '/$1/[redacted]');
}

export async function buildApp(options: BuildOptions) {
  const { config, prisma } = options;
  const app = Fastify({
    logger:
      options.logger ?? {
        level: config.env.LOG_LEVEL,
        // No IP addresses or headers in request logs.
        serializers: {
          req: (req) => ({ id: req.id, method: req.method, url: redactUrl(req.url) }),
        },
      },
    // A hop count trusts exactly that many proxies in front of us; anything a
    // client adds further left in X-Forwarded-For is ignored.
    trustProxy:
      typeof config.trustProxy === 'number'
        ? (() => {
            const hops = config.trustProxy as number;
            return (_address: string, hop: number) => hop < hops;
          })()
        : config.trustProxy,
    bodyLimit: 256 * 1024,
    genReqId: () => randomUUID(),
    requestIdHeader: false,
  });

  // Load and verify the encryption keys before anything can read or write a document.
  // Any mismatch stops start-up here rather than failing later on individual documents.
  try {
    await initKeyring({ config, prisma, kms: options.kms !== undefined ? options.kms : createKmsProvider(config), log: app.log });
  } catch (err) {
    await app.close();
    throw err;
  }

  const deps: AppDeps = {
    config,
    prisma,
    storage: options.storage ?? createStorage(config, prisma),
    geo: options.geo ?? (await createGeoProvider(config)),
    mailer: options.mailer ?? createMailer(config, app.log),
    now: options.now ?? (() => new Date()),
  };
  app.decorate('deps', deps);
  app.setErrorHandler(errorHandler);

  // Resolved once per request, before rate limits and the access gate read it.
  app.decorateRequest('clientIp', '');
  app.addHook('onRequest', async (request) => {
    request.clientIp = resolveClientIp(request, config.clientIpHeader);
  });

  await app.register(cookie);
  await app.register(multipart, { limits: { fileSize: config.maxUploadBytes, files: 1, fields: 5 } });
  await authPlugin(app);
  await securityPlugin(app);

  app.get('/api/health', async () => {
    await prisma.$queryRaw`SELECT 1`;
    return { status: 'ok' };
  });

  await authRoutes(app);
  await documentRoutes(app);
  await sharingRoutes(app);
  await accessRoutes(app);
  await verificationRoutes(app);
  await organizationRoutes(app);
  await insightRoutes(app);
  await adminRoutes(app);

  const webDist = config.env.WEB_DIST_DIR ? path.resolve(config.env.WEB_DIST_DIR) : null;
  if (webDist && existsSync(path.join(webDist, 'index.html'))) {
    await app.register(fastifyStatic, { root: webDist, wildcard: false, index: false, maxAge: '1h' });
    app.get('/', (_req, reply) => reply.header('Cache-Control', 'no-cache').sendFile('index.html'));
  }

  app.setNotFoundHandler((request, reply) => {
    if (request.url.startsWith('/api/') || !webDist || request.method !== 'GET') {
      return reply.status(404).send({ error: { code: 'not_found', message: 'Not found' }, requestId: request.id });
    }
    // Client-side routes of the single-page app.
    return reply.header('Cache-Control', 'no-cache').sendFile('index.html');
  });

  return app;
}

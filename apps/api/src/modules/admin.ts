import type { FastifyInstance } from 'fastify';
import { Prisma } from '@prisma/client';
import { updateIssuerStatusSchema, updateSettingsSchema, updateStatusSchema } from '@trustpass/shared';
import { z } from 'zod';
import { AppError, notFound, parse } from '../lib/errors';
import { checkStorage } from '../lib/storage';
import { requireAdmin } from '../plugins/auth';
import { logEvent } from '../services/audit';
import { runRetention } from '../services/retention';
import { getSettings, saveSettings } from '../services/settings';
import { parseId } from './documents';

const startedAt = new Date();

export async function adminRoutes(app: FastifyInstance) {
  const deps = app.deps;
  const { prisma, now, geo, storage, mailer, config } = deps;

  app.get('/api/admin/overview', async (request) => {
    requireAdmin(request);
    const current = now();
    const dayAgo = new Date(current.getTime() - 24 * 60 * 60 * 1000);
    const [users, suspendedUsers, orgs, documents, activeLinks, attempts24h, denied24h, highEvents24h] = await Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { status: 'suspended' } }),
      prisma.organization.count(),
      prisma.document.count({ where: { deletedAt: null } }),
      prisma.sharingLink.count({ where: { revokedAt: null, expiresAt: { gt: current } } }),
      prisma.accessLog.count({ where: { createdAt: { gte: dayAgo } } }),
      prisma.accessLog.count({ where: { createdAt: { gte: dayAgo }, outcome: { not: 'granted' } } }),
      prisma.securityEvent.count({ where: { createdAt: { gte: dayAgo }, severity: { in: ['warning', 'high'] } } }),
    ]);
    return { users, suspendedUsers, organizations: orgs, documents, activeLinks, attempts24h, denied24h, highEvents24h };
  });

  app.get('/api/admin/users', async (request) => {
    requireAdmin(request);
    const { q } = z.object({ q: z.string().trim().max(100).default('') }).parse(request.query);
    const users = await prisma.user.findMany({
      where: q ? { OR: [{ email: { contains: q.toLowerCase() } }, { fullName: { contains: q, mode: 'insensitive' } }] } : {},
      orderBy: { createdAt: 'desc' },
      take: 100,
      include: { _count: { select: { documents: { where: { deletedAt: null } }, sharingLinks: true } } },
    });
    // Admins see account metadata only; there is no endpoint that decrypts another user's documents.
    return {
      users: users.map((u) => ({
        id: u.id,
        email: u.email,
        fullName: u.fullName,
        accountType: u.accountType,
        role: u.role,
        status: u.status,
        createdAt: u.createdAt,
        lockedUntil: u.lockedUntil,
        documents: u._count.documents,
        links: u._count.sharingLinks,
      })),
    };
  });

  app.patch('/api/admin/users/:id', async (request) => {
    const { user: admin } = requireAdmin(request);
    const id = parseId(request, 'User');
    const { status } = parse(updateStatusSchema, request.body);
    if (id === admin.id) throw new AppError(400, 'self_suspend', 'You cannot change your own status');
    const target = await prisma.user.findUnique({ where: { id } });
    if (!target) throw notFound('User');
    await prisma.$transaction([
      prisma.user.update({ where: { id }, data: { status } }),
      ...(status === 'suspended' ? [prisma.session.deleteMany({ where: { userId: id } })] : []),
    ]);
    await logEvent(prisma, {
      userId: id,
      actorUserId: admin.id,
      eventType: 'admin_user_status_changed',
      severity: 'warning',
      metadata: { status },
    });
    return { ok: true };
  });

  app.get('/api/admin/organizations', async (request) => {
    requireAdmin(request);
    const orgs = await prisma.organization.findMany({
      orderBy: { createdAt: 'desc' },
      take: 200,
      include: { _count: { select: { members: true, receivedLinks: true } } },
    });
    return {
      organizations: orgs.map((o) => ({
        id: o.id,
        name: o.name,
        type: o.type,
        status: o.status,
        createdAt: o.createdAt,
        members: o._count.members,
        receivedLinks: o._count.receivedLinks,
      })),
    };
  });

  app.patch('/api/admin/organizations/:id', async (request) => {
    const { user: admin } = requireAdmin(request);
    const id = parseId(request, 'Organization');
    const { status } = parse(updateStatusSchema, request.body);
    const org = await prisma.organization.findUnique({ where: { id } });
    if (!org) throw notFound('Organization');
    await prisma.organization.update({ where: { id }, data: { status } });
    await logEvent(prisma, {
      actorUserId: admin.id,
      userId: admin.id,
      eventType: 'admin_org_status_changed',
      severity: 'warning',
      metadata: { organization: org.name, status },
    });
    return { ok: true };
  });

  app.get('/api/admin/security-events', async (request) => {
    requireAdmin(request);
    const query = z
      .object({
        severity: z.enum(['info', 'warning', 'high']).optional(),
        type: z.string().max(60).optional(),
        page: z.coerce.number().int().min(1).max(1000).default(1),
      })
      .parse(request.query);
    const where: Prisma.SecurityEventWhereInput = {
      ...(query.severity ? { severity: query.severity } : {}),
      ...(query.type ? { eventType: query.type } : {}),
    };
    const pageSize = 40;
    const [rows, total] = await Promise.all([
      prisma.securityEvent.findMany({ where, orderBy: [{ createdAt: 'desc' }, { id: 'desc' }], skip: (query.page - 1) * pageSize, take: pageSize }),
      prisma.securityEvent.count({ where }),
    ]);
    const userIds = Array.from(new Set(rows.flatMap((r) => [r.userId, r.actorUserId]).filter((x): x is string => Boolean(x))));
    const users = await prisma.user.findMany({ where: { id: { in: userIds } }, select: { id: true, email: true } });
    const email = (id: string | null) => (id ? (users.find((u) => u.id === id)?.email ?? null) : null);
    return {
      page: query.page,
      pageSize,
      total,
      events: rows.map((r) => ({
        id: r.id.toString(),
        type: r.eventType,
        severity: r.severity,
        at: r.createdAt,
        user: email(r.userId),
        actor: email(r.actorUserId),
        metadata: r.metadata,
      })),
    };
  });

  app.get('/api/admin/issuers', async (request) => {
    requireAdmin(request);
    const issuers = await prisma.issuer.findMany({ include: { _count: { select: { credentials: true } } }, orderBy: { createdAt: 'asc' } });
    return {
      issuers: issuers.map((i) => ({
        id: i.id,
        name: i.name,
        identifier: i.identifier,
        kid: i.kid,
        status: i.status,
        simulated: i.isSimulated,
        credentials: i._count.credentials,
        createdAt: i.createdAt,
      })),
    };
  });

  app.patch('/api/admin/issuers/:id', async (request) => {
    const { user: admin } = requireAdmin(request);
    const id = parseId(request, 'Issuer');
    const { status } = parse(updateIssuerStatusSchema, request.body);
    const issuer = await prisma.issuer.findUnique({ where: { id } });
    if (!issuer) throw notFound('Issuer');
    await prisma.issuer.update({ where: { id }, data: { status } });
    await logEvent(prisma, {
      userId: admin.id,
      actorUserId: admin.id,
      eventType: 'admin_issuer_status_changed',
      severity: 'high',
      metadata: { issuer: issuer.name, status },
    });
    return { ok: true };
  });

  app.get('/api/admin/settings', async (request) => {
    requireAdmin(request);
    return { settings: await getSettings(prisma) };
  });

  app.put('/api/admin/settings', async (request) => {
    const { user: admin } = requireAdmin(request);
    const settings = parse(updateSettingsSchema, request.body);
    const before = await getSettings(prisma);
    await saveSettings(prisma, settings, admin.id);
    await logEvent(prisma, {
      userId: admin.id,
      actorUserId: admin.id,
      eventType: 'admin_settings_updated',
      severity: 'warning',
      metadata: { before, after: settings },
    });
    return { settings };
  });

  app.post('/api/admin/retention/run', async (request) => {
    const { user: admin } = requireAdmin(request);
    return { result: await runRetention(deps, admin.id) };
  });

  app.get('/api/admin/health', async (request) => {
    requireAdmin(request);
    const checks: Array<{ name: string; ok: boolean; detail: string }> = [];

    const dbStart = Date.now();
    try {
      await prisma.$queryRaw(Prisma.sql`SELECT 1`);
      checks.push({ name: 'Database', ok: true, detail: `Responded in ${Date.now() - dbStart} ms` });
    } catch {
      checks.push({ name: 'Database', ok: false, detail: 'Query failed' });
    }

    const storageStart = Date.now();
    try {
      await checkStorage(storage);
      checks.push({ name: 'Encrypted file storage', ok: true, detail: `${storage.driver} driver, write/read/delete in ${Date.now() - storageStart} ms` });
    } catch {
      checks.push({ name: 'Encrypted file storage', ok: false, detail: `${storage.driver} driver failed the write/read check` });
    }

    const forwarded = request.headers['x-forwarded-for'];
    const hops = typeof forwarded === 'string' ? forwarded.split(',').length : 0;
    const country = geo.lookup(request.ip);
    checks.push({
      name: 'Geolocation',
      ok: true,
      detail: `${geo.name} provider; your approximate country: ${country ?? 'unknown'}; proxy hops seen: ${hops}; trusted hops: ${String(config.trustProxy)}`,
    });
    checks.push({
      name: 'Email',
      ok: mailer.transport !== 'none',
      detail: mailer.transport === 'none' ? 'No email provider configured: password-reset emails are not sent' : `${mailer.transport} transport`,
    });

    return {
      checks,
      runtime: {
        uptimeSeconds: Math.round((Date.now() - startedAt.getTime()) / 1000),
        node: process.version,
        environment: config.env.NODE_ENV,
        memoryMb: Math.round(process.memoryUsage().rss / 1024 / 1024),
        masterKeyVersion: config.masterKeys.current.version,
      },
    };
  });
}

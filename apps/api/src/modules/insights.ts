import { Prisma } from '@prisma/client';
import type { FastifyInstance } from 'fastify';
import { ACCESS_OUTCOMES } from '@trustpass/shared';
import { z } from 'zod';
import { notFound } from '../lib/errors';
import { requireUser } from '../plugins/auth';
import { fillPlaceholders, ownerLabels } from '../services/metadata';
import { linkStatus } from './sharing';

const dateString = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
const rangeSchema = z.object({
  from: dateString.optional(),
  to: dateString.optional(),
  documentId: z.string().uuid().optional(),
});

const ALERT_TYPES = ['alert_new_country', 'alert_after_end', 'alert_denied_burst', 'account_locked'];

/** An "attempt" is a details view, or any denied request (a granted file fetch is part of a view). */
const attemptFilter: Prisma.AccessLogWhereInput = { OR: [{ resource: 'details' }, { outcome: { not: 'granted' } }] };

function resolveRange(input: { from?: string; to?: string }, now: Date) {
  const to = input.to ? new Date(`${input.to}T00:00:00.000Z`) : new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const end = new Date(to.getTime() + 24 * 60 * 60 * 1000);
  const from = input.from ? new Date(`${input.from}T00:00:00.000Z`) : new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
  return { from, end };
}

export async function insightRoutes(app: FastifyInstance) {
  const deps = app.deps;
  const { prisma, now, config } = deps;

  app.get('/api/analytics', async (request) => {
    const { user } = requireUser(request);
    const query = rangeSchema.parse(request.query);
    if (query.documentId) {
      const owned = await prisma.document.count({ where: { id: query.documentId, ownerId: user.id } });
      if (!owned) throw notFound('Document');
    }
    const { from, end } = resolveRange(query, now());
    const where: Prisma.AccessLogWhereInput = {
      ownerId: user.id,
      createdAt: { gte: from, lt: end },
      ...(query.documentId ? { documentId: query.documentId } : {}),
      ...attemptFilter,
    };

    const docFilter = query.documentId ? Prisma.sql`AND document_id = ${query.documentId}::uuid` : Prisma.empty;
    const [byOutcome, byCountry, daily, visitors, lastAccess, links, byDocument, alerts] = await Promise.all([
      prisma.accessLog.groupBy({ by: ['outcome'], where, _count: { _all: true } }),
      prisma.accessLog.groupBy({ by: ['countryCode', 'outcome'], where, _count: { _all: true } }),
      prisma.$queryRaw<Array<{ day: Date; outcome: string; count: number }>>`
        SELECT date_trunc('day', created_at AT TIME ZONE 'UTC') AS day, outcome::text AS outcome, count(*)::int AS count
        FROM access_logs
        WHERE owner_id = ${user.id}::uuid AND created_at >= ${from} AND created_at < ${end}
          AND (resource = 'details' OR outcome <> 'granted') ${docFilter}
        GROUP BY 1, 2 ORDER BY 1`,
      prisma.$queryRaw<Array<{ count: number }>>`
        SELECT count(DISTINCT ip_hmac)::int AS count FROM access_logs
        WHERE owner_id = ${user.id}::uuid AND created_at >= ${from} AND created_at < ${end} ${docFilter}`,
      prisma.accessLog.findFirst({
        where: { ownerId: user.id, outcome: 'granted', ...(query.documentId ? { documentId: query.documentId } : {}) },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        select: { createdAt: true, countryCode: true },
      }),
      prisma.sharingLink.findMany({
        where: { ownerId: user.id, ...(query.documentId ? { documentId: query.documentId } : {}) },
        select: { revokedAt: true, expiresAt: true },
      }),
      prisma.accessLog.groupBy({ by: ['documentId', 'outcome'], where, _count: { _all: true } }),
      prisma.notification.findMany({
        where: { userId: user.id, type: { in: ALERT_TYPES }, createdAt: { gte: from, lt: end } },
        orderBy: { createdAt: 'desc' },
        take: 10,
      }),
    ]);

    const count = (outcome: string) => byOutcome.find((o) => o.outcome === outcome)?._count._all ?? 0;
    const total = byOutcome.reduce((n, o) => n + o._count._all, 0);
    const current = now();
    const linkStatuses = links.map((l) => linkStatus(l, current));

    const countryMap = new Map<string, { country: string | null; granted: number; denied: number }>();
    for (const row of byCountry) {
      const key = row.countryCode ?? 'unknown';
      const entry = countryMap.get(key) ?? { country: row.countryCode, granted: 0, denied: 0 };
      if (row.outcome === 'granted') entry.granted += row._count._all;
      else entry.denied += row._count._all;
      countryMap.set(key, entry);
    }

    const docIds = Array.from(new Set(byDocument.map((d) => d.documentId)));
    const labels = await ownerLabels(deps, user.id, [...docIds, ...alerts.map((a) => a.documentId)], alerts.map((a) => a.linkId));
    const perDoc = new Map<string, { documentId: string; title: string; granted: number; denied: number }>();
    for (const row of byDocument) {
      const entry = perDoc.get(row.documentId) ?? {
        documentId: row.documentId,
        title: labels.title(row.documentId) ?? 'Document',
        granted: 0,
        denied: 0,
      };
      if (row.outcome === 'granted') entry.granted += row._count._all;
      else entry.denied += row._count._all;
      perDoc.set(row.documentId, entry);
    }

    const dayMap = new Map<string, Record<string, number>>();
    for (let t = from.getTime(); t < end.getTime(); t += 24 * 60 * 60 * 1000) {
      dayMap.set(new Date(t).toISOString().slice(0, 10), {});
    }
    for (const row of daily) {
      const key = new Date(row.day).toISOString().slice(0, 10);
      const entry = dayMap.get(key) ?? {};
      entry[row.outcome] = row.count;
      dayMap.set(key, entry);
    }

    return {
      range: { from: from.toISOString().slice(0, 10), to: new Date(end.getTime() - 1).toISOString().slice(0, 10) },
      summary: {
        totalAttempts: total,
        granted: count('granted'),
        denied: total - count('granted'),
        expiredAttempts: count('denied_expired'),
        revokedAttempts: count('denied_revoked'),
        countryBlocked: count('denied_country'),
        recipientBlocked: count('denied_recipient'),
        countriesDetected: Array.from(countryMap.values()).filter((c) => c.country).length,
        distinctVisitors: visitors[0]?.count ?? 0,
        lastAccess: lastAccess ? { at: lastAccess.createdAt, country: lastAccess.countryCode } : null,
        activeLinks: linkStatuses.filter((s) => s === 'active').length,
        expiredLinks: linkStatuses.filter((s) => s === 'expired').length,
        revokedLinks: linkStatuses.filter((s) => s === 'revoked').length,
      },
      byOutcome: ACCESS_OUTCOMES.map((o) => ({ outcome: o, count: count(o) })),
      byCountry: Array.from(countryMap.values()).sort((a, b) => b.granted + b.denied - (a.granted + a.denied)),
      byDocument: Array.from(perDoc.values()).sort((a, b) => b.granted + b.denied - (a.granted + a.denied)),
      daily: Array.from(dayMap.entries()).map(([day, values]) => ({
        day,
        granted: values.granted ?? 0,
        denied: Object.entries(values)
          .filter(([k]) => k !== 'granted')
          .reduce((n, [, v]) => n + v, 0),
      })),
      alerts: alerts.map((a) => ({
        id: a.id,
        type: a.type,
        title: a.title,
        body: fillPlaceholders(a.body, { document: labels.title(a.documentId) ?? labels.linkTitle(a.linkId), recipient: labels.recipient(a.linkId) }),
        at: a.createdAt,
        linkId: a.linkId,
      })),
    };
  });

  app.get('/api/analytics/access-log', async (request) => {
    const { user } = requireUser(request);
    const query = rangeSchema
      .extend({
        outcome: z.enum(ACCESS_OUTCOMES).optional(),
        page: z.coerce.number().int().min(1).max(1000).default(1),
      })
      .parse(request.query);
    const { from, end } = resolveRange(query, now());
    const where: Prisma.AccessLogWhereInput = {
      ownerId: user.id,
      createdAt: { gte: from, lt: end },
      ...(query.documentId ? { documentId: query.documentId } : {}),
      ...(query.outcome ? { outcome: query.outcome } : {}),
    };
    const pageSize = 25;
    const [rows, total] = await Promise.all([
      prisma.accessLog.findMany({ where, orderBy: [{ createdAt: 'desc' }, { id: 'desc' }], skip: (query.page - 1) * pageSize, take: pageSize }),
      prisma.accessLog.count({ where }),
    ]);
    const labels = await ownerLabels(deps, user.id, [], rows.map((r) => r.linkId));
    const orgIds = Array.from(new Set(rows.map((r) => r.accessorOrgId).filter((x): x is string => Boolean(x))));
    const orgs = await prisma.organization.findMany({ where: { id: { in: orgIds } }, select: { id: true, name: true } });
    return {
      page: query.page,
      pageSize,
      total,
      rows: rows.map((r) => {
        return {
          id: r.id.toString(),
          at: r.createdAt,
          document: labels.linkTitle(r.linkId) ?? 'Document',
          recipient: labels.recipient(r.linkId),
          resource: r.resource,
          outcome: r.outcome,
          country: r.countryCode,
          client: r.userAgentFamily,
          organization: orgs.find((o) => o.id === r.accessorOrgId)?.name ?? null,
          linkId: r.linkId,
        };
      }),
    };
  });

  app.get('/api/activity', async (request) => {
    const { user } = requireUser(request);
    const query = z
      .object({ page: z.coerce.number().int().min(1).max(1000).default(1), type: z.string().max(60).optional() })
      .parse(request.query);
    const pageSize = 30;
    // Users only ever see events filed under their own account.
    const where: Prisma.SecurityEventWhereInput = { userId: user.id, ...(query.type ? { eventType: query.type } : {}) };
    const [rows, total] = await Promise.all([
      prisma.securityEvent.findMany({ where, orderBy: [{ createdAt: 'desc' }, { id: 'desc' }], skip: (query.page - 1) * pageSize, take: pageSize }),
      prisma.securityEvent.count({ where }),
    ]);
    // Logs store ids only (E4): titles and recipients are decrypted here, for the owner.
    const labels = await ownerLabels(deps, user.id, rows.map((r) => r.documentId), rows.map((r) => r.linkId));
    return {
      page: query.page,
      pageSize,
      total,
      events: rows.map((r) => {
        const recipient = labels.recipient(r.linkId);
        const metadata = r.metadata && typeof r.metadata === 'object' && !Array.isArray(r.metadata) ? r.metadata : {};
        return {
          id: r.id.toString(),
          type: r.eventType,
          severity: r.severity,
          at: r.createdAt,
          document: labels.title(r.documentId),
          byYou: r.actorUserId === user.id,
          metadata: recipient ? { ...metadata, recipient } : metadata,
        };
      }),
    };
  });

  app.get('/api/notifications', async (request) => {
    const { user } = requireUser(request);
    const [items, unread] = await Promise.all([
      prisma.notification.findMany({ where: { userId: user.id }, orderBy: { createdAt: 'desc' }, take: 50 }),
      prisma.notification.count({ where: { userId: user.id, readAt: null } }),
    ]);
    const labels = await ownerLabels(deps, user.id, items.map((n) => n.documentId), items.map((n) => n.linkId));
    return {
      unread,
      notifications: items.map((n) => ({
        id: n.id,
        type: n.type,
        title: n.title,
        body: fillPlaceholders(n.body, { document: labels.title(n.documentId) ?? labels.linkTitle(n.linkId), recipient: labels.recipient(n.linkId) }),
        read: Boolean(n.readAt),
        at: n.createdAt,
        linkId: n.linkId,
        documentId: n.documentId,
      })),
    };
  });

  app.post('/api/notifications/read-all', async (request) => {
    const { user } = requireUser(request);
    await prisma.notification.updateMany({ where: { userId: user.id, readAt: null }, data: { readAt: now() } });
    return { ok: true };
  });

  app.post('/api/notifications/:id/read', async (request) => {
    const { user } = requireUser(request);
    const { id } = z.object({ id: z.string().uuid() }).parse(request.params);
    const result = await prisma.notification.updateMany({ where: { id, userId: user.id }, data: { readAt: now() } });
    if (result.count === 0) throw notFound('Notification');
    return { ok: true };
  });

  app.get('/api/dashboard', async (request) => {
    const { user } = requireUser(request);
    const current = now();
    const weekAgo = new Date(current.getTime() - 7 * 24 * 60 * 60 * 1000);
    const [documents, credentials, activeLinks, attempts, recentAccess, recentEvents] = await Promise.all([
      prisma.document.count({ where: { ownerId: user.id, deletedAt: null } }),
      prisma.credential.count({ where: { document: { ownerId: user.id, deletedAt: null }, expiresAt: { gt: current }, issuer: { status: 'trusted' } } }),
      prisma.sharingLink.count({ where: { ownerId: user.id, revokedAt: null, expiresAt: { gt: current } } }),
      prisma.accessLog.groupBy({ by: ['outcome'], where: { ownerId: user.id, createdAt: { gte: weekAgo }, ...attemptFilter }, _count: { _all: true } }),
      prisma.accessLog.findMany({ where: { ownerId: user.id, resource: 'details' }, orderBy: [{ createdAt: 'desc' }, { id: 'desc' }], take: 5 }),
      prisma.securityEvent.findMany({ where: { userId: user.id }, orderBy: [{ createdAt: 'desc' }, { id: 'desc' }], take: 6 }),
    ]);
    // Daily granted/blocked attempts for the last 14 days (UTC days), for the dashboard chart.
    const DAYS = 14;
    const since = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), current.getUTCDate() - (DAYS - 1)));
    const recent = await prisma.accessLog.findMany({ where: { ownerId: user.id, createdAt: { gte: since }, ...attemptFilter }, select: { createdAt: true, outcome: true } });
    const daily = Array.from({ length: DAYS }, (_, i) => ({ date: new Date(since.getTime() + i * 86_400_000).toISOString().slice(0, 10), granted: 0, denied: 0 }));
    for (const r of recent) {
      const day = daily[Math.floor((r.createdAt.getTime() - since.getTime()) / 86_400_000)];
      if (day) day[r.outcome === 'granted' ? 'granted' : 'denied']++;
    }
    const labels = await ownerLabels(deps, user.id, [], recentAccess.map((r) => r.linkId));
    const granted = attempts.find((a) => a.outcome === 'granted')?._count._all ?? 0;
    const total = attempts.reduce((n, a) => n + a._count._all, 0);
    return {
      counts: { documents, verifiedCredentials: credentials, activeLinks, attempts7d: total, granted7d: granted, denied7d: total - granted },
      daily,
      // Which service protects the document keys (provider name only, never key material).
      protection: { keyProvider: config.env.KEY_PROVIDER, kms: config.env.KEY_PROVIDER === 'gcp-kms' },
      recentAccess: recentAccess.map((r) => {
        return { id: r.id.toString(), at: r.createdAt, outcome: r.outcome, country: r.countryCode, document: labels.linkTitle(r.linkId) ?? 'Document', recipient: labels.recipient(r.linkId) };
      }),
      recentEvents: recentEvents.map((e) => ({ id: e.id.toString(), type: e.eventType, severity: e.severity, at: e.createdAt })),
    };
  });
}

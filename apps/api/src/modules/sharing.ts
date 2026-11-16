import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { createLinkSchema, EXPIRY_PRESETS, updateCountriesSchema } from '@trustpass/shared';
import { z } from 'zod';
import { hashToken, linkTokenAad, open, randomToken, seal } from '../lib/crypto';
import { AppError, badRequest, notFound, parse } from '../lib/errors';
import { requireUser } from '../plugins/auth';
import { logEvent, notify } from '../services/audit';
import { getSettings } from '../services/settings';
import type { AppDeps } from '../types';
import { getOwnedDocument, parseId } from './documents';

export function linkStatus(link: { revokedAt: Date | null; expiresAt: Date }, now: Date) {
  if (link.revokedAt) return 'revoked' as const;
  if (link.expiresAt <= now) return 'expired' as const;
  return 'active' as const;
}

function shareUrl(deps: AppDeps, token: string) {
  return `${deps.config.env.APP_URL}/s/${token}`;
}

function decryptToken(deps: AppDeps, linkId: string, encrypted: Uint8Array): string {
  // Try every configured master key so links survive a key rotation.
  for (const key of deps.config.masterKeys.all.values()) {
    try {
      return open(key, encrypted, linkTokenAad(linkId)).toString('utf8');
    } catch {
      /* try the next key */
    }
  }
  throw new AppError(500, 'token_unavailable', 'The link could not be recovered');
}

async function getOwnedLink(deps: AppDeps, id: string, ownerId: string) {
  const link = await deps.prisma.sharingLink.findFirst({
    where: { id, ownerId },
    include: {
      document: { select: { id: true, title: true, kind: true, deletedAt: true } },
      countries: true,
      recipientOrg: { select: { id: true, name: true } },
      permissions: { include: { claim: { select: { id: true, label: true, source: true } } } },
    },
  });
  if (!link) throw notFound('Link');
  return link;
}

export async function sharingRoutes(app: FastifyInstance) {
  const deps = app.deps;
  const { prisma, config, now } = deps;

  app.post(
    '/api/documents/:id/links',
    { config: { rateLimit: { max: 60, timeWindow: '10 minutes' } } },
    async (request, reply) => {
      const { user } = requireUser(request);
      const document = await getOwnedDocument(deps, parseId(request, 'Document'), user.id);
      const input = parse(createLinkSchema, request.body);
      const settings = await getSettings(prisma);
      const current = now();

      const claimIds = Array.from(new Set(input.claimIds));
      const docClaimIds = new Set(document.claims.map((c) => c.id));
      if (claimIds.some((id) => !docClaimIds.has(id))) throw badRequest('One of the selected fields does not belong to this document');

      let recipientOrgId: string | null = null;
      if (input.recipientType === 'organization') {
        const org = await prisma.organization.findFirst({ where: { id: input.recipientOrgId, status: 'active' } });
        if (!org) throw badRequest('That organization was not found');
        recipientOrgId = org.id;
      }

      const maxMs = settings.maxLinkDays * 24 * 60 * 60 * 1000;
      let expiresAt: Date;
      if (input.expiresIn === 'custom') {
        expiresAt = new Date(input.expiresAt!);
        if (expiresAt.getTime() < current.getTime() + 5 * 60_000) throw badRequest('Pick an expiry at least 5 minutes from now');
      } else {
        expiresAt = new Date(current.getTime() + EXPIRY_PRESETS[input.expiresIn] * 1000);
      }
      if (expiresAt.getTime() - current.getTime() > maxMs) {
        throw badRequest(`Links can last at most ${settings.maxLinkDays} days`);
      }

      const token = randomToken(32);
      const linkId = randomUUID();
      const link = await prisma.$transaction(async (tx) => {
        const created = await tx.sharingLink.create({
          data: {
            id: linkId,
            documentId: document.id,
            ownerId: user.id,
            tokenHash: hashToken(token),
            // Encrypted copy so the owner can copy the link again; lookups use the hash.
            tokenEncrypted: seal(config.masterKeys.current.key, token, linkTokenAad(linkId)),
            recipientType: input.recipientType,
            recipientOrgId,
            recipientLabel: input.recipientLabel,
            includeFile: input.includeFile,
            expiresAt,
            createdAt: current,
          },
        });
        if (claimIds.length) await tx.sharingPermission.createMany({ data: claimIds.map((claimId) => ({ linkId: created.id, claimId })) });
        if (input.allowedCountries.length) {
          await tx.allowedCountry.createMany({ data: input.allowedCountries.map((countryCode) => ({ linkId: created.id, countryCode })) });
        }
        await logEvent(tx, {
          userId: user.id,
          actorUserId: user.id,
          eventType: 'link_created',
          documentId: document.id,
          linkId: created.id,
          metadata: {
            recipient: input.recipientLabel,
            recipientType: input.recipientType,
            fields: claimIds.length,
            includeFile: input.includeFile,
            expiresAt: expiresAt.toISOString(),
            countries: input.allowedCountries,
          },
        });
        return created;
      });

      if (recipientOrgId) {
        const members = await prisma.organizationMember.findMany({ where: { orgId: recipientOrgId }, select: { userId: true } });
        for (const m of members) {
          if (m.userId === user.id) continue;
          await notify(prisma, {
            userId: m.userId,
            type: 'link_received',
            title: 'A document was shared with your organization',
            body: `${user.fullName} shared "${document.title}" with your organization. Open it from the organization dashboard.`,
            linkId: link.id,
          });
        }
      }

      return reply.status(201).send({
        link: { id: link.id, expiresAt: link.expiresAt, recipientLabel: link.recipientLabel },
        url: shareUrl(deps, token),
      });
    },
  );

  app.get('/api/links', async (request) => {
    const { user } = requireUser(request);
    const query = z.object({ status: z.enum(['all', 'active', 'expired', 'revoked']).default('all') }).parse(request.query);
    const current = now();
    const where = {
      ownerId: user.id,
      ...(query.status === 'active' ? { revokedAt: null, expiresAt: { gt: current } } : {}),
      ...(query.status === 'expired' ? { revokedAt: null, expiresAt: { lte: current } } : {}),
      ...(query.status === 'revoked' ? { revokedAt: { not: null } } : {}),
    };
    const links = await prisma.sharingLink.findMany({
      where,
      include: {
        document: { select: { id: true, title: true, kind: true } },
        countries: true,
        recipientOrg: { select: { name: true } },
        _count: { select: { permissions: true } },
      },
      orderBy: { createdAt: 'desc' },
      take: 200,
    });
    const stats = await prisma.accessLog.groupBy({
      by: ['linkId', 'outcome'],
      where: { ownerId: user.id, linkId: { in: links.map((l) => l.id) }, OR: [{ resource: 'details' }, { outcome: { not: 'granted' } }] },
      _count: { _all: true },
    });
    return {
      links: links.map((l) => {
        const rows = stats.filter((s) => s.linkId === l.id);
        const granted = rows.filter((r) => r.outcome === 'granted').reduce((n, r) => n + r._count._all, 0);
        const denied = rows.filter((r) => r.outcome !== 'granted').reduce((n, r) => n + r._count._all, 0);
        return {
          id: l.id,
          document: l.document,
          recipientLabel: l.recipientLabel,
          recipientType: l.recipientType,
          recipientOrg: l.recipientOrg?.name ?? null,
          includeFile: l.includeFile,
          claimCount: l._count.permissions,
          countries: l.countries.map((c) => c.countryCode),
          expiresAt: l.expiresAt,
          revokedAt: l.revokedAt,
          createdAt: l.createdAt,
          lastAccessedAt: l.lastAccessedAt,
          status: linkStatus(l, current),
          attempts: { granted, denied, total: granted + denied },
        };
      }),
    };
  });

  app.get('/api/links/:id', async (request) => {
    const { user } = requireUser(request);
    const link = await getOwnedLink(deps, parseId(request, 'Link'), user.id);
    const recent = await prisma.accessLog.findMany({
      where: { linkId: link.id, ownerId: user.id },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 25,
    });
    return {
      link: {
        id: link.id,
        document: link.document,
        recipientLabel: link.recipientLabel,
        recipientType: link.recipientType,
        recipientOrg: link.recipientOrg?.name ?? null,
        includeFile: link.includeFile,
        fields: link.permissions.map((p) => ({ id: p.claim.id, label: p.claim.label, source: p.claim.source })),
        countries: link.countries.map((c) => c.countryCode),
        expiresAt: link.expiresAt,
        revokedAt: link.revokedAt,
        createdAt: link.createdAt,
        lastAccessedAt: link.lastAccessedAt,
        viewCount: link.viewCount,
        status: linkStatus(link, now()),
        recentAccess: recent.map((r) => ({
          id: r.id.toString(),
          outcome: r.outcome,
          resource: r.resource,
          country: r.countryCode,
          client: r.userAgentFamily,
          at: r.createdAt,
        })),
      },
    };
  });

  app.get('/api/links/:id/url', async (request) => {
    const { user } = requireUser(request);
    const link = await getOwnedLink(deps, parseId(request, 'Link'), user.id);
    return { url: shareUrl(deps, decryptToken(deps, link.id, link.tokenEncrypted)) };
  });

  app.put('/api/links/:id/countries', async (request) => {
    const { user } = requireUser(request);
    const link = await getOwnedLink(deps, parseId(request, 'Link'), user.id);
    if (linkStatus(link, now()) !== 'active') throw new AppError(409, 'link_inactive', 'Only active links can be changed');
    const input = parse(updateCountriesSchema, request.body);
    await prisma.$transaction(async (tx) => {
      await tx.allowedCountry.deleteMany({ where: { linkId: link.id } });
      if (input.allowedCountries.length) {
        await tx.allowedCountry.createMany({ data: input.allowedCountries.map((countryCode) => ({ linkId: link.id, countryCode })) });
      }
      await logEvent(tx, {
        userId: user.id,
        actorUserId: user.id,
        eventType: 'link_countries_updated',
        documentId: link.documentId,
        linkId: link.id,
        metadata: { before: link.countries.map((c) => c.countryCode), after: input.allowedCountries },
      });
    });
    return { ok: true, countries: input.allowedCountries };
  });

  app.post('/api/links/:id/revoke', async (request) => {
    const { user } = requireUser(request);
    const link = await getOwnedLink(deps, parseId(request, 'Link'), user.id);
    if (link.revokedAt) return { ok: true, revokedAt: link.revokedAt };
    const revokedAt = now();
    await prisma.sharingLink.update({ where: { id: link.id }, data: { revokedAt } });
    await logEvent(prisma, {
      userId: user.id,
      actorUserId: user.id,
      eventType: 'link_revoked',
      documentId: link.documentId,
      linkId: link.id,
      metadata: { recipient: link.recipientLabel },
    });
    return { ok: true, revokedAt };
  });
}

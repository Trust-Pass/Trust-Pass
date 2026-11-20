import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { createLinkSchema, EXPIRY_PRESETS, REDACTION_MAX_TOTAL_BYTES, updateCountriesSchema, updateDownloadSchema } from '@trustpass/shared';
import { z } from 'zod';
import { hashToken, linkTokenAad, open, randomToken, seal } from '../lib/crypto';
import { AppError, badRequest, notFound, parse } from '../lib/errors';
import { requireUser } from '../plugins/auth';
import { logEvent, notify } from '../services/audit';
import { loadDataKey } from '../services/documents';
import { dataKeys, openClaimLabel, openRecipientLabel, openTitle, sealRecipientLabel, TITLE_SELECT } from '../services/metadata';
import { getSettings } from '../services/settings';
import { buildRedactedPages, storeRedactedPages } from '../services/redaction';
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

export function decryptToken(deps: Pick<AppDeps, 'config'>, linkId: string, encrypted: Uint8Array): string {
  // Link-token keys first; links created before E2 were sealed with the key-encryption key.
  for (const key of [...deps.config.linkTokenKeys.all.values(), ...deps.config.masterKeys.all.values()]) {
    try {
      return open(key, encrypted, linkTokenAad(linkId)).toString('utf8');
    } catch {
      /* try the next key */
    }
  }
  throw new AppError(500, 'token_unavailable', 'The link could not be recovered');
}

/** Like decryptToken, but loads keys added by a rotation since start-up before giving up. */
async function recoverToken(deps: AppDeps, linkId: string, encrypted: Uint8Array): Promise<string> {
  try {
    return decryptToken(deps, linkId, encrypted);
  } catch (err) {
    if (!deps.keys?.enabled) throw err;
    await deps.keys.reload();
    return decryptToken(deps, linkId, encrypted);
  }
}

async function getOwnedLink(deps: AppDeps, id: string, ownerId: string) {
  const link = await deps.prisma.sharingLink.findFirst({
    where: { id, ownerId },
    include: {
      document: { select: { ...TITLE_SELECT, kind: true } },
      countries: true,
      recipientOrg: { select: { id: true, name: true } },
      permissions: { include: { claim: { select: { id: true, claimKey: true, label: true, labelEncrypted: true, source: true } } } },
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
      // JSON, or multipart when the owner's browser sends the rendered pages of a PDF for a
      // redacted copy: one "link" field (the same JSON) and one "page" file per page, in order.
      let body: unknown = request.body;
      const pageImages: Buffer[] = [];
      let pageBytes = 0;
      if (request.isMultipart()) {
        for await (const part of request.parts({ limits: { fileSize: 12 * 1024 * 1024, files: 50, fields: 1, fieldSize: 65_536 } })) {
          if (part.type === 'file') {
            if (part.fieldname !== 'page') throw badRequest('Unexpected file');
            const page = await part.toBuffer();
            pageBytes += page.length;
            // One request may not hold more than REDACTION_MAX_TOTAL_BYTES of page images, so a
            // single owner cannot exhaust the server's memory with 50 large files.
            if (pageBytes > REDACTION_MAX_TOTAL_BYTES) {
              for (const b of pageImages) b.fill(0);
              throw new AppError(413, 'payload_too_large', 'The page images are too large in total. Try a document with fewer pages.');
            }
            pageImages.push(page);
          } else if (part.fieldname === 'link') {
            try {
              body = JSON.parse(String(part.value));
            } catch {
              throw badRequest('The link settings are not valid JSON');
            }
          }
        }
      }
      const input = parse(createLinkSchema, body);
      if (input.fileMode === 'original' && pageImages.length > 0) throw badRequest('Page images are only used for a redacted copy');
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

      await deps.keys?.refreshIfStale();
      const token = randomToken(32);
      const linkId = randomUUID();
      // The recipient label is sealed with the document's key (E3), like the title.
      const dek = await loadDataKey(deps, document.id);
      let recipientLabelEncrypted: Uint8Array<ArrayBuffer>;
      let redacted: Awaited<ReturnType<typeof storeRedactedPages>> | null = null;
      try {
        recipientLabelEncrypted = sealRecipientLabel(dek, document.id, linkId, input.recipientLabel);
        if (input.includeFile && input.fileMode === 'redacted') {
          // The boxes are burned into fresh page images here; only those images are ever shared.
          const pages = await buildRedactedPages(deps, document, dek, input.redactions, pageImages);
          redacted = await storeRedactedPages(deps, document.id, linkId, dek, pages);
          for (const p of pages) p.data.fill(0);
        }
      } finally {
        dek.fill(0);
        for (const b of pageImages) b.fill(0);
      }
      const link = await prisma.$transaction(async (tx) => {
        const created = await tx.sharingLink.create({
          data: {
            id: linkId,
            documentId: document.id,
            ownerId: user.id,
            tokenHash: hashToken(token),
            // Encrypted copy so the owner can copy the link again; lookups use the hash.
            tokenEncrypted: seal(config.linkTokenKeys.current.key, token, linkTokenAad(linkId)),
            recipientType: input.recipientType,
            recipientOrgId,
            recipientLabelEncrypted,
            includeFile: input.includeFile,
            allowDownload: input.includeFile && input.allowDownload,
            fileMode: input.includeFile ? input.fileMode : null,
            expiresAt,
            createdAt: current,
          },
        });
        if (redacted) await tx.redactedPage.createMany({ data: redacted.rows });
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
          // No recipient name here: logs keep ids only (E4).
          metadata: {
            recipientType: input.recipientType,
            fields: claimIds.length,
            includeFile: input.includeFile,
            fileMode: input.includeFile ? input.fileMode : null,
            hiddenAreas: input.includeFile && input.fileMode === 'redacted' ? input.redactions.length : 0,
            allowDownload: input.includeFile && input.allowDownload,
            expiresAt: expiresAt.toISOString(),
            countries: input.allowedCountries,
          },
        });
        return created;
      }).catch(async (err) => {
        // Nothing half-made: the stored page ciphertexts go if the link could not be saved.
        if (redacted) await Promise.all(redacted.written.map((k) => deps.storage.delete(k).catch(() => undefined)));
        throw err;
      });

      if (recipientOrgId) {
        const members = await prisma.organizationMember.findMany({ where: { orgId: recipientOrgId }, select: { userId: true } });
        for (const m of members) {
          if (m.userId === user.id) continue;
          await notify(prisma, {
            userId: m.userId,
            type: 'link_received',
            title: 'A document was shared with your organization',
            // The title stays out of stored notifications (E4); the inbox shows it after its access checks.
            body: `${user.fullName} shared a document with your organization. Open it from the organization dashboard.`,
            linkId: link.id,
          });
        }
      }

      return reply.status(201).send({
        link: { id: link.id, expiresAt: link.expiresAt, recipientLabel: input.recipientLabel, allowDownload: link.allowDownload, fileMode: link.includeFile ? (link.fileMode ?? 'original') : null },
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
        document: { select: { ...TITLE_SELECT, kind: true } },
        countries: true,
        recipientOrg: { select: { name: true } },
        _count: { select: { permissions: true } },
      },
      orderBy: { createdAt: 'desc' },
      take: 200,
    });
    const keys = await dataKeys(deps, links.map((l) => l.documentId));
    const labels = new Map(
      links.map((l) => [l.id, { title: openTitle(keys.get(l.documentId), l.document), recipient: openRecipientLabel(keys.get(l.documentId), l) }]),
    );
    keys.zero();
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
          document: { id: l.document.id, title: labels.get(l.id)!.title, kind: l.document.kind },
          recipientLabel: labels.get(l.id)!.recipient,
          recipientType: l.recipientType,
          recipientOrg: l.recipientOrg?.name ?? null,
          includeFile: l.includeFile,
          allowDownload: l.includeFile && l.allowDownload,
          fileMode: l.includeFile ? (l.fileMode ?? 'original') : null,
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
    const keys = await dataKeys(deps, [link.documentId]);
    const dek = keys.get(link.documentId);
    const title = openTitle(dek, link.document);
    const recipientLabel = openRecipientLabel(dek, link);
    const fields = link.permissions.map((p) => ({ id: p.claim.id, label: openClaimLabel(dek, link.documentId, p.claim), source: p.claim.source }));
    keys.zero();
    return {
      link: {
        id: link.id,
        document: { id: link.document.id, title, kind: link.document.kind, deletedAt: link.document.deletedAt },
        recipientLabel,
        recipientType: link.recipientType,
        recipientOrg: link.recipientOrg?.name ?? null,
        includeFile: link.includeFile,
        allowDownload: link.includeFile && link.allowDownload,
        fileMode: link.includeFile ? (link.fileMode ?? 'original') : null,
        fields,
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
    return { url: shareUrl(deps, await recoverToken(deps, link.id, link.tokenEncrypted)) };
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

  app.put('/api/links/:id/download', async (request) => {
    const { user } = requireUser(request);
    const link = await getOwnedLink(deps, parseId(request, 'Link'), user.id);
    if (linkStatus(link, now()) !== 'active') throw new AppError(409, 'link_inactive', 'Only active links can be changed');
    const input = parse(updateDownloadSchema, request.body);
    if (input.allowDownload && !link.includeFile) throw badRequest('Downloads need the file to be shared on this link');
    if (input.allowDownload === link.allowDownload) return { ok: true, allowDownload: link.allowDownload };
    await prisma.$transaction(async (tx) => {
      await tx.sharingLink.update({ where: { id: link.id }, data: { allowDownload: input.allowDownload } });
      await logEvent(tx, {
        userId: user.id,
        actorUserId: user.id,
        eventType: 'link_download_updated',
        documentId: link.documentId,
        linkId: link.id,
        metadata: { before: link.allowDownload, after: input.allowDownload },
      });
    });
    return { ok: true, allowDownload: input.allowDownload };
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
    });
    return { ok: true, revokedAt };
  });
}

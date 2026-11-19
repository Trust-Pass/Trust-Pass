import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { AccessOutcome, AccessResource, AllowedCountry, Document, DocumentClaim, SharingLink, SharingPermission } from '@prisma/client';
import { countryName } from '@trustpass/shared';
import { z } from 'zod';
import { hashToken, hmacHex } from '../lib/crypto';
import { AppError, notFound } from '../lib/errors';
import { watermarkDocument } from '../lib/pdf';
import { userAgentFamily } from '../lib/user-agent';
import { requireUser } from '../plugins/auth';
import { logEvent, notify, recentlyNotified } from '../services/audit';
import { decryptClaims, loadDataKey, readDocumentFile } from '../services/documents';
import { documentTitles, openRecipientLabel, openTitle, TITLE_SELECT } from '../services/metadata';
import { loadStoredCredential, presentAndVerify, recordVerification } from '../services/verification';
import { memberOrgIds } from '../services/users';
import type { AppDeps } from '../types';
import { fileResponseHeaders } from './documents';
import { linkStatus } from './sharing';

type GateLink = SharingLink & {
  document: Document & { claims: DocumentClaim[] };
  countries: AllowedCountry[];
  permissions: SharingPermission[];
  owner: { fullName: string };
  recipientOrg: { id: string; name: string; status: string } | null;
};

const linkInclude = {
  document: { include: { claims: true } },
  countries: true,
  permissions: true,
  owner: { select: { fullName: true } },
  recipientOrg: { select: { id: true, name: true, status: true } },
} as const;

interface GateDecision {
  outcome: AccessOutcome;
  country: string | null;
  accessorOrgId: string | null;
}

const BURST_WINDOW_MS = 10 * 60_000;
const BURST_THRESHOLD = 3;

/**
 * The single place where share-link access is decided. Checks run in order
 * and the first failure wins: revoked -> expired -> recipient -> country.
 * Every attempt, allowed or denied, is written to access_logs.
 */
export async function evaluateAccess(
  deps: AppDeps,
  request: FastifyRequest,
  link: GateLink,
  resource: AccessResource,
): Promise<GateDecision> {
  const { prisma, geo, config, now } = deps;
  const current = now();
  const country = geo.lookup(request.clientIp);
  const auth = request.auth;

  let accessorOrgId: string | null = null;
  let outcome: AccessOutcome = 'granted';

  if (link.revokedAt || link.document.deletedAt) {
    outcome = 'denied_revoked';
  } else if (link.expiresAt <= current) {
    outcome = 'denied_expired';
  } else if (link.recipientType === 'organization') {
    const orgIds = auth ? await memberOrgIds(prisma, auth.user.id) : [];
    if (!link.recipientOrgId || link.recipientOrg?.status !== 'active' || !orgIds.includes(link.recipientOrgId)) {
      outcome = 'denied_recipient';
    } else {
      accessorOrgId = link.recipientOrgId;
    }
  }
  if (outcome === 'granted' && link.countries.length > 0) {
    const allowed = link.countries.map((c) => c.countryCode);
    // Unknown location is denied when a country rule exists (fail closed).
    if (!country || !allowed.includes(country)) outcome = 'denied_country';
  }

  const logRow = await prisma.accessLog.create({
    data: {
      linkId: link.id,
      documentId: link.documentId,
      ownerId: link.ownerId,
      resource,
      outcome,
      countryCode: country,
      // Keyed hash: counts distinct visitors without storing the IP address.
      ipHmac: hmacHex(config.ipHashKey, request.clientIp),
      userAgentFamily: userAgentFamily(request.headers['user-agent']),
      accessorUserId: auth?.user.id ?? null,
      accessorOrgId,
      createdAt: current,
    },
  });

  if (outcome === 'granted' && resource === 'details') {
    await prisma.sharingLink.update({
      where: { id: link.id },
      data: { viewCount: { increment: 1 }, lastAccessedAt: current },
    });
  }

  await raiseAlerts(deps, link, outcome, country, current, logRow.id).catch((err) => request.log.warn({ err }, 'alert evaluation failed'));
  return { outcome, country, accessorOrgId };
}

/** Alerts say "worth a look"; they never call an attempt an attack. */
async function raiseAlerts(
  deps: AppDeps,
  link: GateLink,
  outcome: AccessOutcome,
  country: string | null,
  current: Date,
  logId: bigint,
) {
  const { prisma } = deps;
  // Stored notifications never contain the title or recipient (E4). {document} and {recipient}
  // are filled in for the owner when the notification is read (services/metadata.ts).

  if (outcome === 'granted') {
    if (!country) return;
    const seenBefore = await prisma.accessLog.count({
      where: { linkId: link.id, outcome: 'granted', countryCode: country, id: { not: logId } },
    });
    if (seenBefore === 0) {
      await notify(prisma, {
        userId: link.ownerId,
        type: 'alert_new_country',
        title: `First view from ${countryName(country)}`,
        body: `Your link for "{document}" ({recipient}) was opened from ${countryName(country)} for the first time. Location is approximate.`,
        linkId: link.id,
        documentId: link.documentId,
        at: current,
      });
    }
    return;
  }

  if (outcome === 'denied_revoked' || outcome === 'denied_expired') {
    const since = new Date(current.getTime() - 60 * 60_000);
    if (!(await recentlyNotified(prisma, link.ownerId, 'alert_after_end', link.id, since))) {
      await notify(prisma, {
        userId: link.ownerId,
        type: 'alert_after_end',
        title: `Someone tried a ${outcome === 'denied_revoked' ? 'revoked' : 'expired'} link`,
        body: `An attempt was made to open your link for "{document}" ({recipient}) after it ${outcome === 'denied_revoked' ? 'was revoked' : 'expired'}. It was blocked.`,
        linkId: link.id,
        documentId: link.documentId,
        at: current,
      });
    }
  }

  const since = new Date(current.getTime() - BURST_WINDOW_MS);
  const denied = await prisma.accessLog.count({
    where: { linkId: link.id, outcome: { not: 'granted' }, createdAt: { gte: since } },
  });
  if (denied >= BURST_THRESHOLD && !(await recentlyNotified(prisma, link.ownerId, 'alert_denied_burst', link.id, since))) {
    await notify(prisma, {
      userId: link.ownerId,
      type: 'alert_denied_burst',
      title: 'Several blocked attempts on one link',
      body: `${denied} attempts to open your link for "{document}" ({recipient}) were blocked in the last 10 minutes. This may be worth a look.`,
      linkId: link.id,
      documentId: link.documentId,
    });
    await logEvent(prisma, {
      userId: link.ownerId,
      eventType: 'repeated_denied_access',
      severity: 'warning',
      linkId: link.id,
      documentId: link.documentId,
      metadata: { deniedInWindow: denied },
      at: current,
    });
  }
}

function denialError(link: GateLink, decision: GateDecision, signedIn: boolean): AppError {
  switch (decision.outcome) {
    case 'denied_revoked':
      return new AppError(410, 'link_revoked', 'This link was revoked by its owner and no longer works.');
    case 'denied_expired':
      return new AppError(410, 'link_expired', `This link expired on ${link.expiresAt.toUTCString()}.`, {
        expiredAt: link.expiresAt.toISOString(),
      });
    case 'denied_recipient':
      return signedIn
        ? new AppError(403, 'not_recipient', 'This link is restricted to members of the recipient organization. Your account is not one of them.')
        : new AppError(401, 'login_required', 'This link is restricted to members of the recipient organization. Sign in with your organization account to open it.');
    case 'denied_country':
      return decision.country
        ? new AppError(403, 'country_blocked', 'This document is not available from your location.')
        : new AppError(403, 'country_unknown', 'Access from your location could not be confirmed, so this document is not available.');
    default:
      return new AppError(403, 'denied', 'Access denied');
  }
}

async function buildSharedView(deps: AppDeps, request: FastifyRequest, link: GateLink, decision: GateDecision) {
  const document = link.document;
  const dek = await loadDataKey(deps, document.id);
  try {
    const permitted = new Set(link.permissions.map((p) => p.claimId));
    const claims = decryptClaims(dek, document.id, document.claims).filter((c) => permitted.has(c.id));

    let verification;
    let presentation: string | null = null;
    let fields: Array<{ label: string; value: string; source: 'issuer' | 'self_declared' }>;

    if (document.kind === 'credential') {
      const sdJwt = await loadStoredCredential(deps, document.id, dek);
      const result = await presentAndVerify(deps, sdJwt, claims.map((c) => c.disclosure!).filter(Boolean));
      presentation = result.presentation;
      verification = result.outcome;
      // Show exactly the values that passed cryptographic verification.
      fields = result.outcome.claims.map((c) => ({ label: c.label, value: c.value, source: 'issuer' as const }));
      if (request.auth) {
        await recordVerification(deps, result.outcome, {
          method: 'share_link',
          userId: request.auth.user.id,
          orgId: decision.accessorOrgId,
          linkId: link.id,
          documentId: document.id,
        });
      }
    } else {
      fields = claims.map((c) => ({ label: c.label, value: c.value, source: 'self_declared' as const }));
      verification = {
        result: 'unverified' as const,
        reason:
          fields.length > 0
            ? 'These details were entered by the document owner. No trusted issuer has signed them.'
            : 'This file was uploaded by its owner. No trusted issuer has signed it, so its authenticity is not verified.',
        checks: [],
        issuer: null,
        claims: [],
        credentialId: null,
        documentId: null,
        expiresAt: null,
      };
    }

    return {
      link: {
        id: link.id,
        recipientLabel: openRecipientLabel(dek, link),
        recipientType: link.recipientType,
        recipientOrg: link.recipientOrg?.name ?? null,
        sharedBy: link.owner.fullName,
        sharedAt: link.createdAt,
        expiresAt: link.expiresAt,
        viewOnly: true,
      },
      document: {
        title: openTitle(dek, document),
        category: document.category,
        kind: document.kind,
        fileShared: link.includeFile,
        mimeType: link.includeFile ? document.mimeType : null,
      },
      fields,
      verification,
      presentation,
      viewer: { approximateCountry: decision.country },
      notice:
        'View only. A watermark identifies this view. Screenshots, screen recording and phone cameras cannot be blocked by any website.',
    };
  } finally {
    dek.fill(0);
  }
}

async function sendWatermarkedFile(deps: AppDeps, reply: FastifyReply, link: GateLink) {
  if (!link.includeFile) throw new AppError(403, 'file_not_shared', 'The owner shared selected details only, not the file.');
  const dek = await loadDataKey(deps, link.document.id);
  let data: Buffer = Buffer.alloc(0);
  let recipient = '';
  try {
    data = await readDocumentFile(deps, link.document, dek);
    recipient = link.recipientOrg?.name ?? openRecipientLabel(dek, link);
  } finally {
    dek.fill(0);
  }
  const watermarked = await watermarkDocument(data, link.document.mimeType, {
    recipient,
    viewedAt: deps.now(),
    linkRef: link.id.slice(0, 8),
  });
  return reply.headers(fileResponseHeaders('application/pdf')).send(watermarked);
}

const tokenParam = z.object({ token: z.string().regex(/^[A-Za-z0-9_-]{20,100}$/) });

export async function accessRoutes(app: FastifyInstance) {
  const deps = app.deps;
  const { prisma } = deps;

  async function findByToken(request: FastifyRequest): Promise<GateLink> {
    const parsed = tokenParam.safeParse(request.params);
    const link = parsed.success
      ? await prisma.sharingLink.findUnique({ where: { tokenHash: hashToken(parsed.data.token) }, include: linkInclude })
      : null;
    if (!link) {
      await logEvent(prisma, {
        eventType: 'invalid_link_attempt',
        severity: 'info',
        metadata: { client: userAgentFamily(request.headers['user-agent']) },
      });
      throw new AppError(404, 'link_not_found', 'This link is not valid. Check that you copied the whole link.');
    }
    return link as GateLink;
  }

  const shareLimit = { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } };

  app.get('/api/share/:token', shareLimit, async (request) => {
    const link = await findByToken(request);
    const decision = await evaluateAccess(deps, request, link, 'details');
    if (decision.outcome !== 'granted') throw denialError(link, decision, Boolean(request.auth));
    return buildSharedView(deps, request, link, decision);
  });

  app.get('/api/share/:token/file', shareLimit, async (request, reply) => {
    const link = await findByToken(request);
    const decision = await evaluateAccess(deps, request, link, 'file');
    if (decision.outcome !== 'granted') throw denialError(link, decision, Boolean(request.auth));
    return sendWatermarkedFile(deps, reply, link);
  });

  // ---- Organization inbox: links addressed to the user's organizations ------

  app.get('/api/inbox', async (request) => {
    const { user } = requireUser(request);
    const orgIds = await memberOrgIds(prisma, user.id);
    const links = await prisma.sharingLink.findMany({
      where: { recipientOrgId: { in: orgIds }, document: { deletedAt: null } },
      include: {
        document: { select: { ...TITLE_SELECT, kind: true, category: true } },
        owner: { select: { fullName: true } },
        recipientOrg: { select: { id: true, name: true } },
        _count: { select: { permissions: true } },
      },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });
    const current = deps.now();
    // Titles only for links that still work: a revoked or expired share reveals nothing more.
    const active = links.filter((l) => linkStatus(l, current) === 'active');
    const titles = await documentTitles(deps, active.map((l) => l.document));
    return {
      items: links.map((l) => ({
        id: l.id,
        document: { title: titles.get(l.document.id) ?? 'Shared document (no longer available)', kind: l.document.kind, category: l.document.category },
        sharedBy: l.owner.fullName,
        organization: l.recipientOrg,
        fieldCount: l._count.permissions,
        includeFile: l.includeFile,
        expiresAt: l.expiresAt,
        createdAt: l.createdAt,
        status: linkStatus(l, current),
      })),
    };
  });

  async function findInboxLink(request: FastifyRequest): Promise<GateLink> {
    requireUser(request);
    const id = z.object({ id: z.string().uuid() }).safeParse(request.params);
    if (!id.success) throw notFound('Shared document');
    const link = await prisma.sharingLink.findFirst({
      where: { id: id.data.id, recipientType: 'organization' },
      include: linkInclude,
    });
    if (!link) throw notFound('Shared document');
    return link as GateLink;
  }

  app.get('/api/inbox/:id', shareLimit, async (request) => {
    const link = await findInboxLink(request);
    const decision = await evaluateAccess(deps, request, link, 'details');
    if (decision.outcome === 'denied_recipient') throw notFound('Shared document');
    if (decision.outcome !== 'granted') throw denialError(link, decision, true);
    return buildSharedView(deps, request, link, decision);
  });

  app.get('/api/inbox/:id/file', shareLimit, async (request, reply) => {
    const link = await findInboxLink(request);
    const decision = await evaluateAccess(deps, request, link, 'file');
    if (decision.outcome === 'denied_recipient') throw notFound('Shared document');
    if (decision.outcome !== 'granted') throw denialError(link, decision, true);
    return sendWatermarkedFile(deps, reply, link);
  });
}

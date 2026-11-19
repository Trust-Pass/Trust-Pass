import type { FastifyInstance } from 'fastify';
import { analyzeQrContent, qrCheckSchema, type QrAnalysis, type QrFinding } from '@trustpass/shared';
import { hashToken } from '../lib/crypto';
import { parse } from '../lib/errors';
import { requireUser } from '../plugins/auth';
import { logEvent } from '../services/audit';

export type TrustPassLinkStatus = 'active' | 'expired' | 'revoked' | 'not_found';

/**
 * QR Shield: checks the text of a QR code (decoded on the user's device) or a pasted link.
 *
 * Privacy and safety:
 * - The address is analysed offline. It is never opened, fetched or resolved, so the check
 *   cannot be used to make the server visit arbitrary addresses (SSRF), and the person who
 *   made the code learns nothing.
 * - The content is not stored. Only dangerous results are logged, as kind and verdict.
 * - For official TrustPass share links the server checks the link exists and is usable,
 *   without counting a view or revealing anything about the document or its owner.
 */
export async function qrRoutes(app: FastifyInstance) {
  const { prisma, config } = app.deps;
  const limit = { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } };

  async function linkStatus(token: string): Promise<TrustPassLinkStatus> {
    const link = await prisma.sharingLink.findUnique({
      where: { tokenHash: hashToken(token) },
      select: { revokedAt: true, expiresAt: true, document: { select: { deletedAt: true } } },
    });
    if (!link) return 'not_found';
    if (link.revokedAt || link.document.deletedAt) return 'revoked';
    if (link.expiresAt.getTime() <= app.deps.now().getTime()) return 'expired';
    return 'active';
  }

  app.post('/api/qr/check', limit, async (request) => {
    const { user } = requireUser(request);
    const { content, source } = parse(qrCheckSchema, request.body);
    const analysis: QrAnalysis = analyzeQrContent(content, { appOrigin: config.appOrigin });

    let trustpassLink: { status: TrustPassLinkStatus } | null = null;
    if (analysis.trustpassToken) {
      const status = await linkStatus(analysis.trustpassToken);
      trustpassLink = { status };
      const finding: Record<TrustPassLinkStatus, QrFinding> = {
        active: { id: 'link_active', severity: 'info', title: 'Active TrustPass link', detail: 'This link exists and can be opened. Only its recipient rules decide who sees the document.' },
        expired: { id: 'link_expired', severity: 'low', title: 'This TrustPass link has expired', detail: 'It is genuine but no longer works. Ask the person who shared it for a new link.' },
        revoked: { id: 'link_revoked', severity: 'low', title: 'This TrustPass link was revoked', detail: 'It is genuine but its owner has turned it off.' },
        not_found: { id: 'link_not_found', severity: 'high', title: 'This TrustPass link does not exist', detail: 'The address looks like a TrustPass share link but no such link was ever created. It may be fake or mistyped.' },
      };
      analysis.findings.unshift(finding[status]);
      if (status === 'not_found') {
        analysis.verdict = 'danger';
        analysis.riskScore = Math.max(analysis.riskScore, 60);
        analysis.summary = 'Dangerous: this is not a real TrustPass link.';
        analysis.canOpen = false;
      } else if (status !== 'active') {
        analysis.verdict = 'caution';
        analysis.summary = status === 'expired' ? 'Genuine TrustPass link, but it has expired.' : 'Genuine TrustPass link, but it was revoked.';
      }
    }
    // Never send the token back: the client already has the text it decoded.
    const { trustpassToken: _omit, ...result } = analysis;

    if (result.verdict === 'danger') {
      await logEvent(prisma, {
        userId: user.id,
        actorUserId: user.id,
        eventType: 'qr_threat_detected',
        severity: 'warning',
        metadata: { source, kind: result.kind, findings: result.findings.filter((f) => f.severity === 'high' || f.severity === 'critical').map((f) => f.id) },
      });
    }
    return { analysis: result, trustpassLink };
  });
}

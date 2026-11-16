import type { FastifyInstance } from 'fastify';
import { requestCredentialSchema, verifyPresentationSchema } from '@trustpass/shared';
import { badRequest, parse } from '../lib/errors';
import { requireUser } from '../plugins/auth';
import { logEvent } from '../services/audit';
import { DEMO_ISSUER, ensureDemoIssuer, issueEnrollmentCredential } from '../services/issuer';
import { getSettings } from '../services/settings';
import { memberOrgIds } from '../services/users';
import { recordVerification, verifyFile, verifyPresentation } from '../services/verification';

export async function verificationRoutes(app: FastifyInstance) {
  const deps = app.deps;
  const { prisma, config } = deps;
  const limit = { config: { rateLimit: { max: 60, timeWindow: '10 minutes' } } };

  async function primaryOrg(userId: string) {
    const ids = await memberOrgIds(prisma, userId);
    return ids[0] ?? null;
  }

  app.post('/api/verify/presentation', limit, async (request) => {
    const { user } = requireUser(request);
    const { presentation } = parse(verifyPresentationSchema, request.body);
    const outcome = await verifyPresentation(deps, presentation);
    const record = await recordVerification(deps, outcome, {
      method: 'presentation',
      userId: user.id,
      orgId: await primaryOrg(user.id),
    });
    await logEvent(prisma, {
      userId: user.id,
      actorUserId: user.id,
      eventType: 'verification_completed',
      metadata: { method: 'presentation', result: outcome.result },
    });
    return { verification: outcome, recordId: record.id };
  });

  app.post('/api/verify/file', limit, async (request) => {
    const { user } = requireUser(request);
    if (!request.isMultipart()) throw badRequest('Send the file as multipart/form-data');
    let file: Buffer | undefined;
    for await (const part of request.parts({ limits: { fileSize: config.maxUploadBytes, files: 1, fields: 2 } })) {
      if (part.type === 'file') file = await part.toBuffer();
    }
    if (!file || file.length === 0) throw badRequest('Choose a file to verify');
    const outcome = await verifyFile(deps, file);
    const record = await recordVerification(deps, outcome, { method: 'file', userId: user.id, orgId: await primaryOrg(user.id) });
    await logEvent(prisma, {
      userId: user.id,
      actorUserId: user.id,
      eventType: 'verification_completed',
      metadata: { method: 'file', result: outcome.result },
    });
    return { verification: outcome, recordId: record.id };
  });

  app.get('/api/verify/records', async (request) => {
    const { user } = requireUser(request);
    const orgIds = await memberOrgIds(prisma, user.id);
    const records = await prisma.verificationRecord.findMany({
      where: { OR: [{ verifiedByUserId: user.id }, ...(orgIds.length ? [{ verifiedByOrgId: { in: orgIds } }] : [])] },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });
    const issuerIds = Array.from(new Set(records.map((r) => r.issuerId).filter((x): x is string => Boolean(x))));
    const issuers = await prisma.issuer.findMany({ where: { id: { in: issuerIds } }, select: { id: true, name: true } });
    const userIds = Array.from(new Set(records.map((r) => r.verifiedByUserId).filter((x): x is string => Boolean(x))));
    const users = await prisma.user.findMany({ where: { id: { in: userIds } }, select: { id: true, fullName: true } });
    return {
      records: records.map((r) => ({
        id: r.id,
        result: r.result,
        method: r.method,
        reason: r.reason,
        issuer: issuers.find((i) => i.id === r.issuerId)?.name ?? null,
        verifiedBy: users.find((u) => u.id === r.verifiedByUserId)?.fullName ?? null,
        createdAt: r.createdAt,
      })),
    };
  });

  // ---- Simulated trusted issuer --------------------------------------------

  app.get('/api/issuer', async (request) => {
    const { user } = requireUser(request);
    const issuer = await ensureDemoIssuer(deps);
    const settings = await getSettings(prisma);
    const held = await prisma.credential.count({ where: { document: { ownerId: user.id, deletedAt: null } } });
    return {
      issuer: {
        name: issuer.name,
        identifier: issuer.identifier,
        status: issuer.status,
        simulated: issuer.isSimulated,
        keyId: issuer.kid,
        algorithm: 'Ed25519 (EdDSA)',
        format: 'SD-JWT',
      },
      held,
      limit: settings.credentialsPerUser,
      vct: DEMO_ISSUER.vct,
    };
  });

  app.post(
    '/api/issuer/credentials',
    { config: { rateLimit: { max: 10, timeWindow: '1 hour' } } },
    async (request, reply) => {
      const { user } = requireUser(request);
      const input = parse(requestCredentialSchema, request.body);
      const document = await issueEnrollmentCredential(deps, user, input);
      return reply.status(201).send({ document: { id: document.id, title: document.title } });
    },
  );
}

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Credential, Document, Issuer } from '@prisma/client';
import { documentMetadataSchema, MAX_CLAIMS_PER_DOCUMENT } from '@trustpass/shared';
import { z } from 'zod';
import { AppError, badRequest, notFound, parse } from '../lib/errors';
import { validateUpload } from '../lib/upload-validation';
import { requireUser } from '../plugins/auth';
import { logEvent } from '../services/audit';
import {
  claimKeyFromLabel,
  decryptClaims,
  loadDataKey,
  readDocumentFile,
  storeEncryptedDocument,
} from '../services/documents';
import { loadStoredCredential, presentAndVerify } from '../services/verification';
import type { AppDeps } from '../types';

export const uuidParam = z.object({ id: z.string().uuid() });

export function parseId(request: FastifyRequest, what = 'Resource'): string {
  const result = uuidParam.safeParse(request.params);
  if (!result.success) throw notFound(what);
  return result.data.id;
}

/** Ownership is part of the query itself, so another user's id simply is not found (no IDOR). */
export async function getOwnedDocument(deps: AppDeps, id: string, ownerId: string) {
  const document = await deps.prisma.document.findFirst({
    where: { id, ownerId, deletedAt: null },
    include: { credential: { include: { issuer: true } }, claims: true },
  });
  if (!document) throw notFound('Document');
  return document;
}

export function quickTrust(
  document: Document & { credential: (Credential & { issuer: Issuer }) | null },
  now: Date,
): { status: 'verified' | 'invalid' | 'unverified'; label: string } {
  if (document.kind !== 'credential' || !document.credential) {
    return { status: 'unverified', label: 'Uploaded by you, not verified by an issuer' };
  }
  if (document.credential.issuer.status !== 'trusted') return { status: 'invalid', label: 'Issuer no longer trusted' };
  if (document.credential.expiresAt <= now) return { status: 'invalid', label: 'Credential expired' };
  return { status: 'verified', label: `Signed by ${document.credential.issuer.name}` };
}

export function fileResponseHeaders(mimeType: string) {
  return {
    'Content-Type': mimeType,
    'Content-Disposition': 'inline; filename="trustpass-document"',
    'Cache-Control': 'no-store, private',
    'X-Content-Type-Options': 'nosniff',
    // Even if a browser rendered the file as a page, it could not run scripts.
    'Content-Security-Policy': "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:",
  };
}

export async function documentRoutes(app: FastifyInstance) {
  const deps = app.deps;
  const { prisma, config, now } = deps;

  app.get('/api/documents', async (request) => {
    const { user } = requireUser(request);
    const documents = await prisma.document.findMany({
      where: { ownerId: user.id, deletedAt: null },
      include: {
        credential: { include: { issuer: true } },
        _count: { select: { claims: true } },
        links: { select: { revokedAt: true, expiresAt: true } },
      },
      orderBy: { createdAt: 'desc' },
    });
    const current = now();
    return {
      documents: documents.map((d) => ({
        id: d.id,
        title: d.title,
        category: d.category,
        kind: d.kind,
        mimeType: d.mimeType,
        sizeBytes: d.sizeBytes,
        createdAt: d.createdAt,
        claimCount: d._count.claims,
        activeLinks: d.links.filter((l) => !l.revokedAt && l.expiresAt > current).length,
        totalLinks: d.links.length,
        trust: quickTrust(d, current),
      })),
    };
  });

  app.post(
    '/api/documents',
    { config: { rateLimit: { max: 30, timeWindow: '10 minutes' } } },
    async (request, reply) => {
      const { user } = requireUser(request);
      if (!request.isMultipart()) throw badRequest('Send the file as multipart/form-data');

      let metadataRaw: string | undefined;
      let file: Buffer | undefined;
      for await (const part of request.parts({ limits: { fileSize: config.maxUploadBytes, files: 1, fields: 5, fieldSize: 16_384 } })) {
        if (part.type === 'file') {
          if (part.fieldname !== 'file') {
            await part.toBuffer();
            continue;
          }
          file = await part.toBuffer();
        } else if (part.fieldname === 'metadata' && typeof part.value === 'string') {
          metadataRaw = part.value;
        }
      }
      if (!file) throw badRequest('Choose a file to upload');
      if (!metadataRaw) throw badRequest('Document details are missing');

      let metadataJson: unknown;
      try {
        metadataJson = JSON.parse(metadataRaw);
      } catch {
        throw badRequest('Document details are not valid JSON');
      }
      const metadata = parse(documentMetadataSchema, metadataJson);
      if (metadata.claims.length > MAX_CLAIMS_PER_DOCUMENT) throw badRequest('Too many fields');

      const validated = await validateUpload(file);
      const taken = new Set<string>();
      const document = await storeEncryptedDocument(deps, {
        ownerId: user.id,
        title: metadata.title,
        category: metadata.category,
        kind: 'file',
        mimeType: validated.mimeType,
        data: validated.data,
        claims: metadata.claims.map((c) => ({
          key: claimKeyFromLabel(c.label, taken),
          label: c.label,
          value: c.value,
          source: 'self_declared' as const,
        })),
      });
      return reply.status(201).send({
        document: {
          id: document.id,
          title: document.title,
          mimeType: document.mimeType,
          sizeBytes: document.sizeBytes,
          encryption: 'AES-256-GCM',
          sha256: document.plaintextSha256,
        },
      });
    },
  );

  app.get('/api/documents/:id', async (request) => {
    const { user } = requireUser(request);
    const document = await getOwnedDocument(deps, parseId(request, 'Document'), user.id);
    const dek = await loadDataKey(deps, document.id);
    try {
      const claims = decryptClaims(dek, document.id, document.claims);
      let verification = null;
      if (document.kind === 'credential' && document.credential) {
        const sdJwt = await loadStoredCredential(deps, document.id, dek);
        const { outcome } = await presentAndVerify(deps, sdJwt, claims.map((c) => c.disclosure!).filter(Boolean));
        verification = outcome;
      }
      const links = await prisma.sharingLink.findMany({
        where: { documentId: document.id, ownerId: user.id },
        include: { countries: true, recipientOrg: { select: { name: true } }, _count: { select: { permissions: true } } },
        orderBy: { createdAt: 'desc' },
      });
      const current = now();
      return {
        document: {
          id: document.id,
          title: document.title,
          category: document.category,
          kind: document.kind,
          mimeType: document.mimeType,
          sizeBytes: document.sizeBytes,
          createdAt: document.createdAt,
          sha256: document.plaintextSha256,
          encryption: { algorithm: 'AES-256-GCM', keyWrapping: 'AES-256-GCM master key', perDocumentKey: true },
          trust: quickTrust(document, current),
          credential: document.credential
            ? {
                id: document.credential.id,
                issuer: document.credential.issuer.name,
                simulatedIssuer: document.credential.issuer.isSimulated,
                issuedAt: document.credential.issuedAt,
                expiresAt: document.credential.expiresAt,
                format: 'SD-JWT (Ed25519)',
              }
            : null,
          verification,
          claims: claims.map(({ disclosure: _d, ...c }) => c),
          links: links.map((l) => ({
            id: l.id,
            recipientLabel: l.recipientLabel,
            recipientType: l.recipientType,
            recipientOrg: l.recipientOrg?.name ?? null,
            includeFile: l.includeFile,
            claimCount: l._count.permissions,
            expiresAt: l.expiresAt,
            revokedAt: l.revokedAt,
            createdAt: l.createdAt,
            viewCount: l.viewCount,
            countries: l.countries.map((c) => c.countryCode),
            status: l.revokedAt ? 'revoked' : l.expiresAt <= current ? 'expired' : 'active',
          })),
        },
      };
    } finally {
      dek.fill(0);
    }
  });

  app.get('/api/documents/:id/file', async (request, reply) => {
    const { user } = requireUser(request);
    const document = await getOwnedDocument(deps, parseId(request, 'Document'), user.id);
    const data = await readDocumentFile(deps, document);
    return reply.headers(fileResponseHeaders(document.mimeType)).send(data);
  });

  app.get('/api/documents/:id/credential', async (request, reply) => {
    const { user } = requireUser(request);
    const document = await getOwnedDocument(deps, parseId(request, 'Document'), user.id);
    if (document.kind !== 'credential') throw notFound('Credential');
    const sdJwt = await loadStoredCredential(deps, document.id);
    return reply
      .headers({
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': 'attachment; filename="trustpass-credential.sdjwt.txt"',
        'Cache-Control': 'no-store, private',
      })
      .send(sdJwt);
  });

  app.delete('/api/documents/:id', async (request) => {
    const { user } = requireUser(request);
    const document = await getOwnedDocument(deps, parseId(request, 'Document'), user.id);
    const current = now();
    // Crypto-shredding: once the wrapped key and ciphertext are gone, the
    // document can never be decrypted again, even from a backup of the database.
    await prisma.$transaction(async (tx) => {
      await tx.sharingLink.updateMany({ where: { documentId: document.id, revokedAt: null }, data: { revokedAt: current } });
      await tx.documentClaim.deleteMany({ where: { documentId: document.id } });
      await tx.credential.deleteMany({ where: { documentId: document.id } });
      await tx.documentKey.deleteMany({ where: { documentId: document.id } });
      await tx.document.update({ where: { id: document.id }, data: { deletedAt: current, title: '[deleted document]' } });
      await logEvent(tx, {
        userId: user.id,
        actorUserId: user.id,
        eventType: 'document_deleted',
        documentId: document.id,
        metadata: { title: document.title },
      });
    });
    await deps.storage.delete(document.storageKey).catch((err) => request.log.warn({ err }, 'storage delete failed'));
    return { ok: true };
  });
}

export function assertNotDeleted(document: Document) {
  if (document.deletedAt) throw new AppError(410, 'deleted', 'This document was deleted');
}

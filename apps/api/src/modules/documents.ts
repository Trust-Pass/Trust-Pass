import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Credential, Document, Issuer } from '@prisma/client';
import { documentMetadataSchema, MAX_CLAIMS_PER_DOCUMENT, redactionPlanSchema } from '@trustpass/shared';
import { PDFDocument } from 'pdf-lib';
import { z } from 'zod';
import { AppError, badRequest, notFound, parse } from '../lib/errors';
import { validateUpload } from '../lib/upload-validation';
import { requireUser } from '../plugins/auth';
import { logEvent } from '../services/audit';
import {
  selfDeclaredClaimKey,
  decryptClaims,
  loadDataKey,
  readDocumentFile,
  storeEncryptedDocument,
} from '../services/documents';
import { loadStoredCredential, presentAndVerify } from '../services/verification';
import { documentTitles, openSha256, openTitle, recipientLabels } from '../services/metadata';
import { open, redactionPlanAad, seal, sha256Hex, toBytes } from '../lib/crypto';
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
): { status: 'verified' | 'invalid' | 'expired' | 'unverified'; label: string } {
  if (document.kind !== 'credential' || !document.credential) {
    return { status: 'unverified', label: 'Uploaded by you, not verified by an issuer' };
  }
  // Same rules as the full check: a revoked issuer cannot be verified; expired is not invalid.
  if (document.credential.issuer.status !== 'trusted') return { status: 'unverified', label: 'Issuer no longer trusted' };
  if (document.credential.expiresAt <= now) return { status: 'expired', label: 'Credential expired' };
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

/** Pages of a stored document (1 for an image). Decrypts it in memory to count PDF pages. */
async function pageCount(deps: AppDeps, document: Parameters<typeof readDocumentFile>[1]): Promise<number> {
  if (document.mimeType !== 'application/pdf') return 1;
  const dek = await loadDataKey(deps, document.id);
  try {
    const data = await readDocumentFile(deps, document, dek);
    try {
      return (await PDFDocument.load(data, { updateMetadata: false })).getPageCount();
    } finally {
      data.fill(0);
    }
  } finally {
    dek.fill(0);
  }
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
    const titles = await documentTitles(deps, documents);
    return {
      documents: documents.map((d) => ({
        id: d.id,
        title: titles.get(d.id)!,
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
          key: selfDeclaredClaimKey(taken),
          label: c.label,
          value: c.value,
          source: 'self_declared' as const,
        })),
      });
      return reply.status(201).send({
        document: {
          id: document.id,
          title: metadata.title,
          mimeType: document.mimeType,
          sizeBytes: document.sizeBytes,
          encryption: 'AES-256-GCM',
          sha256: sha256Hex(validated.data),
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
      const recipients = await recipientLabels(deps, links);
      return {
        document: {
          id: document.id,
          title: openTitle(dek, document),
          category: document.category,
          kind: document.kind,
          mimeType: document.mimeType,
          sizeBytes: document.sizeBytes,
          createdAt: document.createdAt,
          sha256: openSha256(dek, document),
          encryption: {
            algorithm: 'AES-256-GCM',
            keyWrapping: config.env.KEY_PROVIDER === 'gcp-kms' ? 'Google Cloud KMS' : 'AES-256-GCM master key',
            perDocumentKey: true,
            encryptedMetadata: Boolean(document.titleEncrypted),
          },
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
            recipientLabel: recipients.get(l.id)!,
            recipientType: l.recipientType,
            recipientOrg: l.recipientOrg?.name ?? null,
            includeFile: l.includeFile,
            fileMode: l.includeFile ? (l.fileMode ?? 'original') : null,
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

  /**
   * "Check encryption": proves, on demand, what happens to this document at rest. Reads the stored
   * object as it is in storage, decrypts it with the document's own key (AES-256-GCM checks its
   * authentication tag, so any changed byte fails) and compares its SHA-256 with the sealed hash
   * from upload. Read-only: nothing is re-encrypted or rewritten. Owner only.
   */
  app.post(
    '/api/documents/:id/encryption-check',
    { config: { rateLimit: { max: 20, timeWindow: '10 minutes' } } },
    async (request) => {
      const { user } = requireUser(request);
      const document = await getOwnedDocument(deps, parseId(request, 'Document'), user.id);
      const key = await prisma.documentKey.findUnique({ where: { documentId: document.id }, select: { kekVersion: true, wrapIv: true, wrapTag: true } });
      const stored = await deps.storage.get(document.storageKey);
      const storedBytes = stored.length;
      // A plain file would start with its own signature; ciphertext must not.
      const head = stored.subarray(0, 8);
      const looksPlain =
        head.subarray(0, 5).toString('latin1') === '%PDF-' ||
        head.equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) ||
        (head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff);
      stored.fill(0);

      let authenticated = false;
      let sha256: string | null = null;
      let sha256Matches = false;
      const dek = await loadDataKey(deps, document.id);
      try {
        const expected = openSha256(dek, document);
        try {
          // Decrypts, checks the GCM tag and the sealed SHA-256 (and alerts on failure, as for any read).
          const plain = await readDocumentFile(deps, document, dek);
          authenticated = true;
          sha256 = sha256Hex(plain);
          sha256Matches = expected !== null && sha256 === expected;
          plain.fill(0);
        } catch {
          authenticated = false;
        }
      } finally {
        dek.fill(0);
      }
      const labelsSealed = document.claims.filter((c) => c.labelEncrypted).length;
      const redactedPages = await prisma.redactedPage.count({ where: { documentId: document.id } });
      const ok = authenticated && sha256Matches && !looksPlain && Boolean(document.titleEncrypted) && Boolean(document.sha256Encrypted);
      const current = now();
      await logEvent(prisma, {
        userId: user.id,
        actorUserId: user.id,
        eventType: 'document_encryption_checked',
        severity: ok ? 'info' : 'warning',
        documentId: document.id,
        metadata: { ok, authenticated, sha256Matches },
        at: current,
      });
      const provider = config.env.KEY_PROVIDER;
      return {
        check: {
          ok,
          checkedAt: current,
          file: {
            algorithm: 'AES-256-GCM',
            keyBits: 256,
            ivBytes: document.encIv.length,
            tagBytes: document.encTag.length,
            storedBytes,
            originalBytes: document.sizeBytes,
            storedLooksLikePlainFile: looksPlain,
            authenticated,
            sha256,
            sha256Matches,
          },
          key: {
            perDocument: true,
            wrapping: 'AES-256-GCM',
            provider,
            providerLabel:
              provider === 'gcp-kms'
                ? 'Google Cloud KMS'
                : provider === 'fake-kms'
                  ? 'Test-only KMS emulator (never used in production)'
                  : 'Server master key (Google Cloud KMS is not active)',
            kekVersion: key?.kekVersion ?? null,
          },
          metadata: {
            titleEncrypted: Boolean(document.titleEncrypted),
            sha256Encrypted: Boolean(document.sha256Encrypted),
            fieldLabelsEncrypted: labelsSealed,
            fields: document.claims.length,
          },
          redactedCopyPages: redactedPages,
        },
      };
    },
  );

  /**
   * The owner's saved choice of what to hide when this document is shared (sensitive information
   * chosen at upload or later). Sealed with the document's key; the original file is not touched.
   * Applied when the owner shares a redacted copy, where it can still be adjusted.
   */
  app.get('/api/documents/:id/redaction-plan', async (request) => {
    const { user } = requireUser(request);
    const document = await getOwnedDocument(deps, parseId(request, 'Document'), user.id);
    if (!document.redactionPlanEncrypted) return { redactions: [] };
    const dek = await loadDataKey(deps, document.id);
    try {
      const raw = open(dek, toBytes(document.redactionPlanEncrypted), redactionPlanAad(document.id)).toString('utf8');
      const parsed = redactionPlanSchema.safeParse({ redactions: JSON.parse(raw) });
      return { redactions: parsed.success ? parsed.data.redactions : [] };
    } catch {
      return { redactions: [] };
    } finally {
      dek.fill(0);
    }
  });

  app.put('/api/documents/:id/redaction-plan', async (request) => {
    const { user } = requireUser(request);
    const document = await getOwnedDocument(deps, parseId(request, 'Document'), user.id);
    const input = parse(redactionPlanSchema, request.body);
    const pages = await pageCount(deps, document);
    if (input.redactions.some((r) => r.page >= pages)) throw badRequest('An area to hide is on a page the document does not have');
    const dek = await loadDataKey(deps, document.id);
    let sealed: Uint8Array<ArrayBuffer> | null = null;
    try {
      if (input.redactions.length > 0) sealed = seal(dek, JSON.stringify(input.redactions), redactionPlanAad(document.id));
    } finally {
      dek.fill(0);
    }
    await prisma.document.update({ where: { id: document.id }, data: { redactionPlanEncrypted: sealed } });
    await logEvent(prisma, {
      userId: user.id,
      actorUserId: user.id,
      eventType: 'redaction_plan_saved',
      documentId: document.id,
      // Counts per category only: never positions or found text.
      metadata: { areas: input.redactions.length, kinds: [...new Set(input.redactions.map((r) => r.kind))] },
    });
    return { ok: true, areas: input.redactions.length };
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
    const redactedKeys = (await prisma.redactedPage.findMany({ where: { documentId: document.id }, select: { storageKey: true } })).map((r) => r.storageKey);
    // Crypto-shredding: once the wrapped key and ciphertext are gone, this database can
    // never decrypt the document again. A backup taken before the deletion still holds both,
    // and stays readable while its keys exist (see docs/recovery.md, "Deleted documents").
    await prisma.$transaction(async (tx) => {
      await tx.sharingLink.updateMany({ where: { documentId: document.id, revokedAt: null }, data: { revokedAt: current } });
      await tx.documentClaim.deleteMany({ where: { documentId: document.id } });
      await tx.credential.deleteMany({ where: { documentId: document.id } });
      await tx.redactedPage.deleteMany({ where: { documentId: document.id } });
      await tx.documentKey.deleteMany({ where: { documentId: document.id } });
      // The sealed metadata is unreadable without the key; erase it too, with any legacy plain values.
      await tx.sharingLink.updateMany({ where: { documentId: document.id }, data: { recipientLabel: null, recipientLabelEncrypted: null } });
      await tx.document.update({
        where: { id: document.id },
        data: { deletedAt: current, title: null, titleEncrypted: null, plaintextSha256: null, sha256Encrypted: null },
      });
      await logEvent(tx, {
        userId: user.id,
        actorUserId: user.id,
        eventType: 'document_deleted',
        documentId: document.id,
      });
    });
    await deps.storage.delete(document.storageKey).catch((err) => request.log.warn({ err }, 'storage delete failed'));
    for (const key of redactedKeys) await deps.storage.delete(key).catch((err) => request.log.warn({ err }, 'storage delete failed'));
    return { ok: true };
  });
}

export function assertNotDeleted(document: Document) {
  if (document.deletedAt) throw new AppError(410, 'deleted', 'This document was deleted');
}

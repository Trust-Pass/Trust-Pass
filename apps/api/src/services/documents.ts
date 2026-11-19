import { randomUUID } from 'node:crypto';
import type { ClaimSource, Document, DocumentCategory, DocumentClaim, DocumentKind, Prisma } from '@prisma/client';
import {
  claimAad,
  decrypt,
  encrypt,
  fileAad,
  generateDataKey,
  open,
  openString,
  seal,
  sha256Hex,
  toBytes,
  unwrapDataKey,
  wrapDataKey,
} from '../lib/crypto';
import { AppError } from '../lib/errors';
import { newStorageKey } from '../lib/storage';
import { UnknownKeyVersionError } from '../lib/keyset';
import type { AppDeps } from '../types';
import { logEvent } from './audit';
import { openClaimLabel, openSha256, sealClaimLabel, sealSha256, sealTitle } from './metadata';

export interface ClaimInput {
  key: string;
  label: string;
  value: string;
  source: ClaimSource;
  /** SD-JWT disclosure for issuer claims. */
  disclosure?: string;
}

export interface StoreDocumentInput {
  ownerId: string;
  title: string;
  category: DocumentCategory;
  kind: DocumentKind;
  mimeType: string;
  data: Buffer;
  claims: ClaimInput[];
  documentId?: string;
  /** Extra writes that must commit together with the document (e.g. the credential row). */
  extra?: (tx: Prisma.TransactionClient, documentId: string, dek: Buffer) => Promise<void>;
}

/**
 * Envelope encryption on upload:
 *  1. a fresh 256-bit data key (DEK) per document
 *  2. AES-256-GCM over the file, bound to documentId and ownerId via AAD
 *  3. the DEK wrapped by the master key and stored in document_keys
 *  4. only ciphertext goes to object storage, under a random name
 *  5. title, field labels and the file's SHA-256 sealed with the same DEK (E3/E5): nothing
 *     that describes the document is stored, logged or notified in clear
 */
export async function storeEncryptedDocument(deps: AppDeps, input: StoreDocumentInput): Promise<Document> {
  const { prisma, storage, config } = deps;
  // After a rotation, switch to the new key-encryption key before wrapping new data.
  await deps.keys?.refreshIfStale();
  const documentId = input.documentId ?? randomUUID();
  const dek = generateDataKey();
  try {
    const sealed = encrypt(dek, input.data, fileAad(documentId, input.ownerId));
    const wrapped = wrapDataKey(config, dek, documentId);
    const storageKey = newStorageKey();
    await storage.put(storageKey, sealed.ciphertext);

    try {
      return await prisma.$transaction(async (tx) => {
        const document = await tx.document.create({
          data: {
            id: documentId,
            ownerId: input.ownerId,
            titleEncrypted: sealTitle(dek, documentId, input.title),
            category: input.category,
            kind: input.kind,
            mimeType: input.mimeType,
            sizeBytes: input.data.length,
            storageKey,
            sha256Encrypted: sealSha256(dek, documentId, sha256Hex(input.data)),
            encIv: toBytes(sealed.iv),
            encTag: toBytes(sealed.tag),
          },
        });
        await tx.documentKey.create({ data: { documentId, ...wrapped } });
        let position = 0;
        for (const claim of input.claims) {
          await tx.documentClaim.create({
            data: {
              documentId,
              claimKey: claim.key,
              labelEncrypted: sealClaimLabel(dek, documentId, claim.key, claim.label),
              source: claim.source,
              position: position++,
              valueEncrypted: seal(dek, claim.value, claimAad(documentId, claim.key, 'value')),
              disclosureEncrypted: claim.disclosure
                ? seal(dek, claim.disclosure, claimAad(documentId, claim.key, 'disclosure'))
                : null,
            },
          });
        }
        if (input.extra) await input.extra(tx, documentId, dek);
        await logEvent(tx, {
          userId: input.ownerId,
          actorUserId: input.ownerId,
          eventType: input.kind === 'credential' ? 'credential_issued' : 'document_uploaded',
          documentId,
          // No title here: logs keep ids only (E4).
          metadata: { mimeType: input.mimeType, sizeBytes: input.data.length },
        });
        await logEvent(tx, {
          userId: input.ownerId,
          eventType: 'document_encrypted',
          documentId,
          metadata: { algorithm: 'AES-256-GCM', keyWrapping: 'AES-256-GCM', kekVersion: wrapped.kekVersion },
        });
        return document;
      });
    } catch (err) {
      await storage.delete(storageKey).catch(() => undefined);
      throw err;
    }
  } finally {
    dek.fill(0);
  }
}

export async function loadDataKey(deps: AppDeps, documentId: string): Promise<Buffer> {
  const key = await deps.prisma.documentKey.findUnique({ where: { documentId } });
  if (!key) throw new Error(`No data key for document ${documentId}`);
  try {
    return unwrapDataKey(deps.config, key, documentId);
  } catch (err) {
    // Re-wrapped by a rotation after this instance started: load the new keys once, retry.
    if (err instanceof UnknownKeyVersionError && deps.keys?.enabled) {
      await deps.keys.reload();
      return unwrapDataKey(deps.config, key, documentId);
    }
    throw err;
  }
}

/** Decrypts a document's file. Callers must have authorised the request first. */
export async function readDocumentFile(deps: AppDeps, document: Document, dek?: Buffer): Promise<Buffer> {
  const key = dek ?? (await loadDataKey(deps, document.id));
  try {
    const ciphertext = await deps.storage.get(document.storageKey);
    const plaintext = decrypt(
      key,
      { ciphertext, iv: Buffer.from(document.encIv), tag: Buffer.from(document.encTag) },
      fileAad(document.id, document.ownerId),
    );
    const expected = openSha256(key, document);
    if (expected && sha256Hex(plaintext) !== expected) throw new Error('hash mismatch');
    return plaintext;
  } catch (err) {
    // An authentication-tag failure means the ciphertext or its metadata was tampered with.
    await logEvent(deps.prisma, {
      userId: document.ownerId,
      eventType: 'integrity_check_failed',
      severity: 'high',
      documentId: document.id,
      metadata: { stage: 'decrypt' },
    });
    void err; // the original error stays out of the client response
    throw new AppError(500, 'integrity_error', 'The stored file failed its integrity check and cannot be shown.');
  } finally {
    if (!dek) key.fill(0);
  }
}

export interface DecryptedClaim {
  id: string;
  key: string;
  label: string;
  value: string;
  source: ClaimSource;
  disclosure: string | null;
}

export function decryptClaims(dek: Buffer, documentId: string, claims: DocumentClaim[]): DecryptedClaim[] {
  return [...claims]
    .sort((a, b) => a.position - b.position)
    .map((c) => ({
      id: c.id,
      key: c.claimKey,
      label: openClaimLabel(dek, documentId, c),
      value: openString(dek, c.valueEncrypted, claimAad(documentId, c.claimKey, 'value')),
      source: c.source,
      disclosure: c.disclosureEncrypted
        ? openString(dek, c.disclosureEncrypted, claimAad(documentId, c.claimKey, 'disclosure'))
        : null,
    }));
}

export function sealWithDek(dek: Buffer, value: string, aad: string): Uint8Array<ArrayBuffer> {
  return seal(dek, value, aad);
}

export function openWithDek(dek: Buffer, value: Uint8Array, aad: string): Buffer {
  return open(dek, value, aad);
}

/**
 * Key for a field typed by the owner. Neutral on purpose (f1, f2, ...): it is stored in clear
 * next to the encrypted label, so it must not repeat the label (E3). Issuer claims keep their
 * schema names (e.g. student_status), which describe the credential type, not the person.
 */
export function selfDeclaredClaimKey(taken: Set<string>): string {
  let n = taken.size + 1;
  while (taken.has(`f${n}`)) n++;
  const key = `f${n}`;
  taken.add(key);
  return key;
}

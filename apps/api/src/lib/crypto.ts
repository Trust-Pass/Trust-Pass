import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { AppConfig } from '../config';
import { UnknownKeyVersionError } from './keyset';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** Copy into a plain ArrayBuffer-backed Uint8Array (the type Prisma expects for Bytes columns). */
export function toBytes(data: Buffer | Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(data);
}

export interface Sealed {
  iv: Buffer;
  tag: Buffer;
  ciphertext: Buffer;
}

/** AES-256-GCM encryption. `aad` binds the ciphertext to its context (e.g. the document id). */
export function encrypt(key: Buffer, plaintext: Buffer, aad: string): Sealed {
  if (key.length !== 32) throw new Error('AES-256 key must be 32 bytes');
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), ciphertext };
}

/** Throws if the key, IV, tag, AAD or ciphertext were altered. */
export function decrypt(key: Buffer, sealed: Sealed, aad: string): Buffer {
  const decipher = createDecipheriv(ALGORITHM, key, sealed.iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(sealed.tag);
  return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);
}

/** Pack iv | tag | ciphertext into one buffer for small values stored in a single column. */
export function seal(key: Buffer, plaintext: Buffer | string, aad: string): Uint8Array<ArrayBuffer> {
  const data = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
  const { iv, tag, ciphertext } = encrypt(key, data, aad);
  return toBytes(Buffer.concat([iv, tag, ciphertext]));
}

export function open(key: Buffer, blob: Buffer | Uint8Array, aad: string): Buffer {
  const buf = Buffer.from(blob);
  if (buf.length < IV_BYTES + TAG_BYTES) throw new Error('Sealed value is too short');
  return decrypt(
    key,
    { iv: buf.subarray(0, IV_BYTES), tag: buf.subarray(IV_BYTES, IV_BYTES + TAG_BYTES), ciphertext: buf.subarray(IV_BYTES + TAG_BYTES) },
    aad,
  );
}

export function openString(key: Buffer, blob: Buffer | Uint8Array, aad: string): string {
  return open(key, blob, aad).toString('utf8');
}

// ---------------------------------------------------------------------------
// Envelope encryption: per-document data keys wrapped by the master key
// ---------------------------------------------------------------------------

export interface WrappedKey {
  wrappedDek: Uint8Array<ArrayBuffer>;
  wrapIv: Uint8Array<ArrayBuffer>;
  wrapTag: Uint8Array<ArrayBuffer>;
  kekVersion: number;
}

export function generateDataKey(): Buffer {
  return randomBytes(32);
}

export function wrapDataKey(config: AppConfig, dek: Buffer, documentId: string): WrappedKey {
  const { version, key } = config.masterKeys.current;
  const sealed = encrypt(key, dek, `dek|${documentId}`);
  return { wrappedDek: toBytes(sealed.ciphertext), wrapIv: toBytes(sealed.iv), wrapTag: toBytes(sealed.tag), kekVersion: version };
}

export function unwrapDataKey(
  config: AppConfig,
  wrapped: { wrappedDek: Uint8Array; wrapIv: Uint8Array; wrapTag: Uint8Array; kekVersion: number },
  documentId: string,
): Buffer {
  const kek = config.masterKeys.all.get(wrapped.kekVersion);
  if (!kek) throw new UnknownKeyVersionError(wrapped.kekVersion);
  return decrypt(
    kek,
    { ciphertext: Buffer.from(wrapped.wrappedDek), iv: Buffer.from(wrapped.wrapIv), tag: Buffer.from(wrapped.wrapTag) },
    `dek|${documentId}`,
  );
}

/** AAD for a document's file ciphertext: moving ciphertext to another record breaks decryption. */
export function fileAad(documentId: string, ownerId: string): string {
  return `file|${documentId}|${ownerId}`;
}

export function claimAad(documentId: string, claimKey: string, part: 'value' | 'disclosure'): string {
  return `claim|${documentId}|${claimKey}|${part}`;
}

export function credentialAad(documentId: string): string {
  return `credential|${documentId}`;
}

export function linkTokenAad(linkId: string): string {
  return `link-token|${linkId}`;
}

// ---------------------------------------------------------------------------
// Tokens and hashing
// ---------------------------------------------------------------------------

/** 256-bit random token, URL-safe. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256Hex(data: Buffer | Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sha256Base64Url(data: Buffer | Uint8Array | string): string {
  return createHash('sha256').update(data).digest('base64url');
}

/** Tokens are stored only as SHA-256 hashes, so a database leak exposes no working token. */
export function hashToken(token: string): string {
  return sha256Hex(token);
}

export function hmacHex(key: Buffer, data: string, length = 32): string {
  return createHmac('sha256', key).update(data).digest('hex').slice(0, length);
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

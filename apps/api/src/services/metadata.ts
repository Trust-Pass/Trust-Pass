import { DEFAULT_WATERMARK, watermarkSchema, type WatermarkSettings } from '@trustpass/shared';
import { claimLabelAad, open, recipientLabelAad, seal, sha256Aad, titleAad, unwrapDataKey, watermarkAad } from '../lib/crypto';
import { UnknownKeyVersionError } from '../lib/keyset';
import type { AppDeps } from '../types';

/**
 * E3/E5: document metadata (title, field labels, recipient labels, file SHA-256) is sealed with
 * the document's own data key, so it is encrypted at rest and destroyed with the key when the
 * document is deleted (crypto-shredding).
 *
 * Rows written before E3 still have the plain columns until `pnpm keys:encrypt-metadata` runs;
 * every reader here prefers the encrypted value and falls back to the plain one.
 *
 * Callers must have authorised the request before asking for metadata.
 */

export const DELETED_TITLE = 'Deleted document';
const UNREADABLE = 'Document';

type Bytes = Uint8Array | null;

export interface TitleSource {
  id: string;
  title: string | null;
  titleEncrypted: Bytes;
  deletedAt?: Date | null;
}

export interface ClaimLabelSource {
  claimKey: string;
  label: string | null;
  labelEncrypted: Bytes;
}

export interface RecipientSource {
  id: string;
  documentId: string;
  recipientLabel: string | null;
  recipientLabelEncrypted: Bytes;
}

export function sealTitle(dek: Buffer, documentId: string, title: string) {
  return seal(dek, title, titleAad(documentId));
}

export function sealSha256(dek: Buffer, documentId: string, sha256: string) {
  return seal(dek, sha256, sha256Aad(documentId));
}

export function sealClaimLabel(dek: Buffer, documentId: string, claimKey: string, label: string) {
  return seal(dek, label, claimLabelAad(documentId, claimKey));
}

export function sealRecipientLabel(dek: Buffer, documentId: string, linkId: string, label: string) {
  return seal(dek, label, recipientLabelAad(documentId, linkId));
}

function openText(dek: Buffer | undefined, blob: Bytes, aad: string): string | null {
  if (!dek || !blob) return null;
  try {
    return open(dek, blob, aad).toString('utf8');
  } catch {
    return null;
  }
}

export function openTitle(dek: Buffer | undefined, doc: TitleSource): string {
  if (doc.deletedAt) return DELETED_TITLE;
  return openText(dek, doc.titleEncrypted, titleAad(doc.id)) ?? doc.title ?? UNREADABLE;
}

export function openSha256(dek: Buffer, doc: { id: string; plaintextSha256: string | null; sha256Encrypted: Bytes }): string | null {
  return openText(dek, doc.sha256Encrypted, sha256Aad(doc.id)) ?? doc.plaintextSha256;
}

export function openClaimLabel(dek: Buffer | undefined, documentId: string, claim: ClaimLabelSource): string {
  return openText(dek, claim.labelEncrypted, claimLabelAad(documentId, claim.claimKey)) ?? claim.label ?? 'Field';
}

export function openRecipientLabel(dek: Buffer | undefined, link: RecipientSource): string {
  return openText(dek, link.recipientLabelEncrypted, recipientLabelAad(link.documentId, link.id)) ?? link.recipientLabel ?? 'Recipient';
}

export function sealWatermark(dek: Buffer, documentId: string, linkId: string, settings: WatermarkSettings) {
  return seal(dek, JSON.stringify(settings), watermarkAad(documentId, linkId));
}

export interface WatermarkSource {
  id: string;
  documentId: string;
  watermarkEnabled: boolean;
  watermarkEncrypted: Bytes;
}

/**
 * A link's watermark. Fails toward a watermark: it is off only when the clear flag AND the sealed
 * settings both say so. Missing or unreadable settings mean the standard watermark (every link
 * created before watermark control has none).
 */
export function openWatermark(dek: Buffer | undefined, link: WatermarkSource): WatermarkSettings {
  const raw = openText(dek, link.watermarkEncrypted, watermarkAad(link.documentId, link.id));
  let settings: WatermarkSettings = DEFAULT_WATERMARK;
  if (raw) {
    try {
      const parsed = watermarkSchema.safeParse(JSON.parse(raw));
      if (parsed.success) settings = parsed.data;
    } catch {
      /* standard watermark */
    }
  }
  return { ...settings, enabled: settings.enabled || link.watermarkEnabled };
}

/**
 * Unwrap the data keys of several documents at once (one query). Deleted documents have no key
 * any more and are simply absent from the map. Call `zero()` when done.
 */
export async function dataKeys(deps: AppDeps, documentIds: string[]): Promise<{ get(id: string): Buffer | undefined; zero(): void }> {
  const ids = [...new Set(documentIds)];
  const map = new Map<string, Buffer>();
  if (ids.length > 0) {
    const rows = await deps.prisma.documentKey.findMany({ where: { documentId: { in: ids } } });
    let reloaded = false;
    for (const row of rows) {
      try {
        map.set(row.documentId, unwrapDataKey(deps.config, row, row.documentId));
      } catch (err) {
        if (err instanceof UnknownKeyVersionError && deps.keys?.enabled && !reloaded) {
          // Re-wrapped by a rotation after this instance started: load the new keys once, retry.
          await deps.keys.reload();
          reloaded = true;
          try {
            map.set(row.documentId, unwrapDataKey(deps.config, row, row.documentId));
          } catch {
            /* stays unreadable */
          }
        }
      }
    }
  }
  return {
    get: (id) => map.get(id),
    zero: () => {
      for (const k of map.values()) k.fill(0);
      map.clear();
    },
  };
}

/** Titles for a list of documents the caller may see. */
export async function documentTitles(deps: AppDeps, docs: TitleSource[]): Promise<Map<string, string>> {
  const keys = await dataKeys(deps, docs.filter((d) => !d.deletedAt).map((d) => d.id));
  try {
    return new Map(docs.map((d) => [d.id, openTitle(keys.get(d.id), d)]));
  } finally {
    keys.zero();
  }
}

/** Recipient labels for a list of links the caller may see. */
export async function recipientLabels(deps: AppDeps, links: RecipientSource[]): Promise<Map<string, string>> {
  const keys = await dataKeys(deps, links.map((l) => l.documentId));
  try {
    return new Map(links.map((l) => [l.id, openRecipientLabel(keys.get(l.documentId), l)]));
  } finally {
    keys.zero();
  }
}

/** Prisma `select` fragments for the columns these helpers need. */
export const TITLE_SELECT = { id: true, title: true, titleEncrypted: true, deletedAt: true } as const;
export const RECIPIENT_SELECT = { id: true, documentId: true, recipientLabel: true, recipientLabelEncrypted: true } as const;

/**
 * Titles and recipient labels for an owner's own documents and links, in one pass (analytics,
 * activity, notifications, dashboard). Ids that are not the owner's resolve to null.
 */
export async function ownerLabels(deps: AppDeps, ownerId: string, documentIds: Array<string | null | undefined>, linkIds: Array<string | null | undefined>) {
  const linkSet = [...new Set(linkIds.filter((x): x is string => Boolean(x)))];
  const links = linkSet.length
    ? await deps.prisma.sharingLink.findMany({ where: { id: { in: linkSet }, ownerId }, select: RECIPIENT_SELECT })
    : [];
  const docSet = [...new Set([...documentIds.filter((x): x is string => Boolean(x)), ...links.map((l) => l.documentId)])];
  const docs = docSet.length ? await deps.prisma.document.findMany({ where: { id: { in: docSet }, ownerId }, select: TITLE_SELECT }) : [];
  const keys = await dataKeys(deps, docs.filter((d) => !d.deletedAt).map((d) => d.id));
  const titles = new Map(docs.map((d) => [d.id, openTitle(keys.get(d.id), d)]));
  const recipients = new Map(links.map((l) => [l.id, openRecipientLabel(keys.get(l.documentId), l)]));
  const linkDoc = new Map(links.map((l) => [l.id, l.documentId]));
  keys.zero();
  return {
    title: (documentId: string | null | undefined) => (documentId ? (titles.get(documentId) ?? null) : null),
    linkTitle: (linkId: string | null | undefined) => (linkId ? (titles.get(linkDoc.get(linkId) ?? '') ?? null) : null),
    recipient: (linkId: string | null | undefined) => (linkId ? (recipients.get(linkId) ?? null) : null),
  };
}

/** Fill the {document} and {recipient} placeholders of a stored notification (single pass). */
export function fillPlaceholders(text: string, values: { document: string | null; recipient: string | null }): string {
  return text.replace(/\{(document|recipient)\}/g, (_m, name: 'document' | 'recipient') =>
    name === 'document' ? (values.document ?? DELETED_TITLE) : (values.recipient ?? 'a recipient'),
  );
}

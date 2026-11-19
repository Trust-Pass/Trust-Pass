import type { Prisma, PrismaClient } from '@prisma/client';
import type { AppConfig } from '../config';
import { claimAad, claimLabelAad, open, seal, unwrapDataKey } from '../lib/crypto';
import { sealClaimLabel, sealRecipientLabel, sealSha256, sealTitle } from './metadata';

/**
 * E3/E4/E5 backfill, run once with `keys encrypt-metadata` after the migration that adds the
 * encrypted columns. For rows written before E3 it:
 *  - seals titles, file SHA-256, field labels and recipient labels with each document's data
 *    key, then erases the plain values;
 *  - renames self-declared field keys that repeat their label (e.g. "employer") to f1, f2, ...
 *    re-sealing the value under the new key;
 *  - erases plain metadata of deleted documents (their key is gone: nothing left to protect);
 *  - rewrites stored notifications to the {document}/{recipient} placeholder form;
 *  - removes titles and recipient names from security_events metadata. That table is
 *    append-only, so each affected row is copied without them (same id, time and type) inside
 *    one transaction that explicitly allows the purge.
 * Idempotent: a second run finds nothing to do. --dry-run counts only, in a READ ONLY transaction.
 */

type Db = PrismaClient | Prisma.TransactionClient;

export interface MetadataReport {
  dryRun: boolean;
  documents: { sealed: number; deletedErased: number; withoutKey: string[] };
  fields: { sealed: number; renamed: number };
  links: { sealed: number; erased: number };
  notifications: { rewritten: number };
  logs: { cleaned: number };
  /** Plain metadata still present after the run (must be 0 when not a dry run). */
  remaining: { titles: number; hashes: number; labels: number; recipients: number; logRows: number; notifications: number };
}

const LOG_KEYS = ['title', 'recipient', 'recipientLabel', 'label'];
// PostgreSQL regex ("." also matches newlines). Rows already in placeholder form are excluded.
const NOTIFICATION_TITLE = '(link for) ".*" \\(.*\\) (was opened|after it|were blocked)';
const ALREADY = '%"{document}" ({recipient})%';

export async function countPlainMetadata(db: Db) {
  const [titles, hashes, labels, recipients, logRows, notifications] = await Promise.all([
    db.document.count({ where: { title: { not: null } } }),
    db.document.count({ where: { plaintextSha256: { not: null } } }),
    db.documentClaim.count({ where: { label: { not: null } } }),
    db.sharingLink.count({ where: { recipientLabel: { not: null } } }),
    db.$queryRawUnsafe<Array<{ n: bigint }>>(`SELECT count(*)::bigint AS n FROM security_events WHERE metadata ?| $1::text[]`, LOG_KEYS),
    db.$queryRawUnsafe<Array<{ n: bigint }>>(
      `SELECT count(*)::bigint AS n FROM notifications WHERE (body ~ $1 AND body NOT LIKE $2) OR (type = 'link_received' AND body ~ ' shared "')`,
      NOTIFICATION_TITLE,
      ALREADY,
    ),
  ]);
  return { titles, hashes, labels, recipients, logRows: Number(logRows[0]!.n), notifications: Number(notifications[0]!.n) };
}

const isLabelDerivedKey = (key: string) => !/^f\d+$/.test(key);

export async function encryptLegacyMetadata(
  deps: { config: AppConfig; prisma: Db },
  options: { dryRun?: boolean; batchSize?: number; onProgress?: (line: string) => void } = {},
): Promise<MetadataReport> {
  const { config, prisma } = deps;
  const dryRun = options.dryRun ?? false;
  const batchSize = options.batchSize ?? 100;
  const report: MetadataReport = {
    dryRun,
    documents: { sealed: 0, deletedErased: 0, withoutKey: [] },
    fields: { sealed: 0, renamed: 0 },
    links: { sealed: 0, erased: 0 },
    notifications: { rewritten: 0 },
    logs: { cleaned: 0 },
    remaining: { titles: 0, hashes: 0, labels: 0, recipients: 0, logRows: 0, notifications: 0 },
  };

  // 1. Documents (and their fields and links), batch by batch.
  let cursor: string | undefined;
  for (;;) {
    const batch = await prisma.document.findMany({
      where: {
        OR: [
          { title: { not: null } },
          { plaintextSha256: { not: null } },
          { claims: { some: { OR: [{ label: { not: null } }, { source: 'self_declared' }] } } },
          { links: { some: { recipientLabel: { not: null } } } },
        ],
      },
      include: { key: true, claims: true, links: { select: { id: true, recipientLabel: true, recipientLabelEncrypted: true } } },
      orderBy: { id: 'asc' },
      take: batchSize,
      ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
    });
    if (batch.length === 0) break;
    cursor = batch[batch.length - 1]!.id;

    for (const doc of batch) {
      if (doc.deletedAt || !doc.key) {
        if (!doc.deletedAt) {
          report.documents.withoutKey.push(doc.id);
          continue;
        }
        // Deleted: the key is gone, so there is nothing to seal; erase what is still in clear.
        const plainLinks = doc.links.filter((l) => l.recipientLabel !== null).length;
        if (doc.title !== null || doc.plaintextSha256 !== null || plainLinks > 0) {
          report.documents.deletedErased++;
          report.links.erased += plainLinks;
          if (!dryRun) {
            await prisma.document.update({ where: { id: doc.id }, data: { title: null, plaintextSha256: null } });
            await prisma.sharingLink.updateMany({ where: { documentId: doc.id }, data: { recipientLabel: null, recipientLabelEncrypted: null } });
          }
        }
        continue;
      }

      const dek = unwrapDataKey(config, doc.key, doc.id);
      try {
        const data: Prisma.DocumentUpdateInput = {};
        if (doc.title !== null) {
          if (!doc.titleEncrypted) data.titleEncrypted = sealTitle(dek, doc.id, doc.title);
          data.title = null;
        }
        if (doc.plaintextSha256 !== null) {
          if (!doc.sha256Encrypted) data.sha256Encrypted = sealSha256(dek, doc.id, doc.plaintextSha256);
          data.plaintextSha256 = null;
        }
        const docChanged = Object.keys(data).length > 0;

        // Fields: seal labels; give owner-typed fields neutral keys.
        const taken = new Set(doc.claims.map((c) => c.claimKey).filter((k) => !isLabelDerivedKey(k)));
        let next = 1;
        const fieldUpdates: Array<{ id: string; data: Prisma.DocumentClaimUpdateInput }> = [];
        for (const claim of [...doc.claims].sort((a, b) => a.position - b.position)) {
          const rename = claim.source === 'self_declared' && isLabelDerivedKey(claim.claimKey);
          if (claim.label === null && !rename) continue;
          let key = claim.claimKey;
          const update: Prisma.DocumentClaimUpdateInput = {};
          if (rename) {
            while (taken.has(`f${next}`)) next++;
            key = `f${next}`;
            taken.add(key);
            const value = open(dek, claim.valueEncrypted, claimAad(doc.id, claim.claimKey, 'value'));
            update.claimKey = key;
            update.valueEncrypted = seal(dek, value, claimAad(doc.id, key, 'value'));
            value.fill(0);
            if (claim.disclosureEncrypted) {
              const disclosure = open(dek, claim.disclosureEncrypted, claimAad(doc.id, claim.claimKey, 'disclosure'));
              update.disclosureEncrypted = seal(dek, disclosure, claimAad(doc.id, key, 'disclosure'));
              disclosure.fill(0);
            }
            report.fields.renamed++;
          }
          const label = claim.label ?? (claim.labelEncrypted ? open(dek, claim.labelEncrypted, claimLabelAad(doc.id, claim.claimKey)).toString('utf8') : null);
          if (label !== null) {
            update.labelEncrypted = sealClaimLabel(dek, doc.id, key, label);
            update.label = null;
            if (claim.label !== null) report.fields.sealed++;
          }
          fieldUpdates.push({ id: claim.id, data: update });
        }

        const linkUpdates = doc.links
          .filter((l) => l.recipientLabel !== null)
          .map((l) => ({
            id: l.id,
            data: {
              recipientLabelEncrypted: l.recipientLabelEncrypted ?? sealRecipientLabel(dek, doc.id, l.id, l.recipientLabel!),
              recipientLabel: null,
            },
          }));

        if (docChanged) report.documents.sealed++;
        report.links.sealed += linkUpdates.length;
        if (!dryRun && (docChanged || fieldUpdates.length || linkUpdates.length)) {
          const write = async (tx: Prisma.TransactionClient) => {
            if (docChanged) await tx.document.update({ where: { id: doc.id }, data });
            for (const u of fieldUpdates) await tx.documentClaim.update({ where: { id: u.id }, data: u.data });
            for (const u of linkUpdates) await tx.sharingLink.update({ where: { id: u.id }, data: u.data });
          };
          // One transaction per document, so a document is never half-converted.
          if ('$transaction' in prisma) await (prisma as PrismaClient).$transaction(write);
          else await write(prisma);
        }
      } finally {
        dek.fill(0);
      }
    }
    options.onProgress?.(`documents: ${report.documents.sealed} sealed so far`);
  }

  // 2. Notifications: keep the wording, replace the names with placeholders.
  if (dryRun) {
    report.notifications.rewritten = (await countPlainMetadata(prisma)).notifications;
  } else {
    const a = await prisma.$executeRawUnsafe(
      `UPDATE notifications SET body = regexp_replace(body, $1, '\\1 "{document}" ({recipient}) \\2') WHERE body ~ $1 AND body NOT LIKE $2`,
      NOTIFICATION_TITLE,
      ALREADY,
    );
    const b = await prisma.$executeRawUnsafe(
      `UPDATE notifications SET body = regexp_replace(body, ' shared ".*" with your organization', ' shared a document with your organization')
       WHERE type = 'link_received' AND body ~ ' shared "'`,
    );
    report.notifications.rewritten = a + b;
  }

  // 3. security_events (append-only): copy each affected row without the names, same id.
  if (dryRun) {
    report.logs.cleaned = (await countPlainMetadata(prisma)).logRows;
  } else {
    const purge = async (tx: Prisma.TransactionClient) => {
      await tx.$executeRawUnsafe(`SET LOCAL trustpass.allow_log_purge = 'on'`);
      return tx.$executeRawUnsafe(
        `WITH moved AS (DELETE FROM security_events WHERE metadata ?| $1::text[] RETURNING *)
         INSERT INTO security_events (id, user_id, actor_user_id, event_type, severity, document_id, link_id, metadata, created_at)
         SELECT id, user_id, actor_user_id, event_type, severity, document_id, link_id, metadata - $1::text[], created_at FROM moved`,
        LOG_KEYS,
      );
    };
    report.logs.cleaned = '$transaction' in prisma ? await (prisma as PrismaClient).$transaction(purge) : await purge(prisma as Prisma.TransactionClient);
  }

  report.remaining = dryRun ? report.remaining : await countPlainMetadata(prisma);
  return report;
}

export function metadataMigrationSucceeded(report: MetadataReport): boolean {
  const r = report.remaining;
  return report.documents.withoutKey.length === 0 && r.titles + r.hashes + r.labels + r.recipients + r.logRows + r.notifications === 0;
}

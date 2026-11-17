import type { PrismaClient } from '@prisma/client';
import type { AppConfig } from '../config';
import { linkTokenAad, open, seal, toBytes, unwrapDataKey, wrapDataKey } from '../lib/crypto';
import type { Db } from '../lib/keyring';
import { decryptToken } from '../modules/sharing';

/**
 * Moves every document's data key to the current key-encryption key (KEK) and every
 * stored link token to the current link-token key. File ciphertext, field values and
 * credentials are never touched: only the small wrapped keys change.
 *
 * Safe to run more than once and safe to stop half-way: each row is updated on its own,
 * only if it still has the version that was read, and rows already on the current
 * version are skipped. With `dryRun` nothing is written (the CLI also runs dry runs inside
 * a READ ONLY transaction, so the database itself refuses any write); every key is still
 * unwrapped, which proves the old keys work before anything changes. A dry run before the
 * first KMS key exists has no target yet: it then only proves that everything opens.
 */
export interface RewrapReport {
  dryRun: boolean;
  targetKekVersion: number | null;
  targetLinkTokenVersion: number | null;
  dataKeys: { onOldVersion: number; rewrapped: number; failed: string[] };
  linkTokens: { checked: number; resealed: number; unreadable: string[] };
  verification: { dataKeys: number; allOnTarget: boolean; allOpen: boolean; linkTokensOnTarget: boolean };
}

export interface RewrapOptions {
  dryRun?: boolean;
  batchSize?: number;
  onProgress?: (message: string) => void;
}

export async function rewrapAll(deps: { config: AppConfig; prisma: Db }, options: RewrapOptions = {}): Promise<RewrapReport> {
  const { config, prisma } = deps;
  const dryRun = options.dryRun ?? false;
  const batchSize = Math.max(1, Math.min(options.batchSize ?? 100, 1000));
  const target = config.masterKeys.hasCurrent ? config.masterKeys.current.version : null;
  const linkTarget = config.linkTokenKeys.hasCurrent ? config.linkTokenKeys.current : null;
  if (!dryRun && (target === null || linkTarget === null)) throw new Error('No current key to re-wrap onto');
  const report: RewrapReport = {
    dryRun,
    targetKekVersion: target,
    targetLinkTokenVersion: linkTarget?.version ?? null,
    dataKeys: { onOldVersion: 0, rewrapped: 0, failed: [] },
    linkTokens: { checked: 0, resealed: 0, unreadable: [] },
    verification: { dataKeys: 0, allOnTarget: false, allOpen: false, linkTokensOnTarget: false },
  };

  // 1. Data keys, in batches ordered by document id.
  let after: string | undefined;
  for (;;) {
    const batch = await prisma.documentKey.findMany({
      where: { ...(target !== null ? { kekVersion: { not: target } } : {}), ...(after ? { documentId: { gt: after } } : {}) },
      orderBy: { documentId: 'asc' },
      take: batchSize,
    });
    if (batch.length === 0) break;
    for (const row of batch) {
      report.dataKeys.onOldVersion++;
      let dek: Buffer;
      try {
        dek = unwrapDataKey(config, row, row.documentId);
      } catch {
        report.dataKeys.failed.push(row.documentId);
        continue;
      }
      try {
        if (!dryRun) {
          const wrapped = wrapDataKey(config, dek, row.documentId);
          // Only if nobody changed or deleted the row since it was read.
          const updated = await prisma.documentKey.updateMany({
            where: { documentId: row.documentId, kekVersion: row.kekVersion },
            data: wrapped,
          });
          if (updated.count === 1) report.dataKeys.rewrapped++;
        }
      } finally {
        dek.fill(0);
      }
    }
    after = batch[batch.length - 1]!.documentId;
    options.onProgress?.(`data keys: ${report.dataKeys.onOldVersion} checked`);
  }

  // 2. Stored link tokens (the owner's copy, for "Copy link"). The link itself keeps
  //    working either way (lookups use the token hash), but an unreadable copy counts as a
  //    failure: removing an old key would lose "Copy link" for that link.
  let afterLink: string | undefined;
  for (;;) {
    const links = await prisma.sharingLink.findMany({
      where: afterLink ? { id: { gt: afterLink } } : {},
      select: { id: true, tokenEncrypted: true },
      orderBy: { id: 'asc' },
      take: batchSize,
    });
    if (links.length === 0) break;
    for (const link of links) {
      report.linkTokens.checked++;
      if (linkTarget && opensWith(linkTarget.key, link.id, link.tokenEncrypted)) continue;
      let token: string;
      try {
        token = decryptToken({ config }, link.id, link.tokenEncrypted);
      } catch {
        report.linkTokens.unreadable.push(link.id);
        continue;
      }
      if (!dryRun) {
        // Only if the stored copy is still the one that was read.
        const updated = await prisma.sharingLink.updateMany({
          where: { id: link.id, tokenEncrypted: { equals: toBytes(link.tokenEncrypted) } },
          data: { tokenEncrypted: seal(linkTarget!.key, token, linkTokenAad(link.id)) },
        });
        if (updated.count === 1) report.linkTokens.resealed++;
      } else {
        report.linkTokens.resealed++; // would be re-sealed
      }
    }
    afterLink = links[links.length - 1]!.id;
    options.onProgress?.(`link tokens: ${report.linkTokens.checked} checked`);
  }

  // 3. Verification: every data key opens with its recorded version, every link copy
  //    opens, and (unless this was a dry run) everything is on the target versions.
  let allOpen = true;
  let allOnTarget = true;
  let afterCheck: string | undefined;
  for (;;) {
    const batch = await prisma.documentKey.findMany({
      where: afterCheck ? { documentId: { gt: afterCheck } } : {},
      orderBy: { documentId: 'asc' },
      take: batchSize,
    });
    if (batch.length === 0) break;
    for (const row of batch) {
      report.verification.dataKeys++;
      if (row.kekVersion !== target) allOnTarget = false;
      try {
        unwrapDataKey(config, row, row.documentId).fill(0);
      } catch {
        allOpen = false;
      }
    }
    afterCheck = batch[batch.length - 1]!.documentId;
  }
  let linksOnTarget = linkTarget !== null;
  let afterLinkCheck: string | undefined;
  for (;;) {
    const links = await prisma.sharingLink.findMany({
      where: afterLinkCheck ? { id: { gt: afterLinkCheck } } : {},
      select: { id: true, tokenEncrypted: true },
      orderBy: { id: 'asc' },
      take: batchSize,
    });
    if (links.length === 0) break;
    for (const link of links) {
      if (!linkTarget || !opensWith(linkTarget.key, link.id, link.tokenEncrypted)) linksOnTarget = false;
    }
    afterLinkCheck = links[links.length - 1]!.id;
  }
  report.verification.allOpen = allOpen && report.linkTokens.unreadable.length === 0;
  report.verification.allOnTarget = allOnTarget;
  report.verification.linkTokensOnTarget = linksOnTarget;
  return report;
}

function opensWith(key: Buffer, linkId: string, sealed: Uint8Array): boolean {
  try {
    open(key, sealed, linkTokenAad(linkId));
    return true;
  } catch {
    return false;
  }
}

/** A rewrap succeeded when nothing failed, everything opens, and (for a real run) everything moved. */
export function rewrapSucceeded(report: RewrapReport): boolean {
  return (
    report.dataKeys.failed.length === 0 &&
    report.linkTokens.unreadable.length === 0 &&
    report.verification.allOpen &&
    (report.dryRun || (report.verification.allOnTarget && report.verification.linkTokensOnTarget))
  );
}

// ---------------------------------------------------------------------------
// Destroying retired keys
// ---------------------------------------------------------------------------

export interface DestroyReport {
  dryRun: boolean;
  destroyable: Array<{ purpose: string; version: number }>;
  kept: Array<{ purpose: string; version: number; reason: string }>;
  destroyed: number;
}

/**
 * Deletes retired keys that nothing needs any more, so their KMS key version can then be
 * disabled. A retired key is kept when:
 *  - documents still use it (kek), or any stored link copy does not open with the current
 *    link-token key (link_token): run keys:rewrap first;
 *  - it was retired less than `minRetiredMs` ago: running servers may still be wrapping
 *    new data with it until their next key check (KEY_REFRESH_SECONDS).
 * Everything is re-checked inside the deleting transaction, under the keyring lock.
 */
export async function destroyRetiredKeys(
  deps: { config: AppConfig; prisma: Db },
  options: { dryRun?: boolean; now?: Date; minRetiredMs?: number } = {},
): Promise<DestroyReport> {
  const { config, prisma } = deps;
  const dryRun = options.dryRun ?? false;
  const now = options.now ?? new Date();
  const minRetiredMs = options.minRetiredMs ?? Math.max(10 * 60_000, 4 * config.env.KEY_REFRESH_SECONDS * 1000);

  const decide = async (db: Db) => {
    const report: DestroyReport = { dryRun, destroyable: [], kept: [], destroyed: 0 };
    const retired = await db.keyEncryptionKey.findMany({ where: { status: 'retired' }, orderBy: [{ purpose: 'asc' }, { version: 'asc' }] });
    let linksOk: boolean | null = null;
    for (const row of retired) {
      const id = { purpose: row.purpose, version: row.version };
      if (!row.retiredAt || now.getTime() - row.retiredAt.getTime() < minRetiredMs) {
        report.kept.push({ ...id, reason: `retired less than ${Math.round(minRetiredMs / 60_000)} minutes ago` });
        continue;
      }
      if (row.purpose === 'kek') {
        const used = await db.documentKey.count({ where: { kekVersion: row.version } });
        if (used > 0) {
          report.kept.push({ ...id, reason: `${used} document(s) still use it: run keys:rewrap first` });
          continue;
        }
      } else {
        linksOk ??= await allLinksOnCurrentKey(config, db);
        if (!linksOk) {
          report.kept.push({ ...id, reason: 'some link copies are not on the current link-token key: run keys:rewrap first' });
          continue;
        }
      }
      report.destroyable.push(id);
    }
    return report;
  };

  if (dryRun) return decide(prisma);
  if (typeof (prisma as PrismaClient).$transaction !== 'function') throw new Error('Destroying keys needs a database client');

  return (prisma as PrismaClient).$transaction(
    async (tx) => {
      await tx.$executeRawUnsafe(`SELECT pg_advisory_xact_lock(hashtext('trustpass-keyring'))`);
      const report = await decide(tx);
      if (report.destroyable.length > 0) {
        await tx.$executeRawUnsafe(`SELECT set_config('trustpass.allow_key_destroy', 'on', true)`);
        for (const { purpose, version } of report.destroyable) {
          await tx.keyEncryptionKey.delete({ where: { purpose_version: { purpose, version } } });
          report.destroyed++;
        }
      }
      return report;
    },
    { timeout: 120_000 },
  );
}

async function allLinksOnCurrentKey(config: AppConfig, db: Db): Promise<boolean> {
  if (!config.linkTokenKeys.hasCurrent) return false;
  const key = config.linkTokenKeys.current.key;
  let after: string | undefined;
  for (;;) {
    const links = await db.sharingLink.findMany({
      where: after ? { id: { gt: after } } : {},
      select: { id: true, tokenEncrypted: true },
      orderBy: { id: 'asc' },
      take: 500,
    });
    if (links.length === 0) return true;
    if (!links.every((l) => opensWith(key, l.id, l.tokenEncrypted))) return false;
    after = links[links.length - 1]!.id;
  }
}

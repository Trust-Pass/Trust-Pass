import type { PrismaClient } from '@prisma/client';
import type { AppConfig } from '../config';
import { linkTokenAad, open, seal, unwrapDataKey, wrapDataKey } from '../lib/crypto';
import { decryptToken } from '../modules/sharing';

/**
 * Moves every document's data key to the current key-encryption key (KEK) and every
 * stored link token to the current link-token key. File ciphertext, field values and
 * credentials are never touched: only the small wrapped keys change.
 *
 * Safe to run more than once and safe to stop half-way: each row is updated on its own,
 * only if it still has the version that was read, and rows already on the current
 * version are skipped. With `dryRun`, nothing is written; every key is still unwrapped,
 * which proves the old keys work before anything changes.
 */
export interface RewrapReport {
  dryRun: boolean;
  targetKekVersion: number;
  targetLinkTokenVersion: number;
  dataKeys: { onOldVersion: number; rewrapped: number; failed: string[] };
  linkTokens: { checked: number; resealed: number; unreadable: string[] };
  verification: { dataKeys: number; allOnTarget: boolean; allOpen: boolean };
}

export interface RewrapOptions {
  dryRun?: boolean;
  batchSize?: number;
  onProgress?: (message: string) => void;
}

export async function rewrapAll(
  deps: { config: AppConfig; prisma: PrismaClient },
  options: RewrapOptions = {},
): Promise<RewrapReport> {
  const { config, prisma } = deps;
  const dryRun = options.dryRun ?? false;
  const batchSize = Math.max(1, Math.min(options.batchSize ?? 100, 1000));
  const target = config.masterKeys.current.version;
  const linkTarget = config.linkTokenKeys.current;
  const report: RewrapReport = {
    dryRun,
    targetKekVersion: target,
    targetLinkTokenVersion: linkTarget.version,
    dataKeys: { onOldVersion: 0, rewrapped: 0, failed: [] },
    linkTokens: { checked: 0, resealed: 0, unreadable: [] },
    verification: { dataKeys: 0, allOnTarget: false, allOpen: false },
  };

  // 1. Data keys, in batches ordered by document id.
  let after: string | undefined;
  for (;;) {
    const batch = await prisma.documentKey.findMany({
      where: { kekVersion: { not: target }, ...(after ? { documentId: { gt: after } } : {}) },
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

  // 2. Stored link tokens (the owner's copy, for "Copy link"). Unreadable ones are reported,
  //    not fatal: the link itself keeps working, because lookups use the token hash.
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
      try {
        open(linkTarget.key, link.tokenEncrypted, linkTokenAad(link.id));
        continue; // already on the current link-token key
      } catch {
        /* needs re-sealing */
      }
      let token: string;
      try {
        token = decryptToken({ config }, link.id, link.tokenEncrypted);
      } catch {
        report.linkTokens.unreadable.push(link.id);
        continue;
      }
      if (!dryRun) {
        await prisma.sharingLink.update({
          where: { id: link.id },
          data: { tokenEncrypted: seal(linkTarget.key, token, linkTokenAad(link.id)) },
        });
      }
      report.linkTokens.resealed++;
    }
    afterLink = links[links.length - 1]!.id;
    options.onProgress?.(`link tokens: ${report.linkTokens.checked} checked`);
  }

  // 3. Verification: every data key opens with its recorded version, and (unless this was
  //    a dry run) every one is on the target version.
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
  report.verification.allOpen = allOpen;
  report.verification.allOnTarget = allOnTarget;
  return report;
}

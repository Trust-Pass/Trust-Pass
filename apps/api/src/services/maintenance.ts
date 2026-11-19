import type { Prisma } from '@prisma/client';
import type { AppDeps } from '../types';
import { rewrapAll, rewrapSucceeded } from './key-rotation';
import { encryptLegacyMetadata, metadataMigrationSucceeded } from './metadata-migration';

/**
 * Opt-in start-up maintenance, for hosts without a shell (Render free).
 *
 *   STARTUP_MAINTENANCE=encrypt-metadata,rewrap
 *
 * Empty by default: nothing runs. When set, the listed tasks run once after the server has
 * started listening (health checks keep passing), in this order:
 *  - encrypt-metadata: E3/E4/E5 backfill (same code as `keys encrypt-metadata`);
 *  - rewrap: move every data key and link copy onto the current keys (same as `keys rewrap`),
 *    e.g. after switching to KEY_PROVIDER=gcp-kms.
 * Both are idempotent: a restart with the variable still set finds nothing to do. Results are
 * logged as counts only and stored in system_settings ("maintenance:last") for Admin > Health.
 * Remove the variable afterwards. Assumes a single instance (Render free); with several
 * instances, run the `keys` commands from one machine instead.
 */
export const MAINTENANCE_TASKS = ['encrypt-metadata', 'rewrap'] as const;
export type MaintenanceTask = (typeof MAINTENANCE_TASKS)[number];

export function parseMaintenanceTasks(value: string): MaintenanceTask[] {
  const items = value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const item of items) {
    if (!(MAINTENANCE_TASKS as readonly string[]).includes(item)) {
      throw new Error(`STARTUP_MAINTENANCE: unknown task "${item}" (allowed: ${MAINTENANCE_TASKS.join(', ')})`);
    }
  }
  return MAINTENANCE_TASKS.filter((t) => items.includes(t));
}

export interface MaintenanceResult {
  task: MaintenanceTask;
  ok: boolean;
  summary: Record<string, number | string | boolean>;
  error?: string;
}

export interface MaintenanceLogger {
  info(obj: Record<string, unknown>, msg: string): void;
}

export async function runStartupMaintenance(deps: AppDeps, tasks: MaintenanceTask[], log: MaintenanceLogger): Promise<MaintenanceResult[]> {
  const { config, prisma } = deps;
  const results: MaintenanceResult[] = [];
  for (const task of tasks) {
    try {
      if (task === 'encrypt-metadata') {
        const r = await encryptLegacyMetadata({ config, prisma });
        const remaining = Object.values(r.remaining).reduce((a, b) => a + b, 0);
        results.push({
          task,
          ok: metadataMigrationSucceeded(r),
          summary: {
            documentsSealed: r.documents.sealed,
            deletedErased: r.documents.deletedErased,
            documentsWithoutKey: r.documents.withoutKey.length,
            fieldsSealed: r.fields.sealed,
            fieldsRenamed: r.fields.renamed,
            linksSealed: r.links.sealed,
            notificationsRewritten: r.notifications.rewritten,
            logRowsCleaned: r.logs.cleaned,
            plainMetadataRemaining: remaining,
          },
        });
      } else {
        const r = await rewrapAll({ config, prisma });
        results.push({
          task,
          ok: rewrapSucceeded(r),
          summary: {
            targetKekVersion: r.targetKekVersion ?? 'none',
            dataKeysRewrapped: r.dataKeys.rewrapped,
            dataKeysFailed: r.dataKeys.failed.length,
            linkCopiesResealed: r.linkTokens.resealed,
            linkCopiesUnreadable: r.linkTokens.unreadable.length,
          },
        });
      }
    } catch (err) {
      // Never log the error object itself: it could carry key or row details.
      results.push({ task, ok: false, summary: {}, error: err instanceof Error ? err.name : 'Error' });
    }
    const last = results[results.length - 1]!;
    log.info({ maintenance: last.task, ok: last.ok, ...last.summary, ...(last.error ? { error: last.error } : {}) }, 'start-up maintenance task finished');
  }
  const value = { at: deps.now().toISOString(), results } as unknown as Prisma.InputJsonValue;
  await prisma.systemSetting.upsert({ where: { key: 'maintenance:last' }, create: { key: 'maintenance:last', value }, update: { value } });
  return results;
}

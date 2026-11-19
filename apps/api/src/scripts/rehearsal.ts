import { readFileSync } from 'node:fs';
import { PrismaClient } from '@prisma/client';
import { buildApp } from '../app';
import { loadConfig } from '../config';
import { runStartupMaintenance } from '../services/maintenance';
import { countPlainMetadata, encryptLegacyMetadata, metadataMigrationSucceeded } from '../services/metadata-migration';
import {
  checkShareLinks,
  ciphertextFingerprint,
  compareSnapshots,
  probeDocuments,
  RehearsalGeo,
  snapshotDocuments,
  type Failure,
} from '../services/release-rehearsal';

/**
 * Release rehearsal: runs the release's start-up checks and metadata backfill on a RESTORED COPY
 * of the production database and proves nothing was lost or changed.
 *
 *   node dist/rehearsal.js        secrets on standard input, one per line:
 *                                 MASTER_KEY, IP_HASH_SECRET, ISSUER_SIGNING_SEED
 *   DATABASE_URL                  the restored copy (the rehearsal script points it at a RAM-only
 *                                 PostgreSQL reached through a local socket)
 *
 * Refuses any database whose host is not a local socket or localhost. Prints one JSON report:
 * counts, short ids and yes/no answers only. Exit code 0 = every check passed.
 */

export interface RehearsalSecrets {
  masterKey: string;
  ipHashSecret: string;
  issuerSigningSeed: string;
}

export interface RehearsalReport {
  startupChecks: 'passed' | 'refused';
  kekVersions: number[];
  plainMetadataBefore: Record<string, number>;
  before: { counts: Record<string, number>; failures: Failure[] };
  dryRun: { documentsToSeal: number; fieldsToSeal: number; fieldsToRename: number; linksToSeal: number; readBackFailures: number };
  backfill: { ok: boolean; summary: Record<string, unknown>; error?: string };
  plainMetadataAfter: Record<string, number>;
  secondRunChanges: number;
  after: { counts: Record<string, number>; failures: Failure[] };
  unchangedDocuments: number;
  changedDocuments: Failure[];
  links: Awaited<ReturnType<typeof checkShareLinks>> | null;
  /** New link per active document, opened as a recipient: real files viewed and downloaded. */
  recipientProbe: Awaited<ReturnType<typeof probeDocuments>> | null;
  ciphertextUnchanged: boolean;
  verdict: 'REHEARSAL PASSED' | 'REHEARSAL FAILED';
  reasons: string[];
}

/** True for a database reached through a local socket or on this machine. */
export function isLocalDatabase(url: string): boolean {
  try {
    const u = new URL(url);
    const socket = u.searchParams.get('host');
    if (socket?.startsWith('/')) return true;
    return ['localhost', '127.0.0.1', '[::1]', '::1'].includes(u.hostname);
  } catch {
    return false;
  }
}

export async function runRehearsal(
  databaseUrl: string,
  secrets: RehearsalSecrets,
  options: { realNow?: Date; storageDriver?: 'database' | 'local'; storageDir?: string } = {},
): Promise<RehearsalReport> {
  if (!isLocalDatabase(databaseUrl)) throw new Error('The rehearsal only runs on a local copy (local socket or localhost), never on a remote database');
  const realNow = options.realNow ?? new Date();
  const prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  const reasons: string[] = [];
  try {
    const versions = (await prisma.documentKey.groupBy({ by: ['kekVersion'] })).map((v) => v.kekVersion).sort((a, b) => a - b);
    if (versions.length > 1) throw new Error(`Documents use several key versions (${versions.join(', ')}); add PREVIOUS_MASTER_KEYS support before rehearsing`);
    const env: NodeJS.ProcessEnv = {
      NODE_ENV: 'development',
      DATABASE_URL: databaseUrl,
      KEY_PROVIDER: 'env',
      MASTER_KEY: secrets.masterKey,
      MASTER_KEY_VERSION: String(versions[0] ?? 1),
      IP_HASH_SECRET: secrets.ipHashSecret,
      ISSUER_SIGNING_SEED: secrets.issuerSigningSeed,
      STORAGE_DRIVER: options.storageDriver ?? 'database',
      ...(options.storageDir ? { STORAGE_DIR: options.storageDir } : {}),
      GEO_PROVIDER: 'simulated',
      MAIL_TRANSPORT: 'none',
      LOG_LEVEL: 'silent',
      KEY_REFRESH_SECONDS: '0',
    };
    const config = loadConfig(env);
    const clock = { now: realNow };
    const geo = new RehearsalGeo();
    const start = () => buildApp({ config, prisma, geo, now: () => new Date(clock.now), logger: false });

    // 1. Start-up checks of the release (key derivation, stored document keys open).
    let app: Awaited<ReturnType<typeof buildApp>>;
    try {
      app = await start();
      await app.ready();
    } catch {
      return failedEarly(versions, reasons, 'the release refused to start: the configured keys do not open the stored document keys, or the database is not the expected one');
    }

    const fpStart = await ciphertextFingerprint(app.deps);
    const plainBefore = await countPlainMetadata(prisma);
    const before = await snapshotDocuments(app.deps);

    // 2. Dry run of the backfill, in a READ ONLY transaction.
    const dry = await prisma.$transaction(
      async (tx) => {
        await tx.$executeRawUnsafe('SET TRANSACTION READ ONLY');
        return encryptLegacyMetadata({ config, prisma: tx }, { dryRun: true });
      },
      { timeout: 10 * 60_000, maxWait: 30_000 },
    );

    // 3. The real backfill, through the same code path as STARTUP_MAINTENANCE=encrypt-metadata.
    const [maintenance] = await runStartupMaintenance(app.deps, ['encrypt-metadata'], { info: () => undefined });
    const plainAfter = await countPlainMetadata(prisma);
    const second = await encryptLegacyMetadata({ config, prisma });
    const secondRunChanges =
      second.documents.sealed + second.documents.deletedErased + second.fields.sealed + second.fields.renamed + second.links.sealed + second.notifications.rewritten + second.logs.cleaned;
    await app.close();

    // 4. A freshly started server reads everything exactly as before.
    const app2 = await start();
    await app2.ready();
    const after = await snapshotDocuments(app2.deps);
    const comparison = compareSnapshots(before, after);

    // 5. Share links, file views and recipient downloads through the real routes.
    const links = await checkShareLinks(app2.deps, app2, clock, geo, realNow);
    const probe = await probeDocuments(app2.deps, app2, clock, geo, realNow);
    const fpEnd = await ciphertextFingerprint(app2.deps);
    await app2.close();

    const ciphertextUnchanged = fpStart.digest === fpEnd.digest;
    if (before.failures.length) reasons.push(`${before.failures.length} problem(s) reading documents before the backfill`);
    if (dry.documents.verifyFailed.length) reasons.push(`${dry.documents.verifyFailed.length} document(s) fail the read-back check`);
    if (!maintenance?.ok) reasons.push('the backfill did not finish cleanly');
    if (Object.values(plainAfter).some((n) => n > 0)) reasons.push('plain metadata remains after the backfill');
    if (secondRunChanges > 0) reasons.push('a second backfill run still changed something');
    if (after.failures.length) reasons.push(`${after.failures.length} problem(s) reading documents after the backfill`);
    if (comparison.changed.length) reasons.push(`${comparison.changed.length} document(s) read differently after the backfill`);
    if (links.failures.length) reasons.push(`${links.failures.length} share-link check(s) failed`);
    if (!links.downloadsOffByDefault) reasons.push('an existing link has downloads switched on');
    if (probe.failures.length) reasons.push(`${probe.failures.length} recipient check(s) on real documents failed`);
    if (probe.documents > 0 && probe.downloadsOk !== probe.documents) reasons.push('not every active document could be viewed and downloaded by a recipient');
    if (!ciphertextUnchanged) reasons.push('stored files or document keys changed');

    return {
      startupChecks: 'passed',
      kekVersions: versions,
      plainMetadataBefore: plainBefore,
      before: { counts: before.counts, failures: before.failures },
      dryRun: {
        documentsToSeal: dry.documents.sealed,
        fieldsToSeal: dry.fields.sealed,
        fieldsToRename: dry.fields.renamed,
        linksToSeal: dry.links.sealed,
        readBackFailures: dry.documents.verifyFailed.length,
      },
      backfill: { ok: Boolean(maintenance?.ok), summary: maintenance?.summary ?? {}, ...(maintenance?.error ? { error: maintenance.error } : {}) },
      plainMetadataAfter: plainAfter,
      secondRunChanges,
      after: { counts: after.counts, failures: after.failures },
      unchangedDocuments: comparison.same,
      changedDocuments: comparison.changed,
      links,
      recipientProbe: probe,
      ciphertextUnchanged,
      verdict: reasons.length === 0 ? 'REHEARSAL PASSED' : 'REHEARSAL FAILED',
      reasons,
    };
  } finally {
    await prisma.$disconnect();
  }
}

function failedEarly(versions: number[], reasons: string[], reason: string): RehearsalReport {
  reasons.push(reason);
  const empty = { counts: {}, failures: [] };
  return {
    startupChecks: 'refused',
    kekVersions: versions,
    plainMetadataBefore: {},
    before: empty,
    dryRun: { documentsToSeal: 0, fieldsToSeal: 0, fieldsToRename: 0, linksToSeal: 0, readBackFailures: 0 },
    backfill: { ok: false, summary: {} },
    plainMetadataAfter: {},
    secondRunChanges: 0,
    after: empty,
    unchangedDocuments: 0,
    changedDocuments: [],
    links: null,
    recipientProbe: null,
    ciphertextUnchanged: true,
    verdict: 'REHEARSAL FAILED',
    reasons,
  };
}

async function main() {
  const lines = readFileSync(0, 'utf8').split('\n').map((l) => l.replace(/\r$/, ''));
  const secrets = { masterKey: lines[0] ?? '', ipHashSecret: lines[1] ?? '', issuerSigningSeed: lines[2] ?? '' };
  const url = process.env.DATABASE_URL ?? '';
  try {
    const report = await runRehearsal(url, secrets);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.exitCode = report.verdict === 'REHEARSAL PASSED' ? 0 : 1;
  } catch (err) {
    // Configuration problems only; never echo a secret.
    const message = err instanceof Error ? err.message.replace(/[A-Za-z0-9+/=_-]{32,}/g, '[hidden]') : 'unknown error';
    process.stdout.write(`${JSON.stringify({ verdict: 'REHEARSAL FAILED', reasons: [message] }, null, 2)}\n`);
    process.exitCode = 1;
  } finally {
    secrets.masterKey = secrets.ipHashSecret = secrets.issuerSigningSeed = '';
  }
}

// Run when executed directly (not when imported by tests).
const invokedDirectly = process.argv[1] && /(^|[\\/])rehearsal(\.[cm]?[jt]s)?$/.test(process.argv[1]);
if (invokedDirectly) void main().then(() => process.exit(process.exitCode ?? 1));

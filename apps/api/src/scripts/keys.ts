/**
 * Key management commands. None of them print key material.
 *
 * In the production image (no TypeScript sources there):  node apps/api/dist/keys.js <command>
 * In development:                                          pnpm keys:<command>
 *
 *   status                                 provider, stored keys, documents per key version
 *   rewrap [--dry-run]                     move every data key and link copy to the current keys
 *   rotate [--dry-run] [--wait=<s>]        create a new KEK and link-token key, wait for running
 *                                          servers to pick them up, then rewrap
 *   destroy-retired [--dry-run] --confirm  delete retired keys nothing uses any more
 *
 * --dry-run and status run inside a READ ONLY database transaction: PostgreSQL itself
 * refuses any write. Options: --batch=<n> (default 100).
 * Exit code 0 = done and verified, 1 = not clean (run again / see report), 2 = usage.
 */
import { PrismaClient } from '@prisma/client';
import { loadConfig, type AppConfig } from '../config';
import { createManagedKeys, initKeyring, keyringStatus } from '../lib/keyring';
import { createKmsProvider } from '../lib/kms';
import { destroyRetiredKeys, rewrapAll, rewrapSucceeded, type RewrapReport } from '../services/key-rotation';

export interface KeysCliDeps {
  env?: NodeJS.ProcessEnv;
  prisma?: PrismaClient;
  out?: (line: string) => void;
  sleep?: (ms: number) => Promise<void>;
}

const COMMANDS = ['status', 'rewrap', 'rotate', 'destroy-retired'];

export async function runKeysCli(argv: string[], deps: KeysCliDeps = {}): Promise<number> {
  const out = deps.out ?? ((line: string) => console.log(line));
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const [command = 'status', ...rest] = argv;
  const dryRun = rest.includes('--dry-run');
  const confirm = rest.includes('--confirm');
  const batchArg = rest.find((a) => a.startsWith('--batch='));
  const waitArg = rest.find((a) => a.startsWith('--wait='));
  const batchSize = batchArg ? Number(batchArg.slice('--batch='.length)) : 100;
  const waitSeconds = waitArg ? Number(waitArg.slice('--wait='.length)) : null;
  const unknown = rest.filter((a) => a !== '--dry-run' && a !== '--confirm' && a !== batchArg && a !== waitArg);
  if (
    !COMMANDS.includes(command) ||
    unknown.length > 0 ||
    !Number.isInteger(batchSize) ||
    batchSize < 1 ||
    (waitSeconds !== null && (!Number.isInteger(waitSeconds) || waitSeconds < 0))
  ) {
    out('Usage: keys <status|rewrap|rotate|destroy-retired> [--dry-run] [--confirm] [--batch=<n>] [--wait=<seconds>]');
    return 2;
  }

  const env = deps.env ?? process.env;
  const config = loadConfig(env);
  const prisma = deps.prisma ?? new PrismaClient();
  const log = {
    info: (_obj: object, msg: string) => out(msg),
    warn: (_obj: object, msg: string) => out(`WARNING: ${msg}`),
  };
  try {
    const kms = createKmsProvider(config);

    // Read-only commands run entirely inside a READ ONLY transaction.
    if (command === 'status' || dryRun) {
      return await prisma.$transaction(
        async (tx) => {
          await tx.$executeRawUnsafe('SET TRANSACTION READ ONLY');
          await initKeyring({ config, prisma: tx, kms, log, createIfMissing: false, allowMissing: true });
          if (command === 'status') {
            out(JSON.stringify(await keyringStatus(config, tx), null, 2));
            return 0;
          }
          if (command === 'destroy-retired') {
            out(JSON.stringify(await destroyRetiredKeys({ config, prisma: tx }, { dryRun: true }), null, 2));
            return 0;
          }
          if (command === 'rotate') {
            out('Dry run: a real rotate creates a new key-encryption key and link-token key, waits for running servers, then re-wraps.');
          }
          if (!config.masterKeys.hasCurrent) {
            out('Dry run: no KMS-protected key exists yet; a real run creates one first. Checking that every stored key opens.');
          }
          return reportRewrap(await rewrapAll({ config, prisma: tx }, { dryRun: true, batchSize }), out);
        },
        { timeout: 10 * 60_000, maxWait: 30_000 },
      );
    }

    if (command === 'destroy-retired') {
      if (!confirm) {
        out('destroy-retired deletes keys for good. Run it with --dry-run first, then again with --confirm.');
        return 2;
      }
      await initKeyring({ config, prisma, kms, log, createIfMissing: false });
      const report = await destroyRetiredKeys({ config, prisma });
      out(JSON.stringify(report, null, 2));
      if (report.destroyed > 0) out('The destroyed keys can no longer decrypt anything. Their KMS key versions can now be disabled.');
      return 0;
    }

    if (command === 'rotate') {
      if (!kms) {
        out('keys:rotate needs a KMS (KEY_PROVIDER=gcp-kms). With KEY_PROVIDER=env, rotate by changing MASTER_KEY and PREVIOUS_MASTER_KEYS.');
        return 2;
      }
      await initKeyring({ config, prisma, kms, log }); // checks the current keys first
      const created = await createManagedKeys(config, prisma, kms, ['kek', 'link_token'], { retireCurrent: true });
      out(`Created key-encryption key v${created.kek} and link-token key v${created.link_token}; the previous ones are retired and still readable.`);
      // Running servers switch to the new key at their next check. Waiting lets the rewrap
      // below also cover documents they upload in the meantime.
      const wait = waitSeconds ?? config.env.KEY_REFRESH_SECONDS + 5;
      if (wait > 0) {
        out(`Waiting ${wait} s for running servers to pick up the new keys (KEY_REFRESH_SECONDS=${config.env.KEY_REFRESH_SECONDS})...`);
        await sleep(wait * 1000);
      }
    }

    // rewrap, and the second half of rotate: load the keys as the app would, from a fresh
    // config so a key created above becomes current.
    const fresh: AppConfig = command === 'rotate' ? loadConfig(env) : config;
    await initKeyring({ config: fresh, prisma, kms, log });
    const code = reportRewrap(await rewrapAll({ config: fresh, prisma }, { batchSize, onProgress: out }), out);
    if (code !== 0) {
      out('Not everything is on the current keys yet (e.g. a server used the old key just before switching). Run keys:rewrap again.');
    }
    return code;
  } finally {
    if (!deps.prisma) await prisma.$disconnect();
  }
}

function reportRewrap(report: RewrapReport, out: (line: string) => void): number {
  out(JSON.stringify(report, null, 2));
  if (report.linkTokens.unreadable.length > 0) {
    out(`${report.linkTokens.unreadable.length} link copies could not be read with any configured key: keep the old keys until this is resolved.`);
  }
  return rewrapSucceeded(report) ? 0 : 1;
}

// Run when executed directly (not when imported by tests or by rewrap-keys).
const invokedDirectly = process.argv[1] && /(^|[\\/])keys(\.[cm]?[jt]s)?$/.test(process.argv[1]);
if (invokedDirectly) {
  runKeysCli(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exit(1);
    });
}

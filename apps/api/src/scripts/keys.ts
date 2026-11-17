/**
 * Key management commands (never print key material):
 *
 *   pnpm keys:status                 provider, key versions, documents per version
 *   pnpm keys:rewrap [--dry-run]     move every data key and link token to the current keys
 *   pnpm keys:rotate [--dry-run]     create a new KMS-protected KEK and link-token key, then rewrap
 *
 * Options: --batch=<n> (default 100). Exit code 1 if anything failed or did not verify.
 */
import { PrismaClient } from '@prisma/client';
import { loadConfig } from '../config';
import { createManagedKey, initKeyring, keyringStatus } from '../lib/keyring';
import { createKmsProvider } from '../lib/kms';
import { rewrapAll } from '../services/key-rotation';

const log = {
  info: (obj: object, msg: string) => console.log(msg, JSON.stringify(obj)),
  warn: (obj: object, msg: string) => console.warn(`WARNING: ${msg}`, JSON.stringify(obj)),
};

export async function runKeysCli(argv: string[]): Promise<number> {
  const [command = 'status', ...rest] = argv;
  const dryRun = rest.includes('--dry-run');
  const batchArg = rest.find((a) => a.startsWith('--batch='));
  const batchSize = batchArg ? Number(batchArg.slice('--batch='.length)) : 100;
  if (!['status', 'rewrap', 'rotate'].includes(command) || !Number.isInteger(batchSize) || batchSize < 1) {
    console.error('Usage: keys <status|rewrap|rotate> [--dry-run] [--batch=<n>]');
    return 2;
  }

  const config = loadConfig();
  const prisma = new PrismaClient();
  try {
    const kms = createKmsProvider(config);
    if (command === 'rotate') {
      if (!kms) {
        console.error('keys:rotate needs a KMS (KEY_PROVIDER=gcp-kms). With KEY_PROVIDER=env, rotate by changing MASTER_KEY and PREVIOUS_MASTER_KEYS.');
        return 2;
      }
      if (dryRun) {
        console.log('Dry run: a new key-encryption key and link-token key would be created, then every key re-wrapped.');
      } else {
        await initKeyring({ config, prisma, kms, log }); // checks the current keys first
        const kek = await createManagedKey(config, prisma, kms, 'kek', { retireCurrent: true });
        const link = await createManagedKey(config, prisma, kms, 'link_token', { retireCurrent: true });
        console.log(`Created key-encryption key v${kek} and link-token key v${link}`);
      }
    }

    // Load the keys as the app would (a fresh config, so a key created above becomes current).
    const fresh = command === 'rotate' && !dryRun ? loadConfig() : config;
    await initKeyring({ config: fresh, prisma, kms, log, createIfMissing: command !== 'status' });

    if (command === 'status') {
      console.log(JSON.stringify(await keyringStatus(fresh, prisma), null, 2));
      return 0;
    }

    const report = await rewrapAll({ config: fresh, prisma }, { dryRun, batchSize, onProgress: (m) => console.log(m) });
    console.log(JSON.stringify(report, null, 2));
    const ok =
      report.dataKeys.failed.length === 0 &&
      report.verification.allOpen &&
      (dryRun || report.verification.allOnTarget);
    if (!ok) console.error('Re-wrap did not complete cleanly: see "failed" and "verification" above.');
    if (report.linkTokens.unreadable.length > 0) {
      console.warn(`${report.linkTokens.unreadable.length} link token copies could not be read; those links still work, but "Copy link" is unavailable for them.`);
    }
    return ok ? 0 : 1;
  } finally {
    await prisma.$disconnect();
  }
}

// Run when executed directly (not when imported by tests).
const invokedDirectly = process.argv[1] && /(^|[\\/])keys(\.[cm]?[jt]s)?$/.test(process.argv[1]);
if (invokedDirectly) {
  runKeysCli(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exit(1);
    });
}

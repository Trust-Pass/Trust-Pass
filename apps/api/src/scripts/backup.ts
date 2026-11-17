/**
 * Backup support commands. Read-only; they never print secrets or document contents.
 *
 * In the production image:  node apps/api/dist/backup.js <command>
 * In development:           pnpm backup:<command>
 *
 *   manifest --out <file>      describe the database about to be backed up (run it right
 *                              BEFORE the database dump): counts, key versions, one
 *                              fingerprint per encrypted file, key check values
 *   verify [--manifest <file>] restore drill against DATABASE_URL: decrypt every file,
 *                              field, credential and link copy, and compare with the manifest
 *
 * Both run inside a READ ONLY database transaction. Exit 0 = OK, 1 = problems found, 2 = usage.
 * See docs/recovery.md for the full backup and restore procedure.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { PrismaClient } from '@prisma/client';
import { loadConfig } from '../config';
import { initKeyring } from '../lib/keyring';
import { createKmsProvider } from '../lib/kms';
import { createStorage } from '../lib/storage';
import { checkSecrets, createManifest, parseManifest, verifyRestore } from '../services/backup';

export interface BackupCliDeps {
  env?: NodeJS.ProcessEnv;
  prisma?: PrismaClient;
  out?: (line: string) => void;
}

function option(rest: string[], name: string): string | null | undefined {
  const index = rest.indexOf(name);
  if (index === -1) return undefined;
  const value = rest[index + 1];
  return value && !value.startsWith('--') ? value : null;
}

export async function runBackupCli(argv: string[], deps: BackupCliDeps = {}): Promise<number> {
  const out = deps.out ?? ((line: string) => console.log(line));
  const [command, ...rest] = argv;
  const outFile = option(rest, '--out');
  const manifestFile = option(rest, '--manifest');
  const known = new Set(['--out', '--manifest', outFile, manifestFile].filter(Boolean) as string[]);
  if (
    (command !== 'manifest' && command !== 'verify') ||
    rest.some((a) => !known.has(a)) ||
    (command === 'manifest' && !outFile) ||
    (command === 'manifest' && manifestFile !== undefined) ||
    (command === 'verify' && (outFile !== undefined || manifestFile === null))
  ) {
    out('Usage: backup manifest --out <file> | backup verify [--manifest <file>]');
    return 2;
  }

  const config = loadConfig(deps.env ?? process.env);
  const manifest = manifestFile ? parseManifest(readFileSync(manifestFile, 'utf8')) : undefined;
  if (manifest) {
    // Checked before touching any data, so a wrong secret gets a clear message.
    const problems = checkSecrets(config, manifest);
    if (problems.length > 0) {
      for (const p of problems) out(`SECRET MISMATCH: ${p}`);
      return 1;
    }
  }

  const prisma = deps.prisma ?? new PrismaClient();
  const log = { info: (_o: object, msg: string) => out(msg), warn: (_o: object, msg: string) => out(`WARNING: ${msg}`) };
  try {
    const kms = createKmsProvider(config);
    const storage = createStorage(config, prisma);
    return await prisma.$transaction(
      async (tx) => {
        await tx.$executeRawUnsafe('SET TRANSACTION READ ONLY');
        await initKeyring({ config, prisma: tx, kms, log, createIfMissing: false, allowMissing: command === 'manifest' });
        if (command === 'manifest') {
          const created = await createManifest({ config, prisma: tx, storage });
          writeFileSync(outFile!, `${JSON.stringify(created, null, 2)}\n`, { mode: 0o600 });
          out(`Manifest written: ${created.counts.documents} documents, key versions ${created.keys.kekVersionsInUse.map((v) => `v${v.version} (${v.source})`).join(', ') || 'none'}`);
          return 0;
        }
        const report = await verifyRestore({ config, prisma: tx, storage, manifest });
        out(JSON.stringify(report, null, 2));
        out(report.ok ? 'RESTORE OK: every document, field, credential and link copy decrypts.' : 'RESTORE NOT OK: see the report above.');
        return report.ok ? 0 : 1;
      },
      { timeout: 30 * 60_000, maxWait: 30_000 },
    );
  } finally {
    if (!deps.prisma) await prisma.$disconnect();
  }
}

const invokedDirectly = process.argv[1] && /(^|[\\/])backup(\.[cm]?[jt]s)?$/.test(process.argv[1]);
if (invokedDirectly) {
  runBackupCli(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exit(1);
    });
}

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../../src/app';
import { loadOrCreateFakeKmsKey } from '../../src/lib/kms/fake';
import { runBackupCli } from '../../src/scripts/backup';
import { parseManifest, type RestoreReport } from '../../src/services/backup';
import { TEST_DATABASE_URL } from '../env';
import {
  as,
  cliEnv,
  createLink,
  createTestContext,
  documentClaims,
  fingerprint,
  IPS,
  issueCredential,
  registerUser,
  resetDatabase,
  resetKeyring,
  TEST_KMS_KEY_FILE,
  TEST_SECRETS,
  testConfig,
  testPrisma,
  uploadDocument,
  type Session,
  type TestContext,
} from '../helpers';

/**
 * Backup and restore drill, end to end, with the real PostgreSQL tools:
 * data under a legacy key AND a KMS-protected key → manifest → pg_dump → pg_restore into a
 * brand-new database → restore drill → the app on the restored database serves every
 * document, field, credential and link. Plus: wrong or missing secrets, and damaged restores.
 */
const RESTORE_DB = 'trustpass_restore_test';
const restoreUrl = (() => {
  const url = new URL(TEST_DATABASE_URL);
  url.pathname = `/${RESTORE_DB}`;
  return url.toString();
})();
const work = mkdtempSync(path.join(tmpdir(), 'trustpass-backup-'));
const LEGACY = { KEY_PROVIDER: 'env', MASTER_KEY: TEST_SECRETS.MASTER_KEY };
const WITH_LEGACY = { MASTER_KEY: TEST_SECRETS.MASTER_KEY };

let serverMajor = 16;

/**
 * Runs pg_dump / pg_restore with the same major version as the server (a newer pg_restore
 * can write settings an older server rejects): the local tools when they match, otherwise
 * the official postgres image. The password goes in PGPASSWORD, never on the command line.
 */
function pgTool(tool: 'pg_dump' | 'pg_restore', args: string[]) {
  const url = new URL(TEST_DATABASE_URL);
  const env = { ...process.env, PGPASSWORD: decodeURIComponent(url.password) };
  const conn = ['-h', url.hostname, '-p', url.port || '5432', '-U', decodeURIComponent(url.username)];
  let localMajor = 0;
  try {
    localMajor = Number(/(\d+)\./.exec(execFileSync(tool, ['--version'], { stdio: 'pipe' }).toString())?.[1] ?? 0);
  } catch {
    /* not installed */
  }
  if (localMajor === serverMajor) return execFileSync(tool, [...conn, ...args], { env, stdio: 'pipe' });
  return execFileSync(
    'docker',
    ['run', '--rm', '--network', 'host', '-e', 'PGPASSWORD', '-v', `${work}:${work}`, `postgres:${serverMajor}`, tool, ...conn, ...args],
    { env, stdio: 'pipe' },
  );
}

async function backupCli(argv: string[], options: { db?: 'live' | 'restored'; env?: Record<string, string> } = {}) {
  const lines: string[] = [];
  const restored = options.db === 'restored';
  const code = await runBackupCli(argv, {
    env: cliEnv({ ...(restored ? { DATABASE_URL: restoreUrl } : {}), ...(options.env ?? WITH_LEGACY) }),
    prisma: restored ? restorePrisma : testPrisma(),
    out: (l) => lines.push(l),
  });
  const json = lines.find((l) => l.startsWith('{'));
  return { code, output: lines.join('\n'), report: json ? (JSON.parse(json) as RestoreReport) : null };
}

let restorePrisma: PrismaClient;
const apps: Array<{ close(): Promise<unknown> }> = [];
let owner: Session;
const ids: Record<'legacyFile' | 'credential' | 'kmsFile' | 'deletedBefore' | 'deletedAfter' | 'createdAfter', string> = {} as never;
const originals = new Map<string, Buffer>();
let credentialLink: { token: string };
let fileLink: { token: string };
const manifestFile = path.join(work, 'manifest.json');
const dumpFile = path.join(work, 'trustpass.dump');

async function onRestored(overrides: Record<string, string | undefined> = {}): Promise<TestContext> {
  const config = testConfig({
    DATABASE_URL: restoreUrl,
    KEY_PROVIDER: 'fake-kms',
    FAKE_KMS_KEY_FILE: TEST_KMS_KEY_FILE,
    STORAGE_DRIVER: 'database',
    ...WITH_LEGACY,
    ...overrides,
  });
  const app = await buildApp({ config, prisma: restorePrisma, logger: false });
  apps.push(app);
  return { app, prisma: restorePrisma, config, clock: { now: new Date(), advance() {} }, mail: [] } as unknown as TestContext;
}

async function fileOf(ctx: TestContext, id: string) {
  return as(ctx, owner, { method: 'GET', url: `/api/documents/${id}/file` });
}

beforeAll(async () => {
  const [version] = await testPrisma().$queryRawUnsafe<Array<{ server_version_num: string }>>('SHOW server_version_num');
  serverMajor = Math.floor(Number(version!.server_version_num) / 10000);
  await resetDatabase(testPrisma());
  await resetKeyring(testPrisma());
  await testPrisma().$executeRawUnsafe(`DROP DATABASE IF EXISTS "${RESTORE_DB}" WITH (FORCE)`);
  restorePrisma = new PrismaClient({ datasources: { db: { url: restoreUrl } } });

  // 1. Data under the legacy MASTER_KEY (as production has today).
  const legacy = await createTestContext({ STORAGE_DRIVER: 'database', ...LEGACY });
  apps.push(legacy.app);
  owner = await registerUser(legacy);
  ids.legacyFile = (await uploadDocument(legacy, owner, { claims: [{ label: 'Employer', value: 'Example Co' }] })).json().document.id;
  ids.credential = await issueCredential(legacy, owner);
  const status = (await documentClaims(legacy, owner, ids.credential)).find((c) => c.key === 'enrollment_status')!;
  credentialLink = await createLink(legacy, owner, ids.credential, { claimIds: [status.id] });
  ids.deletedBefore = (await uploadDocument(legacy, owner)).json().document.id;
  expect((await as(legacy, owner, { method: 'DELETE', url: `/api/documents/${ids.deletedBefore}` })).statusCode).toBe(200);

  // 2. Data under a KMS-protected key (after the planned switch), with MASTER_KEY kept for the old data.
  const kms = await createTestContext({ STORAGE_DRIVER: 'database', ...WITH_LEGACY });
  apps.push(kms.app);
  ids.kmsFile = (await uploadDocument(kms, owner)).json().document.id;
  fileLink = await createLink(kms, owner, ids.kmsFile, { includeFile: true });
  ids.deletedAfter = (await uploadDocument(kms, owner)).json().document.id;
  for (const id of [ids.legacyFile, ids.credential, ids.kmsFile, ids.deletedAfter]) {
    originals.set(id, (await as(kms, owner, { method: 'GET', url: `/api/documents/${id}/file` })).rawPayload);
  }

  // 3. Backup: manifest first, then the dump.
  const manifest = await backupCli(['manifest', '--out', manifestFile]);
  expect(manifest.code, manifest.output).toBe(0);
  pgTool('pg_dump', ['--format=custom', '--file', dumpFile, '--dbname', new URL(TEST_DATABASE_URL).pathname.slice(1)]);

  // 4. Life goes on after the backup.
  expect((await as(kms, owner, { method: 'DELETE', url: `/api/documents/${ids.deletedAfter}` })).statusCode).toBe(200);
  ids.createdAfter = (await uploadDocument(kms, owner)).json().document.id;

  // 5. Restore into a brand-new, empty database.
  await testPrisma().$executeRawUnsafe(`CREATE DATABASE "${RESTORE_DB}"`);
  pgTool('pg_restore', ['--no-owner', '--no-privileges', '--exit-on-error', '--dbname', RESTORE_DB, dumpFile]);
}, 180_000);

afterAll(async () => {
  while (apps.length) await apps.pop()!.close();
  await restorePrisma?.$disconnect();
  await testPrisma().$executeRawUnsafe(`DROP DATABASE IF EXISTS "${RESTORE_DB}" WITH (FORCE)`);
  await resetDatabase(testPrisma());
  await resetKeyring(testPrisma());
});

describe('the backup manifest', () => {
  it('describes what a restore needs, without any secret or document content', () => {
    const text = readFileSync(manifestFile, 'utf8');
    const manifest = parseManifest(text);
    expect(manifest.counts).toMatchObject({ documents: 4, deletedDocuments: 1, documentKeys: 4, storedObjects: 4 });
    expect(manifest.keys.kekVersionsInUse.map((v) => [v.version, v.source])).toEqual([
      [1, 'legacy'],
      [2, 'kms'],
    ]);
    expect(manifest.keys.legacyKeyChecks.map((k) => k.version)).toEqual([1]);
    expect(manifest.keys.storedKeys.map((k) => [k.purpose, k.version, k.status])).toEqual([
      ['kek', 2, 'active'],
      ['link_token', 3, 'active'],
    ]);
    expect(manifest.documents.map((d) => d.id).sort()).toEqual([ids.legacyFile, ids.credential, ids.kmsFile, ids.deletedAfter].sort());
    expect(manifest.migrations).toContain('20261117160000_key_encryption_keys');

    const config = testConfig({ KEY_PROVIDER: 'env', ...WITH_LEGACY });
    const secrets = [
      TEST_SECRETS.MASTER_KEY,
      TEST_SECRETS.IP_HASH_SECRET,
      TEST_SECRETS.ISSUER_SIGNING_SEED,
      ...[config.masterKeys.current.key, config.issuerSeed, config.ipHashKey, loadOrCreateFakeKmsKey(TEST_KMS_KEY_FILE)].flatMap((k) => [
        k.toString('hex'),
        k.toString('base64'),
      ]),
    ];
    for (const secret of secrets) expect(text).not.toContain(secret);
    for (const original of originals.values()) expect(text).not.toContain(original.toString('base64').slice(0, 40));
  });
});

describe('restoring into a new database', () => {
  it('passes the restore drill: every file, field, credential and link copy decrypts and matches the manifest, and nothing is written', async () => {
    const before = await fingerprint(restorePrisma);
    const drill = await backupCli(['verify', '--manifest', manifestFile], { db: 'restored' });
    expect(drill.code, drill.output).toBe(0);
    expect(drill.report).toMatchObject({
      ok: true,
      secretProblems: [],
      documents: { checked: 4, failed: [] },
      claims: { failed: [] },
      credentials: { checked: 1, failed: [] },
      linkCopies: { checked: 2, unreadable: [] },
      manifest: { missing: [], changed: [], extra: 0, migrationsMissing: [] },
    });
    expect(drill.report!.claims.checked).toBeGreaterThanOrEqual(7);
    expect(await fingerprint(restorePrisma)).toBe(before);
  });

  it('the app on the restored database serves every document byte for byte, with fields, credential and links', async () => {
    const restored = await onRestored();
    for (const id of [ids.legacyFile, ids.credential, ids.kmsFile]) {
      const res = await fileOf(restored, id);
      expect(res.statusCode, id).toBe(200);
      expect(res.rawPayload.equals(originals.get(id)!)).toBe(true);
    }
    expect((await documentClaims(restored, owner, ids.legacyFile))[0]!.value).toBe('Example Co');
    const shared = await restored.app.inject({ method: 'GET', url: `/api/share/${credentialLink.token}`, remoteAddress: IPS.SA });
    expect(shared.statusCode).toBe(200);
    expect(shared.json().verification.result).toBe('verified');
    expect(shared.json().fields).toEqual([{ label: 'Enrollment status', value: 'Active', source: 'issuer' }]);
    expect((await restored.app.inject({ method: 'GET', url: `/api/share/${fileLink.token}/file`, remoteAddress: IPS.SA })).statusCode).toBe(200);
  });

  it('restores the state at backup time: deleted before stays gone, created after is absent, deleted after comes back', async () => {
    const restored = await onRestored();
    expect((await fileOf(restored, ids.deletedBefore)).statusCode).toBe(404);
    expect((await fileOf(restored, ids.createdAfter)).statusCode).toBe(404);
    // Known limit (docs/recovery.md): a document deleted after a backup is readable again
    // from that backup, as long as its keys are still configured.
    const back = await fileOf(restored, ids.deletedAfter);
    expect(back.statusCode).toBe(200);
    expect(back.rawPayload.equals(originals.get(ids.deletedAfter)!)).toBe(true);
  });

  it('the restore drill on the live database reports what changed since the backup', async () => {
    const live = await backupCli(['verify', '--manifest', manifestFile]);
    expect(live.code).toBe(1);
    expect(live.report!.manifest).toMatchObject({ missing: [ids.deletedAfter], changed: [], extra: 1 });
  });
});

describe('restoring with wrong or missing secrets', () => {
  it('names the secret that does not match, before decrypting anything', async () => {
    const wrongKey = await backupCli(['verify', '--manifest', manifestFile], {
      db: 'restored',
      env: { MASTER_KEY: 'a-completely-different-master-key-0123456789-abcdefgh' },
    });
    expect(wrongKey.code).toBe(1);
    expect(wrongKey.output).toMatch(/SECRET MISMATCH: legacy master key v1 does not match/);

    const noKey = await backupCli(['verify', '--manifest', manifestFile], { db: 'restored', env: {} });
    expect(noKey.code).toBe(1);
    expect(noKey.output).toMatch(/legacy master key v1 is needed .* but not configured/);

    const wrongSeed = await backupCli(['verify', '--manifest', manifestFile], {
      db: 'restored',
      env: { ...WITH_LEGACY, ISSUER_SIGNING_SEED: 'another-issuer-seed-0123456789-abcdefghijklmn' },
    });
    expect(wrongSeed.code).toBe(1);
    expect(wrongSeed.output).toMatch(/ISSUER_SIGNING_SEED differs/);
    for (const run of [wrongKey, noKey, wrongSeed]) expect(run.output).not.toContain(TEST_SECRETS.MASTER_KEY);
  });

  it('refuses a KMS that cannot decrypt the restored keys, and an app without the legacy key', async () => {
    const otherKms = path.join(mkdtempSync(path.join(tmpdir(), 'trustpass-other-kms-')), 'root.key');
    await expect(backupCli(['verify'], { db: 'restored', env: { ...WITH_LEGACY, FAKE_KMS_KEY_FILE: otherKms } })).rejects.toThrow(/Could not decrypt/);
    await expect(onRestored({ MASTER_KEY: undefined })).rejects.toThrow(/version 1, which is not configured/);
  });
});

describe('the restore drill detects a damaged or incomplete restore', () => {
  it('reports a changed and a missing encrypted file by document id', async () => {
    const legacy = await restorePrisma.document.findUniqueOrThrow({ where: { id: ids.legacyFile } });
    const kms = await restorePrisma.document.findUniqueOrThrow({ where: { id: ids.kmsFile } });
    const object = await restorePrisma.storedObject.findUniqueOrThrow({ where: { key: legacy.storageKey } });
    const damaged = Buffer.from(object.data);
    damaged[10]! ^= 1;
    await restorePrisma.storedObject.update({ where: { key: legacy.storageKey }, data: { data: new Uint8Array(damaged) } });
    await restorePrisma.storedObject.delete({ where: { key: kms.storageKey } });

    const drill = await backupCli(['verify', '--manifest', manifestFile], { db: 'restored' });
    expect(drill.code).toBe(1);
    expect(drill.report!.ok).toBe(false);
    expect(drill.report!.documents.failed).toEqual(
      expect.arrayContaining([
        { id: ids.legacyFile, stage: 'decrypt' },
        { id: ids.kmsFile, stage: 'storage' },
      ]),
    );
    expect(drill.report!.manifest!.changed).toEqual([ids.legacyFile]);
    expect(drill.output).toMatch(/RESTORE NOT OK/);
  });

  it('rejects bad usage instead of guessing', async () => {
    expect((await backupCli(['manifest'])).code).toBe(2);
    expect((await backupCli(['verify', '--manifest'])).code).toBe(2);
    expect((await backupCli(['restore'])).code).toBe(2);
  });
});

import { Writable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildApp } from '../../src/app';
import { createManagedKey } from '../../src/lib/keyring';
import { FakeKms } from '../../src/lib/kms/fake';
import { runKeysCli } from '../../src/scripts/keys';
import { destroyRetiredKeys, rewrapAll, rewrapSucceeded } from '../../src/services/key-rotation';
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
 * E2 and the fixes from its independent review (A, B, C, E, F, H). Every test starts from
 * an empty keyring and empty data, and cleans up, so other test files keep starting from
 * a fresh key.
 */
const running: TestContext[] = [];
// Database storage (as in production), so every instance sees the same encrypted files.
async function start(overrides: Record<string, string | undefined> = {}) {
  const ctx = await createTestContext({ STORAGE_DRIVER: 'database', ...overrides });
  running.push(ctx);
  return ctx;
}
const LEGACY = { KEY_PROVIDER: 'env', MASTER_KEY: TEST_SECRETS.MASTER_KEY };

async function keysCli(argv: string[], extra: Record<string, string> = {}) {
  const lines: string[] = [];
  const code = await runKeysCli(argv, { env: cliEnv(extra), prisma: testPrisma(), out: (l) => lines.push(l), sleep: async () => {} });
  return { code, output: lines.join('\n') };
}

async function fileOf(ctx: TestContext, session: Session, id: string) {
  const res = await as(ctx, session, { method: 'GET', url: `/api/documents/${id}/file` });
  expect(res.statusCode, res.body).toBe(200);
  return res.rawPayload;
}

async function linkIdFor(token: string) {
  const { hashToken } = await import('../../src/lib/crypto');
  return (await testPrisma().sharingLink.findFirstOrThrow({ where: { tokenHash: hashToken(token) } })).id;
}

async function activeKek() {
  return (await testPrisma().keyEncryptionKey.findFirstOrThrow({ where: { purpose: 'kek', status: 'active' } })).version;
}

async function kekVersionOf(documentId: string) {
  return (await testPrisma().documentKey.findUniqueOrThrow({ where: { documentId } })).kekVersion;
}

beforeEach(async () => {
  await resetDatabase(testPrisma());
  await resetKeyring(testPrisma());
});
afterEach(async () => {
  while (running.length) await running.pop()!.app.close();
  await resetDatabase(testPrisma());
  await resetKeyring(testPrisma());
});

describe('key-encryption keys protected by a KMS', () => {
  it('creates a random KEK and link-token key on first start, with distinct versions, stored only KMS-encrypted', async () => {
    const ctx = await start();
    const rows = await ctx.prisma.keyEncryptionKey.findMany({ orderBy: { version: 'asc' } });
    expect(rows.map((r) => [r.purpose, r.version, r.status, r.provider])).toEqual([
      ['kek', 1, 'active', 'fake-kms'],
      ['link_token', 2, 'active', 'fake-kms'],
    ]);
    const kek = ctx.config.masterKeys.current.key;
    for (const row of rows) {
      expect(Buffer.from(row.encryptedKey).includes(kek)).toBe(false);
      expect(Buffer.from(row.encryptedKey).includes(ctx.config.linkTokenKeys.current.key)).toBe(false);
    }
    expect(kek.equals(ctx.config.linkTokenKeys.current.key)).toBe(false);

    const again = await start();
    expect(again.config.masterKeys.current.key.equals(kek)).toBe(true);
    expect(await ctx.prisma.keyEncryptionKey.count()).toBe(2);
  });

  it('two instances starting at the same time create exactly one key per purpose', async () => {
    const [a, b] = await Promise.all([start(), start()]);
    expect(await a.prisma.keyEncryptionKey.count({ where: { purpose: 'kek' } })).toBe(1);
    expect(await a.prisma.keyEncryptionKey.count({ where: { purpose: 'link_token' } })).toBe(1);
    expect(a.config.masterKeys.current.key.equals(b.config.masterKeys.current.key)).toBe(true);
  });

  it('seals link tokens with the link-token key, not the KEK', async () => {
    const ctx = await start();
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id as string;
    const link = await createLink(ctx, owner, id, { includeFile: true });
    const linkId = await linkIdFor(link.token);
    const { open: openSealed, linkTokenAad } = await import('../../src/lib/crypto');
    const stored = (await ctx.prisma.sharingLink.findUniqueOrThrow({ where: { id: linkId } })).tokenEncrypted;
    expect(openSealed(ctx.config.linkTokenKeys.current.key, stored, linkTokenAad(linkId)).toString()).toBe(link.token);
    expect(() => openSealed(ctx.config.masterKeys.current.key, stored, linkTokenAad(linkId))).toThrow();
  });
});

describe('fix B: versions never clash, and start-up checks before writing', () => {
  it('refuses, without creating any key, when legacy documents need MASTER_KEY; then starts cleanly once it is added', async () => {
    const legacy = await start(LEGACY);
    const owner = await registerUser(legacy);
    const id = (await uploadDocument(legacy, owner)).json().document.id as string;
    const original = await fileOf(legacy, owner, id);

    await expect(start()).rejects.toThrow(/version 1, which is not configured/);
    expect(await testPrisma().keyEncryptionKey.count()).toBe(0); // nothing written

    const both = await start({ MASTER_KEY: TEST_SECRETS.MASTER_KEY });
    const rows = await both.prisma.keyEncryptionKey.findMany({ orderBy: { version: 'asc' } });
    expect(rows.map((r) => [r.purpose, r.version])).toEqual([
      ['kek', 2],
      ['link_token', 3],
    ]);
    expect((await fileOf(both, owner, id)).equals(original)).toBe(true);
    await start({ MASTER_KEY: TEST_SECRETS.MASTER_KEY }); // and it keeps starting
  });

  it('refuses a stored key whose version equals a legacy master key version', async () => {
    await start(); // kek v1, link_token v2
    await expect(start({ MASTER_KEY: TEST_SECRETS.MASTER_KEY, MASTER_KEY_VERSION: '2' })).rejects.toThrow(/clashes with a legacy master key/);
  });

  it('refuses when the KMS cannot decrypt the active key', async () => {
    await start();
    const same = new FakeKms({ keyFile: TEST_KMS_KEY_FILE }).keyName;
    const other = Object.assign(new FakeKms({ key: Buffer.alloc(32, 7) }), { keyName: same });
    const config = testConfig({ KEY_PROVIDER: 'fake-kms', FAKE_KMS_KEY_FILE: TEST_KMS_KEY_FILE, MASTER_KEY: undefined });
    await expect(buildApp({ config, prisma: testPrisma(), kms: other, logger: false })).rejects.toThrow(/Could not decrypt the kek key v1/);
  });

  it('refuses keys protected by a different KMS key, before writing anything', async () => {
    await start();
    const before = await fingerprint(testPrisma());
    const config = testConfig({ KEY_PROVIDER: 'fake-kms', FAKE_KMS_KEY_FILE: TEST_KMS_KEY_FILE, MASTER_KEY: undefined });
    const renamed = Object.assign(new FakeKms({ keyFile: TEST_KMS_KEY_FILE }), { keyName: 'fake-kms/another-key' });
    await expect(buildApp({ config, prisma: testPrisma(), kms: renamed, logger: false })).rejects.toThrow(/different KMS key/);
    expect(await fingerprint(testPrisma())).toBe(before);
  });
});

describe('migrating from the legacy MASTER_KEY to KMS-protected keys', () => {
  it('a link sealed the way production does today (with the KEK itself) keeps working, and the re-wrap moves it to the link-token key', async () => {
    const legacy = await start(LEGACY);
    const owner = await registerUser(legacy);
    const docId = (await uploadDocument(legacy, owner)).json().document.id as string;
    const link = await createLink(legacy, owner, docId, { recipientLabel: 'HR' });
    const linkId = await linkIdFor(link.token);
    // Re-create the pre-E2 row: token sealed with the key-encryption key derived from MASTER_KEY ("kek:v1").
    const { linkTokenAad, seal: sealWith, open: openWith } = await import('../../src/lib/crypto');
    const kek = legacy.config.masterKeys.current.key;
    await legacy.prisma.sharingLink.update({ where: { id: linkId }, data: { tokenEncrypted: sealWith(kek, Buffer.from(link.token), linkTokenAad(linkId)) } });

    const app = await start({ MASTER_KEY: TEST_SECRETS.MASTER_KEY });
    expect((await as(app, owner, { method: 'GET', url: `/api/links/${linkId}/url` })).json().url).toContain(link.token);
    expect((await app.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA })).statusCode).toBe(200);

    const real = await keysCli(['rewrap'], { MASTER_KEY: TEST_SECRETS.MASTER_KEY });
    expect(real.code, real.output).toBe(0);
    const row = await app.prisma.sharingLink.findUniqueOrThrow({ where: { id: linkId } });
    expect(() => openWith(kek, row.tokenEncrypted, linkTokenAad(linkId))).toThrow(); // no longer under the KEK
    const kmsOnly = await start();
    expect((await as(kmsOnly, owner, { method: 'GET', url: `/api/links/${linkId}/url` })).json().url).toContain(link.token);
  });

  it('keeps every old document, field, credential and link working through the switch, the re-wrap and the removal of MASTER_KEY', async () => {
    const legacy = await start(LEGACY);
    const owner = await registerUser(legacy);
    const fileId = (await uploadDocument(legacy, owner, { claims: [{ label: 'Employer', value: 'Example Co' }] })).json().document.id as string;
    const credId = await issueCredential(legacy, owner);
    const status = (await documentClaims(legacy, owner, credId)).find((c) => c.key === 'enrollment_status')!;
    const oldLink = await createLink(legacy, owner, credId, { claimIds: [status.id] });
    const original = await fileOf(legacy, owner, fileId);

    const both = await start({ MASTER_KEY: TEST_SECRETS.MASTER_KEY });
    const kekVersion = both.config.masterKeys.current.version;
    expect((await fileOf(both, owner, fileId)).equals(original)).toBe(true);
    const oldLinkId = await linkIdFor(oldLink.token);
    expect((await as(both, owner, { method: 'GET', url: `/api/links/${oldLinkId}/url` })).json().url).toContain(oldLink.token);

    // Dry run through the real command: exit 0, and not a single byte changes.
    const before = await fingerprint(both.prisma);
    const dry = await keysCli(['rewrap', '--dry-run'], { MASTER_KEY: TEST_SECRETS.MASTER_KEY });
    expect(dry.code, dry.output).toBe(0);
    expect(await fingerprint(both.prisma)).toBe(before);

    // Real rewrap (batches of 1). File ciphertext is not touched.
    const objectsBefore = await both.prisma.document.findMany({ select: { id: true, encIv: true, encTag: true }, orderBy: { id: 'asc' } });
    const real = await keysCli(['rewrap', '--batch=1'], { MASTER_KEY: TEST_SECRETS.MASTER_KEY });
    expect(real.code, real.output).toBe(0);
    expect(await both.prisma.documentKey.count({ where: { kekVersion: { not: kekVersion } } })).toBe(0);
    expect(await both.prisma.document.findMany({ select: { id: true, encIv: true, encTag: true }, orderBy: { id: 'asc' } })).toEqual(objectsBefore);
    expect((await keysCli(['rewrap'], { MASTER_KEY: TEST_SECRETS.MASTER_KEY })).code).toBe(0); // idempotent

    // MASTER_KEY removed: KMS only.
    const kmsOnly = await start();
    expect(kmsOnly.config.legacyKekVersions).toEqual([]);
    expect((await fileOf(kmsOnly, owner, fileId)).equals(original)).toBe(true);
    expect((await documentClaims(kmsOnly, owner, fileId))[0]!.value).toBe('Example Co');
    expect((await as(kmsOnly, owner, { method: 'GET', url: `/api/links/${oldLinkId}/url` })).json().url).toContain(oldLink.token);
    const shared = await kmsOnly.app.inject({ method: 'GET', url: `/api/share/${oldLink.token}`, remoteAddress: IPS.SA });
    expect(shared.statusCode).toBe(200);
    expect(shared.json().verification.result).toBe('verified');
    expect(shared.json().fields).toEqual([{ label: 'Enrollment status', value: 'Active', source: 'issuer' }]);
  });
});

describe('fix A: rotation while an old server is still running', () => {
  it('the old server keeps serving every document and link without a restart, and moves to the new key', async () => {
    const old = await start(); // default KEY_REFRESH_SECONDS=30
    const owner = await registerUser(old);
    const id = (await uploadDocument(old, owner, { claims: [{ label: 'Employer', value: 'Example Co' }] })).json().document.id as string;
    const link = await createLink(old, owner, id, { includeFile: true });
    const linkId = await linkIdFor(link.token);
    const original = await fileOf(old, owner, id);
    const oldVersion = old.config.masterKeys.current.version;

    const rotate = await keysCli(['rotate', '--wait=0']);
    expect(rotate.code, rotate.output).toBe(0);
    const newVersion = await activeKek();
    expect(newVersion).not.toBe(oldVersion);
    expect(await kekVersionOf(id)).toBe(newVersion);

    // The old server has never seen the new key: it reloads on first use.
    expect((await fileOf(old, owner, id)).equals(original)).toBe(true);
    expect((await documentClaims(old, owner, id))[0]!.value).toBe('Example Co');
    expect((await as(old, owner, { method: 'GET', url: `/api/links/${linkId}/url` })).json().url).toContain(link.token);
    const shared = await old.app.inject({ method: 'GET', url: `/api/share/${link.token}/file`, remoteAddress: IPS.SA });
    expect(shared.statusCode).toBe(200);
    expect(old.config.masterKeys.current.version).toBe(newVersion);

    // New uploads on the old server now use the new key.
    const next = (await uploadDocument(old, owner)).json().document.id as string;
    expect(await kekVersionOf(next)).toBe(newVersion);
  });

  it('an old server that read nothing switches to the new keys before its next upload and link', async () => {
    const old = await start({ KEY_REFRESH_SECONDS: '0' });
    const owner = await registerUser(old);
    expect((await keysCli(['rotate', '--wait=0'])).code).toBe(0);
    const id = (await uploadDocument(old, owner)).json().document.id as string;
    expect(await kekVersionOf(id)).toBe(await activeKek());
    const link = await createLink(old, owner, id, { includeFile: true });
    const { open: openSealed, linkTokenAad } = await import('../../src/lib/crypto');
    const fresh = await start();
    const linkId = await linkIdFor(link.token);
    const stored = (await testPrisma().sharingLink.findUniqueOrThrow({ where: { id: linkId } })).tokenEncrypted;
    expect(openSealed(fresh.config.linkTokenKeys.current.key, stored, linkTokenAad(linkId)).toString()).toBe(link.token);
  });

  it('an upload in the window before the old server checks uses the retired key: readable everywhere, and the next rewrap moves it', async () => {
    const old = await start(); // 30 s refresh: it has not checked yet
    const owner = await registerUser(old);
    expect((await keysCli(['rotate', '--wait=0'])).code).toBe(0);
    const id = (await uploadDocument(old, owner)).json().document.id as string;
    const retiredVersion = await kekVersionOf(id);
    expect((await testPrisma().keyEncryptionKey.findFirstOrThrow({ where: { purpose: 'kek', version: retiredVersion } })).status).toBe('retired');

    const other = await start();
    expect((await fileOf(other, owner, id)).length).toBeGreaterThan(0);
    const rewrap = await keysCli(['rewrap']);
    expect(rewrap.code, rewrap.output).toBe(0);
    expect(await kekVersionOf(id)).toBe(await activeKek());
  });
});

describe('fix C: retired keys and recovery', () => {
  async function insertUndecryptableRetiredKek(version: number) {
    await testPrisma().keyEncryptionKey.create({
      data: {
        purpose: 'kek',
        version,
        provider: 'fake-kms',
        kmsKeyName: new FakeKms({ keyFile: TEST_KMS_KEY_FILE }).keyName,
        encryptedKey: new Uint8Array(Buffer.concat([Buffer.from('FKMS1'), Buffer.alloc(60, 1)])),
        status: 'retired',
        retiredAt: new Date(),
      },
    });
  }

  it('skips a retired key the KMS can no longer decrypt when no document uses it', async () => {
    const ctx = await start();
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id as string;
    await insertUndecryptableRetiredKek(10);
    const after = await start();
    expect(after.config.masterKeys.all.has(10)).toBe(false);
    expect((await fileOf(after, owner, id)).length).toBeGreaterThan(0);
  });

  it('stops start-up when documents still need that retired key', async () => {
    const ctx = await start();
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id as string;
    await insertUndecryptableRetiredKek(10);
    await testPrisma().documentKey.update({ where: { documentId: id }, data: { kekVersion: 10 } });
    await expect(start()).rejects.toThrow(/retired kek key v10, which 1 document\(s\) still use/);
  });

  it('destroy-retired keeps keys that are still needed or retired too recently, and safely deletes the rest', async () => {
    const ctx = await start();
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id as string;
    const link = await createLink(ctx, owner, id, { includeFile: true });
    const original = await fileOf(ctx, owner, id);
    const kms = new FakeKms({ keyFile: TEST_KMS_KEY_FILE });
    await createManagedKey(ctx.config, ctx.prisma, kms, 'kek', { retireCurrent: true });
    await createManagedKey(ctx.config, ctx.prisma, kms, 'link_token', { retireCurrent: true });
    const later = new Date(Date.now() + 11 * 60_000);

    // Not re-wrapped yet: both retired keys are still needed.
    const rotated = await start();
    let report = await destroyRetiredKeys({ config: rotated.config, prisma: rotated.prisma }, { now: later });
    expect(report.destroyed).toBe(0);
    expect(report.kept.map((k) => k.reason)).toEqual([expect.stringMatching(/still use it/), expect.stringMatching(/link copies/)]);

    expect((await keysCli(['rewrap'])).code).toBe(0);
    const reloaded = await start();
    // Too recent: running servers may still be using them.
    report = await destroyRetiredKeys({ config: reloaded.config, prisma: reloaded.prisma });
    expect(report.destroyed).toBe(0);
    expect(report.kept.every((k) => /retired less than/.test(k.reason))).toBe(true);

    // The command refuses without --confirm, and its dry run writes nothing.
    expect((await keysCli(['destroy-retired'])).code).toBe(2);
    const before = await fingerprint(testPrisma());
    expect((await keysCli(['destroy-retired', '--dry-run'])).code).toBe(0);
    expect(await fingerprint(testPrisma())).toBe(before);

    report = await destroyRetiredKeys({ config: reloaded.config, prisma: reloaded.prisma }, { now: later });
    expect(report.destroyed).toBe(2);
    expect(await testPrisma().keyEncryptionKey.count({ where: { status: 'retired' } })).toBe(0);

    const afterDestroy = await start();
    expect((await fileOf(afterDestroy, owner, id)).equals(original)).toBe(true);
    const linkId = await linkIdFor(link.token);
    expect((await as(afterDestroy, owner, { method: 'GET', url: `/api/links/${linkId}/url` })).json().url).toContain(link.token);
  });

  it('reports documents it cannot open instead of skipping them silently', async () => {
    const ctx = await start();
    const owner = await registerUser(ctx);
    const damagedId = (await uploadDocument(ctx, owner)).json().document.id as string;
    const okId = (await uploadDocument(ctx, owner)).json().document.id as string;
    const v = await createManagedKey(ctx.config, ctx.prisma, new FakeKms({ keyFile: TEST_KMS_KEY_FILE }), 'kek', { retireCurrent: true });
    const rotated = await start();
    const row = await rotated.prisma.documentKey.findUniqueOrThrow({ where: { documentId: damagedId } });
    const damaged = Buffer.from(row.wrappedDek);
    damaged[0]! ^= 1;
    await rotated.prisma.documentKey.update({ where: { documentId: damagedId }, data: { wrappedDek: new Uint8Array(damaged) } });
    const report = await rewrapAll({ config: rotated.config, prisma: rotated.prisma });
    expect(report.dataKeys.failed).toEqual([damagedId]);
    expect(rewrapSucceeded(report)).toBe(false);
    expect(await kekVersionOf(okId)).toBe(v);
  });
});

describe('fix E: dry runs change nothing at all', () => {
  it('rewrap, rotate, destroy-retired and status dry runs leave every table identical, even before the first KMS key exists', async () => {
    const legacy = await start(LEGACY);
    const owner = await registerUser(legacy);
    const id = (await uploadDocument(legacy, owner)).json().document.id as string;
    await createLink(legacy, owner, id, { includeFile: true });
    const before = await fingerprint(testPrisma());

    const withLegacy = { MASTER_KEY: TEST_SECRETS.MASTER_KEY };
    for (const argv of [['rewrap', '--dry-run'], ['rotate', '--dry-run'], ['destroy-retired', '--dry-run'], ['status']]) {
      const run = await keysCli(argv, withLegacy);
      expect(run.code, `${argv.join(' ')}: ${run.output}`).toBe(0);
      expect(await fingerprint(testPrisma()), argv.join(' ')).toBe(before);
    }
    expect(await testPrisma().keyEncryptionKey.count()).toBe(0);
  });

  it('a dry run fails cleanly, and still writes nothing, when a key is wrong', async () => {
    const legacy = await start(LEGACY);
    const owner = await registerUser(legacy);
    await uploadDocument(legacy, owner);
    const before = await fingerprint(testPrisma());
    await expect(keysCli(['rewrap', '--dry-run'], { MASTER_KEY: 'a-completely-different-master-key-0123456789-abcdefgh' })).rejects.toThrow(
      /does not open the stored document keys/,
    );
    expect(await fingerprint(testPrisma())).toBe(before);
  });

  it('rejects unknown options instead of guessing', async () => {
    expect((await keysCli(['rewrap', '--dryrun'])).code).toBe(2);
    expect((await keysCli(['explode'])).code).toBe(2);
  });
});

describe('fix F: the fake KMS can never write to a production database', () => {
  it('production marks its database at start-up', async () => {
    await start({ ...LEGACY, NODE_ENV: 'production', APP_URL: 'https://trustpass.example', GEO_PROVIDER: 'mmdb', GEO_SIMULATED_MAP: undefined });
    expect((await testPrisma().systemSetting.findUniqueOrThrow({ where: { key: 'environment' } })).value).toBe('production');
  });

  it('the app and every key command refuse the fake KMS on a production database, before writing anything', async () => {
    await testPrisma().systemSetting.create({ data: { key: 'environment', value: 'production' } });
    const before = await fingerprint(testPrisma());
    await expect(start()).rejects.toThrow(/this database belongs to production/);
    for (const argv of [['rewrap'], ['rewrap', '--dry-run'], ['rotate', '--wait=0'], ['status']]) {
      await expect(keysCli(argv), argv.join(' ')).rejects.toThrow(/this database belongs to production/);
    }
    expect(await fingerprint(testPrisma())).toBe(before);
    expect(await testPrisma().keyEncryptionKey.count()).toBe(0);
  });

  it('the database itself rejects fake-KMS keys and protects the marker', async () => {
    await testPrisma().systemSetting.create({ data: { key: 'environment', value: 'production' } });
    await expect(
      testPrisma().keyEncryptionKey.create({
        data: { purpose: 'kek', version: 1, provider: 'fake-kms', kmsKeyName: 'x', encryptedKey: new Uint8Array(64), status: 'active' },
      }),
    ).rejects.toThrow(/refused in a production database/);
    await expect(testPrisma().systemSetting.delete({ where: { key: 'environment' } })).rejects.toThrow(/production marker/);
    await expect(testPrisma().systemSetting.update({ where: { key: 'environment' }, data: { value: 'development' } })).rejects.toThrow(/production marker/);
  });

  it('refuses when the database already holds keys from a real KMS', async () => {
    await testPrisma().keyEncryptionKey.create({
      data: {
        purpose: 'kek',
        version: 1,
        provider: 'gcp-kms',
        kmsKeyName: 'projects/trustpass-kms/locations/europe-west3/keyRings/trustpass/cryptoKeys/root',
        encryptedKey: new Uint8Array(64),
        status: 'active',
      },
    });
    const before = await fingerprint(testPrisma());
    await expect(start()).rejects.toThrow(/protected by gcp-kms/);
    expect(await fingerprint(testPrisma())).toBe(before);
  });
});

describe('fix H: unreadable link copies are failures', () => {
  it('a link copy no configured key opens makes the rewrap fail and is listed; the link itself still works', async () => {
    const ctx = await start();
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id as string;
    const link = await createLink(ctx, owner, id, { includeFile: true });
    const linkId = await linkIdFor(link.token);
    await ctx.prisma.sharingLink.update({ where: { id: linkId }, data: { tokenEncrypted: new Uint8Array(60) } });
    const report = await rewrapAll({ config: ctx.config, prisma: ctx.prisma });
    expect(report.linkTokens.unreadable).toEqual([linkId]);
    expect(report.verification.allOpen).toBe(false);
    expect(rewrapSucceeded(report)).toBe(false);
    const cli = await keysCli(['rewrap']);
    expect(cli.code).toBe(1);
    expect(cli.output).toMatch(/1 link copies could not be read/);
    const shared = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA });
    expect(shared.statusCode).toBe(200);
  });
});

describe('the database protects stored keys', () => {
  it('refuses to delete, truncate or alter them; only the status can change, and only to retired', async () => {
    const ctx = await start();
    const prisma = ctx.prisma;
    await expect(prisma.keyEncryptionKey.deleteMany()).rejects.toThrow(/cannot be deleted/);
    await expect(prisma.$executeRawUnsafe('TRUNCATE "key_encryption_keys"')).rejects.toThrow(/cannot be deleted/);
    await expect(
      prisma.keyEncryptionKey.update({ where: { purpose_version: { purpose: 'kek', version: 1 } }, data: { encryptedKey: new Uint8Array(64) } }),
    ).rejects.toThrow(/only status/);
    await expect(
      prisma.keyEncryptionKey.create({
        data: { purpose: 'kek', version: 9, provider: 'fake-kms', kmsKeyName: 'x', encryptedKey: new Uint8Array(32), status: 'retired' },
      }),
    ).rejects.toThrow(/check constraint|encrypted_check/);
    expect(await prisma.keyEncryptionKey.count()).toBe(2);
  });
});

describe('logs never contain key material', () => {
  it('start-up, upload, sharing, rotation, reload and re-wrap log no key bytes', async () => {
    const lines: string[] = [];
    const stream = new Writable({
      write(chunk, _enc, done) {
        lines.push(String(chunk));
        done();
      },
    });
    const config = testConfig({
      KEY_PROVIDER: 'fake-kms',
      FAKE_KMS_KEY_FILE: TEST_KMS_KEY_FILE,
      MASTER_KEY: TEST_SECRETS.MASTER_KEY,
      STORAGE_DRIVER: 'database',
      LOG_LEVEL: 'trace',
    });
    const app = await buildApp({ config, prisma: testPrisma(), logger: { level: 'trace', stream } });
    try {
      const ctx = { app, prisma: testPrisma(), config, clock: { now: new Date(), advance() {} }, mail: [] } as unknown as TestContext;
      const owner = await registerUser(ctx);
      const id = (await uploadDocument(ctx, owner)).json().document.id as string;
      await createLink(ctx, owner, id, { includeFile: true });
      const cli = await keysCli(['rotate', '--wait=0'], { MASTER_KEY: TEST_SECRETS.MASTER_KEY });
      lines.push(cli.output);
      await as(ctx, owner, { method: 'GET', url: `/api/documents/${id}/file` }); // makes this instance reload

      const logs = lines.join('\n');
      expect(logs).toContain('encryption keys loaded');
      expect(logs).toContain('encryption keys reloaded');
      const fakeRoot = (await import('../../src/lib/kms/fake')).loadOrCreateFakeKmsKey(TEST_KMS_KEY_FILE);
      const secrets = [TEST_SECRETS.MASTER_KEY, fakeRoot, ...config.masterKeys.all.values(), ...config.linkTokenKeys.all.values()].flatMap((k) =>
        typeof k === 'string' ? [k] : [k.toString('hex'), k.toString('base64'), k.toString('base64url')],
      );
      for (const secret of secrets) expect(logs).not.toContain(secret);
    } finally {
      await app.close();
    }
  });
});

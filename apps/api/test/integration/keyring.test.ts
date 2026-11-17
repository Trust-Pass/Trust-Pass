import { Writable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildApp } from '../../src/app';
import { createManagedKey } from '../../src/lib/keyring';
import { FakeKms } from '../../src/lib/kms/fake';
import { rewrapAll } from '../../src/services/key-rotation';
import {
  as,
  createLink,
  createTestContext,
  documentClaims,
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
  type TestContext,
} from '../helpers';

/**
 * E2: key-encryption keys protected by a KMS (the fake KMS here; Google Cloud KMS in
 * production). Every test starts from an empty keyring and empty data, and cleans up,
 * so other test files keep starting from a fresh key.
 */
const open: TestContext[] = [];
// Database storage (as in production), so every instance sees the same encrypted files.
async function start(overrides: Record<string, string | undefined> = {}) {
  const ctx = await createTestContext({ STORAGE_DRIVER: 'database', ...overrides });
  open.push(ctx);
  return ctx;
}
const LEGACY = { KEY_PROVIDER: 'env', MASTER_KEY: TEST_SECRETS.MASTER_KEY };

beforeEach(async () => {
  await resetDatabase(testPrisma());
  await resetKeyring(testPrisma());
});
afterEach(async () => {
  while (open.length) await open.pop()!.app.close();
  await resetDatabase(testPrisma());
  await resetKeyring(testPrisma());
});

describe('key-encryption keys protected by a KMS', () => {
  it('creates a random KEK and link-token key on first start and stores them only KMS-encrypted', async () => {
    const ctx = await start();
    const rows = await ctx.prisma.keyEncryptionKey.findMany({ orderBy: { purpose: 'asc' } });
    expect(rows.map((r) => [r.purpose, r.version, r.status, r.provider])).toEqual([
      ['kek', 1, 'active', 'fake-kms'],
      ['link_token', 1, 'active', 'fake-kms'],
    ]);
    const kek = ctx.config.masterKeys.current.key;
    for (const row of rows) {
      expect(Buffer.from(row.encryptedKey).includes(kek)).toBe(false);
      expect(Buffer.from(row.encryptedKey).includes(ctx.config.linkTokenKeys.current.key)).toBe(false);
    }
    expect(kek.equals(ctx.config.linkTokenKeys.current.key)).toBe(false);

    // A second instance loads the same keys through the KMS instead of creating new ones.
    const again = await start();
    expect(again.config.masterKeys.current.key.equals(kek)).toBe(true);
    expect(await ctx.prisma.keyEncryptionKey.count()).toBe(2);
  });

  it('two instances starting at the same time create exactly one key', async () => {
    const [a, b] = await Promise.all([start(), start()]);
    expect(await a!.prisma.keyEncryptionKey.count({ where: { purpose: 'kek' } })).toBe(1);
    expect(a!.config.masterKeys.current.key.equals(b!.config.masterKeys.current.key)).toBe(true);
  });

  it('wraps new documents with the KMS-protected KEK and decrypts them', async () => {
    const ctx = await start();
    const owner = await registerUser(ctx);
    const upload = await uploadDocument(ctx, owner, { claims: [{ label: 'Employer', value: 'Example Co' }] });
    const id = upload.json().document.id as string;
    const key = await ctx.prisma.documentKey.findUniqueOrThrow({ where: { documentId: id } });
    expect(key.kekVersion).toBe(1);
    expect((await as(ctx, owner, { method: 'GET', url: `/api/documents/${id}/file` })).statusCode).toBe(200);
    expect((await documentClaims(ctx, owner, id))[0]!.value).toBe('Example Co');
  });

  it('seals link tokens with the link-token key, not the KEK', async () => {
    const ctx = await start();
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id as string;
    const link = await createLink(ctx, owner, id, { includeFile: true });
    const linkId = (await ctx.prisma.sharingLink.findFirstOrThrow()).id;
    const { open: openSealed, linkTokenAad } = await import('../../src/lib/crypto');
    const stored = (await ctx.prisma.sharingLink.findUniqueOrThrow({ where: { id: linkId } })).tokenEncrypted;
    expect(openSealed(ctx.config.linkTokenKeys.current.key, stored, linkTokenAad(linkId)).toString()).toBe(link.token);
    expect(() => openSealed(ctx.config.masterKeys.current.key, stored, linkTokenAad(linkId))).toThrow();
    const copy = await as(ctx, owner, { method: 'GET', url: `/api/links/${linkId}/url` });
    expect(copy.json().url).toContain(link.token);
  });
});

describe('start-up refuses a key setup that does not match the data', () => {
  it('refuses when stored documents use a key version that is not configured', async () => {
    const legacy = await start(LEGACY);
    const owner = await registerUser(legacy);
    await uploadDocument(legacy, owner); // wrapped with legacy v1
    await expect(start()).rejects.toThrow(/version 1, which is not configured/);
  });

  it('refuses when the KMS cannot decrypt the stored keys', async () => {
    await start();
    // Same key name as the stored rows, different root key: the KMS itself must refuse.
    const other = Object.assign(new FakeKms({ key: Buffer.alloc(32, 7) }), { keyName: new FakeKms({ keyFile: TEST_KMS_KEY_FILE }).keyName });
    const config = testConfig({ KEY_PROVIDER: 'fake-kms', FAKE_KMS_KEY_FILE: TEST_KMS_KEY_FILE, MASTER_KEY: undefined });
    await expect(buildApp({ config, prisma: testPrisma(), kms: other, logger: false })).rejects.toThrow(/Could not decrypt the kek key v1/);
  });

  it('refuses when a stored key was protected by a different provider or KMS key', async () => {
    await start();
    const config = testConfig({ KEY_PROVIDER: 'fake-kms', FAKE_KMS_KEY_FILE: TEST_KMS_KEY_FILE, MASTER_KEY: undefined });
    const renamed = Object.assign(new FakeKms({ keyFile: TEST_KMS_KEY_FILE }), { keyName: 'fake-kms/another-key' });
    await expect(buildApp({ config, prisma: testPrisma(), kms: renamed, logger: false })).rejects.toThrow(/different KMS key/);
  });
});

describe('migrating from the legacy MASTER_KEY to KMS-protected keys', () => {
  it('keeps every old document, field, credential and link working through the switch, the re-wrap and the removal of MASTER_KEY', async () => {
    // 1. Today's setup: the key comes from MASTER_KEY.
    const legacy = await start(LEGACY);
    const owner = await registerUser(legacy);
    const fileId = (await uploadDocument(legacy, owner, { claims: [{ label: 'Employer', value: 'Example Co' }] })).json().document.id as string;
    const credId = await issueCredential(legacy, owner);
    const status = (await documentClaims(legacy, owner, credId)).find((c) => c.key === 'enrollment_status')!;
    const oldLink = await createLink(legacy, owner, credId, { claimIds: [status.id] });
    const original = (await as(legacy, owner, { method: 'GET', url: `/api/documents/${fileId}/file` })).rawPayload;
    expect(await legacy.prisma.documentKey.count({ where: { kekVersion: 1 } })).toBe(2);

    // 2. Switch to the KMS with MASTER_KEY kept as a legacy key: old data still opens,
    //    new data uses the KMS-protected KEK (v2, after legacy v1).
    const both = await start({ MASTER_KEY: TEST_SECRETS.MASTER_KEY });
    expect(both.config.masterKeys.current.version).toBe(2);
    expect((await as(both, owner, { method: 'GET', url: `/api/documents/${fileId}/file` })).rawPayload.equals(original)).toBe(true);
    const newId = (await uploadDocument(both, owner)).json().document.id as string;
    expect((await both.prisma.documentKey.findUniqueOrThrow({ where: { documentId: newId } })).kekVersion).toBe(2);
    const oldLinkId = (await both.prisma.sharingLink.findFirstOrThrow()).id;
    expect((await as(both, owner, { method: 'GET', url: `/api/links/${oldLinkId}/url` })).json().url).toContain(oldLink.token);

    // 3. Dry run: proves every key opens, changes nothing.
    const before = await both.prisma.documentKey.findMany({ orderBy: { documentId: 'asc' } });
    const dry = await rewrapAll({ config: both.config, prisma: both.prisma }, { dryRun: true });
    expect(dry.dataKeys).toEqual({ onOldVersion: 2, rewrapped: 0, failed: [] });
    expect(dry.linkTokens.resealed).toBe(1);
    expect(dry.verification).toMatchObject({ allOpen: true, allOnTarget: false });
    expect(await both.prisma.documentKey.findMany({ orderBy: { documentId: 'asc' } })).toEqual(before);

    // 4. The real re-wrap, in small batches. File ciphertext is not touched.
    const objectsBefore = await both.prisma.document.findMany({ select: { id: true, encIv: true, encTag: true }, orderBy: { id: 'asc' } });
    const report = await rewrapAll({ config: both.config, prisma: both.prisma }, { batchSize: 1 });
    expect(report.dataKeys).toEqual({ onOldVersion: 2, rewrapped: 2, failed: [] });
    expect(report.linkTokens).toMatchObject({ resealed: 1, unreadable: [] });
    expect(report.verification).toEqual({ dataKeys: 3, allOnTarget: true, allOpen: true });
    expect(await both.prisma.document.findMany({ select: { id: true, encIv: true, encTag: true }, orderBy: { id: 'asc' } })).toEqual(objectsBefore);
    // Running it again finds nothing to do.
    expect((await rewrapAll({ config: both.config, prisma: both.prisma })).dataKeys.onOldVersion).toBe(0);

    // 5. MASTER_KEY removed: KMS only. Everything still works.
    const kmsOnly = await start();
    expect(kmsOnly.config.legacyKekVersions).toEqual([]);
    expect((await as(kmsOnly, owner, { method: 'GET', url: `/api/documents/${fileId}/file` })).rawPayload.equals(original)).toBe(true);
    expect((await documentClaims(kmsOnly, owner, fileId))[0]!.value).toBe('Example Co');
    expect((await as(kmsOnly, owner, { method: 'GET', url: `/api/links/${oldLinkId}/url` })).json().url).toContain(oldLink.token);
    const shared = await kmsOnly.app.inject({ method: 'GET', url: `/api/share/${oldLink.token}`, remoteAddress: IPS.SA });
    expect(shared.statusCode).toBe(200);
    expect(shared.json().verification.result).toBe('verified');
    expect(shared.json().fields).toEqual([{ label: 'Enrollment status', value: 'Active', source: 'issuer' }]);
  });

  it('reports documents it cannot open instead of skipping them silently', async () => {
    const ctx = await start();
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id as string;
    const second = (await uploadDocument(ctx, owner)).json().document.id as string;
    await createManagedKey(ctx.config, ctx.prisma, new FakeKms({ keyFile: TEST_KMS_KEY_FILE }), 'kek', { retireCurrent: true });
    const rotated = await start();
    // Damage one wrapped key (simulates a corrupted row).
    const row = await rotated.prisma.documentKey.findUniqueOrThrow({ where: { documentId: id } });
    const damaged = Buffer.from(row.wrappedDek);
    damaged[0]! ^= 1;
    await rotated.prisma.documentKey.update({ where: { documentId: id }, data: { wrappedDek: new Uint8Array(damaged) } });
    const report = await rewrapAll({ config: rotated.config, prisma: rotated.prisma });
    expect(report.dataKeys.failed).toEqual([id]);
    expect(report.dataKeys.rewrapped).toBe(1);
    expect(report.verification.allOpen).toBe(false);
    expect((await rotated.prisma.documentKey.findUniqueOrThrow({ where: { documentId: second } })).kekVersion).toBe(2);
  });
});

describe('rotating the KMS-protected KEK', () => {
  it('creates a new version, keeps the old one for reading, and re-wraps everything onto the new one', async () => {
    const ctx = await start();
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner)).json().document.id as string;
    const original = (await as(ctx, owner, { method: 'GET', url: `/api/documents/${id}/file` })).rawPayload;

    const v2 = await createManagedKey(ctx.config, ctx.prisma, new FakeKms({ keyFile: TEST_KMS_KEY_FILE }), 'kek', { retireCurrent: true });
    expect(v2).toBe(2);
    const rows = await ctx.prisma.keyEncryptionKey.findMany({ where: { purpose: 'kek' }, orderBy: { version: 'asc' } });
    expect(rows.map((r) => [r.version, r.status])).toEqual([
      [1, 'retired'],
      [2, 'active'],
    ]);

    const rotated = await start();
    expect(rotated.config.masterKeys.current.version).toBe(2);
    expect((await as(rotated, owner, { method: 'GET', url: `/api/documents/${id}/file` })).rawPayload.equals(original)).toBe(true);
    const report = await rewrapAll({ config: rotated.config, prisma: rotated.prisma });
    expect(report.dataKeys.rewrapped).toBe(1);
    expect(report.verification.allOnTarget).toBe(true);
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
  it('start-up, upload, sharing and re-wrap log no key bytes', async () => {
    const lines: string[] = [];
    const stream = new Writable({
      write(chunk, _enc, done) {
        lines.push(String(chunk));
        done();
      },
    });
    const config = testConfig({ KEY_PROVIDER: 'fake-kms', FAKE_KMS_KEY_FILE: TEST_KMS_KEY_FILE, MASTER_KEY: TEST_SECRETS.MASTER_KEY, STORAGE_DRIVER: 'database', LOG_LEVEL: 'trace' });
    const app = await buildApp({ config, prisma: testPrisma(), logger: { level: 'trace', stream } });
    try {
      const ctx = { app, prisma: testPrisma(), config, clock: { now: new Date(), advance() {} }, mail: [] } as unknown as TestContext;
      const owner = await registerUser(ctx);
      const id = (await uploadDocument(ctx, owner)).json().document.id as string;
      await createLink(ctx, owner, id, { includeFile: true });
      await rewrapAll({ config, prisma: testPrisma() });

      const logs = lines.join('\n');
      expect(logs).toContain('encryption keys loaded');
      const fakeRoot = (await import('../../src/lib/kms/fake')).loadOrCreateFakeKmsKey(TEST_KMS_KEY_FILE);
      const secrets = [
        TEST_SECRETS.MASTER_KEY,
        fakeRoot,
        ...config.masterKeys.all.values(),
        ...config.linkTokenKeys.all.values(),
      ].flatMap((k) => (typeof k === 'string' ? [k] : [k.toString('hex'), k.toString('base64'), k.toString('base64url')]));
      for (const secret of secrets) expect(logs).not.toContain(secret);
    } finally {
      await app.close();
    }
  });
});

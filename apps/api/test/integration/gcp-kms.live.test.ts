import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GcpKms, parseServiceAccount } from '../../src/lib/kms/gcp';
import { KmsError } from '../../src/lib/kms/types';
import { runKeysCli } from '../../src/scripts/keys';
import { readDocumentFile } from '../../src/services/documents';
import { as, cliEnv, createTestContext, registerUser, resetDatabase, resetKeyring, samplePdf, testPrisma, TEST_SECRETS, uploadDocument } from '../helpers';

/**
 * LIVE tests against the real Google Cloud KMS. They run only when CI has these secrets
 * (GitHub > Settings > Secrets and variables > Actions):
 *   GCP_TEST_KMS_KEY_NAME          projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<test key>
 *   GCP_TEST_SERVICE_ACCOUNT_JSON  key of a service account that may only use that TEST key
 * Production's key and service account are never used here. Without the secrets the suite is
 * reported as skipped, never as passed.
 */
const KEY = process.env.GCP_TEST_KMS_KEY_NAME;
const SA = process.env.GCP_TEST_SERVICE_ACCOUNT_JSON;
const live = Boolean(KEY && SA);

const kmsEnv = () => ({ KEY_PROVIDER: 'gcp-kms', GCP_KMS_KEY_NAME: KEY!, GCP_SERVICE_ACCOUNT_JSON: SA!, MASTER_KEY: undefined, FAKE_KMS_KEY_FILE: undefined });

describe.skipIf(!live)('Google Cloud KMS (live)', () => {
  beforeAll(async () => {
    await resetDatabase(testPrisma());
    await resetKeyring(testPrisma());
  });
  afterAll(async () => {
    // Leave the shared test database as other suites expect it (fake-KMS keys only).
    await resetDatabase(testPrisma());
    await resetKeyring(testPrisma());
  });

  it('encrypts and decrypts key material; a wrong AAD or a changed byte is refused', async () => {
    const kms = new GcpKms({ keyName: KEY!, credentials: parseServiceAccount(SA!) });
    const secret = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
    const ct = await kms.encrypt(secret, 'kek|v1');
    expect(ct.includes(secret)).toBe(false);
    expect((await kms.decrypt(ct, 'kek|v1')).equals(secret)).toBe(true);
    await expect(kms.decrypt(ct, 'kek|v2')).rejects.toBeInstanceOf(KmsError);
    const bad = Buffer.from(ct);
    bad[bad.length - 1] ^= 1;
    await expect(kms.decrypt(bad, 'kek|v1')).rejects.toThrow();
  });

  it('the app runs on KMS-protected keys: upload, restart, download byte for byte', async () => {
    const ctx = await createTestContext({ ...kmsEnv(), STORAGE_DRIVER: 'database' });
    let id: string;
    let owner: Awaited<ReturnType<typeof registerUser>>;
    const file = await samplePdf();
    try {
      owner = await registerUser(ctx);
      id = (await uploadDocument(ctx, owner, { file, title: 'Live KMS test' })).json().document.id;
      const rows = await ctx.prisma.keyEncryptionKey.findMany();
      expect(rows.length).toBeGreaterThanOrEqual(2);
      expect(rows.every((r) => r.provider === 'gcp-kms' && r.kmsKeyName === KEY)).toBe(true);
    } finally {
      await ctx.app.close();
    }
    // A new server can only read the document by asking the real KMS for the key.
    const again = await createTestContext({ ...kmsEnv(), STORAGE_DRIVER: 'database' });
    try {
      const res = await as(again, owner!, { method: 'GET', url: `/api/documents/${id!}/file` });
      expect(res.statusCode).toBe(200);
      expect(res.rawPayload.equals(file)).toBe(true);
      expect((await as(again, owner!, { method: 'GET', url: `/api/documents/${id!}` })).json().document.title).toBe('Live KMS test');
    } finally {
      await again.app.close();
    }
  });

  it('rotation with the real KMS keeps every document readable by a fresh server', async () => {
    const lines: string[] = [];
    const code = await runKeysCli(['rotate', '--wait=0'], { env: cliEnv(kmsEnv() as Record<string, string>), prisma: testPrisma(), out: (l) => lines.push(l), sleep: async () => {} });
    expect(code, lines.join('\n')).toBe(0);
    const ctx = await createTestContext({ ...kmsEnv(), STORAGE_DRIVER: 'database' });
    try {
      const doc = await ctx.prisma.document.findFirstOrThrow({ where: { deletedAt: null }, include: { key: true } });
      expect(ctx.config.masterKeys.current.version).toBeGreaterThan(1);
      expect(doc.key!.kekVersion).toBe(ctx.config.masterKeys.current.version); // re-wrapped onto the new KEK
      // Read through the service layer: proves the re-wrapped key opens with the KMS-protected KEK.
      expect((await readDocumentFile(ctx.app.deps, doc)).length).toBe(doc.sizeBytes);
    } finally {
      await ctx.app.close();
    }
  });

  it('migration from MASTER_KEY: legacy documents keep working through rewrap and removal of MASTER_KEY', async () => {
    await resetDatabase(testPrisma());
    await resetKeyring(testPrisma());
    const legacy = await createTestContext({ KEY_PROVIDER: 'env', MASTER_KEY: TEST_SECRETS.MASTER_KEY, STORAGE_DRIVER: 'database' });
    const file = await samplePdf();
    let id: string;
    let owner: Awaited<ReturnType<typeof registerUser>>;
    try {
      owner = await registerUser(legacy);
      id = (await uploadDocument(legacy, owner, { file })).json().document.id;
    } finally {
      await legacy.app.close();
    }
    // Production's switch: KMS on, MASTER_KEY still present for the old keys, then rewrap.
    const lines: string[] = [];
    const code = await runKeysCli(['rewrap'], {
      env: cliEnv({ ...(kmsEnv() as Record<string, string>), MASTER_KEY: TEST_SECRETS.MASTER_KEY }),
      prisma: testPrisma(),
      out: (l) => lines.push(l),
      sleep: async () => {},
    });
    expect(code, lines.join('\n')).toBe(0);
    // MASTER_KEY removed: only the real KMS can open the document now.
    const kmsOnly = await createTestContext({ ...kmsEnv(), STORAGE_DRIVER: 'database' });
    try {
      const res = await as(kmsOnly, owner!, { method: 'GET', url: `/api/documents/${id!}/file` });
      expect(res.rawPayload.equals(file)).toBe(true);
    } finally {
      await kmsOnly.app.close();
    }
  });
});

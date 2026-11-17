import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { checkSecrets, keyCheckValue, MANIFEST_FORMAT, parseManifest, type BackupManifest } from '../../src/services/backup';
import { testConfig, TEST_SECRETS } from '../helpers';

function manifestFor(config = testConfig()): BackupManifest {
  return {
    format: MANIFEST_FORMAT,
    createdAt: new Date().toISOString(),
    migrations: [],
    storageDriver: 'database',
    counts: { users: 0, documents: 0, deletedDocuments: 0, documentKeys: 0, storedObjects: 0, claims: 0, credentials: 0, sharingLinks: 0 },
    keys: {
      provider: 'env',
      kmsKey: null,
      kekVersionsInUse: [{ version: 1, documents: 1, source: 'legacy' }],
      storedKeys: [],
      legacyKeyChecks: [{ version: 1, kcv: keyCheckValue(config.masterKeys.all.get(1)!) }],
    },
    secretChecks: { ISSUER_SIGNING_SEED: keyCheckValue(config.issuerSeed), IP_HASH_SECRET: keyCheckValue(config.ipHashKey) },
    documents: [],
  };
}

describe('key check values', () => {
  it('identify a key without revealing it', () => {
    const key = randomBytes(32);
    const kcv = keyCheckValue(key);
    expect(kcv).toMatch(/^[a-f0-9]{16}$/);
    expect(keyCheckValue(Buffer.from(key))).toBe(kcv);
    expect(keyCheckValue(randomBytes(32))).not.toBe(kcv);
    expect(key.toString('hex')).not.toContain(kcv);
  });
});

describe('secret checks before a restore', () => {
  it('pass with the same secrets', () => {
    expect(checkSecrets(testConfig(), manifestFor())).toEqual([]);
  });

  it('name each secret that is missing or different, without printing any of them', () => {
    const manifest = manifestFor();
    const wrong = testConfig({
      MASTER_KEY: 'a-completely-different-master-key-0123456789-abcdefgh',
      ISSUER_SIGNING_SEED: 'another-issuer-seed-0123456789-abcdefghijklmn',
      IP_HASH_SECRET: 'another-ip-hash-secret-0123456789-abcdefghijklm',
    });
    const problems = checkSecrets(wrong, manifest);
    expect(problems).toEqual([
      'legacy master key v1 does not match the one this backup was made with',
      'ISSUER_SIGNING_SEED differs from the backup: issued credentials would verify as invalid',
      'IP_HASH_SECRET differs from the backup: visitor hashes in the access log would no longer match',
    ]);
    const missing = testConfig({ MASTER_KEY: TEST_SECRETS.MASTER_KEY, MASTER_KEY_VERSION: '5' });
    expect(checkSecrets(missing, manifest)[0]).toMatch(/v1 is needed .* but not configured/);
    for (const p of [...problems, ...checkSecrets(missing, manifest)]) {
      expect(p).not.toContain(TEST_SECRETS.MASTER_KEY);
      expect(p).not.toContain('another-issuer-seed');
    }
  });
});

describe('manifest files', () => {
  it('are recognised by their format and rejected otherwise', () => {
    const manifest = manifestFor();
    expect(parseManifest(JSON.stringify(manifest)).keys.legacyKeyChecks).toHaveLength(1);
    expect(() => parseManifest('{"format":"something-else","documents":[]}')).toThrow(/trustpass-backup-manifest/);
    expect(() => parseManifest('not json')).toThrow();
  });
});

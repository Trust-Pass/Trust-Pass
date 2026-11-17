import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import type { AppConfig } from '../config';
import { toBytes, unwrapDataKey } from './crypto';
import type { KeySet } from './keyset';
import type { KmsProvider } from './kms/types';

/**
 * Key hierarchy (E2):
 *
 *   KMS root key (never leaves the KMS)
 *     └─ encrypts → KEKs, stored only as KMS ciphertext in key_encryption_keys
 *          └─ wrap → one random data key per document (document_keys)
 *               └─ encrypt → file, field values, credential
 *
 * At start-up every stored KEK is decrypted once through the KMS and kept in memory.
 * If anything does not match (wrong KMS key, wrong provider, a key version that is in
 * use but missing, a key that does not open the stored document keys) the app refuses
 * to start instead of failing later on individual documents.
 */
export type KeyPurpose = 'kek' | 'link_token';
const PURPOSES: KeyPurpose[] = ['kek', 'link_token'];

export class KeyringError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyringError';
  }
}

export function keyAad(purpose: KeyPurpose, version: number): string {
  return `trustpass-key|${purpose}|v${version}`;
}

interface Logger {
  info(obj: object, msg: string): void;
  warn(obj: object, msg: string): void;
}

export interface KeyringOptions {
  config: AppConfig;
  prisma: PrismaClient;
  kms: KmsProvider | null;
  log?: Logger;
  /** Create the first KMS-protected key when none exists (default true). `keys:status` passes false. */
  createIfMissing?: boolean;
}

function keySetFor(config: AppConfig, purpose: KeyPurpose): KeySet {
  return purpose === 'kek' ? config.masterKeys : config.linkTokenKeys;
}

export async function initKeyring({ config, prisma, kms, log, createIfMissing = true }: KeyringOptions): Promise<void> {
  if (config.env.KEY_PROVIDER !== 'env') {
    if (!kms || kms.name !== config.env.KEY_PROVIDER) {
      throw new KeyringError(`KEY_PROVIDER=${config.env.KEY_PROVIDER} needs a matching KMS provider`);
    }
    for (const purpose of PURPOSES) await loadManagedKeys(config, prisma, kms, purpose, createIfMissing);
  }
  if (!config.masterKeys.hasCurrent || !config.linkTokenKeys.hasCurrent) {
    throw new KeyringError('No current encryption key is configured');
  }
  await verifyKeysInUse(config, prisma);

  log?.info(
    {
      keyProvider: config.env.KEY_PROVIDER,
      kmsKey: kms?.keyName ?? null,
      currentKekVersion: config.masterKeys.current.version,
      kekVersions: config.masterKeys.versions,
      legacyKekVersions: config.legacyKekVersions,
    },
    'encryption keys loaded',
  );
  if (config.isProduction && config.env.KEY_PROVIDER === 'env') {
    log?.warn(
      { keyProvider: 'env' },
      'MASTER_KEY is stored next to the application. Move key protection to a KMS (KEY_PROVIDER=gcp-kms) and run keys:rewrap.',
    );
  }
}

async function loadManagedKeys(config: AppConfig, prisma: PrismaClient, kms: KmsProvider, purpose: KeyPurpose, createIfMissing: boolean) {
  const keySet = keySetFor(config, purpose);
  let rows = await prisma.keyEncryptionKey.findMany({ where: { purpose }, orderBy: { version: 'asc' } });
  if (!rows.some((row) => row.status === 'active')) {
    if (!createIfMissing) throw new KeyringError(`No KMS-protected ${purpose} key exists yet: start the app once, or run keys:rewrap`);
    await createManagedKey(config, prisma, kms, purpose);
    rows = await prisma.keyEncryptionKey.findMany({ where: { purpose }, orderBy: { version: 'asc' } });
  }

  for (const row of rows) {
    if (row.provider !== kms.name) {
      throw new KeyringError(`The ${purpose} key v${row.version} is protected by ${row.provider}, but KEY_PROVIDER is ${kms.name}`);
    }
    if (row.kmsKeyName !== kms.keyName) {
      throw new KeyringError(`The ${purpose} key v${row.version} is protected by a different KMS key (${row.kmsKeyName}) than the configured one (${kms.keyName})`);
    }
    if (config.legacyKekVersions.includes(row.version)) {
      throw new KeyringError(`The ${purpose} key v${row.version} clashes with a legacy master key of the same version`);
    }
    let key: Buffer;
    try {
      key = await kms.decrypt(Buffer.from(row.encryptedKey), keyAad(purpose, row.version));
    } catch (err) {
      throw new KeyringError(`Could not decrypt the ${purpose} key v${row.version} with ${kms.name}: ${err instanceof Error ? err.message : 'unknown error'}`);
    }
    if (key.length !== 32) throw new KeyringError(`The ${purpose} key v${row.version} is not 32 bytes`);
    keySet.add(row.version, key);
  }
  const active = rows.filter((row) => row.status === 'active');
  if (active.length !== 1) throw new KeyringError(`Expected exactly one active ${purpose} key, found ${active.length}`);
  keySet.setCurrent(active[0]!.version);
}

/** Creates a new random key, encrypted by the KMS, and makes it the active one for its purpose. */
export async function createManagedKey(
  config: AppConfig,
  prisma: PrismaClient,
  kms: KmsProvider,
  purpose: KeyPurpose,
  options: { retireCurrent?: boolean } = {},
): Promise<number> {
  return prisma.$transaction(
    async (tx) => {
      // One process at a time, so two instances starting together cannot both create a key.
      await tx.$executeRawUnsafe(`SELECT pg_advisory_xact_lock(hashtext('trustpass-keyring'))`);
      const active = await tx.keyEncryptionKey.findFirst({ where: { purpose, status: 'active' } });
      if (active && !options.retireCurrent) return active.version;

      const maxRow = await tx.keyEncryptionKey.aggregate({ where: { purpose }, _max: { version: true } });
      const candidates = [(maxRow._max.version ?? 0) + 1, ...config.legacyKekVersions.map((v) => v + 1)];
      if (purpose === 'kek') {
        const inUse = await tx.documentKey.aggregate({ _max: { kekVersion: true } });
        candidates.push((inUse._max.kekVersion ?? 0) + 1);
      }
      const version = Math.max(...candidates);

      const key = randomBytes(32);
      let encryptedKey: Buffer;
      try {
        encryptedKey = await kms.encrypt(key, keyAad(purpose, version));
        // Prove the KMS can give it back before relying on it.
        const roundTrip = await kms.decrypt(encryptedKey, keyAad(purpose, version));
        if (!roundTrip.equals(key)) throw new KeyringError('KMS returned a different key');
        roundTrip.fill(0);
      } finally {
        key.fill(0);
      }
      if (active) {
        await tx.keyEncryptionKey.update({
          where: { purpose_version: { purpose, version: active.version } },
          data: { status: 'retired', retiredAt: new Date() },
        });
      }
      await tx.keyEncryptionKey.create({
        data: { purpose, version, provider: kms.name, kmsKeyName: kms.keyName, encryptedKey: toBytes(encryptedKey), status: 'active' },
      });
      return version;
    },
    { timeout: 60_000 },
  );
}

/**
 * Every KEK version used by stored document keys must be configured, and must
 * actually open them. A few keys per version are tried; one success is enough, so a
 * single damaged row cannot stop the whole service.
 */
export async function verifyKeysInUse(config: AppConfig, prisma: PrismaClient) {
  const versions = await prisma.documentKey.groupBy({ by: ['kekVersion'] });
  for (const { kekVersion } of versions) {
    if (!config.masterKeys.all.has(kekVersion)) {
      throw new KeyringError(
        `Stored documents use key-encryption key version ${kekVersion}, which is not configured. ` +
          'Restore that key (PREVIOUS_MASTER_KEYS, or the keyring row and its KMS key) before starting.',
      );
    }
    const samples = await prisma.documentKey.findMany({ where: { kekVersion }, take: 3, orderBy: { documentId: 'asc' } });
    const opens = samples.some((sample) => {
      try {
        unwrapDataKey(config, sample, sample.documentId).fill(0);
        return true;
      } catch {
        return false;
      }
    });
    if (!opens) {
      throw new KeyringError(`Key-encryption key version ${kekVersion} does not open the stored document keys: the configured key is wrong`);
    }
  }
}

export interface KeyringStatus {
  provider: string;
  kmsKey: string | null;
  currentKekVersion: number;
  documentsByKekVersion: Array<{ version: number; documents: number; source: 'kms' | 'legacy' }>;
  documentsOnLegacyKeys: number;
}

export async function keyringStatus(config: AppConfig, prisma: PrismaClient): Promise<KeyringStatus> {
  const groups = await prisma.documentKey.groupBy({ by: ['kekVersion'], _count: { _all: true } });
  const documentsByKekVersion = groups
    .map((g) => ({
      version: g.kekVersion,
      documents: g._count._all,
      source: (config.legacyKekVersions.includes(g.kekVersion) ? 'legacy' : 'kms') as 'kms' | 'legacy',
    }))
    .sort((a, b) => a.version - b.version);
  return {
    provider: config.env.KEY_PROVIDER,
    kmsKey: config.env.KEY_PROVIDER === 'gcp-kms' ? (config.env.GCP_KMS_KEY_NAME ?? null) : null,
    currentKekVersion: config.masterKeys.current.version,
    documentsByKekVersion,
    documentsOnLegacyKeys: documentsByKekVersion.filter((g) => g.source === 'legacy').reduce((n, g) => n + g.documents, 0),
  };
}

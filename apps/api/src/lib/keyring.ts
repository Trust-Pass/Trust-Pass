import { randomBytes } from 'node:crypto';
import type { Prisma, PrismaClient } from '@prisma/client';
import type { AppConfig } from '../config';
import { toBytes, unwrapDataKey } from './crypto';
import type { KeySet } from './keyset';
import type { KmsProvider } from './kms/types';

/**
 * Key hierarchy (E2):
 *
 *   KMS root key (never leaves the KMS)
 *     └─ encrypts → KEKs and link-token keys, stored only as KMS ciphertext in key_encryption_keys
 *          └─ KEK wraps → one random data key per document (document_keys)
 *               └─ encrypt → file, field values, credential
 *
 * Start-up checks everything it can BEFORE writing anything (preflight), then loads the
 * keys (creating the first ones if needed), then verifies them against the stored data.
 * Any mismatch stops start-up instead of failing later on individual documents.
 *
 * Version numbers are shared by every purpose and by the legacy MASTER_KEY versions, so
 * a stored key can never clash with another key of the same version.
 */
export type KeyPurpose = 'kek' | 'link_token';
const PURPOSES: KeyPurpose[] = ['kek', 'link_token'];

/** Read-only queries also work inside a READ ONLY transaction (dry runs). */
export type Db = PrismaClient | Prisma.TransactionClient;

export class KeyringError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyringError';
  }
}

export function keyAad(purpose: KeyPurpose, version: number): string {
  return `trustpass-key|${purpose}|v${version}`;
}

export interface Logger {
  info(obj: object, msg: string): void;
  warn(obj: object, msg: string): void;
}

export interface KeyringOptions {
  config: AppConfig;
  prisma: Db;
  kms: KmsProvider | null;
  log?: Logger;
  /** Create the first KMS-protected keys when none exist (default true). Needs a PrismaClient. */
  createIfMissing?: boolean;
  /** Leave a purpose without a current key instead of failing when none exists (dry runs). */
  allowMissing?: boolean;
}

/** Marks a database as production's, so development tools (the fake KMS) refuse to write to it. */
export const ENVIRONMENT_SETTING = 'environment';

function keySetFor(config: AppConfig, purpose: KeyPurpose): KeySet {
  return purpose === 'kek' ? config.masterKeys : config.linkTokenKeys;
}

function isClient(db: Db): db is PrismaClient {
  return typeof (db as PrismaClient).$transaction === 'function';
}

export async function isProductionDatabase(db: Db): Promise<boolean> {
  const marker = await db.systemSetting.findUnique({ where: { key: ENVIRONMENT_SETTING } });
  return marker?.value === 'production';
}

export async function initKeyring(options: KeyringOptions): Promise<void> {
  const { config, prisma, kms, log, createIfMissing = true, allowMissing = false } = options;
  const managed = config.env.KEY_PROVIDER !== 'env';
  if (managed && (!kms || kms.name !== config.env.KEY_PROVIDER)) {
    throw new KeyringError(`KEY_PROVIDER=${config.env.KEY_PROVIDER} needs a matching KMS provider`);
  }

  // 1. Checks that need no keys, before anything is written.
  await preflight(config, prisma, kms);

  // 2. Production marks its database once, so the fake KMS can never write to it later.
  if (config.isProduction && createIfMissing && isClient(prisma)) {
    await prisma.systemSetting.upsert({
      where: { key: ENVIRONMENT_SETTING },
      create: { key: ENVIRONMENT_SETTING, value: 'production' },
      update: {},
    });
  }

  // 3. Load (and if needed create) the KMS-protected keys.
  if (managed && kms) {
    const missing: KeyPurpose[] = [];
    for (const purpose of PURPOSES) {
      if (!(await prisma.keyEncryptionKey.findFirst({ where: { purpose, status: 'active' } }))) missing.push(purpose);
    }
    if (missing.length > 0 && createIfMissing) {
      if (!isClient(prisma)) throw new KeyringError('Creating keys needs a database client, not a transaction');
      await createManagedKeys(config, prisma, kms, missing);
    } else if (missing.length > 0 && !allowMissing) {
      throw new KeyringError(`No KMS-protected key exists yet (${missing.join(', ')}): start the app once, or run keys:rewrap`);
    }
    for (const purpose of PURPOSES) await loadManagedKeys(config, prisma, kms, purpose, log);
  }

  if (!allowMissing && (!config.masterKeys.hasCurrent || !config.linkTokenKeys.hasCurrent)) {
    throw new KeyringError('No current encryption key is configured');
  }

  // 4. The configured keys must open the stored document keys.
  await verifyKeysInUse(config, prisma);

  log?.info(
    {
      keyProvider: config.env.KEY_PROVIDER,
      kmsKey: kms?.keyName ?? null,
      currentKekVersion: config.masterKeys.hasCurrent ? config.masterKeys.current.version : null,
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

/**
 * Refuses, without writing anything:
 *  - the fake KMS on a database marked as production's;
 *  - stored keys protected by another provider or another KMS key;
 *  - a stored key whose version clashes with a legacy master key;
 *  - document keys whose KEK version is neither a legacy key nor a stored key.
 */
async function preflight(config: AppConfig, db: Db, kms: KmsProvider | null) {
  if (kms?.name === 'fake-kms' && (await isProductionDatabase(db))) {
    throw new KeyringError('KEY_PROVIDER=fake-kms is refused: this database belongs to production');
  }
  const rows = await db.keyEncryptionKey.findMany({ select: { purpose: true, version: true, provider: true, kmsKeyName: true } });
  if (kms) {
    const foreign = rows.find((r) => r.provider !== kms.name || r.kmsKeyName !== kms.keyName);
    if (foreign) {
      throw new KeyringError(
        `The stored ${foreign.purpose} key v${foreign.version} is protected by ${foreign.provider} (${foreign.kmsKeyName}), ` +
          `not by the configured ${kms.name} (${kms.keyName}): a different KMS key`,
      );
    }
  }
  for (const row of rows) {
    if (config.legacyKekVersions.includes(row.version)) {
      throw new KeyringError(`The stored ${row.purpose} key v${row.version} clashes with a legacy master key of the same version`);
    }
  }
  const known = new Set([...config.legacyKekVersions, ...rows.filter((r) => r.purpose === 'kek').map((r) => r.version)]);
  const inUse = await db.documentKey.groupBy({ by: ['kekVersion'] });
  for (const { kekVersion } of inUse) {
    if (!known.has(kekVersion)) {
      throw new KeyringError(
        `Stored documents use key-encryption key version ${kekVersion}, which is not configured. ` +
          'Restore that key (PREVIOUS_MASTER_KEYS, or the keyring row and its KMS key) before starting.',
      );
    }
  }
}

/**
 * Decrypts every stored key of one purpose through the KMS. The active key must work. A
 * retired key that cannot be decrypted (e.g. its KMS key version was disabled) is skipped
 * with a warning when nothing uses it, and stops start-up when documents still need it.
 */
async function loadManagedKeys(config: AppConfig, db: Db, kms: KmsProvider, purpose: KeyPurpose, log?: Logger) {
  const keySet = keySetFor(config, purpose);
  const rows = await db.keyEncryptionKey.findMany({ where: { purpose }, orderBy: { version: 'asc' } });
  const active = rows.filter((row) => row.status === 'active');
  if (active.length > 1) throw new KeyringError(`Expected one active ${purpose} key, found ${active.length}`);

  for (const row of rows) {
    if (keySet.all.has(row.version)) continue; // already loaded (reload after a rotation)
    let key: Buffer;
    try {
      key = await kms.decrypt(Buffer.from(row.encryptedKey), keyAad(purpose, row.version));
      if (key.length !== 32) throw new KeyringError('not 32 bytes');
    } catch (err) {
      const reason = err instanceof Error ? err.message : 'unknown error';
      if (row.status === 'retired') {
        const used = purpose === 'kek' ? await db.documentKey.count({ where: { kekVersion: row.version } }) : 0;
        if (used === 0) {
          log?.warn({ purpose, version: row.version }, `retired ${purpose} key v${row.version} could not be decrypted and is not used by any document; skipped`);
          continue;
        }
        throw new KeyringError(`Could not decrypt the retired ${purpose} key v${row.version}, which ${used} document(s) still use: ${reason}`);
      }
      throw new KeyringError(`Could not decrypt the ${purpose} key v${row.version} with ${kms.name}: ${reason}`);
    }
    keySet.add(row.version, key);
  }
  if (active[0]) keySet.setCurrent(active[0].version);
}

/** Next free version number, shared by every purpose, the legacy keys and the stored document keys. */
async function nextVersion(tx: Prisma.TransactionClient, config: AppConfig): Promise<number> {
  const rows = await tx.keyEncryptionKey.aggregate({ _max: { version: true } });
  const docs = await tx.documentKey.aggregate({ _max: { kekVersion: true } });
  return Math.max(rows._max.version ?? 0, docs._max.kekVersion ?? 0, ...config.legacyKekVersions, 0) + 1;
}

/**
 * Creates new random keys for the given purposes in ONE transaction, encrypted by the KMS,
 * and makes them active (retiring the current ones when `retireCurrent`). A purpose that
 * already has an active key is left alone unless `retireCurrent`.
 */
export async function createManagedKeys(
  config: AppConfig,
  prisma: PrismaClient,
  kms: KmsProvider,
  purposes: KeyPurpose[],
  options: { retireCurrent?: boolean } = {},
): Promise<Partial<Record<KeyPurpose, number>>> {
  if (kms.name === 'fake-kms' && (await isProductionDatabase(prisma))) {
    throw new KeyringError('KEY_PROVIDER=fake-kms is refused: this database belongs to production');
  }
  return prisma.$transaction(
    async (tx) => {
      // One process at a time, so two instances starting together cannot both create a key.
      await tx.$executeRawUnsafe(`SELECT pg_advisory_xact_lock(hashtext('trustpass-keyring'))`);
      const created: Partial<Record<KeyPurpose, number>> = {};
      for (const purpose of purposes) {
        const active = await tx.keyEncryptionKey.findFirst({ where: { purpose, status: 'active' } });
        if (active && !options.retireCurrent) continue;
        const version = await nextVersion(tx, config);
        const key = randomBytes(32);
        let encryptedKey: Buffer;
        try {
          encryptedKey = await kms.encrypt(key, keyAad(purpose, version));
          // Prove the KMS gives it back before relying on it.
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
        created[purpose] = version;
      }
      return created;
    },
    { timeout: 60_000 },
  );
}

/** One purpose, for callers and tests that rotate a single key. */
export async function createManagedKey(
  config: AppConfig,
  prisma: PrismaClient,
  kms: KmsProvider,
  purpose: KeyPurpose,
  options: { retireCurrent?: boolean } = {},
): Promise<number> {
  const created = await createManagedKeys(config, prisma, kms, [purpose], options);
  const version = created[purpose];
  if (version !== undefined) return version;
  const active = await prisma.keyEncryptionKey.findFirstOrThrow({ where: { purpose, status: 'active' } });
  return active.version;
}

/**
 * Every KEK version used by stored document keys must be loaded and must actually open
 * them. A few keys per version are tried; one success is enough, so a single damaged
 * row cannot stop the whole service.
 */
export async function verifyKeysInUse(config: AppConfig, db: Db) {
  const versions = await db.documentKey.groupBy({ by: ['kekVersion'] });
  for (const { kekVersion } of versions) {
    if (!config.masterKeys.all.has(kekVersion)) {
      throw new KeyringError(
        `Stored documents use key-encryption key version ${kekVersion}, which is not configured. ` +
          'Restore that key (PREVIOUS_MASTER_KEYS, or the keyring row and its KMS key) before starting.',
      );
    }
    const samples = await db.documentKey.findMany({ where: { kekVersion }, take: 3, orderBy: { documentId: 'asc' } });
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

/**
 * Keeps a running server in step with key rotations made by `keys:rotate` (or another
 * instance), without a restart:
 *  - before wrapping a new data key, the active versions are re-checked at most every
 *    KEY_REFRESH_SECONDS, so new documents move to a new KEK shortly after a rotation;
 *  - a stored item that uses a version this process has not loaded triggers one reload.
 */
export class KeyringManager {
  private lastCheck: number;
  private reloading: Promise<void> | null = null;

  constructor(
    private readonly options: {
      config: AppConfig;
      prisma: PrismaClient;
      kms: KmsProvider | null;
      log?: Logger;
      refreshMs: number;
      now?: () => number;
    },
  ) {
    this.lastCheck = this.now();
  }

  private now() {
    return (this.options.now ?? Date.now)();
  }

  get enabled(): boolean {
    return this.options.kms !== null;
  }

  /** Loads any keys added since start-up and switches to the active versions. */
  reload(): Promise<void> {
    if (!this.enabled) return Promise.resolve();
    this.reloading ??= (async () => {
      try {
        const { config, prisma, kms, log } = this.options;
        for (const purpose of PURPOSES) await loadManagedKeys(config, prisma, kms!, purpose, log);
        this.lastCheck = this.now();
        log?.info({ currentKekVersion: config.masterKeys.current.version }, 'encryption keys reloaded');
      } finally {
        this.reloading = null;
      }
    })();
    return this.reloading;
  }

  /** Cheap check (one small query at most every refresh interval) before wrapping new data. */
  async refreshIfStale(): Promise<void> {
    if (!this.enabled || this.now() - this.lastCheck < this.options.refreshMs) return;
    this.lastCheck = this.now();
    const { config, prisma } = this.options;
    const active = await prisma.keyEncryptionKey.findMany({ where: { status: 'active' }, select: { purpose: true, version: true } });
    const stale = active.some((row) => {
      const set = keySetFor(config, row.purpose as KeyPurpose);
      return !set.hasCurrent || set.current.version !== row.version;
    });
    if (stale) await this.reload();
  }
}

export interface KeyringStatus {
  provider: string;
  kmsKey: string | null;
  currentKekVersion: number | null;
  documentsByKekVersion: Array<{ version: number; documents: number; source: 'kms' | 'legacy' }>;
  documentsOnLegacyKeys: number;
  storedKeys: Array<{ purpose: string; version: number; status: string; retiredAt: Date | null }>;
}

export async function keyringStatus(config: AppConfig, db: Db): Promise<KeyringStatus> {
  const groups = await db.documentKey.groupBy({ by: ['kekVersion'], _count: { _all: true } });
  const documentsByKekVersion = groups
    .map((g) => ({
      version: g.kekVersion,
      documents: g._count._all,
      source: (config.legacyKekVersions.includes(g.kekVersion) ? 'legacy' : 'kms') as 'kms' | 'legacy',
    }))
    .sort((a, b) => a.version - b.version);
  const storedKeys = await db.keyEncryptionKey.findMany({
    select: { purpose: true, version: true, status: true, retiredAt: true },
    orderBy: [{ purpose: 'asc' }, { version: 'asc' }],
  });
  return {
    provider: config.env.KEY_PROVIDER,
    kmsKey: config.env.KEY_PROVIDER === 'gcp-kms' ? (config.env.GCP_KMS_KEY_NAME ?? null) : null,
    currentKekVersion: config.masterKeys.hasCurrent ? config.masterKeys.current.version : null,
    documentsByKekVersion,
    documentsOnLegacyKeys: documentsByKekVersion.filter((g) => g.source === 'legacy').reduce((n, g) => n + g.documents, 0),
    storedKeys,
  };
}

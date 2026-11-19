import { createHmac } from 'node:crypto';
import type { AppConfig } from '../config';
import { claimAad, claimLabelAad, credentialAad, decrypt, fileAad, open, sha256Hex, titleAad, unwrapDataKey } from '../lib/crypto';
import { openSha256 } from './metadata';
import type { Db } from '../lib/keyring';
import type { ObjectStorage } from '../lib/storage';
import { decryptToken } from '../modules/sharing';

/**
 * Backup and restore support.
 *
 * A TrustPass backup has three parts, and all three are needed to read any document:
 *   1. the database dump (documents, wrapped keys, key_encryption_keys, and with
 *      STORAGE_DRIVER=database the encrypted files themselves in stored_objects);
 *   2. the encrypted files directory when STORAGE_DRIVER=local;
 *   3. the secrets and keys, which are never in the dump: MASTER_KEY / PREVIOUS_MASTER_KEYS
 *      (legacy), access to the KMS key, ISSUER_SIGNING_SEED, IP_HASH_SECRET.
 *
 * The manifest describes a backup without containing any secret: counts, key versions,
 * one fingerprint per encrypted file, and short key check values (KCVs) that tell a
 * restore whether it was given the right secrets, without revealing them.
 * `verifyRestore` is the restore drill: it decrypts every file, field, credential and
 * link copy of a restored database, read-only, and compares it with the manifest.
 */
export const MANIFEST_FORMAT = 'trustpass-backup-manifest/1';

export interface BackupManifest {
  format: typeof MANIFEST_FORMAT;
  createdAt: string;
  migrations: string[];
  storageDriver: string;
  counts: Record<'users' | 'documents' | 'deletedDocuments' | 'documentKeys' | 'storedObjects' | 'claims' | 'credentials' | 'sharingLinks', number>;
  keys: {
    provider: string;
    kmsKey: string | null;
    kekVersionsInUse: Array<{ version: number; documents: number; source: 'legacy' | 'kms' }>;
    storedKeys: Array<{ purpose: string; version: number; status: string; provider: string; kmsKeyName: string }>;
    /** Legacy key versions this backup needs, with a check value for each. */
    legacyKeyChecks: Array<{ version: number; kcv: string }>;
  };
  secretChecks: { ISSUER_SIGNING_SEED: string; IP_HASH_SECRET: string };
  /** One entry per active document: SHA-256 of its encrypted file (ciphertext, never plaintext). */
  documents: Array<{ id: string; ciphertextSha256: string }>;
}

/** 64-bit key check value: HMAC-SHA256 of a fixed label. Identifies a key without revealing it. */
export function keyCheckValue(key: Buffer): string {
  return createHmac('sha256', key).update('trustpass-key-check-value').digest('hex').slice(0, 16);
}

async function appliedMigrations(db: Db): Promise<string[]> {
  const rows = await db.$queryRawUnsafe<Array<{ migration_name: string }>>(
    `SELECT migration_name FROM "_prisma_migrations" WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL ORDER BY migration_name`,
  );
  return rows.map((r) => r.migration_name);
}

/** Builds the manifest. Read-only; the keyring must already be loaded (initKeyring). */
export async function createManifest(deps: { config: AppConfig; prisma: Db; storage: ObjectStorage; now?: Date }): Promise<BackupManifest> {
  const { config, prisma, storage } = deps;
  const [users, documents, deletedDocuments, documentKeys, storedObjects, claims, credentials, sharingLinks] = await Promise.all([
    prisma.user.count(),
    prisma.document.count({ where: { deletedAt: null } }),
    prisma.document.count({ where: { deletedAt: { not: null } } }),
    prisma.documentKey.count(),
    prisma.storedObject.count(),
    prisma.documentClaim.count(),
    prisma.credential.count(),
    prisma.sharingLink.count(),
  ]);
  const groups = await prisma.documentKey.groupBy({ by: ['kekVersion'], _count: { _all: true } });
  const kekVersionsInUse = groups
    .map((g) => ({
      version: g.kekVersion,
      documents: g._count._all,
      source: (config.legacyKekVersions.includes(g.kekVersion) ? 'legacy' : 'kms') as 'legacy' | 'kms',
    }))
    .sort((a, b) => a.version - b.version);
  const storedKeys = await prisma.keyEncryptionKey.findMany({
    select: { purpose: true, version: true, status: true, provider: true, kmsKeyName: true },
    orderBy: [{ purpose: 'asc' }, { version: 'asc' }],
  });
  const legacyKeyChecks = kekVersionsInUse
    .filter((v) => v.source === 'legacy')
    .map((v) => ({ version: v.version, kcv: keyCheckValue(config.masterKeys.all.get(v.version)!) }));

  const docs: BackupManifest['documents'] = [];
  let after: string | undefined;
  for (;;) {
    const batch = await prisma.document.findMany({
      where: { deletedAt: null, ...(after ? { id: { gt: after } } : {}) },
      select: { id: true, storageKey: true },
      orderBy: { id: 'asc' },
      take: 200,
    });
    if (batch.length === 0) break;
    for (const doc of batch) docs.push({ id: doc.id, ciphertextSha256: sha256Hex(await storage.get(doc.storageKey)) });
    after = batch[batch.length - 1]!.id;
  }

  return {
    format: MANIFEST_FORMAT,
    createdAt: (deps.now ?? new Date()).toISOString(),
    migrations: await appliedMigrations(prisma),
    storageDriver: storage.driver,
    counts: { users, documents, deletedDocuments, documentKeys, storedObjects, claims, credentials, sharingLinks },
    keys: {
      provider: config.env.KEY_PROVIDER,
      kmsKey: config.env.KEY_PROVIDER === 'gcp-kms' ? (config.env.GCP_KMS_KEY_NAME ?? null) : null,
      kekVersionsInUse,
      storedKeys,
      legacyKeyChecks,
    },
    secretChecks: { ISSUER_SIGNING_SEED: keyCheckValue(config.issuerSeed), IP_HASH_SECRET: keyCheckValue(config.ipHashKey) },
    documents: docs,
  };
}

export function parseManifest(text: string): BackupManifest {
  const manifest = JSON.parse(text) as BackupManifest;
  if (manifest?.format !== MANIFEST_FORMAT || !Array.isArray(manifest.documents)) {
    throw new Error(`Not a ${MANIFEST_FORMAT} file`);
  }
  return manifest;
}

/**
 * Secrets checks that need no decryption: does each configured legacy key and secret match
 * the one the backup was made with? Run before anything else, for a clear message.
 */
export function checkSecrets(config: AppConfig, manifest: BackupManifest): string[] {
  const problems: string[] = [];
  for (const { version, kcv } of manifest.keys.legacyKeyChecks) {
    const key = config.masterKeys.all.get(version);
    if (!key) problems.push(`legacy master key v${version} is needed (MASTER_KEY or PREVIOUS_MASTER_KEYS) but not configured`);
    else if (keyCheckValue(key) !== kcv) problems.push(`legacy master key v${version} does not match the one this backup was made with`);
  }
  if (keyCheckValue(config.issuerSeed) !== manifest.secretChecks.ISSUER_SIGNING_SEED) {
    problems.push('ISSUER_SIGNING_SEED differs from the backup: issued credentials would verify as invalid');
  }
  if (keyCheckValue(config.ipHashKey) !== manifest.secretChecks.IP_HASH_SECRET) {
    problems.push('IP_HASH_SECRET differs from the backup: visitor hashes in the access log would no longer match');
  }
  const providers = new Set(manifest.keys.storedKeys.map((k) => `${k.provider} ${k.kmsKeyName}`));
  if (providers.size > 0 && config.env.KEY_PROVIDER !== 'env' && config.env.KEY_PROVIDER !== manifest.keys.provider) {
    problems.push(`the backup's keys are protected by ${manifest.keys.provider}, but KEY_PROVIDER is ${config.env.KEY_PROVIDER}`);
  }
  return problems;
}

export interface RestoreReport {
  ok: boolean;
  secretProblems: string[];
  documents: { checked: number; failed: Array<{ id: string; stage: 'key' | 'storage' | 'decrypt' | 'hash' | 'metadata' }> };
  claims: { checked: number; failed: string[] };
  credentials: { checked: number; failed: string[] };
  linkCopies: { checked: number; unreadable: string[] };
  manifest: null | { missing: string[]; changed: string[]; extra: number; migrationsMissing: string[] };
}

/**
 * The restore drill. Decrypts every active document's file (AES-GCM tag + SHA-256 of the
 * plaintext), every field value and disclosure, every credential and every link copy,
 * and compares the files with the manifest. Plaintext is checked and discarded at once;
 * nothing is written (the CLI runs it in a READ ONLY transaction) and nothing is logged
 * except document ids.
 */
export async function verifyRestore(deps: {
  config: AppConfig;
  prisma: Db;
  storage: ObjectStorage;
  manifest?: BackupManifest;
}): Promise<RestoreReport> {
  const { config, prisma, storage, manifest } = deps;
  const report: RestoreReport = {
    ok: false,
    secretProblems: manifest ? checkSecrets(config, manifest) : [],
    documents: { checked: 0, failed: [] },
    claims: { checked: 0, failed: [] },
    credentials: { checked: 0, failed: [] },
    linkCopies: { checked: 0, unreadable: [] },
    manifest: null,
  };
  const seen = new Map<string, string>();

  let after: string | undefined;
  for (;;) {
    const batch = await prisma.document.findMany({
      where: { deletedAt: null, ...(after ? { id: { gt: after } } : {}) },
      include: { key: true, claims: true, credential: true },
      orderBy: { id: 'asc' },
      take: 50,
    });
    if (batch.length === 0) break;
    for (const doc of batch) {
      report.documents.checked++;
      if (!doc.key) {
        report.documents.failed.push({ id: doc.id, stage: 'key' });
        continue;
      }
      let dek: Buffer;
      try {
        dek = unwrapDataKey(config, doc.key, doc.id);
      } catch {
        report.documents.failed.push({ id: doc.id, stage: 'key' });
        continue;
      }
      try {
        let ciphertext: Buffer;
        try {
          ciphertext = await storage.get(doc.storageKey);
        } catch {
          report.documents.failed.push({ id: doc.id, stage: 'storage' });
          continue;
        }
        seen.set(doc.id, sha256Hex(ciphertext));
        let plaintext: Buffer;
        try {
          plaintext = decrypt(dek, { ciphertext, iv: Buffer.from(doc.encIv), tag: Buffer.from(doc.encTag) }, fileAad(doc.id, doc.ownerId));
        } catch {
          report.documents.failed.push({ id: doc.id, stage: 'decrypt' });
          continue;
        }
        const expected = openSha256(dek, doc);
        const hashOk = expected !== null && sha256Hex(plaintext) === expected;
        // E3: sealed title and field labels must open with the same key.
        if (doc.titleEncrypted) {
          try {
            open(dek, doc.titleEncrypted, titleAad(doc.id)).fill(0);
          } catch {
            report.documents.failed.push({ id: doc.id, stage: 'metadata' });
          }
        }
        plaintext.fill(0);
        if (!hashOk) report.documents.failed.push({ id: doc.id, stage: 'hash' });

        for (const claim of doc.claims) {
          report.claims.checked++;
          try {
            open(dek, claim.valueEncrypted, claimAad(doc.id, claim.claimKey, 'value')).fill(0);
            if (claim.labelEncrypted) open(dek, claim.labelEncrypted, claimLabelAad(doc.id, claim.claimKey)).fill(0);
            if (claim.disclosureEncrypted) open(dek, claim.disclosureEncrypted, claimAad(doc.id, claim.claimKey, 'disclosure')).fill(0);
          } catch {
            report.claims.failed.push(claim.id);
          }
        }
        if (doc.credential) {
          report.credentials.checked++;
          try {
            open(dek, doc.credential.credentialEncrypted, credentialAad(doc.id)).fill(0);
          } catch {
            report.credentials.failed.push(doc.id);
          }
        }
      } finally {
        dek.fill(0);
      }
    }
    after = batch[batch.length - 1]!.id;
  }

  let afterLink: string | undefined;
  for (;;) {
    const links = await prisma.sharingLink.findMany({
      where: afterLink ? { id: { gt: afterLink } } : {},
      select: { id: true, tokenEncrypted: true },
      orderBy: { id: 'asc' },
      take: 500,
    });
    if (links.length === 0) break;
    for (const link of links) {
      report.linkCopies.checked++;
      try {
        decryptToken({ config }, link.id, link.tokenEncrypted);
      } catch {
        report.linkCopies.unreadable.push(link.id);
      }
    }
    afterLink = links[links.length - 1]!.id;
  }

  if (manifest) {
    const missing: string[] = [];
    const changed: string[] = [];
    for (const entry of manifest.documents) {
      const restored = seen.get(entry.id);
      if (restored === undefined) {
        if (!report.documents.failed.some((f) => f.id === entry.id)) missing.push(entry.id);
      } else if (restored !== entry.ciphertextSha256) {
        changed.push(entry.id);
      }
    }
    const inManifest = new Set(manifest.documents.map((d) => d.id));
    const migrations = await appliedMigrations(prisma);
    report.manifest = {
      missing,
      changed,
      extra: [...seen.keys()].filter((id) => !inManifest.has(id)).length,
      migrationsMissing: manifest.migrations.filter((m) => !migrations.includes(m)),
    };
  }

  report.ok =
    report.secretProblems.length === 0 &&
    report.documents.failed.length === 0 &&
    report.claims.failed.length === 0 &&
    report.credentials.failed.length === 0 &&
    report.linkCopies.unreadable.length === 0 &&
    (!report.manifest ||
      (report.manifest.missing.length === 0 && report.manifest.changed.length === 0 && report.manifest.migrationsMissing.length === 0));
  return report;
}

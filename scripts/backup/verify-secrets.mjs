/**
 * Proves that saved copies of the TrustPass secrets really open a restored backup.
 *
 *   node verify-secrets.mjs <export.json>   (secrets on standard input, one per line:
 *                                            MASTER_KEY, then ISSUER_SIGNING_SEED; empty = skip)
 *
 * <export.json> is produced by trustpass-backup-drill.sh from the restored copy (RAM only).
 * Uses Node's built-in crypto only. Never prints, logs or writes a secret or any decrypted data:
 * the output is counts and yes/no answers. Exit code 0 = every check passed.
 *
 * What is proven:
 *  - MASTER_KEY: re-derives the key-encryption and link-token keys exactly as the server does
 *    (HKDF-SHA256, salt "trustpass", info "kek:v<n>" / "link-token:v<n>"), unwraps every document
 *    key, decrypts every stored file and checks it against its SHA-256 (sealed or legacy plain),
 *    opens every sealed title, and decrypts every share-link copy and checks it against its hash.
 *  - ISSUER_SIGNING_SEED: derives the Ed25519 key and checks it equals the issuer public key
 *    stored in the backup.
 * IP_HASH_SECRET cannot be proven offline (no stored value depends on it alone).
 */
import { createDecipheriv, createHash, createPrivateKey, createPublicKey, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';

const [exportPath] = process.argv.slice(2);
if (!exportPath) {
  console.error('usage: node verify-secrets.mjs <export.json>');
  process.exit(2);
}
const data = JSON.parse(readFileSync(exportPath, 'utf8'));
const lines = readFileSync(0, 'utf8').split('\n');
const masterKey = (lines[0] ?? '').replace(/\r$/, '');
const issuerSeed = (lines[1] ?? '').replace(/\r$/, '');

const derive = (secret, label) => Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.from('trustpass'), Buffer.from(label), 32));
const hex = (v) => (v == null ? null : Buffer.from(String(v).replace(/^\\x/, ''), 'hex'));
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
function gcmOpen(key, iv, tag, ciphertext, aad) {
  const d = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  d.setAAD(Buffer.from(aad, 'utf8'));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ciphertext), d.final()]);
}
const openSealed = (key, blob, aad) => gcmOpen(key, blob.subarray(0, 12), blob.subarray(12, 28), blob.subarray(28), aad);

const result = { masterKey: null, issuerSeed: null, ipHashSecret: 'not provable offline (only affects visitor statistics)' };
let ok = true;

if (masterKey) {
  const r = { documents: 0, filesDecrypted: 0, hashesMatched: 0, titlesOpened: 0, deletedSkipped: 0, linkTokens: 0, linkTokensMatched: 0, kmsManagedKeys: data.kmsKeys ?? 0, failures: [] };
  let keyFailures = 0;
  const keks = new Map();
  const kek = (v) => keks.get(v) ?? keks.set(v, derive(masterKey, `kek:v${v}`)).get(v);
  for (const doc of data.documents ?? []) {
    if (doc.deleted_at) {
      r.deletedSkipped++;
      continue;
    }
    r.documents++;
    const k = doc.key;
    if (!k) {
      r.failures.push(`${doc.id.slice(0, 8)}: no key`);
      continue;
    }
    let dek;
    try {
      dek = gcmOpen(kek(k.kek_version), hex(k.wrap_iv), hex(k.wrap_tag), hex(k.wrapped_dek), `dek|${doc.id}`);
    } catch {
      r.failures.push(`${doc.id.slice(0, 8)}: document key does not open with this MASTER_KEY (kek v${k.kek_version})`);
      keyFailures++;
      continue;
    }
    try {
      if (doc.file) {
        const plain = gcmOpen(dek, hex(doc.enc_iv), hex(doc.enc_tag), hex(doc.file), `file|${doc.id}|${doc.owner_id}`);
        r.filesDecrypted++;
        const expected = doc.sha256_encrypted ? openSealed(dek, hex(doc.sha256_encrypted), `sha256|${doc.id}`).toString('utf8') : doc.plaintext_sha256;
        if (expected && sha256(plain) === expected) r.hashesMatched++;
        else r.failures.push(`${doc.id.slice(0, 8)}: file SHA-256 mismatch`);
        plain.fill(0);
      }
      if (doc.title_encrypted) {
        openSealed(dek, hex(doc.title_encrypted), `title|${doc.id}`).fill(0);
        r.titlesOpened++;
      }
    } catch {
      r.failures.push(`${doc.id.slice(0, 8)}: file or title does not decrypt`);
    } finally {
      dek.fill(0);
    }
  }
  for (const link of data.links ?? []) {
    r.linkTokens++;
    let opened = false;
    for (const v of data.linkTokenVersions ?? [1]) {
      try {
        const token = openSealed(derive(masterKey, `link-token:v${v}`), hex(link.token_encrypted), `link-token|${link.id}`).toString('utf8');
        if (sha256(token) === link.token_hash) {
          r.linkTokensMatched++;
          opened = true;
          break;
        }
      } catch {
        /* try the next version */
      }
    }
    if (!opened) {
      r.failures.push(`link ${link.id.slice(0, 8)}: copy does not open with this MASTER_KEY`);
      keyFailures++;
    }
  }
  if (r.kmsManagedKeys > 0) r.note = 'This backup also has KMS-protected keys: those need the KMS, not MASTER_KEY.';
  // A wrong key fails at the key step; a right key with a failing file means the backup is damaged.
  r.verdict = r.documents === 0 ? 'NOTHING TO CHECK' : keyFailures > 0 ? 'MASTER_KEY WRONG' : r.failures.length > 0 ? 'MASTER_KEY OK, BACKUP DAMAGED' : 'MASTER_KEY OK';
  if (r.verdict !== 'MASTER_KEY OK') ok = false;
  result.masterKey = r;
}

if (issuerSeed) {
  const seed = derive(issuerSeed, 'issuer-ed25519-seed');
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const x = createPublicKey(priv).export({ format: 'jwk' }).x;
  seed.fill(0);
  const stored = (data.issuers ?? []).map((i) => i?.x).filter(Boolean);
  const match = stored.includes(x);
  result.issuerSeed = { issuersInBackup: stored.length, verdict: match ? 'ISSUER_SIGNING_SEED OK' : 'ISSUER_SIGNING_SEED WRONG' };
  if (!match) ok = false;
}

console.log(JSON.stringify(result, null, 2));
process.exit(ok ? 0 : 1);

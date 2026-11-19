/**
 * Proves that saved copies of the TrustPass secrets really recover the documents of a restored
 * backup: every document key, file, field and credential is decrypted and checked.
 *
 *   node verify-secrets.mjs <export.json>   (secrets on standard input, one per line:
 *                                            MASTER_KEY, then ISSUER_SIGNING_SEED; empty = skip)
 *
 * <export.json> is produced from the restored copy (RAM only) by trustpass-backup-drill.sh or
 * trustpass-recovery-check.sh. Node's built-in crypto only; no network use.
 *
 * Never prints, logs or writes a secret or any decrypted content. Output: counts, short document
 * ids (first 8 characters), sizes, file types and yes/no answers. Decrypted bytes stay in memory
 * and are overwritten after each check. Exit code 0 = every check passed.
 *
 * What is proven with MASTER_KEY:
 *  - the key-encryption key (HKDF-SHA256, salt "trustpass", info "kek:v<n>") unwraps every
 *    document key (AES-256-GCM, AAD "dek|<id>");
 *  - every stored file decrypts (AAD "file|<id>|<owner>"), matches its SHA-256 (sealed or legacy
 *    plain) and starts like a PDF, PNG or JPEG; a credential's file also matches its public hash;
 *  - every field value, label (if sealed), disclosure, sealed title and signed credential opens;
 *  - every page of every redacted copy (Smart Selective Encryption) opens with its document key
 *    (AAD "redacted|<doc>|<link>|<page>") and is a PNG image;
 *  - every share-link copy opens and matches its stored hash: with the link-token key
 *    (info "link-token:v<n>", since E2) or, for links created before E2, with the
 *    key-encryption key itself (info "kek:v<n>"), exactly as the server reads them.
 * With ISSUER_SIGNING_SEED: the derived Ed25519 key equals the issuer public key in the backup.
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
const tryOpen = (key, blob, aad) => {
  try {
    openSealed(key, blob, aad).fill(0);
    return true;
  } catch {
    return false;
  }
};
function fileType(b) {
  if (b.subarray(0, 5).toString('latin1') === '%PDF-') return 'PDF';
  if (b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'PNG';
  if (b.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) return 'JPEG';
  return 'unknown';
}

const claimsByDoc = new Map();
for (const c of data.claims ?? []) claimsByDoc.set(c.document_id, [...(claimsByDoc.get(c.document_id) ?? []), c]);
const credentialByDoc = new Map((data.credentials ?? []).map((c) => [c.document_id, c]));
const redactedByDoc = new Map();
for (const p of data.redactedPages ?? []) redactedByDoc.set(p.document_id, [...(redactedByDoc.get(p.document_id) ?? []), p]);

const result = { masterKey: null, issuerSeed: null, ipHashSecret: 'not provable offline (only affects visitor statistics)' };
let ok = true;

if (masterKey) {
  const r = {
    documents: 0,
    recovered: 0,
    filesDecrypted: 0,
    hashesMatched: 0,
    fieldsOpened: 0,
    fieldsTotal: 0,
    credentialsOpened: 0,
    titlesOpened: 0,
    deletedSkipped: 0,
    redactedPages: 0,
    redactedPagesOpened: 0,
    linkTokens: 0,
    linkTokensMatched: 0,
    linkTokensLegacy: 0,
    kmsManagedKeys: data.kmsKeys ?? 0,
    perDocument: [],
    failures: [],
  };
  let keyFailures = 0;
  const keks = new Map();
  const kek = (v) => keks.get(v) ?? keks.set(v, derive(masterKey, `kek:v${v}`)).get(v);

  for (const doc of data.documents ?? []) {
    if (doc.deleted_at) {
      r.deletedSkipped++;
      continue;
    }
    r.documents++;
    const id = String(doc.id).slice(0, 8);
    const line = { id, kind: doc.kind, mimeType: doc.mime_type, size: doc.size_bytes, key: false, file: null, sha256: false, fields: '0/0', credential: null };
    r.perDocument.push(line);
    const k = doc.key;
    if (!k) {
      r.failures.push(`${id}: no document key in the backup`);
      continue;
    }
    let dek;
    try {
      dek = gcmOpen(kek(k.kek_version), hex(k.wrap_iv), hex(k.wrap_tag), hex(k.wrapped_dek), `dek|${doc.id}`);
      line.key = true;
    } catch {
      r.failures.push(`${id}: document key does not open with this MASTER_KEY (key version ${k.kek_version})`);
      keyFailures++;
      continue;
    }
    let docOk = true;
    try {
      if (doc.file) {
        try {
          const plain = gcmOpen(dek, hex(doc.enc_iv), hex(doc.enc_tag), hex(doc.file), `file|${doc.id}|${doc.owner_id}`);
          r.filesDecrypted++;
          line.file = fileType(plain);
          const digest = sha256(plain);
          plain.fill(0);
          const expected = doc.sha256_encrypted ? openSealed(dek, hex(doc.sha256_encrypted), `sha256|${doc.id}`).toString('utf8') : doc.plaintext_sha256;
          line.sha256 = Boolean(expected) && digest === expected;
          if (line.sha256) r.hashesMatched++;
          else {
            r.failures.push(`${id}: decrypted file does not match its SHA-256`);
            docOk = false;
          }
          if (line.file === 'unknown') {
            r.failures.push(`${id}: decrypted file is not a PDF, PNG or JPEG`);
            docOk = false;
          }
          const cred = credentialByDoc.get(doc.id);
          if (cred && cred.document_hash !== digest) {
            r.failures.push(`${id}: certificate does not match its public credential hash`);
            docOk = false;
          }
        } catch {
          r.failures.push(`${id}: file does not decrypt (damaged or altered)`);
          docOk = false;
        }
      } else {
        r.failures.push(`${id}: encrypted file missing from the backup`);
        docOk = false;
      }

      if (doc.title_encrypted) {
        if (tryOpen(dek, hex(doc.title_encrypted), `title|${doc.id}`)) r.titlesOpened++;
        else {
          r.failures.push(`${id}: title does not decrypt`);
          docOk = false;
        }
      }

      const claims = claimsByDoc.get(doc.id) ?? [];
      let opened = 0;
      for (const c of claims) {
        const base = `claim|${doc.id}|${c.claim_key}`;
        const good =
          tryOpen(dek, hex(c.value_encrypted), `${base}|value`) &&
          (!c.disclosure_encrypted || tryOpen(dek, hex(c.disclosure_encrypted), `${base}|disclosure`)) &&
          (!c.label_encrypted || tryOpen(dek, hex(c.label_encrypted), `${base}|label`));
        if (good) opened++;
      }
      line.fields = `${opened}/${claims.length}`;
      r.fieldsOpened += opened;
      r.fieldsTotal += claims.length;
      if (opened !== claims.length) {
        r.failures.push(`${id}: ${claims.length - opened} field(s) do not decrypt`);
        docOk = false;
      }

      for (const p of redactedByDoc.get(doc.id) ?? []) {
        r.redactedPages++;
        try {
          if (!p.data) throw new Error('missing');
          const page = gcmOpen(dek, hex(p.enc_iv), hex(p.enc_tag), hex(p.data), `redacted|${doc.id}|${p.link_id}|${p.page_index}`);
          const png = fileType(page) === 'PNG';
          page.fill(0);
          if (!png) throw new Error('not png');
          r.redactedPagesOpened++;
        } catch {
          r.failures.push(`${id}: page ${p.page_index + 1} of a redacted copy (link ${String(p.link_id).slice(0, 8)}) does not decrypt`);
          docOk = false;
        }
      }

      const cred = credentialByDoc.get(doc.id);
      if (cred) {
        line.credential = tryOpen(dek, hex(cred.credential_encrypted), `credential|${doc.id}`);
        if (line.credential) r.credentialsOpened++;
        else {
          r.failures.push(`${id}: signed credential does not decrypt`);
          docOk = false;
        }
      }
    } finally {
      dek.fill(0);
    }
    if (docOk) r.recovered++;
  }

  // Same order as the server (modules/sharing.ts decryptToken): link-token keys first, then the
  // key-encryption keys, which sealed every link created before E2.
  const kekVersions = [...new Set([1, ...(data.documents ?? []).map((d) => d.key?.kek_version).filter((v) => Number.isInteger(v))])];
  const linkKeys = (data.linkTokenVersions ?? [1]).map((v) => derive(masterKey, `link-token:v${v}`));
  const candidates = [
    ...linkKeys.map((k) => ({ legacy: false, key: () => k })),
    ...kekVersions.map((v) => ({ legacy: true, key: () => kek(v) })),
  ];
  for (const link of data.links ?? []) {
    r.linkTokens++;
    let opened = false;
    for (const c of candidates) {
      try {
        const token = openSealed(c.key(), hex(link.token_encrypted), `link-token|${link.id}`);
        const match = sha256(token.toString('utf8')) === link.token_hash;
        token.fill(0);
        if (match) {
          r.linkTokensMatched++;
          if (c.legacy) r.linkTokensLegacy++;
          opened = true;
          break;
        }
      } catch {
        /* try the next key */
      }
    }
    if (!opened) {
      r.failures.push(`link ${String(link.id).slice(0, 8)}: copy does not open with this MASTER_KEY`);
      // Only a wrong key if no document key opened either; otherwise this row is damaged.
      if (r.recovered === 0) keyFailures++;
    }
  }
  for (const k of keks.values()) k.fill(0);
  for (const k of linkKeys) k.fill(0);

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

import { createVerify, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config';
import { KeySet } from '../../src/lib/keyset';
import { crc32c } from '../../src/lib/kms/crc32c';
import { FakeKms, loadOrCreateFakeKmsKey } from '../../src/lib/kms/fake';
import { GcpKms, parseServiceAccount } from '../../src/lib/kms/gcp';
import { KmsError } from '../../src/lib/kms/types';
import { TEST_SECRETS } from '../helpers';

const tempDir = () => mkdtempSync(path.join(tmpdir(), 'trustpass-kms-unit-'));

describe('CRC32C', () => {
  it('matches the published check values', () => {
    expect(crc32c(Buffer.from('123456789'))).toBe(0xe3069283);
    expect(crc32c(Buffer.alloc(32))).toBe(0x8a9136aa); // RFC 3720, 32 bytes of zeros
  });
});

describe('fake KMS', () => {
  it('round-trips key material and binds it to its context', async () => {
    const kms = new FakeKms({ key: randomBytes(32) });
    const kek = randomBytes(32);
    const blob = await kms.encrypt(kek, 'trustpass-key|kek|v1');
    expect(blob.includes(kek)).toBe(false);
    expect((await kms.decrypt(blob, 'trustpass-key|kek|v1')).equals(kek)).toBe(true);
    await expect(kms.decrypt(blob, 'trustpass-key|kek|v2')).rejects.toBeInstanceOf(KmsError);
    const tampered = Buffer.from(blob);
    tampered[tampered.length - 1]! ^= 1;
    await expect(kms.decrypt(tampered, 'trustpass-key|kek|v1')).rejects.toBeInstanceOf(KmsError);
  });

  it('a different root key cannot decrypt', async () => {
    const blob = await new FakeKms({ key: randomBytes(32) }).encrypt(randomBytes(32), 'ctx');
    await expect(new FakeKms({ key: randomBytes(32) }).decrypt(blob, 'ctx')).rejects.toThrow(/wrong root key/);
  });

  it('creates its key file once, with random content and owner-only permissions', async () => {
    const file = path.join(tempDir(), 'nested', 'root.key');
    const a = new FakeKms({ keyFile: file });
    const b = new FakeKms({ keyFile: file });
    const kek = randomBytes(32);
    expect((await b.decrypt(await a.encrypt(kek, 'ctx'), 'ctx')).equals(kek)).toBe(true);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(Buffer.from(readFileSync(file, 'utf8'), 'base64')).toHaveLength(32);
    const other = path.join(tempDir(), 'root.key');
    expect(loadOrCreateFakeKmsKey(other).equals(loadOrCreateFakeKmsKey(file))).toBe(false);
  });

  it('rejects a damaged key file', () => {
    const file = path.join(tempDir(), 'bad.key');
    writeFileSync(file, 'not-a-key');
    expect(() => new FakeKms({ keyFile: file })).toThrow(/32-byte/);
  });
});

// ---------------------------------------------------------------------------
// Google Cloud KMS over REST, against a mocked network (CI never calls Google)
// ---------------------------------------------------------------------------

const KEY_NAME = 'projects/trustpass-kms/locations/europe-west3/keyRings/trustpass/cryptoKeys/trustpass-root-kek';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const SERVICE_ACCOUNT = {
  type: 'service_account',
  project_id: 'trustpass-kms',
  private_key_id: 'abc123',
  private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  client_email: 'trustpass-render@trustpass-kms.iam.gserviceaccount.com',
  token_uri: 'https://oauth2.googleapis.com/token',
};

interface Call {
  url: string;
  headers: Record<string, string>;
  body: string;
}

/** A tiny in-memory "Cloud KMS": AES-GCM with a hidden key, CRC32C on every field, like the real API. */
function mockGoogle(options: { failures?: number[]; tokenTtl?: number; corrupt?: 'ciphertext' | 'plaintext'; unverified?: boolean } = {}) {
  const calls: Call[] = [];
  const failures = [...(options.failures ?? [])];
  const inner = new FakeKms({ key: randomBytes(32) });
  let tokens = 0;
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const headers = Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]));
    const body = String(init?.body ?? '');
    calls.push({ url, headers, body });
    const status = failures.shift();
    if (status) return new Response('{"error":{"message":"simulated"}}', { status });
    if (url === 'https://oauth2.googleapis.com/token') {
      tokens++;
      return Response.json({ access_token: `token-${tokens}`, expires_in: options.tokenTtl ?? 3600, token_type: 'Bearer' });
    }
    const req = JSON.parse(body) as Record<string, string>;
    const aad = Buffer.from(req.additionalAuthenticatedData!, 'base64');
    expect(Number(req.additionalAuthenticatedDataCrc32c)).toBe(crc32c(aad));
    if (url.endsWith(':encrypt')) {
      const plaintext = Buffer.from(req.plaintext!, 'base64');
      expect(Number(req.plaintextCrc32c)).toBe(crc32c(plaintext));
      const ct = await inner.encrypt(plaintext, aad.toString('utf8'));
      return Response.json({
        name: `${KEY_NAME}/cryptoKeyVersions/1`,
        ciphertext: ct.toString('base64'),
        ciphertextCrc32c: String(crc32c(ct) ^ (options.corrupt === 'ciphertext' ? 1 : 0)),
        verifiedPlaintextCrc32c: !options.unverified,
        verifiedAdditionalAuthenticatedDataCrc32c: true,
      });
    }
    const ct = Buffer.from(req.ciphertext!, 'base64');
    expect(Number(req.ciphertextCrc32c)).toBe(crc32c(ct));
    let pt: Buffer;
    try {
      pt = await inner.decrypt(ct, aad.toString('utf8'));
    } catch {
      return new Response('{"error":{"status":"INVALID_ARGUMENT"}}', { status: 400 });
    }
    return Response.json({ plaintext: pt.toString('base64'), plaintextCrc32c: String(crc32c(pt) ^ (options.corrupt === 'plaintext' ? 1 : 0)) });
  }) as typeof fetch;
  return { calls, fetchFn, tokenCount: () => tokens };
}

function gcp(fetchFn: typeof fetch, now: () => number = Date.now) {
  return new GcpKms({ keyName: KEY_NAME, credentials: parseServiceAccount(JSON.stringify(SERVICE_ACCOUNT)), fetch: fetchFn, now, sleep: async () => {} });
}

describe('Google Cloud KMS provider', () => {
  it('reads the service account as JSON or base64 and refuses unsafe ones without echoing them', () => {
    const json = JSON.stringify(SERVICE_ACCOUNT);
    expect(parseServiceAccount(json).clientEmail).toBe(SERVICE_ACCOUNT.client_email);
    expect(parseServiceAccount(Buffer.from(json).toString('base64')).privateKeyId).toBe('abc123');
    const bad = (patch: object) => () => parseServiceAccount(JSON.stringify({ ...SERVICE_ACCOUNT, ...patch }));
    expect(bad({ token_uri: 'https://attacker.example/token' })).toThrow(/token_uri/);
    expect(bad({ type: 'authorized_user' })).toThrow(/service account/);
    expect(bad({ client_email: 'someone@example.com' })).toThrow(/client_email/);
    expect(bad({ private_key: 'not a key' })).toThrow(/private_key/);
    let message = '';
    try {
      parseServiceAccount('{"type":"service_account","client_email":"x@y.iam.gserviceaccount.com","private_key":"SECRET-MATERIAL"}');
    } catch (err) {
      message = String(err);
    }
    expect(message).toMatch(/private_key could not be read/);
    expect(message).not.toContain('SECRET-MATERIAL');
    expect(() => new GcpKms({ keyName: 'projects/x', credentials: parseServiceAccount(json) })).toThrow(/GCP_KMS_KEY_NAME/);
  });

  it('signs a correct JWT, encrypts and decrypts with checksums, and binds the context', async () => {
    const google = mockGoogle();
    const kms = gcp(google.fetchFn);
    const kek = randomBytes(32);
    const blob = await kms.encrypt(kek, 'trustpass-key|kek|v1');
    expect((await kms.decrypt(blob, 'trustpass-key|kek|v1')).equals(kek)).toBe(true);
    await expect(kms.decrypt(blob, 'trustpass-key|kek|v9')).rejects.toThrow(/HTTP 400/);

    const tokenCall = google.calls[0]!;
    expect(tokenCall.url).toBe('https://oauth2.googleapis.com/token');
    const form = new URLSearchParams(tokenCall.body);
    expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
    const [header, claims, signature] = form.get('assertion')!.split('.');
    const verifier = createVerify('RSA-SHA256');
    verifier.update(`${header}.${claims}`);
    expect(verifier.verify(publicKey, Buffer.from(signature!, 'base64url'))).toBe(true);
    expect(JSON.parse(Buffer.from(header!, 'base64url').toString())).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'abc123' });
    const payload = JSON.parse(Buffer.from(claims!, 'base64url').toString());
    expect(payload).toMatchObject({ iss: SERVICE_ACCOUNT.client_email, aud: 'https://oauth2.googleapis.com/token', scope: 'https://www.googleapis.com/auth/cloudkms' });
    expect(payload.exp - payload.iat).toBe(3600);

    const encryptCall = google.calls[1]!;
    expect(encryptCall.url).toBe(`https://cloudkms.googleapis.com/v1/${KEY_NAME}:encrypt`);
    expect(encryptCall.headers.authorization).toBe('Bearer token-1');
    expect(encryptCall.body).not.toContain(kek.toString('hex'));
  });

  it('reuses the access token until shortly before it expires', async () => {
    let clock = 1_800_000_000_000;
    const google = mockGoogle();
    const kms = gcp(google.fetchFn, () => clock);
    await kms.encrypt(randomBytes(32), 'a');
    await kms.encrypt(randomBytes(32), 'b');
    expect(google.tokenCount()).toBe(1);
    clock += 3600_000 - 30_000; // inside the 60-second safety margin
    await kms.encrypt(randomBytes(32), 'c');
    expect(google.tokenCount()).toBe(2);
  });

  it('retries 429 and 5xx, but not permission errors (with a helpful hint)', async () => {
    const flaky = mockGoogle({ failures: [503, 429] });
    await expect(gcp(flaky.fetchFn).encrypt(randomBytes(32), 'x')).resolves.toBeInstanceOf(Buffer);

    const denied = mockGoogle({ failures: [403] });
    await expect(gcp(denied.fetchFn).encrypt(randomBytes(32), 'x')).rejects.toThrow(
      /HTTP 403: check that the service account has the Cloud KMS CryptoKey Encrypter\/Decrypter role/,
    );
    expect(denied.calls).toHaveLength(1); // not retried

    const down = mockGoogle({ failures: [500, 500, 500, 500] });
    await expect(gcp(down.fetchFn).encrypt(randomBytes(32), 'x')).rejects.toThrow(/HTTP 500/);
    expect(down.calls).toHaveLength(3); // first try + 2 retries
  });

  it('gets a new token once when Google answers 401', async () => {
    const google = mockGoogle();
    let rejectNext = true;
    const fetchFn = ((url: string | URL | Request, init?: RequestInit) => {
      if (String(url).includes(':encrypt') && rejectNext) {
        rejectNext = false;
        return Promise.resolve(new Response('{}', { status: 401 }));
      }
      return google.fetchFn(url, init);
    }) as typeof fetch;
    await expect(gcp(fetchFn).encrypt(randomBytes(32), 'x')).resolves.toBeInstanceOf(Buffer);
    expect(google.tokenCount()).toBe(2);
  });

  it('detects corruption in transit and unconfirmed checksums', async () => {
    await expect(gcp(mockGoogle({ corrupt: 'ciphertext' }).fetchFn).encrypt(randomBytes(32), 'x')).rejects.toThrow(/corrupted/);
    await expect(gcp(mockGoogle({ unverified: true }).fetchFn).encrypt(randomBytes(32), 'x')).rejects.toThrow(/checksum/);
    const google = mockGoogle({ corrupt: 'plaintext' });
    const kms = gcp(google.fetchFn);
    const blob = await kms.encrypt(randomBytes(32), 'x');
    await expect(kms.decrypt(blob, 'x')).rejects.toThrow(/corrupted/);
  });
});

// ---------------------------------------------------------------------------
// Configuration rules
// ---------------------------------------------------------------------------

describe('key provider configuration', () => {
  const prod = { NODE_ENV: 'production', DATABASE_URL: 'postgres://x', APP_URL: 'https://trustpass.example', ...TEST_SECRETS };

  it('refuses the fake KMS in production', () => {
    expect(() => loadConfig({ ...prod, KEY_PROVIDER: 'fake-kms' })).toThrow(/fake-kms is refused in production/);
  });

  it('needs the key name and the service account for Google Cloud KMS', () => {
    expect(() => loadConfig({ ...prod, KEY_PROVIDER: 'gcp-kms' })).toThrow(/GCP_KMS_KEY_NAME and GCP_SERVICE_ACCOUNT_JSON/);
    expect(() => loadConfig({ ...prod, KEY_PROVIDER: 'gcp-kms', GCP_KMS_KEY_NAME: 'my-key', GCP_SERVICE_ACCOUNT_JSON: '{}' })).toThrow(/GCP_KMS_KEY_NAME must look like/);
    const config = loadConfig({ ...prod, MASTER_KEY: undefined, KEY_PROVIDER: 'gcp-kms', GCP_KMS_KEY_NAME: KEY_NAME, GCP_SERVICE_ACCOUNT_JSON: JSON.stringify(SERVICE_ACCOUNT) });
    expect(config.masterKeys.hasCurrent).toBe(false); // loaded from KMS at start-up, never from the environment
    expect(() => config.masterKeys.current).toThrow(/not loaded yet/);
  });

  it('needs MASTER_KEY only for the legacy env provider', () => {
    expect(() => loadConfig({ ...prod, MASTER_KEY: undefined })).toThrow(/MASTER_KEY: required when KEY_PROVIDER=env/);
    const legacy = loadConfig({ ...prod, KEY_PROVIDER: 'env' });
    expect(legacy.masterKeys.current.version).toBe(1);
    expect(legacy.legacyKekVersions).toEqual([1]);
    // Link tokens get their own key, never the key-encryption key.
    expect(legacy.linkTokenKeys.current.key.equals(legacy.masterKeys.current.key)).toBe(false);
  });

  it('keeps one key per version and refuses conflicting duplicates', () => {
    const set = new KeySet('test');
    const key = randomBytes(32);
    set.add(1, key);
    set.add(1, Buffer.from(key));
    expect(() => set.add(1, randomBytes(32))).toThrow(/Two different/);
    expect(() => set.add(2, randomBytes(16))).toThrow(/32 bytes/);
  });
});

import { createCipheriv, createDecipheriv, createVerify, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { crc32c } from '../../src/lib/kms/crc32c';
import { GcpKms, parseServiceAccount } from '../../src/lib/kms/gcp';
import { createTestContext, resetDatabase, resetKeyring, testPrisma } from '../helpers';
import { defineKmsScenarios } from './gcp-kms-scenarios';

/**
 * The live Google Cloud KMS scenarios against a STRICT emulator of Google's REST API, so the
 * production code path (KEY_PROVIDER=gcp-kms, GcpKms, keyring, app, `keys` command) is exercised on
 * every CI run, not only when real credentials exist. Only the network endpoint is simulated; the
 * emulator refuses everything Google refuses:
 *  - OAuth 2.0 JWT bearer: RS256 signature checked with the service account's public key; iss, aud,
 *    scope, iat/exp (max 1 hour) checked; tokens expire.
 *  - KMS encrypt/decrypt: bearer token required; only the one key the service account may use
 *    (403 PERMISSION_DENIED otherwise); request CRC32C checked (400 on mismatch); AES-256-GCM with the
 *    additional authenticated data (decryption with another AAD fails, like Google's).
 *  - Responses carry name, ciphertextCrc32c / plaintextCrc32c and the verified* flags, as Google's do.
 */

const PROJECT = 'trustpass-emulated';
const KEY_NAME = `projects/${PROJECT}/locations/europe-west3/keyRings/trustpass/cryptoKeys/trustpass-test-kek`;
const CLIENT_EMAIL = `trustpass-ci@${PROJECT}.iam.gserviceaccount.com`;
const TOKEN_URI = 'https://oauth2.googleapis.com/token';

interface Emulator {
  fetch: typeof fetch;
  calls: { token: number; encrypt: number; decrypt: number; denied: number };
  serviceAccountJson: string;
}

function createEmulator(): Emulator {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rootKey = randomBytes(32);
  const tokens = new Map<string, number>(); // token -> expiry (ms)
  const calls = { token: 0, encrypt: 0, decrypt: 0, denied: 0 };
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const error = (status: number, reason: string) => json(status, { error: { code: status, status: reason, message: reason } });

  function verifyAssertion(assertion: string, pub: KeyObject): boolean {
    const [h, c, sig] = assertion.split('.');
    if (!h || !c || !sig) return false;
    const header = JSON.parse(Buffer.from(h, 'base64url').toString()) as { alg?: string };
    if (header.alg !== 'RS256') return false;
    const verifier = createVerify('RSA-SHA256');
    verifier.update(`${h}.${c}`);
    if (!verifier.verify(pub, Buffer.from(sig, 'base64url'))) return false;
    const claims = JSON.parse(Buffer.from(c, 'base64url').toString()) as { iss?: string; aud?: string; scope?: string; iat?: number; exp?: number };
    const now = Math.floor(Date.now() / 1000);
    return (
      claims.iss === CLIENT_EMAIL &&
      claims.aud === TOKEN_URI &&
      typeof claims.scope === 'string' &&
      claims.scope.split(' ').includes('https://www.googleapis.com/auth/cloudkms') &&
      typeof claims.iat === 'number' &&
      typeof claims.exp === 'number' &&
      claims.exp > now &&
      claims.exp - claims.iat <= 3600 &&
      Math.abs(claims.iat - now) < 300
    );
  }

  const emulated: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const body = typeof init?.body === 'string' ? init.body : '';
    if (url === TOKEN_URI) {
      calls.token++;
      const form = new URLSearchParams(body);
      if (form.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:jwt-bearer') return error(400, 'unsupported_grant_type');
      if (!verifyAssertion(form.get('assertion') ?? '', publicKey)) return error(400, 'invalid_grant');
      const token = randomBytes(24).toString('base64url');
      tokens.set(token, Date.now() + 3600_000);
      return json(200, { access_token: token, expires_in: 3599, token_type: 'Bearer' });
    }
    const m = url.match(/^https:\/\/cloudkms\.googleapis\.com\/v1\/(.+):(encrypt|decrypt)$/);
    if (!m) return error(404, 'NOT_FOUND');
    const headers = new Headers(init?.headers);
    const bearer = headers.get('authorization')?.replace(/^Bearer /, '') ?? '';
    if (!tokens.has(bearer) || tokens.get(bearer)! < Date.now()) return error(401, 'UNAUTHENTICATED');
    if (m[1] !== KEY_NAME) {
      calls.denied++;
      return error(403, 'PERMISSION_DENIED');
    }
    const req = JSON.parse(body) as Record<string, string>;
    const aad = Buffer.from(req.additionalAuthenticatedData ?? '', 'base64');
    if (req.additionalAuthenticatedDataCrc32c !== undefined && Number(req.additionalAuthenticatedDataCrc32c) !== crc32c(aad)) return error(400, 'INVALID_ARGUMENT');
    if (m[2] === 'encrypt') {
      calls.encrypt++;
      const plaintext = Buffer.from(req.plaintext ?? '', 'base64');
      if (Number(req.plaintextCrc32c) !== crc32c(plaintext)) return error(400, 'INVALID_ARGUMENT');
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', rootKey, iv);
      cipher.setAAD(aad);
      const ct = Buffer.concat([Buffer.from([1]), iv, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
      return json(200, {
        name: `${KEY_NAME}/cryptoKeyVersions/1`,
        ciphertext: ct.toString('base64'),
        ciphertextCrc32c: String(crc32c(ct)),
        verifiedPlaintextCrc32c: true,
        verifiedAdditionalAuthenticatedDataCrc32c: true,
        protectionLevel: 'SOFTWARE',
      });
    }
    calls.decrypt++;
    const ct = Buffer.from(req.ciphertext ?? '', 'base64');
    if (Number(req.ciphertextCrc32c) !== crc32c(ct)) return error(400, 'INVALID_ARGUMENT');
    try {
      if (ct[0] !== 1 || ct.length < 1 + 12 + 16) throw new Error('bad version');
      const decipher = createDecipheriv('aes-256-gcm', rootKey, ct.subarray(1, 13));
      decipher.setAAD(aad);
      decipher.setAuthTag(ct.subarray(ct.length - 16));
      const plaintext = Buffer.concat([decipher.update(ct.subarray(13, ct.length - 16)), decipher.final()]);
      return json(200, { plaintext: plaintext.toString('base64'), plaintextCrc32c: String(crc32c(plaintext)), usedPrimary: true, protectionLevel: 'SOFTWARE' });
    } catch {
      return error(400, 'INVALID_ARGUMENT');
    }
  };

  const serviceAccountJson = JSON.stringify({
    type: 'service_account',
    project_id: PROJECT,
    private_key_id: randomBytes(20).toString('hex'),
    private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    client_email: CLIENT_EMAIL,
    token_uri: TOKEN_URI,
  });
  return { fetch: emulated, calls, serviceAccountJson };
}

const emulator = createEmulator();
const realFetch = globalThis.fetch;

// Route only Google's two endpoints to the emulator; anything else would be a test bug.
vi.stubGlobal('fetch', ((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  if (url.startsWith('https://oauth2.googleapis.com/') || url.startsWith('https://cloudkms.googleapis.com/')) return emulator.fetch(input, init);
  return realFetch(input, init);
}) as typeof fetch);

defineKmsScenarios('Google Cloud KMS (emulated API, production code path)', true, () => ({ key: KEY_NAME, sa: emulator.serviceAccountJson }));

describe('Google Cloud KMS emulator: refusals reach the app the way Google sends them', () => {
  beforeAll(async () => {
    await resetDatabase(testPrisma());
    await resetKeyring(testPrisma());
  });
  afterAll(async () => {
    await resetDatabase(testPrisma());
    await resetKeyring(testPrisma());
    vi.unstubAllGlobals();
  });

  it('really talked to the emulator: signed sign-in, encrypt and decrypt calls happened', () => {
    expect(emulator.calls.token).toBeGreaterThan(0);
    expect(emulator.calls.encrypt).toBeGreaterThan(0);
    expect(emulator.calls.decrypt).toBeGreaterThan(0);
  });

  it('a service account without permission on the key: the app refuses to start', async () => {
    const otherKey = `projects/${PROJECT}/locations/europe-west3/keyRings/trustpass/cryptoKeys/someone-elses-key`;
    await expect(
      createTestContext({ KEY_PROVIDER: 'gcp-kms', GCP_KMS_KEY_NAME: otherKey, GCP_SERVICE_ACCOUNT_JSON: emulator.serviceAccountJson, MASTER_KEY: undefined, FAKE_KMS_KEY_FILE: undefined }),
    ).rejects.toThrow();
    expect(emulator.calls.denied).toBeGreaterThan(0);
  });

  it('a key file that Google would not accept (wrong private key) cannot sign in', async () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const forged = JSON.stringify({ ...JSON.parse(emulator.serviceAccountJson), private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() });
    const kms = new GcpKms({ keyName: KEY_NAME, credentials: parseServiceAccount(forged), retries: 0 });
    await expect(kms.encrypt(randomBytes(32), 'kek|v1')).rejects.toThrow();
  });

  it('checks the key version name in Google’s answer belongs to the configured key', async () => {
    const kms = new GcpKms({
      keyName: KEY_NAME,
      credentials: parseServiceAccount(emulator.serviceAccountJson),
      retries: 0,
      fetch: async (input, init) => {
        const res = await emulator.fetch(input, init);
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!url.endsWith(':encrypt')) return res;
        const body = (await res.json()) as Record<string, unknown>;
        return new Response(JSON.stringify({ ...body, name: `projects/x/locations/y/keyRings/z/cryptoKeys/other/cryptoKeyVersions/1` }), { status: 200 });
      },
    });
    await expect(kms.encrypt(randomBytes(32), 'kek|v1')).rejects.toThrow(/different key/);
  });
});

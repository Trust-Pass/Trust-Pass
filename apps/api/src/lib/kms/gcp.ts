import { createPrivateKey, createSign, type KeyObject } from 'node:crypto';
import { GCP_KMS_KEY_NAME_RE } from '../../config';
import { crc32c } from './crc32c';
import { KmsError, type KmsProvider } from './types';

/**
 * Google Cloud KMS over its REST API, using only Node's built-in fetch and crypto
 * (no extra dependency). Authentication: a service account key signs a short-lived
 * JWT, which Google exchanges for a one-hour access token (OAuth 2.0 JWT bearer flow).
 *
 * The service account should have exactly one role, Cloud KMS CryptoKey
 * Encrypter/Decrypter, granted on this one key. Every request and response carries a
 * CRC32C checksum, as Google recommends, so corruption in transit is detected.
 */
const TOKEN_URI = 'https://oauth2.googleapis.com/token';
const KMS_ENDPOINT = 'https://cloudkms.googleapis.com/v1/';
const SCOPE = 'https://www.googleapis.com/auth/cloudkms';

export interface GcpServiceAccount {
  clientEmail: string;
  privateKey: KeyObject;
  privateKeyId?: string;
}

/**
 * Accepts the service account JSON as-is or base64-encoded (easier to paste into a
 * hosting dashboard). Error messages never repeat any part of the input.
 */
export function parseServiceAccount(raw: string): GcpServiceAccount {
  const text = raw.trim().startsWith('{') ? raw : Buffer.from(raw.trim(), 'base64').toString('utf8');
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new KmsError('GCP_SERVICE_ACCOUNT_JSON is not valid JSON (or base64-encoded JSON)');
  }
  const { type, client_email: clientEmail, token_uri: tokenUri, private_key: privateKeyPem, private_key_id: privateKeyId } = json;
  if (type !== 'service_account') throw new KmsError('GCP_SERVICE_ACCOUNT_JSON must be a service account key');
  if (typeof clientEmail !== 'string' || !clientEmail.endsWith('.iam.gserviceaccount.com')) {
    throw new KmsError('GCP_SERVICE_ACCOUNT_JSON has no valid client_email');
  }
  // The token endpoint comes from code, never from the file, so a crafted key file cannot
  // send the signed assertion anywhere else.
  if (tokenUri !== undefined && tokenUri !== TOKEN_URI) {
    throw new KmsError(`GCP_SERVICE_ACCOUNT_JSON token_uri must be ${TOKEN_URI}`);
  }
  if (typeof privateKeyPem !== 'string') throw new KmsError('GCP_SERVICE_ACCOUNT_JSON has no private_key');
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch {
    throw new KmsError('GCP_SERVICE_ACCOUNT_JSON private_key could not be read');
  }
  if (privateKey.asymmetricKeyType !== 'rsa') throw new KmsError('GCP_SERVICE_ACCOUNT_JSON private_key must be an RSA key');
  return {
    clientEmail,
    privateKey,
    privateKeyId: typeof privateKeyId === 'string' ? privateKeyId : undefined,
  };
}

export interface GcpKmsOptions {
  keyName: string;
  credentials: GcpServiceAccount;
  fetch?: typeof fetch;
  now?: () => number;
  timeoutMs?: number;
  retries?: number;
  sleep?: (ms: number) => Promise<void>;
}

const b64url = (value: string) => Buffer.from(value, 'utf8').toString('base64url');

export class GcpKms implements KmsProvider {
  readonly name = 'gcp-kms' as const;
  readonly keyName: string;
  private readonly credentials: GcpServiceAccount;
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private token: { value: string; expiresAt: number } | null = null;

  constructor(options: GcpKmsOptions) {
    if (!GCP_KMS_KEY_NAME_RE.test(options.keyName)) {
      throw new KmsError('GCP_KMS_KEY_NAME must look like projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>');
    }
    this.keyName = options.keyName;
    this.credentials = options.credentials;
    this.fetchFn = options.fetch ?? fetch;
    this.now = options.now ?? Date.now;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.retries = options.retries ?? 2;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  async encrypt(plaintext: Buffer, aad: string): Promise<Buffer> {
    const aadBytes = Buffer.from(aad, 'utf8');
    const body = (await this.call('encrypt', {
      plaintext: plaintext.toString('base64'),
      plaintextCrc32c: String(crc32c(plaintext)),
      additionalAuthenticatedData: aadBytes.toString('base64'),
      additionalAuthenticatedDataCrc32c: String(crc32c(aadBytes)),
    })) as {
      name?: string;
      ciphertext?: string;
      ciphertextCrc32c?: string | number;
      verifiedPlaintextCrc32c?: boolean;
      verifiedAdditionalAuthenticatedDataCrc32c?: boolean;
    };
    if (!body.verifiedPlaintextCrc32c || !body.verifiedAdditionalAuthenticatedDataCrc32c) {
      throw new KmsError('Cloud KMS did not confirm the request checksum');
    }
    // Google names the key version it used; it must be a version of the configured key.
    if (body.name !== undefined && !body.name.startsWith(`${this.keyName}/cryptoKeyVersions/`)) {
      throw new KmsError('Cloud KMS encrypted with a different key than the configured one');
    }
    if (typeof body.ciphertext !== 'string') throw new KmsError('Cloud KMS returned no ciphertext');
    const ciphertext = Buffer.from(body.ciphertext, 'base64');
    if (Number(body.ciphertextCrc32c) !== crc32c(ciphertext)) throw new KmsError('Cloud KMS response was corrupted in transit');
    return ciphertext;
  }

  async decrypt(ciphertext: Buffer, aad: string): Promise<Buffer> {
    const aadBytes = Buffer.from(aad, 'utf8');
    const body = (await this.call('decrypt', {
      ciphertext: ciphertext.toString('base64'),
      ciphertextCrc32c: String(crc32c(ciphertext)),
      additionalAuthenticatedData: aadBytes.toString('base64'),
      additionalAuthenticatedDataCrc32c: String(crc32c(aadBytes)),
    })) as { plaintext?: string; plaintextCrc32c?: string | number };
    if (typeof body.plaintext !== 'string') throw new KmsError('Cloud KMS returned no plaintext');
    const plaintext = Buffer.from(body.plaintext, 'base64');
    if (Number(body.plaintextCrc32c) !== crc32c(plaintext)) {
      plaintext.fill(0);
      throw new KmsError('Cloud KMS response was corrupted in transit');
    }
    return plaintext;
  }

  private async call(op: 'encrypt' | 'decrypt', payload: Record<string, string>): Promise<unknown> {
    const send = async () =>
      this.request(
        `${KMS_ENDPOINT}${this.keyName}:${op}`,
        {
          method: 'POST',
          headers: { authorization: `Bearer ${await this.accessToken()}`, 'content-type': 'application/json' },
          body: JSON.stringify(payload),
        },
        op,
      );
    let res = await send();
    if (res.status === 401) {
      // The cached token was revoked or expired early: get a new one once.
      this.token = null;
      res = await send();
    }
    if (!res.ok) throw httpError(op, res.status);
    return res.json();
  }

  private async accessToken(): Promise<string> {
    const now = this.now();
    if (this.token && this.token.expiresAt - 60_000 > now) return this.token.value;
    const iat = Math.floor(now / 1000);
    const header = b64url(
      JSON.stringify({ alg: 'RS256', typ: 'JWT', ...(this.credentials.privateKeyId ? { kid: this.credentials.privateKeyId } : {}) }),
    );
    const claims = b64url(JSON.stringify({ iss: this.credentials.clientEmail, scope: SCOPE, aud: TOKEN_URI, iat, exp: iat + 3600 }));
    const signer = createSign('RSA-SHA256');
    signer.update(`${header}.${claims}`);
    const signature = signer.sign(this.credentials.privateKey).toString('base64url');
    const res = await this.request(
      TOKEN_URI,
      {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion: `${header}.${claims}.${signature}`,
        }).toString(),
      },
      'sign-in',
    );
    if (!res.ok) throw httpError('sign-in', res.status);
    const body = (await res.json()) as { access_token?: string; expires_in?: number };
    if (typeof body.access_token !== 'string') throw new KmsError('Google returned no access token');
    this.token = { value: body.access_token, expiresAt: now + (body.expires_in ?? 3600) * 1000 };
    return this.token.value;
  }

  /** Retries network errors, 429 and 5xx with backoff; other statuses are returned to the caller. */
  private async request(url: string, init: RequestInit, op: string): Promise<Response> {
    let last: KmsError = new KmsError(`Cloud KMS ${op} failed`);
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) await this.sleep(250 * 2 ** (attempt - 1));
      let res: Response;
      try {
        res = await this.fetchFn(url, { ...init, signal: AbortSignal.timeout(this.timeoutMs) });
      } catch (err) {
        last = new KmsError(`Cloud KMS ${op} request failed (${err instanceof Error ? err.name : 'network error'})`);
        continue;
      }
      if (res.status === 429 || res.status >= 500) {
        last = httpError(op, res.status);
        continue;
      }
      return res;
    }
    throw last;
  }
}

function httpError(op: string, status: number): KmsError {
  const hint =
    status === 403
      ? ': check that the service account has the Cloud KMS CryptoKey Encrypter/Decrypter role on this key'
      : status === 404
        ? ': check GCP_KMS_KEY_NAME'
        : status === 400 && op === 'decrypt'
          ? ': the stored key does not belong to this KMS key, or it was changed'
          : '';
  return new KmsError(`Cloud KMS ${op} failed with HTTP ${status}${hint}`);
}

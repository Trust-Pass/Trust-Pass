import { hkdfSync } from 'node:crypto';
import { createRequire } from 'node:module';
import { isIP } from 'node:net';
import path from 'node:path';
import { z } from 'zod';
import { KeySet, type MasterKey } from './lib/keyset';

export type { MasterKey };
export const GCP_KMS_KEY_NAME_RE =
  /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9-]{1,63}\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}$/;

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().positive().default(3000),
  APP_URL: z.string().url().default('http://localhost:5173'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  // Where the key-encryption keys (KEKs) come from:
  //   env      - derived from MASTER_KEY (legacy; the key sits next to the app)
  //   gcp-kms  - random KEKs, stored only encrypted by a Google Cloud KMS key
  //   fake-kms - same as gcp-kms with a local stand-in for KMS (development and tests; refused in production)
  KEY_PROVIDER: z.enum(['env', 'gcp-kms', 'fake-kms']).default('env'),
  // Legacy master key. Required with KEY_PROVIDER=env; with a KMS provider it is only
  // needed until `keys:rewrap` has moved every document to a KMS-protected KEK.
  MASTER_KEY: z.string().min(32, 'MASTER_KEY must be at least 32 characters of random data').optional(),
  MASTER_KEY_VERSION: z.coerce.number().int().min(1).default(1),
  // Older master keys kept for unwrapping during rotation: "1:secret,2:secret"
  PREVIOUS_MASTER_KEYS: z.string().optional(),
  // KEY_PROVIDER=gcp-kms: full key resource name, and the service account key (JSON or base64 JSON)
  GCP_KMS_KEY_NAME: z.string().regex(GCP_KMS_KEY_NAME_RE, 'GCP_KMS_KEY_NAME must look like projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>').optional(),
  GCP_SERVICE_ACCOUNT_JSON: z.string().optional(),
  // KEY_PROVIDER=fake-kms: file holding the fake root key (created with random bytes on first use)
  FAKE_KMS_KEY_FILE: z.string().optional(),
  IP_HASH_SECRET: z.string().min(32, 'IP_HASH_SECRET must be at least 32 characters'),
  ISSUER_SIGNING_SEED: z.string().min(32, 'ISSUER_SIGNING_SEED must be at least 32 characters'),
  STORAGE_DRIVER: z.enum(['local', 'database']).default('local'),
  STORAGE_DIR: z.string().default('./data/storage'),
  GEO_PROVIDER: z.enum(['mmdb', 'simulated']).default('mmdb'),
  GEO_DB_PATH: z.string().optional(),
  GEO_SIMULATED_DEFAULT: z.string().length(2).optional(),
  // "203.0.113.5=SA,198.51.100.7=US"
  GEO_SIMULATED_MAP: z.string().optional(),
  // "false" (direct), "true" (trust all - never in production), a hop count, or a comma list of
  // trusted proxy ranges such as "loopback,linklocal,uniquelocal,100.64.0.0/10"
  TRUST_PROXY: z.string().default('false'),
  // Header set by the platform's edge with the real visitor address, e.g. "cf-connecting-ip" behind
  // Cloudflare. Only use a header the edge always overwrites, or visitors could choose their own address.
  CLIENT_IP_HEADER: z
    .string()
    .regex(/^[A-Za-z0-9-]{1,64}$/, 'CLIENT_IP_HEADER must be a header name')
    .transform((v) => v.toLowerCase())
    .optional(),
  MAIL_TRANSPORT: z.enum(['console', 'smtp', 'none']).default('console'),
  SMTP_URL: z.string().optional(),
  MAIL_FROM: z.string().default('TrustPass <no-reply@trustpass.local>'),
  MAX_UPLOAD_MB: z.coerce.number().int().min(1).max(25).default(10),
  WEB_DIST_DIR: z.string().optional(),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  ADMIN_EMAIL: z.string().optional(),
  ADMIN_PASSWORD: z.string().optional(),
});

export type Env = z.infer<typeof envSchema>;

export interface AppConfig {
  env: Env;
  isProduction: boolean;
  appOrigin: string;
  cookieName: string;
  cookieSecure: boolean;
  trustProxy: boolean | number | string[];
  clientIpHeader: string | null;
  /** Key-encryption keys that wrap per-document data keys. Filled at start-up when a KMS is used. */
  masterKeys: KeySet;
  /** Keys that seal the owner's copy of each share-link token (kept apart from the KEKs). */
  linkTokenKeys: KeySet;
  /** KEK versions that come from MASTER_KEY / PREVIOUS_MASTER_KEYS rather than from a KMS. */
  legacyKekVersions: number[];
  ipHashKey: Buffer;
  issuerSeed: Buffer;
  maxUploadBytes: number;
  sessionIdleMs: number;
  sessionAbsoluteMs: number;
  geoDbPath: string;
}

/**
 * Derive a 256-bit key from a configured secret with HKDF-SHA256. Each
 * purpose uses its own label, so one secret can never be reused as another key.
 */
export function deriveKey(secret: string, label: string): Buffer {
  return Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.from('trustpass'), Buffer.from(label), 32));
}

const PROXY_RANGE_NAMES = new Set(['loopback', 'linklocal', 'uniquelocal']);

function isCidr(value: string): boolean {
  const [ip, bits, extra] = value.split('/');
  if (!ip || extra !== undefined || !isIP(ip)) return false;
  if (bits === undefined) return true;
  const n = Number(bits);
  return Number.isInteger(n) && n >= 0 && n <= (isIP(ip) === 4 ? 32 : 128);
}

/**
 * How to find the visitor's address behind proxies:
 *  - a hop count trusts exactly that many proxies;
 *  - a list of ranges trusts only proxies inside them (e.g. the platform's
 *    private network), so the visitor is the right-most address outside them.
 *    Addresses a client writes into X-Forwarded-For sit further left and are ignored.
 */
function parseTrustProxy(value: string, isProduction: boolean): boolean | number | string[] {
  if (value === 'false' || value === '0' || value === '') return false;
  if (value === 'true') {
    if (isProduction) throw new Error('TRUST_PROXY=true is unsafe in production; set the hop count or the trusted proxy ranges instead');
    return true;
  }
  if (/^\d+$/.test(value)) return Number(value);
  const ranges = value.split(',').map((s) => s.trim()).filter(Boolean);
  for (const range of ranges) {
    if (!PROXY_RANGE_NAMES.has(range) && !isCidr(range)) {
      throw new Error(`TRUST_PROXY entry "${range}" is not loopback, linklocal, uniquelocal or an IP/CIDR range`);
    }
  }
  if (ranges.length === 0) throw new Error('TRUST_PROXY must be false, true, a hop count or a list of proxy ranges');
  return ranges;
}

export function loadConfig(source: NodeJS.ProcessEnv = process.env): AppConfig {
  // Hosting dashboards often leave variables as empty strings: treat those as unset.
  const cleaned = Object.fromEntries(Object.entries(source).filter(([, v]) => v !== undefined && v !== ''));
  // On Render, the public https URL is provided automatically.
  const parsed = envSchema.safeParse({ ...cleaned, APP_URL: cleaned.APP_URL ?? cleaned.RENDER_EXTERNAL_URL });
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n  ');
    throw new Error(`Invalid configuration:\n  ${problems}`);
  }
  const env = parsed.data;
  const isProduction = env.NODE_ENV === 'production';

  if (isProduction && env.GEO_PROVIDER === 'simulated') {
    throw new Error('GEO_PROVIDER=simulated is refused in production: it would let tests choose their own country');
  }
  if (isProduction && !env.APP_URL.startsWith('https://')) {
    throw new Error('APP_URL must use https:// in production');
  }

  if (env.KEY_PROVIDER === 'env' && !env.MASTER_KEY) {
    throw new Error('Invalid configuration:\n  MASTER_KEY: required when KEY_PROVIDER=env');
  }
  if (env.KEY_PROVIDER === 'fake-kms' && isProduction) {
    throw new Error('KEY_PROVIDER=fake-kms is refused in production: it is a local stand-in, not a key management service');
  }
  if (env.KEY_PROVIDER === 'gcp-kms' && (!env.GCP_KMS_KEY_NAME || !env.GCP_SERVICE_ACCOUNT_JSON)) {
    throw new Error('Invalid configuration:\n  KEY_PROVIDER=gcp-kms needs GCP_KMS_KEY_NAME and GCP_SERVICE_ACCOUNT_JSON');
  }

  // Legacy keys from the environment. With a KMS provider they can still decrypt older
  // data, but the current (encrypting) KEK is loaded from the keyring at start-up.
  const masterKeys = new KeySet('key-encryption');
  const linkTokenKeys = new KeySet('link-token');
  const legacy: Array<[number, string]> = [];
  if (env.MASTER_KEY) legacy.push([env.MASTER_KEY_VERSION, env.MASTER_KEY]);
  if (env.PREVIOUS_MASTER_KEYS) {
    for (const entry of env.PREVIOUS_MASTER_KEYS.split(',')) {
      const [v, secret] = entry.split(':');
      const version = Number(v);
      if (!Number.isInteger(version) || version < 1 || !secret || secret.length < 32) {
        throw new Error('PREVIOUS_MASTER_KEYS entries must look like "1:<secret of 32+ chars>"');
      }
      if (!legacy.some(([existing]) => existing === version)) legacy.push([version, secret]);
    }
  }
  const useEnvKeys = env.KEY_PROVIDER === 'env';
  for (const [version, secret] of legacy) {
    const current = useEnvKeys && version === env.MASTER_KEY_VERSION;
    masterKeys.add(version, deriveKey(secret, `kek:v${version}`), { current });
    // Separate key for link tokens, so the KEK only ever wraps data keys.
    linkTokenKeys.add(version, deriveKey(secret, `link-token:v${version}`), { current });
  }

  const geoPackage = createRequire(import.meta.url).resolve('@ip-location-db/dbip-country-mmdb/package.json');
  const defaultGeoDb = path.join(path.dirname(geoPackage), 'dbip-country.mmdb');

  return {
    env,
    isProduction,
    appOrigin: new URL(env.APP_URL).origin,
    // The __Host- prefix forces Secure, Path=/ and no Domain attribute.
    cookieName: isProduction ? '__Host-tp_session' : 'tp_session',
    cookieSecure: isProduction,
    trustProxy: parseTrustProxy(env.TRUST_PROXY, isProduction),
    clientIpHeader: env.CLIENT_IP_HEADER ?? null,
    masterKeys,
    linkTokenKeys,
    legacyKekVersions: legacy.map(([version]) => version).sort((a, b) => a - b),
    ipHashKey: deriveKey(env.IP_HASH_SECRET, 'ip-hmac'),
    issuerSeed: deriveKey(env.ISSUER_SIGNING_SEED, 'issuer-ed25519-seed'),
    maxUploadBytes: env.MAX_UPLOAD_MB * 1024 * 1024,
    sessionIdleMs: 60 * 60 * 1000,
    sessionAbsoluteMs: 12 * 60 * 60 * 1000,
    geoDbPath: env.GEO_DB_PATH ?? defaultGeoDb,
  };
}

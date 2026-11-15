import { hkdfSync } from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().positive().default(3000),
  APP_URL: z.string().url().default('http://localhost:5173'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  MASTER_KEY: z.string().min(32, 'MASTER_KEY must be at least 32 characters of random data'),
  MASTER_KEY_VERSION: z.coerce.number().int().min(1).default(1),
  // Older master keys kept for unwrapping during rotation: "1:secret,2:secret"
  PREVIOUS_MASTER_KEYS: z.string().optional(),
  IP_HASH_SECRET: z.string().min(32, 'IP_HASH_SECRET must be at least 32 characters'),
  ISSUER_SIGNING_SEED: z.string().min(32, 'ISSUER_SIGNING_SEED must be at least 32 characters'),
  STORAGE_DRIVER: z.enum(['local', 'database']).default('local'),
  STORAGE_DIR: z.string().default('./data/storage'),
  GEO_PROVIDER: z.enum(['mmdb', 'simulated']).default('mmdb'),
  GEO_DB_PATH: z.string().optional(),
  GEO_SIMULATED_DEFAULT: z.string().length(2).optional(),
  // "203.0.113.5=SA,198.51.100.7=US"
  GEO_SIMULATED_MAP: z.string().optional(),
  // "false" (direct), "true" (trust all - never in production), or a hop count
  TRUST_PROXY: z.string().default('false'),
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

export interface MasterKey {
  version: number;
  key: Buffer;
}

export interface AppConfig {
  env: Env;
  isProduction: boolean;
  appOrigin: string;
  cookieName: string;
  cookieSecure: boolean;
  trustProxy: boolean | number;
  masterKeys: { current: MasterKey; all: Map<number, Buffer> };
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

function parseTrustProxy(value: string, isProduction: boolean): boolean | number {
  if (value === 'false' || value === '0' || value === '') return false;
  if (value === 'true') {
    if (isProduction) throw new Error('TRUST_PROXY=true is unsafe in production; set the number of proxy hops instead');
    return true;
  }
  const hops = Number(value);
  if (!Number.isInteger(hops) || hops < 0) throw new Error('TRUST_PROXY must be false, true or a hop count');
  return hops;
}

export function loadConfig(source: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.safeParse(source);
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

  const masterKeys = new Map<number, Buffer>();
  masterKeys.set(env.MASTER_KEY_VERSION, deriveKey(env.MASTER_KEY, `kek:v${env.MASTER_KEY_VERSION}`));
  if (env.PREVIOUS_MASTER_KEYS) {
    for (const entry of env.PREVIOUS_MASTER_KEYS.split(',')) {
      const [v, secret] = entry.split(':');
      const version = Number(v);
      if (!Number.isInteger(version) || !secret || secret.length < 32) {
        throw new Error('PREVIOUS_MASTER_KEYS entries must look like "1:<secret of 32+ chars>"');
      }
      if (!masterKeys.has(version)) masterKeys.set(version, deriveKey(secret, `kek:v${version}`));
    }
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
    masterKeys: {
      current: { version: env.MASTER_KEY_VERSION, key: masterKeys.get(env.MASTER_KEY_VERSION)! },
      all: masterKeys,
    },
    ipHashKey: deriveKey(env.IP_HASH_SECRET, 'ip-hmac'),
    issuerSeed: deriveKey(env.ISSUER_SIGNING_SEED, 'issuer-ed25519-seed'),
    maxUploadBytes: env.MAX_UPLOAD_MB * 1024 * 1024,
    sessionIdleMs: 60 * 60 * 1000,
    sessionAbsoluteMs: 12 * 60 * 60 * 1000,
    geoDbPath: env.GEO_DB_PATH ?? defaultGeoDb,
  };
}

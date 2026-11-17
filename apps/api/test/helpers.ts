import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PrismaClient } from '@prisma/client';
import type { InjectOptions, LightMyRequestResponse } from 'fastify';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import sharp from 'sharp';
import { buildApp } from '../src/app';
import { loadConfig, type AppConfig } from '../src/config';
import type { MailMessage, Mailer } from '../src/lib/mail';
import { TEST_DATABASE_URL, TEST_KMS_KEY_FILE } from './env';

export { TEST_KMS_KEY_FILE };

export const TEST_SECRETS = {
  MASTER_KEY: 'test-master-key-0123456789-abcdefghijklmnopqrstuvwxyz',
  IP_HASH_SECRET: 'test-ip-hash-secret-0123456789-abcdefghijklmnop',
  ISSUER_SIGNING_SEED: 'test-issuer-seed-0123456789-abcdefghijklmnopqrs',
};

/** Simulated network: these addresses resolve to these countries. */
export const IPS = {
  SA: '10.0.0.1',
  AE: '10.0.0.2',
  US: '10.0.0.3',
  GB: '10.0.0.4',
  UNKNOWN: '192.168.50.50',
};

export function testConfig(overrides: Record<string, string | undefined> = {}): AppConfig {
  return loadConfig({
    NODE_ENV: 'test',
    APP_URL: 'http://localhost:5173',
    DATABASE_URL: TEST_DATABASE_URL,
    ...TEST_SECRETS,
    STORAGE_DRIVER: 'local',
    STORAGE_DIR: mkdtempSync(path.join(tmpdir(), 'trustpass-test-')),
    GEO_PROVIDER: 'simulated',
    GEO_SIMULATED_MAP: Object.entries(IPS)
      .filter(([k]) => k !== 'UNKNOWN')
      .map(([code, ip]) => `${ip}=${code}`)
      .join(','),
    MAIL_TRANSPORT: 'none',
    LOG_LEVEL: 'silent',
    ...overrides,
  });
}

let sharedPrisma: PrismaClient | null = null;
export function testPrisma() {
  sharedPrisma ??= new PrismaClient({ datasources: { db: { url: TEST_DATABASE_URL } } });
  return sharedPrisma;
}

const TABLES = [
  'access_logs',
  'security_events',
  'verification_records',
  'notifications',
  'sharing_permissions',
  'allowed_countries',
  'sharing_links',
  'credentials',
  'document_claims',
  'document_keys',
  'documents',
  'stored_objects',
  'issuers',
  'organization_members',
  'organizations',
  'password_reset_tokens',
  'sessions',
  'users',
  'system_settings',
];

/** Removes every stored key (tests that start from an empty keyring only). */
export async function resetKeyring(prisma: PrismaClient) {
  await prisma.$transaction([
    prisma.$executeRawUnsafe(`SELECT set_config('trustpass.allow_key_destroy', 'on', true)`),
    prisma.$executeRawUnsafe(`TRUNCATE "key_encryption_keys"`),
  ]);
}

export async function resetDatabase(prisma: PrismaClient) {
  await prisma.$transaction([
    prisma.$executeRawUnsafe(`SELECT set_config('trustpass.allow_log_purge', 'on', true)`),
    prisma.$executeRawUnsafe(`TRUNCATE ${TABLES.map((t) => `"${t}"`).join(', ')} RESTART IDENTITY CASCADE`),
  ]);
}

export interface TestContext {
  app: Awaited<ReturnType<typeof buildApp>>;
  prisma: PrismaClient;
  config: AppConfig;
  clock: { now: Date; advance(ms: number): void };
  mail: MailMessage[];
}

/**
 * App instances in tests use the fake KMS (KEY_PROVIDER=fake-kms) with no MASTER_KEY,
 * the same path production takes with Google Cloud KMS. Pass MASTER_KEY or KEY_PROVIDER
 * to test the legacy path.
 */
export async function createTestContext(overrides: Record<string, string | undefined> = {}): Promise<TestContext> {
  const config = testConfig({ KEY_PROVIDER: 'fake-kms', FAKE_KMS_KEY_FILE: TEST_KMS_KEY_FILE, MASTER_KEY: undefined, ...overrides });
  const prisma = testPrisma();
  const clock = {
    now: new Date(),
    advance(ms: number) {
      this.now = new Date(this.now.getTime() + ms);
    },
  };
  const mail: MailMessage[] = [];
  const mailer: Mailer = { transport: 'smtp', send: async (m) => void mail.push(m) };
  const app = await buildApp({ config, prisma, mailer, now: () => new Date(clock.now), logger: false });
  await app.ready();
  return { app, prisma, config, clock, mail };
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

export interface Session {
  token: string;
  csrf: string;
  userId: string;
  email: string;
  orgId?: string;
}

let counter = 0;
export function uniqueEmail(prefix = 'user') {
  counter += 1;
  return `${prefix}.${Date.now().toString(36)}.${counter}@example.test`;
}

export const PASSWORD = 'Correct-Horse-Battery-9';

function cookieFrom(res: LightMyRequestResponse, name = 'tp_session'): string {
  const cookie = res.cookies.find((c) => c.name === name);
  if (!cookie) throw new Error(`No ${name} cookie in response (status ${res.statusCode}): ${res.body}`);
  return cookie.value;
}

/** Each helper call uses its own address so per-IP rate limits never interfere between tests. */
let ipCounter = 0;
export function freshIp() {
  ipCounter += 1;
  return `172.16.${Math.floor(ipCounter / 250)}.${(ipCounter % 250) + 1}`;
}

export async function registerUser(
  ctx: TestContext,
  options: { email?: string; fullName?: string; organization?: string } = {},
): Promise<Session> {
  const email = options.email ?? uniqueEmail();
  const payload = options.organization
    ? { accountType: 'organization', fullName: options.fullName ?? 'Org Owner', email, password: PASSWORD, organizationName: options.organization, organizationType: 'company' }
    : { accountType: 'individual', fullName: options.fullName ?? 'Reham Test', email, password: PASSWORD };
  const res = await ctx.app.inject({ method: 'POST', url: '/api/auth/register', payload, remoteAddress: freshIp() });
  if (res.statusCode !== 201) throw new Error(`register failed ${res.statusCode}: ${res.body}`);
  const body = res.json();
  return { token: cookieFrom(res), csrf: body.csrfToken, userId: body.user.id, email, orgId: body.organizations[0]?.id };
}

export async function loginUser(ctx: TestContext, email: string, password = PASSWORD): Promise<Session> {
  const res = await ctx.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email, password }, remoteAddress: freshIp() });
  if (res.statusCode !== 200) throw new Error(`login failed ${res.statusCode}: ${res.body}`);
  const body = res.json();
  return { token: cookieFrom(res), csrf: body.csrfToken, userId: body.user.id, email };
}

export async function makeAdmin(ctx: TestContext, session: Session) {
  await ctx.prisma.user.update({ where: { id: session.userId }, data: { role: 'admin' } });
}

/** An authenticated request with the session cookie and CSRF header, like the web app sends. */
export function as(ctx: TestContext, session: Session | null, options: InjectOptions & { ip?: string }) {
  const { ip, ...rest } = options;
  return ctx.app.inject({
    ...rest,
    remoteAddress: ip ?? freshIp(),
    cookies: session ? { tp_session: session.token, ...(rest.cookies ?? {}) } : rest.cookies,
    headers: { ...(session ? { 'x-csrf-token': session.csrf } : {}), ...(rest.headers ?? {}) },
  });
}

// ---------------------------------------------------------------------------
// Files and multipart
// ---------------------------------------------------------------------------

export function multipart(parts: Array<{ name: string; value: string } | { name: string; filename: string; content: Buffer; contentType?: string }>) {
  const boundary = `----trustpass${Math.random().toString(16).slice(2)}`;
  const chunks: Buffer[] = [];
  for (const part of parts) {
    chunks.push(Buffer.from(`--${boundary}\r\n`));
    if ('filename' in part) {
      chunks.push(
        Buffer.from(
          `Content-Disposition: form-data; name="${part.name}"; filename="${part.filename}"\r\nContent-Type: ${part.contentType ?? 'application/octet-stream'}\r\n\r\n`,
        ),
      );
      chunks.push(part.content, Buffer.from('\r\n'));
    } else {
      chunks.push(Buffer.from(`Content-Disposition: form-data; name="${part.name}"\r\n\r\n${part.value}\r\n`));
    }
  }
  chunks.push(Buffer.from(`--${boundary}--\r\n`));
  return { payload: Buffer.concat(chunks), headers: { 'content-type': `multipart/form-data; boundary=${boundary}` } };
}

export const PLAINTEXT_MARKER = 'TRUSTPASS-PLAINTEXT-MARKER-7f3a';

export async function samplePdf(text = PLAINTEXT_MARKER): Promise<Buffer> {
  const pdf = await PDFDocument.create();
  const page = pdf.addPage([400, 300]);
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  page.drawText(text, { x: 20, y: 150, size: 12, font });
  pdf.setSubject(text);
  return Buffer.from(await pdf.save({ useObjectStreams: false }));
}

export async function samplePng(): Promise<Buffer> {
  return sharp({ create: { width: 64, height: 48, channels: 3, background: { r: 20, g: 120, b: 200 } } })
    .png()
    .toBuffer();
}

export async function uploadDocument(
  ctx: TestContext,
  session: Session,
  options: { file?: Buffer; filename?: string; title?: string; claims?: Array<{ label: string; value: string }> } = {},
) {
  const file = options.file ?? (await samplePdf());
  const form = multipart([
    { name: 'metadata', value: JSON.stringify({ title: options.title ?? 'My Test Document', category: 'other', claims: options.claims ?? [] }) },
    { name: 'file', filename: options.filename ?? 'doc.pdf', content: file },
  ]);
  return as(ctx, session, { method: 'POST', url: '/api/documents', payload: form.payload, headers: form.headers });
}

export async function issueCredential(ctx: TestContext, session: Session) {
  const res = await as(ctx, session, {
    method: 'POST',
    url: '/api/issuer/credentials',
    payload: { nameOnCertificate: 'Reham Alkhamees', program: 'BSc Cybersecurity' },
  });
  if (res.statusCode !== 201) throw new Error(`issue failed ${res.statusCode}: ${res.body}`);
  return res.json().document.id as string;
}

export async function documentClaims(ctx: TestContext, session: Session, documentId: string) {
  const res = await as(ctx, session, { method: 'GET', url: `/api/documents/${documentId}` });
  return res.json().document.claims as Array<{ id: string; key: string; label: string; value: string }>;
}

export async function createLink(ctx: TestContext, session: Session, documentId: string, body: Record<string, unknown>) {
  const res = await as(ctx, session, {
    method: 'POST',
    url: `/api/documents/${documentId}/links`,
    payload: { includeFile: false, recipientType: 'anyone', recipientLabel: 'Example Company', expiresIn: '24h', allowedCountries: [], claimIds: [], ...body },
  });
  if (res.statusCode !== 201) throw new Error(`createLink failed ${res.statusCode}: ${res.body}`);
  const json = res.json();
  return { id: json.link.id as string, url: json.url as string, token: (json.url as string).split('/s/')[1]! };
}

// ---------------------------------------------------------------------------
// Operator commands and database snapshots
// ---------------------------------------------------------------------------

/** Environment for the `keys` and `backup` commands, as an operator would set it. */
export function cliEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'test',
    APP_URL: 'http://localhost:5173',
    DATABASE_URL: TEST_DATABASE_URL,
    IP_HASH_SECRET: TEST_SECRETS.IP_HASH_SECRET,
    ISSUER_SIGNING_SEED: TEST_SECRETS.ISSUER_SIGNING_SEED,
    KEY_PROVIDER: 'fake-kms',
    FAKE_KMS_KEY_FILE: TEST_KMS_KEY_FILE,
    STORAGE_DRIVER: 'database',
    GEO_PROVIDER: 'simulated',
    GEO_SIMULATED_DEFAULT: 'SA',
    MAIL_TRANSPORT: 'none',
    LOG_LEVEL: 'silent',
    ...extra,
  };
}

/** Every row of every table, hashed: proves that a command changed nothing at all. */
export async function fingerprint(prisma: PrismaClient): Promise<string> {
  const tables = await prisma.$queryRaw<Array<{ table_name: string }>>`
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`;
  const parts: string[] = [];
  for (const { table_name } of tables) {
    const [row] = await prisma.$queryRawUnsafe<Array<{ h: string; n: bigint }>>(
      `SELECT md5(coalesce(string_agg(x::text, '|' ORDER BY x::text), '')) AS h, count(*) AS n FROM "${table_name}" x`,
    );
    parts.push(`${table_name}:${row!.n}:${row!.h}`);
  }
  return parts.join('\n');
}

import { mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PDFDocument, PDFName, PDFString, StandardFonts } from 'pdf-lib';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  as,
  createLink,
  createTestContext,
  documentClaims,
  IPS,
  PLAINTEXT_MARKER,
  registerUser,
  resetDatabase,
  samplePdf,
  uploadDocument,
  type TestContext,
} from '../helpers';

/**
 * E1: tests that prove documents are encrypted at rest, for both storage drivers
 * (production on Render uses `database`; the other suites only use `local`).
 *
 * Every marker is checked to be PRESENT in the plaintext first, so a test can never
 * pass just because the marker was not there to begin with.
 */

// Letters and digits only, so the slug made from a field label still matches (case-insensitive).
const MARK = {
  file: 'zqfilecanary7f3a',
  title: 'zqtitlecanary7f3a',
  label: 'zqlabelcanary7f3a',
  value: 'zqvaluecanary7f3a',
  hidden: 'zqhiddenvalue7f3a',
  recipient: 'zqrecipient7f3a',
} as const;
type MarkName = keyof typeof MARK;

/** A valid PDF whose bytes contain the marker as plain ASCII (an uncompressed literal string). */
async function canaryPdf(marker: string): Promise<Buffer> {
  const pdf = await PDFDocument.create();
  const page = pdf.addPage([400, 300]);
  page.drawText('Canary document', { x: 20, y: 150, size: 12, font: await pdf.embedFont(StandardFonts.Helvetica) });
  pdf.catalog.set(PDFName.of('TrustPassCanary'), PDFString.of(marker));
  return Buffer.from(await pdf.save({ useObjectStreams: false }));
}

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...filesUnder(full));
    else out.push(full);
  }
  return out;
}

/** Tables (and, for the local driver, stored files) in which each marker appears in clear. */
async function findMarkers(ctx: TestContext): Promise<Record<MarkName, string[]>> {
  const tables = await ctx.prisma.$queryRaw<Array<{ table_name: string }>>`
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name <> '_prisma_migrations'
    ORDER BY table_name`;
  const report = Object.fromEntries(Object.keys(MARK).map((k) => [k, [] as string[]])) as Record<MarkName, string[]>;
  for (const [name, marker] of Object.entries(MARK) as Array<[MarkName, string]>) {
    const hex = Buffer.from(marker, 'utf8').toString('hex'); // bytea columns render as \x<hex>
    for (const { table_name } of tables) {
      // table_name comes from information_schema, not from user input.
      const rows = await ctx.prisma.$queryRawUnsafe<Array<{ hits: bigint }>>(
        `SELECT count(*)::bigint AS hits FROM "${table_name}" x WHERE x::text ILIKE $1 OR x::text ILIKE $2`,
        `%${marker}%`,
        `%${hex}%`,
      );
      if (Number(rows[0]!.hits) > 0) report[name].push(table_name);
    }
    if (ctx.config.env.STORAGE_DRIVER === 'local') {
      for (const file of filesUnder(path.resolve(ctx.config.env.STORAGE_DIR))) {
        if (readFileSync(file).includes(Buffer.from(marker))) report[name].push(`disk:${path.basename(file)}`);
      }
    }
  }
  return report;
}

describe.each(['local', 'database'] as const)('encryption at rest (STORAGE_DRIVER=%s)', (driver) => {
  let ctx: TestContext;
  beforeAll(async () => {
    ctx = await createTestContext({ STORAGE_DRIVER: driver });
  });
  afterAll(async () => {
    await ctx.app.close();
  });
  beforeEach(async () => {
    ctx.clock.now = new Date();
    await resetDatabase(ctx.prisma);
  });

  /** Upload with every marker, share one field (not the hidden one), and open the link once. */
  async function seedEverything() {
    const owner = await registerUser(ctx);
    const file = await canaryPdf(MARK.file);
    expect(file.includes(Buffer.from(MARK.file)), 'precondition: the marker is in the plaintext file').toBe(true);

    const upload = await uploadDocument(ctx, owner, {
      file,
      title: `Passport ${MARK.title}`,
      claims: [
        { label: `Employer ${MARK.label}`, value: `Employer ${MARK.value}` },
        { label: 'Hidden field', value: `Secret ${MARK.hidden}` },
      ],
    });
    expect(upload.statusCode).toBe(201);
    const documentId = upload.json().document.id as string;
    const claims = await documentClaims(ctx, owner, documentId);
    const shared = claims.find((c) => c.value.includes(MARK.value))!;
    const link = await createLink(ctx, owner, documentId, {
      claimIds: [shared.id],
      includeFile: true,
      recipientLabel: `HR ${MARK.recipient}`,
    });
    const view = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA });
    expect(view.statusCode).toBe(200);
    return { owner, documentId, link, file, claims };
  }

  it('stores the file, field values and credentials only as ciphertext', async () => {
    await seedEverything();
    const report = await findMarkers(ctx);
    expect(report.file, 'file content in clear').toEqual([]);
    expect(report.value, 'shared field value in clear').toEqual([]);
    expect(report.hidden, 'unshared field value in clear').toEqual([]);
  });

  it('stored objects have AES-256-GCM shape and no PDF signature', async () => {
    const { documentId, file } = await seedEverything();
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: documentId }, include: { key: true } });
    expect(doc.encIv).toHaveLength(12);
    expect(doc.encTag).toHaveLength(16);
    expect(doc.key!.wrappedDek).toHaveLength(32);
    const stored =
      driver === 'database'
        ? Buffer.from((await ctx.prisma.storedObject.findUniqueOrThrow({ where: { key: doc.storageKey } })).data)
        : readFileSync(path.join(path.resolve(ctx.config.env.STORAGE_DIR), doc.storageKey.slice(0, 2), `${doc.storageKey}.bin`));
    expect(stored.length).toBe(file.length);
    expect(stored.subarray(0, 5).toString('latin1')).not.toBe('%PDF-');
    expect(stored.equals(file)).toBe(false);
  });

  // Known gap (audit A4/A5): titles, field labels and recipient names are stored in clear and
  // copied into logs and notifications. E3/E4 fix this; then change it.fails to it.
  it.fails('stores titles, field labels and recipient names only as ciphertext (fixed by E3/E4)', async () => {
    await seedEverything();
    const report = await findMarkers(ctx);
    console.info(`[E1 canary, ${driver}] metadata found in clear:`, JSON.stringify({ title: report.title, label: report.label, recipient: report.recipient }));
    expect(report.title).toEqual([]);
    expect(report.label).toEqual([]);
    expect(report.recipient).toEqual([]);
  });

  it('decrypts the original byte for byte for the owner', async () => {
    const { owner, documentId, file } = await seedEverything();
    const res = await as(ctx, owner, { method: 'GET', url: `/api/documents/${documentId}/file` });
    expect(res.statusCode).toBe(200);
    expect(res.rawPayload.equals(file)).toBe(true);
    expect(res.headers['cache-control']).toBe('no-store, private');
  });

  it('detects a single changed byte in storage and returns no content', async () => {
    const { owner, documentId } = await seedEverything();
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: documentId } });
    if (driver === 'database') {
      const row = await ctx.prisma.storedObject.findUniqueOrThrow({ where: { key: doc.storageKey } });
      const bytes = Buffer.from(row.data);
      bytes[20]! ^= 0x01;
      await ctx.prisma.storedObject.update({ where: { key: doc.storageKey }, data: { data: new Uint8Array(bytes) } });
    } else {
      const { writeFileSync } = await import('node:fs');
      const file = path.join(path.resolve(ctx.config.env.STORAGE_DIR), doc.storageKey.slice(0, 2), `${doc.storageKey}.bin`);
      const bytes = readFileSync(file);
      bytes[20]! ^= 0x01;
      writeFileSync(file, bytes);
    }
    const res = await as(ctx, owner, { method: 'GET', url: `/api/documents/${documentId}/file` });
    expect(res.statusCode).toBe(500);
    expect(res.json().error.code).toBe('integrity_error');
    expect(res.body).not.toContain(MARK.file);
  });

  it('gives a recipient only the selected field, never the hidden one', async () => {
    const { link } = await seedEverything();
    const res = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain(MARK.value);
    expect(res.body).not.toContain(MARK.hidden); // checked on the raw JSON, not the UI
    expect(res.json().fields).toHaveLength(1);
  });

  it('does not serve the file when the owner did not include it', async () => {
    const { owner, documentId, claims } = await seedEverything();
    const link = await createLink(ctx, owner, documentId, { claimIds: [claims[0]!.id], includeFile: false });
    const res = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}/file`, remoteAddress: IPS.SA });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('file_not_shared');
  });

  it('deletes the wrapped key and the ciphertext (crypto-shredding)', async () => {
    const { owner, documentId } = await seedEverything();
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: documentId } });
    expect((await as(ctx, owner, { method: 'DELETE', url: `/api/documents/${documentId}` })).statusCode).toBe(200);
    expect(await ctx.prisma.documentKey.count({ where: { documentId } })).toBe(0);
    expect(await ctx.prisma.documentClaim.count({ where: { documentId } })).toBe(0);
    if (driver === 'database') expect(await ctx.prisma.storedObject.count({ where: { key: doc.storageKey } })).toBe(0);
    const report = await findMarkers(ctx);
    expect(report.file).toEqual([]);
    expect(report.value).toEqual([]);
  });

  it('a server with a different KMS root key refuses to start and serves nothing', async () => {
    await seedEverything();
    const otherKmsFile = path.join(mkdtempSync(path.join(tmpdir(), 'trustpass-other-kms-')), 'root.key');
    await expect(
      createTestContext({ STORAGE_DRIVER: driver, STORAGE_DIR: ctx.config.env.STORAGE_DIR, FAKE_KMS_KEY_FILE: otherKmsFile }),
    ).rejects.toThrow(/KMS key|could not decrypt/i);
  });

  it('a server with a wrong legacy master key refuses to start', async () => {
    await seedEverything();
    await expect(
      createTestContext({
        STORAGE_DRIVER: driver,
        STORAGE_DIR: ctx.config.env.STORAGE_DIR,
        KEY_PROVIDER: 'env',
        MASTER_KEY: 'a-completely-different-master-key-0123456789-abcdefgh',
      }),
    ).rejects.toThrow(/does not open the stored document keys|not configured|clashes with a legacy master key/);
  });

  it('never stores a key-encryption key in clear', async () => {
    await seedEverything();
    const tables = await ctx.prisma.$queryRaw<Array<{ table_name: string }>>`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name <> '_prisma_migrations'`;
    const secrets = [...ctx.config.masterKeys.all.values(), ...ctx.config.linkTokenKeys.all.values()].map((k) => k.toString('hex'));
    for (const { table_name } of tables) {
      for (const hex of secrets) {
        const rows = await ctx.prisma.$queryRawUnsafe<Array<{ hits: bigint }>>(
          `SELECT count(*)::bigint AS hits FROM "${table_name}" x WHERE x::text ILIKE $1`,
          `%${hex}%`,
        );
        expect(Number(rows[0]!.hits), `key material in ${table_name}`).toBe(0);
      }
    }
  });
});

describe('test-fixture sanity', () => {
  it('reports whether the older sample PDF contains its marker as raw bytes', async () => {
    // documents.test.ts checks that PLAINTEXT_MARKER is absent from storage. That check is only
    // meaningful if the marker was present in the plaintext. pdf-lib writes page text as hex in a
    // compressed stream, so it may not be; this prints the answer for the E1 report.
    const pdf = await samplePdf();
    console.info(`[E1 fixture] samplePdf() contains PLAINTEXT_MARKER as raw bytes: ${pdf.includes(Buffer.from(PLAINTEXT_MARKER))}`);
    expect(pdf.length).toBeGreaterThan(0);
  });
});

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import sharp from 'sharp';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { as, createTestContext, issueCredential, multipart, registerUser, resetDatabase, resetKeyring, TEST_SECRETS, testPrisma, uploadDocument, type TestContext } from '../helpers';

/**
 * The backup recovery checker (scripts/backup/verify-secrets.mjs), run exactly as the recovery
 * check runs it: the export query is read from trustpass-recovery-check.sh itself, run on the
 * database, and the checker gets the secrets on standard input. Covers redacted copies too.
 */

const ROOT = path.resolve(__dirname, '../../../..');
const SCRIPT = readFileSync(path.join(ROOT, 'scripts/backup/trustpass-recovery-check.sh'), 'utf8');

/** The export SQL of the recovery check, with the redacted-pages part the script inserts. */
function exportSql(): string {
  const rp = SCRIPT.match(/\n  RP_SQL="(COALESCE\(\(SELECT json_agg[\s\S]*?)"\nfi/);
  const query = SCRIPT.match(/q "(SELECT json_build_object\([\s\S]*?)" > "\$WORK\/export\.json"/);
  if (!rp || !query) throw new Error('export query not found in trustpass-recovery-check.sh');
  return query[1]!.replace('$RP_SQL', rp[1]!);
}

function runChecker(masterKey: string): { code: number; report: Record<string, any> } {
  const dir = mkdtempSync(path.join(tmpdir(), 'recovery-check-'));
  const file = path.join(dir, 'export.json');
  writeFileSync(file, JSON.stringify(lastExport));
  const res = spawnSync(process.execPath, [path.join(ROOT, 'scripts/backup/verify-secrets.mjs'), file], {
    input: `${masterKey}\n${TEST_SECRETS.ISSUER_SIGNING_SEED}\n`,
    encoding: 'utf8',
  });
  return { code: res.status ?? -1, report: JSON.parse(res.stdout) };
}

let lastExport: unknown;
async function exportBackup() {
  const rows = await ctx.prisma.$queryRawUnsafe<Array<Record<string, unknown>>>(exportSql());
  lastExport = Object.values(rows[0]!)[0];
}

let ctx: TestContext;
beforeAll(async () => {
  const db = testPrisma();
  await resetDatabase(db);
  await resetKeyring(db);
  await db.$disconnect();
  ctx = await createTestContext({ KEY_PROVIDER: 'env', MASTER_KEY: TEST_SECRETS.MASTER_KEY, STORAGE_DRIVER: 'database' });
});
afterAll(async () => {
  await ctx?.app.close();
});
beforeEach(async () => {
  await resetDatabase(ctx.prisma);
});

async function withRedactedCopy() {
  const owner = await registerUser(ctx);
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  pdf.addPage([400, 300]).drawText('page one', { x: 20, y: 150, size: 14, font });
  pdf.addPage([400, 300]).drawText('page two', { x: 20, y: 150, size: 14, font });
  const id = (await uploadDocument(ctx, owner, { file: Buffer.from(await pdf.save()), claims: [{ label: 'Name', value: 'Reham' }] })).json().document.id as string;
  const page = await sharp({ create: { width: 800, height: 600, channels: 3, background: '#ffffff' } }).png().toBuffer();
  const form = multipart([
    {
      name: 'link',
      value: JSON.stringify({ includeFile: true, fileMode: 'redacted', redactions: [{ page: 0, x: 0, y: 0, w: 0.5, h: 0.5 }], recipientType: 'anyone', recipientLabel: 'Example', expiresIn: '24h', allowedCountries: [], claimIds: [] }),
    },
    { name: 'page', filename: 'p1.png', content: page, contentType: 'image/png' },
    { name: 'page', filename: 'p2.png', content: page, contentType: 'image/png' },
  ]);
  const res = await as(ctx, owner, { method: 'POST', url: `/api/documents/${id}/links`, payload: form.payload, headers: form.headers });
  expect(res.statusCode, res.body).toBe(201);
  await issueCredential(ctx, owner);
  return id;
}

describe('backup recovery checker (verify-secrets.mjs) with the recovery check’s own export query', () => {
  it('recovers every document, field, credential, link and redacted page with the right keys', async () => {
    await withRedactedCopy();
    await exportBackup();
    const { code, report } = runChecker(TEST_SECRETS.MASTER_KEY);
    expect(report.masterKey.failures).toEqual([]);
    expect(code).toBe(0);
    expect(report.masterKey).toMatchObject({ verdict: 'MASTER_KEY OK', documents: 2, recovered: 2, credentialsOpened: 1, redactedPages: 2, redactedPagesOpened: 2 });
    expect(report.issuerSeed.verdict).toBe('ISSUER_SIGNING_SEED OK');
    // The report carries no document content.
    expect(JSON.stringify(report)).not.toMatch(/Reham|page one/);
  });

  it('reports a damaged redacted page, and a wrong MASTER_KEY', async () => {
    const id = await withRedactedCopy();
    const pageRow = await ctx.prisma.redactedPage.findFirstOrThrow({ where: { documentId: id, pageIndex: 1 } });
    const stored = await ctx.prisma.storedObject.findUniqueOrThrow({ where: { key: pageRow.storageKey } });
    const damaged = Buffer.from(stored.data);
    damaged[damaged.length - 1]! ^= 0xff;
    await ctx.prisma.storedObject.update({ where: { key: pageRow.storageKey }, data: { data: new Uint8Array(damaged) } });
    await exportBackup();
    const damagedRun = runChecker(TEST_SECRETS.MASTER_KEY);
    expect(damagedRun.code).toBe(1);
    expect(damagedRun.report.masterKey.verdict).toBe('MASTER_KEY OK, BACKUP DAMAGED');
    expect(damagedRun.report.masterKey.failures.join(' ')).toMatch(/page 2 of a redacted copy/);

    const wrong = runChecker('a-wrong-master-key-0123456789-abcdefghijklmnop');
    expect(wrong.code).toBe(1);
    expect(wrong.report.masterKey.verdict).toBe('MASTER_KEY WRONG');
  });
});

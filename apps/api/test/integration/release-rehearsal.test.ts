import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { claimAad, claimLabelAad, open, seal, sha256Aad, titleAad } from '../../src/lib/crypto';
import { isLocalDatabase, runRehearsal } from '../../src/scripts/rehearsal';
import { loadDataKey } from '../../src/services/documents';
import {
  as,
  createLink,
  createTestContext,
  documentClaims,
  IPS,
  issueCredential,
  registerUser,
  resetDatabase,
  resetKeyring,
  samplePdf,
  samplePng,
  TEST_SECRETS,
  testPrisma,
  uploadDocument,
  type TestContext,
} from '../helpers';
import { TEST_DATABASE_URL } from '../env';

/**
 * The release rehearsal (scripts/rehearsal) on a database shaped like production today:
 * KEY_PROVIDER=env with MASTER_KEY, files in the database, documents in the pre-E3 format, and
 * links of every kind. The rehearsal itself is what runs on the restored production backup.
 */

let ctx: TestContext;
const secrets = { masterKey: TEST_SECRETS.MASTER_KEY, ipHashSecret: TEST_SECRETS.IP_HASH_SECRET, issuerSigningSeed: TEST_SECRETS.ISSUER_SIGNING_SEED };

beforeAll(async () => {
  // Earlier test files leave fake-KMS keys; a MASTER_KEY app (like production) refuses to start next to them.
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
  ctx.clock.now = new Date();
  await resetDatabase(ctx.prisma);
  await resetKeyring(ctx.prisma);
});

/** Puts a document back into the format production stores today (before E3). */
async function makeLegacy(documentId: string) {
  const dek = await loadDataKey(ctx.app.deps, documentId);
  const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: documentId }, include: { claims: true, links: true } });
  await ctx.prisma.document.update({
    where: { id: documentId },
    data: {
      title: open(dek, doc.titleEncrypted!, titleAad(documentId)).toString(),
      titleEncrypted: null,
      plaintextSha256: open(dek, doc.sha256Encrypted!, sha256Aad(documentId)).toString(),
      sha256Encrypted: null,
    },
  });
  for (const c of doc.claims.filter((x) => x.source === 'self_declared')) {
    const label = open(dek, c.labelEncrypted!, claimLabelAad(documentId, c.claimKey)).toString();
    const value = open(dek, c.valueEncrypted, claimAad(documentId, c.claimKey, 'value'));
    const legacyKey = label.toLowerCase().replace(/[^a-z0-9]+/g, '_');
    await ctx.prisma.documentClaim.update({
      where: { id: c.id },
      data: { claimKey: legacyKey, label, labelEncrypted: null, valueEncrypted: seal(dek, value, claimAad(documentId, legacyKey, 'value')) },
    });
  }
  for (const l of doc.links) {
    const { openRecipientLabel } = await import('../../src/services/metadata');
    await ctx.prisma.sharingLink.update({ where: { id: l.id }, data: { recipientLabel: openRecipientLabel(dek, l), recipientLabelEncrypted: null } });
  }
  dek.fill(0);
}

/** Production-like data: every kind of document and link. */
async function productionLike() {
  const owner = await registerUser(ctx, { fullName: 'Reham Test' });
  const company = await registerUser(ctx, { organization: 'Example Company', fullName: 'Hiring Manager' });

  const pdf = await samplePdf();
  const doc = (await uploadDocument(ctx, owner, { file: pdf, title: 'Passport scan', claims: [{ label: 'Employer', value: 'Aramco' }, { label: 'National ID', value: '1234567890' }] })).json().document.id as string;
  const claims = await documentClaims(ctx, owner, doc);
  const image = (await uploadDocument(ctx, owner, { file: await samplePng(), filename: 'scan.png', title: 'ID photo' })).json().document.id as string;
  const credential = await issueCredential(ctx, owner);
  const status = (await documentClaims(ctx, owner, credential)).find((c) => c.key === 'enrollment_status')!;
  const gone = (await uploadDocument(ctx, owner, { title: 'Old contract' })).json().document.id as string;

  const links = {
    fieldsAndFile: await createLink(ctx, owner, doc, { claimIds: [claims[0]!.id], includeFile: true, recipientLabel: 'Riyadh Bank HR' }),
    uaeOnly: await createLink(ctx, owner, doc, { claimIds: [claims[1]!.id], allowedCountries: ['AE'] }),
    image: await createLink(ctx, owner, image, { includeFile: true }),
    credential: await createLink(ctx, owner, credential, { claimIds: [status.id], includeFile: true }),
    organization: await createLink(ctx, owner, doc, { includeFile: true, recipientType: 'organization', recipientOrgId: company.orgId }),
    revoked: await createLink(ctx, owner, doc, { includeFile: true }),
    expiring: await createLink(ctx, owner, image, { includeFile: true, expiresIn: '1h' }),
    onDeleted: await createLink(ctx, owner, gone, { includeFile: true }),
  };
  await as(ctx, owner, { method: 'POST', url: `/api/links/${links.revoked.id}/revoke` });
  await as(ctx, owner, { method: 'DELETE', url: `/api/documents/${gone}` });
  // A real view, so access logs and notifications exist like in production.
  expect((await ctx.app.inject({ method: 'GET', url: `/api/share/${links.fieldsAndFile.token}`, remoteAddress: IPS.SA })).statusCode).toBe(200);

  await makeLegacy(doc);
  await makeLegacy(image);
  return { owner, company, doc, image, credential, links };
}

const twoHoursLater = () => new Date(Date.now() + 2 * 60 * 60_000);

describe('release rehearsal on a production-like copy', () => {
  it('passes: every document, field, credential, link and download reads the same before and after the backfill', async () => {
    const data = await productionLike();
    const plainTitlesBefore = await ctx.prisma.document.count({ where: { title: { not: null } } });
    expect(plainTitlesBefore).toBe(2);

    const report = await runRehearsal(TEST_DATABASE_URL, secrets, { realNow: twoHoursLater() });
    expect(report.reasons).toEqual([]);
    expect(report.verdict).toBe('REHEARSAL PASSED');
    expect(report.startupChecks).toBe('passed');
    expect(report.kekVersions).toEqual([1]);

    expect(report.before.counts).toMatchObject({ documents: 3, files: 3, credentials: 1, credentialsVerified: 1 });
    expect(report.after.counts).toEqual(report.before.counts);
    expect(report.unchangedDocuments).toBe(3);
    expect(report.changedDocuments).toEqual([]);
    expect(report.dryRun).toMatchObject({ documentsToSeal: 2, fieldsToRename: 2, readBackFailures: 0 });
    expect(report.backfill.ok).toBe(true);
    expect(Object.values(report.plainMetadataAfter).every((n) => n === 0)).toBe(true);
    expect(report.secondRunChanges).toBe(0);
    expect(report.ciphertextUnchanged).toBe(true);

    const links = report.links!;
    expect(links).toMatchObject({
      links: 8,
      tokensRecovered: 8,
      endedRefused: 2, // revoked + deleted document
      expiredRefusedToday: 1,
      viewsOk: 6,
      filesOk: 5,
      downloadsOk: 5,
      downloadsOffByDefault: true,
      failures: [],
      skipped: [],
    });

    // The rehearsal really converted this copy (it is a throw-away restore in real use).
    expect(await ctx.prisma.document.count({ where: { title: { not: null } } })).toBe(0);
    // ... and downloads are back OFF on every link.
    expect(await ctx.prisma.sharingLink.count({ where: { allowDownload: true } })).toBe(0);
    // The report carries no names, values or tokens.
    const text = JSON.stringify(report);
    for (const secret of ['Passport scan', 'ID photo', 'Aramco', '1234567890', 'Riyadh Bank HR', data.links.fieldsAndFile.token, TEST_SECRETS.MASTER_KEY]) {
      expect(text).not.toContain(secret);
    }
  });

  it('fails when a stored file is damaged, and names the document', async () => {
    const data = await productionLike();
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: data.image } });
    const bytes = Buffer.from(await ctx.app.deps.storage.get(doc.storageKey));
    bytes[5]! ^= 0xff;
    // Database storage never overwrites; damage the stored ciphertext in place.
    await ctx.prisma.storedObject.update({ where: { key: doc.storageKey }, data: { data: new Uint8Array(bytes) } });

    const report = await runRehearsal(TEST_DATABASE_URL, secrets, { realNow: twoHoursLater() });
    expect(report.verdict).toBe('REHEARSAL FAILED');
    expect(report.before.failures).toContainEqual({ ref: data.image.slice(0, 8), stage: 'file' });
  });

  it('fails on a read-back problem and leaves that document in clear', async () => {
    const data = await productionLike();
    const dek = await loadDataKey(ctx.app.deps, data.doc);
    await ctx.prisma.document.update({ where: { id: data.doc }, data: { titleEncrypted: seal(dek, 'Something else', titleAad(data.doc)) } });
    dek.fill(0);

    const report = await runRehearsal(TEST_DATABASE_URL, secrets, { realNow: twoHoursLater() });
    expect(report.verdict).toBe('REHEARSAL FAILED');
    expect(report.dryRun.readBackFailures).toBe(1);
    expect(report.reasons).toContain('1 document(s) fail the read-back check');
    expect((await ctx.prisma.document.findUniqueOrThrow({ where: { id: data.doc } })).title).toBe('Passport scan');
  });

  it('refuses to start with the wrong MASTER_KEY, and changes nothing', async () => {
    await productionLike();
    const before = await ctx.prisma.document.count({ where: { title: { not: null } } });
    const report = await runRehearsal(TEST_DATABASE_URL, { ...secrets, masterKey: 'a-wrong-master-key-0123456789-abcdefghijklmnop' });
    expect(report.startupChecks).toBe('refused');
    expect(report.verdict).toBe('REHEARSAL FAILED');
    expect(await ctx.prisma.document.count({ where: { title: { not: null } } })).toBe(before);
  });

  it('never runs against a remote database', async () => {
    expect(isLocalDatabase('postgresql://u@localhost:5432/db')).toBe(true);
    expect(isLocalDatabase('postgresql://postgres@localhost/rehearsal?host=/work/pg/sock')).toBe(true);
    expect(isLocalDatabase('postgresql://trustpass:x@dpg-dbthlre7bikc73cmpuvg-a/trustpass_nxbq')).toBe(false);
    expect(isLocalDatabase('postgresql://trustpass:x@dpg-x-a.frankfurt-postgres.render.com/db')).toBe(false);
    await expect(runRehearsal('postgresql://trustpass:x@dpg-x-a.frankfurt-postgres.render.com/db', secrets)).rejects.toThrow(/local copy/);
  });
});


import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { claimAad, claimLabelAad, open, recipientLabelAad, seal, sha256Aad, titleAad } from '../../src/lib/crypto';
import { loadDataKey } from '../../src/services/documents';
import {
  as,
  createLink,
  createTestContext,
  documentClaims,
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

/**
 * CI only (REHEARSAL_FIXTURE=1): leaves the test database looking like PRODUCTION TODAY, for the
 * end-to-end test of scripts/rehearsal/trustpass-release-rehearsal.sh:
 *  - KEY_PROVIDER=env with MASTER_KEY, files in the database;
 *  - every row in the pre-E3 format (plain titles, labels, recipient names, hashes; field keys
 *    derived from labels), links of every kind;
 *  - the schema of the only migration production has applied (20261115211140_init): every later
 *    migration is undone and removed from _prisma_migrations. CI then proves the result equals that
 *    migration exactly (prisma migrate diff --exit-code) before backing it up.
 * Skipped in normal test runs.
 */

const enabled = process.env.REHEARSAL_FIXTURE === '1';
let ctx: TestContext;

describe.skipIf(!enabled)('production-shaped fixture for the rehearsal script', () => {
  beforeAll(async () => {
    const db = testPrisma();
    await resetDatabase(db);
    await resetKeyring(db);
    await db.$disconnect();
    ctx = await createTestContext({ KEY_PROVIDER: 'env', MASTER_KEY: TEST_SECRETS.MASTER_KEY, STORAGE_DRIVER: 'database' });
    await resetDatabase(ctx.prisma);
    await resetKeyring(ctx.prisma);
  });
  let closed = false;
  afterAll(async () => {
    if (ctx && !closed) await ctx.app.close();
  });

  it('builds the data and turns the database back into the production schema of today', async () => {
    const owner = await registerUser(ctx, { fullName: 'Fixture Owner' });
    const company = await registerUser(ctx, { organization: 'Fixture Company', fullName: 'Fixture Manager' });
    const doc = (await uploadDocument(ctx, owner, { file: await samplePdf(), title: 'Fixture Passport', claims: [{ label: 'Employer', value: 'FixtureCorp' }, { label: 'National ID', value: '1029384756' }] })).json().document.id as string;
    const claims = await documentClaims(ctx, owner, doc);
    const image = (await uploadDocument(ctx, owner, { file: await samplePng(), filename: 'scan.png', title: 'Fixture Photo' })).json().document.id as string;
    const credential = await issueCredential(ctx, owner);
    const status = (await documentClaims(ctx, owner, credential)).find((c) => c.key === 'enrollment_status')!;
    const gone = (await uploadDocument(ctx, owner, { title: 'Fixture Deleted' })).json().document.id as string;

    await createLink(ctx, owner, doc, { claimIds: [claims[0]!.id], includeFile: true, recipientLabel: 'Fixture Bank HR' });
    await createLink(ctx, owner, doc, { claimIds: [claims[1]!.id], allowedCountries: ['AE'] });
    await createLink(ctx, owner, image, { includeFile: true });
    await createLink(ctx, owner, credential, { claimIds: [status.id], includeFile: true });
    await createLink(ctx, owner, doc, { includeFile: true, recipientType: 'organization', recipientOrgId: company.orgId });
    const revoked = await createLink(ctx, owner, doc, { includeFile: true });
    await createLink(ctx, owner, gone, { includeFile: true });
    await as(ctx, owner, { method: 'POST', url: `/api/links/${revoked.id}/revoke` });
    await as(ctx, owner, { method: 'DELETE', url: `/api/documents/${gone}` });

    // Every document back to the pre-E3 format.
    for (const id of [doc, image, credential]) {
      const dek = await loadDataKey(ctx.app.deps, id);
      const row = await ctx.prisma.document.findUniqueOrThrow({ where: { id }, include: { claims: true, links: true } });
      await ctx.prisma.document.update({
        where: { id },
        data: {
          title: open(dek, row.titleEncrypted!, titleAad(id)).toString(),
          titleEncrypted: null,
          plaintextSha256: open(dek, row.sha256Encrypted!, sha256Aad(id)).toString(),
          sha256Encrypted: null,
        },
      });
      for (const c of row.claims) {
        const label = open(dek, c.labelEncrypted!, claimLabelAad(id, c.claimKey)).toString();
        if (c.source === 'self_declared') {
          const value = open(dek, c.valueEncrypted, claimAad(id, c.claimKey, 'value'));
          const legacyKey = label.toLowerCase().replace(/[^a-z0-9]+/g, '_');
          await ctx.prisma.documentClaim.update({
            where: { id: c.id },
            data: { claimKey: legacyKey, label, labelEncrypted: null, valueEncrypted: seal(dek, value, claimAad(id, legacyKey, 'value')) },
          });
        } else {
          await ctx.prisma.documentClaim.update({ where: { id: c.id }, data: { label, labelEncrypted: null } });
        }
      }
      for (const l of row.links) {
        const label = open(dek, l.recipientLabelEncrypted!, recipientLabelAad(id, l.id)).toString();
        await ctx.prisma.sharingLink.update({ where: { id: l.id }, data: { recipientLabel: label, recipientLabelEncrypted: null } });
      }
      dek.fill(0);
    }
    // The deleted document, as the old code left it (its key is gone; placeholders in clear).
    await ctx.prisma.document.update({ where: { id: gone }, data: { title: '[deleted document]', plaintextSha256: '0'.repeat(64), titleEncrypted: null, sha256Encrypted: null } });
    await ctx.prisma.sharingLink.updateMany({ where: { documentId: gone }, data: { recipientLabel: 'Recipient', recipientLabelEncrypted: null } });

    // Undo every migration after init (all of them only added things; nothing in clear is lost).
    await ctx.app.close();
    closed = true;
    const db = ctx.prisma;
    await db.$executeRawUnsafe(`DROP TABLE "key_encryption_keys"`);
    await db.$executeRawUnsafe(`DROP FUNCTION trustpass_protect_keyring()`);
    await db.$executeRawUnsafe(`DROP FUNCTION trustpass_refuse_fake_kms_in_production()`);
    await db.$executeRawUnsafe(`DROP TRIGGER "system_settings_protect_environment" ON "system_settings"`);
    await db.$executeRawUnsafe(`DROP TRIGGER "system_settings_protect_environment_truncate" ON "system_settings"`);
    await db.$executeRawUnsafe(`DROP FUNCTION trustpass_protect_environment_marker()`);
    await db.$executeRawUnsafe(`DELETE FROM "system_settings" WHERE "key" IN ('environment', 'maintenance:last')`);
    await db.$executeRawUnsafe(`ALTER TABLE "documents" DROP COLUMN "title_encrypted", DROP COLUMN "sha256_encrypted", ALTER COLUMN "title" SET NOT NULL, ALTER COLUMN "plaintext_sha256" SET NOT NULL`);
    await db.$executeRawUnsafe(`ALTER TABLE "document_claims" DROP COLUMN "label_encrypted", ALTER COLUMN "label" SET NOT NULL`);
    await db.$executeRawUnsafe(`ALTER TABLE "sharing_links" DROP COLUMN "recipient_label_encrypted", DROP COLUMN "allow_download", ALTER COLUMN "recipient_label" SET NOT NULL`);
    await db.$executeRawUnsafe(`ALTER TYPE "AccessResource" RENAME TO "AccessResource_release"`);
    await db.$executeRawUnsafe(`CREATE TYPE "AccessResource" AS ENUM ('details', 'file')`);
    await db.$executeRawUnsafe(`ALTER TABLE "access_logs" ALTER COLUMN "resource" TYPE "AccessResource" USING "resource"::text::"AccessResource"`);
    await db.$executeRawUnsafe(`DROP TYPE "AccessResource_release"`);
    const removed = await db.$executeRawUnsafe(`DELETE FROM "_prisma_migrations" WHERE "migration_name" > '20261115211140_init'`);
    expect(removed).toBe(4);
    const titles = await db.$queryRawUnsafe<Array<{ n: bigint }>>(`SELECT count(*)::bigint AS n FROM documents WHERE title IS NOT NULL`);
    expect(Number(titles[0]!.n)).toBe(4);
  });
});

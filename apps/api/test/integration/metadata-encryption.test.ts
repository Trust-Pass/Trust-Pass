import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { claimAad, claimLabelAad, open, recipientLabelAad, seal, sha256Aad, sha256Hex, titleAad } from '../../src/lib/crypto';
import { loadDataKey } from '../../src/services/documents';
import { countPlainMetadata, encryptLegacyMetadata, metadataMigrationSucceeded } from '../../src/services/metadata-migration';
import { as, createLink, createTestContext, documentClaims, IPS, registerUser, resetDatabase, samplePdf, uploadDocument, type Session, type TestContext } from '../helpers';

/**
 * E3/E4/E5: titles, field labels, recipient names and file hashes are encrypted at rest, logs and
 * notifications carry ids only, and every page still shows the real names to the people allowed
 * to see them. Also: the one-time backfill for rows written before E3.
 */

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestContext({ STORAGE_DRIVER: 'database' });
});
afterAll(async () => {
  await ctx.app.close();
});
beforeEach(async () => {
  ctx.clock.now = new Date();
  await resetDatabase(ctx.prisma);
});

const TITLE = 'Passport of Reham';
const RECIPIENT = 'Riyadh Bank HR';

async function seed(owner: Session) {
  const file = await samplePdf();
  const up = await uploadDocument(ctx, owner, {
    file,
    title: TITLE,
    claims: [
      { label: 'Employer', value: 'Aramco' },
      { label: 'National ID', value: '1234567890' },
    ],
  });
  expect(up.statusCode).toBe(201);
  const documentId = up.json().document.id as string;
  const claims = await documentClaims(ctx, owner, documentId);
  const link = await createLink(ctx, owner, documentId, { claimIds: [claims[0]!.id], recipientLabel: RECIPIENT });
  // A view from a new country raises an alert notification for the owner.
  const view = await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA });
  expect(view.statusCode).toBe(200);
  return { documentId, link, file, claims };
}

describe('new rows (E3/E4/E5)', () => {
  it('stores only sealed metadata, opened with the document key and bound to its row', async () => {
    const owner = await registerUser(ctx);
    const { documentId, link, file } = await seed(owner);
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: documentId }, include: { claims: true } });
    expect(doc.title).toBeNull();
    expect(doc.plaintextSha256).toBeNull();
    expect(doc.claims.every((c) => c.label === null && c.labelEncrypted)).toBe(true);
    expect(doc.claims.map((c) => c.claimKey).sort()).toEqual(['f1', 'f2']); // keys no longer repeat labels
    const row = await ctx.prisma.sharingLink.findUniqueOrThrow({ where: { id: link.id } });
    expect(row.recipientLabel).toBeNull();

    const dek = await loadDataKey(ctx.app.deps, documentId);
    expect(open(dek, doc.titleEncrypted!, titleAad(documentId)).toString()).toBe(TITLE);
    expect(open(dek, doc.sha256Encrypted!, sha256Aad(documentId)).toString()).toBe(sha256Hex(file));
    expect(open(dek, row.recipientLabelEncrypted!, recipientLabelAad(documentId, link.id)).toString()).toBe(RECIPIENT);
    // Moving a sealed title to another document fails: the AAD binds it to its row.
    expect(() => open(dek, doc.titleEncrypted!, titleAad('00000000-0000-4000-8000-000000000000'))).toThrow();
    dek.fill(0);
  });

  it('logs and notifications contain ids, never the title or the recipient', async () => {
    const owner = await registerUser(ctx);
    await seed(owner);
    const events = await ctx.prisma.securityEvent.findMany({ where: { userId: owner.userId } });
    expect(events.length).toBeGreaterThan(2);
    expect(JSON.stringify(events.map((e) => e.metadata))).not.toMatch(/Passport|Riyadh Bank|Employer|National ID/);
    const notes = await ctx.prisma.notification.findMany({ where: { userId: owner.userId } });
    expect(notes.length).toBeGreaterThan(0);
    for (const n of notes) expect(`${n.title} ${n.body}`).not.toMatch(/Passport|Riyadh Bank/);
    expect(notes.some((n) => n.body.includes('"{document}" ({recipient})'))).toBe(true);
  });

  it('every page still shows the real names to the owner and the recipient', async () => {
    const owner = await registerUser(ctx);
    const { documentId, link } = await seed(owner);
    const get = async (url: string) => (await as(ctx, owner, { method: 'GET', url })).json();

    expect((await get('/api/documents')).documents[0].title).toBe(TITLE);
    const detail = (await get(`/api/documents/${documentId}`)).document;
    expect(detail.title).toBe(TITLE);
    expect(detail.claims.map((c: { label: string }) => c.label)).toEqual(['Employer', 'National ID']);
    expect(detail.links[0].recipientLabel).toBe(RECIPIENT);
    expect(detail.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(detail.encryption.encryptedMetadata).toBe(true);

    const links = (await get('/api/links')).links;
    expect(links[0]).toMatchObject({ recipientLabel: RECIPIENT, document: { title: TITLE } });
    const one = (await get(`/api/links/${link.id}`)).link;
    expect(one).toMatchObject({ recipientLabel: RECIPIENT, document: { title: TITLE } });
    expect(one.fields.map((f: { label: string }) => f.label)).toEqual(['Employer']);

    const notifications = (await get('/api/notifications')).notifications;
    expect(notifications[0].body).toContain(`"${TITLE}" (${RECIPIENT})`);
    const activity = (await get('/api/activity')).events;
    expect(activity.find((e: { type: string }) => e.type === 'link_created')).toMatchObject({ document: TITLE, metadata: { recipient: RECIPIENT } });
    const log = (await get('/api/analytics/access-log')).rows;
    expect(log[0]).toMatchObject({ document: TITLE, recipient: RECIPIENT });
    expect((await get('/api/dashboard')).recentAccess[0]).toMatchObject({ document: TITLE, recipient: RECIPIENT });

    const share = (await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA })).json();
    expect(share.document.title).toBe(TITLE);
    expect(share.link.recipientLabel).toBe(RECIPIENT);
    expect(share.fields).toEqual([{ label: 'Employer', value: 'Aramco', source: 'self_declared' }]);
  });

  it('another user sees none of it', async () => {
    const owner = await registerUser(ctx);
    const { documentId, link } = await seed(owner);
    const other = await registerUser(ctx);
    for (const url of [`/api/documents/${documentId}`, `/api/links/${link.id}`]) {
      expect((await as(ctx, other, { method: 'GET', url })).statusCode).toBe(404);
    }
    for (const url of ['/api/documents', '/api/links', '/api/notifications', '/api/activity', '/api/analytics/access-log', '/api/dashboard']) {
      const res = await as(ctx, other, { method: 'GET', url });
      expect(res.body).not.toMatch(/Passport|Riyadh Bank/);
    }
  });

  it('deleting a document erases its metadata; old notifications say "Deleted document"', async () => {
    const owner = await registerUser(ctx);
    const { documentId, link } = await seed(owner);
    expect((await as(ctx, owner, { method: 'DELETE', url: `/api/documents/${documentId}` })).statusCode).toBe(200);
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: documentId } });
    expect(doc).toMatchObject({ title: null, titleEncrypted: null, plaintextSha256: null, sha256Encrypted: null });
    const row = await ctx.prisma.sharingLink.findUniqueOrThrow({ where: { id: link.id } });
    expect(row).toMatchObject({ recipientLabel: null, recipientLabelEncrypted: null });
    const notes = (await as(ctx, owner, { method: 'GET', url: '/api/notifications' })).json().notifications;
    expect(notes[0].body).toContain('"Deleted document"');
  });
});

describe('backfill of rows written before E3 (keys encrypt-metadata)', () => {
  /** Turn a freshly uploaded document back into the pre-E3 storage format. */
  async function makeLegacy(documentId: string, linkId: string, ownerId: string) {
    const dek = await loadDataKey(ctx.app.deps, documentId);
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: documentId }, include: { claims: true } });
    await ctx.prisma.document.update({
      where: { id: documentId },
      data: {
        title: open(dek, doc.titleEncrypted!, titleAad(documentId)).toString(),
        titleEncrypted: null,
        plaintextSha256: open(dek, doc.sha256Encrypted!, sha256Aad(documentId)).toString(),
        sha256Encrypted: null,
      },
    });
    for (const c of doc.claims) {
      const label = open(dek, c.labelEncrypted!, claimLabelAad(documentId, c.claimKey)).toString();
      const value = open(dek, c.valueEncrypted, claimAad(documentId, c.claimKey, 'value'));
      const legacyKey = label.toLowerCase().replace(/[^a-z0-9]+/g, '_'); // old slug format: "national_id"
      await ctx.prisma.documentClaim.update({
        where: { id: c.id },
        data: { claimKey: legacyKey, label, labelEncrypted: null, valueEncrypted: seal(dek, value, claimAad(documentId, legacyKey, 'value')) },
      });
    }
    await ctx.prisma.sharingLink.update({ where: { id: linkId }, data: { recipientLabel: RECIPIENT, recipientLabelEncrypted: null } });
    await ctx.prisma.securityEvent.create({ data: { userId: ownerId, eventType: 'document_uploaded', documentId, metadata: { title: TITLE, mimeType: 'application/pdf' } } });
    await ctx.prisma.securityEvent.create({ data: { userId: ownerId, eventType: 'link_revoked', documentId, linkId, metadata: { recipient: RECIPIENT } } });
    await ctx.prisma.notification.create({
      data: { userId: ownerId, type: 'alert_new_country', title: 'First view from Saudi Arabia', body: `Your link for "${TITLE}" (${RECIPIENT}) was opened from Saudi Arabia for the first time. Location is approximate.`, linkId, documentId },
    });
    dek.fill(0);
  }

  it('dry run changes nothing; the real run encrypts everything, keeps every value readable, and is idempotent', async () => {
    const owner = await registerUser(ctx);
    const { documentId, link } = await seed(owner);
    // A deleted document from before E3 with its title still in clear.
    const gone = await seed(owner);
    await as(ctx, owner, { method: 'DELETE', url: `/api/documents/${gone.documentId}` });
    await ctx.prisma.document.update({ where: { id: gone.documentId }, data: { title: '[deleted document]', plaintextSha256: 'ab'.repeat(32) } });
    await makeLegacy(documentId, link.id, owner.userId);

    const before = await countPlainMetadata(ctx.prisma);
    expect(before).toEqual({ titles: 2, hashes: 2, labels: 2, recipients: 1, logRows: 2, notifications: 1 });
    const eventIdsBefore = (await ctx.prisma.securityEvent.findMany({ select: { id: true }, orderBy: { id: 'asc' } })).map((e) => e.id);

    const dry = await ctx.prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe('SET TRANSACTION READ ONLY');
      return encryptLegacyMetadata({ config: ctx.config, prisma: tx }, { dryRun: true });
    });
    expect(dry.documents).toMatchObject({ sealed: 1, deletedErased: 1, withoutKey: [] });
    expect(dry.fields.renamed).toBe(2);
    expect(await countPlainMetadata(ctx.prisma)).toEqual(before);

    const run = await encryptLegacyMetadata({ config: ctx.config, prisma: ctx.prisma });
    expect(metadataMigrationSucceeded(run)).toBe(true);
    expect(run).toMatchObject({ documents: { sealed: 1, deletedErased: 1 }, fields: { sealed: 2, renamed: 2 }, links: { sealed: 1 }, notifications: { rewritten: 1 }, logs: { cleaned: 2 } });
    expect(await countPlainMetadata(ctx.prisma)).toEqual({ titles: 0, hashes: 0, labels: 0, recipients: 0, logRows: 0, notifications: 0 });

    // Log rows were copied, not lost: same ids, nothing named any more.
    const after = await ctx.prisma.securityEvent.findMany({ orderBy: { id: 'asc' } });
    expect(after.map((e) => e.id)).toEqual(eventIdsBefore);
    expect(JSON.stringify(after.map((e) => e.metadata))).not.toMatch(/Passport|Riyadh Bank/);

    // Everything still reads the same through the API, including renamed fields and the file.
    const detail = (await as(ctx, owner, { method: 'GET', url: `/api/documents/${documentId}` })).json().document;
    expect(detail.title).toBe(TITLE);
    expect(detail.claims.map((c: { label: string; value: string }) => [c.label, c.value])).toEqual([
      ['Employer', 'Aramco'],
      ['National ID', '1234567890'],
    ]);
    expect(detail.links[0].recipientLabel).toBe(RECIPIENT);
    const fileRes = await as(ctx, owner, { method: 'GET', url: `/api/documents/${documentId}/file` });
    expect(fileRes.statusCode).toBe(200);
    const share = (await ctx.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA })).json();
    expect(share.fields).toEqual([{ label: 'Employer', value: 'Aramco', source: 'self_declared' }]);
    const notes = (await as(ctx, owner, { method: 'GET', url: '/api/notifications' })).json().notifications;
    expect(notes.find((n: { body: string }) => n.body.startsWith('Your link for'))!.body).toContain(`"${TITLE}" (${RECIPIENT})`);

    // Second run: nothing to do.
    const again = await encryptLegacyMetadata({ config: ctx.config, prisma: ctx.prisma });
    expect(again).toMatchObject({ documents: { sealed: 0, deletedErased: 0 }, fields: { sealed: 0, renamed: 0 }, links: { sealed: 0 }, notifications: { rewritten: 0 }, logs: { cleaned: 0 } });
  });
});

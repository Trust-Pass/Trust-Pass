import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { claimAad, claimLabelAad, open, recipientLabelAad, seal, sha256Aad, sha256Hex, titleAad } from '../../src/lib/crypto';
import { loadDataKey } from '../../src/services/documents';
import { countPlainMetadata, encryptLegacyMetadata, metadataMigrationSucceeded } from '../../src/services/metadata-migration';
import { runKeysCli } from '../../src/scripts/keys';
import { as, cliEnv, createLink, createTestContext, documentClaims, IPS, registerUser, resetDatabase, samplePdf, testPrisma, uploadDocument, type Session, type TestContext } from '../helpers';

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

/** Turns a document written by the current code back into the pre-E3 format (plain metadata, label-derived keys). */
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

describe('backfill of rows written before E3 (keys encrypt-metadata)', () => {
  /** Turn a freshly uploaded document back into the pre-E3 storage format. */
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

describe('backfill read-back: no plain value is cleared unless its encrypted copy opens to the same value', () => {
  /** Two documents in the old format; returns their ids. */
  async function twoLegacy(owner: Session) {
    const a = await seed(owner);
    const b = await seed(owner);
    await makeLegacy(a.documentId, a.link.id, owner.userId);
    await makeLegacy(b.documentId, b.link.id, owner.userId);
    return { a, b };
  }

  async function plainState(documentId: string) {
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id: documentId }, include: { claims: { orderBy: { position: 'asc' } }, links: true } });
    return {
      title: doc.title,
      titleEncrypted: doc.titleEncrypted ? Buffer.from(doc.titleEncrypted).toString('hex') : null,
      sha: doc.plaintextSha256,
      claims: doc.claims.map((c) => ({ key: c.claimKey, label: c.label, value: Buffer.from(c.valueEncrypted).toString('hex'), labelEncrypted: c.labelEncrypted ? 1 : 0 })),
      links: doc.links.map((l) => ({ recipient: l.recipientLabel, enc: l.recipientLabelEncrypted ? Buffer.from(l.recipientLabelEncrypted).toString('hex') : null })),
    };
  }

  async function expectConverted(documentId: string) {
    const st = await plainState(documentId);
    expect(st.title).toBeNull();
    expect(st.sha).toBeNull();
    expect(st.claims.every((c) => c.label === null && /^f\d+$/.test(c.key))).toBe(true);
    expect(st.links.every((l) => l.recipient === null)).toBe(true);
  }

  it('an existing encrypted title that says something else: the document is left exactly as it was', async () => {
    const owner = await registerUser(ctx);
    const { a, b } = await twoLegacy(owner);
    const dek = await loadDataKey(ctx.app.deps, a.documentId);
    await ctx.prisma.document.update({ where: { id: a.documentId }, data: { titleEncrypted: seal(dek, 'A different title', titleAad(a.documentId)) } });
    dek.fill(0);
    const before = await plainState(a.documentId);

    const run = await encryptLegacyMetadata({ config: ctx.config, prisma: ctx.prisma });
    expect(run.documents.verifyFailed).toEqual([a.documentId]);
    expect(metadataMigrationSucceeded(run)).toBe(false);
    // Nothing of document A changed: not its title, not its fields, not its links.
    expect(await plainState(a.documentId)).toEqual(before);
    expect(before.title).toBe(TITLE);
    // Document B was converted normally, and counted.
    await expectConverted(b.documentId);
    expect(run.documents.sealed).toBe(1);
    expect(run.fields).toEqual({ sealed: 2, renamed: 2 });

    // Once the cause is removed, a second run converts A and keeps its real title.
    await ctx.prisma.document.update({ where: { id: a.documentId }, data: { titleEncrypted: null } });
    const again = await encryptLegacyMetadata({ config: ctx.config, prisma: ctx.prisma });
    expect(again.documents.verifyFailed).toEqual([]);
    expect(metadataMigrationSucceeded(again)).toBe(true);
    await expectConverted(a.documentId);
    const detail = (await as(ctx, owner, { method: 'GET', url: `/api/documents/${a.documentId}` })).json().document;
    expect(detail.title).toBe(TITLE);
  });

  it('an encrypted title copied from another document (wrong binding) is refused', async () => {
    const owner = await registerUser(ctx);
    const { a, b } = await twoLegacy(owner);
    const dekB = await loadDataKey(ctx.app.deps, b.documentId);
    // Same text, sealed for document B: it cannot open as document A's title.
    await ctx.prisma.document.update({ where: { id: a.documentId }, data: { titleEncrypted: seal(dekB, TITLE, titleAad(b.documentId)) } });
    dekB.fill(0);
    const before = await plainState(a.documentId);
    const run = await encryptLegacyMetadata({ config: ctx.config, prisma: ctx.prisma });
    expect(run.documents.verifyFailed).toEqual([a.documentId]);
    expect(await plainState(a.documentId)).toEqual(before);
    await expectConverted(b.documentId);
  });

  it('a mismatching encrypted recipient name keeps the whole document in clear (all or nothing)', async () => {
    const owner = await registerUser(ctx);
    const { a, b } = await twoLegacy(owner);
    const dek = await loadDataKey(ctx.app.deps, a.documentId);
    await ctx.prisma.sharingLink.update({
      where: { id: a.link.id },
      data: { recipientLabelEncrypted: seal(dek, 'Someone else', recipientLabelAad(a.documentId, a.link.id)) },
    });
    dek.fill(0);
    const before = await plainState(a.documentId);
    const run = await encryptLegacyMetadata({ config: ctx.config, prisma: ctx.prisma });
    expect(run.documents.verifyFailed).toEqual([a.documentId]);
    const after = await plainState(a.documentId);
    expect(after).toEqual(before);
    expect(after.title).toBe(TITLE); // the title was fine, but it was not cleared either
    expect(after.links[0]!.recipient).toBe(RECIPIENT);
    await expectConverted(b.documentId);
  });

  it('a damaged field value is refused before its key is renamed', async () => {
    const owner = await registerUser(ctx);
    const { a, b } = await twoLegacy(owner);
    const claim = (await ctx.prisma.documentClaim.findMany({ where: { documentId: a.documentId }, orderBy: { position: 'asc' } }))[0]!;
    const damaged = Buffer.from(claim.valueEncrypted);
    damaged[damaged.length - 1]! ^= 0xff;
    await ctx.prisma.documentClaim.update({ where: { id: claim.id }, data: { valueEncrypted: new Uint8Array(damaged) } });
    const before = await plainState(a.documentId);
    const run = await encryptLegacyMetadata({ config: ctx.config, prisma: ctx.prisma });
    expect(run.documents.verifyFailed).toEqual([a.documentId]);
    expect(await plainState(a.documentId)).toEqual(before);
    expect(before.claims[0]!.key).not.toMatch(/^f\d+$/);
    await expectConverted(b.documentId);
  });

  it('a document key that cannot be unwrapped: nothing of that document is touched, the run goes on', async () => {
    const owner = await registerUser(ctx);
    const { a, b } = await twoLegacy(owner);
    const key = await ctx.prisma.documentKey.findUniqueOrThrow({ where: { documentId: a.documentId } });
    const bad = Buffer.from(key.wrappedDek);
    bad[0]! ^= 0xff;
    await ctx.prisma.documentKey.update({ where: { documentId: a.documentId }, data: { wrappedDek: new Uint8Array(bad) } });
    const before = await plainState(a.documentId);
    const run = await encryptLegacyMetadata({ config: ctx.config, prisma: ctx.prisma });
    expect(run.documents.verifyFailed).toEqual([a.documentId]);
    expect(metadataMigrationSucceeded(run)).toBe(false);
    expect(await plainState(a.documentId)).toEqual(before);
    await expectConverted(b.documentId);
    expect(run.remaining.titles).toBe(1);
  });

  it('a dry run reports the same failure and writes nothing', async () => {
    const owner = await registerUser(ctx);
    const { a } = await twoLegacy(owner);
    const dek = await loadDataKey(ctx.app.deps, a.documentId);
    await ctx.prisma.document.update({ where: { id: a.documentId }, data: { titleEncrypted: seal(dek, 'Wrong', titleAad(a.documentId)) } });
    dek.fill(0);
    const plainBefore = await countPlainMetadata(ctx.prisma);
    const dry = await ctx.prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe('SET TRANSACTION READ ONLY');
      return encryptLegacyMetadata({ config: ctx.config, prisma: tx }, { dryRun: true });
    });
    expect(dry.documents.verifyFailed).toEqual([a.documentId]);
    expect(dry.documents.sealed).toBe(1);
    expect(await countPlainMetadata(ctx.prisma)).toEqual(plainBefore);
  });
});

describe('key rotation and a fresh server (E2 + E3 together)', () => {
  it('after rotate + rewrap, a newly started server reads every title, label, recipient, file and link', async () => {
    const owner = await registerUser(ctx);
    const { documentId, link, file } = await seed(owner);
    const before = await ctx.prisma.documentKey.findUniqueOrThrow({ where: { documentId } });

    const lines: string[] = [];
    const code = await runKeysCli(['rotate', '--wait=0'], { env: cliEnv(), prisma: testPrisma(), out: (l) => lines.push(l), sleep: async () => {} });
    expect(code, lines.join('\n')).toBe(0);
    const after = await ctx.prisma.documentKey.findUniqueOrThrow({ where: { documentId } });
    expect(after.kekVersion).toBeGreaterThan(before.kekVersion); // the data key was re-wrapped
    expect(Buffer.from(after.wrappedDek).equals(Buffer.from(before.wrappedDek))).toBe(false);

    // A server that starts now knows only the new keys as current.
    const fresh = await createTestContext({ STORAGE_DRIVER: 'database' });
    try {
      const session = { ...owner };
      const detail = (await as(fresh, session, { method: 'GET', url: `/api/documents/${documentId}` })).json().document;
      expect(detail.title).toBe(TITLE);
      expect(detail.claims.map((c: { label: string; value: string }) => [c.label, c.value])).toEqual([
        ['Employer', 'Aramco'],
        ['National ID', '1234567890'],
      ]);
      expect(detail.links[0].recipientLabel).toBe(RECIPIENT);
      const fileRes = await as(fresh, session, { method: 'GET', url: `/api/documents/${documentId}/file` });
      expect(fileRes.rawPayload.equals(file)).toBe(true);
      const share = (await fresh.app.inject({ method: 'GET', url: `/api/share/${link.token}`, remoteAddress: IPS.SA })).json();
      expect(share.document.title).toBe(TITLE);
      const url = (await as(fresh, session, { method: 'GET', url: `/api/links/${link.id}/url` })).json().url;
      expect(url).toBe(link.url);
    } finally {
      await fresh.app.close();
    }
  });
});


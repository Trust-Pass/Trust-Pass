import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { claimAad, claimLabelAad, open, seal, titleAad } from '../../src/lib/crypto';
import { loadDataKey } from '../../src/services/documents';
import { parseMaintenanceTasks, runStartupMaintenance } from '../../src/services/maintenance';
import { countPlainMetadata } from '../../src/services/metadata-migration';
import { as, createTestContext, makeAdmin, registerUser, resetDatabase, samplePdf, testConfig, uploadDocument, type TestContext } from '../helpers';

/**
 * Start-up maintenance (hosts without a shell, e.g. Render free) and integrity alerts.
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

const quiet = { info: () => undefined };

describe('STARTUP_MAINTENANCE', () => {
  it('parses the allowed tasks in a fixed order and rejects anything else', () => {
    expect(parseMaintenanceTasks('')).toEqual([]);
    expect(parseMaintenanceTasks(' rewrap , encrypt-metadata ')).toEqual(['encrypt-metadata', 'rewrap']);
    expect(() => parseMaintenanceTasks('encrypt-metadata,drop-tables')).toThrow(/unknown task/);
    expect(() => testConfig({ STARTUP_MAINTENANCE: 'rewrap;rm -rf' })).toThrow();
    expect(testConfig({ STARTUP_MAINTENANCE: 'encrypt-metadata,rewrap' }).env.STARTUP_MAINTENANCE).toBe('encrypt-metadata,rewrap');
  });

  it('encrypts legacy metadata and re-wraps keys, records the result, and is idempotent', async () => {
    const owner = await registerUser(ctx);
    const id = (await uploadDocument(ctx, owner, { title: 'Legacy title', claims: [{ label: 'Employer', value: 'Aramco' }] })).json().document.id as string;
    // Turn it back into the pre-E3 format.
    const dek = await loadDataKey(ctx.app.deps, id);
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id }, include: { claims: true } });
    const claim = doc.claims[0]!;
    const value = open(dek, claim.valueEncrypted, claimAad(id, claim.claimKey, 'value'));
    await ctx.prisma.document.update({ where: { id }, data: { title: open(dek, doc.titleEncrypted!, titleAad(id)).toString(), titleEncrypted: null } });
    await ctx.prisma.documentClaim.update({
      where: { id: claim.id },
      data: { claimKey: 'employer', label: open(dek, claim.labelEncrypted!, claimLabelAad(id, claim.claimKey)).toString(), labelEncrypted: null, valueEncrypted: seal(dek, value, claimAad(id, 'employer', 'value')) },
    });
    dek.fill(0);
    expect((await countPlainMetadata(ctx.prisma)).titles).toBe(1);

    const logged: Array<Record<string, unknown>> = [];
    const results = await runStartupMaintenance(ctx.app.deps, ['encrypt-metadata', 'rewrap'], { info: (o) => logged.push(o) });
    expect(results.map((r) => [r.task, r.ok])).toEqual([
      ['encrypt-metadata', true],
      ['rewrap', true],
    ]);
    expect(results[0]!.summary).toMatchObject({ documentsSealed: 1, fieldsSealed: 1, fieldsRenamed: 1, plainMetadataRemaining: 0 });
    // Logs carry counts only.
    expect(JSON.stringify(logged)).not.toMatch(/Legacy title|Employer|Aramco/);
    const stored = await ctx.prisma.systemSetting.findUniqueOrThrow({ where: { key: 'maintenance:last' } });
    expect(JSON.stringify(stored.value)).toContain('"task":"encrypt-metadata"');

    // Everything still reads correctly.
    const detail = (await as(ctx, owner, { method: 'GET', url: `/api/documents/${id}` })).json().document;
    expect(detail.title).toBe('Legacy title');
    expect(detail.claims[0]).toMatchObject({ label: 'Employer', value: 'Aramco' });

    // A restart with the variable still set finds nothing to do.
    const again = await runStartupMaintenance(ctx.app.deps, ['encrypt-metadata', 'rewrap'], quiet);
    expect(again[0]!.summary).toMatchObject({ documentsSealed: 0, fieldsSealed: 0, plainMetadataRemaining: 0 });
    expect(again[1]!.summary).toMatchObject({ dataKeysRewrapped: 0, dataKeysFailed: 0 });
  });

  it('Admin > Health reports metadata encryption and the last maintenance run', async () => {
    const admin = await registerUser(ctx);
    await makeAdmin(ctx, admin);
    await runStartupMaintenance(ctx.app.deps, ['encrypt-metadata'], quiet);
    const checks = (await as(ctx, admin, { method: 'GET', url: '/api/admin/health' })).json().checks as Array<{ name: string; ok: boolean }>;
    expect(checks.find((c) => c.name === 'Metadata encryption')).toMatchObject({ ok: true });
    expect(checks.find((c) => c.name === 'Last start-up maintenance')).toMatchObject({ ok: true });
    expect(checks.find((c) => c.name === 'File integrity')).toMatchObject({ ok: true });
  });
});

describe('integrity alerts', () => {
  it('a tampered file alerts the owner and the admins once, without revealing the title to admins', async () => {
    const owner = await registerUser(ctx);
    const admin = await registerUser(ctx);
    await makeAdmin(ctx, admin);
    const file = await samplePdf();
    const id = (await uploadDocument(ctx, owner, { file, title: 'Secret contract' })).json().document.id as string;
    const doc = await ctx.prisma.document.findUniqueOrThrow({ where: { id } });
    const bytes = Buffer.from((await ctx.prisma.storedObject.findUniqueOrThrow({ where: { key: doc.storageKey } })).data);
    bytes.writeUInt8(bytes.readUInt8(10) ^ 1, 10);
    await ctx.prisma.storedObject.update({ where: { key: doc.storageKey }, data: { data: new Uint8Array(bytes) } });

    for (let i = 0; i < 2; i++) {
      const res = await as(ctx, owner, { method: 'GET', url: `/api/documents/${id}/file` });
      expect(res.statusCode).toBe(500);
      expect(res.json().error.code).toBe('integrity_error');
    }

    // The integrity alert is still raised and stored for the owner and the admin (not repeated
    // within the hour), and logged; it is no longer shown in the notifications bell, which is
    // reserved for repeated-access and expired-link alerts.
    const ownerAlerts = await ctx.prisma.notification.findMany({ where: { userId: owner.userId, type: 'integrity_alert' } });
    expect(ownerAlerts).toHaveLength(1);
    const adminAlerts = await ctx.prisma.notification.findMany({ where: { userId: admin.userId, type: 'integrity_alert' } });
    expect(adminAlerts).toHaveLength(1);
    expect(adminAlerts[0]!.body).toContain(id.slice(0, 8));
    expect(JSON.stringify(adminAlerts)).not.toContain('Secret contract');
    expect(await ctx.prisma.securityEvent.count({ where: { documentId: id, eventType: 'integrity_check_failed' } })).toBeGreaterThan(0);
    const adminNotes = (await as(ctx, admin, { method: 'GET', url: '/api/notifications' })).json().notifications;
    expect(adminNotes.filter((n: { type: string }) => n.type === 'integrity_alert')).toHaveLength(0);
    // Stored rows hold no title either.
    expect(JSON.stringify(await ctx.prisma.notification.findMany())).not.toContain('Secret contract');

    const checks = (await as(ctx, admin, { method: 'GET', url: '/api/admin/health' })).json().checks as Array<{ name: string; ok: boolean; detail: string }>;
    expect(checks.find((c) => c.name === 'File integrity')).toMatchObject({ ok: false });
  });
});

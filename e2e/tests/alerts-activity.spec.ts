import { execFileSync } from 'node:child_process';
import { expect, test, type Locator, type Page } from '@playwright/test';
import { PDFDocument } from 'pdf-lib';
import { login, newPhone, register, shareFields, uniqueEmail } from './helpers';

// Access Analytics shows exactly the same two security alerts as the Notifications bell; every
// other alert stays stored but hidden. The Activity Log can hide sign-in history from view
// without changing a single stored record. Runs on phone (Chromium), desktop and iPhone Safari (WebKit).

const DB = process.env.E2E_DATABASE_URL ?? 'postgresql://trustpass:trustpass_dev@localhost:5432/trustpass_e2e';
const sql = (query: string) => execFileSync('psql', [DB, '-qtAX', '-v', 'ON_ERROR_STOP=1', '-c', query], { encoding: 'utf8', stdio: 'pipe' }).trim();

/** A fingerprint of every activity record of this user: any edit or delete changes it. */
const fingerprint = (userId: string) =>
  sql(`SELECT count(*) || ':' || coalesce(md5(string_agg(e::text, '|' ORDER BY e.id)), '') FROM security_events e WHERE e.user_id = '${userId}'`);
const accessFingerprint = (userId: string) =>
  sql(`SELECT count(*) || ':' || coalesce(md5(string_agg(a::text, '|' ORDER BY a.id)), '') FROM access_logs a JOIN sharing_links l ON l.id = a.link_id WHERE l.owner_id = '${userId}'`);

async function upload(page: Page, title: string) {
  const pdf = await PDFDocument.create();
  pdf.addPage([300, 300]);
  await page.goto('/app/documents/upload');
  await page.getByTestId('file-input').setInputFiles({ name: `${title}.pdf`, mimeType: 'application/pdf', buffer: Buffer.from(await pdf.save()) });
  await page.getByLabel('Title').fill(title);
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  return page.url().split('/').pop()!;
}

type Alert = { kind: string | null; title: string; body: string; document: string; at: string | null };
async function readAlerts(list: Locator): Promise<Alert[]> {
  const items = list.getByRole('listitem');
  const out: Alert[] = [];
  for (let i = 0; i < (await items.count()); i++) {
    const item = items.nth(i);
    out.push({
      kind: await item.getAttribute('data-kind'),
      title: (await item.locator('.font-semibold').first().textContent())!.replace('(unread)', '').trim(),
      body: (await item.locator('.text-slate-600').first().textContent())!.trim(),
      document: (await item.locator('.truncate').first().textContent())!.trim(),
      at: await item.locator('time').getAttribute('datetime'),
    });
  }
  return out.sort((a, b) => a.kind!.localeCompare(b.kind!));
}

test('analytics alerts match the bell exactly; activity log hides sign-in history by default', async ({ page, browser }, info) => {
  test.setTimeout(150_000);
  const shot = (name: string) => page.screenshot({ path: `test-results/tour/${info.project.name}-${name}.jpg`, fullPage: true, type: 'jpeg', quality: 60 });
  const noSideScroll = async () => expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);

  const email = uniqueEmail('logowner');
  await register(page, { name: 'Log Owner', email });
  const userId = sql(`SELECT id FROM users WHERE email = '${email}'`);
  expect(userId).toMatch(/^[0-9a-f-]{36}$/);
  // A second sign-in (another device) so the log has sign-in history.
  await login(await newPhone(browser), email);

  // Document 1: viewed, revoked, then tried again and again → "Repeated access attempts"
  // (this also stores a revoked-link alert, which must stay hidden).
  const leaseId = await upload(page, 'Lease agreement');
  const leaseUrl = await shareFields(page, leaseId, { includeFile: true, recipient: 'Landlord' });
  const recipient = await newPhone(browser);
  await recipient.goto(leaseUrl);
  await expect(recipient.locator('canvas.pdf-page').first()).toBeVisible({ timeout: 30_000 });
  await page.goto('/app/links');
  await page.getByRole('button', { name: 'Revoke' }).first().click();
  await page.getByRole('button', { name: 'Revoke now' }).click();
  await expect(page.getByRole('tab', { name: /Revoked/ })).toContainText('1');
  for (let i = 0; i < 4; i++) expect((await recipient.request.get(`/api/share/${leaseUrl.split('/s/')[1]}`)).status()).toBe(410);

  // Document 2: its link runs out (moved into the past in this throwaway test database), then is opened
  // → "Expired link access blocked".
  const payslipId = await upload(page, 'Payslip');
  const payslipUrl = await shareFields(page, payslipId, { includeFile: true, recipient: 'Bank' });
  expect(sql(`UPDATE sharing_links SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 minute' WHERE document_id = '${payslipId}' RETURNING 1`)).toBe('1');
  expect((await recipient.request.get(`/api/share/${payslipUrl.split('/s/')[1]}`)).status()).toBe(410);

  // Stored rows: both shown alerts, plus a revoked-link alert that must stay hidden.
  const stored = sql(`SELECT string_agg(DISTINCT type, ',') FROM notifications WHERE user_id = '${userId}'`);
  for (const type of ['alert_denied_burst', 'alert_expired_link', 'alert_after_end']) expect(stored).toContain(type);
  const storedCount = Number(sql(`SELECT count(*) FROM notifications WHERE user_id = '${userId}'`));
  expect(storedCount).toBeGreaterThan(2);
  const events = fingerprint(userId);
  const accesses = accessFingerprint(userId);
  expect(events).toMatch(/^[1-9]\d*:/);

  // Bell: exactly the two security alerts, both unread.
  await page.goto('/app');
  await page.getByRole('button', { name: 'Notifications, 2 unread' }).click();
  const bellList = page.getByTestId('notification-list');
  await expect(bellList.getByRole('listitem')).toHaveCount(2);
  await expect(bellList.locator('li[data-read="false"]')).toHaveCount(2);
  await expect(bellList.getByText('(unread)')).toHaveCount(2);
  const bell = await readAlerts(bellList);
  expect(bell.map(({ at, ...rest }) => rest)).toEqual([
    { kind: 'expired_link', title: 'Expired link access blocked', body: 'Someone tried to open your document after the link expired. Access was blocked.', document: 'Document: Payslip' },
    { kind: 'repeated_attempts', title: 'Repeated access attempts', body: 'Someone tried to access your document multiple times.', document: 'Document: Lease agreement' },
  ]);
  for (const a of bell) expect(Math.abs(Date.parse(a.at!) - Date.now())).toBeLessThan(5 * 60_000);
  await expect(bellList).not.toContainText(/first view|revoked|download|certificate|signed in/i);
  await shot('37b-notifications-both');

  // Analytics: the same two alerts — same kinds, titles, descriptions, documents and timestamps, nothing else.
  await page.keyboard.press('Escape');
  await page.goto('/app/analytics');
  const analyticsList = page.getByTestId('security-alerts');
  await expect(analyticsList.getByRole('listitem')).toHaveCount(2);
  expect(await readAlerts(analyticsList)).toEqual(bell);
  await expect(analyticsList).not.toContainText(/first view|revoked link|new country/i);
  await analyticsList.scrollIntoViewIfNeeded();
  await noSideScroll();
  await shot('38-analytics-alerts');

  // Unread state lives in the bell: marking read clears the badge and dots; Analytics is unchanged.
  await page.getByRole('button', { name: 'Notifications, 2 unread' }).click();
  await page.getByRole('button', { name: 'Mark all as read' }).click();
  await expect(bellList.locator('li[data-read="true"]')).toHaveCount(2);
  await expect(bellList.getByText('(unread)')).toHaveCount(0);
  await page.keyboard.press('Escape');
  await page.reload();
  await expect(page.getByRole('button', { name: 'Notifications', exact: true })).toBeVisible();
  await expect(analyticsList.getByRole('listitem')).toHaveCount(2);
  expect(await readAlerts(analyticsList)).toEqual(bell);

  // Activity log: sign-in history is hidden every time the page opens; "Show sign-in history" shows it,
  // "Hide sign-in history" hides it again, and a refresh or a new visit starts hidden again.
  const log = page.locator('ol').first();
  const totalShown = async () => Number((await page.getByText(/^\d+ events$/).innerText()).split(' ')[0]);
  const expectHidden = async () => {
    await expect(page.getByRole('button', { name: 'Show sign-in history' })).toHaveAttribute('aria-pressed', 'false');
    await expect(log.getByText('Sharing link created').first()).toBeVisible();
    await expect(log.getByText(/^(Signed in|Signed out|Session signed out remotely)$/)).toHaveCount(0);
    await expect(page.getByLabel('Event type').locator('option', { hasText: 'Signed in' })).toHaveCount(0);
  };
  await page.goto('/app/activity');
  await expectHidden();
  const hiddenTotal = await totalShown();
  await expect(page.getByTestId('sign-ins-hidden')).toHaveCount(0);
  await noSideScroll();
  await shot('39-activity-default');

  await page.getByRole('button', { name: 'Show sign-in history' }).click();
  await expect(page.getByRole('button', { name: 'Hide sign-in history' })).toHaveAttribute('aria-pressed', 'true');
  await expect(log.getByText('Signed in', { exact: true }).first()).toBeVisible();
  await expect.poll(totalShown).toBe(hiddenTotal + 1); // the one sign-in from the second device
  expect(hiddenTotal + 1).toBeLessThanOrEqual(30); // one page
  await expect(page.getByLabel('Event type').locator('option', { hasText: 'Signed in' })).toHaveCount(1);
  await noSideScroll();
  await shot('39b-activity-sign-ins-shown');

  await page.getByRole('button', { name: 'Hide sign-in history' }).click();
  await expectHidden();
  await expect.poll(totalShown).toBe(hiddenTotal);

  // Shown, then refreshed: hidden again. Same when leaving and reopening the page.
  await page.getByRole('button', { name: 'Show sign-in history' }).click();
  await expect(log.getByText('Signed in', { exact: true }).first()).toBeVisible();
  await page.reload();
  await expectHidden();
  await page.getByRole('button', { name: 'Show sign-in history' }).click();
  await expect(log.getByText('Signed in', { exact: true }).first()).toBeVisible();
  await page.goto('/app/analytics');
  await page.goto('/app/activity');
  await expectHidden();
  await expect.poll(totalShown).toBe(hiddenTotal);

  // Nothing stored was deleted or modified: activity and access records are byte-for-byte the same,
  // and every alert row (shown or hidden) is still there. The log is still append-only.
  expect(fingerprint(userId)).toBe(events);
  expect(accessFingerprint(userId)).toBe(accesses);
  expect(Number(sql(`SELECT count(*) FROM notifications WHERE user_id = '${userId}'`))).toBe(storedCount);
  expect(() => sql(`DELETE FROM security_events WHERE user_id = '${userId}'`)).toThrow(/append-only/);
  expect(() => sql(`UPDATE security_events SET severity = severity WHERE user_id = '${userId}'`)).toThrow(/append-only/);
  expect(fingerprint(userId)).toBe(events);
});

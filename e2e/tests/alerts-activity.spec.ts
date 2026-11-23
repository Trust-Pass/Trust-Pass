import { expect, test } from '@playwright/test';
import { PDFDocument } from 'pdf-lib';
import { login, newPhone, register, shareFields, uniqueEmail } from './helpers';

// Access Analytics shows the same two security alerts as the bell; the Activity Log can hide
// sign-in history from view without touching the append-only log.

test('analytics security alerts match the bell; activity log hides and shows sign-in history', async ({ page, browser }, info) => {
  const shot = (name: string) => page.screenshot({ path: `test-results/tour/${info.project.name}-${name}.jpg`, fullPage: true, type: 'jpeg', quality: 60 });
  const email = uniqueEmail('logowner');
  await register(page, { name: 'Log Owner', email });
  // A second sign-in (another device) so the log has sign-in history.
  await login(await newPhone(browser), email);
  const pdf = await PDFDocument.create();
  pdf.addPage([300, 300]);
  await page.goto('/app/documents/upload');
  await page.getByTestId('file-input').setInputFiles({ name: 'lease.pdf', mimeType: 'application/pdf', buffer: Buffer.from(await pdf.save()) });
  await page.getByLabel('Title').fill('Lease agreement');
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  const url = await shareFields(page, page.url().split('/').pop()!, { includeFile: true, recipient: 'Landlord' });
  const token = url.split('/s/')[1]!;

  // A view (first view: not an alert), then the link is revoked and tried again and again.
  const recipient = await newPhone(browser);
  await recipient.goto(url);
  await expect(recipient.locator('canvas.pdf-page').first()).toBeVisible({ timeout: 30_000 });
  await page.goto('/app/links');
  await page.getByRole('button', { name: 'Revoke' }).first().click();
  await page.getByRole('button', { name: 'Revoke now' }).click();
  await expect(page.getByRole('tab', { name: /Revoked/ })).toContainText('1');
  for (let i = 0; i < 4; i++) expect((await recipient.request.get(`/api/share/${token}`)).status()).toBe(410);

  // Analytics: exactly the alert the bell shows.
  await page.goto('/app/analytics');
  const alerts = page.getByTestId('security-alerts').getByRole('listitem');
  await expect(alerts).toHaveCount(1);
  await expect(alerts.first()).toHaveAttribute('data-kind', 'repeated_attempts');
  await expect(alerts.first()).toContainText('Repeated access attempts');
  await expect(alerts.first()).toContainText('Someone tried to access your document multiple times.');
  await expect(alerts.first()).toContainText('Document: Lease agreement');
  await expect(page.getByTestId('security-alerts').getByText(/First view|revoked link/i)).toHaveCount(0);
  await page.getByRole('button', { name: 'Notifications, 1 unread' }).click();
  await expect(page.getByTestId('notification-list').getByRole('listitem').first()).toContainText('Repeated access attempts');
  await page.keyboard.press('Escape');
  await page.getByTestId('security-alerts').scrollIntoViewIfNeeded();
  await shot('38-analytics-alerts');

  // Activity log: sign-ins are there, then hidden, remembered, and shown again.
  await page.goto('/app/activity');
  const log = page.locator('ol').first();
  await expect(log.getByText('Signed in', { exact: true }).first()).toBeVisible();
  await page.getByRole('button', { name: 'Hide sign-in history' }).click();
  await expect(page.getByRole('button', { name: 'Show hidden sign-in history' })).toBeVisible();
  await expect(log.getByText('Signed in', { exact: true })).toHaveCount(0);
  await expect(page.getByTestId('sign-ins-hidden')).toContainText('hidden from this view. They stay in your security log.');
  await expect(log.getByText('Sharing link created').first()).toBeVisible();
  await expect(page.getByLabel('Event type').locator('option', { hasText: 'Signed in' })).toHaveCount(0);
  await shot('39-activity-hidden');
  await page.reload();
  await expect(page.getByRole('button', { name: 'Show hidden sign-in history' })).toBeVisible();
  await expect(log.getByText('Signed in', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Show hidden sign-in history' }).click();
  await expect(log.getByText('Signed in', { exact: true }).first()).toBeVisible();
  await expect(page.getByTestId('sign-ins-hidden')).toHaveCount(0);
  const width = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
  expect(width).toBe(true);
});

import { expect, test } from '@playwright/test';
import { PDFDocument } from 'pdf-lib';
import { newPhone, register, shareFields, uniqueEmail } from './helpers';

// Notifications are security alerts only: repeated access attempts and expired-link attempts.
// (Expired links need the clock to move, which the API tests cover; here: repeated attempts.)

test('notifications: normal activity is quiet; repeated attempts raise one clear security alert', async ({ page, browser }, info) => {
  await register(page, { name: 'Alert Owner', email: uniqueEmail('alerts') });
  const pdf = await PDFDocument.create();
  pdf.addPage([300, 300]);
  await page.goto('/app/documents/upload');
  await page.getByTestId('file-input').setInputFiles({ name: 'payslip.pdf', mimeType: 'application/pdf', buffer: Buffer.from(await pdf.save()) });
  await page.getByLabel('Title').fill('November payslip');
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  const docId = page.url().split('/').pop()!;
  const url = await shareFields(page, docId, { includeFile: true, allowDownload: true, recipient: 'Landlord' });
  const token = url.split('/s/')[1]!;

  // A first view and a download: normal activity, no notification.
  const recipient = await newPhone(browser);
  await recipient.goto(url);
  await expect(recipient.locator('canvas.pdf-page').first()).toBeVisible({ timeout: 30_000 });
  expect((await recipient.request.get(`/api/share/${token}/download`)).status()).toBe(200);
  await page.goto('/app');
  await expect(page.getByRole('button', { name: 'Notifications', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Notifications', exact: true }).click();
  await expect(page.getByText('No security alerts')).toBeVisible();
  await page.keyboard.press('Escape');

  // The owner revokes the link; someone keeps trying it.
  await page.goto('/app/links');
  await page.getByRole('button', { name: 'Revoke' }).first().click();
  await page.getByRole('button', { name: 'Revoke now' }).click();
  await expect(page.getByRole('tab', { name: /Revoked/ })).toContainText('1');
  for (let i = 0; i < 4; i++) expect((await recipient.request.get(`/api/share/${token}`)).status()).toBe(410);

  await page.goto('/app');
  const bell = page.getByRole('button', { name: 'Notifications, 1 unread' });
  await expect(bell).toBeVisible();
  await bell.click();
  const items = page.getByTestId('notification-list').getByRole('listitem');
  await expect(items).toHaveCount(1);
  const item = items.first();
  await expect(item).toHaveAttribute('data-kind', 'repeated_attempts');
  await expect(item).toHaveAttribute('data-read', 'false');
  await expect(item).toContainText('Repeated access attempts');
  await expect(item).toContainText('Someone tried to access your document multiple times.');
  await expect(item).toContainText('Security alert');
  await expect(item).toContainText('Document: November payslip');
  await expect(item.locator('time')).toHaveAttribute('datetime', /\d{4}-\d{2}-\d{2}T/);
  await expect(item).toContainText('(unread)');
  await page.screenshot({ path: `test-results/tour/${info.project.name}-37-notifications.jpg`, type: 'jpeg', quality: 60 });
  // Nothing about the view, the download or the revoked attempts themselves.
  await expect(page.getByTestId('notification-list').getByText(/downloaded|First view|revoked link/i)).toHaveCount(0);

  // Opening it marks it read and goes to Shared links.
  await item.getByRole('button').click();
  await expect(page).toHaveURL(/\/app\/links$/);
  await expect(page.getByRole('button', { name: 'Notifications', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Notifications', exact: true }).click();
  await expect(page.getByTestId('notification-list').getByRole('listitem').first()).toHaveAttribute('data-read', 'true');
  const width = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
  expect(width).toBe(true);
});

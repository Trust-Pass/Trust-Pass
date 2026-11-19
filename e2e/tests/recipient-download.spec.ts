import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import { PDFDocument } from 'pdf-lib';
import { issueCredential, newPhone, register, shareFields, uniqueEmail } from './helpers';

// The e2e server simulates every visitor as connecting from Saudi Arabia.

test('a recipient downloads a watermarked copy only while the owner allows it', async ({ page, browser }) => {
  await register(page, { name: 'Download Owner', email: uniqueEmail('dl') });
  const docId = await issueCredential(page, 'Download Owner');
  const url = await shareFields(page, docId, { fields: ['Program'], includeFile: true, allowDownload: true, recipient: 'Example Company HR' });
  await expect(page.getByText('Recipient can download a watermarked PDF copy')).toBeVisible();

  const recipient = await newPhone(browser);
  await recipient.goto(url);
  await expect(recipient.getByTestId('download-panel')).toBeVisible();
  const [download] = await Promise.all([recipient.waitForEvent('download'), recipient.getByTestId('download-copy').click()]);
  expect(download.suggestedFilename()).toMatch(/^trustpass-copy-[0-9A-F]{10}\.pdf$/);
  const copy = await readFile((await download.path())!);
  const pdf = await PDFDocument.load(copy);
  expect(pdf.getPageCount()).toBeGreaterThan(0);
  expect(pdf.getTitle()).toContain('TrustPass copy');
  await expect(recipient.getByTestId('download-done')).toBeVisible();

  // The owner turns downloads off; the very next request is refused.
  await page.goto('/app/links');
  await page.getByRole('button', { name: 'Activity' }).first().click();
  await expect(page.getByTestId('link-download')).toContainText('Recipient can download a watermarked PDF');
  await page.getByRole('button', { name: 'Turn off downloads' }).click();
  await expect(page.getByTestId('link-download')).toContainText('View only: downloads are off');

  await recipient.getByTestId('download-copy').click();
  await expect(recipient.getByTestId('download-error')).toContainText('Downloads are not allowed');
  await recipient.reload();
  await expect(recipient.getByTestId('download-panel')).toHaveCount(0);
  await expect(recipient.getByText('Downloads are disabled.')).toBeVisible();
});

test('view-only links show no download button', async ({ page, browser }) => {
  await register(page, { name: 'View Owner', email: uniqueEmail('view') });
  const docId = await issueCredential(page, 'View Owner');
  const url = await shareFields(page, docId, { fields: ['Program'], includeFile: true });
  const recipient = await newPhone(browser);
  await recipient.goto(url);
  await expect(recipient.getByText('Downloads are disabled.')).toBeVisible();
  await expect(recipient.getByTestId('download-panel')).toHaveCount(0);
  const token = url.split('/s/')[1]!;
  const res = await recipient.request.get(`/api/share/${token}/download`);
  expect(res.status()).toBe(403);
});

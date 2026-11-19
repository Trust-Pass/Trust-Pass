import { expect, test } from '@playwright/test';
import { issueCredential, newPhone, register, shareFields, uniqueEmail } from './helpers';

/**
 * Captures the main screens on phone and desktop so the design can be reviewed from CI
 * (uploaded as the "ui-screenshots" artifact). It also fails on page errors or console errors.
 */
test('visual tour of the main screens', async ({ page, browser }, info) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const shot = (name: string) => page.screenshot({ path: `test-results/tour/${info.project.name}-${name}.png`, fullPage: true });

  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await shot('01-landing');
  await page.goto('/login');
  await shot('02-login');

  await register(page, { name: 'Reham Alkhamees', email: uniqueEmail('tour') });
  await shot('03-dashboard-empty');
  const docId = await issueCredential(page);
  await shot('04-document');
  const url = await shareFields(page, docId, { fields: ['Enrollment status'], recipient: 'Example Company' });
  await shot('05-share-ready');
  await page.goto('/app');
  await shot('06-dashboard');
  await page.goto('/app/documents');
  await shot('07-documents');
  await page.goto('/app/links');
  await shot('08-links');
  await page.goto('/app/scan');
  await page.getByRole('tab', { name: 'Paste a link' }).click();
  await page.getByLabel('Link or QR code text').fill('https://www.paypal.com@paypa1-secure.xyz/login');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('qr-verdict')).toBeVisible();
  await shot('09-qr-danger');

  const viewer = await newPhone(browser);
  await viewer.goto(url);
  await expect(viewer.getByTestId('verification-result')).toBeVisible();
  await viewer.screenshot({ path: `test-results/tour/${info.project.name}-10-recipient.png`, fullPage: true });

  if (info.project.name === 'mobile') {
    await page.getByRole('button', { name: 'Open menu' }).click();
    await expect(page.getByRole('dialog', { name: 'Menu' })).toBeVisible();
    await shot('11-menu');
  }
  expect(errors).toEqual([]);
});

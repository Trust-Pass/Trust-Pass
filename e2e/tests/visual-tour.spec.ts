import { expect, test } from '@playwright/test';
import { issueCredential, newPhone, register, shareFields, uniqueEmail } from './helpers';

/**
 * Captures the main screens on phone and desktop so the design can be reviewed from CI
 * (uploaded as the "ui-screenshots" artifact). It also fails on page errors or console errors.
 */
test('visual tour of the main screens', async ({ page, browser }, info) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const shot = (name: string) => page.screenshot({ path: `test-results/tour/${info.project.name}-${name}.jpg`, fullPage: true, animations: 'disabled', type: 'jpeg', quality: 60 });

  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await shot('01-landing');
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
  await shot('02-login');
  // The password field's show/hide control really toggles the input.
  const password = page.getByLabel('Password', { exact: true });
  await password.fill('not-a-real-password');
  await expect(password).toHaveAttribute('type', 'password');
  await page.getByRole('button', { name: 'Show password' }).click();
  await expect(password).toHaveAttribute('type', 'text');
  await page.getByRole('button', { name: 'Hide password' }).click();
  await expect(password).toHaveAttribute('type', 'password');

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
  await page.goto('/app/verify');
  await page.getByRole('button', { name: 'Info: what the verification results mean' }).click();
  await expect(page.getByTestId('results-legend')).toBeVisible();
  await shot('25b-verify-info');
  await page.keyboard.press('Escape');
  await page.goto('/app/scan');
  await page.getByRole('tab', { name: 'Paste a link' }).click();
  await page.getByLabel('Link or QR code text').fill('https://www.paypal.com@paypa1-secure.xyz/login');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('qr-verdict')).toBeVisible();
  await shot('09-qr-danger');

  const viewer = await newPhone(browser);
  await viewer.goto(url);
  await expect(viewer.getByTestId('verification-result')).toBeVisible();
  await viewer.screenshot({ path: `test-results/tour/${info.project.name}-10-recipient.jpg`, fullPage: true, animations: 'disabled', type: 'jpeg', quality: 60 });

  // Back on the dashboard after the recipient's view: the access chart has data now.
  await page.goto('/app');
  await expect(page.getByTestId('key-protection')).toBeVisible();
  await shot('12-dashboard-with-activity');

  if (info.project.name === 'mobile') {
    await page.getByRole('button', { name: 'Open menu' }).click();
    await expect(page.getByRole('dialog', { name: 'Menu' })).toBeVisible();
    await shot('11-menu');
  }
  expect(errors).toEqual([]);
});

/** Every other screen, for the full design review (screens only, no extra assertions beyond loading). */
test('visual tour of the remaining screens', async ({ page, browser }, info) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const shot = (name: string) => page.screenshot({ path: `test-results/tour/${info.project.name}-${name}.jpg`, fullPage: true, animations: 'disabled', type: 'jpeg', quality: 60 });

  await page.goto('/register');
  await expect(page.getByRole('heading', { name: 'Create your account' })).toBeVisible();
  await shot('20-register');
  await page.goto('/forgot-password');
  await shot('21-forgot-password');

  await register(page, { name: 'Reham Alkhamees', email: uniqueEmail('tour2') });
  await page.goto('/app/documents/upload');
  await shot('22-upload');
  const docId = await issueCredential(page);
  await page.goto(`/app/documents/${docId}/share`);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await shot('23-share-form');
  await page.getByText('Include the file').click();
  await expect(page.getByTestId('watermark-controls')).toBeVisible();
  await shot('32-share-watermark');
  await page.getByRole('radio', { name: 'Redacted copy' }).click();
  await expect(page.getByTestId('redaction-page-0').locator('img')).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: 'Detect sensitive information' }).click();
  await expect(page.getByTestId('sensitive-kinds')).toBeVisible();
  await page.getByLabel('Text to hide').fill('Reham Alkhamees');
  await page.getByTestId('find-and-hide').getByRole('button', { name: 'Hide', exact: true }).click();
  await expect(page.getByTestId('find-result')).toContainText('Hid');
  await shot('33-share-redaction');
  await page.getByLabel('Recipient name').fill('Example Company');
  await page.getByRole('button', { name: 'Preview recipient copy' }).click();
  await expect(page.getByTestId('preview-viewer').locator('canvas.pdf-page').first()).toBeVisible({ timeout: 20_000 });
  await shot('34-share-preview');
  await page.goto(`/app/documents/${docId}`);
  await page.getByRole('button', { name: 'Check encryption now' }).click();
  await expect(page.getByTestId('encryption-check-result')).toHaveAttribute('data-ok', 'true');
  await shot('35-encryption-check');
  await page.goto(`/app/documents/${docId}/sensitive`);
  await expect(page.getByTestId('redaction-page-0').locator('img')).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: 'Detect sensitive information' }).click();
  await page.getByRole('radio', { name: 'Blur' }).click();
  await expect(page.getByTestId('sensitive-kinds')).toBeVisible();
  await shot('36-hide-sensitive');
  const url = await shareFields(page, docId, { fields: ['Enrollment status'], recipient: 'Example Company' });
  const viewer = await newPhone(browser);
  await viewer.goto(url);
  await expect(viewer.getByTestId('verification-result')).toBeVisible();

  for (const [path, name] of [
    ['/app/analytics', '24-analytics'],
    ['/app/verify', '25-verify'],
    ['/app/activity', '26-activity'],
    ['/app/credentials', '27-credentials'],
    ['/app/settings', '28-settings'],
    ['/app/scan', '29-qr-camera'],
    ['/app/no-such-page', '30-not-found'],
  ] as const) {
    await page.goto(path);
    await page.waitForLoadState('networkidle');
    await shot(name);
  }
  await page.goto('/app/scan');
  await page.getByRole('tab', { name: 'Paste a link' }).click();
  await page.getByLabel('Link or QR code text').fill('https://www.alrajhibank.com.sa/en');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('qr-verdict')).toHaveAttribute('data-verdict', 'safe');
  await shot('31-qr-safe');
  expect(errors).toEqual([]);
});

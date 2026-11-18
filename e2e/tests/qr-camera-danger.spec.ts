import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { register, uniqueEmail } from './helpers';
import { cameraStats, watchCameraAndPopups } from './qr-helpers';

// Live camera with a phishing QR code (fixtures/qr-phishing.y4m →
// https://www.paypal.com@paypa1-secure.xyz/login): dangerous, and it can never be opened.
const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

test.use({
  permissions: ['camera'],
  launchOptions: {
    args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', `--use-file-for-fake-video-capture=${fixture('qr-phishing.y4m')}`],
  },
});

test('a phishing QR code seen by the camera is Dangerous, explained, and cannot be opened', async ({ page, context }) => {
  await watchCameraAndPopups(page);
  await register(page, { name: 'Qr Phish', email: uniqueEmail('qrphish') });
  await page.goto('/app/scan');

  await expect(page.getByTestId('qr-destination')).toHaveText('https://www.paypal.com@paypa1-secure.xyz/login', { timeout: 20_000 });
  await expect(page.getByTestId('qr-verdict')).toHaveAttribute('data-verdict', 'danger');
  await expect(page.getByTestId('qr-verdict-label')).toHaveText('Dangerous');
  await expect(page.getByTestId('qr-safety')).toHaveAttribute('data-score', '0');
  await expect(page.getByTestId('qr-safety')).toContainText('0%');
  const findings = page.getByTestId('qr-findings');
  await expect(findings.locator('[data-finding="userinfo"]')).toContainText('Disguised address');
  await expect(findings.locator('[data-finding="brand_lookalike"]')).toContainText('Imitates PayPal');
  await expect(findings.locator('[data-finding="risky_tld"]')).toBeVisible();
  await expect(page.getByTestId('qr-domain')).toHaveText('paypa1-secure.xyz');

  // No way to open it, nothing opened, camera released.
  await expect(page.getByTestId('qr-result').getByRole('button', { name: /^Open/ })).toHaveCount(0);
  await expect(page.getByText('Opening is turned off for dangerous content')).toBeVisible();
  expect(await cameraStats(page)).toEqual({ opened: 1, live: 0, popups: [] });
  expect(context.pages()).toHaveLength(1);

  // The dangerous result was recorded in the activity log, without the address.
  await page.goto('/app/activity');
  await expect(page.getByText('Dangerous QR code or link detected').first()).toBeVisible();
  await expect(page.locator('body')).not.toContainText('paypa1-secure');
});

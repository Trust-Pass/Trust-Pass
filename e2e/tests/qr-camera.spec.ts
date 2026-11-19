import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { register, uniqueEmail } from './helpers';
import { cameraStats, watchCameraAndPopups } from './qr-helpers';

// Live camera, end to end. Chromium's fake camera plays a video of a QR code photo
// (fixtures/qr-http-shortlink.y4m → http://goo.by/wkEtco), so the real path runs:
// page opens → camera starts by itself → frames decoded on the device → API check → result.
// Browser launch options must be top-level in the file.
const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

test.use({
  permissions: ['camera'],
  launchOptions: {
    args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', `--use-file-for-fake-video-capture=${fixture('qr-http-shortlink.y4m')}`],
  },
});

test('opening the scanner starts the camera, reads the code and shows the full analysis without opening it', async ({ page, context }) => {
  await watchCameraAndPopups(page);
  await register(page, { name: 'Qr Camera', email: uniqueEmail('qrcam') });

  // 1-3. No click: the camera starts when the page opens and the code is read automatically.
  await page.goto('/app/scan');
  await expect(page.getByRole('heading', { name: 'QR Security Scanner' })).toBeVisible();

  // 4-5. Result on the same page: verdict, safety score, destination, explanations.
  await expect(page.getByTestId('qr-destination')).toHaveText('http://goo.by/wkEtco', { timeout: 20_000 });
  await expect(page.getByTestId('qr-verdict')).toHaveAttribute('data-verdict', 'caution');
  await expect(page.getByTestId('qr-verdict-label')).toHaveText('Suspicious');
  // Two medium warnings (http, short link): risk 50 → safety 50%.
  await expect(page.getByTestId('qr-safety')).toHaveAttribute('data-score', '50');
  await expect(page.getByTestId('qr-safety')).toContainText('50%');
  await expect(page.getByRole('meter', { name: 'Safety score' })).toHaveAttribute('aria-valuenow', '50');
  const findings = page.getByTestId('qr-findings');
  await expect(findings.locator('[data-finding="shortener"]')).toContainText('Short link hides the real destination');
  await expect(findings.locator('[data-finding="not_https"]')).toContainText('Not encrypted');
  await expect(page.getByTestId('qr-result')).toBeInViewport();

  // 6. Nothing was opened, and the camera was released once the code was read.
  let stats = await cameraStats(page);
  expect(stats).toEqual({ opened: 1, live: 0, popups: [] });
  expect(context.pages()).toHaveLength(1);
  expect(new URL(page.url()).pathname).toBe('/app/scan');

  // 7. Scan another: one tap, the camera restarts and scans again.
  await page.getByTestId('qr-result').getByRole('button', { name: 'Scan another QR code' }).click();
  await expect(page.getByTestId('qr-result')).toHaveCount(0);
  await expect(page.getByTestId('camera-scanner')).toHaveAttribute('data-state', 'scanning');
  stats = await cameraStats(page);
  expect(stats.opened).toBe(2);
  expect(stats.live).toBeGreaterThan(0);
  // The same code is ignored for a moment, then read again.
  await expect(page.getByTestId('qr-destination')).toHaveText('http://goo.by/wkEtco', { timeout: 20_000 });
  stats = await cameraStats(page);
  expect(stats).toEqual({ opened: 2, live: 0, popups: [] });
});

test('"Open anyway" on a suspicious code asks first, and opens only after confirming', async ({ page }) => {
  await watchCameraAndPopups(page);
  await register(page, { name: 'Qr Open', email: uniqueEmail('qropen') });
  await page.goto('/app/scan');
  await expect(page.getByTestId('qr-verdict')).toHaveAttribute('data-verdict', 'caution', { timeout: 20_000 });
  await page.getByTestId('qr-result').getByRole('button', { name: 'Open anyway' }).click();
  await expect(page.getByRole('dialog')).toContainText('warning signs');
  await page.getByRole('button', { name: 'Cancel' }).click();
  expect((await cameraStats(page)).popups).toEqual([]);
  await page.getByTestId('qr-result').getByRole('button', { name: 'Open anyway' }).click();
  await page.getByRole('button', { name: 'Open in a new tab' }).click();
  expect((await cameraStats(page)).popups).toEqual(['http://goo.by/wkEtco']);
});

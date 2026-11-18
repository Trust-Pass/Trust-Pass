import { fileURLToPath } from 'node:url';
import { expect, test, type Page } from '@playwright/test';
import { register, uniqueEmail } from './helpers';

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

async function openScanner(page: Page) {
  await page.goto('/app/scan');
  await expect(page.getByRole('heading', { name: 'QR Security Scanner' })).toBeVisible();
}

async function paste(page: Page, text: string) {
  await page.getByRole('tab', { name: 'Paste a link' }).click();
  await page.getByLabel('Link or QR code text').fill(text);
  await page.getByRole('button', { name: 'Check', exact: true }).click();
}

test('a pasted phishing link is dangerous and cannot be opened', async ({ page }) => {
  await register(page, { name: 'Qr Tester', email: uniqueEmail('qr') });
  await openScanner(page);
  await paste(page, 'https://www.paypal.com@paypa1-secure.xyz/login');
  await expect(page.getByTestId('qr-verdict')).toHaveAttribute('data-verdict', 'danger');
  await expect(page.getByTestId('qr-findings').locator('[data-finding="userinfo"]')).toBeVisible();
  await expect(page.getByTestId('qr-domain')).toHaveText('paypa1-secure.xyz');
  await expect(page.getByTestId('qr-result').getByRole('button', { name: /^Open/ })).toHaveCount(0);
  // Shown as text, never as a clickable link.
  await expect(page.getByTestId('qr-content').locator('a')).toHaveCount(0);
});

test('a script in a QR code is shown as text and never runs', async ({ page }) => {
  await register(page, { name: 'Qr Script', email: uniqueEmail('qrjs') });
  await openScanner(page);
  await paste(page, 'javascript:window.__qrxss=1');
  await expect(page.getByTestId('qr-verdict')).toHaveAttribute('data-verdict', 'danger');
  await expect(page.getByTestId('qr-content')).toHaveText('javascript:window.__qrxss=1');
  expect(await page.evaluate(() => (window as unknown as { __qrxss?: number }).__qrxss)).toBeUndefined();
});

test('a clean link can be opened after the check', async ({ page }) => {
  await register(page, { name: 'Qr Clean', email: uniqueEmail('qrok') });
  await openScanner(page);
  await paste(page, 'https://www.google.com/');
  await expect(page.getByTestId('qr-verdict')).toHaveAttribute('data-verdict', 'safe');
  await expect(page.getByTestId('qr-result').getByRole('button', { name: 'Open link' })).toBeVisible();
});

test('a QR code in an uploaded image is decoded on the device and checked', async ({ page }) => {
  await register(page, { name: 'Qr Image', email: uniqueEmail('qrimg') });
  await openScanner(page);
  await page.getByRole('tab', { name: 'Image' }).click();
  await page.getByTestId('qr-image-input').setInputFiles(fixture('qr-http-shortlink.png'));
  await expect(page.getByTestId('qr-content')).toHaveText('http://goo.by/wkEtco', { timeout: 15_000 });
  await expect(page.getByTestId('qr-verdict')).toHaveAttribute('data-verdict', 'caution');
  await expect(page.getByTestId('qr-findings').locator('[data-finding="shortener"]')).toBeVisible();
  await expect(page.getByTestId('qr-findings').locator('[data-finding="not_https"]')).toBeVisible();
  // "Open anyway" asks first.
  await page.getByTestId('qr-result').getByRole('button', { name: 'Open anyway' }).click();
  await expect(page.getByRole('dialog')).toContainText('warning signs');
  await page.getByRole('button', { name: 'Cancel' }).click();
});

test('an image without a QR code gives a clear message', async ({ page }) => {
  await register(page, { name: 'Qr None', email: uniqueEmail('qrnone') });
  await openScanner(page);
  await page.getByRole('tab', { name: 'Image' }).click();
  // 1x1 white PNG
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII=', 'base64');
  await page.getByTestId('qr-image-input').setInputFiles({ name: 'blank.png', mimeType: 'image/png', buffer: png });
  await expect(page.getByText('No QR code was found in this image')).toBeVisible({ timeout: 15_000 });
});

test.describe('live camera', () => {
  test.use({
    permissions: ['camera'],
    launchOptions: {
      args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', `--use-file-for-fake-video-capture=${fixture('qr-http-shortlink.y4m')}`],
    },
  });

  test('scans a QR code from the camera and stops the camera afterwards', async ({ page }) => {
    // Keep a reference to every camera stream the page opens, to check it is released.
    await page.addInitScript(() => {
      const w = window as unknown as { __streams: MediaStream[] };
      w.__streams = [];
      const original = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getUserMedia = async (c) => {
        const s = await original(c);
        w.__streams.push(s);
        return s;
      };
    });
    await register(page, { name: 'Qr Camera', email: uniqueEmail('qrcam') });
    await openScanner(page);
    await page.getByRole('button', { name: 'Start camera' }).click();
    await expect(page.getByTestId('qr-content')).toHaveText('http://goo.by/wkEtco', { timeout: 20_000 });
    await expect(page.getByTestId('qr-verdict')).toHaveAttribute('data-verdict', 'caution');
    const streams = await page.evaluate(() => {
      const all = (window as unknown as { __streams: MediaStream[] }).__streams;
      return { opened: all.length, live: all.flatMap((s) => s.getTracks()).filter((t) => t.readyState === 'live').length };
    });
    expect(streams.opened).toBe(1);
    expect(streams.live).toBe(0);
  });
});

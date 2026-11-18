import { fileURLToPath } from 'node:url';
import { expect, test, type Page } from '@playwright/test';
import { register, uniqueEmail } from './helpers';

// Live camera scanning. Chromium's fake camera plays a short video of a QR code photo, so the real
// getUserMedia → frame capture → decode → check path runs. Browser settings must be top-level.
const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

async function openScanner(page: Page) {
  await page.goto('/app/scan');
  await expect(page.getByRole('heading', { name: 'QR Security Scanner' })).toBeVisible();
}

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

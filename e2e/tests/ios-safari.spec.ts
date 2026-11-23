import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import { register, shareFields, uniqueEmail } from './helpers';

/**
 * Regression: on iPhone Safari, "Hide sensitive information" failed with
 * "this.#n.getOrInsertComputed is not a function" under "The pages could not be prepared".
 * pdfjs-dist's modern build calls Map/WeakMap.prototype.getOrInsertComputed (a new JavaScript
 * feature Safari does not have yet) in the page and in its worker. The app now loads the legacy
 * build, which brings polyfills for both.
 *
 * Runs in two ways:
 *  - every project: the newest built-ins pdf.js uses are removed from the page AND from the pdf.js
 *    worker before they run, as on Safari, so this fails if the modern build ever comes back;
 *  - "iphone-safari" project: the same flows in WebKit (Safari's engine) with iPhone settings.
 */

/** Built-ins newer than iOS Safari that pdf.js relies on. Removed to behave like Safari. */
const STRIP = `
  for (const C of [Map, WeakMap]) {
    delete C.prototype.getOrInsertComputed;
    delete C.prototype.getOrInsert;
  }
  delete Uint8Array.prototype.toHex;
  delete Uint8Array.prototype.toBase64;
  delete Uint8Array.fromBase64;
  delete Uint8Array.fromHex;
  delete Math.sumPrecise;
`;

async function likeSafari(context: BrowserContext) {
  await context.addInitScript(STRIP);
  // The pdf.js worker is a separate script: strip the same built-ins at its top.
  await context.route(/pdf\.worker[^/]*\.mjs(\?.*)?$/, async (route) => {
    const res = await route.fetch();
    const body = await res.text();
    await route.fulfill({ response: res, body: STRIP + body, headers: { ...res.headers(), 'content-type': 'text/javascript' } });
  });
}

async function letterPdf() {
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const p = pdf.addPage([595, 842]);
  p.drawText('Employment letter', { x: 60, y: 760, size: 26, font });
  p.drawText('Email: reham.private@example.com', { x: 60, y: 600, size: 16, font });
  p.drawText('Phone: +966 55 123 4567', { x: 60, y: 560, size: 16, font });
  p.drawText('National ID: 1029384756', { x: 60, y: 520, size: 16, font });
  return Buffer.from(await pdf.save());
}

/**
 * Errors of the kind this regression is about: a missing built-in or a PDF that could not be
 * prepared. (WebKit also logs requests cancelled by page changes, e.g. "... due to access control
 * checks"; those are not PDF errors and are left out.)
 */
const PDF_ERROR = /getOrInsert|is not a function|could not be prepared|pdf/i;
function collectErrors(page: Page) {
  const errors: string[] = [];
  page.on('pageerror', (e) => {
    if (PDF_ERROR.test(e.message)) errors.push(e.message);
  });
  page.on('console', (m) => {
    if (m.type() === 'error' && PDF_ERROR.test(m.text())) errors.push(m.text());
  });
  return errors;
}

test('PDF pages are prepared and sensitive information is detected without the newest JavaScript built-ins', async ({ page, browser }) => {
  await likeSafari(page.context());
  const errors = collectErrors(page);
  await register(page, { name: 'Safari Owner', email: uniqueEmail('safari') });

  // Upload: the editor prepares the pages of a file that is not uploaded yet.
  await page.goto('/app/documents/upload');
  await page.getByTestId('file-input').setInputFiles({ name: 'letter.pdf', mimeType: 'application/pdf', buffer: await letterPdf() });
  await page.getByLabel('Title').fill('Employment letter');
  await page.getByTestId('upload-sensitive').getByText('Hide sensitive information when sharing').click();
  await expect(page.getByText(/could not be prepared/)).toHaveCount(0);
  await expect(page.getByTestId('redaction-page-0').locator('img')).toBeVisible({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Detect sensitive information' }).click();
  const kinds = page.getByTestId('sensitive-kinds');
  await expect(kinds.getByRole('button', { name: 'Email addresses: hidden' })).toBeVisible();
  await expect(kinds.getByRole('button', { name: 'Phone numbers: hidden' })).toBeVisible();
  await expect(kinds.getByRole('button', { name: 'ID numbers: hidden' })).toBeVisible();
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  const docId = page.url().split('/').pop()!;

  // The owner's own viewer, and the stored-document editor.
  await page.getByRole('button', { name: 'Preview', exact: true }).click();
  await expect(page.locator('canvas.pdf-page').first()).toBeVisible({ timeout: 30_000 });
  await page.goto(`/app/documents/${docId}/sensitive`);
  await expect(page.getByTestId('redaction-page-0').locator('img')).toBeVisible({ timeout: 30_000 });

  // Share: the redacted copy is prepared from the saved choice and previewed.
  await page.goto(`/app/documents/${docId}/share`);
  await page.getByText('Include the file').click();
  await expect(page.getByTestId('plan-applied')).toBeVisible();
  await expect(page.getByTestId('redaction-page-0').locator('img')).toBeVisible({ timeout: 30_000 });
  await page.getByLabel('Recipient name').fill('Example Company');
  await page.getByRole('button', { name: 'Preview recipient copy' }).click();
  await expect(page.getByTestId('preview-viewer').locator('canvas.pdf-page').first()).toBeVisible({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Create secure link' }).click();
  const url = (await page.getByTestId('share-url').textContent())!.trim();

  // A recipient on the same kind of browser sees the file.
  const context = await browser.newContext();
  await likeSafari(context);
  const recipient = await context.newPage();
  const recipientErrors = collectErrors(recipient);
  await recipient.goto(url);
  await expect(recipient.locator('canvas.pdf-page').first()).toBeVisible({ timeout: 30_000 });

  expect(errors).toEqual([]);
  expect(recipientErrors).toEqual([]);
  await context.close();
});

test('a shared original file renders for the recipient without the newest built-ins', async ({ page, browser }) => {
  await register(page, { name: 'Viewer Owner', email: uniqueEmail('viewer') });
  await page.goto('/app/documents/upload');
  await page.getByTestId('file-input').setInputFiles({ name: 'letter.pdf', mimeType: 'application/pdf', buffer: await letterPdf() });
  await page.getByLabel('Title').fill('Letter');
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  const url = await shareFields(page, page.url().split('/').pop()!, { includeFile: true, recipient: 'Landlord' });

  const context = await browser.newContext();
  await likeSafari(context);
  const recipient = await context.newPage();
  const errors = collectErrors(recipient);
  await recipient.goto(url);
  await expect(recipient.locator('canvas.pdf-page').first()).toBeVisible({ timeout: 30_000 });
  expect(errors).toEqual([]);
  await context.close();
});

test('the app loads pdf.js only through the legacy build', async ({}, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'source check, once');
  const root = fileURLToPath(new URL('../../apps/web/src/', import.meta.url));
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(ts|tsx)$/.test(name)) files.push(p);
    }
  };
  walk(root);
  const offenders = files.filter((f) => {
    const src = readFileSync(f, 'utf8');
    return /from ['"]pdfjs-dist(?!\/legacy\/)/.test(src) && !f.endsWith('pdfjs-legacy.d.ts');
  });
  expect(offenders).toEqual([]);
  expect(readFileSync(join(root, 'lib', 'pdfjs.ts'), 'utf8')).toContain("'pdfjs-dist/legacy/build/pdf.worker.min.mjs?url'");
});

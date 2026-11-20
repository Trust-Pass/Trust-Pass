import { inflateSync } from 'node:zlib';
import { expect, test } from '@playwright/test';
import { PDFDocument, StandardFonts } from 'pdf-lib';
import { newPhone, register, uniqueEmail } from './helpers';

// Final owner controls in a real browser: encryption check, find-and-hide, watermark off,
// server-built preview, and what the recipient's copies really contain.

const EMAIL = 'reham.private@example.com';
const PHONE = '+966 55 123 4567';
const SALARY = 'Salary: 25,000 SAR';

function pdfText(copy: Buffer): string {
  let content = copy.toString('latin1');
  for (const m of content.matchAll(/stream\r?\n/g)) {
    const start = m.index! + m[0].length;
    try {
      content += inflateSync(copy.subarray(start, content.indexOf('endstream', start))).toString('latin1');
    } catch {
      /* not Flate */
    }
  }
  return content;
}
const hex = (t: string) => Buffer.from(t, 'latin1').toString('hex').toUpperCase();

test('owner checks encryption, finds and hides private details, previews, and shares without a watermark', async ({ page, browser }) => {
  await register(page, { name: 'Controls Owner', email: uniqueEmail('controls') });
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const p = pdf.addPage([595, 842]);
  p.drawText('Employment letter', { x: 60, y: 760, size: 26, font });
  p.drawText(`Email: ${EMAIL}`, { x: 60, y: 600, size: 16, font });
  p.drawText(`Phone: ${PHONE}`, { x: 60, y: 560, size: 16, font });
  p.drawText(SALARY, { x: 60, y: 520, size: 16, font });
  p.drawText('National ID: 1029384756', { x: 60, y: 480, size: 16, font });
  p.drawText('This letter is valid without a signature from the bank.', { x: 60, y: 440, size: 12, font });
  p.drawText('Signature:', { x: 60, y: 200, size: 16, font });
  const bytes = Buffer.from(await pdf.save());

  await page.goto('/app/documents/upload');
  // One encryption method, explained; no fake choices.
  await expect(page.getByTestId('encryption-method').getByRole('radio')).toHaveCount(1);
  await expect(page.getByTestId('encryption-method')).toContainText('AES-256-GCM');
  await page.getByTestId('file-input').setInputFiles({ name: 'letter.pdf', mimeType: 'application/pdf', buffer: bytes });
  await page.getByLabel('Title').fill('Employment letter');

  // Hide sensitive information at upload: detected in the browser, before anything is sent.
  await page.getByTestId('upload-sensitive').getByText('Hide sensitive information when sharing').click();
  await expect(page.getByTestId('redaction-page-0').locator('img')).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: 'Detect sensitive information' }).click();
  const kinds = page.getByTestId('sensitive-kinds');
  await expect(kinds.getByRole('button', { name: 'Email addresses: hidden' })).toBeVisible();
  await expect(kinds.getByRole('button', { name: 'Phone numbers: hidden' })).toBeVisible();
  await expect(kinds.getByRole('button', { name: 'Financial details: hidden' })).toBeVisible();
  await expect(kinds.getByRole('button', { name: 'ID numbers: hidden' })).toBeVisible();
  await expect(kinds.getByRole('button', { name: 'Signatures: hidden' })).toBeVisible();
  // The owner lets recipients see the phone number, then changes their mind.
  await kinds.getByRole('button', { name: 'Phone numbers: hidden' }).click();
  await expect(kinds.getByRole('button', { name: 'Phone numbers: visible' })).toBeVisible();
  await kinds.getByRole('button', { name: 'Phone numbers: visible' }).click();
  await page.getByRole('radio', { name: 'Pixelate' }).click();
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  const docId = page.url().split('/').pop()!;
  const plan = (await (await page.request.get(`/api/documents/${docId}/redaction-plan`)).json()).redactions as Array<{ kind: string; style: string }>;
  expect(new Set(plan.map((r) => r.kind))).toEqual(new Set(['email', 'phone', 'financial', 'id', 'signature']));
  // One signature field: the word inside a sentence is not one.
  expect(plan.filter((r) => r.kind === 'signature')).toHaveLength(1);
  // The 10-digit ID is an ID number, not a phone number.
  expect(plan.filter((r) => r.kind === 'phone')).toHaveLength(1);
  expect(plan.every((r) => r.style === 'pixelate')).toBe(true);

  await page.getByRole('button', { name: 'Check encryption now' }).click();
  await expect(page.getByTestId('encryption-check-result')).toHaveAttribute('data-ok', 'true');
  await expect(page.getByTestId('encryption-check')).toContainText('Authentication tag verified');

  // Sharing starts from the saved choice: a redacted copy with those areas.
  await page.goto(`/app/documents/${docId}/share`);
  await page.getByText('Include the file').click();
  await expect(page.getByTestId('plan-applied')).toBeVisible();
  await expect(page.getByRole('radio', { name: 'Redacted copy' })).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByTestId('redaction-page-0').locator('img')).toBeVisible({ timeout: 20_000 });

  // The watermark is off unless the owner turns it on.
  await expect(page.getByTestId('watermark-controls')).toContainText('Off: the recipient’s copy has no watermark');
  await page.getByLabel('Recipient name').fill('Example Company');
  await page.getByRole('button', { name: 'Preview recipient copy' }).click();
  await expect(page.getByTestId('preview-viewer').locator('canvas.pdf-page').first()).toBeVisible({ timeout: 20_000 });

  await page.getByText('Allow download of a PDF copy').click();
  await page.getByRole('button', { name: 'Create secure link' }).click();
  await expect(page.getByText('No watermark (views and downloads are still logged)')).toBeVisible();
  const url = (await page.getByTestId('share-url').textContent())!.trim();
  const token = url.split('/s/')[1]!;

  const recipient = await newPhone(browser);
  await recipient.goto(url);
  await expect(recipient.getByText(/Redacted copy: the owner hid parts of this document/)).toBeVisible();
  await expect(recipient.getByTestId('download-copy')).toHaveText(/Download PDF/);
  for (const path of ['/file', '/download']) {
    const res = await recipient.request.get(`/api/share/${token}${path}`);
    expect(res.status()).toBe(200);
    const text = pdfText(Buffer.from(await res.body()));
    for (const secret of [EMAIL, PHONE, '25,000', '1029384756', 'Employment letter']) {
      expect(text).not.toContain(secret);
      expect(text).not.toContain(hex(secret));
    }
    expect(text).not.toContain(hex('CONFIDENTIAL'));
    expect(text).not.toMatch(/\/BaseFont/); // page images only: no text layer, no watermark
    const doc = await PDFDocument.load(Buffer.from(await res.body()), { updateMetadata: false });
    expect(`${doc.getTitle()} ${doc.getSubject()} ${doc.getAuthor()}`).not.toMatch(/Employment|reham/i);
  }
  // A recipient cannot change anything or see the owner's controls.
  expect((await recipient.request.put(`/api/links/${token}/watermark`, { data: { watermark: { enabled: true } } })).status()).toBeGreaterThanOrEqual(400);

  // The owner's original is unchanged.
  const original = await page.request.get(`/api/documents/${docId}/file`);
  expect(Buffer.from(await original.body()).equals(bytes)).toBe(true);

  // The owner turns the watermark back on from Shared links; the next view carries it.
  await page.goto('/app/links');
  await page.getByRole('button', { name: 'Activity' }).first().click();
  await page.getByTestId('link-watermark').getByRole('button', { name: 'Turn on watermark' }).click();
  await expect(page.getByTestId('link-watermark')).toContainText('Watermark on');
  const again = await recipient.request.get(`/api/share/${token}/file`);
  expect(pdfText(Buffer.from(await again.body()))).toContain(hex('CONFIDENTIAL'));
});

test('landing and QR Security pages stay short, with no sideways scrolling', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expect(page.locator('#security')).toBeVisible();
  await expect(page.getByText('How it works')).toHaveCount(0);
  await expect(page.getByText('The fine print')).toHaveCount(0);
  const landing = await page.evaluate(() => ({ h: document.documentElement.scrollHeight, vh: innerHeight, w: document.documentElement.scrollWidth, vw: innerWidth }));
  expect(landing.w).toBeLessThanOrEqual(landing.vw);
  expect(landing.h).toBeLessThanOrEqual(landing.vh * 4.5);

  await register(page, { name: 'Scan Layout', email: uniqueEmail('scanlayout') });
  await page.goto('/app/scan');
  await expect(page.getByText('Analyze QR codes to detect phishing, suspicious links, and unsafe destinations before opening them.')).toBeVisible();
  await expect(page.getByText('What TrustPass checks')).toHaveCount(0);
  await expect(page.getByText(/no photo is uploaded/)).toHaveCount(0);
  for (const tab of ['Live camera', 'Image', 'Paste a link']) await expect(page.getByRole('tab', { name: tab }).or(page.getByRole('button', { name: tab })).first()).toBeVisible();
  const scan = await page.evaluate(() => ({ w: document.documentElement.scrollWidth, vw: innerWidth }));
  expect(scan.w).toBeLessThanOrEqual(scan.vw);
});

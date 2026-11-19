import { inflateSync } from 'node:zlib';
import { expect, test } from '@playwright/test';
import { PDFDocument, PDFName, PDFRawStream, StandardFonts, rgb } from 'pdf-lib';
import { newPhone, register, uniqueEmail } from './helpers';

// Smart Selective Encryption in a real browser: pdf.js renders the pages, the owner drags a box
// over the secret line, and the recipient's copy must contain neither its text nor its pixels.

const SECRET = 'SECRET-ID-4242424242';

test('the owner hides an area; the recipient copy has no trace of it, in text or pixels', async ({ page, browser }) => {
  await register(page, { name: 'Redact Owner', email: uniqueEmail('redact') });
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.HelveticaBold);
  const p = pdf.addPage([595, 842]);
  p.drawText('Visible heading', { x: 60, y: 760, size: 28, font });
  // The secret line sits in the bottom quarter of the page, in red so its pixels are recognisable.
  p.drawRectangle({ x: 40, y: 80, width: 515, height: 90, color: rgb(0.9, 0.05, 0.05) });
  p.drawText(SECRET, { x: 60, y: 110, size: 26, font, color: rgb(1, 1, 1) });
  const bytes = Buffer.from(await pdf.save());

  await page.goto('/app/documents/upload');
  await page.getByTestId('file-input').setInputFiles({ name: 'id.pdf', mimeType: 'application/pdf', buffer: bytes });
  await page.getByLabel('Title').fill('ID card');
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  const docId = page.url().split('/').pop()!;

  await page.goto(`/app/documents/${docId}/share`);
  await page.getByText('Include the file').click();
  await page.getByRole('radio', { name: 'Redacted copy' }).click();
  const surface = page.getByTestId('redaction-page-0');
  await expect(surface.locator('img')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole('button', { name: 'Create secure link' })).toBeDisabled();

  // Drag over the bottom 30% of the page (the red block is at 10-20% from the bottom). The bottom of
  // the page is scrolled into view first: pointer events only reach what is on screen.
  await surface.evaluate((el) => el.scrollIntoView({ block: 'end' }));
  const box = (await surface.boundingBox())!;
  await page.mouse.move(box.x + box.width * 0.02, box.y + box.height * 0.7);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width * 0.6, box.y + box.height * 0.85, { steps: 5 });
  await page.mouse.move(box.x + box.width * 0.98, box.y + box.height * 0.98, { steps: 5 });
  await page.mouse.up();
  await expect(page.getByText('1 area hidden.')).toBeVisible();

  await page.getByText('Allow download of a watermarked PDF').click();
  await page.getByLabel('Recipient name').fill('Example Company');
  await page.getByRole('button', { name: 'Create secure link' }).click();
  const url = (await page.getByTestId('share-url').textContent())!.trim();
  const token = url.split('/s/')[1]!;

  const recipient = await newPhone(browser);
  await recipient.goto(url);
  await expect(recipient.getByText(/Redacted copy: the owner hid parts of this document/)).toBeVisible();
  await expect(recipient.locator('canvas.pdf-page').first()).toBeVisible({ timeout: 20_000 });

  for (const path of ['/file', '/download']) {
    const res = await recipient.request.get(`/api/share/${token}${path}`);
    expect(res.status()).toBe(200);
    const copy = Buffer.from(await res.body());
    // No text of the original, in any encoding.
    let content = copy.toString('latin1');
    for (const m of content.matchAll(/stream\r?\n/g)) {
      const start = m.index! + m[0].length;
      try {
        content += inflateSync(copy.subarray(start, content.indexOf('endstream', start))).toString('latin1');
      } catch {
        /* not Flate */
      }
    }
    expect(content).not.toContain(SECRET);
    expect(content).not.toContain(Buffer.from(SECRET).toString('hex').toUpperCase());
    expect(content).not.toContain(Buffer.from('Visible heading').toString('hex').toUpperCase()); // even visible text is pixels only
    // Pixels: the red block is gone, the heading area is still there.
    const doc = await PDFDocument.load(copy);
    let red = 0;
    let dark = 0;
    for (const [, obj] of doc.context.enumerateIndirectObjects()) {
      if (obj instanceof PDFRawStream && obj.dict.get(PDFName.of('Subtype'))?.toString() === '/Image') {
        const px = inflateSync(Buffer.from(obj.contents));
        for (let i = 0; i + 2 < px.length; i += 3) {
          if (px[i]! > 150 && px[i + 1]! < 90 && px[i + 2]! < 90) red++;
          if (px[i]! < 60 && px[i + 1]! < 60 && px[i + 2]! < 60) dark++;
        }
      }
    }
    expect(red).toBe(0);
    expect(dark).toBeGreaterThan(10_000);
  }
});

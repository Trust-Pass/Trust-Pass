import { expect, test } from '@playwright/test';
import { register, uniqueEmail } from './helpers';

// First-stage UI changes: a quieter landing header and a simpler upload page.

test('landing: no sign-in buttons in the top bar; the two buttons under the headline stay', async ({ page }) => {
  await page.goto('/');
  const header = page.locator('header').first();
  await expect(header.getByText('Sign in')).toHaveCount(0);
  await expect(header.getByText('Create your vault')).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Create a free account' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'I already have an account' })).toBeVisible();
  await page.getByRole('link', { name: 'I already have an account' }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto('/');
  await page.getByRole('link', { name: 'Create a free account' }).click();
  await expect(page).toHaveURL(/\/register$/);
  const width = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
  expect(width).toBe(true);
});

test('upload: short page; file rules only on a failed or unsupported file; upload and encryption still work', async ({ page }) => {
  await register(page, { name: 'Upload Owner', email: uniqueEmail('upload') });
  await page.goto('/app/documents/upload');
  await expect(page.getByRole('heading', { name: 'Upload a document' })).toBeVisible();
  // No introductory text, no accepted-files text, no shareable fields.
  await expect(page.getByText(/PDF, PNG or JPEG/)).toHaveCount(0);
  await expect(page.getByText(/Accepted files/)).toHaveCount(0);
  await expect(page.getByText('Shareable fields (optional)')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Add a field' })).toHaveCount(0);
  // Encryption card stays, with one short sentence.
  await expect(page.getByTestId('encryption-method')).toContainText('AES-256-GCM');
  await expect(page.getByText('Your file is encrypted and securely stored.')).toBeVisible();
  await expect(page.getByText(/Offering weaker alternatives/)).toHaveCount(0);
  await expect(page.getByLabel('Title')).toBeVisible();
  await expect(page.getByLabel('Category')).toBeVisible();

  // Unsupported type: the rules appear.
  await page.getByTestId('file-input').setInputFiles({ name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('hello') });
  await expect(page.getByText('This type of file is not supported. Accepted files: PDF, PNG or JPEG, up to 10 MB.')).toBeVisible();
  // Too large: the rules appear.
  await page.getByTestId('file-input').setInputFiles({ name: 'big.pdf', mimeType: 'application/pdf', buffer: Buffer.alloc(11 * 1024 * 1024, 0x20) });
  await expect(page.getByText(/too large\. Accepted files: PDF, PNG or JPEG, up to 10 MB\./)).toBeVisible();
  // A file that claims to be a PDF but is not: the server refuses it and the rules appear.
  await page.getByTestId('file-input').setInputFiles({ name: 'fake.pdf', mimeType: 'application/pdf', buffer: Buffer.from('MZ this is not a pdf at all') });
  await page.getByLabel('Title').fill('Fake');
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await expect(page.getByText(/Accepted files: PDF, PNG or JPEG, up to 10 MB\./)).toBeVisible();

  // A real upload still works, encrypted.
  const { PDFDocument } = await import('pdf-lib');
  const pdf = await PDFDocument.create();
  pdf.addPage([300, 300]);
  await page.getByTestId('file-input').setInputFiles({ name: 'ok.pdf', mimeType: 'application/pdf', buffer: Buffer.from(await pdf.save()) });
  await expect(page.getByText(/Accepted files/)).toHaveCount(0);
  await page.getByLabel('Title').fill('Stage one upload');
  await page.getByLabel('Category').selectOption({ index: 1 });
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  await page.getByRole('button', { name: 'Check encryption now' }).click();
  await expect(page.getByTestId('encryption-check-result')).toHaveAttribute('data-ok', 'true');
});

test('verify: the meaning of each result is behind a small Info button, easy to open and close', async ({ page }) => {
  await register(page, { name: 'Info Reader', email: uniqueEmail('info') });
  await page.goto('/app/verify');
  // Clean page: no legend until asked for.
  await expect(page.getByText('What the results mean')).toHaveCount(0);
  const info = page.getByRole('button', { name: 'Info: what the verification results mean' });
  await expect(info).toBeVisible();
  await expect(info).toHaveText('Info');

  await info.click();
  const dialog = page.getByRole('dialog').filter({ hasText: 'What the results mean' });
  await expect(dialog).toBeVisible();
  const legend = dialog.getByTestId('results-legend');
  await expect(legend.getByRole('listitem')).toHaveCount(4);
  await expect(legend).toContainText('Verified The digital signature is valid and the signing key belongs to a trusted issuer registered in TrustPass.');
  await expect(legend).toContainText('Invalid The signature does not match, or the document was changed after it was signed.');
  await expect(legend).toContainText('Expired The signature is valid and the document is unchanged, but the credential is past its validity period.');
  await expect(legend).toContainText(
    "Unable to verify No supported digital signature, or the signer is not a trusted issuer in TrustPass. A document's look or issuer name is never enough.",
  );
  // The whole dialog fits on screen, with nothing sideways.
  const box = (await dialog.boundingBox())!;
  const viewport = page.viewportSize()!;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 1);
  expect(box.y + box.height).toBeLessThanOrEqual(viewport.height + 1);

  // Close button, Escape and a tap outside all close it; focus returns to the page.
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toBeHidden();
  await info.click();
  await expect(dialog).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await info.click();
  await expect(dialog).toBeVisible();
  await page.mouse.click(5, 5);
  await expect(dialog).toBeHidden();

  // Verification itself is unchanged: an unsigned file is still "Unable to verify".
  const { PDFDocument } = await import('pdf-lib');
  const own = await PDFDocument.create();
  own.addPage([300, 300]);
  await page.getByLabel('File to verify').setInputFiles({ name: 'own.pdf', mimeType: 'application/pdf', buffer: Buffer.from(await own.save()) });
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(page.getByTestId('verification-result')).toHaveAttribute('data-result', 'unverified');
  await expect(page.getByTestId('verification-result')).toContainText('Unable to verify');
  await expect(info).toBeVisible();
});

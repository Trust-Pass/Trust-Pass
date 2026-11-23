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

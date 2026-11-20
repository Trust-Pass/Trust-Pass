import { expect, test } from '@playwright/test';
import { issueCredential, newPhone, register, shareFields, uniqueEmail } from './helpers';

test('share one verified field, open it elsewhere, then revoke it', async ({ page, browser }) => {
  await register(page, { name: 'Reham Alkhamees', email: uniqueEmail('reham') });
  await expect(page.getByRole('heading', { name: /^Good (morning|afternoon|evening), Reham$/ })).toBeVisible();

  const docId = await issueCredential(page);
  const claims = (await (await page.request.get(`/api/documents/${docId}`)).json()).document.claims as Array<{ key: string; value: string }>;
  const studentId = claims.find((c) => c.key === 'student_id')!.value;
  const url = await shareFields(page, docId, { fields: ['Enrollment status'], recipient: 'Example Company' });
  expect(url).toMatch(/\/s\/[A-Za-z0-9_-]{43}$/);

  // The company opens the link on another device.
  const company = await newPhone(browser);
  await company.goto(url);
  await expect(company.getByTestId('verification-result')).toHaveAttribute('data-result', 'verified');
  await expect(company.getByTestId('shared-fields')).toContainText('Enrollment status');
  await expect(company.getByTestId('shared-fields')).toContainText('Active');
  const visible = await company.locator('body').innerText();
  expect(visible).not.toContain(studentId);
  expect(visible).not.toContain('BSc Cybersecurity');
  await expect(company.getByText('1 of 6 signed claims disclosed')).toBeVisible();

  // The owner revokes the link; the company's next attempt fails immediately.
  await page.goto('/app/links');
  await page.getByRole('button', { name: 'Revoke' }).first().click();
  await page.getByRole('button', { name: 'Revoke now' }).click();
  await expect(page.getByRole('tab', { name: /Revoked/ })).toContainText('1');

  await company.reload();
  await expect(company.getByTestId('access-denied')).toHaveAttribute('data-code', 'link_revoked');

  // Analytics show both attempts.
  await page.goto('/app/analytics');
  const summary = page.getByTestId('analytics-summary');
  await expect(summary.getByText('Total attempts').locator('..').locator('..')).toContainText('2');
  await expect(page.locator('span', { hasText: 'Link revoked' }).filter({ visible: true }).first()).toBeVisible();
});

test('upload an encrypted file and share it watermarked, view-only', async ({ page, browser }) => {
  await register(page, { name: 'Sara Test', email: uniqueEmail('sara') });
  const { PDFDocument, StandardFonts } = await import('pdf-lib');
  const pdf = await PDFDocument.create();
  const p = pdf.addPage([595, 842]);
  p.drawText('Employment Offer Letter', { x: 60, y: 760, size: 22, font: await pdf.embedFont(StandardFonts.Helvetica) });
  const bytes = Buffer.from(await pdf.save());

  await page.goto('/app/documents/upload');
  await page.getByTestId('file-input').setInputFiles({ name: 'offer.pdf', mimeType: 'application/pdf', buffer: bytes });
  await page.getByLabel('Title').fill('Offer letter');
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  await expect(page.getByText('AES-256-GCM', { exact: true })).toBeVisible();
  const docId = page.url().split('/').pop()!;

  const url = await shareFields(page, docId, { includeFile: true, recipient: 'Landlord' });
  const landlord = await newPhone(browser);
  await landlord.goto(url);
  await expect(landlord.getByTestId('verification-result')).toHaveAttribute('data-result', 'unverified');
  await expect(landlord.locator('canvas.pdf-page').first()).toBeVisible({ timeout: 20_000 });
  await expect(landlord.getByText('Downloads are disabled')).toBeVisible();
});

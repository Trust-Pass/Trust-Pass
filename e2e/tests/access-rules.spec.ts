import { expect, test } from '@playwright/test';
import { issueCredential, newPhone, register, shareFields, uniqueEmail } from './helpers';

// The e2e server simulates every visitor as connecting from Saudi Arabia.

test('a link limited to the UAE is refused from Saudi Arabia', async ({ page, browser }) => {
  await register(page, { name: 'Geo Owner', email: uniqueEmail('geo') });
  const docId = await issueCredential(page, 'Geo Owner');
  const url = await shareFields(page, docId, {
    fields: ['Program'],
    countries: { remove: ['Saudi Arabia'], add: ['United Arab Emirates'] },
  });
  const visitor = await newPhone(browser);
  await visitor.goto(url);
  await expect(visitor.getByTestId('access-denied')).toHaveAttribute('data-code', 'country_blocked');
  await expect(visitor.getByText('Not available in your location')).toBeVisible();
  await expect(visitor.locator('body')).not.toContainText('United Arab Emirates');
});

test('organization-only links require a member of that organization', async ({ page, browser }) => {
  const orgName = `Example Company ${Date.now().toString(36)}`;
  const company = await newPhone(browser);
  await register(company, { name: 'Hiring Manager', email: uniqueEmail('hr'), organization: orgName });

  await register(page, { name: 'Applicant', email: uniqueEmail('applicant') });
  const docId = await issueCredential(page, 'Applicant Person');
  const url = await shareFields(page, docId, { fields: ['Enrollment status'], organization: orgName });

  // Someone else with the link but no organization account is refused.
  const stranger = await newPhone(browser);
  await stranger.goto(url);
  await expect(stranger.getByTestId('access-denied')).toHaveAttribute('data-code', 'login_required');
  await expect(stranger.locator('body')).not.toContainText(orgName);

  // The company finds it in its inbox, already verified.
  await company.goto('/app/org');
  await company.getByRole('link', { name: /Enrollment Certificate/ }).click();
  await expect(company.getByTestId('verification-result')).toHaveAttribute('data-result', 'verified');
  await expect(company.getByTestId('shared-fields')).toContainText('Active');
});

test("users cannot open another user's document", async ({ page, browser }) => {
  await register(page, { name: 'Owner One', email: uniqueEmail('owner') });
  const docId = await issueCredential(page, 'Owner One');
  const intruder = await newPhone(browser);
  await register(intruder, { name: 'Intruder', email: uniqueEmail('intruder') });
  await intruder.goto(`/app/documents/${docId}`);
  await expect(intruder.getByText('Document not found').first()).toBeVisible();
  const res = await intruder.request.get(`/api/documents/${docId}/file`);
  expect(res.status()).toBe(404);
});

test('script in a document title is shown as text, never run', async ({ page }) => {
  await register(page, { name: 'Xss Tester', email: uniqueEmail('xss') });
  const { PDFDocument } = await import('pdf-lib');
  const pdf = await PDFDocument.create();
  pdf.addPage([200, 200]);
  const payload = '<img src=x onerror="window.__xss=1">';
  await page.goto('/app/documents/upload');
  await page.getByTestId('file-input').setInputFiles({ name: 'x.pdf', mimeType: 'application/pdf', buffer: Buffer.from(await pdf.save()) });
  await page.getByLabel('Title').fill(payload);
  await page.getByRole('button', { name: 'Encrypt and upload' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  await page.goto('/app/documents');
  await expect(page.getByText(payload)).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined();
  const response = await page.request.get('/app/documents');
  expect(response.headers()['content-security-policy']).toContain("script-src 'self'");
});

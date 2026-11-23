import { expect, test } from '@playwright/test';
import { issueCredential, login, newPhone, register, shareFields, uniqueEmail } from './helpers';

test('the Verification page tells genuine, modified and unsigned files apart', async ({ page }) => {
  await register(page, { name: 'Verifier', email: uniqueEmail('verifier') });
  const docId = await issueCredential(page, 'Verifier Person');
  const original = Buffer.from(await (await page.request.get(`/api/documents/${docId}/file`)).body());

  const check = async (name: string, buffer: Buffer) => {
    await page.goto('/app/verify');
    await page.getByLabel('File to verify').setInputFiles({ name, mimeType: 'application/pdf', buffer });
    await page.getByRole('button', { name: 'Verify', exact: true }).click();
    return page.getByTestId('verification-result');
  };

  await expect(await check('genuine.pdf', original)).toHaveAttribute('data-result', 'verified');

  const modified = Buffer.from(original);
  const at = modified.indexOf('stream\n') + 20;
  modified[at] = modified[at]! ^ 0x01;
  const tampered = await check('modified.pdf', modified);
  await expect(tampered).toHaveAttribute('data-result', 'invalid');
  await expect(tampered).toContainText('modified');

  const { PDFDocument } = await import('pdf-lib');
  const own = await PDFDocument.create();
  own.addPage([300, 300]);
  const unsigned = await check('own.pdf', Buffer.from(await own.save()));
  await expect(unsigned).toHaveAttribute('data-result', 'unverified');
  await expect(unsigned).toContainText('Unable to verify');

  // Looks like the certificate and names the issuer, but carries no signature: never Verified.
  const lookAlike = await PDFDocument.create();
  const font = await lookAlike.embedFont((await import('pdf-lib')).StandardFonts.Helvetica);
  lookAlike.addPage([595, 420]).drawText('TrustPass Demo University - Enrollment Certificate - VERIFIED', { x: 30, y: 300, size: 14, font });
  await expect(await check('look-alike.pdf', Buffer.from(await lookAlike.save()))).toHaveAttribute('data-result', 'unverified');

  // A pasted credential that is not one: unable to verify.
  await page.goto('/app/verify');
  await page.getByRole('tab', { name: /credential/i }).click();
  await page.getByRole('textbox').fill('This is definitely a genuine credential, trust me.');
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(page.getByTestId('verification-result')).toHaveAttribute('data-result', 'unverified');

  await expect(page.getByText('Verification records')).toBeVisible();
});

test('revoking the issuer means its credentials can no longer be verified anywhere', async ({ page, browser }) => {
  await register(page, { name: 'Holder', email: uniqueEmail('holder') });
  const docId = await issueCredential(page, 'Holder Person');
  const url = await shareFields(page, docId, { fields: ['Program'] });

  const admin = await newPhone(browser);
  await login(admin, 'admin@e2e.test', 'E2E-Admin-Password-2026');
  await admin.goto('/app/admin');
  await admin.getByRole('tab', { name: 'Issuers' }).click();
  await admin.getByRole('button', { name: 'Revoke trust' }).click();
  await expect(admin.getByRole('button', { name: 'Trust again' })).toBeVisible();

  try {
    const recipient = await newPhone(browser);
    await recipient.goto(url);
    await expect(recipient.getByTestId('verification-result')).toHaveAttribute('data-result', 'unverified');
    await expect(recipient.getByTestId('verification-result')).toContainText('revoked');
  } finally {
    await admin.getByRole('button', { name: 'Trust again' }).click();
    await expect(admin.getByRole('button', { name: 'Revoke trust' })).toBeVisible();
  }
});

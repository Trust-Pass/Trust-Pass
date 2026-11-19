import { expect, type Browser, type Page } from '@playwright/test';

export const PASSWORD = 'Correct-Horse-Battery-9';

let n = 0;
export function uniqueEmail(prefix: string) {
  n += 1;
  return `${prefix}.${Date.now().toString(36)}${n}@e2e.test`;
}

export async function register(page: Page, opts: { name: string; email: string; organization?: string }) {
  await page.goto('/register');
  if (opts.organization) {
    await page.getByRole('radio', { name: /Organization/ }).click();
    await page.getByLabel('Organization name').fill(opts.organization);
  }
  await page.getByLabel(/full name/i).fill(opts.name);
  await page.getByLabel('Email').fill(opts.email);
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.waitForURL('**/app');
}

export async function login(page: Page, email: string, password = PASSWORD) {
  await page.goto('/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.waitForURL('**/app');
}

/** Requests a signed demo credential and returns its document id. */
export async function issueCredential(page: Page, nameOnCertificate = 'Reham Alkhamees') {
  await page.goto('/app/credentials');
  await page.getByLabel('Name on the certificate').fill(nameOnCertificate);
  await page.getByRole('button', { name: 'Issue my signed credential' }).click();
  await page.waitForURL(/\/app\/documents\/[0-9a-f-]{36}$/);
  await expect(page.getByTestId('verification-result')).toHaveAttribute('data-result', 'verified');
  return page.url().split('/').pop()!;
}

export async function shareFields(
  page: Page,
  documentId: string,
  opts: { fields?: string[]; recipient?: string; organization?: string; countries?: { add?: string[]; remove?: string[] }; includeFile?: boolean; allowDownload?: boolean },
) {
  await page.goto(`/app/documents/${documentId}/share`);
  for (const field of opts.fields ?? []) await page.getByText(field, { exact: true }).click();
  if (opts.includeFile) await page.getByText('Include the file').click();
  if (opts.allowDownload) await page.getByText('Allow download of a watermarked PDF').click();
  if (opts.organization) {
    await page.getByRole('radio', { name: 'A TrustPass organization' }).click();
    await page.getByLabel('Search organizations').fill(opts.organization);
    await page.getByRole('button', { name: opts.organization }).click();
  } else {
    await page.getByLabel('Recipient name').fill(opts.recipient ?? 'Example Company');
  }
  for (const country of opts.countries?.remove ?? []) await page.getByRole('button', { name: `Remove ${country}` }).click();
  for (const country of opts.countries?.add ?? []) await page.getByRole('button', { name: country, pressed: false }).click();
  await page.getByRole('button', { name: 'Create secure link' }).click();
  const url = (await page.getByTestId('share-url').textContent())!.trim();
  return url;
}

export async function newPhone(browser: Browser) {
  const context = await browser.newContext();
  return context.newPage();
}

import { expect, test } from '@playwright/test';

// The homepage ends with the team credits; no other page shows them.

const TEAM = ['Reham Alkhamees', 'Nouf Alfulaij', 'Layan Alshahrani', 'Rana Alharbi'];

test('homepage shows the team credits at the very bottom, and only there', async ({ page }, info) => {
  await page.goto('/');
  const credits = page.getByTestId('credits');
  await credits.scrollIntoViewIfNeeded();
  await expect(credits).toBeVisible();
  await expect(credits.getByText('Developed by', { exact: true })).toBeVisible();
  await expect(credits.getByRole('list', { name: 'Team members' }).getByRole('listitem')).toHaveText(TEAM);
  await expect(credits.getByText('© 2026 TrustPass. All rights reserved.', { exact: true })).toBeVisible();
  // Nothing else in it: no emails, phone numbers or extra names.
  expect((await credits.innerText()).replace(/\s+/g, ' ').trim()).toBe(`Developed by ${TEAM.join(' ')} © 2026 TrustPass. All rights reserved.`);

  // It is the last thing on the page.
  const isLast = await credits.evaluate((el) => {
    const box = el.getBoundingClientRect();
    return Math.abs(box.bottom + scrollY - document.documentElement.scrollHeight) < 2;
  });
  expect(isLast).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: `test-results/tour/${info.project.name}-40-homepage-credits.jpg`, fullPage: true, type: 'jpeg', quality: 60 });

  for (const path of ['/login', '/register', '/forgot-password', '/s/not-a-real-link', '/app']) {
    await page.goto(path);
    await expect(page.locator('body')).not.toContainText('Developed by');
    await expect(page.locator('body')).not.toContainText('Alkhamees');
  }
});

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [['list']],
  use: {
    baseURL: 'http://localhost:3100',
    trace: 'off',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'mobile', use: { ...devices['iPhone 13'], browserName: 'chromium' } },
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    // Safari's engine (WebKit) with iPhone settings, for the iOS regression flows.
    { name: 'iphone-safari', use: { ...devices['iPhone 13'] }, testMatch: /ios-safari\.spec\.ts/ },
  ],
  webServer: {
    command: './start-server.sh',
    url: 'http://localhost:3100/api/health',
    timeout: 120_000,
    reuseExistingServer: false,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});

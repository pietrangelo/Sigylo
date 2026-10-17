import { defineConfig } from '@playwright/test';

// Runs against the real stack (Worker + static assets + PostgreSQL), started
// by scripts/e2e.sh. Set PLAYWRIGHT_CHROMIUM to use a preinstalled browser.
const executablePath = process.env.PLAYWRIGHT_CHROMIUM;

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: false,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: process.env.SIGYLO_E2E_URL ?? 'http://127.0.0.1:8787',
    locale: 'it-IT',
    permissions: ['clipboard-read', 'clipboard-write'],
    launchOptions: executablePath ? { executablePath } : {},
  },
});

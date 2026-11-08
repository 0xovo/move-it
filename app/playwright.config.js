import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/ui',
  workers: 1,
  use: { baseURL: 'http://127.0.0.1:4178', headless: true, viewport: { width: 520, height: 780 } },
  webServer: { command: 'node prepare.mjs && node tests/server.mjs', url: 'http://127.0.0.1:4178', reuseExistingServer: false }
});

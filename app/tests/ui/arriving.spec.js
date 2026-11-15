import { test, expect } from '@playwright/test';

test('arriving profiles show browser picker on this computer', async ({ page }) => {
  await page.addInitScript(() => {
    window.calls = [];
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name, args) => {
          window.calls.push({ name, args });
          if (name === 'welcome_start') {
            return { device: 'This laptop', browser: 'Brave', paired: true, pipeSet: true, otherDevice: 'Other laptop' };
          }
          if (name === 'home_state') return { lastSync: null, canUndo: false };
          if (name === 'preview_counts') {
            return {
              target: 'Other laptop',
              browsers: [{
                name: 'brave', display: 'Brave', skipped: [],
                profiles: [{
                  id: 'brave:default', name: 'Work', ticked: true, destination: 'brave',
                  cookies: 4, logins: 2, passwords: 1, bookmarks: 0, history: 3, extensions: 0,
                }],
              }],
              arriving: [{
                id: 'brave:profile-1', name: 'Play', fromBrowser: 'brave', fromBrowserDisplay: 'Brave',
                fromDevice: 'Other laptop', destination: 'chrome', routed: true,
              }],
              targets: [
                { name: 'brave', display: 'Brave', available: true },
                { name: 'chrome', display: 'Chrome', available: true },
              ],
              skipped: [],
            };
          }
          if (name === 'browser_open_check') return { status: 'clear' };
          if (name === 'move_start') return { cookies: 1, logins: 1, historyUrls: 1, wroteBox: true, skipped: [], routes: [] };
          if (name === 'engine_idle') return true;
          if (name === 'updater_context') return { packageManaged: false, githubUrl: 'https://example.test' };
          if (name === 'updater_check') return null;
          throw new Error(name);
        },
      },
    };
  });
  await page.goto('/');
  await page.locator('#preview-button').click();
  await expect(page.locator('#arriving-title')).toContainText('Arriving from Other laptop');
  await expect(page.locator('#arriving-profiles select')).toHaveValue('chrome');
  await page.locator('#move').click();
  const call = await page.evaluate(() => window.calls.find(c => c.name === 'move_start'));
  expect(call.args.routes).toContainEqual({ profile: 'brave:profile-1', browser: 'chrome' });
});

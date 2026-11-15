import { test, expect } from '@playwright/test';

test('stale incoming routes are pruned on refresh preview', async ({ page }) => {
  await page.addInitScript(() => {
    window.previewCalls = 0;
    window.calls = [];
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name, args) => {
          window.calls.push({ name, args });
          if (name === 'welcome_start') {
            return { device: 'This laptop', browser: 'Brave', paired: true, pipeSet: true, otherDevice: 'Other' };
          }
          if (name === 'home_state') return { lastSync: null, canUndo: false };
          if (name === 'preview_counts') {
            window.previewCalls += 1;
            const arriving = window.previewCalls <= 2
              ? [{ id: 'brave:profile-1', name: 'Play', fromBrowser: 'brave', fromBrowserDisplay: 'Brave', fromDevice: 'Other', destination: 'chrome', routed: true }]
              : [];
            return {
              target: 'Other',
              browsers: [{
                name: 'brave', display: 'Brave', skipped: [],
                profiles: [{ id: 'brave:default', name: 'Work', ticked: true, destination: 'brave', cookies: 1, logins: 0, passwords: 0, bookmarks: 0, history: 0, extensions: 0 }],
              }],
              arriving,
              targets: [{ name: 'brave', display: 'Brave', available: true }, { name: 'chrome', display: 'Chrome', available: true }],
              skipped: [],
            };
          }
          if (name === 'browser_open_check') return { status: 'clear' };
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
  await expect(page.locator('#arriving-title')).toContainText('Arriving from');
  const mid = await page.evaluate(() => window.calls.filter(c => c.name === 'preview_counts').pop());
  expect(mid.args.routes.length).toBeGreaterThan(0);
  await page.locator('#preview-back').click();
  await page.locator('#preview-button').click();
  const last = await page.evaluate(() => window.calls.filter(c => c.name === 'preview_counts').pop());
  expect(last.args.routes).toEqual([]);
});

test('move passes excluded and routes to browser_open_check', async ({ page }) => {
  await page.addInitScript(() => {
    window.calls = [];
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name, args) => {
          window.calls.push({ name, args });
          if (name === 'welcome_start') {
            return { device: 'This laptop', browser: 'Brave', paired: true, pipeSet: true, otherDevice: 'Other' };
          }
          if (name === 'home_state') return { lastSync: null, canUndo: false };
          if (name === 'preview_counts') {
            return {
              target: 'Other',
              browsers: [{
                name: 'brave', display: 'Brave', skipped: [],
                profiles: [{ id: 'brave:default', name: 'Work', ticked: true, destination: 'brave', cookies: 1, logins: 0, passwords: 0, bookmarks: 0, history: 0, extensions: 0 }],
              }],
              arriving: [],
              targets: [{ name: 'brave', display: 'Brave', available: true }],
              skipped: [],
            };
          }
          if (name === 'browser_open_check') return { status: 'clear' };
          if (name === 'move_start') return { cookies: 0, logins: 0, historyUrls: 0, wroteBox: true, skipped: [], routes: [] };
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
  await page.locator('#move').click();
  const check = await page.evaluate(() => window.calls.find(c => c.name === 'browser_open_check'));
  expect(check.args).toEqual({ excluded: [], routes: [] });
});

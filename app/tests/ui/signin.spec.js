import { test, expect } from '@playwright/test';

async function mock(page) {
  await page.addInitScript(() => {
    window.calls = [];
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name, args) => {
          window.calls.push({ name, args });
          if (name === 'welcome_start') return { device: 'Test', paired: false, pipeSet: false, otherDevice: null };
          if (name === 'home_state') return { lastSync: null, canUndo: false };
          if (name === 'pipe_candidates') {
            return [
              { label: 'Sign in with Google Drive', kind: 'google', path: null, connected: false, cloud: true },
              { label: 'Dropbox (connected)', kind: 'dropbox', path: null, connected: true, cloud: true },
              { label: 'Another folder', kind: 'folder', path: null },
            ];
          }
          if (name === 'pipe_sign_in_begin') return { status: 'waiting', authorizeUrl: 'https://example.test/auth' };
          if (name === 'pipe_sign_in_finish') return { status: 'connected', provider: 'google' };
          if (name === 'use_cloud_pipe') return { kind: 'google', place: '/tmp/staging' };
          if (name === 'pipe_sign_out') return null;
          if (name === 'engine_idle') return true;
          if (name === 'updater_context') return { packageManaged: false, githubUrl: 'https://example.test' };
          if (name === 'updater_check') return null;
          throw new Error(`Unexpected: ${name}`);
        },
      },
    };
  });
}

test('cloud pipe rows sign in and show connected disconnect', async ({ page }) => {
  await mock(page);
  await page.goto('/');
  await page.locator('#start').click();
  await page.locator('#preview-button').click();
  await expect(page.getByRole('radio', { name: /Sign in with Google Drive/ })).toBeVisible();
  await page.getByRole('radio', { name: /Dropbox \(connected\)/ }).click();
  await expect(page.locator('#pipe-disconnect')).toBeVisible();
  await page.getByRole('radio', { name: /Sign in with Google Drive/ }).click();
  await expect(page.locator('#use-pipe')).toContainText('Sign in and use Google Drive');
  await page.locator('#use-pipe').click();
  expect(await page.evaluate(() => window.calls.some(c => c.name === 'pipe_sign_in_begin'))).toBe(true);
  expect(await page.evaluate(() => window.calls.some(c => c.name === 'pipe_sign_in_finish'))).toBe(true);
});

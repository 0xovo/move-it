import { test, expect } from '@playwright/test';

async function mock(page, paired = true) {
  await page.addInitScript(({ paired }) => {
    window.calls = [];
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name, args) => {
          window.calls.push({ name, args });
          const start = { device: 'Test laptop', browser: 'Brave', paired, pipeSet: paired, otherDevice: paired ? 'Other laptop' : null };
          switch (name) {
            case 'welcome_start': return start;
            case 'home_state': return { lastSync: 1794484988, canUndo: false };
            case 'open_external': return null;
            case 'preview_counts':
              return {
                target: 'Other laptop',
                browsers: [{
                  name: 'brave', display: 'Brave', skipped: [],
                  profiles: [{
                    id: 'brave:default', name: 'MX', ticked: true, isNew: true, destination: 'brave',
                    cookies: 10, logins: 4, passwords: 2, bookmarks: 1, history: 8, extensions: 1,
                  }],
                }],
                targets: [], skipped: [],
              };
            case 'browser_open_check': return { status: 'clear' };
            case 'move_start': return { cookies: 10, logins: 2, historyUrls: 8, wroteBox: true, skipped: [], routes: [] };
            case 'engine_idle': return true;
            case 'updater_context': return { packageManaged: false, githubUrl: 'https://github.com/0xovo/move-it/releases/latest' };
            case 'updater_check': return null;
            default: throw new Error(`Unexpected: ${name}`);
          }
        },
      },
    };
  }, { paired });
}

test('welcome shows two movement choices', async ({ page }) => {
  await mock(page, false);
  await page.goto('/');
  await expect(page.getByRole('button', { name: /Move to another computer/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /Move between browsers/ })).toBeVisible();
});

test('move sends optional kinds to the backend', async ({ page }) => {
  await mock(page);
  await page.goto('/');
  await page.locator('#preview-button').click();
  await page.getByRole('button', { name: /Choose what to move for MX/i }).click();
  await page.locator('.profile-kinds-panel').getByText('Saved passwords').click();
  await page.locator('#move').click();
  const call = await page.evaluate(() => window.calls.find(c => c.name === 'move_start'));
  expect(call.args.profileKinds).toEqual({
    'brave:default': ['cookies', 'bookmarks', 'history', 'extensions'],
  });
});

test('sign-in cancel keeps the error notice', async ({ page }) => {
  await page.addInitScript(() => {
    window.calls = [];
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name) => {
          if (name === 'welcome_start') return { device: 'T', paired: false, pipeSet: false, otherDevice: null };
          if (name === 'home_state') return { lastSync: null, canUndo: false };
          if (name === 'pipe_candidates') return [{ label: 'Sign in with Google Drive', kind: 'google', cloud: true, connected: false }];
          if (name === 'pipe_sign_in_begin') return { status: 'waiting' };
          if (name === 'pipe_sign_in_finish') return new Promise((_, rej) => { window.reject = () => rej(new Error('cancelled')); });
          if (name === 'pipe_sign_in_cancel') { window.reject?.(); return null; }
          if (name === 'engine_idle') return true;
          if (name === 'updater_context') return { packageManaged: false, githubUrl: 'https://example.test' };
          if (name === 'updater_check') return null;
          throw new Error(name);
        },
      },
    };
  });
  await page.goto('/');
  await page.locator('#start-cross').click();
  await page.locator('#preview-button').click();
  await page.getByRole('radio', { name: /Google Drive/ }).click();
  await page.locator('#use-pipe').click();
  await page.locator('#pipe-sign-in-cancel').click();
  await expect(page.locator('#error')).toContainText('Sign-in was cancelled.');
});

test('what to move for all sets every profile', async ({ page }) => {
  await mock(page);
  await page.addInitScript(() => {
    const orig = window.__TAURI__.core.invoke;
    window.__TAURI__.core.invoke = async (name, args) => {
      const r = await orig(name, args);
      if (name === 'preview_counts') {
        const p = r.browsers[0].profiles[0];
        r.browsers[0].profiles.push({ ...p, id: 'brave:p2', name: 'Work' });
      }
      return r;
    };
  });
  await page.goto('/');
  await page.locator('#preview-button').click();
  await page.locator('#kinds-all').click();
  await page.locator('#kinds-all-list').getByText('Saved passwords').click();
  await page.locator('#kinds-all-apply').click();
  await expect(page.locator('.profile-kind-summary').first()).toContainText('4 of 5');
  await page.locator('#move').click();
  const call = await page.evaluate(() => window.calls.find(c => c.name === 'move_start'));
  const four = ['cookies', 'bookmarks', 'history', 'extensions'];
  expect(call.args.profileKinds).toEqual({ 'brave:default': four, 'brave:p2': four });
});

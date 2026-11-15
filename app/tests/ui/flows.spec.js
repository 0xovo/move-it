import { test, expect } from '@playwright/test';
import os from 'node:os';
import path from 'node:path';
async function mock(page, paired = false) {
  await page.addInitScript(({ paired }) => {
    window.calls = []; window.listeners = {}; window.paired = paired; window.openBrowser = false;
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async (name, handler) => { window.listeners[name] = handler; return () => {}; } },
      core: { invoke: async (name, args) => {
        window.calls.push({ name, args });
        const start = { device: 'Test laptop', paired: window.paired, pipeSet: window.paired, otherDevice: window.paired ? 'Other laptop' : null };
        switch (name) {
          case 'welcome_start': return start;
          case 'home_state': return { lastSync: null, canUndo: true };
          case 'pipe_candidates': return [{ label: 'Dropbox', kind: 'folder', path: '/scratch/shared' }, { label: 'Another folder', kind: 'folder', path: null }];
          case 'use_pipe': return { kind: 'folder', place: '/scratch/shared/Move It' };
          case 'pair_show_code': return { code: '123 456', thisDevice: 'Test laptop' };
          case 'pair_enter_code': window.paired = true; return { status: 'success', otherDevice: 'Other laptop' };
          case 'preview_counts': return { target: 'Other laptop', browsers: [{ name: 'brave', display: 'Brave', cookies: 4, logins: 4, passwords: 2, bookmarks: 1, history: 8, extensions: 1, skipped: [{ browser: 'Brave', reason: 'Brave uses Windows App-Bound protection on some data' }], profiles: [{ id: 'brave:default', name: 'Personal', ticked: true, destination: 'brave', isNew: true, cookies: 4, logins: 4, passwords: 2, bookmarks: 1, history: 8, extensions: 1 }] }], targets: [{ name: 'chrome', display: 'Google Chrome', available: true }], skipped: [] };
          case 'browser_open_check': case 'local_open_check': return window.openBrowser ? { status: 'blocked', browser: 'Brave' } : { status: 'clear' };
          case 'move_start': case 'local_move': window.listeners['move-progress']?.({ payload: { frac: 0.5, line: 'Moving test data' } }); return { cookies: 4, logins: 2, historyUrls: 8, wroteBox: true, sentProfiles: 2, sentLogins: 2, sentHistoryUrls: 8, sentCookies: 4, skipped: [] };
          case 'undo_last': return { status: args.force ? 'done' : 'changed' };
          case 'local_browsers': return [{ browser: 'brave', display: 'Brave' }, { browser: 'chrome', display: 'Chrome' }];
          case 'local_preview': return { source: 'Brave', target: 'Chrome', logins: 4, passwords: 2, extensions: 1, bookmarks: 1, history: 8, skipped: [] };
          case 'logs_recent': return [{ at_unix: 1, level: 'info', message: '<script>test</script>' }];
          case 'export_logs': return true;
          case 'updater_context': return { packageManaged: false, githubUrl: 'https://github.com/0xovo/move-it/releases/latest' };
          case 'updater_check': return null;
          case 'engine_idle': return true;
          case 'pipe_sign_in_begin': return { status: 'waiting', authorizeUrl: 'https://example.test/auth' };
          case 'pipe_sign_in_finish': return { status: 'connected', provider: 'google' };
          case 'use_cloud_pipe': return { kind: 'google', place: '/tmp/staging' };
          case 'pipe_sign_out': return null;
          case 'pipe_install_byok': return { status: 'installed' };
          default: throw new Error(`Unexpected command: ${name}`);
        }
      } }
    };
  }, { paired });
}
test('welcome, home and version use the native contract', async ({ page }) => {
  await mock(page); await page.goto('/');
  await page.getByRole('button', { name: 'Move to another computer' }).click();
  await expect(page.locator('#home')).toBeVisible(); await expect(page.locator('#home [data-version]')).toHaveText('Move It v0.1.0');
  await page.getByRole('button', { name: 'About', exact: true }).click();
  await expect(page.locator('#about [data-version]')).toHaveText('Move It v0.1.0');
  await page.screenshot({ path: 'test-results/about.png' });
});
test('folder, pairing, preview and move show actual reports and skips', async ({ page }) => {
  await mock(page); await page.goto('/'); await page.locator('#start-cross').click(); await page.locator('#preview-button').click();
  await page.locator('#pipe-more summary').click();
  await page.getByRole('radio', { name: /Dropbox/ }).click(); await page.locator('#use-pipe').click();
  await expect(page.locator('#pair-code')).toHaveText('123 456'); await page.locator('#have-code').click();
  await page.locator('#code-input').fill('123456'); await page.getByRole('button', { name: 'Pair devices' }).click();
  await expect(page.locator('#profiles')).toContainText('Personal');
  await expect(page.locator('#profiles .profile-dest')).toHaveCount(0);
  await expect(page.locator('#skipped')).not.toContainText(/App-Bound/i);
  await page.getByRole('button', { name: /Choose what to move for Personal/i }).click();
  await expect(page.locator('.profile-kinds-panel')).toContainText('Saved passwords');
  await page.screenshot({ path: path.join(os.homedir(), 'moveit', 'notes', 'preview-after.png') });
  await page.screenshot({ path: 'test-results/preview.png' });
  await page.locator('#move').click(); await expect(page.locator('#done')).toBeVisible();
  await expect(page.locator('#done-title')).toHaveText('Sent');
  await expect(page.locator('#report')).toContainText('Sent 2 profiles');
});
test('open browser blocks a move and retry checks again', async ({ page }) => {
  await mock(page, true); await page.goto('/'); await page.locator('#preview-button').click();
  await page.evaluate(() => { window.openBrowser = true; }); await page.locator('#move').click();
  await expect(page.locator('#blocked')).toBeVisible(); expect(await page.evaluate(() => window.calls.some(c => c.name === 'move_start'))).toBe(false);
  await page.evaluate(() => { window.openBrowser = false; }); await page.locator('#retry').click(); await expect(page.locator('#done')).toBeVisible();
});
test('never-launched engine error opens the blocked screen', async ({ page }) => {
  await mock(page, true); await page.goto('/'); await page.locator('#home [data-nav="local"]').click();
  await page.evaluate(() => {
    const prev = window.__TAURI__.core.invoke;
    window.__TAURI__.core.invoke = async (name, args) => {
      if (name === 'local_preview') throw new Error('Open Brave once, then come back');
      return prev(name, args);
    };
  });
  await page.locator('#local-preview').click();
  await expect(page.locator('#blocked')).toBeVisible();
  await expect(page.locator('#blocked-title')).toHaveText('Open Brave once, then come back');
  await expect(page.locator('#blocked-sub')).toContainText('has not been opened');
});
test('same-device move and safe log rendering', async ({ page }) => {
  await mock(page, true); await page.goto('/'); await page.locator('#home [data-nav="local"]').click();
  await page.locator('#local-preview').click(); await expect(page.locator('#profiles')).toContainText('Brave');
  await page.locator('#move').click(); await page.locator('#done-button').click(); await page.locator('#home [data-nav="logs"]').click();
  await expect(page.locator('#log-lines')).toContainText('<script>test</script>'); await expect(page.locator('#log-lines script')).toHaveCount(0);
});
test('changed browser data requires explicit undo confirmation', async ({ page }) => {
  await mock(page, true); await page.goto('/'); await page.locator('#undo').click(); await expect(page.locator('#undo-confirm')).toBeVisible();
  expect(await page.evaluate(() => window.calls.filter(c => c.name === 'undo_last').every(c => !c.args.force))).toBe(true);
  await page.locator('#force-undo').click(); await expect(page.locator('#status')).toContainText('Back to how it was');
});

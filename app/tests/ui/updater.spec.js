import { test, expect } from '@playwright/test';

async function mock(page, { packageManaged = false, engineIdle = true } = {}) {
  await page.addInitScript(({ packageManaged, engineIdle }) => {
    window.engineIdle = engineIdle;
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: {
        listen: async (name, handler) => {
          if (name === 'update-available') window.emitUpdate = version => handler({ payload: version });
          return () => {};
        },
      },
      core: {
        invoke: async (name, args) => {
          switch (name) {
            case 'welcome_start':
              return { device: 'Test laptop', paired: true, pipeSet: true, otherDevice: 'Other laptop' };
            case 'home_state':
              return { lastSync: null, canUndo: false };
            case 'updater_context':
              return { packageManaged, githubUrl: 'https://github.com/0xovo/move-it/releases/latest' };
            case 'updater_check':
              return null;
            case 'engine_idle':
              return window.engineIdle;
            case 'open_release_page':
              window.openedRelease = args.url;
              return null;
            case 'updater_install':
              window.installCalls = (window.installCalls || 0) + 1;
              return null;
            default:
              throw new Error(`Unexpected command: ${name}`);
          }
        },
      },
    };
  }, { packageManaged, engineIdle });
}

test('update notice appears on home with update now', async ({ page }) => {
  await mock(page);
  await page.goto('/');
  await expect(page.locator('#home')).toBeVisible();
  await page.evaluate(() => window.emitUpdate('1.2.0'));
  await expect(page.locator('#update-notice')).toBeVisible();
  await expect(page.locator('#update-notice-text')).toHaveText('Move It 1.2.0 is ready');
  await expect(page.locator('#update-now')).toHaveText('Update now');
});

test('update notice hides during a move and package installs link out', async ({ page }) => {
  await mock(page, { packageManaged: true });
  await page.goto('/');
  await page.evaluate(() => window.emitUpdate('1.2.0'));
  await expect(page.locator('#update-notice')).toBeVisible();
  await page.evaluate(() => {
    for (const section of document.querySelectorAll('main > .state')) section.hidden = section.id !== 'moving';
  });
  await expect(page.locator('#update-notice')).toBeHidden();
  for (const section of await page.locator('main > .state').all()) {
    if (await section.getAttribute('id') === 'home') await section.evaluate(el => { el.hidden = false; });
    else await section.evaluate(el => { el.hidden = true; });
  }
  await expect(page.locator('#update-notice')).toBeVisible();
  await expect(page.locator('#update-now')).toHaveText('Get it on GitHub');
  await page.locator('#update-now').click();
  expect(await page.evaluate(() => window.openedRelease)).toContain('github.com/0xovo/move-it/releases');
});

test('update now calls updater_install once on unmanaged installs', async ({ page }) => {
  await mock(page);
  await page.goto('/');
  await page.evaluate(() => window.emitUpdate('1.2.0'));
  await expect(page.locator('#update-notice')).toBeVisible();
  await page.locator('#update-now').click();
  expect(await page.evaluate(() => window.installCalls)).toBe(1);
});

test('boot shows welcome before a stalled update check finishes', async ({ page }) => {
  await page.addInitScript(() => {
    let resolveCheck;
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name) => {
          if (name === 'updater_context') {
            return { packageManaged: false, githubUrl: 'https://github.com/0xovo/move-it/releases/latest' };
          }
          if (name === 'updater_check') {
            return new Promise(resolve => { resolveCheck = () => resolve('9.9.9'); });
          }
          if (name === 'welcome_start') {
            return { device: 'Test laptop', paired: false, pipeSet: false };
          }
          if (name === 'engine_idle') return true;
          throw new Error(`Unexpected command: ${name}`);
        },
      },
    };
    window.finishUpdateCheck = () => resolveCheck?.();
  });
  await page.goto('/');
  await expect(page.locator('#welcome')).toBeVisible();
  await expect(page.locator('main')).not.toHaveAttribute('aria-busy', 'true');
  await page.evaluate(() => window.finishUpdateCheck());
  await expect(page.locator('#update-notice')).toBeVisible();
});

test('later dismisses the waiting version for this session', async ({ page }) => {
  await mock(page);
  await page.goto('/');
  await page.evaluate(() => window.emitUpdate('1.2.0'));
  await page.locator('#update-later').click();
  await expect(page.locator('#update-notice')).toBeHidden();
});

import { test, expect } from '@playwright/test';

async function pairedPreview(page, preview, startExtra = {}) {
  await page.addInitScript(({ preview, startExtra }) => {
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name, args) => {
          if (name === 'welcome_start') {
            return {
              device: 'Test laptop',
              paired: true,
              pipeSet: true,
              pipeKind: 'dropbox',
              otherDevice: 'Other laptop',
              ...startExtra,
            };
          }
          if (name === 'home_state') return { lastSync: null, canUndo: false };
          if (name === 'preview_counts') return preview;
          if (name === 'browser_open_check') return { status: 'clear' };
          if (name === 'engine_idle') return true;
          if (name === 'updater_context') return { packageManaged: false, githubUrl: 'https://example.test' };
          if (name === 'updater_check') return null;
          throw new Error(name);
        },
      },
    };
  }, { preview, startExtra });
  await page.goto('/');
  await page.locator('#preview-button').click();
}

test('profile expand opens per-profile what-to-move list', async ({ page }) => {
  await pairedPreview(page, {
    target: 'Other laptop',
    browsers: [{
      name: 'brave', display: 'Brave', skipped: [],
      profiles: [
        { id: 'brave:p1', name: '0xovo', ticked: true, destination: 'brave', cookies: 1, logins: 1, passwords: 0, bookmarks: 0, history: 0, extensions: 0 },
      ],
    }],
    targets: [], skipped: [],
  });
  const expand = page.getByRole('button', { name: /Choose what to move for 0xovo/i });
  await expect(expand).toHaveAttribute('aria-expanded', 'false');
  expect(await expand.evaluate(el => el.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);
  await expand.click();
  await expect(expand).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('.profile-kinds-panel')).toContainText('Saved passwords');
  await expect(page.locator('.profile-kind-summary')).toHaveText('All data');
});

test('profile rows stack name and destination with tick boxes', async ({ page }) => {
  await pairedPreview(page, {
    target: 'Other laptop',
    browsers: [{
      name: 'brave', display: 'Brave', skipped: [],
      profiles: [
        { id: 'brave:p1', name: '0xovo', ticked: true, destination: 'brave', cookies: 1, logins: 1, passwords: 0, bookmarks: 0, history: 0, extensions: 0 },
      ],
    }],
    targets: [], skipped: [],
  });
  const row = page.locator('.profile-row').first();
  await expect(row.locator('input[type=checkbox]')).toBeVisible();
  await expect(row.locator('.profile-title')).toHaveText('0xovo');
  await expect(row.locator('.profile-dest')).toHaveCount(0);
  expect(await row.evaluate(el => el.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);
});

test('needs attention uses plain language without App-Bound', async ({ page }) => {
  await pairedPreview(page, {
    target: 'Other laptop',
    browsers: [{
      name: 'brave', display: 'Brave',
      skipped: [{ browser: 'Brave', reason: '14 App-Bound cookies' }],
      profiles: [{ id: 'brave:d', name: 'MX', ticked: true, destination: 'brave', cookies: 1, logins: 1, passwords: 0, bookmarks: 0, history: 0, extensions: 0 }],
    }],
    targets: [], skipped: [],
  });
  const box = page.locator('#skipped');
  await expect(box).toContainText(/stay on this device/);
  await expect(box).not.toContainText(/App-Bound/i);
});

test('empty preview hides sections and move button', async ({ page }) => {
  await pairedPreview(page, { target: 'Other laptop', browsers: [], targets: [], skipped: [] });
  await expect(page.locator('#preview-empty')).toBeVisible();
  await expect(page.locator('#preview-profiles-title')).toBeHidden();
  await expect(page.locator('#move')).toBeHidden();
  await expect(page.locator('#preview-back')).toBeVisible();
});

test('about links show icons with labels', async ({ page }) => {
  await page.addInitScript(() => {
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name) => {
          if (name === 'welcome_start') return { device: 'T', paired: false, pipeSet: false, otherDevice: null };
          if (name === 'engine_idle') return true;
          if (name === 'updater_context') return { packageManaged: false, githubUrl: 'https://example.test' };
          if (name === 'updater_check') return null;
          throw new Error(name);
        },
      },
    };
  });
  await page.goto('/');
  await page.locator('#about-link').click();
  for (const label of ['GitHub', 'X', 'Ko-fi', 'Website']) {
    const btn = page.getByRole('button', { name: label });
    await expect(btn).toBeVisible();
    await expect(btn.locator('svg')).toBeVisible();
    await expect(btn.locator('.about-link-label')).toHaveText(label);
  }
});

test('welcome primary description has readable contrast', async ({ page }) => {
  await page.goto('/');
  const sub = page.locator('#start-cross .choice-sub');
  const contrast = await sub.evaluate(el => {
    const s = getComputedStyle(el);
    const parse = c => {
      const m = c.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
      return m ? [+m[1], +m[2], +m[3]].map(v => v / 255) : [0, 0, 0];
    };
    const lum = ([r, g, b]) => {
      const f = x => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4);
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    const fg = lum(parse(s.color));
    const bg = lum(parse(getComputedStyle(el.closest('.btn-primary')).backgroundColor));
    const hi = Math.max(fg, bg);
    const lo = Math.min(fg, bg);
    return (hi + 0.05) / (lo + 0.05);
  });
  expect(contrast).toBeGreaterThanOrEqual(4.5);
});

test('pairing subtitle names configured storage', async ({ page }) => {
  await page.addInitScript(() => {
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name) => {
          if (name === 'welcome_start') return { device: 'T', paired: false, pipeSet: true, pipeKind: 'dropbox', otherDevice: null };
          if (name === 'home_state') return { lastSync: null, canUndo: false };
          if (name === 'pair_show_code') return { code: '111 222' };
          if (name === 'engine_idle') return true;
          if (name === 'updater_context') return { packageManaged: false, githubUrl: 'https://example.test' };
          if (name === 'updater_check') return null;
          throw new Error(name);
        },
      },
    };
  });
  await page.goto('/');
  await page.locator('#pair-button').click();
  await expect(page.locator('#pair-sub')).toHaveText('Both computers must use Dropbox.');
});

test('storage other options row is at least 44px tall', async ({ page }) => {
  await page.addInitScript(() => {
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async () => () => {} },
      core: {
        invoke: async (name) => {
          if (name === 'welcome_start') return { device: 'T', paired: false, pipeSet: false, otherDevice: null };
          if (name === 'home_state') return { lastSync: null, canUndo: false };
          if (name === 'pipe_candidates') return [{ label: 'Sign in with Dropbox', kind: 'dropbox', cloud: true, connected: false }];
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
  const h = await page.locator('#pipe-more summary').evaluate(el => el.getBoundingClientRect().height);
  expect(h).toBeGreaterThanOrEqual(44);
});

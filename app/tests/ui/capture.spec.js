// Throwaway: walks every screen/state of the Move It UI with a mocked Tauri bridge
// and saves full-page PNGs. Window size from tauri.conf.json: 520x780.
import { test } from '@playwright/test';
import os from 'node:os';
import path from 'node:path';

const OUT = path.join(os.homedir(), 'moveit', 'notes', 'ux-after');
test.use({ viewport: { width: 520, height: 780 } });
test.setTimeout(1_500_000);

let n = 0;
const failures = [];
async function shot(page, name) {
  await page.waitForTimeout(900); // let the lemur loader draw
  n += 1; const t0 = Date.now();
  await page.screenshot({ path: `${OUT}/${String(n).padStart(2, '0')}-${name}.png`, fullPage: true });
  console.log('shot', n, name, Date.now() - t0, 'ms');
}

// ---------- realistic data ----------
const prof = (id, name, cookies, logins, passwords, extensions, bookmarks, history, extra = {}) =>
  ({ id: `brave:${id}`, name, ticked: true, destination: 'brave', cookies, logins, passwords, extensions, bookmarks, history, ...extra });
const PROFILES = [
  prof('default', 'MX', 603, 412, 86, 11, 238, 9421),
  prof('profile1', '0xovo', 1214, 1206, 143, 19, 512, 31870),
  prof('profile2', 'dsd', 87, 64, 9, 3, 41, 1288),
  prof('profile3', 'ss', 31, 23, 2, 0, 7, 204),
];
const TARGETS = [
  { name: 'brave', display: 'Brave', available: true },
  { name: 'chrome', display: 'Chrome', available: true },
  { name: 'vivaldi', display: 'Vivaldi', available: true },
  { name: 'edge', display: 'Edge', available: false, reason: 'not set up on this device' },
];
const brave = (over = {}) => ({ name: 'brave', display: 'Brave', skipped: [], profiles: PROFILES, ...over });
const PREVIEW = {
  normal: { target: 'Other laptop', browsers: [brave({ skipped: [{ browser: 'Brave', reason: '14 App-Bound cookies' }] })], targets: [], skipped: [] },
  single: { target: 'Other laptop', browsers: [brave({ profiles: PROFILES.map(p => p.name === 'ss' ? { ...p, destination: 'chrome' } : p) })], targets: [TARGETS[0], TARGETS[1]], skipped: [] },
  routes: { target: 'Other laptop', browsers: [brave({ profiles: PROFILES.map(p => p.name === 'ss' ? { ...p, destination: 'chrome' } : p) })], targets: TARGETS, skipped: [] },
  arriving: {
    target: 'Other laptop',
    browsers: [brave({ profiles: [PROFILES[0]] })],
    arriving: [{
      id: 'brave:profile-1', name: '0xovo', fromBrowser: 'brave', fromBrowserDisplay: 'Brave',
      fromDevice: 'Other laptop', destination: 'chrome', routed: true,
    }],
    targets: TARGETS, skipped: [],
  },
  newProfile: { target: 'Other laptop', browsers: [brave({ profiles: PROFILES.map(p => p.name === 'ss' ? { ...p, isNew: true } : p) })], targets: [], skipped: [] },
  errors: {
    target: 'Other laptop',
    browsers: [
      brave({ skipped: [{ browser: 'Brave', reason: '14 App-Bound cookies' }, { browser: 'Brave', reason: 'Payment methods are encrypted to this device' }] }),
      { name: 'chrome', display: 'Chrome', skipped: [{ browser: 'Chrome', reason: '3 profiles are locked by a managed policy' }], profiles: [prof('default', 'Personal', 340, 188, 31, 6, 97, 4410, { id: 'chrome:default', destination: 'chrome' })] },
    ],
    targets: [],
    skipped: [{ browser: '', reason: 'Safari data is not supported yet' }, { browser: '', reason: 'The sealed box is 2 days old; run Move It on the other device first' }],
  },
  empty: { target: 'Other laptop', browsers: [], targets: [], skipped: [] },
};
const REPORT_CLEAN = { cookies: 1935, logins: 240, historyUrls: 42783, wroteBox: true, skipped: [] };
const REPORT_SKIPS = {
  cookies: 1921, logins: 238, historyUrls: 42783, wroteBox: true, boxesSkipped: 1, lockedCookies: 14,
  skipped: [{ browser: 'Brave', reason: 'Payment methods are encrypted to this device' }],
};
const REPORT_ROUTES = {
  cookies: 1935, logins: 240, historyUrls: 42783, wroteBox: false, skipped: [],
  routes: [
    { profile: 'MX', status: 'moved', toBrowser: 'Chrome', intoProfile: 'Person 1' },
    { profile: 'ss', status: 'failed', reason: 'Chrome is open; close it completely and try again' },
  ],
};
const LOGS = [
  { at_unix: 1794484800, level: 'info', message: 'Move It v0.1.0 started' },
  { at_unix: 1794484812, level: 'info', message: 'Pipe set: Dropbox/Move It' },
  { at_unix: 1794484860, level: 'info', message: 'Paired with Other laptop' },
  { at_unix: 1794484921, level: 'info', message: 'Preview: 4 Brave profiles, 1,705 cookies, 240 passwords' },
  { at_unix: 1794484950, level: 'warn', message: '14 App-Bound cookies could not be read' },
  { at_unix: 1794484988, level: 'info', message: 'Move finished, sealed box written (3.2 MB)' },
  { at_unix: 1794485100, level: 'error', message: 'Dropbox: 429 too many requests, retrying in 5s' },
];
const CHROME_BRAVE = [{ browser: 'brave', display: 'Brave' }, { browser: 'chrome', display: 'Chrome' }];

// ---------- mock bridge ----------
async function mock(page, over = {}) {
  const cfg = {
    start: { device: 'MX-Fedora', paired: false, pipeSet: false, otherDevice: null },
    home: { lastSync: null, canUndo: false },
    cand: { found: true, google: false, dropbox: false, byok: false },
    signIn: 'connected', signInBegin: { status: 'waiting', attempt: 1, authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=moveit&scope=drive.appdata', opened: true },
    preview: PREVIEW.normal, report: REPORT_CLEAN, moveHang: false,
    pairCode: '482 913', pairEnter: { status: 'success', otherDevice: 'Other laptop' },
    undoStatus: 'done', open: 'clear', openBrowser: 'Brave',
    update: null, packageManaged: false, idle: true,
    localBrowsers: CHROME_BRAVE,
    localPreview: { source: 'Brave', target: 'Chrome', cookies: 1935, logins: 1705, passwords: 240, extensions: 39, bookmarks: 798, history: 42783, skipped: [{ browser: 'Brave', reason: '14 App-Bound cookies' }] },
    logs: LOGS, errors: {},
    ...over,
  };
  await page.addInitScript((cfg) => {
    window.cfg = cfg; window.calls = []; window.listeners = {};
    const candidates = () => {
      const c = window.cfg.cand, list = [];
      if (c.found) list.push({ label: 'Dropbox', kind: 'folder', path: '/home/user/Dropbox' }, { label: 'Google Drive', kind: 'folder', path: '/home/user/Google Drive' });
      list.push(
        { label: c.google ? 'Google Drive (connected)' : 'Sign in with Google Drive', kind: 'google', path: null, connected: c.google, cloud: true, byok: c.byok },
        { label: c.dropbox ? 'Dropbox (connected)' : 'Sign in with Dropbox', kind: 'dropbox', path: null, connected: c.dropbox, cloud: true, byok: c.byok },
        { label: 'Git repository', kind: 'git', path: null }, { label: 'Another folder', kind: 'folder', path: null },
        { label: 'Advanced', kind: 'group', path: null },
        { label: c.byok ? 'Use my own app keys (configured)' : 'Use my own app keys', kind: 'byok', path: null, connected: c.byok, cloud: true });
      return list;
    };
    window.__TAURI__ = {
      app: { getVersion: async () => '0.1.0' },
      event: { listen: async (name, handler) => { window.listeners[name] = handler; return () => {}; } },
      core: { invoke: async (name, args) => {
        window.calls.push({ name, args });
        const c = window.cfg;
        if (c.errors[name]) throw new Error(c.errors[name]);
        switch (name) {
          case 'welcome_start': return c.start;
          case 'home_state': return c.home;
          case 'pipe_candidates': return candidates();
          case 'pick_folder': return c.picked || '/home/user/code/move-it-box';
          case 'use_pipe': return { kind: c.useKind || args.expectedKind, place: `${args.path}/Move It` };
          case 'use_cloud_pipe': return { kind: args.provider, place: '/tmp/staging' };
          case 'pipe_install_byok': c.cand.byok = true; return { status: 'installed' };
          case 'pipe_sign_out': c.cand.google = false; c.cand.dropbox = false; return null;
          case 'pipe_sign_in_begin': return c.signInBegin;
          case 'pipe_sign_in_finish':
            if (c.signIn === 'hang') return new Promise((_, rej) => { window.rejectSignIn = () => rej(new Error('sign-in was cancelled')); });
            c.cand[args && args.provider || 'google'] = true; return { status: 'connected', provider: 'google', attempt: 1 };
          case 'pipe_sign_in_cancel': window.rejectSignIn?.(); return null;
          case 'pipe_sign_in_discard': return { status: 'discarded' };
          case 'pair_show_code': return { code: c.pairCode, thisDevice: c.start.device };
          case 'pair_enter_code': if (c.pairEnter.status === 'success') { c.start = { ...c.start, paired: true, otherDevice: c.pairEnter.otherDevice }; } return c.pairEnter;
          case 'preview_counts': return c.preview;
          case 'browser_open_check': case 'local_open_check': return c.open === 'blocked' ? { status: 'blocked', browser: c.openBrowser } : { status: 'clear' };
          case 'move_start': case 'local_move':
            window.listeners['move-progress']?.({ payload: { frac: 0.18, line: 'Reading your Brave profiles' } });
            if (c.moveHang) return new Promise((res) => { window.finishMove = () => res(c.report); });
            return c.report;
          case 'undo_last': return { status: args.force ? 'done' : c.undoStatus };
          case 'local_browsers': return c.localBrowsers;
          case 'local_preview': return c.localPreview;
          case 'logs_recent': return c.logs;
          case 'export_logs': return true;
          case 'updater_context': return { packageManaged: c.packageManaged, githubUrl: 'https://github.com/0xovo/move-it/releases/latest' };
          case 'updater_check': return c.update;
          case 'engine_idle': return c.idle;
          case 'updater_install': case 'open_release_page': return null;
          default: throw new Error(`Unexpected command: ${name}`);
        }
      } },
    };
  }, cfg);
}
const open = async (page, over) => { await mock(page, over); await page.goto('/'); await page.waitForTimeout(300); };
const setCfg = (page, fn) => page.evaluate(fn);
const PAIRED = { device: 'MX-Fedora', paired: true, pipeSet: true, otherDevice: 'Other laptop' };
const PIPE_ONLY = { device: 'MX-Fedora', paired: false, pipeSet: true, otherDevice: null };
const radio = (page, re) => page.getByRole('radio', { name: re });
const pickPipe = async (page, re, { other = false } = {}) => {
  if (other) await page.locator('#pipe-more').evaluate(el => { el.open = true; });
  await radio(page, re).click();
};

async function scene(name, fn) {
  try { await fn(); } catch (e) { failures.push(`${name}: ${String(e).split('\n')[0]}`); console.log('FAILED', name, e); }
}

test('capture every screen', async ({ page }) => {
  page.setDefaultTimeout(6000);
  // ===== Boot / welcome =====
  await scene('welcome', async () => { await open(page); await shot(page, 'welcome'); });

  // outside the desktop app (no window.__TAURI__): done in its own fresh page below
  const ctx = page.context();
  await scene('outside-app', async () => {
    const p = await ctx.newPage(); await p.goto('/'); await shot(p, 'outside-desktop-app-disabled'); await p.close();
  });
  await scene('boot-error', async () => {
    await open(page, { errors: { welcome_start: 'could not read the Move It settings file' } }); await shot(page, 'boot-error-blank');
  });

  // ===== Home variants =====
  await scene('home-fresh', async () => { await open(page); await page.locator('#start-cross').click(); await shot(page, 'home-fresh-no-moves'); });
  await scene('home-pipe-only', async () => { await open(page, { start: PIPE_ONLY }); await shot(page, 'home-folder-set-not-paired'); });
  await scene('home-paired', async () => { await open(page, { start: PAIRED }); await shot(page, 'home-paired-no-moves'); });
  await scene('home-last-sync', async () => { await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: false } }); await shot(page, 'home-paired-last-sync'); });
  await scene('home-undo', async () => { await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: true } }); await shot(page, 'home-can-undo'); });
  await scene('update', async () => { await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: true }, update: '0.2.0' }); await page.waitForTimeout(400); await shot(page, 'home-update-notice'); });
  await scene('update-pm', async () => { await open(page, { start: PAIRED, update: '0.2.0', packageManaged: true }); await page.waitForTimeout(400); await shot(page, 'home-update-notice-package-managed'); });
  await scene('update-welcome', async () => { await open(page, { update: '0.2.0' }); await page.waitForTimeout(400); await shot(page, 'welcome-update-notice'); });
  await scene('update-installing', async () => {
    await open(page, { start: PAIRED, update: '0.2.0' }); await page.waitForTimeout(400);
    await page.locator('#update-now').click(); await shot(page, 'home-update-installing-notice');
  });
  await scene('update-later', async () => {
    await open(page, { start: PAIRED, update: '0.2.0' }); await page.waitForTimeout(400);
    await page.locator('#update-later').click(); await shot(page, 'home-update-dismissed-later');
  });
  await scene('about', async () => { await open(page, { start: PAIRED }); await page.locator('#about-link').click(); await shot(page, 'about'); });

  // ===== Pipe picker =====
  const toPipe = async (over = {}) => { await open(page, { start: { device: 'MX-Fedora', paired: false, pipeSet: false, otherDevice: null }, ...over }); await page.locator('#start-cross').click(); await page.locator('#preview-button').click(); };
  await scene('pipe-initial', async () => { await toPipe(); await shot(page, 'pipe-picker-nothing-selected'); });
  await scene('pipe-nofolders', async () => { await toPipe({ cand: { found: false, google: false, dropbox: false, byok: false } }); await shot(page, 'pipe-picker-no-folders-found'); });
  await scene('pipe-folder', async () => { await toPipe(); await pickPipe(page, /^Dropbox/, { other: true }); await shot(page, 'pipe-folder-selected'); });
  await scene('pipe-another', async () => { await toPipe(); await pickPipe(page, /Another folder/, { other: true }); await shot(page, 'pipe-another-folder-selected'); });
  await scene('pipe-git', async () => { await toPipe(); await pickPipe(page, /Git repository/, { other: true }); await shot(page, 'pipe-git-selected'); });
  await scene('pipe-git-notclone', async () => {
    await toPipe({ useKind: 'folder' }); await pickPipe(page, /Git repository/, { other: true }); await page.locator('#use-pipe').click(); await shot(page, 'pipe-git-not-a-clone-error');
  });
  await scene('pipe-use-error', async () => {
    await toPipe({ errors: { use_pipe: 'Move It cannot write to /home/user/Dropbox (read-only folder)' } });
    await pickPipe(page, /^Dropbox/, { other: true }); await page.locator('#use-pipe').click(); await shot(page, 'pipe-use-folder-error');
  });
  await scene('pipe-google', async () => { await toPipe(); await radio(page, /Sign in with Google Drive/).click(); await shot(page, 'pipe-google-selected-needs-sign-in'); });
  await scene('pipe-dropbox', async () => { await toPipe(); await radio(page, /Sign in with Dropbox/).click(); await shot(page, 'pipe-dropbox-selected-needs-sign-in'); });
  await scene('pipe-connected', async () => {
    await toPipe({ cand: { found: true, google: false, dropbox: true, byok: false } }); await radio(page, /Dropbox \(connected\)/).click(); await shot(page, 'pipe-dropbox-connected-selected-disconnect');
  });
  await scene('pipe-both-connected', async () => {
    await toPipe({ cand: { found: true, google: true, dropbox: true, byok: false } }); await shot(page, 'pipe-picker-both-clouds-connected');
  });
  await scene('pipe-disconnect', async () => {
    await toPipe({ cand: { found: true, google: false, dropbox: true, byok: false } }); await radio(page, /Dropbox \(connected\)/).click();
    await page.locator('#pipe-disconnect').click(); await shot(page, 'pipe-disconnected-notice');
  });
  await scene('pipe-signin-waiting-link', async () => {
    await toPipe({ signIn: 'hang', signInBegin: { status: 'waiting', attempt: 1, authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=moveit&scope=drive.appdata', opened: false } });
    await radio(page, /Sign in with Google Drive/).click(); await page.locator('#use-pipe').click(); await page.locator('#pipe-sign-in-link').waitFor();
    await shot(page, 'pipe-signin-waiting-browser-did-not-open');
  });
  await scene('pipe-signin-waiting-copied', async () => {
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.locator('#pipe-sign-in-copy').click(); await shot(page, 'pipe-signin-waiting-link-copied');
  });
  await scene('pipe-signin-cancelled', async () => {
    await page.locator('#pipe-sign-in-cancel').click(); await page.locator('#pipe-sign-in-cancel').waitFor({ state: 'hidden' });
    // NOTE: app sets the 'Sign-in was cancelled.' error and then calls pipes() whose show() clears it, so no notice is visible.
    await shot(page, 'pipe-after-signin-cancel-no-notice');
  });
  await scene('pipe-signin-waiting-opened', async () => {
    await toPipe({ signIn: 'hang' }); // link visible, browser opened
    await radio(page, /Sign in with Dropbox/).click(); await page.locator('#use-pipe').click(); await page.locator('#pipe-sign-in-link').waitFor();
    await shot(page, 'pipe-signin-waiting-browser-opened');
  });
  await scene('pipe-signin-nolink', async () => {
    await toPipe({ signIn: 'hang', signInBegin: { status: 'waiting', attempt: 1 } });
    await radio(page, /Sign in with Google Drive/).click(); await page.locator('#use-pipe').click(); await page.locator('#pipe-sign-in-cancel').waitFor();
    await shot(page, 'pipe-signin-waiting-no-link');
  });
  await scene('pipe-signin-error', async () => {
    await toPipe({ errors: { pipe_sign_in_begin: 'could not open the sign-in listener on 127.0.0.1 (port busy)' } });
    await radio(page, /Sign in with Google Drive/).click(); await page.locator('#use-pipe').click(); await shot(page, 'pipe-signin-error');
  });
  await scene('pipe-cloud-error', async () => {
    await toPipe({ cand: { found: true, google: true, dropbox: false, byok: false }, errors: { use_cloud_pipe: 'Google Drive refused the request: storage quota exceeded' } });
    await radio(page, /Google Drive \(connected\)/).click(); await page.locator('#use-pipe').click(); await shot(page, 'pipe-connect-cloud-error');
  });
  await scene('pipe-signin-ok-to-pair', async () => {
    // after signing in the flow continues to the preview/pair step
    await toPipe(); await radio(page, /Sign in with Google Drive/).click(); await page.locator('#use-pipe').click();
    await page.locator('#pair-code').waitFor({ timeout: 5000 }); await shot(page, 'pair-after-google-sign-in-show-code');
  });
  await scene('pipe-byok', async () => {
    await toPipe(); await shot(page, 'pipe-byok-not-configured-listed');
    await pickPipe(page, /Use my own app keys/, { other: true }); await shot(page, 'pipe-byok-configured-after-install');
  });
  await scene('pipe-byok-error', async () => {
    await toPipe({ errors: { pipe_install_byok: 'The keys file is missing client_id' } });
    await pickPipe(page, /Use my own app keys/, { other: true }); await shot(page, 'pipe-byok-install-error');
  });
  await scene('pipe-byok-google', async () => {
    await toPipe({ cand: { found: false, google: false, dropbox: false, byok: true } }); await radio(page, /Sign in with Google Drive/).click(); await shot(page, 'pipe-byok-keys-google-selected');
  });
  await scene('pipe-from-home', async () => {
    await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: true }, cand: { found: true, google: false, dropbox: true, byok: false } });
    await page.locator('#home [data-nav="pipe"]').click(); await shot(page, 'pipe-change-folder-from-home');
  });
  await scene('pipe-home-link-cancel', async () => {
    await toPipe({ signIn: 'hang' }); await radio(page, /Sign in with Google Drive/).click(); await page.locator('#use-pipe').click();
    await page.locator('#pipe-sign-in-cancel').waitFor(); await page.locator('#home-link').click(); await page.locator('#home').waitFor(); await shot(page, 'home-after-cancel-via-wordmark');
  });

  // ===== Pairing =====
  await scene('pair-show', async () => { await open(page, { start: PIPE_ONLY }); await page.locator('#pair-button').click(); await shot(page, 'pair-show-code'); });
  await scene('pair-waiting', async () => { await page.locator('#check-pair').click(); await shot(page, 'pair-show-code-waiting-notice'); });
  await scene('pair-enter', async () => { await page.locator('#have-code').click(); await shot(page, 'pair-enter-code-empty'); });
  await scene('pair-typed', async () => { await page.locator('#code-input').fill('482913'); await shot(page, 'pair-enter-code-typed'); });
  await scene('pair-wrong', async () => {
    await setCfg(page, () => { window.cfg.pairEnter = { status: 'wrong', triesLeft: 2 }; });
    await page.locator('#code-input').fill('111222'); await page.getByRole('button', { name: 'Pair devices' }).click(); await shot(page, 'pair-error-wrong-code');
  });
  await scene('pair-newcode', async () => {
    await setCfg(page, () => { window.cfg.pairEnter = { status: 'need_new_code' }; });
    await page.locator('#code-input').fill('111222'); await page.getByRole('button', { name: 'Pair devices' }).click(); await shot(page, 'pair-error-need-new-code');
  });
  await scene('pair-nooffer', async () => {
    await setCfg(page, () => { window.cfg.pairEnter = { status: 'no_offer' }; });
    await page.locator('#code-input').fill('111222'); await page.getByRole('button', { name: 'Pair devices' }).click(); await shot(page, 'pair-error-no-offer');
  });
  await scene('pair-code-error', async () => {
    await open(page, { start: PIPE_ONLY, errors: { pair_show_code: 'could not write the pairing offer to the shared folder' } });
    await page.locator('#pair-button').click(); await shot(page, 'pair-show-code-error');
  });
  await scene('pair-from-no-pipe', async () => {
    // paired=false and no folder yet: Pair a device goes through the picker first
    await open(page, { start: { device: 'MX-Fedora', paired: true, pipeSet: false, otherDevice: null } });
    await page.locator('#pair-button').click(); await shot(page, 'pair-needs-pipe-picker-first');
  });
  await scene('pair-success', async () => {
    await open(page, { start: PIPE_ONLY }); await page.locator('#pair-button').click(); await page.locator('#have-code').click();
    await page.locator('#code-input').fill('482913'); await page.getByRole('button', { name: 'Pair devices' }).click(); await page.locator('#preview').waitFor();
    await shot(page, 'preview-just-paired-notice');
  });
  await scene('pair-check-ok', async () => {
    await open(page, { start: PIPE_ONLY }); await page.locator('#pair-button').click();
    await setCfg(page, () => { window.cfg.start = { device: 'MX-Fedora', paired: true, pipeSet: true, otherDevice: 'Other laptop' }; });
    await page.locator('#check-pair').click(); await page.locator('#preview').waitFor(); await shot(page, 'preview-after-check-pairing-notice');
  });

  // ===== Preview =====
  const toPreview = async (over = {}) => { await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: true }, ...over }); await page.locator('#preview-button').click(); await page.locator('#preview').waitFor(); };
  await scene('preview-normal', async () => { await toPreview({ preview: PREVIEW.normal }); await shot(page, 'preview-4-brave-profiles-with-cannot-move'); });
  await scene('preview-unticked', async () => {
    await page.locator('.profile-row > input[type=checkbox]').nth(1).uncheck(); await page.waitForTimeout(300); await shot(page, 'preview-profile-0xovo-unticked');
  });
  await scene('preview-new', async () => { await toPreview({ preview: PREVIEW.newProfile }); await shot(page, 'preview-new-profile-badge'); });
  await scene('preview-arriving', async () => {
    await toPreview({ preview: PREVIEW.arriving });
    await shot(page, 'preview-arriving-browser-picks');
  });
  await scene('preview-errors', async () => { await toPreview({ preview: PREVIEW.errors }); await shot(page, 'preview-two-browsers-errors-box'); });
  await scene('preview-empty', async () => { await toPreview({ preview: PREVIEW.empty }); await shot(page, 'preview-nothing-found'); });
  await scene('preview-error', async () => {
    await open(page, { start: PAIRED, errors: { preview_counts: 'The sealed box could not be opened (wrong key). Pair the devices again.' } });
    await page.locator('#preview-button').click(); await shot(page, 'home-preview-failed-error');
  });
  await scene('preview-never', async () => {
    await open(page, { start: PAIRED, errors: { preview_counts: 'Open Brave once, then come back.' } });
    await page.locator('#preview-button').click(); await page.locator('#blocked').waitFor(); await shot(page, 'blocked-brave-never-opened');
  });
  await scene('preview-open-error', async () => {
    await open(page, { start: PAIRED, errors: { preview_counts: 'Brave is open; close it completely and try again' } });
    await page.locator('#preview-button').click(); await page.locator('#blocked').waitFor(); await shot(page, 'blocked-brave-open-from-preview');
  });
  await scene('preview-nopipe', async () => {
    await open(page, { start: { device: 'MX-Fedora', paired: true, pipeSet: false, otherDevice: 'Other laptop' } });
    await page.locator('#preview-button').click(); await shot(page, 'pipe-picker-opened-from-move-it-without-folder');
  });
  await scene('preview-nopair', async () => {
    await open(page, { start: PIPE_ONLY }); await page.locator('#preview-button').click(); await shot(page, 'pair-opened-from-move-it-not-paired');
  });

  // ===== Move: blocked, moving, done =====
  await scene('move-blocked', async () => {
    await toPreview({ open: 'blocked' }); await page.locator('#move').click(); await page.locator('#blocked').waitFor(); await shot(page, 'blocked-close-brave-before-move');
  });
  await scene('move-blocked-retry-still', async () => {
    await page.locator('#retry').click(); await page.locator('#blocked').waitFor(); await shot(page, 'blocked-still-open-after-retry');
  });
  await scene('moving', async () => {
    await toPreview({ moveHang: true }); await page.locator('#move').click(); await page.locator('#moving').waitFor();
    await page.evaluate(() => window.listeners['move-progress']({ payload: { frac: 0.1, line: 'Getting started' } }));
    await shot(page, 'moving-10-percent');
    await page.evaluate(() => window.listeners['move-progress']({ payload: { frac: 0.45, line: 'Copying logins and cookies' } }));
    await shot(page, 'moving-45-percent');
    await page.evaluate(() => window.listeners['move-progress']({ payload: { frac: 0.85, line: 'Sealing your box' } }));
    await shot(page, 'moving-85-percent');
  });
  await scene('moving-update-hidden', async () => {
    // same screen with an update pending: notice must stay hidden while moving
    await toPreview({ moveHang: true, update: '0.2.0' }); await page.locator('#move').click(); await page.locator('#moving').waitFor();
    await shot(page, 'moving-update-pending-notice-hidden');
  });
  await scene('done-clean', async () => {
    await toPreview(); await page.locator('#move').click(); await page.locator('#done').waitFor(); await shot(page, 'done-clean');
  });
  await scene('done-home', async () => {
    await page.locator('#done-button').click(); await page.locator('#home').waitFor(); await shot(page, 'home-after-done');
  });
  await scene('done-skips', async () => {
    await toPreview({ report: REPORT_SKIPS }); await page.locator('#move').click(); await page.locator('#done').waitFor(); await shot(page, 'done-with-skips');
  });
  await scene('done-routes', async () => {
    await toPreview({ preview: PREVIEW.routes, report: REPORT_ROUTES }); await page.locator('#move').click(); await page.locator('#done').waitFor(); await shot(page, 'done-routes-moved-and-failed');
  });
  await scene('move-error', async () => {
    await toPreview({ errors: { move_start: 'Dropbox: could not upload the sealed box (network unreachable)' } });
    await page.locator('#move').click(); await page.locator('#error').waitFor(); await shot(page, 'preview-move-failed-error');
  });
  await scene('move-never', async () => {
    await toPreview({ errors: { move_start: 'Open Brave once, then come back.' } });
    await page.locator('#move').click(); await page.locator('#blocked').waitFor(); await shot(page, 'blocked-brave-never-opened-during-move');
  });

  // ===== Undo =====
  await scene('undo-dialog', async () => {
    await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: true }, undoStatus: 'changed' });
    await page.locator('#undo').click(); await page.locator('#undo-confirm').waitFor(); await shot(page, 'undo-confirm-dialog-browser-changed');
  });
  await scene('undo-done', async () => {
    await page.locator('#force-undo').click(); await page.locator('#status').waitFor(); await shot(page, 'home-undo-done-notice');
  });
  await scene('undo-keep', async () => {
    await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: true }, undoStatus: 'changed' });
    await page.locator('#undo').click(); await page.locator('#undo-confirm').waitFor(); await page.locator('#cancel-undo').click(); await shot(page, 'home-undo-kept-changes');
  });
  await scene('undo-direct', async () => {
    await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: true }, undoStatus: 'done' });
    await page.locator('#undo').click(); await page.locator('#status').waitFor(); await shot(page, 'home-undo-done-no-prompt');
  });
  await scene('undo-none', async () => {
    await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: true }, undoStatus: 'none' });
    await page.locator('#undo').click(); await page.locator('#status').waitFor(); await shot(page, 'home-undo-nothing-to-undo');
  });
  await scene('undo-open', async () => {
    await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: true }, open: 'blocked' });
    await page.locator('#undo').click(); await page.locator('#blocked').waitFor(); await shot(page, 'blocked-close-brave-before-undo');
  });
  await scene('undo-error', async () => {
    await open(page, { start: PAIRED, home: { lastSync: 1794484988, canUndo: true }, errors: { undo_last: 'The backup from the last move is missing' } });
    await page.locator('#undo').click(); await page.locator('#error').waitFor(); await shot(page, 'home-undo-error');
  });

  // ===== Local move =====
  const toLocal = async (over = {}) => { await open(page, { start: PAIRED, ...over }); await page.locator('#home [data-nav="local"]').click(); await page.locator('#local').waitFor(); };
  await scene('local-pick', async () => { await toLocal(); await shot(page, 'local-pick-brave-to-chrome'); });
  await scene('local-welcome-entry', async () => {
    await open(page); await page.locator('#start-local').click(); await page.locator('#local').waitFor(); await shot(page, 'local-pick-from-welcome');
  });
  await scene('local-one-browser', async () => { await toLocal({ localBrowsers: [CHROME_BRAVE[0]] }); await shot(page, 'local-only-one-browser-disabled'); });
  await scene('local-none', async () => { await toLocal({ localBrowsers: [] }); await shot(page, 'local-no-browsers'); });
  await scene('local-same', async () => {
    await toLocal(); await page.locator('#target').selectOption('brave'); await page.locator('#local-preview').click(); await shot(page, 'local-same-browser-error');
  });
  await scene('local-preview', async () => { await toLocal(); await page.locator('#local-preview').click(); await page.locator('#preview').waitFor(); await shot(page, 'local-preview-brave-to-chrome'); });
  await scene('local-preview-clean', async () => {
    await toLocal({ localPreview: { source: 'Brave', target: 'Chrome', cookies: 1935, logins: 1705, passwords: 240, extensions: 39, bookmarks: 798, history: 42783, skipped: [] } });
    await page.locator('#local-preview').click(); await page.locator('#preview').waitFor(); await shot(page, 'local-preview-no-skips');
  });
  await scene('local-preview-never', async () => {
    await toLocal({ errors: { local_preview: 'Open Chrome once, then come back.' } }); await page.locator('#local-preview').click(); await page.locator('#blocked').waitFor(); await shot(page, 'blocked-chrome-never-opened-local');
  });
  await scene('local-preview-error', async () => {
    await toLocal({ errors: { local_preview: 'Could not read the Brave profile folder' } }); await page.locator('#local-preview').click(); await shot(page, 'local-preview-error');
  });
  await scene('local-move-blocked', async () => {
    await toLocal({ open: 'blocked', openBrowser: 'Chrome' }); await page.locator('#local-preview').click(); await page.locator('#preview').waitFor();
    await page.locator('#move').click(); await page.locator('#blocked').waitFor(); await shot(page, 'blocked-close-chrome-before-local-move');
  });
  await scene('local-moving', async () => {
    await toLocal({ moveHang: true }); await page.locator('#local-preview').click(); await page.locator('#preview').waitFor();
    await page.locator('#move').click(); await page.locator('#moving').waitFor();
    await page.evaluate(() => window.listeners['move-progress']({ payload: { frac: 0.6, line: 'Moving bookmarks and extensions' } }));
    await shot(page, 'local-moving-60-percent');
    await page.evaluate(() => window.finishMove());
  });
  await scene('local-done', async () => {
    await page.locator('#done').waitFor(); await shot(page, 'local-done-with-skips');
  });

  // ===== Logs =====
  await scene('logs', async () => { await open(page, { start: PAIRED }); await page.locator('#home [data-nav="logs"]').click(); await page.locator('#logs').waitFor(); await shot(page, 'logs-with-entries'); });
  await scene('logs-export', async () => { await page.locator('#export-logs').click(); await page.locator('#status').waitFor(); await shot(page, 'logs-export-saved-notice'); });
  await scene('logs-empty', async () => { await open(page, { start: PAIRED, logs: [] }); await page.locator('#home [data-nav="logs"]').click(); await page.locator('#logs').waitFor(); await shot(page, 'logs-empty'); });
  await scene('logs-error', async () => {
    await open(page, { start: PAIRED, errors: { logs_recent: 'log buffer unavailable' } }); await page.locator('#home [data-nav="logs"]').click(); await shot(page, 'home-logs-failed-error');
  });
  await scene('logs-update', async () => {
    await open(page, { start: PAIRED, update: '0.2.0' }); await page.locator('#home [data-nav="logs"]').click(); await page.locator('#logs').waitFor(); await page.waitForTimeout(300); await shot(page, 'logs-with-update-notice');
  });

  console.log('FAILURES:', JSON.stringify(failures, null, 1));
  if (failures.length) throw new Error(`${failures.length} scenes failed`);
});

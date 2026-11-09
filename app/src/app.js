import { countLabels, totals, reportLines } from './model.js';
import { updateNoticeText, updatePrimaryLabel, shouldShowUpdateNotice, GITHUB_RELEASE } from './update.js';
const $ = id => document.getElementById(id);
const api = window.__TAURI__;
let busy = false, startInfo = null, selectedPipe = null, afterPipe = 'preview', signInWaiting = false, signInAbort = false, signInNavAfterCancel = null, usingByokKeys = false;
let pendingUpdate = null, dismissedUpdate = null, packageManaged = false, githubUrl = GITHUB_RELEASE;
let local = false, excluded = [], routes = [], retryAction = null;
const loaders = new Map();
const text = (tag, value, className) => { const el = document.createElement(tag); el.textContent = value; if (className) el.className = className; return el; };
function notice(message, error = false) { const el = $(error ? 'error' : 'status'); el.textContent = message; el.hidden = !message; }
function show(name) {
  for (const section of document.querySelectorAll('main > .state')) section.hidden = section.id !== name;
  document.querySelector('.app').dataset.screen = name;
  notice(''); notice('', true); window.scrollTo(0, 0);
  refreshUpdateNotice();
}
async function refreshUpdateNotice() {
  const panel = $('update-notice');
  if (!api || !pendingUpdate) { panel.hidden = true; return; }
  const engineIdle = await call('engine_idle');
  const onMoveScreen = !$('moving').hidden;
  const visible = shouldShowUpdateNotice({ pendingVersion: pendingUpdate, dismissedVersion: dismissedUpdate, engineIdle, onMoveScreen, uiBusy: busy });
  panel.hidden = !visible;
  if (!visible) return;
  $('update-notice-text').textContent = updateNoticeText(pendingUpdate);
  $('update-now').textContent = updatePrimaryLabel(packageManaged);
}
async function call(name, args = {}) { return api.core.invoke(name, args); }
async function task(fn) {
  if (busy) return;
  busy = true; document.querySelector('main').setAttribute('aria-busy', 'true');
  try { await fn(); } catch (error) { notice(String(error), true); }
  finally { busy = false; document.querySelector('main').setAttribute('aria-busy', 'false'); refreshUpdateNotice(); }
}
const on = (id, fn) => $(id).addEventListener('click', () => task(fn));
async function home() {
  const state = await call('home_state');
  show('home'); $('last-sync').textContent = state.lastSync ? `Last move ${new Date(state.lastSync * 1000).toLocaleString()}` : 'No moves yet';
  $('undo').disabled = !state.canUndo;
  $('device').textContent = startInfo?.otherDevice ? `${startInfo.device} · ${startInfo.otherDevice}` : startInfo?.device || '';
}
function pipeUseLabel(candidate) {
  if (candidate.kind === 'group') return null;
  if (candidate.cloud) {
    if (candidate.kind === 'byok') return candidate.connected ? 'Use my keys' : 'Choose my app keys';
    if (candidate.connected) return `Use ${candidate.label.replace(' (connected)', '')}`;
    return `Sign in and use ${candidate.label.replace(/^Sign in with /, '')}`;
  }
  if (candidate.kind === 'git') return 'Use this git repo';
  return 'Use this folder';
}
function setSignInUi(waiting) {
  signInWaiting = waiting;
  $('pipe-sign-in-cancel').hidden = !waiting;
  if (waiting) $('use-pipe').disabled = true;
  refreshUpdateNotice();
}

async function cancelActiveSignIn(afterCancel = null) {
  if (!signInWaiting) return;
  signInAbort = true;
  if (afterCancel) signInNavAfterCancel = afterCancel;
  await call('pipe_sign_in_cancel');
}

async function finishSignInCancelUi(finish, byok) {
  const nav = signInNavAfterCancel;
  signInNavAfterCancel = null;
  setSignInUi(false);
  if (signInAbort && finish?.status === 'connected') {
    busy = true;
    document.querySelector('main').setAttribute('aria-busy', 'true');
  }
  try {
    if (signInAbort && finish?.status === 'connected') {
      try {
        await call('pipe_sign_in_discard', { provider: selectedPipe.kind, byok, attempt: finish.attempt });
      } catch (error) {
        notice(String(error), true);
        if (nav) await nav();
        else await pipes(afterPipe);
        return;
      }
    }
    if (nav) {
      await nav();
      return;
    }
    await pipes(afterPipe);
    notice('Sign-in was cancelled.', true);
  } finally {
    if (signInAbort && finish?.status === 'connected') {
      busy = false;
      document.querySelector('main').setAttribute('aria-busy', 'false');
      refreshUpdateNotice();
    }
  }
}

async function pipes(next = 'preview') {
  afterPipe = next; selectedPipe = null; signInWaiting = false; signInAbort = false;
  $('pipe-sign-in-cancel').hidden = true;
  $('use-pipe').disabled = true; $('pipe-path').textContent = '';
  $('pipe-disconnect').hidden = true;
  const candidates = await call('pipe_candidates'); const list = $('pipe-options'); list.replaceChildren();
  for (const candidate of candidates) {
    if (candidate.kind === 'group') {
      list.append(text('div', candidate.label, 'group-label'));
      continue;
    }
    const button = text('button', '', candidate.cloud ? 'option' : 'option');
    button.type = 'button'; button.setAttribute('role', 'radio'); button.setAttribute('aria-checked', 'false');
    const hint = candidate.cloud
      ? (candidate.connected ? 'Connected to Move It' : 'Sign in in your browser')
      : (candidate.path ? 'Found on this computer' : 'Choose a folder');
    const label = text('span', '', 'label'); label.append(text('b', candidate.label), text('small', hint));
    button.append(label, text('span', '', 'dot'));
    button.addEventListener('click', () => task(async () => {
      if (signInWaiting) return;
      if (candidate.kind === 'byok' && !candidate.path) {
        const installed = await call('pipe_install_byok');
        if (installed?.status === 'installed') usingByokKeys = true;
        return pipes(next);
      }
      if (candidate.cloud) {
        if (candidate.byok != null) usingByokKeys = candidate.byok;
      } else {
        usingByokKeys = false;
      }
      let path = candidate.path;
      if (!path && !candidate.cloud) path = await call('pick_folder');
      if (!path && !candidate.cloud) return;
      selectedPipe = { ...candidate, path: path || null };
      for (const other of list.querySelectorAll('[role="radio"]')) other.setAttribute('aria-checked', String(other === button));
      $('pipe-path').textContent = path || '';
      const action = pipeUseLabel(candidate);
      const span = $('use-pipe').querySelector('span');
      if (action && span) span.textContent = action;
      $('use-pipe').disabled = false;
      $('pipe-disconnect').hidden = !(candidate.cloud && candidate.connected);
    }));
    list.append(button);
  }
  show('pipe');
}
async function pairing(enter = false) {
  if (!startInfo.pipeSet) return pipes(enter ? 'enter-code' : 'pair');
  show('pair'); $('pair-form').hidden = !enter; $('show-code-panel').hidden = enter;
  if (!enter) { $('pair-code').textContent = ''; const result = await call('pair_show_code'); $('pair-code').textContent = result.code; }
  else $('code-input').focus();
}
function counts(element, data) {
  element.replaceChildren();
  for (const [key, label] of Object.entries(countLabels)) { const row = text('div', '', 'row'); row.append(text('b', (Number(data[key]) || 0).toLocaleString()), text('span', label)); element.append(row); }
}
function skips(element, entries) {
  element.replaceChildren(); if (!entries.length) return;
  const card = text('div', '', 'skips'); card.append(text('b', 'Cannot move'));
  for (const entry of entries) card.append(text('p', `${entry.browser || ''}${entry.browser ? ': ' : ''}${entry.reason}`));
  element.append(card);
}
async function preview(first = false) {
  if (!startInfo.pipeSet) return pipes('preview');
  if (!startInfo.paired) return pairing();
  local = false;
  if (first) { excluded = []; routes = []; }
  try {
    const data = await call('preview_counts', { excluded, routes });
    if (first) excluded = data.browsers.flatMap(b => b.profiles.filter(p => !p.ticked).map(p => p.id));
    $('preview-target').textContent = `Between this device and ${data.target || 'your other device'}`;
    const container = $('profiles'); container.replaceChildren();
    for (const browser of data.browsers) {
      container.append(text('div', browser.display, 'group-label'));
      for (const profile of browser.profiles) {
        const card = text('div', '', 'card profile'); const label = text('label', ''); const check = document.createElement('input'); check.type = 'checkbox'; check.checked = !excluded.includes(profile.id);
        label.append(check, text('span', `${profile.name}${profile.isNew ? ' · New' : ''}`)); card.append(label);
        check.addEventListener('change', () => task(async () => {
          excluded = check.checked ? excluded.filter(id => id !== profile.id) : [...new Set([...excluded, profile.id])];
          if (!check.checked) routes = routes.filter(r => r.profile !== profile.id);
          await preview();
        }));
        if (check.checked && data.targets.some(t => t.available && t.name !== browser.name)) {
          const select = document.createElement('select'); select.setAttribute('aria-label', `Destination for ${profile.name}`);
          for (const target of data.targets) { const option = text('option', `${target.display}${target.reason ? ` — ${target.reason}` : ''}`); option.value = target.name; option.disabled = !target.available; select.append(option); }
          select.value = profile.destination;
          select.addEventListener('change', () => task(async () => { routes = routes.filter(r => r.profile !== profile.id); if (select.value !== browser.name) routes.push({ profile: profile.id, browser: select.value }); await preview(); }));
          card.append(select);
        }
        container.append(card);
      }
    }
    counts($('totals'), totals(data.browsers.flatMap(b => b.profiles.filter(p => !excluded.includes(p.id))))); skips($('skipped'), [...data.skipped, ...data.browsers.flatMap(b => b.skipped)]); show('preview');
  } catch (error) {
    if (showEngineBlock(error, () => preview(first))) return;
    throw error;
  }
}
async function localPick() {
  const browsers = await call('local_browsers');
  for (const id of ['source', 'target']) { $(id).replaceChildren(); for (const browser of browsers) { const option = text('option', browser.display); option.value = browser.browser; $(id).append(option); } }
  if (browsers.length > 1) $('target').selectedIndex = 1;
  $('local-preview').disabled = browsers.length < 2; $('local-hint').textContent = browsers.length < 2 ? 'Open two supported browsers once to create their profiles, then return here.' : '';
  show('local');
}
const localArgs = () => ({ source: $('source').value, target: $('target').value });
async function localPreview() {
  if ($('source').value === $('target').value) throw new Error('Choose two different browsers.');
  try {
    const data = await call('local_preview', localArgs()); local = true; $('profiles').replaceChildren(); $('preview-target').textContent = `From ${data.source} to ${data.target}, on this device`;
    counts($('totals'), data); skips($('skipped'), data.skipped); show('preview');
  } catch (error) {
    if (showEngineBlock(error, localPreview)) return;
    throw error;
  }
}
function showBlocked(title, sub, action) {
  retryAction = action;
  show('blocked');
  $('blocked-title').textContent = title;
  $('blocked-sub').textContent = sub;
}
/** Engine NeverLaunched / BrowserOpen messages become the blocked screen. */
function showEngineBlock(error, action) {
  const msg = String(error?.message || error).replace(/^Error:\s*/, '');
  const never = msg.match(/^Open (.+) once, then come back\.?$/i);
  if (never) {
    showBlocked(msg, `${never[1]} has not been opened on this device yet. Open it once so it can set itself up, then come back to Move It.`, action);
    return true;
  }
  const open = msg.match(/^(?:the browser is still open.*|(.+) is open; close it completely and try again)$/i);
  if (open) {
    const browser = open[1] || 'your browser';
    showBlocked(`Close ${browser} and tap again`, `Move It can only move your things while ${browser} is closed.`, action);
    return true;
  }
  return false;
}
async function checkOpen(action) {
  const check = await call(local ? 'local_open_check' : 'browser_open_check', local ? localArgs() : {});
  if (check.status === 'blocked') {
    showBlocked(`Close ${check.browser} and tap again`, `Move It can only move your things while ${check.browser} is closed.`, action);
    return false;
  }
  return true;
}
async function move() {
  if (!await checkOpen(move)) return;
  show('moving'); loaders.get('moving')?.setProgress(0); $('moving-line').textContent = 'Getting started';
  try {
    const report = await call(local ? 'local_move' : 'move_start', local ? localArgs() : { excluded, routes });
    loaders.get('moving')?.setProgress(1);
    $('report').replaceChildren(...reportLines(report).map(line => { const row = text('div', '', 'row'); row.append(text('span', line)); return row; }));
    const entries = [...(report.skipped || [])];
    if (report.boxesSkipped) entries.push({ reason: `${report.boxesSkipped} unreadable boxes were skipped.` });
    if (report.lockedCookies) entries.push({ reason: `${report.lockedCookies} protected cookies stayed behind.` });
    skips($('report-skips'), entries); $('done-title').textContent = entries.length || report.routes?.some(r => r.status === 'failed') ? 'Move finished with skips' : 'Move finished'; show('done');
  } catch (error) {
    if (showEngineBlock(error, move)) return;
    show('preview'); throw error;
  }
}
async function undo(force = false) {
  local = false;
  if (!await checkOpen(() => undo(force))) return;
  try {
    const result = await call('undo_last', { force });
    if (result.status === 'changed') { $('undo-confirm').showModal(); return; }
    await home(); notice(result.status === 'done' ? 'Back to how it was before the last move.' : 'There is no move to undo.');
  } catch (error) {
    if (showEngineBlock(error, () => undo(force))) return;
    throw error;
  }
}
async function logs() { const lines = await call('logs_recent'); $('log-lines').replaceChildren(...lines.slice().reverse().map(line => text('p', `${new Date(line.at_unix * 1000).toLocaleString()} · ${line.level}: ${line.message}`))); if (!lines.length) $('log-lines').append(text('p', 'No activity in this session yet.')); show('logs'); }

on('start', home); on('about-home', home); on('about-link', async () => show('about'));
$('home-link').addEventListener('click', () => { if (signInWaiting) { void cancelActiveSignIn(() => task(home)); return; } task(home); });
on('preview-button', () => preview(true)); on('pair-button', () => pairing()); on('undo', () => undo());
async function usePipe() {
  if (busy || signInWaiting || !selectedPipe) return;
  if (selectedPipe.cloud && ['google', 'dropbox'].includes(selectedPipe.kind)) {
    const byok = usingByokKeys;
    if (!selectedPipe.connected) {
      signInAbort = false;
      setSignInUi(true);
      notice('Finish signing in in your browser, then return here.');
      try {
        await call('pipe_sign_in_begin', { provider: selectedPipe.kind, byok });
        const finish = await call('pipe_sign_in_finish');
        if (signInAbort || finish?.status !== 'connected') {
          await finishSignInCancelUi(finish, byok);
          return;
        }
        setSignInUi(false);
      } catch (error) {
        setSignInUi(false);
        const nav = signInNavAfterCancel;
        signInNavAfterCancel = null;
        if (nav) { await nav(); return; }
        if (signInAbort) notice('Sign-in was cancelled.', true);
        else notice(String(error), true);
        await pipes(afterPipe);
        return;
      }
    }
    busy = true;
    document.querySelector('main').setAttribute('aria-busy', 'true');
    try {
      await call('use_cloud_pipe', { provider: selectedPipe.kind, byok });
      startInfo.pipeSet = true;
      notice('');
      if (afterPipe === 'pair' || afterPipe === 'enter-code') await pairing(afterPipe === 'enter-code'); else await preview(true);
    } catch (error) {
      notice(String(error), true);
    } finally {
      busy = false;
      document.querySelector('main').setAttribute('aria-busy', 'false');
      refreshUpdateNotice();
    }
    return;
  }
  busy = true;
  document.querySelector('main').setAttribute('aria-busy', 'true');
  try {
    const result = await call('use_pipe', { path: selectedPipe.path, expectedKind: selectedPipe.kind });
    if (selectedPipe.kind === 'git' && result.kind !== 'git') { notice('This folder is not a git clone. Choose an existing clone.', true); return; }
    startInfo.pipeSet = true;
    if (afterPipe === 'pair' || afterPipe === 'enter-code') await pairing(afterPipe === 'enter-code'); else await preview(true);
  } catch (error) {
    notice(String(error), true);
  } finally {
    busy = false;
    document.querySelector('main').setAttribute('aria-busy', 'false');
    refreshUpdateNotice();
  }
}
$('use-pipe').addEventListener('click', () => void usePipe());
$('pipe-sign-in-cancel').addEventListener('click', () => void cancelActiveSignIn());
on('pipe-disconnect', async () => {
  if (!selectedPipe?.cloud) return;
  const provider = selectedPipe.kind === 'byok' ? 'google' : selectedPipe.kind;
  if (!['google', 'dropbox'].includes(provider)) return;
  await call('pipe_sign_out', { provider });
  notice('Disconnected. You can sign in again at any time.');
  await pipes(afterPipe);
});
on('have-code', () => pairing(true)); on('show-code', () => pairing());
on('check-pair', async () => { startInfo = await call('welcome_start'); if (startInfo.otherDevice) { await preview(true); notice(`Paired with ${startInfo.otherDevice}.`); } else notice('Waiting for your other device to enter the code.'); });
$('pair-form').addEventListener('submit', event => { event.preventDefault(); task(async () => {
  const result = await call('pair_enter_code', { code: $('code-input').value }); $('code-input').value = '';
  if (result.status === 'success') { startInfo = await call('welcome_start'); await preview(true); notice(`Paired with ${result.otherDevice}.`); }
  else if (result.status === 'wrong') notice(`That code did not match. ${result.triesLeft} tries left.`, true);
  else notice(result.status === 'need_new_code' ? 'Show a new code on the other device.' : 'No pairing offer found. Check the shared folder and show a new code.', true);
}); });
on('local-preview', localPreview); on('move', move); on('done-button', home); on('retry', async () => { if (retryAction) await retryAction(); });
on('force-undo', async () => { $('undo-confirm').close(); await undo(true); }); on('cancel-undo', async () => $('undo-confirm').close());
on('export-logs', async () => { if (await call('export_logs')) notice('Log report saved.'); }); on('refresh-logs', logs);
on('update-later', () => { dismissedUpdate = pendingUpdate; refreshUpdateNotice(); });
on('update-now', async () => {
  if (packageManaged) { await call('open_release_page', { url: githubUrl }); return; }
  await call('updater_install');
  notice('Installing update. Move It will restart when ready.');
});
for (const button of document.querySelectorAll('[data-nav]')) {
  button.addEventListener('click', () => {
    if (signInWaiting) {
      const dest = button.dataset.nav;
      void cancelActiveSignIn(() => task(() => ({ local: localPick, logs, pipe: pipes })[dest]()));
      return;
    }
    task(() => ({ local: localPick, logs, pipe: pipes })[button.dataset.nav]());
  });
}

const UPDATE_CHECK_MS = 8_000;

async function runBackgroundUpdateCheck() {
  try {
    const found = await Promise.race([
      call('updater_check'),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), UPDATE_CHECK_MS)),
    ]);
    if (found) pendingUpdate = found;
    await refreshUpdateNotice();
  } catch { /* optional check; never block startup */ }
}

async function boot() {
  if (!api) { show('welcome'); notice('Open Move It in its desktop app to use your browser data.', true); document.querySelectorAll('button').forEach(b => b.disabled = true); return; }
  const version = await api.app.getVersion(); for (const el of document.querySelectorAll('[data-version]')) el.textContent = `Move It v${version}`;
  await api.event.listen('move-progress', ({ payload }) => { loaders.get('moving')?.setProgress(payload.frac); $('moving-line').textContent = payload.line; refreshUpdateNotice(); });
  await api.event.listen('update-available', ({ payload }) => { pendingUpdate = payload; refreshUpdateNotice(); });
  const ctx = await call('updater_context'); packageManaged = !!ctx.packageManaged; githubUrl = ctx.githubUrl || GITHUB_RELEASE;
  void runBackgroundUpdateCheck();
  new MutationObserver(() => refreshUpdateNotice()).observe($('moving'), { attributes: true, attributeFilter: ['hidden'] });
  startInfo = await call('welcome_start'); if (startInfo.paired || startInfo.pipeSet) await home(); else show('welcome');
}
// Artwork failure must not prevent the engine or controls from working.
for (const el of document.querySelectorAll('.lemur')) {
  MoveItLoader.create(el, { frames: window.MOVEIT_FRAMES, base: 'design/loader/frames/' }).then(loader => { loader.setMode(el.dataset.mode); loaders.set(el.closest('section').id, loader); }).catch(() => { el.textContent = 'Move It'; });
}
task(boot);

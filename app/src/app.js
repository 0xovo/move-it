import { kindDefs, aggregateKinds, kindSummaryText, reportLines, skipLines, formatAttentionLine, slotLabel, sourceProfileTitle, localProfileId, needsProfilePick, preselectedSlot } from './model.js';
import { updateNoticeText, updatePrimaryLabel, shouldShowUpdateNotice, GITHUB_RELEASE } from './update.js';

const $ = id => document.getElementById(id);
const api = window.__TAURI__;
const ALLOWED_OPEN = new Set(['https://ko-fi.com/0xovo', 'https://getmoveit.tech', 'https://github.com/0xovo/move-it', 'https://x.com/0xovoo']);
const SHARE_URL = 'https://getmoveit.tech';

let busy = false, startInfo = null, selectedPipe = null, afterPipe = 'preview', signInWaiting = false, signInAbort = false;
let signInNavAfterCancel = null, usingByokKeys = false, storageName = 'shared storage';
let pendingUpdate = null, dismissedUpdate = null, packageManaged = false, githubUrl = GITHUB_RELEASE;
let local = false, excluded = [], routes = [], retryAction = null, previewCache = null;
let localProfilesByBrowser = {};
let profileKinds = {}, expandedProfiles = new Set(), moveCount = 0, donateDismissed = false;
const loaders = new Map();

const text = (tag, value, className) => { const el = document.createElement(tag); el.textContent = value; if (className) el.className = className; return el; };

let stickyError = '';
function notice(message, error = false) {
  const el = $(error ? 'error' : 'status');
  el.textContent = message;
  el.hidden = !message;
  if (error) stickyError = message || '';
}

function show(name) {
  for (const section of document.querySelectorAll('main > .state')) section.hidden = section.id !== name;
  document.querySelector('.app').dataset.screen = name;
  $('status').textContent = '';
  $('status').hidden = true;
  if (stickyError) {
    $('error').textContent = stickyError;
    $('error').hidden = false;
  } else {
    $('error').textContent = '';
    $('error').hidden = true;
  }
  window.scrollTo(0, 0);
  refreshUpdateNotice();
}

async function openLink(url) {
  if (!ALLOWED_OPEN.has(url) && !url.startsWith('https://x.com/intent/post?')) return;
  await call('open_external', { url });
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

function storageLabelFromKind(kind) {
  return ({ google: 'Google Drive', dropbox: 'Dropbox', git: 'a git repository', folder: 'a shared folder' })[kind] || 'shared storage';
}

async function home() {
  const state = await call('home_state');
  show('home');
  const other = startInfo?.otherDevice;
  $('home-sub').textContent = startInfo?.device ? `This device: ${startInfo.device}` : '';
  if (!startInfo?.pipeSet) {
    $('home-title').textContent = 'Not paired yet';
    $('preview-button').textContent = 'Set up moving';
  } else if (startInfo.paired && other) {
    $('home-title').textContent = `Ready to move to ${other}`;
    const browser = startInfo.browser || 'your browser';
    $('preview-button').textContent = `Move ${browser} to ${other}`;
  } else {
    $('home-title').textContent = 'Choose storage and pair';
    $('preview-button').textContent = 'Set up moving';
  }
  $('undo').hidden = !state.canUndo;
  if (state.canUndo) {
    const when = state.lastSync ? new Date(state.lastSync * 1000).toLocaleString() : '';
    $('undo').textContent = when ? `Undo last move (${when})` : 'Undo last move';
  }
  $('last-sync').textContent = state.lastSync ? `Last move ${new Date(state.lastSync * 1000).toLocaleString()}` : 'No moves yet';
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
  if (!waiting) showSignInLink(null);
  if (waiting) $('use-pipe').disabled = true;
  refreshUpdateNotice();
}

function showSignInLink(begin) {
  const url = begin && typeof begin.authorizeUrl === 'string' && begin.authorizeUrl.startsWith('https://') ? begin.authorizeUrl : '';
  $('pipe-sign-in-link').hidden = !url;
  $('pipe-sign-in-url').value = url;
  $('pipe-sign-in-copy').textContent = 'Copy link';
  $('pipe-sign-in-link-text').textContent = begin && begin.opened === false
    ? 'Your browser did not open. Copy this link and open it in your browser.'
    : "Browser didn't open? Copy this link and open it in your browser.";
}

async function copySignInLink() {
  const field = $('pipe-sign-in-url');
  if (!field.value) return;
  let copied = false;
  try { await navigator.clipboard.writeText(field.value); copied = true; } catch {}
  if (!copied) { field.focus(); field.select(); try { copied = document.execCommand('copy'); } catch {} }
  $('pipe-sign-in-copy').textContent = copied ? 'Copied' : 'Select and copy the link';
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
    if (nav) { await nav(); return; }
    const aborted = signInAbort;
    await pipes(afterPipe);
    if (aborted) {
      notice('Sign-in was cancelled.', true);
      stickyError = 'Sign-in was cancelled.';
      $('error').textContent = stickyError;
      $('error').hidden = false;
    }
  } finally {
    if (signInAbort && finish?.status === 'connected') {
      busy = false;
      document.querySelector('main').setAttribute('aria-busy', 'false');
      refreshUpdateNotice();
    }
  }
}

function renderPipeOption(candidate, list) {
  const button = text('button', '', 'option');
  button.type = 'button'; button.setAttribute('role', 'radio'); button.setAttribute('aria-checked', 'false');
  const hint = candidate.cloud
    ? (candidate.connected ? 'Connected to Move It' : 'Sign in, in your browser')
    : (candidate.path ? 'Found on this computer' : 'Choose a folder');
  const label = text('span', '', 'label');
  label.append(text('b', candidate.label), text('small', candidate.hint || hint));
  button.append(label, text('span', '', 'dot'));
  button.addEventListener('click', () => task(async () => {
    if (signInWaiting) return;
    if (candidate.kind === 'byok' && !candidate.path) {
      const installed = await call('pipe_install_byok');
      if (installed?.status === 'installed') usingByokKeys = true;
      return pipes(afterPipe);
    }
    if (candidate.cloud) usingByokKeys = candidate.byok ?? false;
    else usingByokKeys = false;
    let path = candidate.path;
    if (!path && !candidate.cloud && candidate.kind !== 'byok') path = await call('pick_folder');
    if (!path && !candidate.cloud && candidate.kind !== 'byok') return;
    selectedPipe = { ...candidate, path: path || null };
    for (const other of document.querySelectorAll('#pipe-recommended [role="radio"], #pipe-other [role="radio"]')) {
      other.setAttribute('aria-checked', String(other === button));
    }
    $('pipe-path').textContent = path || '';
    $('pipe-folder-alt').hidden = true;
    if (candidate.altFolder) {
      $('pipe-folder-alt').hidden = false;
      $('pipe-folder-alt').textContent = `or use the ${candidate.altFolder.label} folder on this computer`;
    }
    const action = pipeUseLabel(candidate);
    const span = $('use-pipe').querySelector('span');
    if (action && span) span.textContent = action;
    $('use-pipe').disabled = false;
    $('pipe-disconnect').hidden = !(candidate.cloud && candidate.connected);
  }));
  list.append(button);
}

async function pipes(next = 'preview') {
  afterPipe = next; selectedPipe = null; signInWaiting = false; signInAbort = false;
  $('pipe-sign-in-cancel').hidden = true;
  $('use-pipe').disabled = true; $('pipe-path').textContent = ''; $('pipe-folder-alt').hidden = true;
  $('pipe-disconnect').hidden = true;
  const candidates = await call('pipe_candidates');
  const recommended = $('pipe-recommended');
  const other = $('pipe-other');
  recommended.replaceChildren();
  other.replaceChildren();
  const folders = { dropbox: null, google: null };
  for (const c of candidates) {
    if (c.kind === 'folder' && c.path) {
      if (c.label === 'Dropbox' && !folders.dropbox) folders.dropbox = c;
      if (c.label === 'Google Drive' && !folders.google) folders.google = c;
    }
  }
  for (const c of candidates) {
    if (c.kind === 'google') renderPipeOption({ ...c, altFolder: folders.google }, recommended);
    else if (c.kind === 'dropbox') renderPipeOption({ ...c, altFolder: folders.dropbox }, recommended);
    else if (c.kind === 'group') continue;
    else if (c.kind === 'byok' || (!c.cloud && ['folder', 'git'].includes(c.kind))) {
      renderPipeOption(c, other);
    }
  }
  if (!recommended.children.length) $('pipe-recommended-label').hidden = true;
  else $('pipe-recommended-label').hidden = false;
  show('pipe');
}

async function pairing(enter = false) {
  if (!startInfo.pipeSet) return pipes(enter ? 'enter-code' : 'pair');
  $('pair-sub').textContent = `Both computers must use ${storageName}.`;
  show('pair'); $('pair-form').hidden = !enter; $('show-code-panel').hidden = enter;
  if (!enter) { $('pair-code').textContent = ''; const result = await call('pair_show_code'); $('pair-code').textContent = result.code; }
  else $('code-input').focus();
}

function skips(element, entries) {
  element.replaceChildren();
  if (!entries.length) return;
  const card = text('div', '', 'skips'); card.append(text('b', 'Needs attention'));
  const seen = new Set();
  for (const entry of entries) {
    const line = formatAttentionLine(entry);
    if (!line || seen.has(line)) continue;
    seen.add(line);
    card.append(text('p', line));
  }
  element.append(card);
}

function profileDestLabel(profile, data, browser) {
  const other = data.target || startInfo?.otherDevice || 'your other computer';
  const dest = profile.destination || browser.name;
  const match = data.targets?.find(t => t.name === dest);
  const name = match?.display || browser.display;
  if (local) return `Goes into ${profile.destination || name}`;
  return profile.isNew ? `Goes into ${name} on ${other} as a new profile` : `Goes into ${name} on ${other}`;
}

function renderRouteCard(data) {
  const card = $('route-card');
  if (local || !data.browsers?.length) { card.hidden = true; return; }
  card.hidden = false; card.replaceChildren();
  const grid = text('div', '', 'route-grid');
  const from = text('div', '', 'route-col');
  from.append(text('span', 'From', 'route-tag'), text('b', startInfo?.device || 'This computer'), text('span', data.browsers[0]?.display || '', 'route-detail'));
  const arrow = text('div', '→', 'route-arrow-mid');
  const to = text('div', '', 'route-col');
  to.append(text('span', 'To', 'route-tag'), text('b', data.target || 'Other computer'), text('span', `Through ${storageName}`, 'route-detail'));
  grid.append(from, arrow, to);
  card.append(grid);
}

function ensureProfileKinds(profiles) {
  for (const p of profiles) {
    if (!profileKinds[p.id]) profileKinds[p.id] = kindDefs.map(k => k.id);
  }
}

function selectedKindsFor(profileId) {
  return profileKinds[profileId] || kindDefs.map(k => k.id);
}

function buildProfileKindsPayload(data) {
  const map = {};
  for (const p of tickedProfiles(data)) {
    const sel = selectedKindsFor(p.id);
    if (sel.length < kindDefs.length) map[p.id] = sel;
  }
  return Object.keys(map).length ? map : undefined;
}

function refreshKindSummary(summaryEl, profileId) {
  summaryEl.textContent = kindSummaryText(selectedKindsFor(profileId).length);
}

function renderProfileKindsPanel(profile, panel, summaryEl) {
  panel.replaceChildren();
  const counts = aggregateKinds(profile);
  for (const def of kindDefs) {
    const card = text('label', '', 'kind-row');
    const check = document.createElement('input');
    check.type = 'checkbox';
    check.checked = selectedKindsFor(profile.id).includes(def.id);
    check.addEventListener('change', () => {
      const cur = selectedKindsFor(profile.id);
      profileKinds[profile.id] = check.checked
        ? [...new Set([...cur, def.id])]
        : cur.filter(k => k !== def.id);
      if (!profileKinds[profile.id].length) {
        profileKinds[profile.id] = [def.id];
        check.checked = true;
      }
      refreshKindSummary(summaryEl, profile.id);
      renderProfileKindsPanel(profile, panel, summaryEl);
    });
    const body = text('span', '', 'kind-body');
    const detail = def.detail || `${counts[def.id].toLocaleString()} item${counts[def.id] === 1 ? "" : "s"}`;
    body.append(text('b', def.label), text('small', detail));
    card.append(check, body);
    panel.append(card);
  }
}

function renderProfileBlock(browser, profile, data, container) {
  const ticked = !excluded.includes(profile.id);
  const block = text('div', '', 'card profile-block' + (ticked ? '' : ' is-off'));
  const row = text('label', '', 'kind-row profile-row');
  const check = document.createElement('input');
  check.type = 'checkbox';
  check.checked = ticked;
  const body = text('span', '', 'profile-body');
  body.append(
    text('span', profile.name, 'profile-title'),
    ...(local ? [text('span', profileDestLabel(profile, data, browser), 'profile-dest')] : []),
  );
  row.append(check, body);
  check.addEventListener('change', () => task(async () => {
    excluded = check.checked ? excluded.filter(id => id !== profile.id) : [...new Set([...excluded, profile.id])];
    const arrivingIds = new Set((previewCache?.arriving || []).map(p => p.id));
    if (!check.checked && !arrivingIds.has(profile.id)) {
      routes = routes.filter(r => r.profile !== profile.id);
    }
    await preview();
  }));
  block.append(row);
  if (!ticked) { container.append(block); return; }

  const tools = text('div', '', 'profile-tools');
  const expand = text('button', '', 'profile-expand');
  expand.type = 'button';
  const expanded = expandedProfiles.has(profile.id);
  expand.setAttribute('aria-expanded', expanded ? 'true' : 'false');
  expand.setAttribute('aria-label', `Choose what to move for ${profile.name}`);
  const summary = text('span', kindSummaryText(selectedKindsFor(profile.id).length), 'profile-kind-summary');
  expand.append(text('span', 'Moving:', 'profile-expand-label'), summary);
  const panel = text('div', '', 'profile-kinds-panel');
  panel.hidden = !expanded;
  renderProfileKindsPanel(profile, panel, summary);
  expand.addEventListener('click', () => {
    if (expandedProfiles.has(profile.id)) expandedProfiles.delete(profile.id);
    else expandedProfiles.add(profile.id);
    panel.hidden = !expandedProfiles.has(profile.id);
    expand.setAttribute('aria-expanded', expandedProfiles.has(profile.id) ? 'true' : 'false');
  });
  tools.append(expand);
  block.append(tools);
  block.append(panel);
  container.append(block);
}

function tickedProfiles(data) {
  return data.browsers.flatMap(b => b.profiles.filter(p => !excluded.includes(p.id)));
}

function pruneStaleRoutes(arriving) {
  const ids = new Set((arriving || []).map(p => p.id));
  const kept = routes.filter(r => ids.has(r.profile));
  const changed = kept.length !== routes.length;
  routes = kept;
  return changed;
}

function syncDefaultArrivingRoutes(data) {
  let changed = false;
  for (const profile of data.arriving || []) {
    if (profile.destination === profile.fromBrowser) continue;
    if (routes.some(r => r.profile === profile.id)) continue;
    routes.push({ profile: profile.id, browser: profile.destination });
    changed = true;
  }
  return changed;
}

function renderArrivingSection(data) {
  const section = $('arriving-section');
  const arriving = data.arriving || [];
  if (local || !arriving.length) { section.hidden = true; return; }
  section.hidden = false;
  const from = arriving[0]?.fromDevice || data.target || 'your other computer';
  $('arriving-title').textContent = `Arriving from ${from}`;
  const container = $('arriving-profiles');
  container.replaceChildren();
  for (const profile of arriving) {
    const block = text('div', '', 'card profile-block arriving-block');
    const body = text('span', '', 'profile-body');
    body.append(
      text('span', profile.name, 'profile-title'),
      text('span', `From ${profile.fromBrowserDisplay}`, 'profile-dest'),
    );
    const pick = text('div', '', 'arriving-pick');
    const label = text('label', 'Put it into', 'group-label');
    const select = document.createElement('select');
    select.setAttribute('aria-label', `Browser on this computer for ${profile.name}`);
    for (const target of data.targets) {
      const option = text('option', target.display);
      option.value = target.name;
      option.disabled = !target.available;
      if (target.reason && !target.available) option.title = target.reason;
      select.append(option);
    }
    select.value = profile.destination;
    select.addEventListener('change', () => task(async () => {
      routes = routes.filter(r => r.profile !== profile.id);
      if (select.value !== profile.fromBrowser) routes.push({ profile: profile.id, browser: select.value });
      await preview();
    }));
    pick.append(label, select);
    if (profile.destinationNote) pick.append(text('p', profile.destinationNote, 'hint'));
    block.append(body, pick);
    container.append(block);
  }
}

function updateMoveButton(data) {
  const n = tickedProfiles(data).length;
  const arrivingN = (data.arriving || []).length;
  const total = n + arrivingN;
  $('move').disabled = !total;
  $('move').textContent = total ? `Move ${total} profile${total === 1 ? '' : 's'}` : 'Move';
}

async function preview(first = false) {
  if (!startInfo.pipeSet) return pipes('preview');
  if (!startInfo.paired && !local) return pairing();
  if (first) { excluded = []; routes = []; profileKinds = {}; expandedProfiles = new Set(); }
  try {
    let data;
    if (local) {
      const lp = await call('local_preview', localArgs());
      const slot = selectedSourceSlot();
      const picked = sourceProfiles().find(p => p.slot === slot);
      data = {
        target: lp.target,
        browsers: [{
          name: 'local', display: lp.source, skipped: lp.skipped || [],
          profiles: [{
            id: localProfileId(slot), name: sourceProfileTitle(lp.source, slot, picked?.name), ticked: true, isNew: false, destination: lp.target,
            logins: lp.logins, passwords: lp.passwords, cookies: lp.cookies, extensions: lp.extensions,
            bookmarks: lp.bookmarks, history: lp.history,
          }],
        }],
        targets: [], skipped: lp.skipped || [],
      };
    } else {
      if (!first && previewCache?.arriving) pruneStaleRoutes(previewCache.arriving);
      let draft = await call('preview_counts', { excluded, routes });
      if (syncDefaultArrivingRoutes(draft)) {
        data = await call('preview_counts', { excluded, routes });
      } else {
        data = draft;
      }
    }
    previewCache = data;
    if (first) excluded = data.browsers.flatMap(b => b.profiles.filter(p => !p.ticked).map(p => p.id));
    const arrivingN = (data.arriving || []).length;
    const empty = !data.browsers.length && !arrivingN;
    $('preview-empty').hidden = !empty;
    $('profiles').hidden = !data.browsers.length;
    $('preview-profiles-title').hidden = !data.browsers.length;
    $('move').hidden = empty;
    $('preview-step').hidden = local;
    $('preview-sub').textContent = local
      ? `Everything you tick stays on this computer.`
      : 'Review profiles and data types before you move.';
    renderRouteCard(data);
    renderArrivingSection(data);
    const container = $('profiles'); container.replaceChildren();
    const allProfiles = data.browsers.flatMap(b => b.profiles);
    ensureProfileKinds(allProfiles);
    $('kinds-all').hidden = allProfiles.length < 2;
    for (const browser of data.browsers) {
      for (const profile of browser.profiles) {
        renderProfileBlock(browser, profile, data, container);
      }
    }
    skips($('skipped'), [...data.skipped, ...data.browsers.flatMap(b => b.skipped)]);
    updateMoveButton(data);
    show('preview');
  } catch (error) {
    if (showEngineBlock(error, () => preview(first))) return;
    throw error;
  }
}

async function localPick() {
  const browsers = await call('local_browsers');
  for (const id of ['source', 'target']) { $(id).replaceChildren(); for (const browser of browsers) { const option = text('option', browser.display); option.value = browser.browser; $(id).append(option); } }
  if (browsers.length > 1) $('target').selectedIndex = 1;
  try {
    const byBrowser = await call('local_profiles');
    localProfilesByBrowser = Object.fromEntries((byBrowser || []).map(b => [b.browser, b.profiles || []]));
  } catch { localProfilesByBrowser = {}; }
  syncSourceProfiles();
  $('local-hint').textContent = browsers.length < 2 ? 'Open two supported browsers once to create their profiles, then return here.' : '';
  show('local');
}

function sourceProfiles() {
  return localProfilesByBrowser[$('source').value] || [{ slot: 'Default', name: 'Default' }];
}

function selectedSourceSlot() {
  return $('source-profile').value || preselectedSlot(sourceProfiles()) || 'Default';
}

function syncSourceProfiles() {
  const profiles = sourceProfiles();
  const select = $('source-profile');
  select.replaceChildren();
  for (const profile of profiles) {
    const option = text('option', slotLabel(profile.slot, profile.name));
    option.value = profile.slot;
    select.append(option);
  }
  const multi = needsProfilePick(profiles);
  if (multi) {
    const prompt = text('option', 'Choose a profile');
    prompt.value = '';
    select.prepend(prompt);
    select.value = '';
  } else if (profiles.length) {
    select.value = profiles[0].slot;
  }
  $('source-profile-label').hidden = !multi;
  select.hidden = !multi;
  syncLocalContinue();
}

function syncLocalContinue() {
  const unpicked = needsProfilePick(sourceProfiles()) && !$('source-profile').value;
  $('local-preview').disabled = $('source').options.length < 2 || $('source').value === $('target').value || unpicked;
}

$('source').addEventListener('change', syncSourceProfiles);
$('source-profile').addEventListener('change', syncLocalContinue);
$('target').addEventListener('change', syncLocalContinue);

const localArgs = () => ({
  source: $('source').value,
  target: $('target').value,
  sourceSlot: selectedSourceSlot(),
  targetSlot: 'Default',
});

async function localPreview() {
  if ($('source').value === $('target').value) throw new Error('Choose two different browsers.');
  if (needsProfilePick(sourceProfiles()) && !$('source-profile').value) throw new Error('Choose which profile to move.');
  try {
    local = true;
    await preview(true);
  } catch (error) {
    if (showEngineBlock(error, localPreview)) return;
    throw error;
  }
}

function showBlocked(title, sub, action) {
  retryAction = action;
  show('blocked');
  $('blocked-title').textContent = title.replace(/tap/gi, 'click');
  $('blocked-sub').textContent = sub;
}

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
    showBlocked(`Close ${browser} and click again`, `Move It can only move your things while ${browser} is closed.`, action);
    return true;
  }
  return false;
}

async function checkOpen(action) {
  const check = await call(
    local ? 'local_open_check' : 'browser_open_check',
    local ? localArgs() : { excluded, routes },
  );
  if (check.status === 'blocked') {
    showBlocked(`Close ${check.browser} and click again`, `Move It can only move your things while ${check.browser} is closed.`, action);
    return false;
  }
  return true;
}

function loadDonatePrefs() {
  try {
    const raw = localStorage.getItem('moveit-donate');
    if (raw) donateDismissed = !!JSON.parse(raw).dismissed;
    moveCount = Number(localStorage.getItem('moveit-move-count') || 0);
  } catch {}
}

function saveDonateDismissed() {
  donateDismissed = true;
  try { localStorage.setItem('moveit-donate', JSON.stringify({ dismissed: true })); } catch {}
}

function maybeShowDonate(success) {
  const card = $('donate-card');
  if (!success || donateDismissed) { card.hidden = true; return; }
  moveCount += 1;
  try { localStorage.setItem('moveit-move-count', String(moveCount)); } catch {}
  const show = moveCount === 1 || moveCount % 5 === 0;
  card.hidden = !show;
}

async function move() {
  if (!await checkOpen(move)) return;
  const profileKindsArg = buildProfileKindsPayload(previewCache || { browsers: [] });
  show('moving'); loaders.get('moving')?.setProgress(0); $('moving-line').textContent = 'Getting started';
  try {
    const args = local
      ? { ...localArgs(), profileKinds: profileKindsArg }
      : { excluded, routes, profileKinds: profileKindsArg };
    const report = await call(local ? 'local_move' : 'move_start', args);
    loaders.get('moving')?.setProgress(1);
    const sent = !local && Number(report.sentProfiles || 0) > 0;
    $('report').replaceChildren(...reportLines(report, { local, otherDevice: startInfo?.otherDevice }).map(line => {
      const row = text('div', '', 'row'); row.append(text('span', line)); return row;
    }));
    skips($('report-skips'), skipLines(report).map(reason => ({ reason })));
  const hadIssues = skipLines(report).length || report.routes?.some(r => r.status === 'failed');
    if (local) $('done-title').textContent = hadIssues ? 'Move finished with skips' : 'Move finished';
    else if (sent) {
      $('done-title').textContent = 'Sent';
      $('done-sub').hidden = false;
      $('done-sub').textContent = `Now open Move It on ${startInfo?.otherDevice || 'your other computer'} and tap Move there. It will ask which browser to put each profile in.`;
    } else {
      $('done-sub').hidden = true;
      $('done-title').textContent = hadIssues ? 'Move finished with skips' : 'Move finished';
    }
    maybeShowDonate(!hadIssues);
    show('done');
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

async function logs() {
  const lines = await call('logs_recent');
  $('log-lines').replaceChildren(...lines.slice().reverse().map(line => text('p', `${new Date(line.at_unix * 1000).toLocaleString()} · ${line.level}: ${line.message}`)));
  if (!lines.length) $('log-lines').append(text('p', 'No activity in this session yet.'));
  show('logs');
}

const aboutIcon = (label, svg) => {
  const span = document.createElement('span');
  span.className = 'about-link-icon';
  span.setAttribute('aria-hidden', 'true');
  span.innerHTML = svg;
  const btn = text('button', '', 'about-link');
  btn.type = 'button';
  btn.setAttribute('aria-label', label);
  btn.append(span, text('span', label, 'about-link-label'));
  return btn;
};

function buildAboutLinks() {
  const wrap = $('about-links');
  wrap.replaceChildren();
  const links = [
    ['GitHub', 'https://github.com/0xovo/move-it', '<svg viewBox="0 0 16 16" width="18" height="18" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.65 7.65 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>'],
    ['X', 'https://x.com/0xovoo', '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>'],
    ['Ko-fi', 'https://ko-fi.com/0xovo', '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 8h12v8a4 4 0 0 1-4 4H10a4 4 0 0 1-4-4V8z"/><path d="M6 8c0-2 1.5-4 4-4h4c2.5 0 4 2 4 4"/></svg>'],
    ['Website', 'https://getmoveit.tech', '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>'],
  ];
  for (const [label, url, svg] of links) {
    const btn = aboutIcon(label, svg);
    btn.addEventListener('click', () => void openLink(url));
    wrap.append(btn);
  }
}

on('start-cross', home);
$('start-local').addEventListener('click', () => task(localPick));
on('about-home', home);
on('about-link', async () => { buildAboutLinks(); show('about'); });
$('home-link').addEventListener('click', () => { if (signInWaiting) { void cancelActiveSignIn(() => task(home)); return; } task(home); });
$('pipe-sign-in-copy').addEventListener('click', () => { void copySignInLink(); });
$('pipe-sign-in-url').addEventListener('focus', (e) => e.target.select());
on('preview-button', () => { local = false; return preview(true); });
on('pair-button', () => pairing());
on('undo', () => undo());
on('preview-back', home);
$('donate-close').addEventListener('click', () => { $('donate-card').hidden = true; });
$('donate-dismiss').addEventListener('click', () => { saveDonateDismissed(); $('donate-card').hidden = true; });
$('donate-kofi').addEventListener('click', () => void openLink('https://ko-fi.com/0xovo'));
$('donate-share').addEventListener('click', async () => {
  const share = 'https://x.com/intent/post?text=' + encodeURIComponent('Move It packs your whole browser for another device — ') + '&url=' + encodeURIComponent(SHARE_URL);
  try { await navigator.clipboard.writeText(SHARE_URL); notice('Copied getmoveit.tech to your clipboard.'); } catch { notice('Copy https://getmoveit.tech to share Move It.'); }
  await openLink(share);
});

async function usePipe() {
  if (busy || signInWaiting || !selectedPipe) return;
  if (selectedPipe.cloud && ['google', 'dropbox'].includes(selectedPipe.kind)) {
    const byok = usingByokKeys;
    if (!selectedPipe.connected) {
      signInAbort = false;
      setSignInUi(true);
      notice('Finish signing in in your browser, then return here.');
      try {
        const begin = await call('pipe_sign_in_begin', { provider: selectedPipe.kind, byok });
        if (signInWaiting) showSignInLink(begin);
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
      storageName = storageLabelFromKind(selectedPipe.kind);
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
    storageName = storageLabelFromKind(result.kind || selectedPipe.kind);
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
on('have-code', () => pairing(true));
on('show-code', () => pairing());
on('check-pair', async () => { startInfo = await call('welcome_start'); if (startInfo.otherDevice) { await preview(true); notice(`Paired with ${startInfo.otherDevice}.`); } else notice('Waiting for your other device to enter the code.'); });
$('pair-form').addEventListener('submit', event => { event.preventDefault(); task(async () => {
  const code = $('code-input').value.replace(/\s+/g, '');
  $('code-input').value = code.replace(/(\d{3})(\d+)/, '$1 $2').trim();
  const result = await call('pair_enter_code', { code: $('code-input').value.replace(/\s/g, '') });
  $('code-input').value = '';
  if (result.status === 'success') { startInfo = await call('welcome_start'); await preview(true); notice(`Paired with ${result.otherDevice}.`); }
  else if (result.status === 'wrong') notice(`That code did not match. ${result.triesLeft} tries left.`, true);
  else notice(result.status === 'need_new_code' ? 'Show a new code on the other device.' : 'No pairing offer found. Check the shared folder and show a new code.', true);
}); });
on('local-preview', localPreview);
on('move', move);
on('done-button', home);
on('retry', async () => { if (retryAction) await retryAction(); });
on('force-undo', async () => { $('undo-confirm').close(); await undo(true); });
on('cancel-undo', async () => $('undo-confirm').close());
on('export-logs', async () => { if (await call('export_logs')) notice('Log report saved.'); });
on('refresh-logs', logs);
on('boot-retry', () => task(boot));
on('boot-export', async () => { if (api && await call('export_logs')) notice('Log report saved.'); });
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
    task(() => ({ local: () => { local = true; return localPick(); }, logs, pipe: pipes })[button.dataset.nav]());
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
  } catch {}
}

function showBootFail(message) {
  $('boot-fail-msg').textContent = message;
  for (const section of document.querySelectorAll('main > .state')) section.hidden = section.id !== 'boot-fail';
}

async function boot() {
  loadDonatePrefs();
  if (!api) {
    show('welcome');
    notice('Open Move It in its desktop app to use your browser data.', true);
    document.querySelectorAll('button:not(#about-link)').forEach(b => { if (!b.closest('#welcome')) b.disabled = true; });
    return;
  }
  try {
    const version = await api.app.getVersion();
    for (const el of document.querySelectorAll('[data-version]')) el.textContent = `Move It v${version}`;
    await api.event.listen('move-progress', ({ payload }) => { loaders.get('moving')?.setProgress(payload.frac); $('moving-line').textContent = payload.line; refreshUpdateNotice(); });
    await api.event.listen('update-available', ({ payload }) => { pendingUpdate = payload; refreshUpdateNotice(); });
    const ctx = await call('updater_context');
    packageManaged = !!ctx.packageManaged; githubUrl = ctx.githubUrl || GITHUB_RELEASE;
    void runBackgroundUpdateCheck();
    new MutationObserver(() => refreshUpdateNotice()).observe($('moving'), { attributes: true, attributeFilter: ['hidden'] });
    startInfo = await call('welcome_start');
    if (startInfo.pipeKind) storageName = storageLabelFromKind(startInfo.pipeKind);
    if (startInfo.paired || startInfo.pipeSet) await home();
    else show('welcome');
  } catch (error) {
    showBootFail(String(error));
  }
}

for (const el of document.querySelectorAll('.lemur')) {
  MoveItLoader.create(el, { frames: window.MOVEIT_FRAMES, base: 'design/loader/frames/' }).then(loader => { loader.setMode(el.dataset.mode); loaders.set(el.closest('section').id, loader); }).catch(() => { el.textContent = 'Move It'; });
}

task(boot);

function openKindsAll() {
  const list = $('kinds-all-list'); list.replaceChildren();
  const ids = (previewCache?.browsers || []).flatMap(b => b.profiles.map(p => p.id));
  for (const def of kindDefs) {
    const row = text('label', '', 'card kind-row');
    const check = document.createElement('input');
    check.type = 'checkbox'; check.value = def.id;
    check.checked = ids.every(id => selectedKindsFor(id).includes(def.id));
    const body = text('span', '', 'kind-body'); body.append(text('b', def.label));
    row.append(check, body); list.append(row);
  }
  $('kinds-all-dialog').showModal();
}
$('kinds-all').addEventListener('click', openKindsAll);
$('kinds-all-cancel').addEventListener('click', () => $('kinds-all-dialog').close());
$('kinds-all-apply').addEventListener('click', () => {
  const kinds = [...$('kinds-all-list').querySelectorAll('input:checked')].map(c => c.value);
  if (!kinds.length) return;
  for (const b of previewCache?.browsers || []) for (const p of b.profiles) profileKinds[p.id] = [...kinds];
  $('kinds-all-dialog').close();
  task(() => preview());
});

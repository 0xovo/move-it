import { test } from 'node:test';
import assert from 'node:assert/strict';
import { aggregateKinds, kindSummaryText, reportLines, skipLines, formatAttentionLine, slotLabel, sourceProfileTitle, localProfileId, needsProfilePick, preselectedSlot } from '../src/model.js';

test('kind summary names all data or a partial count', () => {
  assert.equal(kindSummaryText(5), 'All data');
  assert.equal(kindSummaryText(3), '3 of 5 kinds');
});

test('saved password count is the logins total, not logins plus passwords', () => {
  // Core passwords is a subset of logins (rows with a non-empty password
  // value), not a separate store. Summing them double-counts.
  // Staged Brave Profile 1 case: 1 login row, that row has a password.
  assert.equal(aggregateKinds({ logins: 1, passwords: 1 }).passwords, 1);
  // 3 exported logins, 2 with a password value: the move carries all 3.
  assert.equal(aggregateKinds({ logins: 3, passwords: 2 }).passwords, 3);
  assert.equal(aggregateKinds({ logins: 0, passwords: 0 }).passwords, 0);
});

test('sending shows what was sent, not zero received', () => {
  const lines = reportLines({ wroteBox: true, sentProfiles: 4, sentLogins: 35, sentHistoryUrls: 8554, sentCookies: 1, cookies: 0, logins: 0, historyUrls: 0, boxesRead: 0 });
  assert.equal(lines[0], 'Sent 4 profiles: 35 saved passwords, 8,554 history items, 1 website login');
  assert(!lines.some(s => /Received/.test(s)));
});

test('a box already waiting still counts as sent', () => {
  const lines = reportLines({ wroteBox: false, sentProfiles: 1, sentLogins: 1, sentHistoryUrls: 0, sentCookies: 0 });
  assert.match(lines[0], /^Sent 1 profile: 1 saved password/);
});

test('nothing to do says so', () => {
  assert.deepEqual(reportLines({ wroteBox: false }), ['Nothing new to move.']);
});

test('skip lines use plain wording', () => {
  const lines = skipLines({ boxesSkipped: 1, skipped: [] });
  assert.match(lines[0], /could not be read/);
});

test('attention lines drop App-Bound on Linux', () => {
  const line = formatAttentionLine({ browser: 'Brave', reason: '14 App-Bound cookies' });
  assert.match(line, /stay on this device/);
  assert.doesNotMatch(line, /App-Bound/i);
});

test('attention lines name Windows locks when on Windows', () => {
  const line = formatAttentionLine(
    { browser: 'Chrome', reason: '14 saved logins are App-Bound and cannot be moved' },
    { windows: true },
  );
  assert.match(line, /14 logins are locked by Chrome on Windows/);
});

test('slot label adds the profile name only when it differs from the folder', () => {
  assert.equal(slotLabel('Profile 1', '0xovo'), 'Profile 1 (0xovo)');
  assert.equal(slotLabel('Profile 1', 'Profile 1'), 'Profile 1');
  assert.equal(slotLabel('Default', ''), 'Default');
  assert.equal(slotLabel('Default', null), 'Default');
});

test('counts screen title names the browser and the picked profile', () => {
  assert.equal(sourceProfileTitle('Brave', 'Profile 1', '0xovo'), 'Brave / Profile 1 (0xovo)');
  assert.equal(sourceProfileTitle('Brave', 'Default', 'Default'), 'Brave / Default');
});

test('local profile id mirrors the core kind id', () => {
  assert.equal(localProfileId('Default'), 'local:default');
  assert.equal(localProfileId('Profile 1'), 'local:profile-1');
  assert.equal(localProfileId('Profile 12'), 'local:profile-12');
});

test('a pick is required only when a browser holds more than one profile', () => {
  assert.equal(needsProfilePick([]), false);
  assert.equal(needsProfilePick([{ slot: 'Default' }]), false);
  assert.equal(needsProfilePick([{ slot: 'Default' }, { slot: 'Profile 1' }]), true);
  assert.equal(needsProfilePick(null), false);
});

test('a lone profile is preselected, several are not', () => {
  assert.equal(preselectedSlot([{ slot: 'Profile 2' }]), 'Profile 2');
  assert.equal(preselectedSlot([{ slot: 'Default' }, { slot: 'Profile 1' }]), null);
  assert.equal(preselectedSlot([]), null);
});

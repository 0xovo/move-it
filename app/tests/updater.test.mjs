import { test } from 'node:test';
import assert from 'node:assert/strict';
import { updateNoticeText, updatePrimaryLabel, shouldShowUpdateNotice, shouldDeferUpdatePrompt } from '../src/update.js';

const gate = (overrides = {}) => ({
  pendingVersion: '1.2.0',
  dismissedVersion: null,
  engineIdle: true,
  onMoveScreen: false,
  uiBusy: false,
  ...overrides,
});

test('notice copy names the waiting version', () => {
  assert.equal(updateNoticeText('2.0.0'), 'Move It 2.0.0 is ready');
});

test('package-managed installs point people to GitHub', () => {
  assert.equal(updatePrimaryLabel(true), 'Get it on GitHub');
  assert.equal(updatePrimaryLabel(false), 'Update now');
});

test('update notice waits for a quiet engine and screen', () => {
  assert.equal(shouldShowUpdateNotice(gate()), true);
  assert.equal(shouldShowUpdateNotice(gate({ pendingVersion: null })), false);
  assert.equal(shouldShowUpdateNotice(gate({ dismissedVersion: '1.2.0' })), false);
  assert.equal(shouldShowUpdateNotice(gate({ engineIdle: false })), false);
  assert.equal(shouldShowUpdateNotice(gate({ onMoveScreen: true })), false);
  assert.equal(shouldShowUpdateNotice(gate({ uiBusy: true })), false);
});

test('defer matches the same operation gate as the notice', () => {
  assert.equal(shouldDeferUpdatePrompt(gate({ engineIdle: false })), true);
  assert.equal(shouldDeferUpdatePrompt(gate({ onMoveScreen: true })), true);
  assert.equal(shouldDeferUpdatePrompt(gate()), false);
});

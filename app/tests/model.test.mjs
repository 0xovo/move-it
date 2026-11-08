import { test } from 'node:test';
import assert from 'node:assert/strict';
import { totals, reportLines } from '../src/model.js';
test('counts come from every browser and handle an empty preview', () => {
  assert.equal(totals([{ logins: 3 }, { logins: 4 }]).logins, 7);
  assert.equal(totals([]).logins, 0);
});
test('sending a box does not claim the other device received it', () => {
  const lines = reportLines({ wroteBox: true, cookies: 0, routes: [{ profile: 'work', status: 'failed', reason: 'browser open' }] });
  assert(lines.some(s => s.includes('Run Move It on the other device')));
  assert(lines.some(s => s.includes('browser open')));
});

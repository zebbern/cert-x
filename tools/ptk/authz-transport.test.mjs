import test from 'node:test';
import assert from 'node:assert/strict';
import { createIsolatedTransport } from '../../security/compat/authz-transport.mjs';

const input = () => ({ request: { url: 'https://target.test/item?a=1', method: 'GET', headers: [{ name: 'Cookie', value: 'stale' }, { name: 'Authorization', value: 'stale' }, { name: 'Api-Key', value: 'stale' }], body: '' }, credentials: [], credentialNames: ['api-key'], scope: { origins: ['https://target.test'], excludePaths: [] }, deadline: Date.now() + 10000 });
function fixture({ setupFails = false, cleanupFails = false, fetchFails = false, unsupported = false, prior = [] } = {}) {
  const updates = [], fetches = []; let rules = prior;
  const api = { runtime: { id: 'abcdefghijklmnopabcdefghijklmnop' }, declarativeNetRequest: {
    getSessionRules: async () => rules,
    isRegexSupported: async () => ({ isSupported: !unsupported }),
    updateSessionRules: async change => { updates.push(change); if (change.addRules?.length) { if (setupFails) throw Error('rule rejected'); rules.push(...change.addRules); } else if (cleanupFails) throw Error('cleanup rejected'); rules = rules.filter(rule => !change.removeRuleIds?.includes(rule.id)); },
  } };
  const send = createIsolatedTransport({ api, fetchImpl: async (url, opts) => { fetches.push({ url, opts }); if (fetchFails) throw Error('network unavailable'); return new Response('{"ok":true}', { status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': 'poison=true' } }); } });
  return { send, updates, fetches, rules: () => rules };
}
test('isolated transport omits ambient credentials/cache, installs exact Cookie rule and strips credential union', async () => {
  const f = fixture(), value = input(); value.request.headers.push({ name: 'X-Owner-Auth-Token', value: 'unselected-owner-secret' }); value.credentials = [{ name: 'Cookie', value: 'account=selected' }, { name: 'Authorization', value: 'Bearer selected' }];
  const result = await f.send(value); assert.equal(result.status, 200); assert.equal(f.rules().length, 0);
  const { opts } = f.fetches[0]; assert.equal(opts.credentials, 'omit'); assert.equal(opts.cache, 'no-store'); assert.equal(opts.redirect, 'manual'); assert.equal(opts.headers.get('cookie'), null); assert.equal(opts.headers.get('api-key'), null); assert.equal(opts.headers.get('authorization'), 'Bearer selected');
  assert.equal(opts.headers.get('x-owner-auth-token'), null);
  const rule = f.updates.find(update => update.addRules)?.addRules[0];
  assert.equal(rule.condition.regexFilter, '^https://target\\.test/item\\?a=1$'); assert.deepEqual(rule.condition.requestMethods, ['get']);
  assert.deepEqual(rule.action.requestHeaders.find(header => header.header === 'cookie'), { header: 'cookie', operation: 'set', value: 'account=selected' });
  assert.ok(rule.action.responseHeaders.some(header => header.header === 'set-cookie' && header.operation === 'remove'));
});
test('setup/regex failures do not dispatch; transport errors still remove credential rules', async () => {
  for (const option of ['setupFails', 'unsupported', 'fetchFails']) {
    const f = fixture({ [option]: true }); await assert.rejects(f.send(input())); assert.equal(f.fetches.length, option === 'fetchFails' ? 1 : 0); assert.equal(f.rules().length, 0);
  }
});
test('cleanup failure poisons subsequent dispatch until runtime reload', async () => {
  const f = fixture({ cleanupFails: true }); await assert.rejects(f.send(input()), /cleanup failed/); await assert.rejects(f.send(input()), /cleanup failed/); assert.equal(f.fetches.length, 1);
});
test('startup removes interrupted owned rules, preserves unrelated rules, and stop before dispatch cleans up', async () => {
  const own = { id: 1800000000, priority: 1000000, condition: { initiatorDomains: ['abcdefghijklmnopabcdefghijklmnop'] } }, other = { id: 123, priority: 1, condition: {} };
  const f = fixture({ prior: [own, other] }), value = input(); value.beforeDispatch = async () => { throw Error('stopped'); };
  await assert.rejects(f.send(value), /stopped/); assert.equal(f.fetches.length, 0); assert.deepEqual(f.rules(), [other]);
});

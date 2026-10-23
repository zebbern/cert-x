import test from 'node:test';
import assert from 'node:assert/strict';
import { createAccessRunner, validateAccessPlan } from '../../security/compat/authz-core.mjs';
import { createTargetedRunner } from '../../security/compat/dast-core.mjs';

const clone = value => JSON.parse(JSON.stringify(value));
const origin = 'https://target.test';
const request = path => ({ url: origin + path, method: 'GET', headers: [{ name: 'Cookie', value: 'captured-stale' }, { name: 'Authorization', value: 'Bearer stale' }], body: '' });
const account = id => ({ id, label: 'Account ' + id, revision: 1, headers: [{ name: 'Cookie', value: 'session=private-' + id }], probe: { request: request('/me'), claims: [{ pointer: '/id', expected: id }] } });
const plan = () => ({ batchId: 'access-one', owner: 'chat-one', workspaceId: 'workspace-one', origin, tabId: 1, scope: { origins: [origin], excludePaths: ['/excluded'] }, budget: { maxRequests: 100, maxRequestsPerSecond: 1, concurrency: 1, durationSeconds: 300 }, accounts: [account('a'), account('b')], cases: [{ id: 'object-a', label: 'Private object', request: request('/objects/a'), ownerAccountId: 'a', readOnly: true, evidence: { object: { pointer: '/id', expected: 'object-private-a' }, protected: { pointer: '/secret', expected: 'PRIVATE-CANARY' } }, expectations: [{ accountId: 'b', expected: 'deny' }, { accountId: 'anonymous', expected: 'deny' }] }] });
const json = (body, status = 200) => ({ status, body: JSON.stringify(body), contentType: 'application/json', opaque: false });
function fixture({ leak = false, missingEvidence = false, wrongObject = false, csrf = false, html = false, graphql = false, invalidJson = false, revoked = false, drift = false, repeatFails = false, anonNull = false, anonMissing = false, ownerMismatch = false, samePrincipal = false, distinctRole = false, deniedStatus = 403, disclosureStatus = 200, errorProtected = false, deferred = false, persist = async () => {}, acquire, release, isBusy } = {}) {
  let clock = 1000, resolveSend; const sent = [], probes = new Map(), objects = new Map();
  const runner = createAccessRunner({ now: () => clock, sleep: async ms => { clock += ms; }, persist, acquire, release, isBusy,
    send: async input => {
      await input.beforeDispatch(); const id = input.credentials.find(header => header.name === 'Cookie')?.value.split('-').at(-1) || 'anonymous';
      sent.push({ at: clock, id, path: new URL(input.request.url).pathname, input });
      if (deferred) await new Promise(resolve => resolveSend = resolve);
      if (new URL(input.request.url).pathname === '/me') {
        probes.set(id, (probes.get(id) || 0) + 1);
        if (id === 'anonymous') return anonNull ? json({ id: null }) : anonMissing ? json({}) : json({ error: 'unauthorized' }, 401);
        if (id === 'a' && ownerMismatch) return json({ id: 'wrong-owner' });
        if (id === 'b' && (revoked || drift && probes.get(id) > 1)) return json({ id: 'different-account' });
        if (samePrincipal) return json({ id: 'a', role: id === 'b' && distinctRole ? 'other-role' : 'reader' });
        return json({ id });
      }
      objects.set(id, (objects.get(id) || 0) + 1);
      if (id === 'a') return json({ id: 'object-private-a', secret: 'PRIVATE-CANARY' });
      if (csrf) return json({ error: 'CSRF token invalid' }, 403);
      if (html) return { status: 403, contentType: 'text/html', body: '<html>Sign in</html>' };
      if (graphql) return json({ data: { id: 'object-private-a', secret: 'PRIVATE-CANARY' }, errors: [{ message: 'denied' }] });
      if (invalidJson) return { status: 403, contentType: 'application/json', body: '{"secret":"wrong","secret":"PRIVATE-CANARY"}' };
      if (errorProtected) return json({ error: 'forbidden', secret: 'PRIVATE-CANARY' }, 403);
      if (leak && !(repeatFails && objects.get(id) > 1)) return json({ id: wrongObject ? 'own-other-object' : 'object-private-a', ...(missingEvidence ? {} : { secret: 'PRIVATE-CANARY' }) }, disclosureStatus);
      return json({ error: 'denied' }, deniedStatus);
    } });
  return { runner, sent, finish: () => resolveSend?.(), advance: ms => clock += ms };
}

test('access plan validates read-only declarations, scope, evidence, account identity and credential headers', () => {
  assert.doesNotThrow(() => validateAccessPlan(plan()));
  const changes = [value => value.cases[0].readOnly = false, value => value.cases[0].request.method = 'DELETE', value => value.cases[0].request.url = origin + '/excluded/a', value => value.cases[0].evidence.protected.pointer = '/id', value => value.cases[0].evidence.protected.expected = '', value => value.accounts[0].headers.push({ name: 'Cookie', value: 'duplicate' }), value => value.accounts[0].headers[0].value += '\r\nInjected: true', value => value.accounts[0].probe.request.method = 'POST'];
  for (const change of changes) { const value = plan(); change(value); assert.throws(() => validateAccessPlan(value)); }
});
test('owned account runner allows user-configured request duration and rate budgets above the previous ceilings',async()=>{
  const f=fixture(),value=plan();value.budget={maxRequests:2500,durationSeconds:7200,maxRequestsPerSecond:20,concurrency:1};
  assert.doesNotThrow(()=>validateAccessPlan(value));await f.runner.run(value);await f.runner.wait(value);assert.equal(f.runner.status(value).state,'completed');
  assert.ok(f.sent.length>1);for(let index=1;index<f.sent.length;index++)assert.ok(f.sent[index].at-f.sent[index-1].at>=50);
  assert.throws(()=>validateAccessPlan({...value,budget:{...value.budget,concurrency:2}}),/concurrency/);
});

test('header-only access tests reject recognizable credentials in URLs and POST bodies before dispatch', () => {
  for (const key of ['access_token', 'csrf-token', 'password', 'session[id]', 'auth.token', 'api_key']) {
    const value = plan(); value.cases[0].request.url += '?' + encodeURIComponent(key) + '=hidden-owner-credential'; assert.throws(() => validateAccessPlan(value), /header\/cookie/);
  }
  for (const body of ['{"input":{"access_token":"hidden-owner"}}', '{"auth":{"value":"hidden-owner"}}', '{"password":"hidden-owner"}']) {
    const value = plan(); value.cases[0].request.method = 'POST'; value.cases[0].request.body = body; value.cases[0].request.headers.push({ name: 'Content-Type', value: 'application/json' }); assert.throws(() => validateAccessPlan(value), /header\/cookie/);
  }
  const form = plan(); form.accounts[0].probe.readOnly = true; form.accounts[0].probe.request = { ...request('/me'), method: 'POST', body: 'id=1&_csrf=hidden-owner', headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }] }; assert.throws(() => validateAccessPlan(form), /header\/cookie/);
  const safe = plan(); safe.cases[0].request = { ...request('/objects'), method: 'POST', body: '{"id":1,"authorId":"writer","keep":true}', headers: [{ name: 'Content-Type', value: 'application/json' }] }; assert.doesNotThrow(() => validateAccessPlan(safe));
});

test('verified comparison distinguishes expected denial and repeated unexpected access without leaking private evidence', async () => {
  for (const leak of [false, true]) {
    const f = fixture({ leak }), value = plan(); await f.runner.run(value); await f.runner.wait(value); const result = f.runner.result(value);
    assert.equal(result.state, 'completed'); assert.equal(result.cells.length, 2); assert.ok(result.cells.every(cell => cell.outcome === (leak ? 'unexpected_access' : 'expected_denial')));
    assert.equal(result.requestsSent, leak ? 15 : 9); assert.equal(result.requestsSent, f.sent.length);
    assert.ok(f.sent.every((item, index) => !index || item.at - f.sent[index - 1].at >= 1000));
    assert.ok(!JSON.stringify(result).includes('PRIVATE-CANARY')); assert.ok(!JSON.stringify(result).includes('object-private-a')); assert.ok(!JSON.stringify(result).includes('session=private'));
    assert.equal(result.cells[0].baseline.objectPointer, '/id'); assert.equal(result.cells[0].baseline.protectedPointer, '/secret'); assert.ok(result.cells[0].baseline.responseByteLength > 0);
    assert.equal((await f.runner.run(value)).accepted, false); assert.equal(f.sent.length, result.requestsSent);
  }
});

test('protected evidence, object identity, stable sessions and repeated access are required', async () => {
  for (const option of ['missingEvidence', 'wrongObject', 'csrf', 'html', 'graphql', 'invalidJson', 'revoked', 'drift', 'repeatFails']) {
    const f = fixture({ leak: true, [option]: true }), value = plan(); value.cases[0].expectations = [{ accountId: 'b', expected: 'deny' }];
    await f.runner.run(value); await f.runner.wait(value); const result = f.runner.result(value);
    assert.equal(result.state, 'completed', option); assert.equal(result.cells[0].outcome, 'inconclusive', option); assert.equal(result.findings.length, 0, option);
  }
});

test('explicit expected allow, ordinary denial statuses and failed owner verification remain distinct', async () => {
  const allowed = fixture({ leak: true }), expected = plan(); expected.cases[0].expectations = [{ accountId: 'b', expected: 'allow' }];
  await allowed.runner.run(expected); await allowed.runner.wait(expected); assert.equal(allowed.runner.result(expected).cells[0].outcome, 'expected_access'); assert.equal(allowed.sent.length, 6);
  for (const deniedStatus of [401, 403, 404]) {
    const denied = fixture({ deniedStatus }), value = plan(); value.cases[0].expectations = [{ accountId: 'b', expected: 'deny' }]; await denied.runner.run(value); await denied.runner.wait(value); assert.equal(denied.runner.result(value).cells[0].outcome, 'expected_denial');
  }
  const mismatch = fixture({ ownerMismatch: true }), value = plan(); await mismatch.runner.run(value); await mismatch.runner.wait(value);
  assert.ok(mismatch.runner.result(value).cells.every(cell => cell.outcome === 'inconclusive')); assert.equal(mismatch.sent.length, 1); assert.equal(mismatch.sent[0].path, '/me');
});

test('owner-deny contradictions and indistinguishable identity claims cannot produce cross-account findings', async () => {
  const contradictory = plan(); contradictory.cases[0].expectations = [{ accountId: 'a', expected: 'deny' }];
  assert.throws(() => validateAccessPlan(contradictory), /baseline owner/);
  for (const distinctRole of [false, true]) {
    const value = plan(); value.cases[0].expectations = [{ accountId: 'b', expected: 'deny' }];
    value.accounts[0].probe.claims = [{ pointer: '/id', expected: 'a' }, { pointer: '/role', expected: 'reader' }];
    value.accounts[1].probe.claims = [{ pointer: '/role', expected: distinctRole ? 'other-role' : 'reader' }, { pointer: '/id', expected: 'a' }];
    const f = fixture({ leak: true, samePrincipal: true, distinctRole }); await f.runner.run(value); await f.runner.wait(value); const result = f.runner.result(value);
    assert.equal(result.cells[0].outcome, distinctRole ? 'unexpected_access' : 'inconclusive');
    if (!distinctRole) { assert.match(result.cells[0].reason, /do not distinguish/); assert.equal(f.sent.length, 3); }
  }
});

test('denial status does not conceal reproduced protected data, while partial error disclosure stays inconclusive', async () => {
  const disclosed = fixture({ leak: true, disclosureStatus: 403 }), value = plan();
  await disclosed.runner.run(value); await disclosed.runner.wait(value); const result = disclosed.runner.result(value);
  assert.ok(result.cells.every(cell => cell.outcome === 'unexpected_access')); assert.equal(result.requestsSent, 15);
  assert.ok(result.cells.every(cell => cell.evidence.status === 403 && cell.confirmation.status === 403));
  assert.ok(!JSON.stringify(result).includes('PRIVATE-CANARY'));
  const partial = fixture({ errorProtected: true }), partialPlan = plan();
  await partial.runner.run(partialPlan); await partial.runner.wait(partialPlan);
  assert.ok(partial.runner.result(partialPlan).cells.every(cell => cell.outcome === 'inconclusive')); assert.equal(partial.runner.result(partialPlan).findings.length, 0);
});

test('anonymous requires denial or explicit null principal, never a missing claim', async () => {
  for (const options of [{ anonNull: true }, { anonMissing: true }]) {
    const f = fixture(options), value = plan(); value.cases[0].expectations = [{ accountId: 'anonymous', expected: 'deny' }];
    await f.runner.run(value); await f.runner.wait(value); assert.equal(f.runner.result(value).cells[0].outcome, options.anonNull ? 'expected_denial' : 'inconclusive');
    assert.ok(f.sent.filter(item => item.id === 'anonymous').every(item => item.input.credentials.length === 0));
  }
});

test('verification returns only safe identity outcome and honors global reservation', async () => {
  let locked = false; const acquire = () => { if (locked) return false; locked = true; return true; }, release = () => { locked = false; };
  const f = fixture({ deferred: true, acquire, release }), value = plan(), verify = { ...value, account: value.accounts[0] };
  const waiting = f.runner.verify(verify);
  for (let i = 0; i < 30 && !f.sent.length; i++) await Promise.resolve();
  assert.equal(locked, true); await assert.rejects(f.runner.run(value), /already active/);
  const injection = createTargetedRunner({ acquire, release, loadPtk: async () => { throw Error('must not reach'); } });
  const injectionPlan = { ...value, families: ['xss'], requests: [{ ...request('/search?q=a'), id: 'capture', allowReplay: true, parameters: [{ location: 'query', name: 'q', index: 0 }] }] };
  await assert.rejects(injection.run(injectionPlan), /already active/);
  f.finish(); const result = await waiting; assert.equal(result.verified, true); assert.equal(result.requestsSent, 1); assert.equal(locked, false); assert.ok(!JSON.stringify(result).includes('private-a'));
});

test('all identity probes count toward budgets and interrupted batches never replay', async () => {
  const f = fixture(), value = plan(); value.budget.maxRequests = 2; await f.runner.run(value); await f.runner.wait(value);
  assert.equal(f.runner.status(value).state, 'budget_exhausted'); assert.equal(f.sent.length, 2);
  const restored = createAccessRunner({ send: async () => { throw Error('must not run'); }, interrupted: [f.runner.status(value)] });
  assert.equal((await restored.run(value)).accepted, false); assert.throws(() => restored.result(value), /after restart/);
  const timed = fixture(), timedPlan = plan(); timedPlan.budget.durationSeconds = 1; await timed.runner.run(timedPlan); await timed.runner.wait(timedPlan);
  assert.equal(timed.runner.status(timedPlan).state, 'expired'); assert.equal(timed.sent.length, 1);
});

test('Stop keeps an in-flight access request bounded and cancels queued probes', async () => {
  const f = fixture({ deferred: true }), value = plan(); await f.runner.run(value);
  for (let i = 0; i < 30 && !f.sent.length; i++) await Promise.resolve();
  assert.equal((await f.runner.stop(value)).state, 'stopping'); f.finish(); await f.runner.wait(value);
  assert.equal(f.runner.status(value).state, 'stopped'); assert.equal(f.sent.length, 1); assert.equal(f.runner.hasActive(), false);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { createTargetedRunner, validatePlan, scopedUrl, redirectVerdict } from '../../security/compat/dast-core.mjs';
const clone = value => JSON.parse(JSON.stringify(value));
const base = (overrides = {}) => ({ batchId: 'batch-one', owner: 'chat-one', tabId: 1, origin: 'https://target.test', families: ['xss'],
  scope: { origins: ['https://target.test'], excludePaths: ['/admin'] }, budget: { maxRequests: 100, maxRequestsPerSecond: 1, concurrency: 1, durationSeconds: 300 },
  requests: [{ id: 'capture-one', url: 'https://target.test/search?q=hello&keep=constant', method: 'GET', body: '', allowReplay: true,
    headers: [{ name: 'Cookie', value: 'session=PRIVATE-COOKIE' }, { name: 'Authorization', value: 'Bearer PRIVATE-TOKEN' }], parameters: [{ location: 'query', name: 'q', index: 0 }] }], ...overrides });
function fixture({ vulnerable = true, status = 200, leak = false, deferred = false, saved = [], delayReservation = false, storageLatency = false, unstableControl = false } = {}) {
  let clock = 1000, release, releaseSave, saveHeld = false;
  const sends = [];
  const module = {
    parse: seed => ({ request: { url: seed.url, method: seed.method, body: { text: seed.body }, headers: seed.headers }, metadata: {} }),
    build: (schema, parameters) => parameters.flatMap(parameter => [1, 2, 3].map(index => {
      const next = clone(schema), url = new URL(next.request.url); url.searchParams.set(leak ? 'keep' : parameter.name, 'hello<script>PTK' + index + '</script>'); next.request.url = url.href;
      return { schema: next, parameter, attackId: 'xss_' + index, attackName: 'PTK fixture', payload: '<script>PTK' + index + '</script>' };
    })),
    control: (schema, parameter) => { const next = clone(schema), url = new URL(next.request.url); url.searchParams.set(parameter.name, 'hello-control'); next.request.url = url.href; return next; },
    validate: (attack, original) => ({ success: attack.response.body.includes('<script>') && !original.response.body.includes('<script>'), proof: attack.response.body }),
    send: async schema => {
      sends.push({ at: clock, schema: clone(schema) });
      if (deferred) await new Promise(resolve => release = resolve);
      const value = new URL(schema.request.url).searchParams.get('q');
      return { ...schema, response: { statusCode: status, body: unstableControl && value === 'hello-control' ? '<script>unrelated-state-change</script>' : vulnerable ? value : value.replaceAll('<', '&lt;'), timeMs: 5 } };
    },
  };
  const runner = createTargetedRunner({ loadPtk: async () => module, now: () => clock, sleep: async ms => { clock += ms; },
    persist: async records => { saved.push(clone(records)); if (storageLatency && !saveHeld && records[0].requestsSent === 1 && records[0].inFlight === 1) { saveHeld = true; clock += 1500; } if (delayReservation && !saveHeld && records[0].requestsSent === 1) { saveHeld = true; await new Promise(resolve => releaseSave = resolve); } } });
  return { runner, sends, saved, finish: () => release?.(), reserved: () => !!releaseSave, finishSave: () => releaseSave?.(), advance: ms => clock += ms };
}
test('scope rejects ambiguous paths, exclusion descendants and foreign origins while permitting encoded query data', () => {
  const scope = base().scope;
  for (const url of ['https://other.test/search', 'https://target.test/admin', 'https://target.test/admin/users', 'https://target.test/safe/%2e%2e/admin', 'https://target.test/%252fadmin', 'https://target.test/a%2fb', 'https://target.test/a\\b', 'https://target.test/a;%2fadmin', 'https://target.test/%ZZ']) assert.throws(() => scopedUrl(url, scope), undefined, url);
  assert.equal(scopedUrl('https://target.test/search?q=%252fadmin', scope).pathname, '/search');
  assert.equal(scopedUrl('https://target.test/administrator', scope).pathname, '/administrator');
});
test('captured replay is explicit, repeated names retain ordinals and invalid requests fail before execution', () => {
  assert.doesNotThrow(() => validatePlan(base()));
  const invalid = [
    seed => seed.allowReplay = false, seed => seed.method = 'DELETE', seed => seed.url += '&q=%GG',
    seed => seed.parameters[0].index = 1, seed => { seed.method = 'POST'; seed.body = '{"q":"x","q":"duplicate"}'; seed.headers.push({ name: 'Content-Type', value: 'application/json' }); },
    seed => seed.headers[0].value = 'cookie\r\nInjected: value',
  ];
  for (const change of invalid) { const plan = base(); change(plan.requests[0]); assert.throws(() => validatePlan(plan)); }
  const repeated = base(); repeated.requests[0].url += '&q=duplicate'; repeated.requests[0].parameters = [{ location: 'query', name: 'q', index: 2 }]; assert.doesNotThrow(() => validatePlan(repeated));
});
test('real coordinator bounds every baseline/control/mutation/confirmation dispatch and redacts credential headers', async () => {
  const f = fixture(), plan = base(); await f.runner.run(plan); await f.runner.wait(plan);
  const result = f.runner.result(plan); assert.equal(result.state, 'completed'); assert.equal(result.requestsSent, 8); assert.equal(f.sends.length, 8);
  assert.equal(result.findings.length, 3); assert.ok(result.findings.every(item => item.classification === 'reproduced_reflection' && item.verifiedImpact === false));
  for (let index = 1; index < f.sends.length; index++) assert.ok(f.sends[index].at - f.sends[index - 1].at >= 1000);
  assert.ok(f.sends.every(item => item.schema.opts.follow_redirect === false && item.schema.opts.transport_retry_count === 0 && item.schema.opts.retry_on_transport_failure === false));
  assert.ok(!JSON.stringify(result).includes('PRIVATE-COOKIE')); assert.ok(!JSON.stringify(result).includes('PRIVATE-TOKEN'));
  const again = await f.runner.run(plan); assert.equal(again.accepted, false); assert.equal(f.sends.length, 8);
  assert.throws(() => f.runner.result({ ...plan, owner: 'other' }), /another chat/);
});
test('sanitized negative, redirect and expired-auth responses cannot become confirmed vulnerabilities', async () => {
  const negative = fixture({ vulnerable: false }), plan = base(); await negative.runner.run(plan); await negative.runner.wait(plan);
  assert.equal(negative.runner.result(plan).findings.length, 0); assert.equal(negative.sends.length, 5);
  for (const status of [0, 302, 401, 403, 429]) {
    const f = fixture({ status }); await f.runner.run(plan); await f.runner.wait(plan); const result = f.runner.result(plan);
    assert.equal(result.state, 'failed'); assert.equal(result.findings.length, 0); assert.equal(f.sends.length, 1);
  }
});
test('unstable benign controls prevent unrelated response changes becoming reproduced reflections', async () => {
  const f = fixture({ unstableControl: true }), plan = base(); await f.runner.run(plan); await f.runner.wait(plan);
  const result = f.runner.result(plan); assert.equal(result.state, 'completed'); assert.equal(result.findings.length, 0); assert.equal(f.sends.length, 5);
  assert.ok(result.requests[0].attacks.every(attack => attack.matched === false));
});
test('captured Cookie replay uses PTK strict override while requests without Cookie omit ambient identity', async () => {
  const captured = fixture(), plan = base(); await captured.runner.run(plan); await captured.runner.wait(plan);
  assert.ok(captured.sends.every(item => item.schema.opts.credentials === 'include' && item.schema.opts.strict_cookie_override === true));
  const absent = fixture(), anonymous = base(); anonymous.requests[0].headers = anonymous.requests[0].headers.filter(header => header.name !== 'Cookie');
  await absent.runner.run(anonymous); await absent.runner.wait(anonymous);
  assert.ok(absent.sends.every(item => item.schema.opts.credentials === 'omit'));
});
test('stale parser Content-Length never reaches replay DNR header overrides', async () => {
  const f = fixture(), plan = base(); plan.requests[0].headers.push({ name: 'Content-Length', value: '3' });
  await f.runner.run(plan); await f.runner.wait(plan);
  assert.ok(f.sends.length > 0);
  assert.ok(f.sends.every(item => item.schema.request.headers.every(header => header.name.toLowerCase() !== 'content-length')));
});
test('rate intervals are measured at actual dispatch even when storage persistence stalls', async () => {
  const f = fixture({ storageLatency: true }), plan = base(); await f.runner.run(plan); await f.runner.wait(plan);
  assert.equal(f.sends.length, 8); for (let index = 1; index < f.sends.length; index++) assert.ok(f.sends[index].at - f.sends[index - 1].at >= 1000);
});
test('request/time budgets and unselected-field mutations fail closed at dispatch', async () => {
  const plan = base(); plan.budget.maxRequests = 2;
  const count = fixture(); await count.runner.run(plan); await count.runner.wait(plan); assert.equal(count.sends.length, 2); assert.equal(count.runner.status(plan).state, 'budget_exhausted');
  const timed = base(); timed.budget.durationSeconds = 1;
  const time = fixture(); await time.runner.run(timed); await time.runner.wait(timed); assert.equal(time.sends.length, 1); assert.equal(time.runner.status(timed).state, 'expired');
  const leak = fixture({ leak: true }); await leak.runner.run(base()); await leak.runner.wait(base()); assert.equal(leak.sends.length, 2); assert.match(leak.runner.status(base()).errors[0], /unselected/);
});
test('owned targeted runtime accepts larger configurable budgets and rate while retaining serial isolation',async()=>{
  const f=fixture(),value=base({budget:{maxRequests:2500,durationSeconds:7200,maxRequestsPerSecond:20,concurrency:1}});
  await f.runner.run(value);await f.runner.wait(value);assert.equal(f.runner.result(value).state,'completed');assert.equal(f.sends.length,8);
  for(let index=1;index<f.sends.length;index++)assert.ok(f.sends[index].at-f.sends[index-1].at>=50);
  for(const rate of [0,-1,Infinity])assert.throws(()=>validatePlan(base({budget:{...value.budget,maxRequestsPerSecond:rate}})));
});
test('Stop cancels queued work and retains stopping until the bounded in-flight request settles', async () => {
  const f = fixture({ deferred: true }), plan = base(); await f.runner.run(plan);
  for (let i = 0; i < 20 && !f.sends.length; i++) await Promise.resolve();
  const stopped = await f.runner.stop(plan); assert.equal(stopped.state, 'stopping'); assert.equal(stopped.inFlight, 1);
  f.finish(); await f.runner.wait(plan); assert.equal(f.runner.status(plan).state, 'stopped'); assert.equal(f.sends.length, 1);
});
test('deadline changing while reserved dispatch persists cannot cause a late network request', async () => {
  const f = fixture({ delayReservation: true }), plan = base(); await f.runner.run(plan);
  for (let i = 0; i < 20 && !f.reserved(); i++) await Promise.resolve();
  assert.equal(f.reserved(), true); f.advance(301000); f.finishSave(); await f.runner.wait(plan);
  assert.equal(f.sends.length, 0); assert.equal(f.runner.status(plan).state, 'expired'); assert.equal(f.runner.status(plan).requestsSent, 0);
});
test('concurrent batches serialize admission and worker restart tombstones never replay', async () => {
  const f = fixture({ deferred: true }), first = base(), second = base({ batchId: 'second' });
  const attempts = await Promise.allSettled([f.runner.run(first), f.runner.run(second)]);
  assert.equal(attempts[0].status, 'fulfilled'); assert.equal(attempts[1].status, 'rejected');
  for (let i = 0; i < 20 && !f.sends.length; i++) await Promise.resolve();
  const status = f.runner.status(first);
  const restarted = createTargetedRunner({ loadPtk: async () => { throw Error('Must not replay'); }, interrupted: [status] });
  assert.equal((await restarted.run(first)).accepted, false); assert.equal(restarted.status(first).state, 'interrupted');
  assert.throws(() => restarted.result(first), /no longer retained/);
  await f.runner.stop(first); f.finish(); await f.runner.wait(first);
});

function familyFixture({ family = 'sql_injection', generic = false, baselineError = false, unstableBaseline = false, unstableControl = false, repeatFails = false, json = false, rewrite = false, nearHost = false } = {}) {
  let clock = 0; const sends = [], counts = new Map();
  const plan = base({ families: [family] }), seed = plan.requests[0];
  seed.url = 'https://target.test/search?q=hello';
  if (json) {
    seed.method = 'POST'; seed.body = '{ "filter": {"q":"hello"}, "large": 900719925474099312345, "flag":true,"nil":null,"escaped":"\\u0061" }';
    seed.headers.push({ name: 'Content-Type', value: 'application/json; charset=utf-8' }); seed.parameters = [{ location: 'json', name: '/filter/q', index: 0 }];
  }
  const read = schema => json ? globalThis.CertXDastInputs.parseJson(schema.request.body.text)[0].value : new URL(schema.request.url).searchParams.get('q');
  const mutate = (schema, parameter, value) => {
    const next = clone(schema);
    if (json) next.request.body.text = globalThis.CertXDastInputs.replaceJson(next.request.body.text, parameter, value);
    else { const url = new URL(next.request.url); url.searchParams.set(parameter.name, value); next.request.url = url.href; }
    if (rewrite) next.request.body.text = next.request.body.text.replace('900719925474099312345', '900719925474099300000');
    return next;
  };
  const module = {
    parse: seed => ({ request: { url: seed.url, method: seed.method, body: { text: seed.body }, headers: seed.headers }, metadata: {} }),
    build: (schema, parameters, families) => {
      assert.deepEqual(families, [family]);
      return parameters.flatMap(parameter => (family === 'sql_injection' ? ["'hello", '"hello', "hello'", 'hello"'] : ['https://cert-x-redirect.invalid/unique-marker']).map((payload, index) => ({
        family, schema: mutate(schema, parameter, payload), parameter, attackId: family + index, attackName: family, payload,
      })));
    },
    control: (schema, parameter) => mutate(schema, parameter, 'hello-control'),
    validate: (attack, baseline) => ({ success: attack.response.body.includes('SQL syntax') && !baseline.response.body.includes('SQL syntax'), proof: 'SQL syntax' }),
    async send(schema) {
      sends.push(clone(schema)); const value = read(schema); counts.set(value, (counts.get(value) || 0) + 1);
      const mutation = value !== 'hello' && value !== 'hello-control';
      const sql = baselineError || unstableBaseline && value === 'hello' && counts.get(value) === 2 || unstableControl && value === 'hello-control' || mutation && !generic && !(repeatFails && counts.get(value) > 1);
      return { ...schema, response: { statusCode: family === 'open_redirect' ? 302 : mutation && generic ? 500 : 200,
        body: sql ? 'SQL syntax' : 'ordinary response', headers: family === 'open_redirect' ? [{ name: 'Location', value: mutation ? nearHost ? value.replace('.invalid', '.invalid.evil.test') : value : '/landing' }] : [] } };
    },
  };
  return { plan, sends, runner: createTargetedRunner({ loadPtk: async () => module, now: () => clock, sleep: async ms => { clock += ms; } }) };
}

test('SQL coordinator requires signatures absent from both baselines and control, and a repeated match', async () => {
  for (const options of [{}, { generic: true }, { baselineError: true }, { unstableBaseline: true }, { unstableControl: true }, { repeatFails: true }]) {
    const f = familyFixture(options); await f.runner.run(f.plan); await f.runner.wait(f.plan); const result = f.runner.result(f.plan);
    assert.equal(result.state, 'completed'); assert.equal(result.progress.total, 4); assert.equal(result.progress.tested, 4);
    assert.equal(result.findings.length, Object.keys(options).length ? 0 : 4);
    assert.ok(result.findings.every(finding => finding.family === 'sql_injection' && finding.classification === 'reproduced_sql_error'));
    assert.equal(result.requestsSent, f.sends.length); assert.ok(result.requestsSent <= 11);
  }
});

test('mixed-family plans expose unsupported family/parameter coverage without claiming those checks ran', async () => {
  const f = fixture(), plan = base({ families: ['xss', 'sql_injection'] });
  await f.runner.run(plan); await f.runner.wait(plan);
  assert.equal(f.runner.status(plan).state, 'completed');
  const coverage = f.runner.result(plan).coverage;
  assert.equal(coverage.find(item => item.family === 'sql_injection').state, 'unsupported'); assert.equal(coverage.find(item => item.family === 'sql_injection').probesSent, 0);
  assert.equal(coverage.find(item => item.family === 'xss').state, 'tested'); assert.equal(f.runner.status(plan).findingsCount, 3);
});

test('HTTP redirect uses exact unique Location, retains ordinary redirect baselines and never follows', async () => {
  for (const nearHost of [false, true]) {
    const f = familyFixture({ family: 'open_redirect', nearHost }); await f.runner.run(f.plan); await f.runner.wait(f.plan); const result = f.runner.result(f.plan);
    assert.equal(result.state, 'completed'); assert.equal(result.progress.total, 1); assert.equal(result.findings.length, nearHost ? 0 : 1);
    assert.ok(f.sends.every(schema => schema.opts.follow_redirect === false));
    if (!nearHost) { assert.equal(result.findings[0].classification, 'reproduced_redirect'); assert.equal(result.findings[0].confirmation.redirectFollowed, false); }
  }
  const task = { payload: 'https://cert-x-redirect.invalid/token' }, baseline = { request: { url: 'https://target.test/a' }, response: { statusCode: 200, headers: [] } };
  for (const location of ['https://cert-x-redirect.invalid.evil/token', 'https://cert-x-redirect.invalid@evil.test/token', 'https://cert-x-redirect.invalid/other', 'https://cert-x-redirect.invalid/token#fragment']) {
    assert.equal(redirectVerdict({ ...baseline, response: { statusCode: 302, headers: [{ name: 'Location', value: location }] } }, baseline, task).success, false);
  }
});

test('JSON string mutation preserves unrelated token bytes and rejects type, duplicate, auth and ordinal changes', async () => {
  const f = familyFixture({ json: true }); assert.doesNotThrow(() => validatePlan(f.plan));
  for (const value of ['application/json ; charset=utf-8', 'application/vnd.example+json; charset="UTF-8"', 'application/vnd!example+json']) {
    const plan = clone(f.plan); plan.requests[0].headers.find(header => header.name === 'Content-Type').value = value; assert.doesNotThrow(() => validatePlan(plan));
  }
  for (const value of ['application/json; charset=latin-1', 'application/json; charset=utf-8; arbitrary=value']) {
    const plan = clone(f.plan); plan.requests[0].headers.find(header => header.name === 'Content-Type').value = value; assert.throws(() => validatePlan(plan));
  }
  await f.runner.run(f.plan); await f.runner.wait(f.plan); const result = f.runner.result(f.plan);
  assert.equal(result.state, 'completed'); assert.equal(result.findings.length, 4); assert.equal(f.sends[0].request.body.text, f.plan.requests[0].body);
  assert.ok(f.sends.every(schema => schema.request.body.text.includes('900719925474099312345') && schema.request.body.text.includes('"escaped":"\\u0061"')));
  for (const mutate of [seed => seed.parameters[0].index = 1, seed => seed.parameters[0] = { location: 'json', name: '/large', index: 1 }, seed => seed.body = '{"filter":{"q":"a","q":"b"}}', seed => { seed.body = '{"password":"secret"}'; seed.parameters[0] = { location: 'json', name: '/password', index: 0 }; }]) {
    const plan = clone(f.plan); mutate(plan.requests[0]); assert.throws(() => validatePlan(plan));
  }
  const rewrite = familyFixture({ json: true, rewrite: true }); await rewrite.runner.run(rewrite.plan); await rewrite.runner.wait(rewrite.plan);
  assert.equal(rewrite.runner.status(rewrite.plan).state, 'failed'); assert.equal(rewrite.sends.length, 0); assert.match(rewrite.runner.status(rewrite.plan).errors[0], /unselected JSON/);
});

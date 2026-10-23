import test from 'node:test';
import assert from 'node:assert/strict';
import { createTargetedRunner, normalizeReflectedInput } from './dast-core.mjs';
const inputs = globalThis.CertXDastInputs, clone = value => JSON.parse(JSON.stringify(value));
const base = family => ({ batchId: 'strategies', owner: 'chat', tabId: 1, origin: 'https://target.test', families: [family], scope: { origins: ['https://target.test'], excludePaths: [] }, budget: { maxRequests: 100, maxRequestsPerSecond: 1, concurrency: 1, durationSeconds: 300 }, requests: [{ id: 'seed', url: 'https://target.test/check?q=1', method: 'GET', headers: [], body: '', allowReplay: true, parameters: [{ location: 'query', name: 'q', index: 0 }] }] });
function fixture({ behavior = 'boolean', negative = false, parameterized = false, dynamic = false, unstableFalse = false, contentType = 'application/json', status = 200, context = 'numeric' } = {}) {
  let clock = 0; const sent = [];
  const mutate = (schema, parameter, replacement) => { const result = clone(schema), wire = inputs.replaceRequestInput({ url: schema.request.url, body: schema.request.body.text }, parameter, replacement); result.request.url = wire.url; result.request.body.text = wire.body; return result; };
  const ptk = {
    parse: seed => ({ request: { url: seed.url, method: seed.method, headers: seed.headers, body: { text: seed.body } }, metadata: {} }), mutate,
    build: (schema, parameters, families) => families.flatMap(family => family === 'response_checks' ? [{ family, strategy: 'passive', moduleId: 'recon_error_stacktraces', attackId: 'stack', attackName: 'Stack observation', metadata: {} }] : parameters.flatMap(parameter => {
      const originalValue = inputs.getRequestInput({ url: schema.request.url, body: schema.request.body.text }, parameter).value;
      if (family === 'sql_boolean') return [{ family, strategy: 'boolean', parameter, originalValue, context, attackId: 'boolean' }];
      if (family === 'ssti') return ['mustache', 'dollar', 'erb'].map(template => ({ family, strategy: 'ssti', parameter, originalValue, template, attackId: template }));
      const payload = family === 'jsonp_callback_injection' ? 'certxJsonp_first' : '<script>fixture</script>', variant = mutate(schema, parameter, payload);
      variant.metadata = { jsonpCallbackProofRegex: 'certxJsonp_first' }; return [{ family, parameter, schema: variant, payload, attackId: family, originalValue }];
    })),
    control: (schema, parameter) => mutate(schema, parameter, 'control'),
    validate: (attack, original, task) => ({ success: task.family === 'response_checks' ? true : task.family === 'jsonp_callback_injection' ? attack.response.body.includes(attack.metadata.jsonpCallbackProofRegex) : attack.response.body.includes('<script>') && !original.response.body.includes('<script>') }),
    send: async schema => {
      sent.push({ at: clock, schema: clone(schema) });
      const value = inputs.getRequestInput({ url: schema.request.url, body: schema.request.body.text }, { location: 'query', name: 'q', index: new URL(schema.request.url).searchParams.getAll('q').length > 1 ? 1 : 0 }).value;
      let body;
      if (behavior === 'boolean') {
        const match = /AND\s+["']?(\d+)["']?=["']?(\d+)/.exec(value), truth = !match || match[1] === match[2];
        body = JSON.stringify({ rows: parameterized && match ? [] : negative || truth ? ['object'] : unstableFalse ? ['different' + sent.length] : [], echo: value, ...(dynamic ? { nonce: sent.length } : {}) });
      } else if (behavior === 'ssti') body = negative ? value : value.replace(/\{\{(\d+)\*(\d+)\}\}/g, (_, a, b) => String(Number(a) * Number(b)));
      else if (behavior === 'jsonp') body = negative ? '{"fixed":true}' : value + '({"fixed":true});';
      else if (behavior === 'ordinal') body = [...new URL(schema.request.url).searchParams.values(), ...new URLSearchParams(schema.request.body.text).values()].join(' ');
      else body = 'Traceback: fixture stack';
      return { ...schema, response: { statusCode: status, body, headers: [{ name: 'Content-Type', value: contentType }], timeMs: 1 } };
    },
  };
  return { sent, runner: createTargetedRunner({ loadPtk: async () => ptk, now: () => clock, sleep: async ms => { clock += ms; } }) };
}
test('boolean strategy requires stable varied and repeated predicates, excluding reflected input only', async () => {
  for (const options of [{}, { negative: true }, { parameterized: true }, { dynamic: true }, { unstableFalse: true }, { context: 'single-quoted' }]) {
    const f = fixture(options), plan = base('sql_boolean'); if (options.context) plan.requests[0].url = 'https://target.test/check?q=alice';
    await f.runner.run(plan); await f.runner.wait(plan); const result = f.runner.result(plan);
    assert.equal(result.state, 'completed'); assert.equal(result.findings.length, options.negative || options.parameterized || options.dynamic || options.unstableFalse ? 0 : 1);
    assert.equal(result.coverage[0].state, options.dynamic || options.unstableFalse ? 'inconclusive' : 'tested');
    assert.equal(result.requestsSent, options.dynamic ? 2 : 10); assert.equal(result.coverage[0].probesSent, result.requestsSent);
    for (let index = 1; index < f.sent.length; index++) assert.ok(f.sent[index].at - f.sent[index - 1].at >= 1000);
  }
  assert.equal(normalizeReflectedInput('counter=999; echo=1 AND 23=23', '1 AND 23=23', '1'), 'counter=999; echo=1');
  assert.equal(normalizeReflectedInput('{"echo":"alice\' AND \'23\'=\'23","count":23}', "alice' AND '23'='23", 'alice'), '{"echo":"alice","count":23}');
  assert.equal(normalizeReflectedInput('q=alice%27%20AND%20%2723%27%3D%2723&count=23', "alice' AND '23'='23", 'alice'), 'q=alice&count=23');
});
test('template arithmetic requires independent marker products, intact literal control and reproduction', async () => {
  for (const negative of [false, true]) {
    const f = fixture({ behavior: 'ssti', negative, contentType: 'text/html' }), plan = base('ssti'); await f.runner.run(plan); await f.runner.wait(plan); const result = f.runner.result(plan);
    assert.equal(result.state, 'completed'); assert.equal(result.findings.length, negative ? 0 : 1);
    assert.ok(result.findings.every(item => item.classification === 'reproduced_template_evaluation' && item.verifiedImpact === false));
    assert.equal(result.coverage[0].state, 'tested'); assert.equal(result.requestsSent, negative ? 10 : 12);
  }
});
test('JSONP callback control is an observation and requires JSON invocation plus supported MIME', async () => {
  for (const options of [{ contentType: 'text/javascript' }, { contentType: 'text/plain' }, { contentType: 'application/json', negative: true }]) {
    const f = fixture({ behavior: 'jsonp', ...options }), plan = base('jsonp_callback_injection'); await f.runner.run(plan); await f.runner.wait(plan); const result = f.runner.result(plan);
    assert.equal(result.findings.length, 0); assert.equal(result.observations.length, options.contentType === 'text/javascript' ? 1 : 0); assert.equal(result.coverage[0].state, 'tested');
  }
});
test('passive error-response checks use one baseline and expose no raw header proof', async () => {
  const f = fixture({ behavior: 'passive', status: 500 }), plan = base('response_checks'); plan.requests[0].parameters = [];
  await f.runner.run(plan); await f.runner.wait(plan); const result = f.runner.result(plan);
  assert.equal(result.state, 'completed'); assert.equal(result.requestsSent, 1); assert.equal(result.findings.length, 0); assert.equal(result.observations.length, 1); assert.equal(result.coverage[0].state, 'tested');
  assert.equal(result.observations[0].moduleId, 'recon_error_stacktraces');
});
test('repeated field ordinals and query/form collisions preserve every unselected raw token', async () => {
  const f = fixture({ behavior: 'ordinal', contentType: 'text/html' }), plan = base('xss'), seed = plan.requests[0];
  seed.url = 'https://target.test/check?q=first%20raw&&q=second+raw&flag&keep=a%2bb'; seed.method = 'POST'; seed.headers = [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }]; seed.body = 'q=body+raw&keep=z%20z';
  seed.parameters = [{ location: 'query', name: 'q', index: 1 }, { location: 'form', name: 'q', index: 0 }];
  await f.runner.run(plan); await f.runner.wait(plan); const result = f.runner.result(plan);
  assert.equal(result.state, 'completed'); assert.equal(result.findings.length, 2); assert.notEqual(result.findings[0].id, result.findings[1].id);
  assert.ok(f.sent.every(item => item.schema.request.url.includes('q=first%20raw&&') && item.schema.request.url.endsWith('&flag&keep=a%2bb') && item.schema.request.body.text.endsWith('&keep=z%20z')));
});
test('budget interruption preserves partial coverage and leaves later checks skipped', async () => {
  const f = fixture(), plan = base('sql_boolean'); plan.families.push('ssti'); plan.budget.maxRequests = 4;
  await f.runner.run(plan); await f.runner.wait(plan); const result = f.runner.result(plan);
  assert.equal(result.state, 'budget_exhausted'); assert.equal(result.requestsSent, 4); assert.equal(result.findings.length, 0);
  assert.equal(result.coverage[0].state, 'inconclusive'); assert.equal(result.coverage[0].probesSent, 4); assert.equal(result.coverage[1].state, 'skipped');
});

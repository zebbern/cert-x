const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto').webcrypto;

const source = fs.readFileSync(path.join(__dirname, 'dast-companion.js'), 'utf8').replace(/^import .*;\r?\n/gm, '').replace('export function installCertXDast', 'function installCertXDast');
const families = ['xss', 'sql_injection', 'open_redirect', 'jsonp_callback_injection'];
const ids = [['xss_1', 'xss_2', 'xss_3'], ['sqlinjection_1', 'sqlinjection_3', 'sqlinjection_2', 'sqlinjection_4'], ['redir_1'], ['jsonp_callback_1']];
const pack = { modules: [...families.map((id, index) => ({ id, attacks: ids[index].map(attackId => ({ id: attackId, name: attackId, condition: {}, validation: {}, action: { params: [{ value: '<script>fixture</script>', operation: 'add', position: 'after' }] } })) })), ...['headers', 'recon_cors_posture', 'recon_cache_privacy', 'recon_error_stacktraces', 'recon_sourcemaps_debug'].map(id => ({ id, type: 'passive', attacks: [] }))] };
const extensionId = 'abcdefghijklmnopabcdefghijklmnop';
const endpoint = 'https://target.test/search?q=baseline%20space';
const schema = () => ({ opts: { follow_redirect: false }, request: { url: endpoint, method: 'GET', headers: [{ name: 'X-PTK-ReqId', value: 'captured-stale-id' }, { name: 'x-ptk-source', value: 'captured-source' }, { name: 'Authorization', value: 'Bearer frozen' }] } });

async function adapter(send, { failListener = false } = {}) {
  const registries = { before: new Set(), headers: new Set() }, registrations = [];
  function event(name) {
    return {
      addListener(listener, filter, options) {
        if (name === 'headers' && failListener) throw Error('Listener setup rejected');
        registrations.push({ name, filter, options }); registries[name].add(listener);
      },
      removeListener(listener) { registries[name].delete(listener); },
    };
  }
  const emit = (name, details) => { for (const listener of registries[name]) listener(details); };
  class Request {
    static parseRawRequest() { return { request: { body: { text: 'parser normalized text' } } }; }
    async sendRequest(input) {
      assert.equal(this.isolatedRedirectSession, false); assert.equal(this.useListeners, false); assert.equal(this.trackWithListeners, false);
      return send(input, emit);
    }
  }
  const context = vm.createContext({ URL, URLSearchParams, TextEncoder, crypto, ptk_module: class { prepareAttack(value) { return structuredClone(value); } }, ptk_request: Request,
    DAST_FAMILIES: families, fetch: async () => ({ ok: true, json: async () => pack }),
    chrome: { runtime: { id: extensionId, getURL: value => 'chrome-extension://' + extensionId + '/' + value }, webRequest: { onBeforeSendHeaders: event('before'), onHeadersReceived: event('headers') } },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, 'dast-inputs.js'), 'utf8'), context);
  vm.runInContext(source + '\nglobalThis.testAdapter = loadPtk; globalThis.testGuards = installAccessGuards; globalThis.testAccessStart = startAccessBatch; globalThis.testBind = bindValidationConstants;', context);
  return { instance: await context.testAdapter(), registries, registrations, context, Request };
}

const before = input => ({ initiator: 'chrome-extension://' + extensionId, url: endpoint, method: 'GET', requestId: 'own-network-request', requestHeaders: [{ name: 'X-PTK-ReqId', value: input.opts.ptk_req_id }] });
const received = () => ({ initiator: 'chrome-extension://' + extensionId, url: endpoint, requestId: 'own-network-request', statusCode: 302, responseHeaders: [{ name: 'Location', value: 'https://cert-x-redirect.invalid/marker' }] });
const opaque = input => ({ ...input, response: { statusCode: 0, body: '', headers: [] } });
const cleaned = value => { assert.equal(value.registries.before.size, 0); assert.equal(value.registries.headers.size, 0); };

test('companion observer recovers only correlated redirect headers and replaces captured PTK IDs', async () => {
  const value = await adapter(async (input, emit) => {
    assert.notEqual(input.opts.ptk_req_id, 'captured-stale-id');
    assert.ok(input.request.headers.every(header => !header.name.toLowerCase().startsWith('x-ptk-')));
    assert.equal(input.request.headers[0].value, 'Bearer frozen');
    emit('before', before(input)); emit('headers', received()); return opaque(input);
  });
  const result = await value.instance.send(schema());
  assert.equal(result.response.statusCode, 302); assert.equal(result.response.headers[0].value, 'https://cert-x-redirect.invalid/marker'); cleaned(value);
  assert.ok(value.registrations.every(item => item.filter.urls[0] === 'https://target.test/*' && item.filter.types[0] === 'xmlhttprequest'));
});

test('transport and Cookie DNR receive the same canonical URL for literal query quotes', async () => {
  const value = await adapter(async input => {
    assert.equal(input.request.url, 'https://target.test/search?q=%27quoted');
    assert.equal(input.request.headers.find(header => header.name === 'Cookie').value, 'frozen=selected-account');
    return { ...input, response: { statusCode: 200, body: 'ok', headers: [] } };
  });
  const input = schema(); input.request.url = "https://target.test/search?q='quoted"; input.request.headers.push({ name: 'Cookie', value: 'frozen=selected-account' });
  await value.instance.send(input); cleaned(value);
});

test('correlated ordinary response headers retain Set-Cookie for passive analysis only', async () => {
  const value = await adapter(async (input, emit) => {
    emit('before', before(input)); emit('headers', { ...received(), statusCode: 500, responseHeaders: [{ name: 'Set-Cookie', value: 'fixture=value; HttpOnly' }] });
    return { ...input, response: { statusCode: 500, body: 'error', headers: [] } };
  });
  const result = await value.instance.send(schema()); assert.equal(result.response.headers[0].name, 'Set-Cookie'); cleaned(value);
});

test('companion builds lightweight descriptors and mutates exact repeated input occurrences lazily', async () => {
  const value = await adapter(async input => opaque(input));
  const original = { request: { url: 'https://target.test/check?q=first%20raw&&q=second+raw&keep=a%2bb&flag', method: 'POST', headers: [], body: { text: 'q=body+raw&keep=z%20z', mimeType: 'application/x-www-form-urlencoded' } } };
  const parameters = [{ location: 'query', name: 'q', index: 1 }, { location: 'form', name: 'q', index: 0 }];
  const tasks = value.instance.build(original, parameters, ['xss']); assert.equal(tasks.length, 6); assert.ok(tasks.every(task => !Object.hasOwn(task, 'schema')));
  for (const task of tasks) {
    const variant = value.instance.taskSchema(original, task);
    assert.ok(variant.request.url.startsWith('https://target.test/check?q=first%20raw&&')); assert.ok(variant.request.url.endsWith('&keep=a%2bb&flag')); assert.ok(variant.request.body.text.endsWith('&keep=z%20z'));
    if (task.parameter.location === 'query') assert.equal(variant.request.body.text, original.request.body.text); else assert.equal(variant.request.url, original.request.url);
  }
});

test('companion observer ignores page traffic, wrong nonce, endpoint, method, order and request ID', async () => {
  const cases = [
    { before: { initiator: 'https://target.test' } }, { before: { url: 'https://target.test/other' } }, { before: { method: 'POST' } },
    { before: { requestHeaders: [{ name: 'X-PTK-ReqId', value: 'captured-stale-id' }] } },
    { headers: { initiator: 'https://target.test' } }, { headers: { url: 'https://target.test/other' } }, { headers: { requestId: 'unrelated-request' } }, { reverse: true },
  ];
  for (const scenario of cases) {
    const value = await adapter(async (input, emit) => {
      if (scenario.reverse) emit('headers', received());
      emit('before', { ...before(input), ...scenario.before });
      if (!scenario.reverse) emit('headers', { ...received(), ...scenario.headers });
      return opaque(input);
    });
    const result = await value.instance.send(schema()); assert.equal(result.response.statusCode, 0, JSON.stringify(scenario)); cleaned(value);
  }
});

test('companion removes both observers after transport failure and partial observer setup', async () => {
  const failed = await adapter(async () => { throw Error('Request failed'); });
  await assert.rejects(failed.instance.send(schema()), /Request failed/); cleaned(failed);
  let dispatched = false;
  const setup = await adapter(async () => { dispatched = true; }, { failListener: true });
  await assert.rejects(setup.instance.send(schema()), /Listener setup/); cleaned(setup); assert.equal(dispatched, false);
});

test('companion parser preserves raw JSON text across supported media spelling', async () => {
  const value = await adapter(async input => opaque(input));
  const body = '{ "q":"hello", "n":900719925474099312345, "escaped":"\\u0061" }';
  for (const contentType of ['application/json ; charset=utf-8', 'application/vnd!example+json', 'application/problem+json; charset="UTF-8"']) {
    const parsed = value.instance.parse({ url: endpoint, method: 'POST', headers: [{ name: 'Content-Type', value: contentType }], body });
    assert.equal(parsed.request.body.mimeType, 'application/json'); assert.equal(parsed.request.body.text, body); assert.equal(parsed.request.body.params.length, 0);
  }
});

test('PTK request and scan guards block account-comparison overlap and preserve normal invocation', async () => {
  let active = false, finish, called = 0;
  const value = await adapter(async input => { called++; return opaque(input); });
  const syncFailure = Error('original synchronous failure');
  const app = { dast: { marker: 'original-this', async runBackgroundScan(...args) { assert.equal(this.marker, 'original-this'); return args; }, engine: { marker: 7, start(value) { return this.marker + value; } } },
    iast: { async runBackgroundScan() { return 'iast'; } }, recorder: { startReplay() { throw syncFailure; } } };
  const guards = value.context.testGuards(app, () => active), scan = app.dast.runBackgroundScan;
  value.context.testGuards(app, () => active); assert.equal(app.dast.runBackgroundScan, scan, 'Guard installation must be idempotent');
  const asyncResult = app.dast.runBackgroundScan(1, 'host'); assert.equal(typeof asyncResult.then, 'function'); assert.deepEqual(await asyncResult, [1, 'host']);
  assert.equal(app.dast.engine.start(5), 12, 'Synchronous PTK methods must keep synchronous return values');
  assert.throws(() => app.recorder.startReplay(), error => error === syncFailure); assert.equal(guards.pending, 0);
  active = true;
  assert.throws(() => new value.Request().sendRequest(schema()), /account comparison/); assert.throws(() => app.dast.runBackgroundScan(1), /account comparison/); assert.throws(() => app.iast.runBackgroundScan(), /account comparison/); assert.equal(called, 0);
  await assert.rejects(value.context.fetch('https://target.test/resource'), /temporarily paused/);
  assert.equal((await value.context.fetch('chrome-extension://' + extensionId + '/asset.json')).ok, true);
  assert.equal((await guards.originalFetch('https://target.test/resource')).ok, true, 'Isolated transport retains the explicit original fetch');
  active = false;
  assert.equal((await value.context.fetch('https://target.test/resource')).ok, true);
  await value.instance.send(schema()); assert.equal(called, 1); assert.equal(guards.pending, 0);
  const blocking = await adapter(async input => { await new Promise(resolve => finish = resolve); return opaque(input); });
  const pendingGuard = blocking.context.testGuards({}, () => false), pending = blocking.instance.send(schema());
  for (let index = 0; index < 20 && !finish; index++) await Promise.resolve();
  assert.equal(pendingGuard.pending, 1, 'Queued or in-flight PTK sends must prevent comparison admission'); finish(); await pending; assert.equal(pendingGuard.pending, 0);
  const direct = await adapter(async input => opaque(input)); let finishFetch;
  direct.context.fetch = async () => { await new Promise(resolve => finishFetch = resolve); return { ok: true }; };
  const directGuard = direct.context.testGuards({}, () => false), pendingFetch = direct.context.fetch('https://target.test/direct');
  assert.equal(directGuard.pending, 1, 'Preexisting direct worker fetches must also prevent comparison admission'); finishFetch(); await pendingFetch; assert.equal(directGuard.pending, 0);
});

test('access run RPC distinguishes definite non-admission from accepted or retained lifecycle results', async () => {
  const value = await adapter(async input => opaque(input)), payload = { batchId: 'batch-one', owner: 'chat-one' };
  const rejected = await value.context.testAccessStart({ run: async () => { throw Error('A PTK analysis is already active.'); } }, payload);
  assert.equal(rejected.accepted, false); assert.equal(rejected.state, 'failed'); assert.equal(rejected.requestsSent, 0); assert.match(rejected.error, /already active/);
  const retained = { accepted: false, state: 'running', requestsSent: 4, ...payload };
  assert.equal(await value.context.testAccessStart({ run: async () => retained }, payload), retained);
});

test('pinned PTK cache rule retains its declared regex inside JsonLogic header scopes', async () => {
  const ptkSource = process.env.PTK_SOURCE || path.resolve(__dirname, '../../../insp/pentestkit-10.0.0-release');
  const pack = JSON.parse(fs.readFileSync(path.join(ptkSource, 'src/ptk/background/dast/modules/modules.json'), 'utf8'));
  const definition = pack.modules.find(module => module.id === 'recon_cache_privacy'), rule = definition.attacks.find(attack => attack.id === 'recon_cache_public_with_set_cookie');
  const { jsonLogic } = await import('data:text/javascript;base64,' + Buffer.from(fs.readFileSync(path.join(ptkSource, 'src/ptk/background/lib/json-logic-js.js'), 'utf8')).toString('base64'));
  jsonLogic.add_operation('regex', (value, pattern) => new RegExp(pattern, 'gmi').test(value));
  const adapterValue = await adapter(async input => opaque(input)), constants = rule.metadata.constants;
  const compiled = adapterValue.context.testBind(rule.validation.rule, constants), before = JSON.stringify(rule.validation.rule);
  const evaluate = (cache, cookie, url = 'https://target.test/response.js') => ({ attack: { metadata: constants }, original: { request: { url }, response: { headers: [...(cookie ? [{ name: 'Set-Cookie', value: 'fixture-private-cookie=value; HttpOnly' }] : []), { name: 'Cache-Control', value: cache }] } } });
  assert.equal(jsonLogic.apply(rule.validation.rule, evaluate('public, max-age=60', true)), false, 'Unbound pinned metadata reference is lost inside some/none');
  assert.equal(jsonLogic.apply(compiled, evaluate('public, max-age=60', true)), true);
  assert.equal(jsonLogic.apply(compiled, evaluate('public, max-age=60, no-store', true)), false);
  assert.equal(jsonLogic.apply(compiled, evaluate('public, max-age=60', false)), false);
  assert.equal(jsonLogic.apply(compiled, evaluate('public, max-age=60', true, 'https://target.test/static/app.js')), false);
  assert.equal(JSON.stringify(rule.validation.rule), before, 'Binding must not alter the pinned source rule');
  assert.ok(!JSON.stringify(compiled).includes('fixture-private-cookie'));
});

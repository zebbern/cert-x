const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function fixture() {
  const gets = [], calls = [], messages = [];
  const event = { addListener() {} };
  let tab = { id: 699983413, url: 'https://target.test/app' }, selected;
  const service = { handle: async (op, args, context) => { calls.push({ op, args, context }); return { runId: 'owned-run', state: 'running' }; } };
  const sandbox = vm.createContext({ console, URL, TextEncoder, AbortController, KI_POLICY_CONTEXT: Symbol('policy'),
    Tt: () => selected == null ? null : { primaryTabId: selected }, kiWorkspaceOwner: value => value,
    certXSecurity: service, chrome: {
      runtime: { id: 'fixture', getURL: file => 'chrome-extension://fixture/' + file, onMessage: { addListener: fn => messages.push(fn) } },
      storage: { onChanged: event }, tabs: { get: async id => {
        assert.equal(typeof id, 'number', 'Chrome receives only a numeric ID'); gets.push(id);
        if (!tab || id !== tab.id) throw Error('No tab with id: ' + id); return tab;
      } }
    }
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../src/ki-security.js'), 'utf8'), sandbox);
  sandbox.kiSecurityContext = async () => ({ owner: 'chat', scope: { origins: [], excludePaths: [] } });
  sandbox.kiPolicyState = async () => ({ parentEnabled: true, rule: 'allow' });
  const call = (op, args) => sandbox.kiSecurityOperate(op, args, 'chat');
  const tool = (name, args) => sandbox.kiSecurityToolDefs('chat').find(item => item.name === name).resolveExecution(args).execute({});
  return { sandbox, gets, calls, call, tool, messages, setTab: value => tab = value, select: value => selected = value };
}

test('scan normalizes the exact screenshot alias and decimal string before Chrome and service dispatch', async () => {
  const f = fixture(), input = { engines: ['DAST'], tab: '699983413' };
  const result = await f.tool('security_start_scan', input);
  assert.equal(result.isError, undefined); assert.equal(JSON.parse(result.output).runId, 'owned-run');
  assert.deepEqual(f.gets, [699983413]); assert.equal(f.calls[0].args.tabId, 699983413);
  assert.equal(Object.hasOwn(f.calls[0].args, 'tab'), false);
  assert.deepEqual(input, { engines: ['DAST'], tab: '699983413' }, 'caller arguments remain unchanged');
});

test('canonical and nested operation targets normalize consistently without changing unrelated input values', async () => {
  for (const args of [
    { tabId: '699983413', arguments: { action: 'start' } },
    { arguments: { tabId: '699983413', action: 'start' } },
    { tab: 699983413, arguments: { tab: '699983413', action: 'start' } }
  ]) {
    const f = fixture(); await f.call('execute', { capability: 'capture', ...args });
    assert.equal(f.calls[0].args.tabId, 699983413); assert.deepEqual(f.gets, [699983413]);
    if (args.arguments.tabId || args.arguments.tab) assert.equal(f.calls[0].args.arguments.tabId, 699983413);
  }
  const f = fixture(); await f.call('execute', { capability: 'utility', arguments: { tool: 'jwt', token: '699983413' } });
  assert.equal(f.calls[0].args.arguments.token, '699983413'); assert.deepEqual(f.gets, []);
});

test('malformed and conflicting targets fail before Chrome or runtime with actionable deterministic errors', async () => {
  for (const value of ['', ' ', '-1', '1.2', '1e3', '0x10', '2147483648', true, null, [], {}, 1.5, -1, Infinity]) {
    const f = fixture(), result = JSON.parse((await f.tool('security_start_scan', { tab: value })).output);
    assert.equal(result.code, 'invalid_target_tab', JSON.stringify(value)); assert.equal(result.retryable, false);
    assert.match(result.recovery, /list_browser_tabs.*Do not retry unchanged/); assert.equal(f.gets.length, 0); assert.equal(f.calls.length, 0);
  }
  const f = fixture();
  await assert.rejects(f.call('start', { tabId: 699983413, tab: '7' }), /Conflicting/);
  await assert.rejects(f.call('execute', { tabId: 699983413, arguments: { tabId: '7' } }), /Conflicting/);
  assert.equal(f.gets.length, 0); assert.equal(f.calls.length, 0);
});

test('only omitted targets may use the selected chat tab; stale and unsupported targets explain recovery', async () => {
  const f = fixture(); f.select('699983413'); await f.call('start', {}); assert.deepEqual(f.gets, [699983413]);
  await assert.rejects(f.call('start', { tabId: '' }), /valid browser tab/);
  f.select(undefined); const missing = JSON.parse((await f.tool('security_start_scan', {})).output); assert.equal(missing.code, 'invalid_target_tab');
  f.setTab(null); const stale = JSON.parse((await f.tool('security_start_scan', { tabId: 699983413 })).output); assert.equal(stale.code, 'target_tab_unavailable'); assert.equal(stale.retryable, false);
  f.setTab({ id: 699983413, url: 'chrome://settings' }); const unsupported = JSON.parse((await f.tool('security_start_scan', { tabId: 699983413 })).output); assert.equal(unsupported.code, 'target_tab_unsupported');
});

test('trusted settings callers receive the same structured errors and run references survive failures', async () => {
  const f = fixture();
  const reply = await new Promise(resolve => f.messages[0]({ type: 'KI_SECURITY', op: 'start', session: 'chat', tab: 'bad' }, { id: 'fixture', url: 'chrome-extension://fixture/providers/providers.html' }, resolve));
  assert.equal(reply.ok, false); assert.equal(reply.retryable, false); assert.equal(reply.code, 'invalid_target_tab');
  f.sandbox.certXSecurity.handle = async () => { throw Object.assign(Error('Start outcome unknown'), { runId: 'owned-uncertain-run' }); };
  const result = JSON.parse((await f.tool('security_start_scan', { tabId: 699983413 })).output);
  assert.equal(result.runId, 'owned-uncertain-run'); assert.equal(result.error, 'Start outcome unknown');
});

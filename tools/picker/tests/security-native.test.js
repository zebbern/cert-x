const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), vm = require('node:vm'), { webcrypto } = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, '../src/ki-native.js'), 'utf8');
const event = () => { const listeners = new Set(); return { addListener: fn => listeners.add(fn), removeListener: fn => listeners.delete(fn), emit: (...args) => { for (const fn of listeners) fn(...args); } }; };
function harness() {
  const data = { ki_native_settings: { enabled: true, servers: [] }, sidepanel_approval_mode: 'full_access' }, sent = [], approvals = [], admissions = [], lost = [];
  const port = { features: ['security_runtime_v1','security_raw_v2'], onMessage: event(), onDisconnect: event(), postMessage(message) { sent.push(message); if (message.op === 'status') queueMicrotask(() => port.onMessage.emit({ id: message.id, ok: true, result: { features: port.features } })); if (message.op === 'security_status') queueMicrotask(() => port.onMessage.emit({ id: message.id, ok: true, result: { protocolVersion: 1, components: {} } })); }, disconnect() { port.onDisconnect.emit(); } };
  const changed = event(), listener = event();
  let policy = { parentEnabled: true, rule: 'inherit', fullAccess: true }, checks = 0;
  const sandbox = { console, Promise, TextEncoder, setTimeout, clearTimeout, AbortController, crypto: webcrypto, Map, Symbol, Error, kiWorkspaceHostLost: async () => {}, kiWorkspaceJob: async () => {}, kiMcpCache: {}, kiPolicyState: async () => policy, KN: { request: async value => { approvals.push(value); return 'allow_once'; } }, certXSecurity: { localLost: async value => lost.push(value), localEvent: async () => {} }, chrome: { runtime: { connectNative: () => port, onMessage: listener, getURL: file => 'chrome-extension://fixture/' + file }, storage: { onChanged: changed, local: { get: async keys => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map(key => [key, data[key]])) } } } };
  vm.createContext(sandbox); vm.runInContext(source, sandbox);
  const controller = new AbortController(), context = { owner: 'chat', session: 'chat', runId: 'run', workspaceId: 'workspace', scope: { origins: ['https://target.test'], excludePaths: [] }, config: {}, signal: controller.signal, recheck: async () => { checks++; }, checkRequest: async request => admissions.push(request) };
  const until = async condition => { for (let index = 0; index < 100; index++) { if (condition()) return; await new Promise(resolve => setTimeout(resolve, 1)); } throw Error('Expected native message was not emitted.'); };
  return { sandbox, data, sent, approvals, admissions, port, changed, context, controller, lost, until, policy: value => policy = value, checks: () => checks };
}
test('native security dispatch admits each send through the exact owned lease and fails stale admissions', async () => {
  const h = harness(), running = h.sandbox.kiNativeSecurityExecute('transport.http1', { url: 'https://target.test/a' }, h.context);
  await h.until(() => h.sent.some(message => message.op === 'security_dispatch')); const dispatched = h.sent.find(message => message.op === 'security_dispatch');
  assert.equal(dispatched.params.context.owner, 'chat'); assert.equal(dispatched.params.context.runId, 'run'); assert.ok(dispatched.params.context.lease);
  const admission = { event: 'security_admission', requestId: 'wire-1', owner: 'chat', runId: 'run', lease: dispatched.params.context.lease, request: { url: 'https://target.test/a', method: 'GET', kind: 'target' } };
  h.port.onMessage.emit(admission); await h.until(() => h.sent.some(message => message.op === 'security_admission_result'));
  assert.equal(h.sent.find(message => message.op === 'security_admission_result').params.allow, true); assert.equal(h.admissions.length, 1); assert.ok(h.checks() >= 3);
  h.port.onMessage.emit({ id: dispatched.id, ok: true, result: { status: 200 } }); assert.equal((await running).status, 200);
  h.port.onMessage.emit({ ...admission, requestId: 'wire-late' }); await h.until(() => h.sent.some(message => message.params?.requestId === 'wire-late'));
  assert.equal(h.sent.find(message => message.params?.requestId === 'wire-late').params.allow, false); assert.equal(h.admissions.length, 1);
});
test('persistent native sessions keep one approval and deny traffic after local access is revoked', async () => {
  const h = harness(); h.policy({ parentEnabled: true, rule: 'ask', fullAccess: true });
  const running = h.sandbox.kiNativeSecurityExecute('browser.create', {}, h.context);
  await h.until(() => h.sent.some(message => message.op === 'security_dispatch')); const dispatched = h.sent.find(message => message.op === 'security_dispatch'), lease = dispatched.params.context.lease;
  h.port.onMessage.emit({ id: dispatched.id, ok: true, result: { sessionId: 'browser-one', persistent: true, leaseId: lease } }); await running;
  assert.equal(h.approvals.length, 1);
  for (const requestId of ['wire-1', 'wire-2']) { h.port.onMessage.emit({ event: 'security_admission', requestId, owner: 'chat', runId: 'run', lease, request: { url: 'https://target.test/a', kind: 'target' } }); await h.until(() => h.sent.some(message => message.params?.requestId === requestId)); }
  assert.equal(h.approvals.length, 1); assert.equal(h.admissions.length, 2);
  h.data.ki_native_settings.enabled = false;
  h.port.onMessage.emit({ event: 'security_admission', requestId: 'revoked', owner: 'chat', runId: 'run', lease, request: { url: 'https://target.test/a', kind: 'target' } }); await h.until(() => h.sent.some(message => message.params?.requestId === 'revoked'));
  assert.equal(h.sent.find(message => message.params?.requestId === 'revoked').params.allow, false); assert.equal(h.admissions.length, 2);
  h.sandbox.kiNativeDisconnect(); assert.equal(h.sandbox.kiNativeSecurityLeases.size, 0); assert.equal(h.lost.length, 1);
});
test('unknown owner and cancelled leases never authorize a native send', async () => {
  const h = harness(), promise = h.sandbox.kiNativeSecurityExecute('transport.http2', {}, h.context);
  const handled = promise.catch(error => error);
  await h.until(() => h.sent.some(message => message.op === 'security_dispatch')); const dispatch = h.sent.find(message => message.op === 'security_dispatch');
  h.port.onMessage.emit({ event: 'security_admission', requestId: 'wrong-owner', owner: 'other', runId: 'run', lease: dispatch.params.context.lease, request: { url: 'https://target.test/a' } }); await h.until(() => h.sent.some(message => message.params?.requestId === 'wrong-owner'));
  assert.equal(h.sent.find(message => message.params?.requestId === 'wrong-owner').params.allow, false); assert.equal(h.admissions.length, 0);
  h.controller.abort(); assert.match((await handled).message, /cancelled/i); assert.ok(h.sent.some(message => message.op === 'security_cancel')); assert.equal(h.sandbox.kiNativeSecurityLeases.size, 0);
});
test('setup is a user action and new MCP additions do not reset unrelated servers', async () => {
  const h = harness(); await assert.rejects(h.sandbox.kiNativeSecuritySetup({ components: ['browser'] }, {}), /settings/);
  assert.equal(h.sent.length, 0);
  h.sandbox.kiNativeConnect(); h.changed.emit({ ki_native_settings: { oldValue: { enabled: true, servers: [{ command: 'node', args: ['old'] }] }, newValue: { enabled: true, servers: [{ command: 'node', args: ['old'] }, { id: 'webhook', command: 'python', args: ['-m', 'webhook_mcp_server'], secretRef: 'reference' }] } } }, 'local');
  await new Promise(resolve => setTimeout(resolve, 2)); assert.equal(h.sent.some(message => message.op === 'mcp_reset'), false);
});
test('browser follow-ups retain only an existing lease for the same owned run', async () => {
  const h = harness(), created = h.sandbox.kiNativeSecurityExecute('browser.create', {}, h.context);
  await h.until(() => h.sent.some(message => message.op === 'security_dispatch')); const first = h.sent.find(message => message.op === 'security_dispatch');
  h.port.onMessage.emit({ id: first.id, ok: true, result: { persistent: true, leaseId: first.params.context.lease } }); await created;
  const followup = h.sandbox.kiNativeSecurityExecute('browser.navigate', {}, h.context);
  await h.until(() => h.sent.filter(message => message.op === 'security_dispatch').length === 2); const second = h.sent.filter(message => message.op === 'security_dispatch')[1];
  h.port.onMessage.emit({ id: second.id, ok: true, result: { persistent: true, leaseId: first.params.context.lease } }); await followup;
  assert.equal(h.sandbox.kiNativeSecurityLeases.size, 1); assert.ok(h.sandbox.kiNativeSecurityLeases.has(first.params.context.lease));
  const foreign = h.sandbox.kiNativeSecurityExecute('browser.create', {}, { ...h.context, runId: 'other' }); const rejected = assert.rejects(foreign, /invalid persistent lease/);
  await h.until(() => h.sent.filter(message => message.op === 'security_dispatch').length === 3); const third = h.sent.filter(message => message.op === 'security_dispatch')[2];
  h.port.onMessage.emit({ id: third.id, ok: true, result: { persistent: true, leaseId: first.params.context.lease } }); await rejected;
  assert.equal(h.sandbox.kiNativeSecurityLeases.size, 1); h.sandbox.kiNativeDisconnect();
});
test('setup progress and cancellation use only the explicit installer channel', async () => {
  const h = harness(), progress = []; h.sandbox.chrome.runtime.sendMessage = async message => progress.push(message);
  const setup = h.sandbox.kiNativeSecuritySetup({components:['browser']}, {userAction:true}); const cancelled = assert.rejects(setup, /cancelled/);
  await h.until(() => h.sent.some(message => message.op === 'security_setup')); const request = h.sent.find(message => message.op === 'security_setup');
  h.port.onMessage.emit({event:'security_event',result:{type:'setup_progress',phase:'download',bytes:30,total:100}}); await h.until(() => progress.length === 1); assert.equal(progress[0].progress.bytes,30);
  const stopping = h.sandbox.kiNativeSecurityCancelSetup(); await h.until(() => h.sent.some(message => message.op === 'security_cancel')); const stop = h.sent.find(message => message.op === 'security_cancel'); assert.deepEqual(JSON.parse(JSON.stringify(stop.params)), {setup:true});
  h.port.onMessage.emit({id:stop.id,ok:true,result:{cancelled:true,setup:true}}); await stopping; h.port.onMessage.emit({id:request.id,ok:false,error:'Setup cancelled'}); await cancelled;
  assert.equal(h.sandbox.kiNativeSecuritySetupActive,false); h.port.onMessage.emit({event:'security_event',result:{type:'setup_progress',bytes:90,total:100}}); await new Promise(resolve=>setTimeout(resolve,2)); assert.equal(progress.length,1);
});
test('restart requires host support and never pretends an old host restarted',async()=>{
 const h=harness(),restart=h.sandbox.kiNativeSecurityRestart();const failure=assert.rejects(restart,/Update the local runtime/);
 await h.until(()=>h.sent.some(message=>message.op==='status'));const status=h.sent.find(message=>message.op==='status');h.port.onMessage.emit({id:status.id,ok:true,result:{features:['security_runtime_v1']}});await failure;
 assert.equal(h.sent.some(message=>message.op==='security_restart'),false);
});

test('raw protocol calls refuse stale hosts before native dispatch',async()=>{
 const h=harness();h.port.features=['security_runtime_v1'];
 await assert.rejects(h.sandbox.kiNativeSecurityExecute('transport.http1',{url:'https://target.test/'},h.context),/Update the local runtime/);
 assert.equal(h.sent.some(message=>message.op==='security_dispatch'),false);
});
test('same-host scope refuses an older host before starting local effects',async()=>{
 const h=harness();h.port.features=['security_runtime_v1','security_raw_v2'];
 await assert.rejects(h.sandbox.kiNativeSecurityExecute('browser.create',{url:'https://target.test/'},{...h.context,scope:{origins:['https://target.test'],excludePaths:[],matchMode:'host'}}),/Update the local runtime.*same-host/);
 assert.equal(h.sent.some(message=>message.op==='security_dispatch'),false);
});
test('prepared candidate inputs require a compatible native executor before dispatch',async()=>{
 const h=harness();
 await assert.rejects(h.sandbox.kiNativeSecurityExecute('browser.runCandidate',{job:{certXPreparedMutations:true}},h.context),/Update the local runtime.*candidate inputs/);
 assert.equal(h.sent.some(message=>message.op==='security_dispatch'),false);
});

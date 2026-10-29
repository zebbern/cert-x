import test from 'node:test';
import assert from 'node:assert/strict';
import { BrowserCaptureManager } from '../../../security/ptk/background/capture/browserCaptureManager.js';
const deferred = () => { let resolve; const promise = new Promise(r => resolve = r); return { promise, resolve }; };
const frame = { tabId: 1, frameId: 'root', documentId: 'doc', loaderId: 'doc', sessionGeneration: 1, url: 'https://app.test/', documentUrl: 'https://app.test/' };
const request = { ...frame, requestId: 'xhr', resourceType: 'XHR', url: 'https://app.test/opaque', method: 'GET' };
// Tests hold the drain open on purpose; the default drain timeout must outlast any process stall
// (1 s did not), and the test that exercises the timeout passes its own.
async function harness({ timeout = 10000, barrier, drain, active = () => true } = {}) {
 let emit, admit;
 const adapter = { setEventSink(fn) { emit = fn; }, setAdmission(fn) { admit = fn; },
   async configure() {}, async release() {}, getSnapshot: () => ({ frames: [frame] }),
   protocolBarrier: barrier || (async () => ({ requests: [request] })), drain: drain || (async () => {}) };
 const manager = new BrowserCaptureManager({ adapter, epoch: 'test', isOwnerActive: active });
 const lease = await manager.acquire({ ownerId: 'SCA:test', tabId: 1, acquisition: { drainTimeoutMs: timeout },
   scope: { targetUrl: frame.url }, capabilities: ['network', 'authBodies'],
   selectResource: record => record.response?.mimeType === 'application/javascript' });
 const events = []; lease.subscribe(event => events.push(event));
 return { manager, lease, events, emit: event => emit(event), admit: (...args) => admit(...args) };
}
test('stop admits only exact pre-cut request completion after late MIME, drains consumer work', async () => {
 const barrier = deferred(), nativeDrain = deferred(), consumer = deferred();
 const h = await harness({ barrier: () => barrier.promise, drain: () => nativeDrain.promise });
 h.lease.subscribe(async event => { if (event.type === 'body') await consumer.promise; });
 let done = false; const stopping = h.lease.stopAndDrain().then(result => { done = true; return result; });
 // Browser events delivered before the native protocol cut retain normal admission.
 assert.equal(h.admit(request, 'metadata'), true);
 barrier.resolve({ requests: [request] }); await new Promise(setImmediate);
 const response = { ...request, response: { status: 200, mimeType: 'application/javascript' } };
 assert.equal(h.admit(response, 'authBodies'), true);
 for (const changed of [{ requestId: 'future' }, { documentId: 'replacement' }, { hop: 1 }, { sessionGeneration: 2 }])
   assert.equal(h.admit({ ...response, ...changed }, 'authBodies'), false);
 h.emit({ type: 'body', record: { ...response, body: 'window.x=1;', complete: true } });
 nativeDrain.resolve(); await new Promise(setImmediate); assert.equal(done, false);
 consumer.resolve(); assert.equal((await stopping).complete, true);
 assert.equal(h.events.filter(event => event.type === 'body').length, 1);
 await h.lease.release('done');
});
test('stop timeout keeps earlier evidence and explicitly reports incomplete drainage', async () => {
 const pending = deferred(), h = await harness({ timeout: 5, drain: () => pending.promise });
 const result = await h.lease.stopAndDrain();
 assert.equal(result.complete, false); assert.equal(result.reason, 'capture_drain_timeout');
 assert.ok(h.events.some(event => event.record.reason === 'capture_drain_timeout'));
 await h.lease.release('done'); pending.resolve();
});
test('revocation during stop barrier cannot grant a late authenticated body', async () => {
 let active = true; const barrier = deferred();
 const h = await harness({ barrier: () => barrier.promise, active: () => active });
 const stopping = h.lease.stopAndDrain(); active = false; barrier.resolve({ requests: [request] });
 assert.equal((await stopping).complete, false);
 assert.equal(h.admit({ ...request, response: { status: 200, mimeType: 'application/javascript' } }, 'authBodies'), false);
 await h.lease.release('done');
});

test('known unrelated streams do not hold stop and unknown Fetch is released after non-JS MIME', async () => {
 const pending = deferred(); let cut;
 const stream = { ...request, requestId: 'events', resourceType: 'EventSource', response: { status: 200, mimeType: 'text/event-stream' } };
 const h = await harness({ barrier: async () => ({ requests: [stream, request] }), drain: options => pending.promise });
 // Inspect the adapter contract at the exact stop cut.
 h.manager.adapter.drain = async (tabId, options) => { cut = options.pending; await pending.promise; };
 const stopping = h.lease.stopAndDrain(); await new Promise(setImmediate);
 assert.equal(cut.size, 1, 'Only the unknown-MIME XHR is provisional');
 h.emit({ type: 'response', record: { ...request, response: { status: 200, mimeType: 'text/event-stream' } } });
 assert.equal(cut.size, 0, 'A known unrelated stream no longer blocks drainage');
 pending.resolve(); assert.equal((await stopping).complete, true);
 await h.lease.release('done');
});

test('adapter drain cut waits only for matching reads, not another owner post-cut work', async () => {
 const { ChromiumCaptureAdapter } = await import('../../../security/ptk/background/capture/chromiumCaptureAdapter.js');
 const state = { alive: true, pendingJobs: 2, requests: new Map() };
 const own = { state, record: request }, other = { state, record: { ...request, requestId: 'other-owner-after-cut' } };
 const adapter = Object.assign(Object.create(ChromiumCaptureAdapter.prototype), { tabs: new Map([[1, state]]), jobs: [], activeJobs: new Set([own, other]), running: 2, waiters: [] });
 const key = record => JSON.stringify([record.sessionId || '', record.sessionGeneration, record.requestId, record.hop || 0, record.frameId, record.documentId || record.loaderId, record.url]);
 let done = false;
 const drained = adapter.drain(1, { pending: new Set([key(request)]) }).then(() => { done = true; });
 await new Promise(setImmediate); assert.equal(done, false);
 adapter.activeJobs.delete(own); state.pendingJobs--; adapter._notifyWaiters();
 await drained;
 assert.equal(adapter.activeJobs.has(other), true, 'Other owner read remains active');
});

test('retired source collector never disables a replacement attachment debugger', async () => {
 const { ChromiumCaptureAdapter } = await import('../../../security/ptk/background/capture/chromiumCaptureAdapter.js');
 const read = deferred(), entered = deferred();
 const context = { ...frame, contextId: 7 };
 const state = { alive: true, capabilities: new Set(['executedSources']), runtimeEnabled: true, children: new Set(),
   frames: new Map([['root', context]]), defaultContexts: new Map([[JSON.stringify(['', 7]), context]]), sessionGenerations: new Map([['', 1]]) };
 const calls = [];
 const adapter = Object.assign(Object.create(ChromiumCaptureAdapter.prototype), {
   tabs: new Map([[1, state]]), maxResourceBytes: 8388608, maxTabBytes: 33554432,
   async protocolBarrier() {}, admit: () => true, _emit() {},
   async send(tabId, method) {
     calls.push(method);
     if (method === 'Debugger.enable') state.executedCollector.scripts.push({ scriptId: '1', executionContextId: 7, url: 'https://app.test/a.js' });
     if (method === 'Debugger.getScriptSource') { entered.resolve(); await read.promise; throw Error('capture_session_unavailable'); }
     return {};
   }
 });
 const collection = adapter.collectExecutedSources(1);
 await entered.promise;
 state.alive = false; adapter.tabs.set(1, { alive: true, sessionGenerations: new Map([['', 2]]) });
 read.resolve(); await collection;
 assert.equal(calls.includes('Debugger.disable'), false);
});

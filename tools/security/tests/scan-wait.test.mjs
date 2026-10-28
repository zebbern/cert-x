import test from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityService, RUNS_KEY } from '../../../security/service.mjs';

const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const progress = (idle = false, status = 'running') => ({ ok: true, status, engines: { DAST: {
  status: idle ? 'idle' : 'running', idle, progress: { done: idle ? 2 : 1, total: 2 },
  captureStats: { observedRequestsStarted: 1, observedRequestsQueued: 1 },
} } });
async function fixture(engines = ['DAST']) {
  const data = {}, calls = [], context = { owner: 'chat-one', scope: { origins: ['https://app.test'], excludePaths: [] } };
  const storage = { async get(keys) { return Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map(key => [key, data[key]])); }, async set(value) { Object.assign(data, structuredClone(value)); } };
  const runtime = { ready: Promise.resolve(), describe: async () => ({ operations: [] }), query: async () => progress(),
    async invoke(op, args, ctx) {
      calls.push(op);
      if (op === 'startScan') { await ctx.checkRequest({ url: 'https://app.test/', kind: 'dast_probe' }); return { ok: true, sessionId: 'native-one', status: 'running' }; }
      if (op === 'scanStatus') return this.query();
      if (op === 'getFindings') return { ok: true, findings: [], nextOffset: null };
      if (op === 'stopScan') return { ok: true, status: 'completed' };
      throw Error('Unexpected operation: ' + op);
    } };
  const service = createSecurityService(runtime, { storage, privateStorage: null, uuid: () => 'run-one' });
  const run = await service.handle('start', { tabId: 1, engines }, context);
  const wait = (args = {}, extra = {}) => service.handle('status', { runId: run.runId, waitForIdle: true, ...args }, { ...context, ...extra });
  return { service, runtime, context, calls, data, run, wait };
}

test('status can await actual DAST queue idle without marking the observing run complete', async () => {
  const f = await fixture(); let idle = false, reads = 0;
  f.runtime.query = async () => { reads++; return progress(idle); };
  // The second read follows a 1 s poll pause; the deadline sits well past it so a stalled process still sees idle.
  const pending = f.wait({ timeoutMs: 5000 }); setTimeout(() => { idle = true; }, 15);
  const result = await pending;
  assert.equal(result.state, 'running'); assert.equal(result.wait.outcome, 'idle'); assert.equal(result.wait.idle, true);
  assert.equal(result.wait.timedOut, false); assert.equal(result.engineStatus.DAST.idle, true);
  assert.equal(reads, 2, 'Polls at most once per second after the initial read');
  assert.equal(f.calls.filter(op => op === 'stopScan').length, 0);
});

test('wait ends on terminal engine state and retains its final result', async () => {
  const f = await fixture(); f.runtime.query = async () => progress(true, 'completed');
  const result = await f.wait();
  assert.equal(result.state, 'completed'); assert.equal(result.wait.outcome, 'terminal'); assert.equal(result.wait.timedOut, false);
  assert.equal(f.calls.filter(op => op === 'stopScan').length, 0);
});

test('wait timeout reports current progress without completing or stopping the scan', async () => {
  const f = await fixture(); const started = Date.now(), result = await f.wait({ timeoutMs: 25 });
  assert.ok(Date.now() - started < 900, 'The 25 ms timeout cuts the 1 s poll pause short'); assert.equal(result.wait.outcome, 'timeout'); assert.equal(result.wait.timedOut, true);
  assert.equal(result.state, 'running'); assert.equal(result.engineStatus.DAST.idle, false);
  assert.equal(f.calls.filter(op => op === 'stopScan').length, 0);
});

test('an unresponsive status read cannot hold the wait or publish a late terminal result', async () => {
  const f = await fixture(), gate = deferred(); f.runtime.query = () => gate.promise;
  const result = await f.wait({ timeoutMs: 20 });
  assert.equal(result.state, 'running'); assert.equal(result.wait.outcome, 'timeout');
  gate.resolve(progress(true, 'completed')); await delay(5);
  assert.equal(f.data[RUNS_KEY][0].state, 'running');
  assert.equal(f.calls.filter(op => op === 'stopScan').length, 0);
});

test('cancelling a status wait is prompt and does not cancel the scan', async () => {
  const f = await fixture(), controller = new AbortController(), gate = deferred();
  f.runtime.query = () => gate.promise;
  const pending = f.wait({}, { signal: controller.signal });
  const rejected = assert.rejects(pending, /caller cancelled/);
  setTimeout(() => controller.abort(Error('caller cancelled')), 15);
  await rejected;
  gate.resolve(progress(true, 'completed')); await delay(5);
  assert.equal(f.data[RUNS_KEY][0].state, 'running'); assert.equal(f.calls.filter(op => op === 'stopScan').length, 0);
});

test('permission revocation during a native read is checked before returning it', async () => {
  const f = await fixture(), gate = deferred(); let revoked = false;
  f.runtime.query = () => gate.promise;
  const pending = f.wait({ timeoutMs: 1000 }, { recheck: async () => { if (revoked) throw Error('permission revoked'); } });
  const rejected = assert.rejects(pending, /permission revoked/);
  await delay(5); revoked = true; gate.resolve(progress(true)); await rejected;
  assert.equal(f.calls.filter(op => op === 'stopScan').length, 0);
});

test('timeout cannot bypass a permission change during the last polling pause', async () => {
  const f = await fixture(); let revoked = false;
  const pending = f.wait({ timeoutMs: 35 }, { recheck: async () => { if (revoked) throw Error('permission revoked'); } });
  const rejected = assert.rejects(pending, /permission revoked/);
  setTimeout(() => { revoked = true; }, 10); await rejected;
  assert.equal(f.calls.filter(op => op === 'stopScan').length, 0);
});

test('a concurrent completed stop wins over an older pending status read', async () => {
  const f = await fixture(), gate = deferred(); let reads = 0;
  f.runtime.query = () => ++reads === 1 ? gate.promise : Promise.resolve(progress(true, 'completed'));
  const pending = f.wait({ timeoutMs: 40 }); await delay(5);
  const stopped = await f.service.handle('stop', { runId: f.run.runId }, f.context);
  const result = await pending;
  assert.equal(stopped.state, 'completed'); assert.equal(result.state, 'completed'); assert.equal(result.wait.outcome, 'terminal');
  gate.resolve(progress()); await delay(5); assert.equal(f.data[RUNS_KEY][0].state, 'completed');
});

test('a stop completed during final permission validation returns terminal rather than stale idle', async () => {
  const f = await fixture(); f.runtime.query = async () => progress(true);
  let checks = 0;
  const result = await f.wait({}, { recheck: async () => {
    if (++checks === 3) {
      f.runtime.query = async () => progress(true, 'completed');
      await f.service.handle('stop', { runId: f.run.runId }, f.context);
    }
  } });
  assert.equal(result.state, 'completed'); assert.equal(result.wait.outcome, 'terminal'); assert.equal(result.wait.idle, false);
});

test('wait selection validates ownership, bounds and engine applicability before polling', async () => {
  const f = await fixture(), before = f.calls.length;
  await assert.rejects(f.wait({}, { owner: 'foreign' }), /does not belong/);
  for (const timeoutMs of [0, 30001, 1.5, '100']) await assert.rejects(f.wait({ timeoutMs }), /timeoutMs/);
  await assert.rejects(f.wait({ waitForIdle: 'true' }), /boolean/);
  await assert.rejects(f.wait({ timeoutMs: 0 }), error => error.code === 'invalid_status_wait' && error.retryable === false && error.recovery.includes('waitForIdle:true'));
  assert.equal(f.calls.length, before);
  const other = await fixture(['SCA']); await assert.rejects(other.wait(), /DAST scan queue/);
  const ordinary = await f.service.handle('status', { runId: f.run.runId }, f.context);
  assert.equal(ordinary.wait, undefined);
  const disabled = await f.wait({ waitForIdle: false }); assert.equal(disabled.wait, undefined);
});

test('query failure returns unavailable rather than repeatedly retrying or claiming idle', async () => {
  const f = await fixture(); let reads = 0;
  f.runtime.query = async () => { reads++; throw Error('engine progress unavailable'); };
  const result = await f.wait();
  assert.equal(result.state, 'unknown'); assert.equal(result.wait.outcome, 'unavailable'); assert.equal(reads, 1);
  assert.equal(result.wait.idle, false); assert.equal(f.calls.filter(op => op === 'stopScan').length, 0);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityService } from '../../../security/service.mjs';

function harness(snapshot, { failStop = false, dispatches = [] } = {}) {
  const data = {};
  const storage = {
    async get(keys) { return Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map(key => [key, data[key]])); },
    async set(values) { Object.assign(data, values); }
  };
  let stopped = false;
  const runtime = {
    ready: Promise.resolve(),
    async describe() { return { operations: [] }; },
    async invoke(operation, args, context) {
      if (operation === 'startScan') { for(const request of dispatches)await context.checkRequest(request);return { sessionId: 'native-dast', status: 'running' }; }
      if (operation === 'scanStatus') return { ok: true, status: stopped ? 'completed' : 'running', engines: { DAST: snapshot } };
      if (operation === 'stopScan') { if (failStop) throw Error('fixture stop failed'); stopped = true; return { ok: true, status: 'completed' }; }
      if (operation === 'getFindings') return { ok: true, findings: [], nextOffset: null };
      throw Error('Unexpected operation: ' + operation);
    }
  };
  const service = createSecurityService(runtime, { storage, privateStorage: null, uuid: () => 'run-dast' });
  const context = { owner: 'chat', workspaceId: 'workspace', scope: { origins: ['http://127.0.0.1:3181'], excludePaths: [] } };
  return { service, context };
}

const empty = { status: 'idle', progress: { done: 0, total: 0 }, captureStats: { observedRequestsStarted: 0, observedRequestsQueued: 0, observedRequestsErrored: 0 }, proxySeededRequests: 0, selectedTargetSeededRequests: 0, waitingForInteraction: true };

test('mixed-engine admission counts keep DAST baselines and probes separate',async()=>{
 const url='http://127.0.0.1:3181/',f=harness({...empty,progress:{done:1,total:1},waitingForInteraction:false,selectedTargetSeededRequests:1},{dispatches:[{url,kind:'dast_baseline'},{url,kind:'dast_probe'},{url,kind:'other_engine'}]});
 const run=await f.service.handle('start',{tabId:1,engines:['DAST','SCA']},f.context);
 assert.equal(run.coverage.dast.baselineDispatches,1);assert.equal(run.coverage.dast.probeDispatches,1);assert.equal(run.coverage.dast.dastRequestsDispatched,2);assert.equal(run.coverage.dast.runRequestsDispatched,3);assert.notEqual(run.coverage.dast.phase,'dispatch_attribution_unknown');
 await f.service.handle('stop',{runId:run.runId},f.context);
});

test('DAST zero-input stop is incomplete, with distinct zero dispatch and task counts', async () => {
  const { service, context } = harness(empty);
  const started = await service.handle('start', { tabId: 1, engines: ['DAST'], options: { preset: 'ptk-defaults' } }, context);
  assert.equal(started.state, 'running');
  assert.equal(started.coverage.dast.phase, 'waiting_for_interaction');
  assert.equal(started.coverage.dast.runRequestsDispatched, 0);
  const ended = await service.handle('stop', { runId: started.runId }, context);
  assert.equal(ended.state, 'incomplete');
  assert.equal(ended.coverage.dast.phase, 'no_requests');
  assert.equal(ended.coverage.dast.tasksExecuted, 0);
  assert.equal(ended.coverage.dast.runRequestsDispatched, 0);
});

test('DAST engine failure inside successful status stays visible and can be stopped', async () => {
  const { service, context } = harness({ ...empty, engineError: 'fixture engine rejected planning' });
  const started = await service.handle('start', { tabId: 1, engines: ['DAST'] }, context);
  assert.equal(started.state, 'unknown');
  assert.equal(started.error, 'fixture engine rejected planning');
  assert.equal(started.coverage.dast.phase, 'engine_error');
  const ended = await service.handle('stop', { runId: started.runId }, context);
  assert.equal(ended.state, 'error');
  assert.equal(ended.coverage.dast.error, 'fixture engine rejected planning');
});

test('failed stop retains final DAST coverage and the stop error', async () => {
  const { service, context } = harness(empty, { failStop: true });
  const started = await service.handle('start', { tabId: 1, engines: ['DAST'] }, context);
  const result = await service.handle('stop', { runId: started.runId }, context);
  assert.equal(result.state, 'unknown');
  assert.equal(result.error, 'fixture stop failed');
  assert.equal(result.coverage.dast.phase, 'no_requests');
});

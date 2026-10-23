import test from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityService, RUNS_KEY, PRIVATE_EVIDENCE_KEY } from '../../../security/service.mjs';
import { resolveConfig, validateOptions, scopeAllows, SETTINGS_KEY } from '../../../security/config.mjs';

test('browser reads never inherit navigation or login effects from creation or response state',async()=>{
 const f=fixture(),calls=[];f.runtime.describe=async()=>({operations:['browser']});
 f.runtime.invoke=async(op,args)=>{calls.push(structuredClone(args));return {sessionId:'browser-a',url:'about:blank',persistent:true};};
 const created=await f.service.handle('execute',{capability:'browser',arguments:{action:'create',url:'https://app.test/original',actions:[{type:'click',selector:'#submit'}]}},f.context);
 const invoke=(action,extra={})=>f.service.handle('execute',{capability:'browser',arguments:{action,runId:created.runId,...extra}},f.context);
 await invoke('navigate',{url:'https://app.test/new'});
 for(const action of ['inspect','screenshot','capture','status'])await invoke(action);
 assert.equal(calls[1].url,'https://app.test/new');
 for(const args of calls.slice(2)){assert.equal(args.url,undefined);assert.equal(args.actions,undefined);assert.equal(args.sessionId,'browser-a');assert.equal(args.runId,created.runId);}
 await f.service.handle('stop',{runId:created.runId},f.context);
});
test('candidate actions sent to browser tools fail before native dispatch or run creation',async()=>{
 const f=fixture();f.runtime.describe=async()=>({operations:['browser']});
 await assert.rejects(f.service.handle('execute',{capability:'browser',arguments:{action:'reproduce',runId:'wrong-family'}},f.context),/security_candidates.*No local operation/);
 assert.equal(f.calls.length,0);assert.equal((await f.service.handle('state',{},f.context)).runs.length,0);
});
test('candidate job follow-ups explain missing execution references before creating another run',async()=>{
 const f=fixture();f.runtime.describe=async()=>({operations:['candidate']});
 await assert.rejects(f.service.handle('execute',{capability:'candidate',arguments:{action:'status',runId:'source',jobId:'job'}},f.context),/requires executionRunId.*No local operation/);
 assert.equal(f.calls.length,0);assert.equal((await f.service.handle('state',{},f.context)).runs.length,0);
});

test('raw evidence paging does not resend original wire bytes or response fields',async()=>{
 const f=fixture(),calls=[];f.runtime.describe=async()=>({operations:['raw']});
 f.runtime.invoke=async(op,args)=>{calls.push(structuredClone(args));return args.action==='evidence'?{base64:'e30=',nextOffset:null}:{response:{base64:'response-bytes'},evidence:{evidenceId:'evidence-a'}};};
 const run=await f.service.handle('execute',{capability:'raw',arguments:{action:'http1',requestBase64:'request-bytes'}},f.context);
 await f.service.handle('execute',{capability:'raw',arguments:{action:'evidence',runId:run.runId,evidenceId:'evidence-a',offset:0}},f.context);
 assert.deepEqual(calls[1],{action:'evidence',runId:run.runId,evidenceId:'evidence-a',offset:0});
});

function fixture(seed = {}) {
  const data = structuredClone(seed), calls = [], contexts = new Map(); let sequence = 0;
  const storage = { async get(keys) { return Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map(key => [key, structuredClone(data[key])])); }, async set(value) { Object.assign(data, structuredClone(value)); } };
  const runtime = { ready: Promise.resolve(), describe: async () => ({ operations: ['startScan','scanStatus','stopScan','getFindings','exportFullReport','replay','utility'], version: '10.0.0' }),
    async invoke(op, args, context) {
      calls.push({op,args,context});
      if (op === 'startScan') { const sessionId = 'native-' + ++sequence; contexts.set(sessionId, context); return { ok: true, sessionId, status: 'running' }; }
      if (op === 'scanStatus') return { status: 'running', engines: { DAST: { ready: true } } };
      if (op === 'stopScan') return { status: 'completed', summary: { stopped: true } };
      if (op === 'getFindings') return { findings: [{ id: 'one', nativeProof: { status: 403, body: 'protected record' } }], nextOffset: null, coverage: { tested: 1 } };
      if (op === 'exportFullReport') return { reports: [{ engine: 'DAST', data: { native: true } }] };
      return { ok: true, result: 'done' };
    } };
  const service = createSecurityService(runtime, { storage, uuid: () => 'run-' + ++sequence });
  const context = { owner: 'chat-a', workspaceId: 'work-a', scope: { origins: ['https://app.test', 'https://api.test'], excludePaths: ['/excluded'] } };
  return { service, runtime, storage, data, calls, contexts, context, start: options => service.handle('start', { tabId: 1, engines: ['DAST'], options }, context) };
}

test('run reference lookup returns only this chat and recovers source scans without native handles', async () => {
 const f=fixture(),a=await f.start(),b=await f.service.handle('start',{tabId:2,engines:['SCA']},{...f.context,owner:'other'});
 const list=await f.service.handle('runs',{limit:1},f.context);
 assert.equal(list.total,1);assert.equal(list.runs[0].runId,a.runId);assert.equal(list.runs[0].kind,'scan');assert.equal(list.runs[0].runtimeId,undefined);
 await assert.rejects(f.service.handle('status',{runId:b.runId},f.context),error=>error.code==='run_reference_unavailable'&&error.retryable===false&&error.recovery.includes('security_list_runs'));
 await assert.rejects(f.service.handle('runs',{},{}),/Choose a chat/);
 await f.service.handle('stop',{runId:a.runId},f.context);await f.service.handle('stop',{runId:b.runId},{...f.context,owner:'other'});
});

test('unsupported utility selection fails before dispatch or run creation', async () => {
 const f=fixture();
 await assert.rejects(f.service.handle('execute',{capability:'utility',arguments:{tool:'zap',action:'scan'}},f.context),error=>error.code==='invalid_operation_arguments'&&error.retryable===false);
 assert.equal(f.calls.length,0);assert.equal((await f.service.handle('runs',{},f.context)).total,0);
});

test('findings and exports retain exact module totals and selected engines for reporting', async () => {
 const f=fixture(),invoke=f.runtime.invoke.bind(f.runtime);
 f.runtime.invoke=(op,args,context)=>op==='getFindings'?Promise.resolve({findings:[{id:'x1',moduleId:'xss'},{id:'x2',moduleId:'xss'},{id:'cmd',moduleId:'os_command_injection'}],nextOffset:null}):invoke(op,args,context);
 const run=await f.start();const findings=await f.service.handle('findings',{runId:run.runId,limit:1},f.context);
 assert.equal(findings.total,3);assert.deepEqual(findings.summary.byModule,{xss:2,os_command_injection:1});assert.equal(findings.summary.countsBasis,'retained_findings');assert.deepEqual(findings.selectedEngines,['DAST']);
 assert.equal(findings.requestBudget.exhausted,false);assert.equal(findings.requestBudget.used,run.requestsSent);
 const exported=await f.service.handle('export',{runId:run.runId},f.context);
 assert.deepEqual(exported.run.summary.byModule,findings.summary.byModule);assert.deepEqual(exported.run.engines,['DAST']);
 await f.service.handle('stop',{runId:run.runId},f.context);
});

test('terminal DAST status retains the planned-versus-entered accounting gap', async () => {
 const f=fixture(),original=f.runtime.invoke.bind(f.runtime);let stopped=false;
 f.runtime.invoke=async(op,args,context)=>{
  if(op==='stopScan'){stopped=true;return {status:'completed',engines:{DAST:{progress:{total:100,done:60},captureStats:{observedRequestsStarted:1},idle:true}}};}
  if(op==='scanStatus')return {status:stopped?'completed':'running',engines:{DAST:{progress:{total:100,done:60},captureStats:{observedRequestsStarted:1},idle:true}}};
  return original(op,args,context);
 };
 const run=await f.start(),active=await f.service.handle('status',{runId:run.runId},f.context);
 assert.equal(active.coverage.dast.plannedMinusEntered,40);
 assert.ok(!active.coverage.actionableGaps.some(gap=>gap.code==='planned_tasks_not_entered'));
 const ended=await f.service.handle('stop',{runId:run.runId},f.context);
 assert.equal(ended.coverage.dast.plannedMinusEntered,40);
 assert.ok(ended.coverage.actionableGaps.some(gap=>gap.code==='planned_tasks_not_entered'));
});

test('tightening acquisition ceilings stops active SCA and keeps evidence', async () => {
  const f = fixture();
  const run = await f.service.handle('start', { tabId: 1, engines: ['SCA'], options: { acquisition: { maxScripts: 256 } } }, f.context);
  await f.storage.set({ [SETTINGS_KEY]: { limits: { acquisition: { maxScripts: 64 } } } });
  const stopped = await f.service.handle('revalidate');
  assert.equal(stopped.length, 1);
  assert.match(stopped[0].stopReason, /Acquisition limits were reduced/);
  assert.ok(f.calls.some(call => call.op === 'stopScan'));
  const evidence = await f.service.handle('findings', { runId: run.runId }, f.context);
  assert.equal(evidence.findings[0].id, 'one');
});

test('nested acquisition updates preserve other defaults and explicit ceilings', async () => {
  const f = fixture(), context = { ...f.context, userAction: true };
  await f.service.handle('configure', { defaults: { acquisition: { maxScripts: 512, drainTimeoutMs: 7000 } }, limits: { acquisition: { maxScripts: 600 } } }, context);
  await f.service.handle('configure', { defaults: { acquisition: { drainTimeoutMs: 9000 } }, limits: { acquisition: { drainTimeoutMs: 12000 } } }, context);
  const value = await f.service.resolveConfig('work-a');
  assert.equal(value.acquisition.maxScripts, 512);
  assert.equal(value.acquisition.drainTimeoutMs, 9000);
  assert.deepEqual(value.limits.acquisition, { maxScripts: 600, drainTimeoutMs: 12000 });
});

test('a late failing status poll cannot overwrite a completed stop', async () => {
  const f = fixture(), run = await f.service.handle('start', { tabId: 1, engines: ['SCA'] }, f.context);
  const invoke = f.runtime.invoke.bind(f.runtime);
  let rejectPoll, entered;
  const pending = new Promise(resolve => { entered = resolve; });
  let held = false;
  f.runtime.invoke = (op, args, context) => {
    if (op === 'scanStatus' && !held) { held = true; entered(); return new Promise((_, reject) => { rejectPoll = reject; }); }
    return invoke(op, args, context);
  };
  const poll = f.service.handle('status', { runId: run.runId }, f.context);
  await pending;
  const ended = await f.service.handle('stop', { runId: run.runId }, f.context);
  rejectPoll(Error('late target detached'));
  assert.equal((await poll).state, ended.state);
  assert.equal((await f.service.handle('status', { runId: run.runId }, f.context)).error, undefined);
});

test('SCA empty acquisition is incomplete and recovery survives evidence collection and export', async () => {
  const f = fixture(), invoke = f.runtime.invoke.bind(f.runtime);
  f.runtime.invoke = (op, args, context) => op === 'scanStatus' ? { status: 'completed', coverage: { scaBodies: { analyzed: 0 }, scaSources: { analyzed: 0 } } } : invoke(op, args, context);
  const run = await f.service.handle('start', { tabId: 1, engines: ['SCA'] }, f.context);
  assert.equal(run.state, 'incomplete');
  const findings = await f.service.handle('findings', { runId: run.runId }, f.context);
  assert.ok(findings.coverage.actionableGaps.some(gap => gap.code === 'no_content_analyzed'));
  const report = await f.service.handle('export', { runId: run.runId }, f.context);
  assert.equal(report.report.run.coverage.recovery.state, 'incomplete');
});

test('Thorough defaults preserve comprehensive native controls and have no old hard ceilings', () => {
  const defaults = resolveConfig(); assert.equal(defaults.scanStrategy, 'COMPREHENSIVE'); assert.equal(defaults.scanControlProfile, 'wide'); assert.equal(defaults.maxRequests, null);assert.equal(defaults.schedulerBreadthFirst,true);assert.equal(defaults.enableHtmlLinkDiscovery,true);assert.equal(defaults.htmlLinkDiscoveryBudget,'safe');
  const configured = resolveConfig({}, null, { maxRequests: 30000, durationSeconds: 7200, concurrency: 9, maxRequestsPerSecond: 20 });
  assert.equal(configured.maxRequests, 30000); assert.equal(configured.durationSeconds, 7200); assert.equal(configured.concurrency, 9);
  assert.equal(resolveConfig({}, null, { schedulerBreadthFirst:false }).schedulerBreadthFirst,false);
  assert.equal(resolveConfig({}, null, { preset: 'ptk-defaults' }).scanStrategy, 'SMART');assert.equal(resolveConfig({}, null, { preset: 'ptk-defaults' }).schedulerBreadthFirst,false);assert.equal(resolveConfig({}, null, { preset:'ptk-defaults' }).enableHtmlLinkDiscovery,undefined);
});

test('local persistent operations bind one lease and budget across follow-ups, with cleanup after revocation',async()=>{
 const f=fixture();f.runtime.describe=async()=>({operations:['browser']});let initial,revoked=false;
 f.context.recheck=async()=>{if(revoked)throw Error('revoked');};
 f.context.localExecute=async(action,args,ctx)=>{if(action==='browser.create'){initial=ctx;await ctx.checkRequest({url:'https://app.test/one'});return {sessionId:'private-browser',persistent:true,state:'open'};}if(action==='browser.navigate'){assert.equal(ctx.runId,initial.runId);assert.equal(ctx.checkRequest,initial.checkRequest);await ctx.checkRequest({url:args.url});return {persistent:true,state:'open'};}if(action==='browser.close'){await ctx.checkRequest({kind:'control'});await assert.rejects(ctx.checkRequest({url:'https://app.test/forbidden'}),/stopped operation/);return {state:'closed'};}throw Error(action);};
 f.runtime.invoke=(cap,args,ctx)=>ctx.localExecute(cap+'.'+args.action,args);
 const result=await f.service.handle('execute',{capability:'browser',arguments:{action:'create'}},f.context);assert.equal((await f.service.handle('state',{},f.context)).runs[0].state,'running');
 await f.service.handle('execute',{capability:'browser',arguments:{action:'navigate',runId:result.runId,url:'https://app.test/two'}},f.context);
 assert.equal((await f.service.handle('state',{},f.context)).runs[0].requestsSent,2);
 await assert.rejects(f.service.handle('execute',{capability:'browser',arguments:{action:'navigate',runId:result.runId}}, {...f.context,owner:'foreign'}),/does not belong/);
 revoked=true;assert.equal((await f.service.handle('stop',{runId:result.runId},f.context)).state,'cancelled');
});

test('local executor loss interrupts owned active operations without replaying them',async()=>{
 const f=fixture();f.runtime.describe=async()=>({operations:['browser']});f.runtime.invoke=async()=>({persistent:true,sessionId:'private',state:'open'});
 const run=await f.service.handle('execute',{capability:'browser',arguments:{action:'create'}},f.context);await f.service.localLost('pipe closed');
 assert.equal((await f.service.handle('status',{runId:run.runId},f.context)).state,'interrupted');
 await assert.rejects(f.service.handle('execute',{capability:'browser',arguments:{action:'navigate',runId:run.runId}},f.context),/lease ended/);
});

test('missing or mismatched browser run references fail before native side effects',async()=>{
 const f=fixture();f.runtime.describe=async()=>({operations:['browser']});let calls=0;
 f.runtime.invoke=async()=>{calls++;return {sessionId:'session-a',persistent:true,state:'open'};};
 for(const action of ['navigate','status','inspect','interact','close'])await assert.rejects(f.service.handle('execute',{capability:'browser',arguments:{action,sessionId:'session-a',url:'https://app.test/'}},f.context),/original runId/);
 assert.equal(calls,0);assert.equal((await f.service.handle('state',{},f.context)).runs.length,0);
 const created=await f.service.handle('execute',{capability:'browser',arguments:{action:'create'}},f.context);
 await assert.rejects(f.service.handle('execute',{capability:'browser',arguments:{action:'navigate',runId:created.runId,sessionId:'other',url:'https://app.test/'}},f.context),/does not match/);assert.equal(calls,1);
 await f.service.handle('execute',{capability:'browser',arguments:{action:'navigate',runId:created.runId,url:'https://app.test/'}},f.context);assert.equal(calls,2);
});

test('polling a local operation during creation waits for its actual native handle',async()=>{
 const f=fixture();f.runtime.describe=async()=>({operations:['browser']});let release,entered;
 const created=new Promise(resolve=>{entered=resolve;}),pending=new Promise(resolve=>{release=resolve;});let statusCalls=0;
 f.runtime.invoke=async(_op,args)=>{if(args.action==='create'){entered();await pending;return {sessionId:'actual-session',state:'open',persistent:true};}statusCalls++;assert.equal(args.sessionId,'actual-session');return {state:'open',persistent:true};};
 const work=f.service.handle('execute',{capability:'browser',arguments:{action:'create'}},f.context);await created;
 const initial=(await f.service.handle('state',{},f.context)).runs[0];
 assert.equal((await f.service.handle('status',{runId:initial.runId},f.context)).state,'starting');assert.equal(statusCalls,0);
 release();await work;const state=await f.service.handle('status',{runId:initial.runId},f.context);
 assert.equal(statusCalls,1);assert.equal(state.state,'running');assert.equal(state.error,undefined);
});

test('stopping a finite raw operation awaits abort without invoking a nonexistent stop action',async()=>{
 const f=fixture();f.runtime.describe=async()=>({operations:['raw']});let entered,settled=false,calls=0;
 const started=new Promise(resolve=>{entered=resolve;});
 f.runtime.invoke=async(_op,args,ctx)=>{calls++;assert.equal(args.action,'http1');entered();await new Promise((_,reject)=>ctx.signal.addEventListener('abort',()=>setTimeout(()=>{settled=true;reject(ctx.signal.reason);},20),{once:true}));};
 const work=f.service.handle('execute',{capability:'raw',arguments:{action:'http1'}},f.context);const rejected=assert.rejects(work,/Stopped by user/);await started;
 const id=(await f.service.handle('state',{},f.context)).runs[0].runId;
 const stopped=await f.service.handle('stop',{runId:id},f.context);await rejected;
 assert.equal(settled,true);assert.equal(stopped.state,'cancelled');assert.equal(stopped.error,undefined);assert.equal(calls,1);
});
test('workspace preferences and explicit user limits have distinct precedence', () => {
  const settings = { defaults: { concurrency: 5 }, limits: { concurrency: 4, maxRequests: 150 }, workspaces: { work: { defaults: { concurrency: 3 }, limits: { maxRequests: 100 } } } };
  assert.equal(resolveConfig(settings, 'work').concurrency, 3); assert.equal(resolveConfig(settings, 'work').maxRequests, 100);
  assert.throws(() => resolveConfig(settings, 'work', { maxRequests: null }), /explicit user limit/);
  assert.throws(() => resolveConfig(settings, 'work', { concurrency: 5 }), /explicit user limit/);
  assert.equal(resolveConfig(settings, 'work', { maxRequests: 70 }).maxRequests, 70);
});
test('invalid and prototype-bearing configuration is rejected, without silently ignoring misspelled limits', () => {
  assert.throws(() => validateOptions({ maxRequsts: 10 }), /Unknown security option/);
  assert.throws(() => validateOptions({ concurrency: 1.5 }), /integer/);
  assert.throws(() => validateOptions(JSON.parse('{"engineOptions":{"__proto__":{"x":1}}}')), /Unsafe/);
});
test('scope exclusions apply after repeated path decoding while query payloads remain available',()=>{
 const scope={origins:['https://app.test'],excludePaths:['/admin']};
 for(const path of ['/admin/x','/%61dmin','/%2561dmin','/safe/../admin','/admin;matrix/x'])assert.equal(scopeAllows('https://app.test'+path,scope),false,path);
 assert.equal(scopeAllows('https://app.test/search?q=%2561dmin',scope),true);assert.equal(scopeAllows('https://app.test/administrator',scope),true);
});
test('configured run scope cannot be widened, and host mode survives a narrower exact-origin run',async()=>{
 const f=fixture();f.context.scope={origins:['https://app.test:8443'],excludePaths:['/private'],matchMode:'host'};
 await assert.rejects(f.service.handle('start',{tabId:1,scope:{origins:['https://other.test'],excludePaths:[]}},f.context),/exceeds/);
 await assert.rejects(f.service.handle('start',{tabId:1,scope:{origins:['https://app.test:8443'],excludePaths:[],matchMode:'host',includeSubdomains:true}},f.context),/exceeds/);
 const run=await f.service.handle('start',{tabId:1,scope:{origins:['http://app.test:8080'],excludePaths:[]}},f.context);
 const guard=[...f.contexts.values()][0].checkRequest;
 await guard({url:'http://app.test:8080/public'});
 await assert.rejects(guard({url:'https://app.test:8443/public'}),/outside run scope/);
 await assert.rejects(guard({url:'http://app.test:8080/private/data'}),/outside.*scope/);
 await f.service.handle('stop',{runId:run.runId},f.context);
});
test('run ownership is enforced for status, evidence and export', async () => {
  const f = fixture(), run = await f.start();
  for (const op of ['status','findings','evidence','stop','export']) await assert.rejects(f.service.handle(op,{runId:run.runId},{owner:'chat-b'}), /does not belong/);
  const result = await f.service.handle('findings',{runId:run.runId},f.context); assert.equal(result.findings[0].nativeProof.status,403);
});
test('equivalent concurrent starts reuse a single native scan', async () => {
  const f = fixture(); const [a,b] = await Promise.all([f.start(),f.start()]);
  assert.equal(a.runId,b.runId); assert.equal(b.reused,true); assert.equal(f.calls.filter(x=>x.op==='startScan').length,1);
});
test('all findings pages are retained, not silently capped at 500', async () => {
  const f = fixture(), native = f.runtime.invoke;
  f.runtime.invoke = async (op,args,ctx) => op === 'getFindings' ? { findings: Array.from({length:args.offset===0?500:30},(_,i)=>({id:String(args.offset+i)})), nextOffset:args.offset===0?500:null } : native(op,args,ctx);
  const run = await f.start(), result = await f.service.handle('findings',{runId:run.runId,offset:500},f.context);
  assert.equal(result.total,530); assert.equal(result.findings.length,30); assert.equal(result.nextOffset,null);
});
test('engine truncation without a continuation remains explicit', async () => {
  const f = fixture(), native = f.runtime.invoke;
  f.runtime.invoke = async (op,args,ctx) => op === 'getFindings' ? { findings:[{id:'sample'}],truncated:true } : native(op,args,ctx);
  const run=await f.start(),result=await f.service.handle('findings',{runId:run.runId},f.context);
  assert.equal(result.truncated,true); assert.match(result.error,/truncated/);
});
test('each dispatched request checks scope, exclusions, revocation and live user limits', async () => {
  const f=fixture(); let allowed=true; f.context.recheck=async()=>{if(!allowed)throw Error('revoked');};
  const run=await f.start({maxRequests:3,maxRequestsPerSecond:100000}); const guard=[...f.contexts.values()][0].checkRequest;
  await guard({url:'https://app.test/one'}); await guard({url:'https://api.test/two'});
  await assert.rejects(guard({url:'https://outside.test/'}),/outside/); await assert.rejects(guard({url:'https://app.test/excluded/data'}),/outside/);
  allowed=false;await assert.rejects(guard({url:'https://app.test/three'}),/revoked/);allowed=true;
  await f.storage.set({[SETTINGS_KEY]:{limits:{maxRequests:2}}});await assert.rejects(guard({url:'https://app.test/three'}),/budget exhausted/);
});
test('explicit request limits are shared by concurrent child runs with the same owner', async () => {
  const f=fixture({[SETTINGS_KEY]:{limits:{maxRequests:2}}});
  await f.start({maxRequestsPerSecond:100000}); await f.service.handle('start',{tabId:2,engines:['SAST'],options:{maxRequestsPerSecond:100000}},f.context);
  const [a,b]=[...f.contexts.values()];await a.checkRequest({url:'https://app.test/a'});await b.checkRequest({url:'https://api.test/b'});await assert.rejects(b.checkRequest({url:'https://app.test/c'}),/budget exhausted/);
});

test('raw sends consume shared probe budgets while connections and HTTP counts stay distinct',async()=>{
  const f=fixture({[SETTINGS_KEY]:{limits:{maxRequests:3}}});
  const run=await f.start({maxRequestsPerSecond:100000});
  await f.service.handle('start',{tabId:2,engines:['SAST'],options:{maxRequestsPerSecond:100000}},f.context);
  const [a,b]=[...f.contexts.values()];
  await a.checkRequest({kind:'raw_connect',url:'wss://app.test/socket'});
  await assert.rejects(a.checkRequest({kind:'raw_connect',url:'wss://app.test/excluded/socket'}),/outside/);
  await assert.rejects(a.checkRequest({kind:'raw_send',url:'https://app.test/',targets:[{url:'https://outside.test/'}]}),/outside/);
  await assert.rejects(a.checkRequest({kind:'raw_send',url:'https://app.test/',targets:[{url:'https://app.test/excluded/'}]}),/outside/);
  await assert.rejects(a.checkRequest({kind:'raw_send',url:'https://app.test/',targets:[{}]}),/Invalid raw routing/);
  await a.checkRequest({kind:'raw_send',url:'wss://app.test/socket'});
  await a.checkRequest({url:'https://app.test/normal'});
  await b.checkRequest({kind:'raw_send',url:'https://api.test/control'});
  const state=await f.service.handle('status',{runId:run.runId},f.context);
  assert.equal(state.requestsSent,2);assert.equal(state.probeUnits,1);assert.equal(state.httpRequestsSent,1);assert.equal(state.connectionAttempts,1);
  await assert.rejects(b.checkRequest({kind:'raw_send',url:'https://api.test/probe'}),/budget exhausted/);
});

test('raw decoded routing targets are rechecked against changed workspace scope before dispatch',async()=>{
 const f=fixture();f.context.scopeNow=async()=>({origins:['https://app.test'],excludePaths:[]});
 const run=await f.start({maxRequestsPerSecond:100000}),context=[...f.contexts.values()][0];
 await assert.rejects(context.checkRequest({kind:'raw_send',url:'https://app.test/',targets:[{url:'https://api.test/restricted'}]}),/workspace scope changed/);
 assert.equal((await f.service.handle('status',{runId:run.runId},f.context)).requestsSent,0);
});
test('application errors inside successful transport responses are not accepted', async () => {
  const f=fixture();f.runtime.invoke=async()=>({ok:true,result:{success:false,error:'engine failed'}});
  await assert.rejects(f.start(),/engine failed/); const state=await f.service.handle('state',{},f.context);assert.equal(state.runs[0].state,'unknown');
});
test('settings cannot be rewritten by model execution', async () => {
  const f=fixture(); await assert.rejects(f.service.handle('configure',{defaults:{maxRequests:800}},f.context),/direct settings/);
  const result=await f.service.handle('configure',{scope:'workspace',defaults:{maxRequests:800},limits:{concurrency:2}},{...f.context,userAction:true});assert.equal(result.config.maxRequests,800);assert.equal(result.config.concurrency,2);
});
test('restart retains evidence, marks interrupted work and never repeats a start', async () => {
  const f=fixture(),run=await f.start(); await f.service.handle('findings',{runId:run.runId},f.context);
  const starts=f.calls.filter(x=>x.op==='startScan').length;
  const recovered=createSecurityService(f.runtime,{storage:f.storage});await recovered.ready;
  const state=await recovered.handle('state',{},f.context);assert.equal(state.runs[0].state,'interrupted');assert.equal(f.calls.filter(x=>x.op==='startScan').length,starts);
  const findings=await recovered.handle('findings',{runId:run.runId},f.context);assert.equal(findings.findings[0].id,'one');assert.equal(f.data[RUNS_KEY][0].state,'interrupted');
});
test('scope revocation during a rate wait rejects queued work without counting it as sent', async () => {
  const f=fixture(); let scope=f.context.scope;f.context.scopeNow=async()=>scope;
  const run=await f.start({maxRequestsPerSecond:20}),guard=[...f.contexts.values()][0].checkRequest;
  await guard({url:'https://app.test/a'});const queued=guard({url:'https://app.test/b'});
  await new Promise(resolve=>setTimeout(resolve,5));scope={origins:['https://api.test'],excludePaths:[]};
  await assert.rejects(queued,/scope changed/);const state=await f.service.handle('state',{},f.context);assert.equal(state.runs[0].requestsSent,1);assert.equal(state.runs[0].requestsReserved,0);await f.service.handle('stop',{runId:run.runId},f.context);
});
test('limits reduced during a rate wait are checked at actual dispatch', async () => {
  const f=fixture();await f.start({maxRequestsPerSecond:20});const guard=[...f.contexts.values()][0].checkRequest;
  await guard({url:'https://app.test/a'});const queued=guard({url:'https://app.test/b'});
  await new Promise(resolve=>setTimeout(resolve,5));await f.storage.set({[SETTINGS_KEY]:{limits:{maxRequests:1}}});
  await assert.rejects(queued,/budget exhausted/);const state=await f.service.handle('state',{},f.context);assert.equal(state.runs[0].requestsSent,1);assert.equal(state.runs[0].requestsReserved,0);
});
test('replay transport errors inside native request schemas are failed operations with retained evidence',async()=>{
  const f=fixture();f.runtime.invoke=async()=>({request:{url:'https://app.test/'},response:{statusCode:'',errorName:'Error',errorMessage:'redirect outside scope'}});
  await assert.rejects(f.service.handle('execute',{capability:'replay',tabId:1,arguments:{request:{url:'https://app.test/'}}},f.context),/redirect outside scope/);
  const state=await f.service.handle('state',{},f.context);assert.equal(state.runs[0].state,'error');assert.equal(state.runs[0].operation,'replay');
  const evidence=await f.service.handle('evidence',{runId:state.runs[0].runId},f.context);assert.equal(evidence.result.response.errorMessage,'redirect outside scope');
});
test('saving defaults never removes limits and saving limits never removes preferences',async()=>{
  const f=fixture(),user={...f.context,userAction:true};
  for(const scope of ['global','workspace']) {
    await f.service.handle('configure',{scope,limits:{maxRequests:40}},user);
    await f.service.handle('configure',{scope,defaults:{maxRequestsPerSecond:7}},user);
    const a=await f.service.handle('settings');const bucket=scope==='global'?a:a.workspaces['work-a'];assert.equal(bucket.limits.maxRequests,40);assert.equal(bucket.defaults.maxRequestsPerSecond,7);
    await f.service.handle('configure',{scope,limits:{concurrency:2}},user);
    const b=await f.service.handle('settings');const next=scope==='global'?b:b.workspaces['work-a'];assert.equal(next.limits.maxRequests,40);assert.equal(next.defaults.maxRequestsPerSecond,7);
  }
});
test('concurrent settings saves preserve independent global and workspace changes',async()=>{
  const f=fixture(),user={...f.context,userAction:true};await Promise.all([
    f.service.handle('configure',{scope:'global',limits:{maxRequests:50}},user),
    f.service.handle('configure',{scope:'workspace',defaults:{maxRequestsPerSecond:8}},user),
  ]);const settings=await f.service.handle('settings');assert.equal(settings.limits.maxRequests,50);assert.equal(settings.workspaces['work-a'].defaults.maxRequestsPerSecond,8);
});
test('explicit concurrency is shared by sibling runs and releases on errors',async()=>{
  const f=fixture({[SETTINGS_KEY]:{limits:{concurrency:1}}});await f.start();await f.service.handle('start',{tabId:2,engines:['SAST']},f.context);
  const [a,b]=[...f.contexts.values()];let release,entered=false;
  const first=a.withRequest({url:'https://app.test/'},()=>new Promise(resolve=>release=resolve));
  while(!release)await new Promise(resolve=>setTimeout(resolve,1));
  const second=b.withRequest({url:'https://api.test/'},async()=>{entered=true;throw Error('network failed');});
  await new Promise(resolve=>setTimeout(resolve,5));assert.equal(entered,false);release('ok');await first;await assert.rejects(second,/network failed/);
  assert.equal(await a.withRequest({},async()=>42),42);
});
test('opaque status zero is not a successful HTTP replay',async()=>{
  const f=fixture();f.runtime.invoke=async()=>({request:{url:'https://app.test/'},response:{statusLine:'HTTP/1.1 0',statusCode:0,headers:[]}});
  await assert.rejects(f.service.handle('execute',{capability:'replay',tabId:1,arguments:{request:{url:'https://app.test/'}}},f.context),/opaque or unavailable/);
});
test('resolved account credentials stay in session evidence and out of model results and persistent summaries',async()=>{
  const f=fixture(),privateData={},privateStorage={get:async key=>({[key]:privateData[key]}),set:async value=>Object.assign(privateData,structuredClone(value))};await f.service.ready;
  f.runtime.invoke=async()=>({request:{url:'https://app.test/',headers:[{name:'Authorization',value:'Bearer PRIVATE-ACCOUNT-TOKEN'},{name:'Cookie',value:'session=PRIVATE-COOKIE'}]},response:{statusCode:200,body:'application evidence'}});
  const service=createSecurityService(f.runtime,{storage:f.storage,privateStorage}),context={...f.context,account:{headers:[{name:'Authorization',value:'Bearer PRIVATE-ACCOUNT-TOKEN'},{name:'Cookie',value:'session=PRIVATE-COOKIE'}]}};
  const result=await service.handle('execute',{capability:'replay',tabId:1,arguments:{request:{url:'https://app.test/'}}},context);
  assert.ok(!JSON.stringify(result).includes('PRIVATE-ACCOUNT-TOKEN'));assert.ok(!JSON.stringify(f.data).includes('PRIVATE-ACCOUNT-TOKEN'));
  assert.equal(privateData[PRIVATE_EVIDENCE_KEY][result.runId].native.request.headers[0].value,'Bearer PRIVATE-ACCOUNT-TOKEN');
  assert.equal(result.response.body,'application evidence');
});
test('revocation stops passive observation even without another network request',async()=>{
 const f=fixture();let allowed=true;f.context.recheck=async()=>{if(!allowed)throw Error('Permission revoked');};
 const run=await f.service.handle('start',{tabId:1,engines:['IAST']},f.context);allowed=false;await f.service.handle('revalidate');
 const state=await f.service.handle('state',{},f.context);assert.equal(state.runs.find(item=>item.runId===run.runId).state,'completed');assert.equal(f.calls.filter(item=>item.op==='stopScan').length,1);
});
test('a confirmed preflight refusal releases its reservation and allows a later start',async()=>{
 const f=fixture(),original=f.runtime.invoke;let refuse=true;
 f.runtime.invoke=async(op,args,context)=>{if(op==='startScan'&&refuse)throw Object.assign(Error('Engine already running'),{admitted:false});return original(op,args,context);};
 await assert.rejects(f.start(),/already running/);let state=await f.service.handle('state',{},f.context);assert.equal(state.runs[0].state,'error');
 refuse=false;const run=await f.start();assert.equal(run.state,'running');assert.equal(run.reused,undefined);await f.service.handle('stop',{runId:run.runId},f.context);
});
test('capture and macro admission stay running until native activity ends, with correct stop routing',async()=>{
 const f=fixture();f.runtime.describe=async()=>({operations:['capture','macro']});let capture=true,mode='replay',stopPending=true;
 f.runtime.invoke=async(op,args)=>{f.calls.push({op,args});if(op==='capture'){if(args.action==='stop')capture=false;return {active:capture};}if(args.action==='replay')return {success:true,accepted:true};if(args.action==='stop'&&!stopPending)mode=null;return {mode,replayResult:{status:mode?'running':'stopped'}};};
 const captured=await f.service.handle('execute',{capability:'capture',tabId:1,arguments:{action:'start'}},f.context);assert.equal((await f.service.handle('status',{runId:captured.runId},f.context)).state,'running');
 capture=false;assert.equal((await f.service.handle('status',{runId:captured.runId},f.context)).state,'completed');
 const replay=await f.service.handle('execute',{capability:'macro',tabId:1,arguments:{action:'replay'}},f.context);assert.equal((await f.service.handle('status',{runId:replay.runId},f.context)).state,'running');
 assert.equal((await f.service.handle('stop',{runId:replay.runId},f.context)).state,'stopping');mode=null;
 assert.equal((await f.service.handle('status',{runId:replay.runId},f.context)).state,'cancelled');assert.ok(!f.calls.some(call=>call.op==='stopScan'));
});
test('PDF and Markdown requests require the declared artifact and never silently fall back to JSON',async()=>{
 const f=fixture(),run=await f.start(),original=f.runtime.invoke;await f.service.handle('stop',{runId:run.runId},f.context);
 await assert.rejects(f.service.handle('export',{runId:run.runId,format:'pdf'},f.context),/did not produce/);
 f.runtime.invoke=async(op,args,context)=>op==='exportFullReport'?{reports:[],artifact:{format:args.format,mime:args.format==='pdf'?'application/pdf':'text/markdown',...(args.format==='pdf'?{bytes:[37,80,68,70,45,49,46,55]}:{text:'# Report'})}}:original(op,args,context);
 const pdf=await f.service.handle('export',{runId:run.runId,format:'pdf',options:{preset:'executive'}},f.context);assert.equal(pdf.artifact.mime,'application/pdf');
 const md=await f.service.handle('export',{runId:run.runId,format:'markdown'},f.context);assert.equal(md.artifact.text,'# Report');
});
test('identity preparation consumes the same run request budget before engine admission',async()=>{
 const f=fixture({[SETTINGS_KEY]:{limits:{maxRequests:2}}});f.context.prepare=async context=>{await context.checkRequest({url:'https://app.test/me'});await context.checkRequest({url:'https://app.test/me'});};
 const run=await f.start({maxRequestsPerSecond:100000});assert.equal(run.requestsSent,2);const context=[...f.contexts.values()][0];await assert.rejects(context.checkRequest({url:'https://app.test/object'}),/budget exhausted/);
});
test('failed identity preparation cannot launch the engine and releases admission',async()=>{
 const f=fixture();f.context.prepare=async()=>{throw Error('Identity mismatch');};await assert.rejects(f.start(),/Identity mismatch/);assert.equal(f.calls.filter(call=>call.op==='startScan').length,0);assert.equal((await f.service.handle('state',{},f.context)).runs[0].state,'error');
 delete f.context.prepare;const run=await f.start();assert.equal(run.state,'running');await f.service.handle('stop',{runId:run.runId},f.context);
});
test('restart binds recovered DAST evidence to its original automation session and preserves full native data',async()=>{
 const f=fixture(),run=await f.start();const persisted=f.data[RUNS_KEY][0];
 f.runtime.recoverInterrupted=async({sessionId})=>({sessionId,engines:[{engine:'DAST',scanId:'native-scan',scan:{requests:[{id:'request',response:{body:'preserved native proof'}}]}}],findings:[{id:'recovered',ruleId:'xss_1'}]});
 const restarted=createSecurityService(f.runtime,{storage:f.storage});await restarted.ready;
 // Startup now collects the first status/evidence snapshot. Recovery must merge
 // it with the recovered engine snapshot instead of discarding either source.
 const findings=await restarted.handle('findings',{runId:run.runId},f.context);assert.deepEqual(findings.findings.map(item=>item.id).sort(),['one','recovered']);
 const evidence=await restarted.handle('evidence',{runId:run.runId},f.context);assert.equal(evidence.native.sessionId,persisted.runtimeId);assert.equal(evidence.native.engines[0].scan.requests[0].response.body,'preserved native proof');
 assert.equal((await restarted.handle('state',{},f.context)).runs[0].state,'interrupted');
});
test('restart refuses a mismatched recovery snapshot without exposing another run’s findings',async()=>{
 const f=fixture(),run=await f.start();f.runtime.recoverInterrupted=async()=>({sessionId:'other-session',findings:[{id:'foreign'}]});
 const restarted=createSecurityService(f.runtime,{storage:f.storage});await restarted.ready;
 const result=await restarted.handle('findings',{runId:run.runId},f.context);assert.deepEqual(result.findings.map(item=>item.id),['one']);assert.ok(!result.findings.some(item=>item.id==='foreign'));assert.match(result.error,/different engine session/);
});

test('follow-up approval comes from the current action without mutating the original lease',async()=>{
 const f=fixture(),seen=[];f.runtime.describe=async()=>({operations:['oast']});
 f.runtime.invoke=async(op,args,context)=>{seen.push(context);return {oastId:'endpoint',state:'monitoring',persistent:true};};
 const first=await f.service.handle('execute',{capability:'oast',arguments:{action:'create'}},{...f.context,permissionApproved:true});
 await f.service.handle('execute',{capability:'oast',arguments:{action:'events',runId:first.runId}},{...f.context,permissionApproved:false});
 await f.service.handle('execute',{capability:'oast',arguments:{action:'events',runId:first.runId}},{...f.context,permissionApproved:true});
 assert.equal(seen[0].permissionApproved,true);assert.equal(seen[1].permissionApproved,false);assert.deepEqual(seen[1].currentActionApproval,{approved:false,userAction:false});assert.equal(seen[2].currentActionApproval.approved,true);
 assert.equal(seen[1].checkRequest,seen[0].checkRequest);assert.notEqual(seen[1],seen[2]);
});

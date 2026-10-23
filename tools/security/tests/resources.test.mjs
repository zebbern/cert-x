import test from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityResources } from '../../../security/resources.mjs';

function fixture() {
  const calls = [], values = {}, session = new Map(), dynamic = new Map();
  const event = () => { const listeners = new Set(); return { addListener: fn => listeners.add(fn), removeListener: fn => listeners.delete(fn), emit: (...args) => { for (const fn of listeners) fn(...args); } }; };
  let failAttach = false, failStorage = false, failedCommand, document;
  const chrome = {
    runtime: { id: 'fixture', onMessage: event(), getURL: name => 'chrome-extension://fixture/' + name, async getContexts() { return document ? [{ documentUrl: document }] : []; } },
    storage: { session: { async get(key) { return { [key]: structuredClone(values[key]) }; }, async set(data) { if (failStorage) throw Error('storage unavailable'); Object.assign(values, structuredClone(data)); } } },
    debugger: {
      onEvent: event(), onDetach: event(),
      attach(target, version, cb) { calls.push(['attach', target, version]); if (failAttach) chrome.runtime.lastError = { message: 'another debugger owns target' }; cb(); delete chrome.runtime.lastError; },
      detach(target, cb) { calls.push(['detach', target]); chrome.debugger.onDetach.emit(target, 'canceled_by_user'); cb(); },
      sendCommand(target, method, params, cb) { calls.push([method, target, params]); if(failedCommand===method){failedCommand=undefined;chrome.runtime.lastError={message:'command failed'};cb();delete chrome.runtime.lastError;}else cb({ result: 'ok' }); },
      getTargets(cb) { cb([]); }
    },
    declarativeNetRequest: Object.fromEntries(['Session', 'Dynamic'].flatMap(kind => {
      const map = kind === 'Session' ? session : dynamic;
      return [['get' + kind + 'Rules', cb => cb([...map.values()])], ['update' + kind + 'Rules', (change, cb) => { for (const id of change.removeRuleIds || []) map.delete(id); for (const rule of change.addRules || []) map.set(rule.id, rule); cb(); }]];
    })),
    offscreen: {
      hasDocument(cb) { cb(!!document); },
      createDocument(options, cb) { document = chrome.runtime.getURL(options.url); cb(); },
      closeDocument(cb) { document = undefined; cb(); }
    }
  };
  return { chrome, calls, values, session, dynamic, failAttach: () => { failAttach = true; }, failStorage: () => { failStorage = true; }, failCommand: method => { failedCommand=method; } };
}

const iframeAutoAttach={autoAttach:true,waitForDebuggerOnStart:false,flatten:true,filter:[{type:'iframe',exclude:false},{exclude:true}]};

test('new Runtime owner receives exact live contexts without disabling another owner', async () => {
 const f=fixture(),r=createSecurityResources(f.chrome),a=r.forOwner('browser'),b=r.forOwner('scan'),target={tabId:4},child={tabId:4,sessionId:'child'},seen=[];
 await r.ready;await a.debugger.attach(target,'1.3');await a.debugger.sendCommand(target,'Runtime.enable');
 const emit=(source,id,uniqueId)=>f.chrome.debugger.onEvent.emit(source,'Runtime.executionContextCreated',{context:{id,uniqueId,origin:'https://app.test',name:'',auxData:{isDefault:true,frameId:'frame'}}});
 emit(target,1,'old');emit(target,2,'destroyed');
 f.chrome.debugger.onEvent.emit(target,'Runtime.executionContextDestroyed',{executionContextUniqueId:'destroyed'});
 emit(target,1,'new');
 f.chrome.debugger.onEvent.emit(target,'Target.attachedToTarget',{sessionId:'child',targetInfo:{type:'iframe'}});
 await a.debugger.sendCommand(child,'Runtime.enable');emit(child,1,'child-context');
 await b.debugger.attach(target,'1.3');b.debugger.onEvent.addListener((source,method,params)=>seen.push({source,method,params}));
 await b.debugger.sendCommand(target,'Runtime.enable');
 assert.deepEqual(seen.map(x=>x.params.context.uniqueId),['new']);
 assert.deepEqual(seen[0].source,target);
 await b.debugger.sendCommand(target,'Runtime.enable');assert.equal(seen.length,1,'No duplicate replay to existing subscriber');
 await b.debugger.sendCommand(child,'Runtime.enable');assert.equal(seen[1].params.context.uniqueId,'child-context');assert.deepEqual(seen[1].source,child);
 await b.debugger.sendCommand(target,'Runtime.disable');await b.debugger.sendCommand(child,'Runtime.disable');await b.debugger.detach(target);
 assert.equal(f.calls.filter(call=>call[0]==='Runtime.disable'||call[0]==='detach').length,0);
 assert.deepEqual(await a.debugger.sendCommand(target,'Runtime.evaluate',{expression:'1'}),{result:'ok'});
});

test('context replay cannot survive navigation clear, child detach, or last Runtime disable', async () => {
 const f=fixture(),r=createSecurityResources(f.chrome),a=r.forOwner('a'),b=r.forOwner('b'),target={tabId:7},child={tabId:7,sessionId:'child'},seen=[];
 await r.ready;await a.debugger.attach(target,'1.3');await b.debugger.attach(target,'1.3');
 const created=source=>f.chrome.debugger.onEvent.emit(source,'Runtime.executionContextCreated',{context:{id:1,uniqueId:'stale',auxData:{isDefault:true}}});
 await a.debugger.sendCommand(target,'Runtime.enable');created(target);f.chrome.debugger.onEvent.emit(target,'Runtime.executionContextsCleared',{});
 b.debugger.onEvent.addListener((source,method,params)=>{if(method==='Runtime.executionContextCreated')seen.push(params);});
 await b.debugger.sendCommand(target,'Runtime.enable');assert.equal(seen.length,0);
 await b.debugger.sendCommand(target,'Runtime.disable');created(target);seen.length=0;await a.debugger.sendCommand(target,'Runtime.disable');
 await a.debugger.sendCommand(target,'Runtime.enable');await b.debugger.sendCommand(target,'Runtime.enable');assert.equal(seen.length,0);
 f.chrome.debugger.onEvent.emit(target,'Target.attachedToTarget',{sessionId:'child',targetInfo:{type:'iframe'}});await a.debugger.sendCommand(child,'Runtime.enable');created(child);seen.length=0;
 f.chrome.debugger.onEvent.emit(target,'Target.detachedFromTarget',{sessionId:'child'});
 created(child);seen.length=0; // Late events from the detached incarnation are not replayable.
 f.chrome.debugger.onEvent.emit(target,'Target.attachedToTarget',{sessionId:'child',targetInfo:{type:'iframe'}});
 await a.debugger.sendCommand(child,'Runtime.enable');await b.debugger.sendCommand(child,'Runtime.enable');assert.equal(seen.length,0);
});

test('bounded incomplete context inventory refuses partial replay without disturbing existing owner', async () => {
 const f=fixture(),r=createSecurityResources(f.chrome),a=r.forOwner('a'),b=r.forOwner('b'),target={tabId:7};
 await r.ready;await a.debugger.attach(target,'1.3');await b.debugger.attach(target,'1.3');await a.debugger.sendCommand(target,'Runtime.enable');
 f.chrome.debugger.onEvent.emit(target,'Runtime.executionContextCreated',{context:{id:1,name:'x'.repeat(40000)}});
 await assert.rejects(b.debugger.sendCommand(target,'Runtime.enable'),/inventory incomplete/);
 await b.debugger.sendCommand(target,'Runtime.disable');assert.equal(f.calls.filter(call=>call[0]==='Runtime.disable').length,0);
 f.chrome.debugger.onEvent.emit(target,'Runtime.executionContextsCleared',{});
 await b.debugger.sendCommand(target,'Runtime.enable');
});

test('matching auto-attach consumers share ownership and replay existing children only to new subscribers',async()=>{
 const f=fixture(),r=createSecurityResources(f.chrome),capture=r.forOwner('capture'),iast=r.forOwner('iast'),target={tabId:4},seen=[];await r.ready;
 await capture.debugger.attach(target,'1.3');await capture.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach);
 f.chrome.debugger.onEvent.emit(target,'Target.attachedToTarget',{sessionId:'child',targetInfo:{type:'iframe',targetId:'frame'}});
 iast.debugger.onEvent.addListener((source,method,params)=>seen.push({source,method,params}));await iast.debugger.attach(target,'1.3');
 await iast.debugger.sendCommand(target,'Target.setAutoAttach',{filter:[{exclude:false,type:'iframe'},{exclude:true}],flatten:true,autoAttach:true,waitForDebuggerOnStart:false});
 assert.equal(seen.length,1);assert.equal(seen[0].params.sessionId,'child');assert.deepEqual(seen[0].source,target);
 await iast.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach);assert.equal(seen.length,1);
 assert.equal(f.calls.filter(call=>call[0]==='Target.setAutoAttach').length,1);
 await iast.debugger.sendCommand(target,'Target.setAutoAttach',{autoAttach:false});
 assert.equal(f.calls.filter(call=>call[0]==='Target.setAutoAttach'&&!call[2].autoAttach).length,0);
 await capture.debugger.detach(target);
 assert.equal(f.calls.filter(call=>call[0]==='Target.setAutoAttach'&&!call[2].autoAttach).length,1);
  assert.equal(f.calls.find(call=>call[0]==='Target.setAutoAttach'&&!call[2].autoAttach)[2].filter,undefined,'Chrome forbids a target filter when disabling auto-attach');
 assert.equal(f.calls.filter(call=>call[0]==='detach').length,0);
 assert.deepEqual(await iast.debugger.sendCommand(target,'Runtime.evaluate',{expression:'1'}),{result:'ok'});
 await iast.debugger.detach(target);assert.equal(f.calls.filter(call=>call[0]==='detach').length,1);
});

test('shared auto-attach rejects incompatible configuration and preserves callback errors',async()=>{
 const f=fixture(),r=createSecurityResources(f.chrome),a=r.forOwner('a'),b=r.forOwner('b'),target={tabId:5};await r.ready;
 await a.debugger.attach(target,'1.3');await b.debugger.attach(target,'1.3');
 f.failCommand('Target.setAutoAttach');await assert.rejects(a.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach),/command failed/);
 await b.debugger.sendCommand(target,'Target.setAutoAttach',{...iframeAutoAttach,waitForDebuggerOnStart:true});
 let error;await a.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach,()=>{error=a.runtime.lastError?.message;});assert.match(error,/configuration is in use/);assert.equal(a.runtime.lastError,undefined);
 await b.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach); // sole subscriber can reconfigure
 await a.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach);
 const before=f.calls.length;await assert.rejects(b.debugger.sendCommand(target,'Target.setAutoAttach',{...iframeAutoAttach,filter:[{type:'worker',exclude:false}]}),/configuration is in use/);assert.equal(f.calls.length,before);
 await a.debugger.sendCommand(target,'Target.setAutoAttach',{autoAttach:false});f.failCommand('Target.setAutoAttach');
 await assert.rejects(b.debugger.sendCommand(target,'Target.setAutoAttach',{autoAttach:false}),/command failed/);
 await b.debugger.sendCommand(target,'Target.setAutoAttach',{autoAttach:false});
 assert.equal(f.calls.filter(call=>call[0]==='Target.setAutoAttach'&&!call[2].autoAttach).length,2,'Failed disable retains ownership so it can be retried');
});

test('detached child sessions purge descendant subscriptions and domains without disturbing the parent owner',async()=>{
 const f=fixture(),r=createSecurityResources(f.chrome),a=r.forOwner('a'),b=r.forOwner('b'),target={tabId:6},child={tabId:6,sessionId:'child'},grand={tabId:6,sessionId:'grand'};await r.ready;
 await a.debugger.attach(target,'1.3');await b.debugger.attach(target,'1.3');await a.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach);
 f.chrome.debugger.onEvent.emit(target,'Target.attachedToTarget',{sessionId:'child',targetInfo:{type:'iframe'}});
 await a.debugger.sendCommand(child,'Target.setAutoAttach',iframeAutoAttach);await a.debugger.sendCommand(child,'Page.enable');
 f.chrome.debugger.onEvent.emit(child,'Target.attachedToTarget',{sessionId:'grand',targetInfo:{type:'iframe'}});await a.debugger.sendCommand(grand,'Runtime.enable');
 f.chrome.debugger.onEvent.emit(target,'Target.detachedFromTarget',{sessionId:'child'});const before=f.calls.length;
 await a.debugger.sendCommand(child,'Target.setAutoAttach',{autoAttach:false});await a.debugger.sendCommand(grand,'Runtime.disable');
 assert.equal(f.calls.length,before);await assert.rejects(a.debugger.sendCommand(grand,'Runtime.evaluate',{expression:'1'}),/child session detached/);
 const seen=[];b.debugger.onEvent.addListener((_,method,params)=>seen.push([method,params]));await b.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach);assert.equal(seen.length,0,'Detached children are not replayed');
 await a.debugger.detach(target);assert.equal(f.calls.filter(call=>call[0]==='detach'||/\.disable$/.test(call[0])).length,0);
 assert.deepEqual(await b.debugger.sendCommand(target,'Runtime.evaluate',{expression:'1'}),{result:'ok'});
});

test('nested subscriptions release children before parent and preserve another owner on the same child',async()=>{
 const f=fixture(),r=createSecurityResources(f.chrome),a=r.forOwner('a'),b=r.forOwner('b'),target={tabId:8},child={tabId:8,sessionId:'child'};await r.ready;
 await a.debugger.attach(target,'1.3');await b.debugger.attach(target,'1.3');await a.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach);
 f.chrome.debugger.onEvent.emit(target,'Target.attachedToTarget',{sessionId:'child',targetInfo:{type:'iframe'}});
 await a.debugger.sendCommand(child,'Target.setAutoAttach',iframeAutoAttach);await b.debugger.sendCommand(child,'Target.setAutoAttach',iframeAutoAttach);
 await a.debugger.detach(target);
 assert.equal(f.calls.filter(call=>call[0]==='Target.setAutoAttach'&&!call[2].autoAttach).length,0,'Another consumer of a child keeps its parent subscription alive');
 await b.debugger.sendCommand(child,'Target.setAutoAttach',{autoAttach:false});
 const disabled=f.calls.filter(call=>call[0]==='Target.setAutoAttach'&&!call[2].autoAttach);assert.deepEqual(disabled.map(call=>call[1].sessionId),['child',undefined]);
 assert.ok(disabled.every(call=>!Object.hasOwn(call[2],'filter')),'Recursive cleanup omits filters on every disabled session');
});

test('child domain consumers retain parent auto-attach until the domain is released',async()=>{
 const f=fixture(),r=createSecurityResources(f.chrome),a=r.forOwner('a'),b=r.forOwner('b'),target={tabId:9},child={tabId:9,sessionId:'child'};await r.ready;
 await a.debugger.attach(target,'1.3');await b.debugger.attach(target,'1.3');await a.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach);
 f.chrome.debugger.onEvent.emit(target,'Target.attachedToTarget',{sessionId:'child',targetInfo:{type:'iframe'}});await b.debugger.sendCommand(child,'Runtime.enable');
 await a.debugger.detach(target);assert.equal(f.calls.filter(call=>call[0]==='Target.setAutoAttach'&&!call[2].autoAttach).length,0);
 await b.debugger.sendCommand(child,'Runtime.disable');assert.equal(f.calls.at(-1)[0],'Target.setAutoAttach');assert.equal(f.calls.at(-1)[2].autoAttach,false);
});

test('closing the last dependent child prunes the otherwise unowned parent subscription',async()=>{
 const f=fixture(),r=createSecurityResources(f.chrome),a=r.forOwner('a'),b=r.forOwner('b'),target={tabId:10},child={tabId:10,sessionId:'child'};await r.ready;
 await a.debugger.attach(target,'1.3');await b.debugger.attach(target,'1.3');await a.debugger.sendCommand(target,'Target.setAutoAttach',iframeAutoAttach);
 f.chrome.debugger.onEvent.emit(target,'Target.attachedToTarget',{sessionId:'child',targetInfo:{type:'iframe'}});await b.debugger.sendCommand(child,'Runtime.enable');await a.debugger.detach(target);
 f.chrome.debugger.onEvent.emit(target,'Target.detachedFromTarget',{sessionId:'child'});
 await b.debugger.sendCommand(target,'Runtime.evaluate',{expression:'1'}); // ordered after event cleanup
 assert.equal(f.calls.filter(call=>call[0]==='Target.setAutoAttach'&&!call[2].autoAttach).length,1);
 assert.equal(f.calls.filter(call=>call[0]==='Runtime.disable'||call[0]==='detach').length,0);
});

test('a child detached during enable cannot resurrect its domain or auto-attach record',async()=>{
 for(const method of ['Page.enable','Target.setAutoAttach']){
  const f=fixture(),r=createSecurityResources(f.chrome),a=r.forOwner('a'),b=r.forOwner('b'),target={tabId:11},child={tabId:11,sessionId:'child'};await r.ready;
  await a.debugger.attach(target,'1.3');await b.debugger.attach(target,'1.3');f.chrome.debugger.onEvent.emit(target,'Target.attachedToTarget',{sessionId:'child',targetInfo:{type:'iframe'}});
  const nativeSend=f.chrome.debugger.sendCommand;f.chrome.debugger.sendCommand=(source,command,params,cb)=>{if(command===method&&source.sessionId==='child')f.chrome.debugger.onEvent.emit(target,'Target.detachedFromTarget',{sessionId:'child'});nativeSend(source,command,params,cb);};
  await assert.rejects(a.debugger.sendCommand(child,method,method==='Target.setAutoAttach'?iframeAutoAttach:{}),/child session detached/);await a.debugger.detach(target);
  assert.equal(f.calls.some(call=>call[1]?.sessionId==='child'&&(/\.disable$/.test(call[0])||call[2]?.autoAttach===false)),false);
 }
});

test('one attachment serves agent and capture; domain disable and release retain other owner', async () => {
  const f = fixture(), resources = createSecurityResources(f.chrome), browser = resources.forOwner('browser'), security = resources.chrome;
  await resources.ready;
  const target = { tabId: 12 };
  await security.debugger.attach(target, '1.3');
  await browser.debugger.detach(target); // Legacy pre-attach cleanup.
  await browser.debugger.attach(target, '1.3');
  await security.debugger.sendCommand(target, 'Network.enable', { maxTotalBufferSize: 100 });
  await browser.debugger.sendCommand(target, 'Network.enable', { maxTotalBufferSize: 50 });
  assert.equal(f.calls.filter(call => call[0] === 'attach').length, 1);
  assert.equal(f.calls.at(-1)[2].maxTotalBufferSize, 100);
  await browser.debugger.sendCommand(target, 'Network.disable');
  await browser.debugger.detach(target);
  assert.equal(f.calls.filter(call => call[0] === 'Network.disable' || call[0] === 'detach').length, 0);
  assert.deepEqual(await security.debugger.sendCommand(target, 'Runtime.evaluate', { expression: '1' }), { result: 'ok' });
  await security.debugger.detach(target);
  assert.equal(f.calls.filter(call => call[0] === 'detach').length, 1);
});

test('events reach only current owners and external detach revokes both', async () => {
  const f = fixture(), resources = createSecurityResources(f.chrome), a = resources.forOwner('a'), b = resources.forOwner('b');
  await resources.ready;
  let events = 0, detaches = 0;
  a.debugger.onEvent.addListener(() => events++); b.debugger.onEvent.addListener(() => events++);
  a.debugger.onDetach.addListener(() => detaches++); b.debugger.onDetach.addListener(() => detaches++);
  await a.debugger.attach({ tabId: 1 }, '1.3'); await b.debugger.attach({ tabId: 2 }, '1.3');
  f.chrome.debugger.onEvent.emit({ tabId: 1 }, 'Network.requestWillBeSent', {}); assert.equal(events, 1);
  await b.debugger.attach({ tabId: 1 }, '1.3');
  f.chrome.debugger.onDetach.emit({ tabId: 1 }, 'target_closed'); assert.equal(detaches, 2);
  await assert.rejects(a.debugger.sendCommand({ tabId: 1 }, 'Runtime.evaluate'), /not acquired/);
});

test('callback consumers see errors through facade runtime.lastError', async () => {
  const f = fixture(), resources = createSecurityResources(f.chrome); await resources.ready; f.failAttach();
  let message;
  await resources.chrome.debugger.attach({ tabId: 1 }, '1.3', () => { message = resources.chrome.runtime.lastError?.message; });
  assert.match(message, /another debugger/); assert.equal(resources.chrome.runtime.lastError, undefined);
  await assert.rejects(resources.chrome.debugger.attach({ tabId: 1 }, '1.3'), /another debugger/);
});

test('exclusive debugger domain cannot be claimed by another owner', async () => {
  const f = fixture(), r = createSecurityResources(f.chrome), a = r.forOwner('a'), b = r.forOwner('b'); await r.ready;
  await a.debugger.attach({ tabId: 1 }, '1.3'); await b.debugger.attach({ tabId: 1 }, '1.3');
  await a.debugger.sendCommand({ tabId: 1 }, 'Fetch.enable', {});
  await assert.rejects(b.debugger.sendCommand({ tabId: 1 }, 'Fetch.enable', {}), /in use/);
});

test('rule namespaces survive restart; upstream reset cannot delete CSP or another owner', async () => {
  const f = fixture(); f.session.set(830000001, { id: 830000001, action: { type: 'modifyHeaders' } });
  const r = createSecurityResources(f.chrome); await r.ready;
  const rule = { id: 1, condition: { urlFilter: '|https://example.test/' }, action: { type: 'block' } };
  await r.chrome.declarativeNetRequest.updateSessionRules({ addRules: [rule] });
  await r.forOwner('accounts').declarativeNetRequest.updateSessionRules({ addRules: [rule] });
  assert.equal(f.session.size, 3);
  const restarted = createSecurityResources(f.chrome); await restarted.ready;
  const owned = await restarted.chrome.declarativeNetRequest.getSessionRules(); assert.deepEqual(owned, [rule]);
  await restarted.chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: owned.map(item => item.id) });
  assert.equal(f.session.size, 2); assert.ok(f.session.has(830000001));
  assert.deepEqual(await restarted.forOwner('accounts').declarativeNetRequest.getSessionRules(), [rule]);
});

test('failed rule ownership persistence rolls physical rule update back', async () => {
  const f = fixture(), r = createSecurityResources(f.chrome); await r.ready; f.failStorage();
  await assert.rejects(r.chrome.declarativeNetRequest.updateSessionRules({ addRules: [{ id: 1, condition: {}, action: { type: 'block' } }] }), /storage unavailable/);
  assert.equal(f.session.size, 0);
});

test('offscreen document shares a URL and is not closed by an unowned release', async () => {
  const f = fixture(), r = createSecurityResources(f.chrome), b = r.forOwner('browser'); await r.ready;
  await r.chrome.offscreen.createDocument({ url: 'security/ptk/offscreen/runtime_offscreen.html', reasons: ['WORKERS'], justification: 'test' });
  await b.offscreen.closeDocument(); assert.equal(await r.chrome.offscreen.hasDocument(), true);
  await assert.rejects(b.offscreen.createDocument({ url: 'different.html' }), /in use/);
  await b.offscreen.createDocument({ url: 'security/ptk/offscreen/runtime_offscreen.html' });
  await r.chrome.offscreen.closeDocument(); assert.equal(await b.offscreen.hasDocument(), true);
  await b.offscreen.closeDocument(); assert.equal(await b.offscreen.hasDocument(), false);
});

test('imported popup and page management channels cannot bypass native permissions', async () => {
  const f=fixture(),r=createSecurityResources(f.chrome);await r.ready;const seen=[];
  const handler=message=>seen.push(message.channel);r.chrome.runtime.onMessage.addListener(handler);
  for(const channel of ['ptk_popup2background_request','ptk_popup2background_settings','ptk_content2background_automation','ptk_privileged_replayable_export'])f.chrome.runtime.onMessage.emit({channel},{id:'fixture'},()=>{});
  f.chrome.runtime.onMessage.emit({channel:'ptk_content_sast2background_sast'},{id:'fixture'},()=>{});
  assert.deepEqual(seen,['ptk_content_sast2background_sast']);
  r.chrome.runtime.onMessage.removeListener(handler);assert.equal(r.chrome.runtime.onMessage.hasListener(handler),false);
});

test('worker restart releases only recorded attachments still controlled by this extension', async () => {
  const f=fixture(),r=createSecurityResources(f.chrome);await r.ready;
  await r.chrome.debugger.attach({tabId:7},'1.3');
  const next=createSecurityResources(f.chrome);await next.ready;
  assert.equal(f.calls.filter(call=>call[0]==='detach').length,1);
  await next.chrome.debugger.attach({tabId:7},'1.3');
  assert.equal(f.calls.filter(call=>call[0]==='attach').length,2);
});

// Native contract.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),{webcrypto}=require('node:crypto');
const event=()=>({listeners:[],addListener(fn){this.listeners.push(fn);},removeListener(){}});
async function setup(){
 const {createSecurityService}=await import('../../../security/service.mjs');let n=0;
 const data={sidepanel_approval_mode:'full_access'},privateData={},calls=[],outputs=[],approvals=[],native=new Map();
 const area=target=>({async get(keys){return Object.fromEntries((Array.isArray(keys)?keys:[keys]).map(k=>[k,structuredClone(target[k])]));},async set(value){Object.assign(target,structuredClone(value));}});
 const tab={id:1,url:'https://app.test/home',title:'App',status:'complete'};
 const chrome={runtime:{id:'extension',getURL:p=>'chrome-extension://extension/'+p,onMessage:event(),getManifest:()=>({version:'1'}),connectNative(){throw Error('Browser-only testing must not connect to the disabled local runtime.');}},storage:{local:area(data),session:area(privateData),onChanged:event()},tabs:{get:async()=>tab,query:async()=>[tab],onRemoved:event()},alarms:{onAlarm:event(),create:async()=>{},clear:async()=>{}},webNavigation:{onCommitted:event()},notifications:{onClicked:event()},downloads:{download:async()=>9,search:async()=>[{id:9,state:'complete',filename:'C:/Downloads/security.json'}]}};
 const runtime={ready:Promise.resolve(),describe:async()=>({ready:true,version:'10.0.0',operations:['startScan','scanStatus','stopScan','getFindings','getEvidence','exportFullReport','replay','utility']}),async invoke(op,args,context){calls.push({op,args,context});
  if(op==='startScan'){const sessionId='native-'+ ++n;native.set(sessionId,{status:'running',context});return {ok:true,sessionId,status:'running'};}
  if(op==='scanStatus')return {status:native.get(args.sessionId)?.status||'interrupted',engines:{IAST:{status:native.get(args.sessionId)?.status,agentReady:true}}};
  if(op==='stopScan'){native.get(args.sessionId).status='completed';return {ok:true,status:'completed'};}
  if(op==='getFindings')return {findings:[{id:'finding',native:{proof:'evidence'}}],nextOffset:null,coverage:{tested:1}};
  if(op==='getEvidence')return {finding:{id:args.evidenceId,response:{status:403,body:'protected'}}};
  if(op==='exportFullReport')return {reports:[{engine:'IAST',data:{findings:['candidate']}}]};
  if(op==='replay'){await context.checkRequest(args.request);return {response:{status:200}};}return {ok:true};
 }};
 const service=createSecurityService(runtime,{storage:chrome.storage.local,uuid:()=> 'run-'+ ++n}),selected={workspace:null,tools:{groups:{ptk:true},tools:{}},permissions:{groups:{},tools:{}}};
 const context=vm.createContext({chrome,console,crypto:webcrypto,URL,TextEncoder,TextDecoder,Uint8Array,setTimeout,clearTimeout,AbortController,Date,Error,Map,Set,Promise,queueMicrotask,btoa:x=>Buffer.from(x,'binary').toString('base64'),certXSecurity:service,
  kiWorkspaceOwner:s=>s==='child'?'chat':s,kiWorkspaceOutput:async(s,item)=>outputs.push({s,item}),kiWorkspaceCapture:async()=>{},kiContextResolve:async()=>structuredClone(selected),kiContextFor:()=>selected,kiContextAllows:(m,c)=>m.securityStop||c.tools.groups.ptk!==false,kiContextRule:(m,c,r)=>m.securityStop?'allow':c.tools.groups.ptk===false?'disabled':r,kiContextArgs:(_n,args)=>structuredClone(args||{}),Tt:()=>({primaryTabId:1}),KN:{request:async opts=>{approvals.push(opts);return 'allow_once';}},pP:{},Ra:new Map()});
 for(const file of ['ki-permissions.js','ki-native.js','ki-security.js','ki-ptk.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,'../src',file),'utf8'),context);
 await service.ready;await context.kiPtkReady;await context.kiPolicyLoad();
 const call=(op,args={},type='KI_SECURITY',sender={id:'extension',url:chrome.runtime.getURL('providers/providers.html')})=>new Promise(resolve=>{for(const fn of chrome.runtime.onMessage.listeners)fn({type,op,session:'chat',...args},sender,resolve);});
 const tool=async(name,args)=>{await context.kiPolicyLoad();const raw=context.kiSecurityToolDefs('chat').find(x=>x.name===name);assert.ok(raw,name);return context.kiPolicyWrap(raw,'chat').resolveExecution(args).execute({signal:new AbortController().signal,toolCallId:'call'});};
 return {context,chrome,data,tab,calls,outputs,approvals,selected,runtime,service,call,tool,native};
}
test('native readiness has no companion installation or page activation',async()=>{const f=await setup(),r=await f.call('capabilities');assert.equal(r.result.version,'10.0.0');assert.equal(f.calls.length,0);});
test('native scan accepts full engine selection and settings above the prior ceilings',async()=>{const f=await setup();assert.equal((await f.call('start',{tabId:1,expectedOrigin:'https://wrong.test'})).ok,false);const r=await f.call('start',{tabId:1,engines:['DAST','IAST','SAST','SCA'],options:{durationSeconds:5000,maxRequests:5000}});assert.equal(r.ok,true);assert.equal(r.result.config.maxRequests,5000);await f.call('stop',{runId:r.result.runId});});
test('current profile restrictions block manual scan starts',async()=>{const f=await setup();f.selected.tools.groups.ptk=false;const r=await f.call('start',{tabId:1});assert.equal(r.ok,false);assert.match(r.error,/disabled/);assert.equal(f.calls.length,0);});
test('Research without owned runs receives no implicit security cleanup tools',async()=>{const f=await setup();f.selected.tools.groups.ptk=false;assert.equal(f.context.kiSecurityToolDefs('chat').length,0);});
test('global settings work without a chat while execution requires an owner',async()=>{const f=await setup();assert.equal((await f.call('state',{session:null})).ok,true);assert.equal((await f.call('configure',{session:null,scope:'global',defaults:{concurrency:4}})).ok,true);assert.equal((await f.call('start',{session:null,tabId:1})).ok,false);});
test('web pages cannot invoke native management messages',async()=>{const f=await setup();for(const op of ['start','configure','execute'])assert.equal((await f.call(op,{tabId:1},'KI_SECURITY',{id:'extension',url:'https://app.test/'})).ok,false);assert.equal(f.calls.length,0);});
test('ownership blocks status, evidence, stop and export from another chat',async()=>{const f=await setup(),run=(await f.call('start',{tabId:1})).result;for(const op of ['status','findings','evidence','export','stop']){const r=await f.call(op,{runId:run.runId,session:'other'});assert.equal(r.ok,false);assert.match(r.error,/does not belong/);}await f.call('stop',{runId:run.runId});});
test('findings preserve native proof and evidence exposes the underlying response',async()=>{const f=await setup(),run=(await f.call('start',{tabId:1})).result;assert.equal((await f.call('findings',{runId:run.runId})).result.findings[0].native.proof,'evidence');assert.equal((await f.call('evidence',{runId:run.runId,evidenceId:'finding'})).result.finding.response.status,403);await f.call('stop',{runId:run.runId});});
test('application-level start failures produce an inspectable unknown record',async()=>{const f=await setup();f.runtime.invoke=async()=>({ok:true,success:false,error:'engine refused'});const r=await f.call('start',{tabId:1});assert.equal(r.ok,false);assert.match(r.error,/engine refused/);assert.ok(r.runId);});
test('Full access skips implicit prompts but legacy Always ask applies to native names',async()=>{const f=await setup();let r=await f.tool('security_start_scan',{tabId:1});assert.equal(r.isError,undefined);assert.equal(f.approvals.length,0);await f.call('stop',{runId:JSON.parse(r.output).runId});f.data.ki_tool_permissions={tools:{'ptk:ptk_run_dast':'ask'}};r=await f.tool('security_start_scan',{tabId:1});assert.equal(f.approvals.length,1);await f.call('stop',{runId:JSON.parse(r.output).runId});});
test('legacy Disabled rules remain effective through canonical names',async()=>{const f=await setup();f.data.ki_tool_permissions={tools:{'ptk:ptk_run_dast':'disabled'}};const r=await f.tool('security_start_scan',{tabId:1});assert.equal(r.isError,true);assert.match(r.output,/disabled/);assert.equal(f.calls.length,0);});
test('canonical Disabled rules remain effective through retained aliases',async()=>{const f=await setup();f.data.ki_tool_permissions={tools:{'ptk:security_start_scan':'disabled'}};const r=await f.call('start',{tabId:1,expectedOrigin:'https://app.test'},'KI_PTK');assert.equal(r.ok,false);assert.match(r.error,/disabled/);assert.equal(f.calls.length,0);});
test('revocation during approval prevents dispatch',async()=>{const f=await setup();f.data.ki_tool_permissions={tools:{'ptk:security_start_scan':'ask'}};f.context.KN.request=async()=>{f.data.ki_tool_permissions.tools['ptk:security_start_scan']='disabled';return 'allow_once';};const r=await f.tool('security_start_scan',{tabId:1});assert.equal(r.isError,true);assert.equal(f.calls.length,0);});
test('stop remains available after profile and tool revocation',async()=>{const f=await setup(),run=(await f.call('start',{tabId:1})).result;f.selected.tools.groups.ptk=false;f.data.ki_tool_permissions={groups:{ptk:'disabled'}};const r=await f.tool('security_stop_scan',{runId:run.runId});assert.equal(JSON.parse(r.output).state,'completed');});
test('terminal engine badges are refreshed after drain',async()=>{const f=await setup(),run=(await f.call('start',{tabId:1,engines:['IAST']})).result;await f.call('status',{runId:run.runId});const r=(await f.call('stop',{runId:run.runId})).result;assert.equal(r.state,'completed');assert.equal(r.engineStatus.IAST.status,'completed');});
test('only confirmed downloads register report outputs',async()=>{const f=await setup(),run=(await f.call('start',{tabId:1})).result;await f.call('stop',{runId:run.runId});const r=await f.call('export',{runId:run.runId});assert.equal(r.ok,true);assert.equal(r.result.reports.length,1);assert.equal(f.outputs[0].item.runId,run.runId);f.chrome.downloads.search=async()=>[{state:'interrupted',error:'FILE_ACCESS_DENIED'}];assert.equal((await f.call('export',{runId:run.runId})).ok,false);assert.equal(f.outputs.length,1);});
test('replay uses the selected ordinary-chat target and rejects another origin',async()=>{const f=await setup();assert.equal((await f.call('execute',{capability:'replay',tabId:1,arguments:{request:{url:'https://app.test/a'}}})).ok,true);const r=await f.call('execute',{capability:'replay',tabId:1,arguments:{request:{url:'https://outside.test/'}}});assert.equal(r.ok,false);assert.match(r.error,/outside/);});
test('no-workspace replay selects its explicit request target without adding another origin',async()=>{
 const f=await setup();let result=await f.call('execute',{capability:'replay',arguments:{request:{url:'https://app.test/a'}}});assert.equal(result.ok,true,result.error);
 const operation=f.calls.filter(call=>call.op==='replay').at(-1);assert.deepEqual(JSON.parse(JSON.stringify(operation.context.scope)),{origins:['https://app.test'],excludePaths:[]});
 result=await f.call('execute',{capability:'replay',arguments:{request:{url:'https://api.test/a'}}});assert.equal(result.ok,true,result.error);
 assert.deepEqual(JSON.parse(JSON.stringify(f.calls.filter(call=>call.op==='replay').at(-1).context.scope)),{origins:['https://api.test'],excludePaths:[]});
});
test('no-workspace port probe selects only the explicit host across requested ports',async()=>{
 const f=await setup();const result=await f.call('execute',{capability:'utility',arguments:{tool:'portscan',host:'app.test',ports:[8080,8443]}});assert.equal(result.ok,true,result.error);
 const operation=f.calls.filter(call=>call.op==='utility').at(-1);assert.deepEqual(JSON.parse(JSON.stringify(operation.context.scope)),{origins:['http://app.test'],excludePaths:[],matchMode:'host'});
});
test('configured same-host scope admits selected ports and schemes, then revokes current restrictions',async()=>{
 const f=await setup();f.selected.workspace={id:'work',dastScope:{origins:['https://app.test:8443'],excludePaths:['/private'],matchMode:'host'}};
 const run=(await f.call('start',{tabId:1})).result,guard=f.calls.find(call=>call.op==='startScan').context.checkRequest;
 await guard({url:'http://app.test:8080/public'});
 await assert.rejects(guard({url:'https://api.test/public'}),/outside/);
 await assert.rejects(guard({url:'https://app.test:8080/private/data'}),/outside/);
 f.selected.workspace.dastScope={origins:['https://app.test:8443'],excludePaths:['/private']};
 await assert.rejects(guard({url:'http://app.test:8080/public'}),/scope changed/);
 await f.call('stop',{runId:run.runId});
});
test('legacy aliases use the native service and preserve scanId response fields',async()=>{const f=await setup(),r=await f.call('start',{tabId:1,expectedOrigin:'https://app.test',engines:['SAST','SCA']},'KI_PTK');assert.equal(r.ok,true);assert.ok(r.result.scanId);assert.equal(f.calls.filter(x=>x.op==='startScan').length,1);assert.equal((await f.call('stop',{scanId:r.result.scanId},'KI_PTK')).ok,true);});
test('legacy aliases retain original engine contracts rather than bypassing native DAST permissions',async()=>{const f=await setup();for(const engines of [['DAST'],['IAST','SAST']]){const result=await f.call('start',{tabId:1,expectedOrigin:'https://app.test',engines},'KI_PTK');assert.equal(result.ok,false);assert.match(result.error,/legacy alias/);}assert.equal(f.calls.length,0);});
test('historical companion handles never trigger page management',async()=>{const f=await setup();await assert.rejects(f.context.kiPtkBridge(1,'https://app.test','stopScan',{}),/earlier companion/);assert.equal(f.calls.length,0);});
test('subagents retain parent ownership',async()=>{const f=await setup(),run=(await f.call('start',{tabId:1})).result;assert.equal((await f.call('status',{runId:run.runId,session:'child'})).ok,true);await f.call('stop',{runId:run.runId});});
test('saved snapshots cannot silently substitute a different browser identity',async()=>{const f=await setup(),r=await f.call('start',{tabId:1,engines:['DAST','IAST'],accountId:'account'});assert.equal(r.ok,false);assert.match(r.error,/prepared browser session/);assert.equal(f.calls.length,0);});
test('retained aliases dispatch privately without appearing in the model tool list',async()=>{
 const f=await setup(),tools=f.context.kiSecurityToolDefs('chat');assert.ok(tools.every(tool=>!tool.name.startsWith('ptk_')));
 const alias=f.context.kiSecurityLegacyLookup(tools,'ptk_start_scan');assert.ok(alias);
 const result=await alias.resolveExecution({tabId:1,expectedOrigin:'https://app.test',engines:['SAST']}).execute({signal:new AbortController().signal});const run=JSON.parse(result.output);assert.ok(run.scanId);await f.call('stop',{runId:run.scanId});
 f.data.ki_tool_permissions={tools:{'ptk:security_start_scan':'disabled'}};await f.context.kiPolicyLoad();assert.equal(f.context.kiSecurityLegacyLookup(tools,'ptk_start_scan'),undefined);
 assert.equal(f.context.kiSecurityLegacyLookup([], 'ptk_start_scan'),undefined);assert.equal(f.context.kiSecurityLegacyLookup(tools,'unknown'),undefined);
});
test('removing workspace scope and moving a chat revoke queued scan requests',async()=>{
 const f=await setup();f.selected.workspace={id:'work',dastScope:{origins:['https://app.test'],excludePaths:[]}};
 const run=(await f.call('start',{tabId:1})).result,context=f.calls.find(call=>call.op==='startScan').context;
 f.selected.workspace.dastScope.origins=[];await assert.rejects(context.checkRequest({url:'https://app.test/a'}),/scope changed/);
 f.selected.workspace={id:'other',dastScope:{origins:['https://app.test'],excludePaths:[]}};await assert.rejects(context.checkRequest({url:'https://app.test/a'}),/workspace changed/);
 await f.call('stop',{runId:run.runId});
});
function cookieRecord(f) { const context=f.calls.filter(call=>call.op==='utility').at(-1).context;return {owner:context.owner,workspaceId:context.workspaceId,scope:structuredClone(context.scope),grant:structuredClone(context.cookiePolicyGrant),tool:'security_utility'}; }
test('automatic cookie effects revalidate permissions without creating approval prompts',async()=>{
 const f=await setup();await f.tool('security_utility',{tabId:1,arguments:{tool:'cookies',action:'readonly',cookieId:'selected-cookie'}});const record=cookieRecord(f);
 assert.equal(record.grant.owner,'chat');assert.equal(record.grant.approvalRequired,false);await f.context.certXSecurityCookiePolicyContext(record);assert.equal(f.approvals.length,0);
 f.data.ki_tool_permissions={tools:{'ptk:security_utility':'disabled'}};await assert.rejects(f.context.certXSecurityCookiePolicyContext(record),/disabled/);
 f.data.ki_tool_permissions={};f.data.sidepanel_approval_mode='approve_for_me';await assert.rejects(f.context.certXSecurityCookiePolicyContext(record),/stricter/);assert.equal(f.approvals.length,0);
});
test('an already-approved Ask cookie policy survives reload-shaped grants without per-cookie approvals',async()=>{
 const f=await setup();f.data.sidepanel_approval_mode='approve_for_me';f.data.ki_tool_permissions={tools:{'ptk:security_utility':'ask'}};
 await f.tool('security_utility',{tabId:1,arguments:{tool:'cookies',action:'block',cookieId:'selected-cookie'}});const record=JSON.parse(JSON.stringify(cookieRecord(f)));
 assert.equal(f.approvals.length,1);assert.equal(record.grant.approvedForAsk,true);
 for(let i=0;i<3;i++){const context=await f.context.certXSecurityCookiePolicyContext(record);await context.recheck();}assert.equal(f.approvals.length,1);
 f.selected.tools.groups.ptk=false;await assert.rejects(f.context.certXSecurityCookiePolicyContext(record),/disabled/);
});
test('cookie policy scope narrows with the workspace and grant ownership cannot be altered',async()=>{
 const f=await setup();f.selected.workspace={id:'work',dastScope:{origins:['https://app.test','https://api.test'],excludePaths:[]}};
 await f.tool('security_utility',{tabId:1,arguments:{tool:'cookies',action:'readonly',cookieId:'selected-cookie'}});const record=cookieRecord(f);
 f.selected.workspace.dastScope={origins:['https://api.test'],excludePaths:['/private']};const current=await f.context.certXSecurityCookiePolicyContext(record);assert.deepEqual(JSON.parse(JSON.stringify(current.scope)),{origins:['https://api.test'],excludePaths:['/private']});
 f.selected.workspace.dastScope.origins=[];await assert.rejects(f.context.certXSecurityCookiePolicyContext(record),/scope/);
 f.selected.workspace={id:'moved',dastScope:{origins:['https://app.test'],excludePaths:[]}};await assert.rejects(f.context.certXSecurityCookiePolicyContext(record),/different workspace/);
 await assert.rejects(f.context.certXSecurityCookiePolicyContext({...record,owner:'other'}),/fresh explicit grant/);
 await assert.rejects(f.context.certXSecurityCookiePolicyContext({...record,grant:null}),/fresh explicit grant/);
});
test('persistent cookie policy intersects original host mode with current exact origins',async()=>{
 const {scopeAllows}=await import('../../../security/config.mjs');const f=await setup();
 f.selected.workspace={id:'work',dastScope:{origins:['https://app.test:8443'],excludePaths:['/private'],matchMode:'host'}};
 await f.tool('security_utility',{tabId:1,arguments:{tool:'cookies',action:'readonly',cookieId:'selected-cookie'}});
 const record=cookieRecord(f);f.selected.workspace.dastScope={origins:['http://app.test:8080','https://outside.test'],excludePaths:['/admin']};
 const current=await f.context.certXSecurityCookiePolicyContext(record);
 assert.equal(scopeAllows('http://app.test:8080/public',current.scope),true);
 for(const url of ['https://app.test:8443/public','https://outside.test/public','http://app.test:8080/private','http://app.test:8080/admin'])assert.equal(scopeAllows(url,current.scope),false,url);
});
test('caller-supplied cookie grants do not bypass the actual approval decision',async()=>{
 const f=await setup();f.data.sidepanel_approval_mode='approve_for_me';f.context.KN.request=async()=> 'deny';
 const result=await f.tool('security_utility',{tabId:1,arguments:{tool:'cookies',action:'block',cookieId:'selected-cookie',cookiePolicyGrant:{approvedForAsk:true,owner:'other'}}});
 assert.equal(result.isError,true);assert.equal(f.calls.filter(call=>call.op==='utility').length,0);
});
test('clearing an owned cookie policy remains available after tools are disabled',async()=>{
 const f=await setup();await f.tool('security_utility',{tabId:1,arguments:{tool:'cookies',action:'readonly',cookieId:'selected-cookie'}});
 f.selected.tools.groups.ptk=false;f.data.ki_tool_permissions={groups:{ptk:'disabled'}};
 const result=await f.tool('security_clear_cookie_policy',{policyId:'owned-policy'});assert.equal(result.isError,undefined);
 const last=f.calls.filter(call=>call.op==='utility').at(-1);assert.equal(last.args.action,'unset');assert.equal(last.args.policyId,'owned-policy');assert.equal(last.context.owner,'chat');
});

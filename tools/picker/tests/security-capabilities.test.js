const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const manifest=require('../../../security/capabilities.json');
async function fixture(){
 const {OPERATION_SCHEMAS}=await import('../../../security/engine/operation-arguments.mjs');
 const event={addListener(){}},service={operationSchemas:OPERATION_SCHEMAS,describe:async()=>({...manifest,version:'10.0.0',configuration:{preset:'thorough'},transport:{http:true},acquisitionSupport:{SCA:'bounded'},targetScope:{configured:true}})};
 const context=vm.createContext({console,URL,TextEncoder,AbortController,setTimeout,clearTimeout,KI_POLICY_CONTEXT:Symbol('policy'),kiWorkspaceOwner:x=>x,certXSecurity:service,chrome:{runtime:{onMessage:event,id:'fixture',getURL:x=>'chrome-extension://fixture/'+x},storage:{onChanged:event}}});
 vm.runInContext(fs.readFileSync(path.join(__dirname,'../src/ki-security.js'),'utf8'),context);
 context.kiSecurityContext=async()=>({owner:'chat'});context.kiSecurityLocalAvailability=async()=>({ready:false,reason:'Local access disabled'});
 return {context,call:args=>context.kiSecurityOperate('capabilities',args,'chat'),health:()=>context.kiSecurityHealth('chat'),tool:context.kiSecurityToolDefs('chat').find(tool=>tool.name==='security_start_scan'),agentResult:(op,args,result)=>context.kiSecurityAgentResult(op,args,result),surfaceMap:(tabId,scope)=>context.kiSecuritySurfaceMap(tabId,scope)};
}
const plain=value=>JSON.parse(JSON.stringify(value));
test('compact capabilities retain readiness, module selectors and lifecycle contracts without source audit bulk',async()=>{
 const f=await fixture(),summary=await f.call({}),full=await f.call({detail:'full'});
 assert.equal(summary.detail,'summary');assert.equal(summary.sourceAudit,undefined);assert.equal(summary.advancedBrowserVerification,undefined);assert.equal(summary.verificationNotes,undefined);
 assert.deepEqual(plain(summary.configuration),{preset:'thorough'});assert.equal(summary.transport.http,true);assert.equal(summary.localRuntime.ready,false);
 assert.equal(summary.modules.length,manifest.modules.length);
 assert.deepEqual(Object.keys(summary.modules[0]),['id','engine','name','executable','checkCount']);assert.equal(summary.modules[0].checkCount,manifest.modules[0].checks.length);
 assert.equal(summary.unavailableTotal,manifest.metadataOnly.length);assert.ok(summary.unavailable.length<=20);assert.equal(summary.unavailableTruncated,manifest.metadataOnly.length>20);
 assert.ok(summary.operationArguments.security_scan_status);assert.deepEqual(plain(summary.operationArguments.security_scan_status.schema.required),['runId']);
 assert.equal(summary.operationArguments.security_candidates,undefined,'Specialist schema requested on demand');assert.equal(summary.operationArguments.security_start_scan,undefined,'Large start schema requested on demand');assert.equal(summary.operationArguments.security_utility,undefined,'Large utility schema requested on demand');
 assert.deepEqual(plain(full.sourceAudit),manifest.sourceAudit);assert.ok(full.operationArguments.security_candidates);assert.equal(full.detail,'full');
 assert.ok(JSON.stringify(summary).length<JSON.stringify(full).length/2,'Summary should materially reduce capability context');
 const health=await f.health();assert.equal(health.detail,'summary');assert.equal(health.sourceAudit,undefined,'General get_capabilities must not reintroduce the full security audit inventory');
});
test('agent-facing progress and findings omit bulk while retaining counts, references and explicit full detail',async()=>{
 const f=await fixture(),run={runId:'run-1',state:'running',engines:['DAST'],requestsSent:12,config:{maxRequests:20},summary:{findings:1,byModule:{xss:1}},coverage:{dast:{tasksPlanned:20,probeDispatches:12,taskSkips:0}},engineStatus:{DAST:{status:'running',idle:false,progress:{done:12,total:20},taskQueue:8,nativeBulk:'x'.repeat(20000)}},lastStatus:{nativeBulk:'y'.repeat(20000)},wait:{outcome:'timeout'}};
 const status=f.agentResult('status',{},run);assert.equal(status.runId,'run-1');assert.equal(status.coverage.dast.probeDispatches,12);assert.equal(status.engineStatus.DAST.progress.total,20);assert.equal(status.wait.outcome,'timeout');assert.deepEqual(plain(status.requestBudget),{used:12,limit:20,exhausted:false});assert.equal(status.lastStatus,undefined);assert.ok(JSON.stringify(status).length<2000);
 assert.equal(f.agentResult('status',{detail:'full'},run),run);
 const page={runId:'run-1',total:1,nextOffset:null,findings:[{id:'finding-1',engine:'DAST',moduleId:'xss',title:'Reflected XSS',severity:'high',location:{url:'https://fixture.test/?q=x',param:'q'},evidence:{response:'z'.repeat(20000)}}],summary:run.summary,selectedEngines:['DAST'],coverage:run.coverage};
 const findings=f.agentResult('findings',{},page);assert.equal(findings.findings[0].id,'finding-1');assert.equal(findings.findings[0].evidenceAvailable,true);assert.equal(findings.findings[0].evidence,undefined);assert.ok(JSON.stringify(findings).length<1500);assert.equal(f.agentResult('findings',{detail:'full'},page),page);
});
test('selected capability returns exactly the public tool schema and rejects unknown/unavailable tool names',async()=>{
 const f=await fixture(),value=await f.call({tool:'security_candidates'});
 assert.equal(value.tool,'security_candidates');assert.deepEqual(Object.keys(value.operationArguments),['security_candidates']);assert.equal(value.modules,undefined);assert.equal(value.sourceAudit,undefined);
 assert.ok(value.operationArguments.security_candidates.schema.properties.arguments.required.includes('runId'));
 const modelSchema=f.context.kiSecurityToolDefs('chat').find(tool=>tool.name==='security_candidates').parameters.properties.arguments;
 const fullSchema=value.operationArguments.security_candidates.schema.properties.arguments;
 assert.deepEqual(Object.keys(modelSchema.properties),Object.keys(fullSchema.properties));assert.deepEqual(plain(modelSchema.required),plain(fullSchema.required));
 assert.equal(modelSchema.properties.runId.description,undefined);assert.equal(typeof fullSchema.properties.runId.description,'string');
 assert.ok(JSON.stringify(modelSchema).length<JSON.stringify(fullSchema).length,'Model schema keeps validation fields without repeating long guidance.');
 await assert.rejects(f.call({tool:'candidate'}),/unavailable/);await assert.rejects(f.call({detail:'huge'}),/summary.*full/);
});
test('start schema makes module arrays and ordinary typed settings explicit',async()=>{
 const f=await fixture(),options=f.tool.parameters.properties.options.properties;
 for(const key of ['moduleIds','modules','excludeModules']){assert.equal(options[key].type,'array');assert.equal(options[key].items.type,'string');assert.equal(options.engineOptions.properties.DAST.properties[key].type,'array');}
 assert.equal(options.runCve.type,'boolean');assert.equal(options.schedulerBreadthFirst.type,'boolean');assert.equal(options.concurrency.type,'integer');assert.equal(options.maxRequestsPerSecond.type,'number');assert.ok(options.preset.enum.includes('thorough'));assert.ok(options.maxRequests.type.includes('null'));
});
test('agent registry omits specialist tools whose prerequisites are absent and restores them when ready',async()=>{
 const f=await fixture(),context=f.context;
 context.kiContextFor=()=>({tools:{groups:{ptk:true},tools:{}},workspace:null});context.kiContextAllows=()=>true;
 context.kiNativeCache={enabled:false};
 context.kiDastToolDefs=()=>[{name:'ptk_capture_requests',description:'capture',parameters:{type:'object',properties:{}}}];
 context.kiAuthzToolDefs=()=>[{name:'ptk_list_accounts',description:'accounts',parameters:{type:'object',properties:{}}}];
 let names=context.kiSecurityToolDefs('chat').map(tool=>tool.name);
 for(const name of ['security_raw','security_oast','security_zap','security_browser','security_capture_requests','security_list_accounts'])assert.ok(!names.includes(name),name);
 assert.ok(names.includes('security_start_scan'));
 context.kiNativeCache.enabled=true;context.kiContextFor=()=>({tools:{groups:{ptk:true},tools:{}},workspace:{dastScope:{origins:['https://fixture.test']}}});
 names=context.kiSecurityToolDefs('chat').map(tool=>tool.name);
 for(const name of ['security_raw','security_capture_requests','security_list_accounts'])assert.ok(names.includes(name),name);
});
test('selected-page inventory lists scoped routes and form methods without copying input or query values',async()=>{
 const f=await fixture();let selection;
 f.context.chrome.scripting={executeScript:async args=>{selection=args;return [{result:{url:'https://app.test/',links:['https://app.test/search?q=private-value','https://app.test/private/notes','https://other.test/'],linkCount:3,forms:[{action:'https://app.test/submit?token=private-value',method:'POST',fields:[{name:'message',type:'text'},{name:'csrf',type:'hidden'}]}],formCount:1}}]}};
 const result=await f.surfaceMap(7,{origins:['https://app.test'],excludePaths:['/private']});
 assert.equal(selection.target.tabId,7);assert.equal(selection.world,'ISOLATED');assert.equal(result.available,true);
 assert.deepEqual(plain(result.links),[{url:'https://app.test/search',queryKeys:['q']}]);
 assert.deepEqual(plain(result.forms),[{url:'https://app.test/submit',queryKeys:['token'],method:'POST',fields:[{name:'message',type:'text'},{name:'csrf',type:'hidden'}]}]);
 assert.ok(!JSON.stringify(result).includes('private-value'));assert.match(result.note,/not proof/);
 const run=f.agentResult('start',{}, {runId:'run-1',state:'running',engines:['DAST'],surfaceMap:result});
 assert.deepEqual(plain(run.surfaceMap),plain(result));
});

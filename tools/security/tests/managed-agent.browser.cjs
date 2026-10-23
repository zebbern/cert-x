// Scripted model protocol -> canonical tools -> owned service -> native messaging -> isolated executor.
// This tests real tool execution through the chat loop, not live model inference.
// Browser plugin is unavailable; use the project's isolated Chromium harness.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict'),{execFileSync,spawn}=require('node:child_process');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-managed-agent-'));
const registry='HKCU\\Software\\Chromium\\NativeMessagingHosts\\com.cert_x.host';
const installed=process.env.CERT_X_MANAGED_COMPONENTS||path.join(process.env.CERT_X_TEST_RUNTIME||path.join(process.env.LOCALAPPDATA||os.homedir(),'cert-x','security-runtime'),'installed.json');
const evidenceRoot=process.env.CERT_X_EVIDENCE_ROOT||path.join(process.env.LOCALAPPDATA||os.homedir(),'cert-x','verification');
fs.mkdirSync(evidenceRoot,{recursive:true});
const runtimeRoot=path.join(temp,'runtime'),wire=[],modelCalls=[],toolResults=new Map(),errors=[];
let browser,server,daemon,daemonErrors='',registered=false,phase='prime',step=0,origin,tabId,worker,panel,fixturePage,requestSequence=0,invalidTargetWireCount;
const resultFor=name=>{const value=toolResults.get(name);assert.ok(value,'Model must receive '+name);return value;};
const browserArgs=action=>({action,runId:resultFor('create').runId,sessionId:resultFor('create').sessionId});
const sourcePack=JSON.parse(fs.readFileSync(path.join(root,'security/ptk/background/dast/modules/modules.json'),'utf8'));
const selectedRulepack={...sourcePack,modules:sourcePack.modules.filter(module=>module.id==='xss').map(module=>({...module,attacks:module.attacks.filter(attack=>attack.id==='xss_1')}))};
const candidate=()=>{const item=resultFor('candidates').candidates.find(value=>String(value.routeKey).includes('|GET|'));assert.ok(item,'Captured GET traffic must yield a reproducible candidate');return item;};
function steps(){return phase==='main' ? [
 ['create','security_browser',()=>({arguments:{action:'create',url:origin+'/app',headless:true}})],
 ['navigate','security_browser',()=>({arguments:{...browserArgs('navigate'),url:origin+'/next'}})],
 ['inspect-current','security_browser',()=>({arguments:browserArgs('inspect')})],
 ['screenshot-current','security_browser',()=>({arguments:browserArgs('screenshot')})],
 ['verify','security_browser',()=>({arguments:{...browserArgs('verify'),probe:{selector:'h1',expectedText:'Managed fixture'}}})],
 ['import','security_api',()=>({arguments:{action:'import',data:JSON.stringify({openapi:'3.0.0',info:{title:'Echo',version:'1'},servers:[{url:origin}],paths:{'/api/echo':{post:{operationId:'echo',requestBody:{required:true,content:{'application/json':{schema:{required:['value']}}}},responses:{200:{description:'echo'}}}}}})}})],
 ['prepare','security_api',()=>({arguments:{action:'prepare',specRef:resultFor('import').specRef,operationId:'echo',body:{value:'MODEL-NATIVE-ECHO'}}})],
 ['execute','security_api',()=>({arguments:{action:'execute',planRef:resultFor('prepare').planRef}})],
 ['invalid-target','security_start_scan',()=>{invalidTargetWireCount=wire.length;return {tabId:undefined,tab:'not-a-tab',engines:['DAST']};}],
 ['source','security_start_scan',()=>{const failure=resultFor('invalid-target');assert.equal(failure.code,'invalid_target_tab');assert.equal(failure.retryable,false);assert.match(failure.recovery,/list_browser_tabs.*Do not retry unchanged/);assert.equal(wire.length,invalidTargetWireCount,'Invalid scan target must not cause target traffic');return {tabId:undefined,tab:String(tabId),engines:['DAST','SAST'],options:{preset:'ptk-defaults',rulepack:selectedRulepack,runCve:false,allowCaptureWithoutInteraction:true}};}],
 ['source-stop','security_stop_scan',async()=>{await fixturePage.reload();await new Promise(resolve=>setTimeout(resolve,9000));return {runId:resultFor('source').runId};}],
 ['candidates','security_candidates',()=>({arguments:{action:'list',runId:resultFor('source').runId}})],
 ['candidate-readiness','security_candidates',()=>({arguments:{action:'readiness',runId:resultFor('source').runId,candidateId:candidate().id}})],
 ['reproduce','security_candidates',()=>({arguments:{action:'reproduce',runId:resultFor('source').runId,candidateId:candidate().id,snapshotId:resultFor('candidates').snapshotId,browserSessionId:resultFor('create').sessionId,constraints:{maxRequests:5,maxMutations:1,maxDurationMs:15000}}})],
 ['job-status','security_candidates',async()=>{await new Promise(resolve=>setTimeout(resolve,2000));return {arguments:{action:'status',runId:resultFor('source').runId,executionRunId:resultFor('reproduce').runId,jobId:resultFor('reproduce').jobId}};}],
 ['job-artifact','security_browser',()=>({arguments:{...browserArgs('readArtifact'),artifactRef:resultFor('job-status').artifacts[0].artifactRef,limit:128}})],
 ['candidate-package','security_evidence_package',()=>({arguments:{action:'create',runId:resultFor('source').runId,candidateId:candidate().id,title:'Model reproduction evidence',notes:JSON.stringify({executionRunId:resultFor('reproduce').runId,jobId:resultFor('reproduce').jobId,summary:resultFor('job-status').summary,artifacts:resultFor('job-status').artifacts})}})],
 ['candidate-report','security_evidence_package',()=>({arguments:{action:'export',runId:resultFor('source').runId,packageId:resultFor('candidate-package').evidencePackage.id,format:'markdown'}})],
 ['close','security_browser',()=>({arguments:browserArgs('close')})],
] : phase==='ask' ? [['ask-create','security_browser',()=>({arguments:{action:'create',url:origin+'/ticks',headless:true}})]]
 : phase==='stop' ? [['stop','security_stop_scan',()=>({runId:resultFor('ask-create').runId})]]
 : phase==='missing' ? [['missing','security_browser',()=>({arguments:{action:'create',url:origin+'/app',headless:true}})]] : [];}
function decode(content){if(typeof content==='string'){try{return JSON.parse(content.replace(/^<system>.*?<\/system>\s*/s,''));}catch{return {text:content};}}return content;}
async function main(){
 assert.ok(fs.existsSync(installed),'Set CERT_X_MANAGED_COMPONENTS to a prepared managed runtime installed.json');
 let exists=false;try{execFileSync('reg.exe',['query',registry],{stdio:'ignore'});exists=true;}catch{}assert.equal(exists,false,'Preserve any existing Chromium native host registration');
 fs.mkdirSync(runtimeRoot,{recursive:true});fs.copyFileSync(installed,path.join(runtimeRoot,'installed.json'));
 server=http.createServer(async(req,res)=>{
  res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','*');if(req.method==='OPTIONS')return res.end();
  if(req.url.endsWith('/models')){res.setHeader('Content-Type','application/json');return res.end(JSON.stringify({data:[{id:'mock/managed',name:'Managed fixture'}]}));}
  const chunks=[];for await(const c of req)chunks.push(c);const body=Buffer.concat(chunks).toString();
  if(!req.url.includes('chat/completions')){wire.push({url:req.url,method:req.method,body});if(req.url==='/app.js'){res.setHeader('Content-Type','application/javascript');return res.end('document.getElementById("sink").innerHTML=new URLSearchParams(location.search).get("q");');}if(req.url==='/api/echo'){res.setHeader('Content-Type','application/json');return res.end(body);}if(req.url==='/tick'){res.setHeader('Content-Type','text/plain');return res.end('tick');}const fixtureInput=new URL(req.url,'http://fixture').searchParams.get('q')||'';if(fixtureInput.includes('<'))res.statusCode=500;res.setHeader('Content-Type','text/html');return res.end((fixtureInput.includes('<')?'<pre>TemplateSyntaxError: invalid template expression</pre>':'')+'<!doctype html><title>Managed application</title><h1>Managed fixture</h1><div id="sink">'+(new URL(req.url,'http://fixture').searchParams.get('q')||'')+'</div><script src="/app.js"></script>'+(req.url==='/ticks'?'<script>setInterval(()=>fetch("/tick").catch(()=>{}),250)</script>':''));}
  try{
   const request=JSON.parse(body);modelCalls.push({phase,tools:(request.tools||[]).map(x=>x.function.name)});
   for(const message of request.messages||[])if(message.role==='tool'&&message.tool_call_id?.startsWith('managed-'))toolResults.set(message.tool_call_id.slice(8),decode(message.content));
   const item=steps()[step++];if(item)assert.ok(modelCalls.at(-1).tools.includes(item[1]),'Advertised tool '+item[1]);
   const delta=item?{role:'assistant',tool_calls:[{index:0,id:'managed-'+item[0],type:'function',function:{name:item[1],arguments:JSON.stringify({tabId,...await item[2]()})}}]}:{role:'assistant',content:'MANAGED '+phase+' COMPLETE'};
   res.writeHead(200,{'Content-Type':'text/event-stream'});const send=data=>res.write('data: '+JSON.stringify(data)+'\n\n');
   const id='managed-model-'+ ++requestSequence;send({id,object:'chat.completion.chunk',choices:[{index:0,delta}]});send({id,object:'chat.completion.chunk',choices:[{index:0,delta:{},finish_reason:item?'tool_calls':'stop'}]});res.end('data: [DONE]\n\n');
  }catch(error){errors.push(error.message);res.statusCode=500;res.end(error.message);}
 });await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launchPersistentContext(path.join(temp,'profile'),{headless:true,viewport:{width:720,height:950},executablePath:process.env.CHROMIUM_PATH||path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(()=>certXSecurity.ready);const id=new URL(worker.url()).host;
 const host=path.join(temp,'host');execFileSync('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',path.join(root,'tools/host/install.ps1'),'-ExtensionId',id,'-Browser','Chromium','-OutputDirectory',host],{windowsHide:true,stdio:'pipe'});registered=true;
 const installedHost=path.join(host,'Chromium',id),launcher=path.join(installedHost,'launch.cmd');fs.writeFileSync(launcher,'@echo off\r\nset "CERT_X_SECURITY_ROOT='+runtimeRoot+'"\r\n"'+process.execPath+'" "'+path.join(installedHost,'ki-host.js')+'" %*\r\n');
 daemon=spawn(process.execPath,[path.join(installedHost,'security/daemon.cjs'),runtimeRoot],{windowsHide:true,stdio:['ignore','ignore','pipe']});daemon.stderr.on('data',chunk=>daemonErrors+=chunk);
 for(let i=0;i<100&&!fs.existsSync(path.join(runtimeRoot,'daemon.json'));i++)await new Promise(resolve=>setTimeout(resolve,50));
 await worker.evaluate(async origin=>{await chrome.storage.local.set({sidepanel_language:'en',sidepanel_theme:'dark',sidepanel_approval_mode:'full_access',ki_native_settings:{enabled:true,servers:[]},sidepanel_connections:[{id:'mock',label:'Managed fixture',presetId:'openrouter',apiKey:'fixture',host:origin+'/api/v1'}]});},origin);
 fixturePage=await browser.newPage();await fixturePage.goto(origin+'/app?q=fixture');tabId=await worker.evaluate(async origin=>(await chrome.tabs.query({})).find(tab=>tab.url===origin+'/app?q=fixture').id,origin);
 const settings=await browser.newPage();await settings.goto('chrome-extension://'+id+'/providers/providers.html?section=security');await settings.waitForFunction(()=>!document.querySelector('main').inert);
 const workspace=await settings.evaluate(async origin=>chrome.runtime.sendMessage({type:'KI_CONTEXT',op:'save_workspace',workspace:{id:'managed-agent',name:'Managed agent',profileId:'bugbounty',dastScope:{origins:[origin],excludePaths:[]}}}),origin);assert.equal(workspace.ok,true,JSON.stringify(workspace));
 panel=await browser.newPage();panel.on('pageerror',e=>errors.push(e.message));await panel.goto('chrome-extension://'+id+'/pages/sidepanel.html');await panel.waitForFunction(()=>document.querySelector('.wb-composer-model .wb-mode-toggle')?.disabled===false);
 const prompt=async next=>{phase=next;step=0;await panel.locator('.wb-editor').first().click();await panel.keyboard.type('Run '+next+' fixture.');await panel.keyboard.press('Enter');};
 await prompt('prime');await panel.getByText('MANAGED prime COMPLETE',{exact:true}).waitFor({timeout:45000});await panel.getByLabel('Workspace',{exact:true}).selectOption('managed-agent');await panel.waitForFunction(()=>document.querySelector('[aria-label="Profile"]').disabled===false);
 await prompt('main');await panel.getByText('MANAGED main COMPLETE',{exact:true}).waitFor({timeout:90000});
 for(const [name]of steps())if(name!=='invalid-target')assert.equal(resultFor(name).error,undefined,name+': '+JSON.stringify(resultFor(name)));
 assert.equal(resultFor('inspect-current').url,origin+'/next','Inspection must keep the explicitly navigated page');assert.ok(resultFor('screenshot-current').artifactRef);assert.equal(wire.filter(x=>x.url==='/next').length,1,'Inspect/screenshot/verify cannot replay navigation');
 assert.equal(resultFor('verify').verified,true);assert.equal(resultFor('close').state,'cancelled');assert.equal(wire.filter(x=>x.url==='/api/echo'&&x.body==='{"value":"MODEL-NATIVE-ECHO"}').length,1);assert.equal(await panel.locator('.wb-permission').count(),0);
 assert.ok(resultFor('candidates').candidates.length>0);assert.equal(resultFor('job-status').status,'completed',JSON.stringify(resultFor('job-status')));assert.ok(resultFor('job-status').artifacts.length>0,'Completed reproduction retains native artifacts');assert.ok(Buffer.from(resultFor('job-artifact').base64,'base64').length>0);assert.ok(resultFor('candidate-report').content.includes('Model reproduction evidence'));assert.ok(resultFor('candidate-report').content.includes(resultFor('job-status').artifacts[0].artifactRef));
 await worker.evaluate(()=>chrome.storage.local.set({ki_tool_permissions:{groups:{local:'ask'}}}));
 await prompt('ask');const approval=panel.locator('.wb-permission');await approval.waitFor({timeout:45000});await approval.getByRole('button',{name:'Just once',exact:true}).click();await panel.getByText('MANAGED ask COMPLETE',{exact:true}).waitFor({timeout:45000});
 await new Promise(resolve=>setTimeout(resolve,1000));assert.equal(resultFor('ask-create').error,undefined,JSON.stringify(resultFor('ask-create')));const ticks=wire.filter(x=>x.url==='/tick').length;assert.ok(ticks>=2);assert.equal(await panel.locator('.wb-permission').count(),0,'Per-send admission must reuse the one run grant');
 await worker.evaluate(()=>chrome.storage.local.set({ki_tool_permissions:{groups:{local:'disabled'}}}));await new Promise(resolve=>setTimeout(resolve,800));const stoppedAt=wire.filter(x=>x.url==='/tick').length;await new Promise(resolve=>setTimeout(resolve,800));assert.equal(wire.filter(x=>x.url==='/tick').length,stoppedAt,'Revocation blocks page traffic');
 await prompt('stop');await panel.getByText('MANAGED stop COMPLETE',{exact:true}).waitFor({timeout:45000});
 const stopped=resultFor('stop'),revocationReason='Tool "Use an isolated testing browser" is disabled in Tools & permissions.';
 // Revalidation may close the browser before this explicit stop. The terminal
 // record retains that historical permission failure; it is not a failed stop.
 assert.equal(stopped.state,'cancelled',JSON.stringify(stopped));assert.equal(stopped.runId,resultFor('ask-create').runId);
 assert.equal(stopped.summary.state,'closed');assert.equal(stopped.summary.sessionId,resultFor('ask-create').sessionId);assert.equal(stopped.summary.persistent,false);assert.deepEqual(stopped.summary.pages,[]);
 if(stopped.error!==undefined){assert.equal(stopped.error,revocationReason,'Only the exact intentional revocation may remain as historical error');assert.equal(stopped.stopReason,revocationReason);}
 assert.equal(await panel.locator('.wb-permission').count(),0,'Stopping after revocation must not ask for new approval');
 await new Promise(resolve=>setTimeout(resolve,800));assert.equal(wire.filter(x=>x.url==='/tick').length,stoppedAt,'Stopped browser cannot resume page traffic');
 await worker.evaluate(()=>chrome.storage.local.set({ki_tool_permissions:{}}));const components=JSON.parse(fs.readFileSync(path.join(runtimeRoot,'installed.json'),'utf8'));delete components.components.node;fs.writeFileSync(path.join(runtimeRoot,'installed.json'),JSON.stringify(components));
 await prompt('missing');await panel.getByText('MANAGED missing COMPLETE',{exact:true}).waitFor({timeout:45000});assert.match(resultFor('missing').error,/not installed|setup/i);assert.deepEqual(errors,[]);
 const evidenceFile=path.join(evidenceRoot,'cert-x-managed-agent-results.json');fs.writeFileSync(evidenceFile,JSON.stringify({provider:'scripted_fixture',liveModelInference:false,invalidTargetRecovery:true,invalidTargetWireCount,modelCalls,toolResults:Object.fromEntries(toolResults),wire},null,2));console.log(JSON.stringify({provider:'scripted_fixture',liveModelInference:false,modelCalls:modelCalls.length,nativeWireRequests:wire.length,invalidTargetRecovery:true,apiEchoRequests:1,actualCandidateReproduction:true,nativeArtifactRead:true,reportArtifactReferences:true,oneRunApproval:true,revocation:true,missingRuntime:true,evidenceFile}));
}
main().catch(async error=>{console.error(error);if(panel)console.error((await panel.locator('body').innerText().catch(()=>'' )).slice(-7000));const evidenceFile=path.join(evidenceRoot,'cert-x-managed-agent-failure.json');fs.writeFileSync(evidenceFile,JSON.stringify({provider:'scripted_fixture',liveModelInference:false,toolResults:Object.fromEntries(toolResults),errors,daemonErrors,wire},null,2));console.error(JSON.stringify({errors,daemonErrors,evidenceFile}));process.exitCode=1;}).finally(async()=>{
 await browser?.close(); // Stop native-client polling before terminating the owned daemon.

 try{const descriptor=JSON.parse(fs.readFileSync(path.join(runtimeRoot,'daemon.json'),'utf8'));if(!Number.isSafeInteger(descriptor.pid)||descriptor.pid<1)throw Error('Invalid task daemon PID');const commandLine=execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',`(Get-CimInstance Win32_Process -Filter 'ProcessId=${descriptor.pid}').CommandLine`],{windowsHide:true,encoding:'utf8'}).replaceAll('\\','/').toLowerCase();if(commandLine.includes(path.resolve(temp).replaceAll('\\','/').toLowerCase())&&commandLine.includes('/security/daemon.cjs')&&commandLine.includes(path.resolve(runtimeRoot).replaceAll('\\','/').toLowerCase()))execFileSync('taskkill.exe',['/PID',String(descriptor.pid),'/T','/F'],{windowsHide:true,stdio:'ignore'});}catch{}
 if(registered)execFileSync('reg.exe',['delete',registry,'/f'],{windowsHide:true,stdio:'ignore'});
 if(server){const closed=new Promise(resolve=>server.close(resolve));server.closeAllConnections();await closed;}const absolute=path.resolve(temp);if(absolute.startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(absolute).startsWith('cert-x-managed-agent-'))fs.rmSync(absolute,{recursive:true,force:true,maxRetries:5,retryDelay:150});
});

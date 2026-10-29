// Live OpenRouter inference through cert-x's actual sidepanel chat and native tools.
// The two setup tool calls are scripted solely to retain a real captured scan in
// this chat. Every investigation call after setup comes from the live model.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {execFileSync,spawn}=require('node:child_process');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),model='xiaomi/mimo-v2.6-flash';
const evidenceRoot=path.join(process.env.LOCALAPPDATA,'cert-x','verification');
fs.mkdirSync(evidenceRoot,{recursive:true});
const registry='HKCU\\Software\\Chromium\\NativeMessagingHosts\\com.cert_x.host';
const sourcePack=JSON.parse(fs.readFileSync(path.join(root,'security/ptk/background/dast/modules/modules.json'),'utf8'));
const selectedRulepack={...sourcePack,modules:sourcePack.modules.filter(x=>x.id==='xss').map(x=>({...x,attacks:x.attacks.filter(y=>y.id==='xss_1')}))};
const keyLine=fs.readFileSync(path.join(root,'.env.local'),'utf8').split(/\r?\n/).find(x=>/^\s*OPENROUTER_API_KEY\s*=/.test(x));
if(!keyLine)throw Error('OPENROUTER_API_KEY is absent from repository .env.local');
const apiKey=keyLine.slice(keyLine.indexOf('=')+1).trim().replace(/^['"]|['"]$/g,'');
assert.ok(apiKey,'OPENROUTER_API_KEY is empty');
const work=fs.mkdtempSync(path.join(evidenceRoot,'live-work-'));
const runtimeRoot=path.join(work,'runtime'),evidenceFile=path.join(evidenceRoot,'cert-x-live-model-results.json');
const evidence={kind:'live_model',model,setup:{scripted:true},startedAt:new Date().toISOString(),inferenceRequests:0,requestLimit:24,outputTokenLimit:1200,durationLimitMs:600000,spendingLimitUSD:0.5,priorAccountedCostUSD:Number(process.env.CERT_X_LIVE_PRIOR_COST_USD||0),accountedCostUSD:Number(process.env.CERT_X_LIVE_PRIOR_COST_USD||0),requests:[],toolResults:[],fixtureRequests:[],reportDownloads:[],errors:[]};
let browser,server,daemon,daemonErrors='',registered=false,panel,worker,fixturePage,origin,tabId,phase='setup',setupStep=0,setupResults=new Map(),deadline=0;
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const decode=value=>{try{return JSON.parse(typeof value==='string'?value.replace(/^<system>.*?<\/system>\s*/s,''):value)}catch{return {text:String(value)}}};
const safeError=error=>String(error?.message||error).replaceAll(apiKey,'[credential]');
function parseSse(body){
 const calls=new Map(),text=[];let finishReason=null,usage=null,sseDone=false;
 for(const line of body.split(/\r?\n/))if(line.startsWith('data: ')){
  const data=line.slice(6);if(data==='[DONE]'){sseDone=true;continue}let value;try{value=JSON.parse(data)}catch{continue}
  if(value.usage)usage=value.usage;
  for(const choice of value.choices||[]){const delta=choice.delta||{};if(delta.content)text.push(delta.content);if(choice.finish_reason)finishReason=choice.finish_reason;
   for(const call of delta.tool_calls||[]){const old=calls.get(call.index)||{id:'',name:'',arguments:''};old.id+=call.id||'';old.name+=call.function?.name||'';old.arguments+=call.function?.arguments||'';calls.set(call.index,old)}
  }
 }
 return {finishReason,usage,sseDone,assistantText:text.join(''),toolCalls:[...calls.values()]};
}
function setupDelta(request){
 for(const message of request.messages||[])if(message.role==='tool'&&message.tool_call_id?.startsWith('setup-'))setupResults.set(message.tool_call_id.slice(6),decode(message.content));
 const steps=[['scan','security_start_scan',()=>({tabId,engines:['DAST','SAST'],options:{preset:'ptk-defaults',rulepack:selectedRulepack,runCve:false,allowCaptureWithoutInteraction:true}})],['stop','security_stop_scan',async()=>{await fixturePage.reload();await wait(9000);return {runId:setupResults.get('scan')?.runId}}]];
 const step=steps[setupStep++];
 if(!step)return {role:'assistant',content:'Fixture scan setup complete.'};
 assert.ok(request.tools?.some(x=>x.function?.name===step[1]),'Setup tool missing: '+step[1]);
 return Promise.resolve(step[2]()).then(args=>({role:'assistant',tool_calls:[{index:0,id:'setup-'+step[0],type:'function',function:{name:step[1],arguments:JSON.stringify(args)}}]}));
}
async function main(){
 assert.ok(Number.isFinite(evidence.priorAccountedCostUSD)&&evidence.priorAccountedCostUSD>=0&&evidence.priorAccountedCostUSD<0.5,'Invalid prior spending');
 const modelsResponse=await fetch('https://openrouter.ai/api/v1/models',{signal:AbortSignal.timeout(15000)});assert.equal(modelsResponse.ok,true,'Pricing lookup failed');
 const selected=(await modelsResponse.json()).data.find(item=>item.id===model);assert.ok(selected,'Selected model is unavailable');
 evidence.pricing=selected.pricing;const inputPrice=Number(selected.pricing.prompt),outputPrice=Number(selected.pricing.completion);
 assert.ok(Number.isFinite(inputPrice)&&inputPrice>=0&&Number.isFinite(outputPrice)&&outputPrice>=0,'Unknown token pricing');
 assert.equal(Number(selected.pricing.request||0),0,'Per-request charges require separate accounting');
 const installed=path.join(process.env.LOCALAPPDATA,'cert-x','security-runtime','installed.json');
 assert.ok(fs.existsSync(installed),'Prepared managed runtime missing');
 let existing=false;try{execFileSync('reg.exe',['query',registry],{stdio:'ignore'});existing=true}catch{};
 assert.equal(existing,false,'Existing Chromium native host registration must not be clobbered');
 fs.mkdirSync(runtimeRoot,{recursive:true});fs.copyFileSync(installed,path.join(runtimeRoot,'installed.json'));
 server=http.createServer(async(req,res)=>{
  try{
   if(req.url.endsWith('/models')){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({data:[{id:model,name:model}]}));return}
   const chunks=[];for await(const chunk of req)chunks.push(chunk);const body=Buffer.concat(chunks).toString();
   if(!req.url.includes('/chat/completions')){
    evidence.fixtureRequests.push({url:req.url,method:req.method,body:body.slice(0,200)});
    res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','*');if(req.method==='OPTIONS'){res.end();return}
    if(req.url==='/app.js'){res.setHeader('Content-Type','application/javascript');res.end('document.getElementById("sink").innerHTML=new URLSearchParams(location.search).get("q");');return}
    const q=new URL(req.url,'http://fixture').searchParams.get('q')||'';
    if(q.includes('<'))res.statusCode=500;
    res.setHeader('Content-Type','text/html');res.end((q.includes('<')?'<pre>TemplateSyntaxError: invalid template expression</pre>':'')+'<!doctype html><title>Managed application</title><h1>Managed fixture</h1><div id="sink">'+q+'</div><script src="/app.js"></script>');return;
   }
   const request=JSON.parse(body);
   for(const message of request.messages||[])if(message.role==='tool'&&!message.tool_call_id?.startsWith('setup-')){
    const id=message.tool_call_id,decoded=decode(message.content);
    if(!evidence.toolResults.some(x=>x.id===id))evidence.toolResults.push({id,result:decoded});
   }
   if(phase==='setup'||phase==='prime'){
    const delta=phase==='prime'?{role:'assistant',content:'Fixture workspace ready.'}:await setupDelta(request),id='fixture-setup-'+setupStep;
    res.writeHead(200,{'Content-Type':'text/event-stream'});
    res.write('data: '+JSON.stringify({id,object:'chat.completion.chunk',choices:[{index:0,delta}]})+'\n\n');
    res.write('data: '+JSON.stringify({id,object:'chat.completion.chunk',choices:[{index:0,delta:{},finish_reason:delta.tool_calls?'tool_calls':'stop'}]})+'\n\n');res.end('data: [DONE]\n\n');return;
   }
   if(Date.now()>deadline||evidence.inferenceRequests>=24){res.writeHead(429,{'Content-Type':'application/json'});res.end(JSON.stringify({error:{message:'Live verification bound reached'}}));return}
   assert.equal(request.model,model,'UI must select the requested model');
   const outgoing={...request,model,max_tokens:1200,reasoning:{enabled:false},stream_options:{include_usage:true}};
   // Reserve a conservative UTF-8 byte upper bound for input tokens plus
   // framing overhead. Never spend an uncertain failed-request reservation twice.
   const reservedCostUSD=(Buffer.byteLength(JSON.stringify(outgoing))+4096)*inputPrice+1200*outputPrice;
   if(evidence.accountedCostUSD+reservedCostUSD>evidence.spendingLimitUSD){evidence.errors.push('Live validation spending ceiling reached before dispatch');res.writeHead(429,{'Content-Type':'application/json'});res.end(JSON.stringify({error:{message:'Live validation spending ceiling reached'}}));return;}
   evidence.accountedCostUSD+=reservedCostUSD;evidence.inferenceRequests++;
   const entry={number:evidence.inferenceRequests,at:new Date().toISOString(),advertisedToolNames:(request.tools||[]).map(x=>x.function?.name),model:request.model,reservedCostUSD};evidence.requests.push(entry);
   const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),Math.max(1,deadline-Date.now()));
   try{
    const upstream=await fetch('https://openrouter.ai/api/v1/chat/completions',{method:'POST',headers:{'Authorization':'Bearer '+apiKey,'Content-Type':'application/json'},body:JSON.stringify(outgoing),signal:controller.signal});
    entry.httpStatus=upstream.status;entry.providerHeaders={requestId:upstream.headers.get('x-request-id')||null};
    const responseText=await upstream.text();
    if(upstream.ok){Object.assign(entry,parseSse(responseText))}else{let error;try{error=JSON.parse(responseText)}catch{error={message:responseText.slice(0,500)}}entry.providerError=error}
    res.writeHead(upstream.status,{'Content-Type':upstream.headers.get('content-type')||'application/json'});res.end(responseText);
   }catch(error){entry.transportError=safeError(error);res.writeHead(502,{'Content-Type':'application/json'});res.end(JSON.stringify({error:{message:entry.transportError}}))}finally{if(Number.isFinite(entry.usage?.prompt_tokens)&&Number.isFinite(entry.usage?.completion_tokens)){entry.accountedCostUSD=Math.max(Number(entry.usage.cost)||0,entry.usage.prompt_tokens*inputPrice+entry.usage.completion_tokens*outputPrice);evidence.accountedCostUSD+=entry.accountedCostUSD-reservedCostUSD;}else entry.accountedCostUSD=reservedCostUSD;entry.settled=true;clearTimeout(timeout);console.log(JSON.stringify({request:entry.number,httpStatus:entry.httpStatus,finishReason:entry.finishReason,toolCalls:(entry.toolCalls||[]).map(call=>call.name),accountedCostUSD:evidence.accountedCostUSD}));}
  }catch(error){evidence.errors.push(safeError(error));if(!res.headersSent)res.writeHead(500,{'Content-Type':'application/json'});res.end(JSON.stringify({error:{message:safeError(error)}}))}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launchPersistentContext(path.join(work,'profile'),{headless:true,viewport:{width:720,height:950},executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(()=>certXSecurity.ready);const extensionId=new URL(worker.url()).host;
 const host=path.join(work,'host');execFileSync('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',path.join(root,'tools/host/install.ps1'),'-ExtensionId',extensionId,'-Browser','Chromium','-OutputDirectory',host],{windowsHide:true,stdio:'pipe'});registered=true;
 const installedHost=path.join(host,'Chromium',extensionId);fs.writeFileSync(path.join(installedHost,'launch.cmd'),'@echo off\r\nset "CERT_X_SECURITY_ROOT='+runtimeRoot+'"\r\n"'+process.execPath+'" "'+path.join(installedHost,'ki-host.js')+'" %*\r\n');
 daemon=spawn(process.execPath,[path.join(installedHost,'security/daemon.cjs'),runtimeRoot],{windowsHide:true,stdio:['ignore','ignore','pipe']});daemon.stderr.on('data',chunk=>daemonErrors+=chunk);
 for(let i=0;i<100&&!fs.existsSync(path.join(runtimeRoot,'daemon.json'));i++)await wait(50);
 await worker.evaluate(async origin=>{await chrome.storage.local.set({sidepanel_language:'en',sidepanel_theme:'dark',sidepanel_approval_mode:'full_access',ki_native_settings:{enabled:true,servers:[]},sidepanel_connections:[{id:'live',label:'Selected OpenRouter model',presetId:'openrouter',apiKey:'local-proxy-placeholder',host:origin+'/api/v1'}]})},origin);
 fixturePage=await browser.newPage();await fixturePage.goto(origin+'/app?q=fixture');tabId=await worker.evaluate(async target=>(await chrome.tabs.query({})).find(tab=>tab.url===target).id,origin+'/app?q=fixture');
 const settings=await browser.newPage();await settings.goto('chrome-extension://'+extensionId+'/providers/providers.html?section=security');await settings.waitForFunction(()=>!document.querySelector('main').inert);
 const workspace=await settings.evaluate(async target=>chrome.runtime.sendMessage({type:'KI_CONTEXT',op:'save_workspace',workspace:{id:'live-agent',name:'Live agent',profileId:'bugbounty',dastScope:{origins:[target],excludePaths:[]}}}),origin);assert.equal(workspace.ok,true,JSON.stringify(workspace));
 panel=await browser.newPage();panel.on('pageerror',error=>evidence.errors.push(error.message));await panel.goto('chrome-extension://'+extensionId+'/pages/sidepanel.html');await panel.waitForFunction(()=>document.querySelector('.wb-composer-model .wb-mode-toggle')?.disabled===false);
 async function prompt(value){await panel.locator('.wb-editor').first().click();await panel.keyboard.type(value);await panel.keyboard.press('Enter')}
 phase='prime';await prompt('Prepare fixture workspace.');await panel.getByText('Fixture workspace ready.',{exact:true}).waitFor({timeout:45000});
 await panel.getByLabel('Workspace',{exact:true}).selectOption('live-agent');await panel.waitForFunction(()=>document.querySelector('[aria-label="Profile"]').disabled===false);
 phase='setup';await prompt('Prepare the local fixture scan.');await panel.getByText('Fixture scan setup complete.',{exact:true}).waitFor({timeout:90000});
 assert.ok(setupResults.get('scan')?.runId,'Real setup scan run was not created');assert.equal(setupResults.get('stop')?.error,undefined,JSON.stringify(setupResults.get('stop')));
 evidence.setup.scanRunId=setupResults.get('scan').runId;evidence.setup.stopResult=setupResults.get('stop');
 evidence.reasoning={enabled:false};
 phase='live';deadline=Date.now()+600000;evidence.liveStartedAt=new Date().toISOString();
 evidence.livePrompt='Investigate the already captured local scan '+evidence.setup.scanRunId+' on the authorized synthetic localhost fixture '+origin+'/app. Use advertised security tools and exact returned IDs. List candidates, inspect one candidate and readiness, create an isolated managed browser session, reproduce with that session, and check the job until terminal. For the artifact step, artifact metadata and one security_browser.readArtifact call suffice; do not decode binary artifacts or write scripts. Then independently test browser impact in the actual managed browser: navigate its page to /app?q=<script>document.title=\'XSS_EXEC_MARKER\'</script> (URL-encode the q value), inspect that page and record its title; navigate the same managed page to /app?q=hello and inspect its title as a negative control. Use the original browser runId returned by create on every browser follow-up, including navigate, inspect, and readArtifact. Do not evaluate on the extension settings or sidepanel page. After the browser impact and control, create and export an evidence package for the candidate, then call security_export_report for the scan run. Describe candidate observations separately from demonstrated browser impact and avoid unsupported authentication or access-control claims. Independent tool calls may be issued together. Finish with a factual result under 150 words.';
 await prompt(evidence.livePrompt);
 // The Profile selector can remain enabled while inference is still in flight.
 // Wait for a completed provider turn, not a composer control's transient state.
 while(Date.now()<deadline){
  const last=evidence.requests.at(-1);
  if(last?.finishReason&&last.finishReason!=='tool_calls'||last?.providerError||last?.transportError||evidence.errors.some(error=>error.includes('spending ceiling'))||evidence.inferenceRequests>=24&&last?.settled)break;
  await wait(250);
 }
 // The deadline aborts an in-flight upstream fetch. Wait for its response body
 // or abort result before persisting evidence and closing the local proxy.
 const settleUntil=Date.now()+30000;
 while(evidence.requests.at(-1)&&!evidence.requests.at(-1).settled&&Date.now()<settleUntil)await wait(100);
 assert.ok(evidence.requests.at(-1)?.settled,'Final inference request did not settle');
 evidence.liveTerminalReason=evidence.requests.at(-1)?.finishReason==='stop'?'model_stop':evidence.inferenceRequests>=24?'request_limit':Date.now()>=deadline?'time_limit':'provider_failure';
 await wait(1500);
 evidence.finishedAt=new Date().toISOString();evidence.panelText=(await panel.locator('body').innerText()).slice(-12000);
 const calls=evidence.requests.flatMap(x=>x.toolCalls||[]);evidence.modelToolCalls=calls.length;evidence.calledTools=calls.map(x=>x.name);
 const reports=evidence.toolResults.filter(item=>calls.some(call=>call.id===item.id&&call.name==='security_export_report')).flatMap(item=>item.result?.reports||[]).filter(report=>Number.isInteger(report.downloadId));
 for(const report of reports){
  const item=await worker.evaluate(async downloadId=>(await chrome.downloads.search({id:downloadId}))[0]||null,report.downloadId);
  const record={id:report.downloadId,state:item?.state||'missing',filename:item?.filename||null,expectedName:report.name,expectedBytes:report.size,bytes:0};
  // Playwright stores Chrome downloads under opaque temporary basenames. The
  // export result supplies the intended name; Chrome supplies the actual path.
  if(item?.state==='complete'&&item.filename&&fs.existsSync(item.filename)&&/^cert-x-security-[a-zA-Z0-9_-]+\.(md|json|pdf)$/.test(report.name)&&fs.statSync(item.filename).size===report.size){
   const target=path.join(evidenceRoot,report.name);fs.copyFileSync(item.filename,target,fs.constants.COPYFILE_EXCL);record.retainedPath=target;record.bytes=fs.statSync(target).size;record.sha256=crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex');
  }
  evidence.reportDownloads.push(record);
 }
 assert.ok(evidence.inferenceRequests>0,'No live inference request');
 assert.ok(calls.some(x=>x.name==='security_candidates'),'Live model did not investigate candidates');
 console.log(JSON.stringify({model,inferenceRequests:evidence.inferenceRequests,calledTools:evidence.calledTools,providerErrors:evidence.requests.filter(x=>x.httpStatus!==200).map(x=>({number:x.number,status:x.httpStatus,error:x.providerError||x.transportError})),evidenceFile}));
}
main().catch(async error=>{evidence.errors.push(safeError(error));if(panel)evidence.panelText=(await panel.locator('body').innerText().catch(()=>'' )).slice(-12000);console.error(safeError(error));process.exitCode=1}).finally(async()=>{
 await browser?.close(); // Stop native-client polling before terminating the owned daemon.

 evidence.finishedAt||=new Date().toISOString();evidence.daemonErrors=daemonErrors;fs.writeFileSync(evidenceFile,JSON.stringify(evidence,null,2).replaceAll(apiKey,'[credential]'));
 try{const descriptor=JSON.parse(fs.readFileSync(path.join(runtimeRoot,'daemon.json'),'utf8'));if(!Number.isSafeInteger(descriptor.pid)||descriptor.pid<1)throw Error('Invalid daemon PID');const commandLine=execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',`(Get-CimInstance Win32_Process -Filter 'ProcessId=${descriptor.pid}').CommandLine`],{windowsHide:true,encoding:'utf8'}).replaceAll('\\','/').toLowerCase();if(commandLine.includes(path.resolve(work).replaceAll('\\','/').toLowerCase())&&commandLine.includes('/security/daemon.cjs'))execFileSync('taskkill.exe',['/PID',String(descriptor.pid),'/T','/F'],{windowsHide:true,stdio:'ignore'})}catch{}
 try{const registration=execFileSync('reg.exe',['query',registry,'/ve'],{windowsHide:true,encoding:'utf8'}).replaceAll('\\','/').toLowerCase();const ownedHost=path.join(work,'host').replaceAll('\\','/').toLowerCase();if(registration.includes(ownedHost+'/'))execFileSync('reg.exe',['delete',registry,'/f'],{windowsHide:true,stdio:'ignore'});else if(registered)console.error('Chromium registration changed during run; preserving it.')}catch(error){if(registered)console.error('Could not verify/remove owned Chromium registration:',error.message)}
 if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
 const absolute=path.resolve(work);if(absolute.startsWith(path.resolve(evidenceRoot)+path.sep)&&path.basename(absolute).startsWith('live-work-'))fs.rmSync(absolute,{recursive:true,force:true,maxRetries:5,retryDelay:150});
 try{execFileSync(process.execPath,[path.join(__dirname,'live-model-verify.cjs'),evidenceFile],{stdio:'inherit'})}catch{process.exitCode=1}
});

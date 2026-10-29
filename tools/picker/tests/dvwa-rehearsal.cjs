// Demo rehearsal against a real DVWA target (default http://127.0.0.1:4280,
// override with DVWA_ORIGIN). Proves the full machine end-to-end on the actual
// demo target: login, DAST scan through the real tool channel, findings,
// terminal stop, report export, and the knowledge-graph tools advertised to
// the model and executed through a scripted model turn.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-dvwa-rehearsal-'));
const origin=process.env.DVWA_ORIGIN||'http://127.0.0.1:4280',sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let browser,panel,worker,base,session,modelStep=0;
const pageErrors=[],modelCalls=[],toolResults=[],resumeSeen=[];
const mark=(phase,detail)=>console.log('REHEARSAL',phase,detail||'');
async function main(){
let provider;
try{
 // Mock model provider: scripts graph_write -> graph_digest -> done, and
 // records which tools were advertised plus every tool result the model saw.
 const provider=http.createServer((req,res)=>{
  const url=new URL(req.url,'http://fixture');
  if(url.pathname.endsWith('/models')){res.setHeader('Content-Type','application/json');return res.end(JSON.stringify({data:[{id:'mock/rehearsal',name:'Rehearsal',context_length:128000}]}));}
  if(url.pathname.endsWith('/chat/completions')){let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{try{
   const request=JSON.parse(body),names=(request.tools||[]).map(tool=>tool.function?.name);modelCalls.push(names);
   for(const item of request.messages||[])if(item.role==='tool')toolResults.push(String(item.content));
   // Two-level script: the orchestrator delegates recon to a subagent whose
   // task brief carries the marker; the subagent writes the graph and returns
   // a summary, then the orchestrator reads the digest.
   const isSub=(request.messages||[]).some(item=>item.role==='user'&&String(item.content).includes('RECON-BRIEF'));
   const isResume=(request.messages||[]).some(item=>item.role==='user'&&String(item.content).includes('[resume]'));
   const hadToolResult=(request.messages||[]).some(item=>item.role==='tool');
   if(isResume)resumeSeen.push(1);
   const graphWrite={name:'graph_write',arguments:JSON.stringify({nodes:[
      {id:'dvwa',kind:'origin',label:origin},
      {id:'r-sqli',kind:'route',label:'/vulnerabilities/sqli/'},
      {id:'p-id',kind:'param',label:'id'}],
     edges:[{from:'dvwa',to:'r-sqli',kind:'hosts'},{from:'r-sqli',to:'p-id',kind:'has_param'}]})};
   // Failure injection: the subagent's would-be final answer (after its graph
   // write) is killed mid-stream; the resume path must retry with [resume]
   // and only then deliver the summary.
   let action,killStream=false;
   if(isSub){if(isResume)action=null;else if(hadToolResult)killStream=true;else action=graphWrite;}
   else{const main=[{name:'agent',arguments:JSON.stringify({description:'Recon the DVWA sqli area',prompt:'RECON-BRIEF: enumerate the DVWA sqli area and record it with graph_write, then summarize.'})},{name:'graph_digest',arguments:'{}'}];action=main[modelStep++]||null;}
   if(killStream){res.writeHead(200,{'Content-Type':'text/event-stream'});res.write('data: '+JSON.stringify({id:'rehearsal',object:'chat.completion.chunk',choices:[{index:0,delta:{role:'assistant',content:'SUBAG'}}]})+'\n\n');res.destroy();return;}
   const finalText=isSub?'SUBAGENT-DONE':'REHEARSAL-DONE';
   res.writeHead(200,{'Content-Type':'text/event-stream'});const send=x=>res.write('data: '+JSON.stringify(x)+'\n\n');
   send({id:'rehearsal',object:'chat.completion.chunk',choices:[{index:0,delta:action?{role:'assistant',tool_calls:[{index:0,id:'reh-'+Math.floor(Math.random()*1e9),type:'function',function:{name:action.name,arguments:action.arguments}}]}:{role:'assistant',content:finalText}}]});
   send({id:'rehearsal',object:'chat.completion.chunk',choices:[{index:0,delta:{},finish_reason:action?'tool_calls':'stop'}]});res.end('data: [DONE]\n\n');
  }catch(error){res.statusCode=500;res.end();}});return;}
  res.writeHead(404);res.end();
 });await new Promise(resolve=>provider.listen(0,'127.0.0.1',resolve));
 const downloads=path.join(temp,'downloads'),profile=path.join(temp,'profile');fs.mkdirSync(downloads);fs.mkdirSync(path.join(profile,'Default'),{recursive:true});
 fs.writeFileSync(path.join(profile,'Default/Preferences'),JSON.stringify({download:{default_directory:downloads,prompt_for_download:false}}));
 browser=await chromium.launchPersistentContext(profile,{headless:true,downloadsPath:downloads,viewport:{width:720,height:1000},executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 mark('browser launched');
 worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker',{timeout:15000});
 await worker.evaluate(async()=>{await certXSecurity.ready;});
 base='chrome-extension://'+new URL(worker.url()).host;
 for(let i=0;i<8;i++){await worker.evaluate(host=>chrome.storage.local.set({sidepanel_language:'en',sidepanel_theme:'dark',sidepanel_approval_mode:'full_access',sidepanel_connections:[{id:'mock',label:'Mock',presetId:'openrouter',apiKey:'fixture',host:host+'/api/v1'}]}),'http://127.0.0.1:'+provider.address().port);await sleep(300);if((await worker.evaluate(()=>chrome.storage.local.get('sidepanel_connections'))).sidepanel_connections?.length)break;}
 // Phase A: real target (local container or hosted pentest-ground instance).
 // Login; a fresh hosted instance (redeployed every 30 min) needs one-time
 // database creation before login succeeds.
 const target=await browser.newPage();target.on('pageerror',error=>pageErrors.push(error.message));
 const login=async()=>{
  await target.goto(origin+'/login.php');
  await target.fill('input[name=username]','admin');await target.fill('input[name=password]','password');
  await Promise.all([target.waitForNavigation(),target.click('input[name=Login]')]);
  return new URL(target.url()).pathname;
 };
 let landed=await login();
 if(landed!=='/index.php'){
  assert.equal(landed,'/setup.php','login must reach the index or the setup page');
  await Promise.all([target.waitForNavigation(),target.click('input[name=create_db]')]);
  landed=await login();
  assert.equal(landed,'/index.php','DVWA login must reach the index after setup (create the database first)');
 }
 await target.goto(origin+'/security.php');
 if(!/<option value="low" selected=/i.test(await target.content())){
  await target.selectOption('select[name=security]','low');
  await Promise.all([target.waitForNavigation(),target.click('input[name=seclev_submit]')]);
 }
 assert.match(await target.content(),/<option value="low" selected=/i,'DVWA security must be on Low for the rehearsal');
 mark('dvwa ready','logged in, security low');
 const tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(tab=>tab.url.startsWith(url)).id,origin);
 // Side panel on the DVWA tab; bugbounty profile so security tools are selected.
 panel=await browser.newPage();panel.on('pageerror',error=>pageErrors.push(error.message));
 await panel.goto(base+'/pages/sidepanel.html?tabId='+tabId);
 await panel.waitForFunction(()=>document.querySelector('[aria-label="Profile"]')?.disabled===false);
 await panel.getByLabel('Profile',{exact:true}).selectOption('bugbounty');
 await panel.locator('.ki-security-panel').waitFor();
 // The profile assignment lives on the panel's real chat; use that session.
 for(let i=0;i<20;i++){const chats=await worker.evaluate(()=>chrome.storage.local.get('ki_contexts').then(value=>value.ki_contexts?.chats||{}));
  const bugbounty=Object.entries(chats).find(([id,chat])=>chat.profileId==='bugbounty');
  if(bugbounty){session=bugbounty[0];break;}await sleep(500);}
 assert.ok(session,'bugbounty chat must exist after profile selection');
 const raw=async(op,args={})=>Promise.race([panel.evaluate(message=>chrome.runtime.sendMessage(message),{type:'KI_SECURITY',op,session,...args}),new Promise((_,reject)=>setTimeout(()=>reject(Error('Timed out '+op)),45000))]);
 const call=async(op,args={})=>{const response=await raw(op,args);assert.equal(response?.ok,true,JSON.stringify(response));return response.result;};
 mark('scan start');
 const started=await call('start',{tabId,engines:['DAST'],scope:{origins:[origin],excludePaths:[]},options:{preset:'thorough',maxRequests:60,durationSeconds:60}});
 assert.ok(started.runId,'start must return a runId');
 // Exercise the vulnerable surface while the scan observes.
 for(const route of ['/vulnerabilities/sqli/?id=1&Submit=Submit','/vulnerabilities/xss_r/?name=rehearsal','/vulnerabilities/brute/']){await target.goto(origin+route);await sleep(700);}
 let status,waited=0;for(;waited<40;waited++){status=await call('status',{runId:started.runId});if(status.requestsSent>0&&status.engineStatus?.DAST?.idle!==false)break;await sleep(1000);}
 assert.ok(status.requestsSent>0,'DAST must dispatch probe requests (got '+status.requestsSent+')');
 const stopped=await call('stop',{runId:started.runId});
 for(let i=0;i<60;i++){status=await call('status',{runId:started.runId});if(status.state!=='running'&&status.state!=='stopping')break;await sleep(1000);}
 // A stop with work in flight can end 'cancelled' rather than 'completed';
 // any terminal state with retained evidence passes.
 assert.ok(['completed','cancelled'].includes(status.state),'stop must reach a terminal state (got '+status.state+')');
 const findings=await call('findings',{runId:started.runId,limit:200});
 const families=[...new Set((findings.findings||[]).map(item=>item.moduleId||item.ruleId))];
 const exported=await call('export',{runId:started.runId,format:'json'});
 const download=(await worker.evaluate(id=>chrome.downloads.search({id}),exported.reports[0].downloadId))[0];
 assert.equal(download.state,'complete');
 const report=JSON.parse(fs.readFileSync(download.filename,'utf8'));
 assert.equal(report.run.runId,started.runId);
 mark('scan complete',JSON.stringify({requestsSent:status.requestsSent,findings:findings.total,families:families.slice(0,8),reportBytes:fs.statSync(download.filename).size}));
 // Phase B: orchestration through scripted model turns. The orchestrator
 // delegates recon to a subagent (agent tool), the subagent writes the graph,
 // its summary returns, and the orchestrator reads the digest.
 await panel.locator('.wb-editor').first().click();
 await panel.keyboard.type('Delegate recon for the DVWA sqli area, then summarize the frontier.');
 await panel.keyboard.press('Enter');
 await panel.getByText('REHEARSAL-DONE',{exact:true}).waitFor({timeout:60000});
 await panel.waitForFunction(()=>document.querySelector('[aria-label="Profile"]')?.disabled===false);
 const advertised=modelCalls[modelCalls.length-1]||[];
 for(const tool of ['agent','graph_digest','security_start_scan','attach_tab'])assert.ok(advertised.includes(tool),'Model schema must advertise '+tool);
 const writeResult=JSON.parse(toolResults.find(text=>text.includes('"written"')));
 assert.equal(writeResult.written.nodes,3);
 assert.ok(toolResults.some(text=>text.includes('SUBAGENT-DONE')),'The subagent summary must return to the orchestrator');
 assert.equal(resumeSeen.length,1,'the killed subagent stream must trigger exactly one [resume] retry');
 const digest=JSON.parse(toolResults.find(text=>text.includes('"unvisitedRoutes"')));
 assert.equal(digest.counts.nodes>=3,true);
 assert.ok(digest.unvisitedRoutes.includes('/vulnerabilities/sqli/'),'frontier must list the unvisited sqli route');
 assert.deepEqual(pageErrors,[],'no page errors');
 console.log('REHEARSAL-PASS',JSON.stringify({requestsSent:status.requestsSent,findings:findings.total,families,graphCounts:digest.counts,unvisitedRoutes:digest.unvisitedRoutes,orchestrated:true,advertisedTools:advertised.filter(name=>name.startsWith('graph_')||name.startsWith('security_')||name==='agent').length}));
}catch(error){console.error('REHEARSAL-FAIL at',error.message);console.error('DEBUG',JSON.stringify({conversations:modelCalls.map(names=>({tools:names.length,hasAgent:names.includes('agent'),hasGraphWrite:names.includes('graph_write')})),lastResults:toolResults.slice(-5).map(text=>text.slice(0,160))}));process.exitCode=1;}
finally{try{await Promise.race([browser?.close(),sleep(5000)]);}catch{}try{provider?.close();}catch{}process.exit(process.exitCode||0);}
}
main();

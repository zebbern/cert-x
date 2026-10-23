// Differential browser test: original PTK and cert-x use independent profiles
// with identical application fixtures and engine options. No companion patches.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const {resolveReference}=require('../prepare-reference.cjs');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-security-parity-'));
const engines=(process.env.PARITY_ENGINES||'SAST,SCA').split(',');
let server,browser,reference;
const wire=[];
async function run(extension,integrated,origin,safe) {
  browser=await chromium.launchPersistentContext(path.join(temp,(integrated?'owned':'reference')+(safe?'-safe':'')),{headless:true,executablePath:process.env.CHROMIUM_PATH||path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),args:['--disable-extensions-except='+extension,'--load-extension='+extension]});
  const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker',{timeout:15000});
  const logs=[];browser.on('console',message=>{if(['error','warning'].includes(message.type()))logs.push(message.text());});
  await worker.evaluate(async integrated=>{if(integrated)await globalThis.certXSecurity.ready;else {for(let i=0;i<200&&!globalThis.ptk_app?.ready;i++)await new Promise(r=>setTimeout(r,25));await globalThis.ptk_app.ready;globalThis.ptk_app.devLocalConfig.automationEnabled=true;}},integrated);
  const page=await browser.newPage(),url=origin+(safe?'/safe':'/unsafe')+'?q=probe';
  await page.goto(url);
  const tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(t=>t.url===url).id,url);
  const context={owner:'parity',tabId,scope:{origins:[origin],excludePaths:[]},config:{scanStrategy:'SMART',dastScanStrategy:'SMART',scanControlProfile:'safe',maxRequestsPerSecond:5,concurrency:3,planningConcurrency:2,runCve:false}};
  const started=await worker.evaluate(async({integrated,engines,tabId,url,context})=>{
    if(engines.includes('DAST')) {
      const pack=await(await fetch(chrome.runtime.getURL((integrated?'security/':'')+'ptk/background/dast/modules/modules.json'))).json();
      const xss=pack.modules.find(module=>module.id==='xss');
      context.config.rulepack={...pack,modules:[{...xss,attacks:xss.attacks.filter(attack=>['xss_1','xss_2','xss_3'].includes(attack.id))}]};
      context.config.concurrency=1;
    }
    if(integrated)return globalThis.certXSecurity.runtime.invoke('startScan',{tabId,engines,options:context.config},context);
    const tab=await chrome.tabs.get(tabId);return globalThis.ptk_app.automation.msg_session_start({pageUrl:url,options:{engines,runCve:false,policyCode:'SMART',engineConfigs:{DAST:context.config}}},{id:chrome.runtime.id,frameId:0,url,tab});
  },{integrated,engines,tabId,url,context});
  assert.ok(started.sessionId,JSON.stringify(started));
  await page.reload();
  await page.getByRole('button',{name:'Render',exact:true}).click();
  if(engines.includes('DAST')) {
    await worker.evaluate(async ({origin,safe,tabId})=>{
      const engine=globalThis.ptk_app.dast.engine;
      const url=origin+(safe?'/safe':'/unsafe')+'?q=probe';
      await engine.enqueue({raw:'GET '+url+' HTTP/1.1\r\nHost: '+new URL(origin).host+'\r\n\r\n',ui_url:url,responseType:'main_frame',fingerprint:'parity-explicit-seed'}, {url,tabId,method:'GET',type:'main_frame',statusCode:200,requestId:'parity-request',responseHeaders:[{name:'Content-Type',value:'text/html'}]});
    },{origin,safe,tabId});
  }
  if(engines.includes('IAST')) {
    // Both runtimes get the same post-readiness application activity.
    await worker.evaluate(async()=>{const limit=Date.now()+12000;while(Date.now()<limit){if(globalThis.ptk_app.iast?.agentReady===true)break;await new Promise(r=>setTimeout(r,100));}});
    await page.evaluate(()=>document.querySelector('button')?.click());
  }
  await new Promise(r=>setTimeout(r,engines.includes('DAST')?12000:4000));
  const stopped=await worker.evaluate(async({integrated,sessionId,tabId,url,context})=>{
    if(integrated)return globalThis.certXSecurity.runtime.invoke('stopScan',{sessionId},context);
    return globalThis.ptk_app.automation.msg_session_end({options:{sessionId,sessionScope:'current-tab'},wait:true},{id:chrome.runtime.id,frameId:0,url,tab:{id:tabId,url}});
  },{integrated,sessionId:started.sessionId,tabId,url,context});
  assert.notEqual(stopped.ok,false,JSON.stringify(stopped));
  const result=await worker.evaluate(async id=>{const a=globalThis.ptk_app.automation,s=a.sessions.get(id);return {status:s.status,engines:s.engineStates,findings:a._collectFindings(s,Number.MAX_SAFE_INTEGER)};},started.sessionId);
  fs.writeFileSync(path.join(os.tmpdir(),'cert-x-security-parity-last-'+(integrated?'owned':'reference')+'.json'),JSON.stringify({engines,safe,result,logs,wire},null,2));
  assert.equal(result.status,'completed',JSON.stringify({integrated,safe,result,logs:logs.slice(-15)}));
  for(const engine of engines)assert.notEqual(result.engines[engine]?.status,'error',JSON.stringify(result.engines));
  await browser.close();browser=null;
  return result;
}
function normalized(result) {
  return result.findings.findings.map(f=>({engine:f.engine,moduleId:f.moduleId,ruleId:f.ruleId,title:f.title,severity:f.severity,url:f.url,confidence:f.confidence})).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
}
async function main(){
  reference=resolveReference(process.env.PTK_REFERENCE_ROOT);
  server=http.createServer((req,res)=>{wire.push({method:req.method,url:req.url});const url=new URL(req.url,'http://fixture');
    // Retire.js filename/version detection fixture, not an implementation of jQuery.
    if(/^\/jquery-/.test(url.pathname)){res.setHeader('Content-Type','application/javascript');return res.end('/* dependency version detection fixture */');}
    if(url.pathname==='/unsafe.js'){res.setHeader('Content-Type','application/javascript');return res.end('function render(){document.getElementById("sink").innerHTML=new URLSearchParams(location.search).get("q")||"fixture";} document.querySelector("button").onclick=render; render();');}
    if(url.pathname==='/safe.js'){res.setHeader('Content-Type','application/javascript');return res.end('function render(){document.getElementById("sink").textContent=new URLSearchParams(location.search).get("q")||"fixture";} document.querySelector("button").onclick=render; render();');}
    if(url.pathname==='/favicon.ico'){res.writeHead(204);return res.end();}
    const q=url.searchParams.get('q')||'',value=url.pathname==='/safe'?q.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;'):q;
    res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Parity fixture</title><button>Render</button><section>'+value+'</section><div id="sink"></div><script src="'+(url.pathname==='/safe'?'/safe.js':'/unsafe.js')+'"></script><script src="/jquery-'+(url.pathname==='/safe'?'3.7.1':'1.12.4')+'.js"></script>');
  });await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
  const evidence={engines,reference:reference.sha256||reference.extensionPath,cases:[]};
  for(const safe of [false,true]){
    const baseline=await run(reference.extensionPath,false,origin,safe),owned=await run(root,true,origin,safe);
    evidence.cases.push({safe,baseline,owned,baselineNormalized:normalized(baseline),ownedNormalized:normalized(owned)});
    const evidenceFile=path.join(os.tmpdir(),'cert-x-security-parity-'+engines.join('-')+'.json');fs.writeFileSync(evidenceFile,JSON.stringify(evidence,null,2));
    assert.deepEqual(normalized(owned),normalized(baseline),'Finding/evidence classification parity on '+(safe?'negative':'positive')+' fixture; evidence: '+evidenceFile);
    if(engines.includes('SAST'))assert.equal(normalized(owned).some(f=>f.ruleId==='dom-xss-taint'),!safe,'Known taint-flow positive/negative oracle');
    if(engines.includes('DAST'))assert.equal(normalized(owned).some(f=>f.moduleId==='xss'),!safe,'Known reflected XSS positive/negative oracle');
    if(engines.includes('SCA'))assert.equal(normalized(owned).some(f=>f.engine==='SCA'),!safe,'Known vulnerable/fixed dependency version oracle');
    console.log(JSON.stringify({engines,safe,baselineFindings:baseline.findings.findings.length,ownedFindings:owned.findings.findings.length,parity:true,evidenceFile}));
  }
}
main().catch(error=>{console.error(error);process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(r=>server.close(r));for(const folder of [temp,reference?.directory])if(folder&&path.resolve(folder).startsWith(path.resolve(os.tmpdir())+path.sep)&&/^cert-x-security-(?:parity|reference)-/.test(path.basename(folder)))fs.rmSync(folder,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

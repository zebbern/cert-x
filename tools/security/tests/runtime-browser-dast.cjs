const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const {resolveReference}=require('../prepare-reference.cjs');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-security-browser-dast-'));
let browser,server,reference;const wire=[];
const angularFile=path.join(__dirname,'fixtures/angular/angular-1.1.5.min.js');
async function run(extension,integrated,origin,kind,safe){
 const logs=[];browser=await chromium.launchPersistentContext(path.join(temp,(integrated?'owned':'ref')+'-'+kind+'-'+safe),{headless:true,executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+extension,'--load-extension='+extension]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');worker.on('console',m=>{if(m.type()==='error')logs.push(m.text());});
 await worker.evaluate(async integrated=>{if(integrated){await certXSecurity.ready;}else{for(let i=0;i<200&&!globalThis.ptk_app?.ready;i++)await new Promise(r=>setTimeout(r,50));await ptk_app.ready;ptk_app.devLocalConfig.automationEnabled=true;}},integrated);
 const page=await browser.newPage(),url=origin+'/'+kind+(safe?'-safe':'-unsafe')+'?q=hello'+(kind==='spa'?'#/search?q=hello':'');await page.goto(url);await page.waitForTimeout(150);
 const tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(t=>t.url===url).id,url);
 const context={owner:'browser-parity-'+kind,tabId,scope:{origins:[origin],excludePaths:[]},config:{scanStrategy:'COMPREHENSIVE',safetyProfile:'wide',maxRequestsPerSecond:20,concurrency:1,planningConcurrency:1,runCve:false,allowCaptureWithoutInteraction:true}};
 const start=await worker.evaluate(async({integrated,tabId,url,kind,context})=>{
  const pack=await(await fetch(chrome.runtime.getURL((integrated?'security/':'')+'ptk/background/dast/modules/modules.json'))).json();
  const module=pack.modules.find(m=>m.id===(kind==='angular'?'angularjs_client_template_injection':'spa_dom_xss'));
  if(kind==='angular')module.attacks=module.attacks.filter(a=>a.id==='angularjs_csti_reflected_1_0_1_to_1_1_5');
  context.config.rulepack={...pack,modules:[module]};
  if(integrated)return certXSecurity.runtime.invoke('startScan',{tabId,engines:['DAST'],options:context.config},context);
  return ptk_app.automation.msg_session_start({pageUrl:url,options:{engines:['DAST'],runCve:false,policyCode:'COMPREHENSIVE',engineConfigs:{DAST:context.config}}},{id:chrome.runtime.id,frameId:0,url,tab:{id:tabId,url}});
 },{integrated,tabId,url,kind,context});assert.ok(start.sessionId,JSON.stringify(start));
 await worker.evaluate(async({url,tabId})=>ptk_app.dast.engine.enqueue({raw:'GET '+url+' HTTP/1.1\r\nHost: '+new URL(url).host+'\r\n\r\n',ui_url:url,responseType:'main_frame',fingerprint:'explicit-browser-seed'},{url,tabId,method:'GET',type:'main_frame',statusCode:200,requestId:'seed',responseHeaders:[{name:'Content-Type',value:'text/html'}]}),{url,tabId});
 await page.getByRole('button',{name:'Exercise'}).click();
 await page.waitForTimeout(kind==='angular'?6500:4500);
 const result=await worker.evaluate(async({integrated,id,context})=>{
  const a=ptk_app.automation,s=a.sessions.get(id);
  const before=ptk_app.dast.engine.getProgressSnapshot();
  if(integrated)await certXSecurity.runtime.invoke('stopScan',{sessionId:id},context);else await a.msg_session_end({options:{sessionId:id,sessionScope:'current-tab'},wait:true},{id:chrome.runtime.id,frameId:0,url:s.pageUrl,tab:{id:s.tabId,url:s.pageUrl}});
  return {status:s.status,engines:s.engineStates,findings:a._collectFindings(s,100),before,scan:ptk_app.dast.scanResult};
 },{integrated,id:start.sessionId,context});
 fs.writeFileSync(path.join(os.tmpdir(),'cert-x-'+kind+'-'+(integrated?'owned':'reference')+'-'+safe+'.json'),JSON.stringify({result,logs},null,2));
 assert.equal(result.status,'completed',JSON.stringify({kind,integrated,safe,status:result.status,engines:result.engines,logs}));
 await browser.close();browser=null;return result;
}
async function main(){
 reference=resolveReference(process.env.PTK_REFERENCE_ROOT);
 server=http.createServer((req,res)=>{wire.push(req.url);const url=new URL(req.url,'http://fixture');if(url.pathname==='/angular-1.1.5.min.js'){res.setHeader('Content-Type','application/javascript');return res.end(fs.readFileSync(angularFile));}if(url.pathname==='/favicon.ico'){res.writeHead(204);return res.end();}res.setHeader('Content-Type','text/html');const safe=url.pathname.endsWith('-safe'),q=url.searchParams.get('q')||'hello';if(url.pathname.startsWith('/angular-'))return res.end('<!doctype html><html ng-app><head><script src="/angular-1.1.5.min.js"></script></head><body><button>Exercise</button><main '+(safe?'ng-non-bindable':'')+'>'+q+'</main></body></html>');res.end('<!doctype html><button>Exercise</button><main id="sink"></main><script>function render(){document.querySelector("#sink").'+(safe?'textContent':'innerHTML')+'=new URLSearchParams(location.hash.split("?")[1]||"").get("q")||"";}window.onhashchange=render;document.querySelector("button").onclick=render;render();</script>');});await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
 for(const kind of (process.env.DAST_BROWSER_KIND?[process.env.DAST_BROWSER_KIND]:['angular','spa']))for(const safe of [false,true]){
  const ref=await run(reference.extensionPath,false,origin,kind,safe),owned=await run(root,true,origin,kind,safe);
  const project=result=>result.findings.findings.map(f=>({moduleId:f.moduleId,ruleId:f.ruleId,severity:f.severity,confidence:f.confidence})).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  assert.deepEqual(project(owned),project(ref),'Native browser-confirmation parity');
  if(kind==='spa') {
    // PTK also reports harmless text reflection as a lower-confidence candidate.
    // Preserve that observation, but require execution evidence only on the vulnerable sink.
    for(const result of [ref,owned])assert.equal((result.scan.findings||[]).some(f=>f.evidence?.dast?.meta?.executed===true),!safe,'SPA execution positive/negative oracle');
    if(safe)assert.ok(owned.scan.findings.every(f=>f.evidence?.dast?.meta?.executed===false));
  } else assert.equal(owned.findings.findings.length>0,!safe,'Positive/negative browser-confirmed detection oracle '+kind);
  console.log(JSON.stringify({kind,safe,baseline:project(ref),owned:project(owned),parity:true}));
 }
}
main().catch(e=>{console.error(e);process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(r=>server.close(r));for(const dir of [temp,reference?.directory])if(dir&&path.resolve(dir).startsWith(path.resolve(os.tmpdir())+path.sep)&&/^cert-x-security-/.test(path.basename(dir)))fs.rmSync(dir,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

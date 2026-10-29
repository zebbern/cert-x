// Body-only detection on opaque resource URLs, isolated authenticated documents.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const {resolveReference}=require('../prepare-reference.cjs');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-sca-auth-')),file=path.join(root,'tools/security/evidence/sca-authenticated-browser.json');
const source=fs.readFileSync(path.join(__dirname,'fixtures/angular/angular-1.1.5.min.js'),'utf8'),wire=[],evidence={wire,fixture:'Real AngularJS 1.1.5 served behind HttpOnly session cookie at opaque bundle.js/fragment.js paths; B receives clean JavaScript.'};
let browser,server,reference,side='';const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function run(extension,integrated,origin){
 side=integrated?'owned':'reference';const cases=[];console.log('SCA auth',side,'launch');
 browser=await chromium.launchPersistentContext(path.join(temp,side),{headless:true,executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+extension,'--load-extension='+extension]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(async integrated=>{if(integrated)await certXSecurity.ready;else{await ptk_app.ready;ptk_app.devLocalConfig.automationEnabled=true;}},integrated);
 const page=await browser.newPage();
 for(const account of ['a','b','anonymous']){
  await browser.clearCookies();await page.goto(origin+(account==='anonymous'?'/app':'/login/'+account));
  const tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(tab=>tab.url===url).id,page.url());
  const context={owner:'sca-auth',tabId,scope:{origins:[origin],excludePaths:[]},config:{preset:'ptk-defaults'}};
  const started=await worker.evaluate(async({integrated,tabId,context})=>{const tab=await chrome.tabs.get(tabId);if(integrated)return certXSecurity.runtime.invoke('startScan',{tabId,engines:['SCA'],options:context.config},context);return ptk_app.automation.msg_session_start({pageUrl:tab.url,options:{engines:['SCA'],runCve:false,engineConfigs:{SCA:{}}}},{id:chrome.runtime.id,url:tab.url,frameId:0,tab});},{integrated,tabId,context});
  assert.ok(started.sessionId,JSON.stringify(started));const before=wire.length;
  await page.getByRole('button',{name:'Load assets'}).click();await page.waitForFunction(()=>globalThis.fixtureLoaded===true);await wait(2500);
  await worker.evaluate(async({integrated,sessionId,context})=>{if(integrated)return certXSecurity.runtime.invoke('stopScan',{sessionId},context);const tab=await chrome.tabs.get(context.tabId);return ptk_app.automation.msg_session_end({options:{sessionId,sessionScope:'current-tab'},wait:true},{id:chrome.runtime.id,url:tab.url,frameId:0,tab});},{integrated,sessionId:started.sessionId,context});
  const scan=await worker.evaluate(()=>JSON.parse(JSON.stringify(ptk_app.sca.scanResult)));const publicStatus=integrated?await worker.evaluate(({sessionId,context})=>certXSecurity.runtime.invoke('scanStatus',{sessionId},context),{sessionId:started.sessionId,context}):null;if(integrated)assert.equal(publicStatus.coverage.scaBodies.analyzed,scan.scaBodyCoverage?.analyzed||0);const bodies=wire.slice(before).filter(item=>/\/(bundle|fragment)\.js$/.test(item.url));
  cases.push({account,scan,publicStatus,bodyRequests:bodies});evidence[side]=cases;fs.writeFileSync(file,JSON.stringify(evidence,null,2));
  const bodyFindings=(scan.findings||[]).filter(f=>f.evidence?.sca?.component?.detection==='filecontent'&&f.evidence.sca.component.name==='angularjs');
  if(account==='a')assert.ok(bodyFindings.length>0,'Authenticated body must produce real content-signature detection');else assert.equal(bodyFindings.length,0,'Clean/anonymous document cannot borrow account A body');
  if(integrated){assert.equal(bodies.length,2,'No anonymous refetch after browser-loaded assets');assert.ok(bodies.every(item=>item.account===account));if(account!=='anonymous')assert.equal(scan.scaBodyCoverage.analyzed,2);else assert.ok(scan.scaBodyCoverage.gaps>=2);}
  console.log('SCA auth',side,account,JSON.stringify({bodyFindings:bodyFindings.length,coverage:scan.scaBodyCoverage,bodyRequests:bodies.length}));
 }
 await browser.close();browser=null;return cases;
}
async function main(){
 server=http.createServer((req,res)=>{const account=req.headers.cookie?.match(/fixture_account=(a|b)/)?.[1]||'anonymous';wire.push({side,url:req.url,account});res.setHeader('Cache-Control','no-store');
  if(req.url.startsWith('/login/')){res.writeHead(302,{'Set-Cookie':'fixture_account='+req.url.slice(-1)+'; HttpOnly; Path=/','Location':'/app'});return res.end();}
  if(req.url==='/favicon.ico'){res.writeHead(204);return res.end();}
  if(req.url==='/bundle.js'||req.url==='/fragment.js'){res.setHeader('Content-Type','application/javascript');if(account==='anonymous'){res.writeHead(401);return res.end('/* login required */');}return res.end(account==='a'?source:'globalThis.cleanAccountLibrary = true;');}
  res.setHeader('Content-Type','text/html');res.end('<!doctype html><button id="load">Load assets</button><script>load.onclick=async()=>{const script=document.createElement("script");script.src="/bundle.js";const loaded=new Promise(resolve=>{script.onload=resolve;script.onerror=resolve});document.head.append(script);await Promise.all([loaded,fetch("/fragment.js").then(r=>r.text())]);globalThis.fixtureLoaded=true;}</script>');
 });await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 await run(root,true,origin);
 if(process.env.SCA_OWNED_ONLY!=='1'){reference=resolveReference(process.env.PTK_REFERENCE_ROOT);evidence.referenceSha256=reference.sha256;await run(reference.extensionPath,false,origin);require('./sca-authenticated-verify.cjs').verify(evidence);}
 evidence.passed=true;fs.writeFileSync(file,JSON.stringify(evidence,null,2));console.log(JSON.stringify({file,owned:true,reference:!!reference,passed:true}));
}
main().catch(error=>{evidence.error=error.stack;fs.writeFileSync(file,JSON.stringify(evidence,null,2));console.error(error);process.exitCode=1}).finally(async()=>{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));for(const directory of [temp,reference?.directory])if(directory){assert.ok(path.resolve(directory).startsWith(path.resolve(os.tmpdir())+path.sep)&&/^cert-x-(sca-auth|security-reference)-/.test(path.basename(directory)));fs.rmSync(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});}});

const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-sast-combined-'));
const output=path.join(root,'tools/security/evidence/sast-preloaded-combined.json'),wire=[],cases=[];
let browser,server;
async function main(){
 server=http.createServer((req,res)=>{wire.push(req.url);res.setHeader('Cache-Control','no-store');
  if(req.url.startsWith('/login')){res.writeHead(302,{'Set-Cookie':'fixture_auth=yes; HttpOnly; Path=/','Location':'/exec'+(req.url.includes('?')?req.url.slice(req.url.indexOf('?')):'')});return res.end();}
  if(req.url==='/favicon.ico'){res.writeHead(204);return res.end();}
  if(!String(req.headers.cookie).includes('fixture_auth=yes')){res.writeHead(401);return res.end('login required');}
  if(req.url.startsWith('/asset.js')){res.setHeader('Content-Type','application/javascript');return res.end('function showInput(){ document.getElementById("sink").'+(req.url.includes('safe')?'textContent':'innerHTML')+' = location.hash; }');}
  if(req.url==='/missing.js'){req.socket.destroy();return;}
  res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Authenticated preloaded form</title><form method="post"><input name="ip" value="127.0.0.1"><button>Submit</button></form><div id="sink"></div><script src="/asset.js'+(req.url.includes('safe')?'?safe':'')+'"></script>'+(req.url.includes('missing')?'<script src="/missing.js"></script>':''));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin=`http://127.0.0.1:${server.address().port}`;
 browser=await chromium.launchPersistentContext(path.join(temp,'profile'),{headless:true,executablePath:process.env.CHROMIUM_PATH||path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(async()=>certXSecurity.ready);
 const page=await browser.newPage();
 for(const scenario of [{name:'preloaded-positive',engines:['SAST']},{name:'preloaded-safe',engines:['SAST','SCA'],query:'?safe'},{name:'missing-external',engines:['SAST','SCA'],query:'?missing',reload:true},{name:'limited-after-navigation',engines:['SAST'],reload:true,acquisition:{maxResourceBytes:32,maxTotalBytes:64}},{name:'combined-positive',engines:['DAST','SAST','SCA']}]){
  const {engines}=scenario;
  await page.goto(origin+'/login'+(scenario.query||''));await page.waitForLoadState('load');const before=wire.length;
  const tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(t=>t.url===url).id,page.url());
  const context={owner:'sast-combined',scope:{origins:[origin],excludePaths:[]}};
  const started=await worker.evaluate(({tabId,engines,context,acquisition})=>certXSecurity.handle('start',{tabId,engines,options:{runCve:false,...(acquisition?{acquisition}:{}),engineOptions:{DAST:{moduleIds:['headers']}}}},context),{tabId,engines,context,acquisition:scenario.acquisition});
  if(scenario.reload){await page.reload();await page.waitForLoadState('load');}
  const deadline=Date.now()+7000;let status;
  do{status=await worker.evaluate(({runId,context})=>certXSecurity.handle('status',{runId},context),{runId:started.runId,context});if(status.engineStatus?.SAST?.firstCollectionSettled)break;await new Promise(r=>setTimeout(r,100));}while(Date.now()<deadline);
  const stopped=await worker.evaluate(({runId,context})=>certXSecurity.handle('stop',{runId},context),{runId:started.runId,context});
  const native=await worker.evaluate(()=>({scan:JSON.parse(JSON.stringify(ptk_app.sast.scanResult)),progress:ptk_app.sast.sessionCoordinator.getAutomationState()}));
  cases.push({name:scenario.name,engines,status,stopped,native});
  const domXss=native.scan.findings.filter(f=>f.ruleId==='dom-xss-taint');
  if(scenario.name==='limited-after-navigation'){
   assert.equal(domXss.length,0);assert.ok(native.scan.sastSourceWarnings.some(item=>item.reason==='sast_acquisition_resource_limit'));assert.ok(native.scan.sastAnalysisAcquisition.bytes<=64);assert.equal(stopped.state,'incomplete');continue;
  }
  if(scenario.name==='preloaded-safe')assert.equal(domXss.length,0);
  else assert.ok(domXss.length,'Available vulnerable script must be analyzed: '+scenario.name);
  if(!scenario.reload)assert.equal(wire.slice(before).filter(url=>url.startsWith('/asset.js')).length,0,'Preloaded script must not be refetched');
  if(scenario.reload){assert.ok(native.scan.sastAcquisition.sourceGaps>0);assert.ok(native.scan.sastAcquisition.missingResources.length>0);}
  else assert.equal(native.scan.sastPreloadedCoverage.analyzedScripts,1);
 }
 fs.writeFileSync(output,JSON.stringify({cases,wire},null,2));
 console.log(JSON.stringify({output,cases:cases.map(c=>({engines:c.engines,state:c.stopped.state,sast:c.stopped.engineStatus?.SAST,findings:c.native.scan.findings?.length}))}));
}
main().catch(e=>{console.error(e);fs.writeFileSync(output,JSON.stringify({error:e.stack,cases,wire},null,2));process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(r=>{server.close(r);server.closeAllConnections();});const resolved=fs.realpathSync(temp);assert.ok(resolved.startsWith(fs.realpathSync(os.tmpdir())+path.sep)&&path.basename(resolved).startsWith('cert-x-sast-combined-'));fs.rmSync(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

// Isolated Chromium proof that Thorough discovers in-scope HTML links while
// PTK defaults retain their original no-discovery behavior.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-html-discovery-'));
let browser,server;const wire=[];
async function main(){
 server=http.createServer((req,res)=>{
  wire.push({method:req.method,url:req.url});res.setHeader('Content-Type','text/html');res.setHeader('Cache-Control','no-store');
  if(req.url==='/favicon.ico'){res.writeHead(204);return res.end();}
  if(req.url.startsWith('/target'))return res.end('<!doctype html><title>Target</title><p>Reached '+new URL(req.url,'http://fixture').searchParams.get('q')+'</p>');
  res.end('<!doctype html><title>Home</title><a href="/target?q=hello">Target route</a>');
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launchPersistentContext(path.join(temp,'profile'),{headless:true,executablePath:process.env.CHROMIUM_PATH||path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(()=>certXSecurity.ready);
 const pack=JSON.parse(fs.readFileSync(path.join(root,'security/ptk/background/dast/modules/modules.json'),'utf8'));
 pack.modules=pack.modules.filter(module=>['headers','xss'].includes(module.id)).map(module=>module.id==='xss'?{...module,attacks:module.attacks.slice(0,1)}:module);assert.equal(pack.modules.length,2);
 const page=await browser.newPage(),results=[];
 for(const preset of ['ptk-defaults','thorough']){
  await page.goto(origin+'/');const before=wire.length,tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(tab=>tab.url===url)?.id,page.url());assert.ok(Number.isInteger(tabId));
  const context={owner:'discovery-'+preset,scope:{origins:[origin],excludePaths:[]}};
  const start=await worker.evaluate(({tabId,context,pack,preset})=>certXSecurity.handle('start',{tabId,engines:['DAST'],options:{preset,allowCaptureWithoutInteraction:true,rulepack:pack,runCve:false,maxRequests:30,maxRequestsPerSecond:10,concurrency:1,planningConcurrency:1,durationSeconds:60}},context),{tabId,context,pack,preset});
  const deadline=Date.now()+25000;let status;
  do{status=await worker.evaluate(({runId,context})=>certXSecurity.handle('status',{runId},context),{runId:start.runId,context});if(status.engineStatus?.DAST?.idle&&status.coverage?.dast?.baselineDispatches>0&&(preset==='ptk-defaults'||status.coverage?.dast?.tasksExecuted>0))break;await new Promise(resolve=>setTimeout(resolve,200));}while(Date.now()<deadline);
  assert.ok(status.engineStatus?.DAST?.idle,'Bounded fixture scan did not become idle');
  const engine=await worker.evaluate(async()=>({type:ptk_app.dast.engine.constructor.name,scheduler:(await ptk_app.dast.engine.getPerformanceTelemetry()).scheduler,breadthFirst:ptk_app.dast.engine.settings.schedulerBreadthFirst,htmlLinks:ptk_app.dast.engine.settings.enableHtmlLinkDiscovery}));
  await worker.evaluate(({runId,context})=>certXSecurity.handle('stop',{runId},context),{runId:start.runId,context});
  const hits=wire.slice(before).filter(item=>item.url.startsWith('/target?q=hello'));
  results.push({preset,hits:hits.length,config:start.config,engine,executed:status.coverage?.dast?.tasksExecuted});
 }
 assert.equal(results[0].config.schedulerBreadthFirst,false);assert.equal(results[0].hits,0,'PTK defaults should not follow HTML links');
 assert.equal(results[1].config.schedulerBreadthFirst,true);assert.equal(results[1].config.enableHtmlLinkDiscovery,true);
 assert.ok(results[1].hits>0,'Thorough should request the linked in-scope route without agent navigation');
 assert.ok(results[1].engine.scheduler.breadthFirstDispatches>0,'Thorough should dispatch at least one breadth-first task: '+JSON.stringify({engine:results[1].engine,executed:results[1].executed,linkedRequests:results[1].hits}));
 console.log(JSON.stringify({origin,results:results.map(item=>({preset:item.preset,linkedRequests:item.hits,breadthFirstDispatches:item.engine.scheduler.breadthFirstDispatches}))}));
}
main().catch(error=>{console.error(error.stack);process.exitCode=1}).finally(async()=>{
 await browser?.close();if(server)await new Promise(resolve=>{server.close(resolve);server.closeAllConnections()});
 const resolved=fs.realpathSync(temp),rootTemp=fs.realpathSync(os.tmpdir())+path.sep;
 assert.ok(resolved.startsWith(rootTemp)&&path.basename(resolved).startsWith('cert-x-html-discovery-'));
 fs.rmSync(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:100});
});

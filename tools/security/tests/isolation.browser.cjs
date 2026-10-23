const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-security-isolation-'));let browser,server;
async function main(){
 server=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Isolation fixture</title><input id="value"><button id="render">Render</button><div id="sink"></div><script>document.querySelector("#render").onclick=()=>document.querySelector("#sink").innerHTML=new URLSearchParams(location.search).get("q");</script>');});await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launchPersistentContext(path.join(temp,'profile'),{headless:true,executablePath:process.env.CHROMIUM_PATH||path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(()=>globalThis.certXSecurity.ready);
 const first=await browser.newPage(),second=await browser.newPage();await first.goto(origin+'/first?q=first');await second.goto(origin+'/second?q=second');
 const tabs=await worker.evaluate(()=>chrome.tabs.query({})),a=tabs.find(t=>t.url?.includes('/first?')).id,b=tabs.find(t=>t.url?.includes('/second?')).id;
 const scope={origins:[origin],excludePaths:[]},contextA={owner:'owner-a',workspaceId:'workspace-a',scope},contextB={owner:'owner-b',workspaceId:'workspace-b',scope};
 const start=async(tabId,engines,context)=>worker.evaluate(({tabId,engines,context})=>globalThis.certXSecurity.handle('start',{tabId,engines,options:{preset:'ptk-defaults'}},context),{tabId,engines,context});
 const ra=await start(a,['SAST'],contextA),rb=await start(b,['IAST'],contextB);
 assert.equal(ra.state,'running');assert.equal(rb.state,'running');await first.reload();await second.reload();await second.getByRole('button',{name:'Render'}).click();
 await new Promise(r=>setTimeout(r,2000));
 const result=await worker.evaluate(async({ra,rb,contextA,contextB})=>{
  const service=globalThis.certXSecurity;await service.handle('stop',{runId:ra.runId},contextA);const b=await service.handle('status',{runId:rb.runId},contextB);
  let denied=false;try{await service.handle('findings',{runId:ra.runId},contextB);}catch{denied=true;}
  const aFindings=await service.handle('findings',{runId:ra.runId},contextA);await service.handle('stop',{runId:rb.runId},contextB);
  const bFindings=await service.handle('findings',{runId:rb.runId},contextB);return{bStateWhileAStopped:b.state,denied,aFindings,bFindings};
 },{ra,rb,contextA,contextB});
 assert.equal(result.bStateWhileAStopped,'running');assert.equal(result.denied,true);
 assert.ok(result.aFindings.total>0);assert.ok(result.aFindings.findings.every(f=>f.engine==='SAST'));assert.ok(result.bFindings.findings.every(f=>f.engine==='IAST'));
 assert.ok(!JSON.stringify(result.aFindings).includes('/second?'));assert.ok(!JSON.stringify(result.bFindings).includes('/first?'));
 console.log(JSON.stringify({independentEnginesAcrossWorkspaces:true,stopIsolation:true,crossOwnerBlocked:true,separateEvidence:true,a:result.aFindings.total,b:result.bFindings.total}));
}
main().catch(error=>{console.error(error);process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(r=>server.close(r));if(path.resolve(temp).startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(temp).startsWith('cert-x-security-isolation-'))fs.rmSync(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

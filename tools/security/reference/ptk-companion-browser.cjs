// Uses the actual prepared PTK v10 extension against an isolated local fixture.
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), http = require('node:http'), zlib = require('node:zlib'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const extension = process.env.PTK_EXTENSION || path.join(process.env.LOCALAPPDATA, 'cert-x/ptk/v10/src');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-ptk-real-'));
let browser, server; const pageErrors = [], consoleErrors = [];
async function main() {
  assert.equal(JSON.parse(fs.readFileSync(path.join(extension, 'manifest.json'), 'utf8')).version, '10.0.0');
  server = http.createServer((req,res) => {
    if (req.url.startsWith('/app.js')) {res.setHeader('Content-Type','application/javascript');res.end('const input = new URLSearchParams(location.search).get("q"); document.getElementById("sink").innerHTML = input || "fixture";');return;}
    if (req.url === '/favicon.ico') {res.writeHead(204);res.end();return;}
    res.setHeader('Content-Type','text/html');res.end('<!doctype html><html><head><title>cert-x PTK local fixture</title></head><body><h1>PTK integration fixture</h1><div id="sink"></div><script src="/app.js"></script></body></html>');
  });
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve)); const url='http://127.0.0.1:'+server.address().port+'/?q=fixture';
  const root = path.resolve(__dirname, '../../..'), downloads = path.join(temp,'downloads'), profile=path.join(temp,'profile');
  fs.mkdirSync(path.join(profile,'Default'),{recursive:true});fs.mkdirSync(downloads);
  fs.writeFileSync(path.join(profile,'Default/Preferences'),JSON.stringify({download:{default_directory:downloads,prompt_for_download:false}}));
  browser = await chromium.launchPersistentContext(profile, {headless:true,downloadsPath:downloads, executablePath:require('../../chromium-path.cjs'), args:['--disable-extensions-except='+root+','+extension,'--load-extension='+root+','+extension]});
  for(let i=0;i<200&&browser.serviceWorkers().length<2;i++)await new Promise(resolve=>setTimeout(resolve,50));
  const ptkWorker=browser.serviceWorkers().find(w=>new URL(w.url()).pathname==='/app.js'),certWorker=browser.serviceWorkers().find(w=>new URL(w.url()).pathname==='/background/background.js');
  assert.ok(ptkWorker&&certWorker,'Both real extensions must load');
  await ptkWorker.evaluate(async()=>{for(let i=0;i<200&&!self.ptk_app?.ready;i++)await new Promise(r=>setTimeout(r,50));if(!self.ptk_app?.ready)throw Error('PTK worker did not initialize');await self.ptk_app.ready;});
  const session='ptk-real-integration-chat',id=new URL(certWorker.url()).host;
  await certWorker.evaluate(()=>chrome.storage.local.set({sidepanel_language:'en',sidepanel_theme:'dark'}));
  const settings=await browser.newPage();settings.on('pageerror',e=>pageErrors.push(e.message));await settings.goto('chrome-extension://'+id+'/providers/providers.html?section=ptk&session='+session);
  await settings.waitForFunction(()=>!document.querySelector('main').inert);
  const call=async(op,args={})=>{const response=await settings.evaluate(message=>chrome.runtime.sendMessage(message),{type:'KI_PTK',op,session,...args});assert.equal(response?.ok,true,JSON.stringify(response));return response.result;};
  const assigned=await settings.evaluate(session=>chrome.runtime.sendMessage({type:'KI_CONTEXT',op:'assign_chat',session,profileId:'bugbounty',modelExplicit:null}),session);assert.equal(assigned.ok,true,JSON.stringify(assigned));
  const page=await browser.newPage();page.on('pageerror',e=>pageErrors.push(e.message));page.on('console',m=>{if(m.type()==='error')consoleErrors.push(m.text());});await page.goto(url);await page.bringToFront();await page.waitForFunction(()=>!!window.PTK_AUTOMATION);
  const tabs=await call('tabs');const target=tabs.find(t=>t.url===url);assert.ok(target);
  const checked=await call('check',{tabId:target.tabId});assert.equal(checked.version,'10.0.0');assert.equal(checked.ready,false);assert.ok(checked.blockers.includes('automation_disabled'));
  await certWorker.evaluate(async tabId=>{await chrome.debugger.attach({tabId},'1.3');await chrome.debugger.sendCommand({tabId},'Runtime.enable');},target.tabId);
  // Exercise actual settings controls; starting focuses the target for PTK's activation handshake.
  await settings.bringToFront();
  await settings.reload();await settings.waitForFunction(()=>!document.querySelector('main').inert);
  await settings.getByLabel('PTK tab').selectOption(String(target.tabId));
  await settings.getByRole('button',{name:'Check connection',exact:true}).click();
  await settings.getByText('PTK is available · activation needed',{exact:true}).waitFor();
  await settings.getByRole('button',{name:'Analyze app',exact:true}).click();
  let started;
  for(let i=0;i<100;i++){const state=await call('state');started=state.scans.find(scan=>scan.owner===session);if(started?.state==='running')break;if(started?.state==='unknown')throw Error(JSON.stringify(started));await new Promise(resolve=>setTimeout(resolve,100));}
  assert.equal(started?.state,'running',JSON.stringify(started));assert.deepEqual(started.engines,['SAST','SCA']);
  const browserAction=await certWorker.evaluate(tabId=>chrome.debugger.sendCommand({tabId},'Runtime.evaluate',{expression:'document.title',returnByValue:true}),target.tabId);assert.equal(browserAction.result.value,'cert-x PTK local fixture');
  await page.reload();await page.waitForFunction(()=>window.PTK_AGENT?.preflight().ready===true);
  await new Promise(resolve=>setTimeout(resolve,5000));
  const observed=await call('status',{scanId:started.scanId});assert.equal(observed.owner,session);
  await settings.bringToFront();await settings.getByRole('button',{name:'Stop',exact:true}).click();
  let final;
  for(let attempt=0;attempt<45;attempt++){final=await call('status',{scanId:started.scanId});if(['completed','error','unknown'].includes(final.state))break;await new Promise(resolve=>setTimeout(resolve,1000));}
  assert.equal(final.state,'completed',JSON.stringify(final));
  const findings=await call('findings',{scanId:started.scanId,limit:50});assert.ok(Array.isArray(findings.findings));
  const exported=await call('export',{scanId:started.scanId});assert.equal(exported.reports.length,2);
  const reports=[];
  for(const report of exported.reports){
    const item=(await certWorker.evaluate(id=>chrome.downloads.search({id}),report.downloadId))[0];assert.equal(item.state,'complete');
    const file=path.resolve(item.filename);assert.ok(file.startsWith(path.resolve(temp)+path.sep),'Fixture downloads must stay in temp: '+file);
    const bytes=fs.readFileSync(file);assert.equal(bytes.length,report.size);const data=JSON.parse(zlib.gunzipSync(bytes).toString('utf8'));assert.equal(data.engine,report.engine);
    reports.push({engine:report.engine,bytes:bytes.length,parsed:true});
  }
  const outputReply=await settings.evaluate(session=>chrome.runtime.sendMessage({type:'KI_WORKSPACE',op:'outputs',session}),session);assert.equal(outputReply.ok,true);assert.equal(outputReply.result.filter(item=>exported.reports.some(report=>report.downloadId===item.downloadId)&&item.owner===session).length,2);
  const other=await settings.evaluate(scanId=>chrome.runtime.sendMessage({type:'KI_PTK',op:'findings',session:'another-chat',scanId}),started.scanId);assert.equal(other.ok,false);
  await settings.getByRole('button',{name:'Findings',exact:true}).click();await settings.getByText('Scanner candidates · verify impact before reporting',{exact:true}).waitFor();await settings.screenshot({path:path.join(os.tmpdir(),'cert-x-ptk-real-findings.png'),fullPage:true});
  assert.deepEqual(pageErrors,[]);assert.deepEqual(consoleErrors,[]);
  await certWorker.evaluate(tabId=>chrome.debugger.detach({tabId}),target.tabId);
  console.log(JSON.stringify({actualPtkVersion:checked.version,adapter:true,manualUi:true,debuggerCoexistence:true,readinessBeforeActivation:checked.blockers,scan:started.scanId,state:final.state,findingsCount:findings.findings.length,truncated:findings.truncated,reports,outputOwnership:true,crossChatBlocked:true,pageErrors,consoleErrors}));
}
main().catch(error=>{console.error(error);console.error(JSON.stringify({pageErrors,consoleErrors}));process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));const absolute=path.resolve(temp);if(absolute.startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(absolute).startsWith('cert-x-ptk-real-'))fs.rmSync(absolute,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

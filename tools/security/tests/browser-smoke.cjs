// Real single-extension startup and native operation checks, isolated from user Chrome.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-security-smoke-'));
let browser, server;
async function main() {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://fixture');
    if (url.pathname === '/app.js') { res.setHeader('Content-Type', 'application/javascript'); return res.end('document.getElementById("sink").innerHTML = new URLSearchParams(location.search).get("q") || "fixture";'); }
    if (url.pathname === '/echo') { res.setHeader('Content-Type','application/json'); return res.end(JSON.stringify({query:Object.fromEntries(url.searchParams)})); }
    res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>Security fixture</title><h1>Native security fixture</h1><div id="sink"></div><script src="/app.js"></script>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const downloads=path.join(temp,'downloads'),profile=path.join(temp,'profile');fs.mkdirSync(downloads);fs.mkdirSync(path.join(profile,'Default'),{recursive:true});fs.writeFileSync(path.join(profile,'Default/Preferences'),JSON.stringify({download:{default_directory:downloads,prompt_for_download:false}}));
  browser = await chromium.launchPersistentContext(profile, { headless: true, downloadsPath:downloads, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker', { timeout: 15000 });
  const logs=[];worker.on('console',message=>{logs.push(message.text()); if(message.type()==='error')console.error('WORKER:',message.text());});
  const boot = await worker.evaluate(async () => { await globalThis.certXSecurity?.ready; await globalThis.certXSecurityCompatibilityReady; return { service: !!globalThis.certXSecurity, runtime: !!globalThis.ptk_app, url: location.href }; });
  assert.ok(boot.service && boot.runtime, JSON.stringify({boot,logs}));
  const id = new URL(worker.url()).host, session = 'security-native-smoke';
  const settings = await browser.newPage(), pageErrors=[];
  settings.on('pageerror', error => pageErrors.push(error.message));
  await settings.goto('chrome-extension://' + id + '/providers/providers.html?section=security&session=' + session);
  await settings.waitForFunction(() => !document.querySelector('main').inert);
  const call = async (op,args={}) => {
    const result = await settings.evaluate(message=>chrome.runtime.sendMessage(message),{type:'KI_SECURITY',op,session,...args});
    assert.equal(result?.ok,true,JSON.stringify(result));return result.result;
  };
  const assigned = await settings.evaluate(session=>chrome.runtime.sendMessage({type:'KI_CONTEXT',op:'assign_chat',session,profileId:'bugbounty',modelExplicit:null}),session);
  assert.equal(assigned.ok,true,JSON.stringify(assigned));
  const target = await browser.newPage(); await target.goto(origin + '/?q=baseline');
  const tabs = await worker.evaluate(()=>chrome.tabs.query({})), tabId=tabs.find(tab=>tab.url?.includes('/?q=baseline')).id;
  await worker.evaluate(async tabId=>{await globalThis.certXBrowserChrome.debugger.attach({tabId},'1.3');await globalThis.certXBrowserChrome.debugger.sendCommand({tabId},'Runtime.enable');await globalThis.certXBrowserChrome.debugger.sendCommand({tabId},'Network.enable');},tabId);
  const capabilities = await call('capabilities');
  console.log('CAPABILITIES',JSON.stringify(capabilities).slice(0,1200));
  const decoded = await call('execute',{capability:'utility',arguments:{tool:'decode',method:'base64',text:'Y2VydC14'},tabId});
  console.log('UTILITY',JSON.stringify(decoded));
  const combined=process.env.SECURITY_SMOKE_ENGINES==='all',engines=combined?['DAST','IAST','SAST','SCA']:['SAST','SCA'];
  const started=await call('start',{tabId,engines,scope:{origins:[origin],excludePaths:[]},options:combined?{preset:'thorough',moduleIds:['xss'],runCve:false}:{preset:'ptk-defaults'}});
  console.log('START',JSON.stringify(started));
  assert.ok(started.runId,'Run ID returned');
  await target.reload();
  await new Promise(resolve=>setTimeout(resolve,3000));
  console.log('STATUS',JSON.stringify(await call('status',{runId:started.runId})).slice(0,2500));
  const stopped=await call('stop',{runId:started.runId});console.log('STOP',JSON.stringify(stopped).slice(0,1500));
  assert.ok(['completed','cancelled'].includes(stopped.state),'Combined stop must reach a confirmed terminal state');
  const afterStop=await worker.evaluate(tabId=>globalThis.certXBrowserChrome.debugger.sendCommand({tabId},'Runtime.evaluate',{expression:'document.title',returnByValue:true}),tabId);
  assert.equal(afterStop.result.value,'Security fixture','Stopping capture preserves the agent debugger attachment');
  await worker.evaluate(tabId=>globalThis.certXBrowserChrome.debugger.detach({tabId}),tabId);
  const findings=await call('findings',{runId:started.runId});console.log('FINDINGS',JSON.stringify(findings).slice(0,2500));
  assert.ok(findings.total>0,'Real SAST findings were collected');
  const evidence=await call('evidence',{runId:started.runId,evidenceId:findings.findings[0].id});
  assert.ok(evidence.finding?.location||evidence.native,'Evidence includes native location/proof');
  const exported=await call('export',{runId:started.runId});assert.ok(exported.reports.length);
  const saved=(await worker.evaluate(id=>chrome.downloads.search({id}),exported.reports[0].downloadId))[0];assert.equal(saved.state,'complete');
  assert.ok(path.resolve(saved.filename).startsWith(path.resolve(temp)+path.sep));const report=JSON.parse(fs.readFileSync(saved.filename,'utf8'));assert.equal(report.run.runId,started.runId);assert.ok(report.native.reports.some(item=>item.engine==='SAST'));
  if(combined)assert.deepEqual(report.native.reports.map(item=>item.engine).sort(),engines.slice().sort(),'All four engines retain an export in the combined workflow');
  const outputs=await settings.evaluate(session=>chrome.runtime.sendMessage({type:'KI_WORKSPACE',op:'outputs',session}),session);assert.equal(outputs.ok,true);assert.ok(outputs.result.some(item=>item.downloadId===saved.id&&item.owner===session));
  const foreign=await settings.evaluate(message=>chrome.runtime.sendMessage(message),{type:'KI_SECURITY',op:'evidence',session:'foreign-chat',runId:started.runId});assert.equal(foreign.ok,false);
  assert.deepEqual(pageErrors,[]);
  await settings.setViewportSize({width:420,height:900});await settings.screenshot({path:path.join(os.tmpdir(),'cert-x-native-security-smoke.png'),fullPage:true});
  console.log(JSON.stringify({singleExtension:true,engines,boot,tabId,runId:started.runId,nativeEvidence:true,exportParsed:true,outputOwnership:true,crossChatBlocked:true,pageErrors}));
}
main().catch(error=>{console.error(error);process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));const absolute=path.resolve(temp);if(absolute.startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(absolute).startsWith('cert-x-security-smoke-'))fs.rmSync(absolute,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

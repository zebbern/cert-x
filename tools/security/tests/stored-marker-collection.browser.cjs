// Inert stored-marker retrieval and negative confirmation only. This does not
// execute an XSS payload or establish positive stored-XSS confirmation parity.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const {resolveReference}=require('../prepare-reference.cjs');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-stored-marker-')),evidenceDir=path.join(root,'tools/security/evidence');fs.mkdirSync(evidenceDir,{recursive:true});const evidenceFile=path.join(evidenceDir,'stored-marker-collection.json');
let server,browser,reference,stored='',side='';const wire=[],evidence={scope:'Inert stored marker: real submission, retrieval and browser confirmation negative. Positive execution remains unverified.',wire};
async function run(extension,integrated,origin){
 side=integrated?'owned':'reference';stored='';console.log('STORED-MARKER',side);
 browser=await chromium.launchPersistentContext(path.join(temp,side),{headless:true,executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+extension,'--load-extension='+extension]});const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');
 const page=await browser.newPage();await page.goto('chrome-extension://'+new URL(worker.url()).host+'/manifest.json');
 const result=await page.evaluate(async({integrated,origin})=>{
  const prefix=integrated?'security/ptk/':'ptk/',load=file=>import(chrome.runtime.getURL(prefix+file));await load('packages/browser-polyfill/browser-polyfill.min.js');
  const [{dastEngine},{ptk_request},{DastPrivilegedBrowserAdapter}]=await Promise.all([load('background/dast/dastEngine.js'),load('background/rbuilder.js'),load('background/dast/runtime/privilegedBrowserAdapter.js')]);
  const adapter=new DastPrivilegedBrowserAdapter({browserApi:globalThis.browser}),ownerId='inert-stored-fixture';
  const browserOperations={remote:true,call:(method,args)=>adapter.execute({type:'browser_call',ownerId,method,args}),sendRuntimeMessage:message=>chrome.runtime.sendMessage(message)};
  const engine=new dastEngine({scanStrategy:'SMART',maxRequestsPerSecond:5,concurrency:1,planningConcurrency:1,rulepack:{modules:[]},cveRulepack:{modules:[]},runCve:false},{browserOperations});await engine._moduleLoadPromise;engine.host=new URL(origin).host;engine.domains=[];
  const marker='CERTX_STORED_INERT_MARKER',body='comment='+encodeURIComponent('<b>'+marker+'</b>');
  const request=ptk_request.parseRawRequest('POST '+origin+'/submit HTTP/1.1\r\nHost: '+new URL(origin).host+'\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: '+new TextEncoder().encode(body).length+'\r\n\r\n'+body,{follow_redirect:false});
  const executed=await engine.activeAttack(request);
  const task={id:'inert-stored-marker',moduleId:'stored_xss_blind',module:{id:'stored_xss_blind',runtime:{mode:'standard'}},attack:{id:'inert-storage-observation',action:{params:[{value:'<b>'+marker+'</b>'}]},runtime:{confirmation:{tracking:{enabled:true,mode:'followup_get',marker,confidence:90}}}},payload:{metadata:{attacked:{location:'form',name:'comment'}}}};
  const result=await engine._runTracking(task,executed,{original:request});
  await engine._unregisterBrowserNavHarnessScript();await adapter.cleanup(ownerId);
  return {result,executed,events:engine.scanResult?.runtimeEvents||engine.runtimeEvents||[],stats:engine.scanStats};
 },{integrated,origin});
 const relevant=wire.filter(item=>item.side===side);assert.equal(relevant.filter(r=>r.method==='POST').length,1,'Tracker must not repeat the state-changing submission');assert.ok(relevant.some(r=>r.path==='/view'&&r.method==='GET'),'Stored marker was not retrieved');assert.equal(result.result,null,'Inert stored HTML must not be confirmed as script execution');
 await browser.close();browser=null;return {raw:result,wire:relevant.map(({side,...entry})=>entry)};
}
async function main(){
 reference=resolveReference(process.env.PTK_REFERENCE_ROOT);evidence.referenceSha256=reference.sha256;
 server=http.createServer(async(req,res)=>{const chunks=[];for await(const chunk of req)chunks.push(chunk);const body=Buffer.concat(chunks).toString();wire.push({side,path:req.url,method:req.method,body});res.setHeader('Content-Type','text/html');if(req.method==='POST'&&req.url==='/submit'){stored=new URLSearchParams(body).get('comment')||'';res.statusCode=302;res.setHeader('Location','/view');return res.end('stored');}if(req.url==='/view')return res.end('<!doctype html><title>Stored inert fixture</title>'+stored);res.end('<!doctype html><title>Submission endpoint</title>');});await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
 evidence.reference=await run(reference.extensionPath,false,origin);evidence.owned=await run(root,true,origin);
 fs.writeFileSync(evidenceFile,JSON.stringify(evidence,null,2));assert.deepEqual(evidence.owned.wire,evidence.reference.wire,'Stored-marker submission/retrieval/navigation wire differs');
 const harnessFailures=[...evidence.reference.raw.events,...evidence.owned.raw.events].filter(event=>event.error||event.reason==='ping_failed');
 evidence.summary={realSubmissionOncePerRuntime:true,realRetrieval:true,inertMarkerUnconfirmed:true,browserConfirmation:harnessFailures.length?'unverified: browser-operation adapter unavailable':'negative observed',harnessFailures,positiveStoredExecution:'unverified'};fs.writeFileSync(evidenceFile,JSON.stringify(evidence,null,2));console.log(JSON.stringify({evidenceFile,...evidence.summary}));
 assert.equal(harnessFailures.length,0,'Retrieval completed, but missing browser-operation adapter prevents a browser-confirmation result.');
}
main().catch(error=>{evidence.error=error.stack||error.message;fs.writeFileSync(evidenceFile,JSON.stringify(evidence,null,2));console.error(error);process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(r=>server.close(r));for(const folder of [temp,reference?.directory])if(folder&&path.resolve(folder).startsWith(path.resolve(os.tmpdir())+path.sep)&&/^cert-x-(?:stored-marker|security-reference)-/.test(path.basename(folder)))fs.rmSync(folder,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

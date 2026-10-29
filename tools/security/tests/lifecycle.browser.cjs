const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict'),http=require('node:http');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-security-lifecycle-'));
let context,server,activeProbes=0;
async function main(){
 server=http.createServer((req,res)=>{if(req.headers['x-ptk-source']==='dast')activeProbes++;res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Lifecycle fixture</title><div id="sink"></div><script>document.querySelector("#sink").innerHTML=new URLSearchParams(location.search).get("q")||"fixture";</script>');});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
 context=await chromium.launchPersistentContext(path.join(temp,'profile'),{headless:true,executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');await worker.evaluate(()=>globalThis.certXSecurity.ready);
 const id=new URL(worker.url()).host,session='lifecycle-chat',settings=await context.newPage();
 await settings.goto('chrome-extension://'+id+'/providers/providers.html?section=security&session='+session);
 const request=async(op,args={})=>{const v=await settings.evaluate(m=>chrome.runtime.sendMessage(m),{type:'KI_SECURITY',op,session,...args});assert.equal(v?.ok,true,JSON.stringify(v));return v.result;};
 // Worker restarts race state hydration: poll for the exact expected runs
 // instead of asserting on the first read after reload (the old flake).
 const waitFor=async(pred,desc)=>{for(let i=0;i<80;i++){try{const s=await request('state');if(pred(s))return s;}catch{}await new Promise(r=>setTimeout(r,500));}throw Error('Timed out waiting for '+desc);};
 await settings.evaluate(session=>chrome.runtime.sendMessage({type:'KI_CONTEXT',op:'assign_chat',session,profileId:'bugbounty',modelExplicit:null}),session);
 const page=await context.newPage();await page.goto(origin+'/?q=one');
 const tabId=(await request('tabs')).find(tab=>tab.url.startsWith(origin)).tabId;
 const run=await request('start',{tabId,engines:['SAST'],options:{preset:'ptk-defaults'}});
 await page.reload();await new Promise(r=>setTimeout(r,2500));await request('status',{runId:run.runId});
 const before=await request('findings',{runId:run.runId});assert.ok(before.total>0,'Positive evidence before restart');
 await request('stop',{runId:run.runId});
 const active=await request('start',{tabId,engines:['SAST'],options:{preset:'ptk-defaults'}});
 await page.reload();await new Promise(r=>setTimeout(r,1500));await request('status',{runId:active.runId});
 const cdp=await context.newCDPSession(settings),versions=new Map();
 cdp.on('ServiceWorker.workerVersionUpdated',event=>{for(const v of event.versions)versions.set(v.versionId,v);});
 await cdp.send('ServiceWorker.enable');
 for(let i=0;i<200&&![...versions.values()].some(v=>v.scriptURL===worker.url());i++)await new Promise(r=>setTimeout(r,50));
 const version=[...versions.values()].find(v=>v.scriptURL===worker.url());assert.ok(version,'Browser exposes the installed worker version');
 await cdp.send('ServiceWorker.stopWorker',{versionId:version.versionId});
 await settings.reload();
 const state=await waitFor(s=>{const c=s.runs.find(r=>r.runId===run.runId),a=s.runs.find(r=>r.runId===active.runId);return c&&a&&c.state==='completed'&&a.state==='interrupted';},'completed+interrupted runs after restart'),completed=state.runs.find(r=>r.runId===run.runId),interrupted=state.runs.find(r=>r.runId===active.runId);
 assert.equal(completed.state,'completed');assert.equal(interrupted.state,'interrupted');
 const after=await request('findings',{runId:run.runId});assert.deepEqual(after.findings,before.findings,'Completed evidence persists exactly across worker restart');
 // No stale active run is silently replayed. A fresh start must acquire resources successfully.
 const fresh=await request('start',{tabId,engines:['SAST'],options:{preset:'ptk-defaults'}});assert.equal(fresh.state,'running');await request('stop',{runId:fresh.runId});
 const other=await settings.evaluate(m=>chrome.runtime.sendMessage(m),{type:'KI_SECURITY',op:'findings',session:'unrelated-chat',runId:run.runId});assert.equal(other.ok,false);
 const activeDast=await request('start',{tabId,engines:['DAST'],options:{moduleIds:['xss'],runCve:false,allowCaptureWithoutInteraction:true,maxRequestsPerSecond:2}});await page.reload();
 for(let i=0;i<300&&activeProbes===0;i++)await new Promise(r=>setTimeout(r,100));assert.ok(activeProbes>0,'DAST sent actual probes before restart');
 // The fixture counts the planner's baseline replay as a probe before the executor has saved
 // any request record (observed under load: requests:0 recovered). A dispatched task means
 // its plan was enqueued, and the record is saved at enqueue, so wait for that first.
 const dispatched=async()=>(await request('status',{runId:activeDast.runId})).engineStatus?.DAST?.progress?.done>0;
 for(let i=0;i<300&&!await dispatched();i++)await new Promise(r=>setTimeout(r,100));assert.ok(await dispatched(),'DAST dispatched a planned task before restart');
 const current=[...versions.values()].find(v=>v.scriptURL.endsWith('/background/entry.js')&&v.runningStatus==='running');assert.ok(current);
 await cdp.send('ServiceWorker.stopWorker',{versionId:current.versionId});await settings.reload();
 const restarted=await waitFor(s=>{const d=s.runs.find(r=>r.runId===activeDast.runId);return d&&d.state==='interrupted'&&d.recoveredEvidence===true;},'recovered DAST evidence after executor release'),interruptedDast=restarted.runs.find(r=>r.runId===activeDast.runId);assert.equal(interruptedDast.state,'interrupted');assert.equal(interruptedDast.recoveredEvidence,true,'Surviving executor evidence is retained');
 const recovered=await request('evidence',{runId:activeDast.runId});assert.equal(recovered.native.sessionId,activeDast.runtimeId,'Recovery binds to the original automation session');
 const nativeDast=recovered.native.engines.find(engine=>engine.engine==='DAST');assert.ok(nativeDast?.scanId);assert.equal(nativeDast.scan.scanId,nativeDast.scanId);assert.ok(nativeDast.scan.requests?.length>0,'Actual pre-interruption requests survive executor release');assert.equal(nativeDast.scan.interrupted,true);
 const settled=activeProbes;await new Promise(r=>setTimeout(r,1200));assert.equal(activeProbes,settled,'Interrupted DAST cannot continue sending probes');
 const nextDast=await request('start',{tabId,engines:['DAST'],options:{moduleIds:['xss'],runCve:false,allowCaptureWithoutInteraction:true}});assert.equal(nextDast.state,'running');await request('stop',{runId:nextDast.runId});
 console.log(JSON.stringify({workerRestart:true,completedEvidencePreserved:after.total,activeRunInterrupted:true,freshStart:true,dastInterruptedWithoutReplay:true,freshDastStart:true,crossChatBlocked:true}));
}
main().catch(error=>{console.error(error);process.exitCode=1;}).finally(async()=>{await context?.close();if(server)await new Promise(r=>server.close(r));if(path.resolve(temp).startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(temp).startsWith('cert-x-security-lifecycle-'))fs.rmSync(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});});


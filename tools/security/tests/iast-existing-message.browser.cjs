// Existing-document first-event acquisition. Application bubble listeners are
// installed before scanning; markers are inert and never execute script.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');const {resolveReference}=require('../prepare-reference.cjs');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-existing-message-')),dir=path.join(root,'tools/security/evidence');fs.mkdirSync(dir,{recursive:true});const diagnostic=process.env.EXISTING_MESSAGE_DIAGNOSTIC==='1',file=path.join(dir,diagnostic?'iast-existing-message-diagnostic.json':'iast-existing-message.json');
const markers={html:'<b>CERTX_MSG_FIRST</b>',safe:'<b>CERTX_MSG_SAFE</b>'},evidence={schema:1,scope:'Inert first-message acquisition in existing documents, no reload, application callback count and safe textContent.'};let browser,server,reference;const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const applicationScript=`
window.fixtureDocumentId=crypto.randomUUID();
window.fixtureAgentAtListenerInstall=globalThis.__PTK_IAST_AGENT_LOADED__===true;
window.fixtureNativeDescriptor=Object.getOwnPropertyDescriptor(MessageEvent.prototype,'data');
window.fixtureNativeDataGetter=fixtureNativeDescriptor.get;
window.fixtureIdentities=[];window.fixtureObjectCalls=0;
window.fixtureCalls={html:0,safe:0};window.fixtureOrder=[];
${diagnostic?'window.addEventListener("message",event=>{if(event.data==="CERTX_ORDER_ONLY")fixtureOrder.push("bubble-existing");});':''}
window.addEventListener('message',event=>{
 if(event.source!==window)return;
 const value=event.data;
 if(value&&typeof value==='object'&&value.fixtureIdentity==='CERTX_IDENTITY_OBJECT'){
  fixtureObjectCalls++;fixtureIdentities.push({kind:'object',same:value===fixtureNativeDataGetter.call(event),repeatedSame:value===event.data});return;
 }
 if(typeof value!=='string'||!value.includes('CERTX_MSG_'))return;
 fixtureIdentities.push({kind:'string',same:value===fixtureNativeDataGetter.call(event),repeatedSame:value===event.data});
 if(value.includes('SAFE')){fixtureCalls.safe++;document.querySelector('#safe').textContent=value;}
 else{fixtureCalls.html++;document.querySelector('#html').innerHTML=value;}
});
document.querySelector('#send-html').onclick=()=>window.postMessage(${JSON.stringify(markers.html)},location.origin);
document.querySelector('#send-text').onclick=()=>window.postMessage(${JSON.stringify(markers.safe)},location.origin);
`;
function matched(findings,value){return findings.filter(f=>{const e=f.evidence?.iast||{};return String(e.context?.valuePreview||'').includes(value)||(e.sources||[]).some(s=>String(s.raw||s.value||'').includes(value))||(e.samples||[]).some(s=>String(s.matched||'').includes(value));}).map(f=>({ruleId:f.ruleId,sinkId:f.evidence?.iast?.sinkId,sourceKind:f.evidence?.iast?.sourceKind,location:f.location?.url}));}
async function run(extension,integrated,origin){
 const side=integrated?'owned':'reference';console.log('EXISTING-MESSAGE',side);browser=await chromium.launchPersistentContext(path.join(temp,side),{headless:true,executablePath:process.env.CHROMIUM_PATH||path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),args:['--disable-extensions-except='+extension,'--load-extension='+extension]});const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');
 await worker.evaluate(async integrated=>{if(integrated)await certXSecurity.ready;else{for(let i=0;i<200&&!globalThis.ptk_app;i++)await new Promise(r=>setTimeout(r,25));await ptk_app.ready;ptk_app.devLocalConfig.automationEnabled=true;}},integrated);
 const page=await browser.newPage();await page.goto(origin+'/app');const before=await page.evaluate(()=>({documentId:fixtureDocumentId,agentAtListenerInstall:fixtureAgentAtListenerInstall,calls:fixtureCalls}));assert.equal(before.agentAtListenerInstall,false,'Application listener must predate the scan agent');
 const tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(t=>t.url===url).id,page.url()),context={owner:'existing-message',tabId,scope:{origins:[origin],excludePaths:[]},config:{preset:'ptk-defaults',scanStrategy:'SMART',runCve:false}};
 const started=await worker.evaluate(async({integrated,context})=>{if(integrated)return certXSecurity.runtime.invoke('startScan',{tabId:context.tabId,engines:['IAST'],options:context.config},context);const tab=await chrome.tabs.get(context.tabId);return ptk_app.automation.msg_session_start({pageUrl:tab.url,options:{engines:['IAST'],policyCode:'SMART',runCve:false}},{id:chrome.runtime.id,url:tab.url,frameId:0,tab});},{integrated,context});assert.ok(started.sessionId,JSON.stringify(started));
 await page.waitForFunction(()=>globalThis.__PTK_IAST_AGENT_LOADED__===true&&globalThis.__PTK_IAST_AGENT_AUTHORIZED__===true&&globalThis.__PTK_IAST_DEBUG_STATE__?.().activeRuleIds?.length>0,{},{timeout:10000});await sleep(1200);
 const debug=()=>page.evaluate(()=>({authorized:globalThis.__PTK_IAST_AGENT_AUTHORIZED__??null,provisional:globalThis.__PTK_IAST_PROVISIONAL_HOOKS__??null,loaded:globalThis.__PTK_IAST_AGENT_LOADED__??null,propagation:globalThis.__PTK_IAST_PROPAGATION_ENABLED__??null,state:typeof globalThis.__PTK_IAST_DEBUG_STATE__==='function'?globalThis.__PTK_IAST_DEBUG_STATE__():null}));
 const diagnostics=diagnostic?{beforeFirst:await debug()}:null;
 await page.getByRole('button',{name:'Send HTML marker'}).click();await page.waitForFunction(()=>fixtureCalls.html===1);await sleep(1500);
 const first=await worker.evaluate(()=>JSON.parse(JSON.stringify(ptk_app.iast.scanResult)));let repeated;
 if(diagnostic){diagnostics.afterFirst=await debug();await page.getByRole('button',{name:'Send HTML marker'}).click();await page.waitForFunction(()=>fixtureCalls.html===2);await sleep(1200);diagnostics.afterRepeated=await debug();repeated=await worker.evaluate(()=>JSON.parse(JSON.stringify(ptk_app.iast.scanResult)));}
 await page.getByRole('button',{name:'Send text marker'}).click();await page.waitForFunction(()=>fixtureCalls.safe===1);await sleep(1200);
 await page.evaluate(()=>window.postMessage({fixtureIdentity:'CERTX_IDENTITY_OBJECT',nested:{text:'inert object fixture'}},location.origin));await page.waitForFunction(()=>fixtureObjectCalls===1);
 const getterContract=await page.evaluate(()=>{
  const descriptor=Object.getOwnPropertyDescriptor(MessageEvent.prototype,'data'),current=descriptor.get,original=fixtureNativeDataGetter;
  const error=(getter,receiver)=>{try{getter.call(receiver);return null;}catch(error){return error.name;}};
  const values=['native string',{fixture:'object'}].map(data=>{const event=new MessageEvent('message',{data});return {kind:typeof data,same:current.call(event)===original.call(event),repeatedSame:current.call(event)===current.call(event)};});
  return {values,identities:fixtureIdentities.slice(),objectCalls:fixtureObjectCalls,descriptorPreserved:descriptor.enumerable===fixtureNativeDescriptor.enumerable&&descriptor.configurable===fixtureNativeDescriptor.configurable,receivers:[{},new Event('message'),Object.create(MessageEvent.prototype)].map(value=>({original:error(original,value),current:error(current,value)}))};
 });
 if(diagnostic){await page.evaluate(()=>{window.addEventListener('message',event=>{if(event.data==='CERTX_ORDER_ONLY')fixtureOrder.push('capture-late');},{capture:true});window.postMessage('CERTX_ORDER_ONLY',location.origin);});await page.waitForFunction(()=>fixtureOrder.length===2);diagnostics.nativeListenerOrder=await page.evaluate(()=>fixtureOrder.slice());}
 const after=await page.evaluate(()=>({documentId:fixtureDocumentId,agentLoaded:globalThis.__PTK_IAST_AGENT_LOADED__===true,calls:fixtureCalls,html:document.querySelector('#html').innerHTML,safe:document.querySelector('#safe').innerHTML}));
 await worker.evaluate(async({integrated,sessionId,context})=>{if(integrated)return certXSecurity.runtime.invoke('stopScan',{sessionId},context);const tab=await chrome.tabs.get(context.tabId);return ptk_app.automation.msg_session_end({options:{sessionId,sessionScope:'current-tab'},wait:true},{id:chrome.runtime.id,url:tab.url,frameId:0,tab});},{integrated,sessionId:started.sessionId,context});
 const final=await worker.evaluate(()=>JSON.parse(JSON.stringify(ptk_app.iast.scanResult)));
 await page.evaluate(()=>window.postMessage('<b>CERTX_MSG_AFTER_STOP</b>',location.origin));await page.waitForFunction(expected=>fixtureCalls.html===expected,diagnostic?3:2);await sleep(1000);
 const postStop=await worker.evaluate(()=>JSON.parse(JSON.stringify(ptk_app.iast.scanResult))),result={before,after,first,final,postStop,getterContract,diagnostics,...(repeated?{repeated,repeatedObservations:matched(repeated.findings||[],markers.html)}:{}),firstObservations:matched(first.findings||[],markers.html),safeObservations:matched(final.findings||[],markers.safe)};evidence[side]=result;fs.writeFileSync(file,JSON.stringify(evidence,null,2));
 assert.ok(getterContract.descriptorPreserved);assert.equal(getterContract.objectCalls,1);for(const item of [...getterContract.values,...getterContract.identities])assert.ok(item.same&&item.repeatedSame,'Native getter must return identical values and object identities');for(const item of getterContract.receivers){assert.equal(item.original,'TypeError');assert.equal(item.current,item.original,'Native receiver validation must remain intact');}assert.deepEqual(postStop.findings,final.findings,'Messages after stop must not add evidence');
 assert.equal(after.documentId,before.documentId,'Scan must not reload the pre-existing application');assert.deepEqual(after.calls,{html:diagnostic?2:1,safe:1},'Instrumentation must not duplicate or suppress application callbacks');assert.equal(result.safeObservations.length,0,'Safe textContent must not emit a marker finding');await browser.close();browser=null;return result;
}
async function main(){reference=resolveReference(process.env.PTK_REFERENCE_ROOT);evidence.referenceSha256=reference.sha256;server=http.createServer((_req,res)=>{res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Existing message listener</title><button id="send-html">Send HTML marker</button><button id="send-text">Send text marker</button><div id="html"></div><div id="safe"></div><script>'+applicationScript+'</script>');});await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
 const original=await run(reference.extensionPath,false,origin),owned=await run(root,true,origin);evidence.summary={originalFirst:original.firstObservations.length,ownedFirst:owned.firstObservations.length,originalSafe:original.safeObservations.length,ownedSafe:owned.safeObservations.length,callbacksUnchanged:true,noReload:true};fs.writeFileSync(file,JSON.stringify(evidence,null,2));console.log(JSON.stringify({file,...evidence.summary}));
 assert.equal(original.firstObservations.length,0,'Characterize original pre-existing bubble-listener timing');assert.ok(owned.firstObservations.some(f=>f.sourceKind==='postMessage'&&f.sinkId==='dom.innerHTML'),'Owned existing-document instrumentation must acquire the first message before the application sink');
}
main().catch(error=>{evidence.error=error.stack||error.message;fs.writeFileSync(file,JSON.stringify(evidence,null,2));console.error(error);process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(r=>server.close(r));for(const folder of [temp,reference?.directory])if(folder&&path.resolve(folder).startsWith(path.resolve(os.tmpdir())+path.sep)&&/^cert-x-(?:existing-message|security-reference)-/.test(path.basename(folder)))fs.rmSync(folder,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

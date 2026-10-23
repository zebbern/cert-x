import test from 'node:test';
import assert from 'node:assert/strict';
globalThis.self ||= {};
globalThis.browser ||= {runtime:{getURL:path=>'chrome-extension://fixture/'+path,onMessage:{addListener(){}}},tabs:{onRemoved:{addListener(){}},onUpdated:{addListener(){}}},storage:{local:{async get(){return{}},async set(){}}}};
const {ptk_sast}=await import('../../../security/ptk/background/sast.js');

function fixture({preloaded=true,incompleteCount=0,reason='executed',failAnalysis=false}={}){
 const identity={epoch:'e',captureId:'capture',tabId:1,ownerId:'owner',frameId:'root',documentId:'doc',sessionGeneration:1,navigationGeneration:1,url:'https://app.test/'};
 const token={},scan={scanId:'scan'},calls=[];
 const sast=Object.assign(Object.create(ptk_sast.prototype),{resultStore:{scanResult:scan},browserCaptureLeases:new Map(),_assertAnalysisContext(){},async _completedOriginalCollectionKey(){return null;},async _scanCodeNow(scripts){calls.push(scripts);if(failAnalysis)throw Error('sast_worker_error');return [{id:'proof'}];},sessionCoordinator:{sessionToken:token,currentGeneration:1,beginCollection(){return{generation:1,collectionId:'one'};},markPayloadReceived(){},markCollectionAnalysis(){},completeCollection(){calls.push('complete');}}});
 const entry={tabId:1,scanId:'scan',ownerId:'owner',lease:{epoch:'e',captureId:'capture'},initialDocuments:new Set(preloaded?[sast._nativeDocumentKey(identity)]:[])};
 sast.browserCaptureLeases.set(1,entry);
 let released=false;
 const batch={acquireAnalysisReceipt:()=>({release(){}}),read:()=>({identity,reason,incompleteCount,records:[{scriptId:'script',resourceType:'Script',url:'https://app.test/script.js',body:'document.body.innerHTML=location.hash;'}]}),release(){released=true;}};
 return {sast,entry,batch,token,scan,calls,released:()=>released};
}
test('preloaded script batch analyzes available code without pretending original HTML was captured',async()=>{
 const f=fixture();assert.deepEqual(await f.sast._scanSourceBatch(f.entry,f.batch,f.token),[{id:'proof'}]);
 assert.equal(f.calls[0].length,1);assert.equal(f.scan.sastPreloadedCoverage.analyzedScripts,1);assert.equal(f.scan.sastPreloadedCoverage.originalHtmlUnavailable,true);assert.equal(f.released(),true);
});
test('a document created during capture still requires its original response and retains available analysis',async()=>{
 const f=fixture({preloaded:false});await assert.rejects(f.sast._scanSourceBatch(f.entry,f.batch,f.token),/sast_captured_source_partial:1/);
 assert.equal(f.calls[0].length,1);assert.equal(f.scan.sastPreloadedCoverage,undefined);assert.equal(f.entry.sourceBatchError,'sast_captured_source_partial:1');assert.equal(f.released(),true);
});
test('preloaded collection does not hide incomplete native reads or engine failure',async()=>{
 const partial=fixture({reason:'final',incompleteCount:1});await assert.rejects(partial.sast._scanSourceBatch(partial.entry,partial.batch,partial.token),/sast_captured_source_partial:1/);assert.equal(partial.calls.length,0);
 const failed=fixture({failAnalysis:true});await assert.rejects(failed.sast._scanSourceBatch(failed.entry,failed.batch,failed.token),/sast_worker_error/);assert.equal(failed.scan.sastPreloadedCoverage.analyzedScripts,0);assert.equal(failed.entry.sourceBatchError,'sast_worker_error');
});
test('preloaded coverage is deduplicated within exact document identity',async()=>{
 const f=fixture();await f.sast._scanSourceBatch(f.entry,f.batch,f.token);await f.sast._scanSourceBatch(f.entry,f.batch,f.token);
 assert.equal(f.scan.sastPreloadedCoverage.documents,1);assert.equal(f.scan.sastPreloadedCoverage.analyzedScripts,1);
});

test('analysis acquisition budgets deduplicate exact document/content and reject cumulative overruns',async()=>{
 const f=fixture();f.scan.settings={acquisition:{maxResourceBytes:16,maxTotalBytes:24}};f.sast._schedulePersistScanResult=()=>{};
 const context={identity:f.batch.read().identity,file:'https://app.test/'};
 const charge=(code,identity=context.identity)=>f.sast._chargeAnalysisAcquisition([{src:'https://app.test/a.js',code}],[],{...context,identity});
 await charge('12345');await charge('12345');assert.equal(f.scan.sastAnalysisAcquisition.bytes,10);
 await charge('12345',{...context.identity,documentId:'other'});assert.equal(f.scan.sastAnalysisAcquisition.bytes,20);
 f.scan.findings=[{id:'retained'}];await assert.rejects(charge('123'),/sast_acquisition_total_limit/);
 assert.equal(f.scan.sastAnalysisAcquisition.bytes,20);assert.deepEqual(f.scan.findings,[{id:'retained'}]);assert.equal(f.scan.sastSourceWarnings.at(-1).reason,'sast_acquisition_total_limit');
});

test('oversized original/live HTML and source never reach the analysis transport',async()=>{
 const f=fixture();f.scan.settings={acquisition:{maxResourceBytes:16,maxTotalBytes:64}};f.sast._schedulePersistScanResult=()=>{};
 let dispatches=0;f.sast.transport={async scanCodeRemote(){dispatches++;return[];}};
 f.sast._recordZapTiming=()=>{};
 const options={tabId:1,nativeDocument:f.batch.read().identity,generation:1};
 await assert.rejects(ptk_sast.prototype._scanCodeNow.call(f.sast,[{src:'https://app.test/a.js',code:'x'.repeat(9)}],[],'https://app.test/',options),/sast_acquisition_resource_limit/);
 await assert.rejects(ptk_sast.prototype._scanCodeNow.call(f.sast,[],['12345','12345'],'https://app.test/',options),/sast_acquisition_resource_limit/);
 assert.equal(dispatches,0);assert.equal(f.scan.sastAnalysisAcquisition.bytes,0);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { createIastDocuments } from '../../../security/engine/iast-documents.mjs';
function fixture(){
 const event=()=>{const callbacks=new Set();return {addListener:f=>callbacks.add(f),removeListener:f=>callbacks.delete(f),emit:(...args)=>{for(const f of callbacks)f(...args);},get size(){return callbacks.size;}};};
 const calls=[],injections=[],frames=[{url:'https://app.test/',documentId:'main'},{url:'https://app.test/frame',documentId:'allowed'},{url:'https://app.test/%2570rivate/frame',documentId:'excluded'},{url:'https://foreign.test/',documentId:'foreign'}];let sequence=0;
 const api={debugger:{onEvent:event(),onDetach:event(),async attach(){},async detach(){calls.push(['detach']);},async sendCommand(target,method,params){calls.push([method,target,params]);return method==='Page.addScriptToEvaluateOnNewDocument'?{identifier:'script-'+(++sequence)}:{};}},webNavigation:{onCommitted:event(),async getAllFrames(){return structuredClone(frames);}},scripting:{async executeScript(args){injections.push(args);return [];}}};
 const context={scope:{origins:['https://app.test'],excludePaths:['/private']}},coverage=[];
 const hooks=createIastDocuments({api,tabId:1,source:'source',files:['iast.js'],context,onCoverage:value=>coverage.push(value)});
 return {api,hooks,calls,injections,frames,context,coverage};
}
test('existing injection pins allowed document IDs, deduplicates and removes root/child scripts on stop',async()=>{
 const f=fixture();await f.hooks.start();assert.deepEqual(f.injections.map(x=>x.target.documentIds),[['main'],['allowed']]);assert.ok(f.injections.every(x=>x.target.frameIds===undefined&&x.world==='MAIN'));
 f.api.debugger.onEvent.emit({tabId:1},'Target.attachedToTarget',{sessionId:'child',targetInfo:{type:'iframe'}});
 await new Promise(resolve=>setTimeout(resolve,0));await f.hooks.stop();
 assert.equal(f.calls.filter(x=>x[0]==='Page.removeScriptToEvaluateOnNewDocument').length,2);assert.equal(f.injections.length,2);assert.equal(f.api.webNavigation.onCommitted.size,0);
 f.api.webNavigation.onCommitted.emit({tabId:1});assert.equal(f.injections.length,2);
});
test('navigation during injection never falls back from a stale document ID to its frame',async()=>{
 const f=fixture();let attempts=0;f.api.scripting.executeScript=async args=>{attempts++;if(args.target.documentIds[0]==='main'){f.frames.splice(0,1);throw Error('Document disappeared');}f.injections.push(args);};
 await f.hooks.start();assert.equal(attempts,2);assert.deepEqual(f.injections.map(x=>x.target.documentIds),[['allowed']]);await f.hooks.stop();
});
test('real injection failures surface and still release debugger ownership',async()=>{
 const f=fixture();f.api.scripting.executeScript=async()=>{throw Error('injection failed');};
 await assert.rejects(f.hooks.start(),/injection failed/);assert.equal(f.calls.at(-1)[0],'detach');assert.equal(f.api.debugger.onEvent.size,0);
});
test('scope narrowing is rechecked between existing document injections',async()=>{
 const f=fixture();f.context.scopeNow=async()=>({origins:['https://app.test'],excludePaths:f.injections.length?['/frame']:[]});
 await f.hooks.start();assert.deepEqual(f.injections.map(x=>x.target.documentIds),[['main']]);await f.hooks.stop();assert.equal(f.coverage.at(-1).active,false);
});

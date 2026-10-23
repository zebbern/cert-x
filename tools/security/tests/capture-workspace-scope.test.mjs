import test from 'node:test';
import assert from 'node:assert/strict';
import { BrowserCaptureManager } from '../../../security/ptk/background/capture/browserCaptureManager.js';
async function fixture(scope){
 let admission;
 const manager=new BrowserCaptureManager({adapter:{setEventSink(){},setAdmission(fn){admission=fn;},async configure(){},async release(){}}});
 await manager.acquire({ownerId:'scan',tabId:1,scope,capabilities:['network']});
 return url=>admission({tabId:1,url,documentUrl:'https://app.test/app',resourceType:'Fetch'},'metadata');
}
test('capture workspace scope admits selected origins and rejects exclusions before retaining events',async()=>{
 const allowed=await fixture({targetUrl:'https://app.test/app',origins:['https://app.test','https://api.test'],excludePaths:['/private']});
 assert.equal(allowed('https://app.test/api'),true);assert.equal(allowed('https://api.test/api'),true);
 for(const url of ['https://foreign.test/api','https://app.test/private/data','https://api.test/%2570rivate/data','https://api.test/private;matrix/data'])assert.equal(allowed(url),false,url);
});
test('capture consumers without workspace scope retain their original single-origin contract',async()=>{
 const allowed=await fixture({targetUrl:'https://app.test/app'});
 assert.equal(allowed('https://app.test/api'),true);assert.equal(allowed('https://api.test/api'),false);
});
test('capture retains explicit host/subdomain matching and exclusions',async()=>{
 const allowed=await fixture({targetUrl:'https://app.test/app',origins:['https://app.test'],excludePaths:['/private'],matchMode:'host',includeSubdomains:true});
 assert.equal(allowed('http://app.test:8080/data'),true);assert.equal(allowed('https://api.app.test:8443/data'),true);
 for(const url of ['https://notapp.test/data','https://app.test.foreign.test/data','http://api.app.test:8080/%2570rivate/data'])assert.equal(allowed(url),false,url);
});

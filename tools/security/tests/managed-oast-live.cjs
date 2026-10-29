// Bounded live acceptance: one new endpoint, marker-only HTTP/DNS events, then
// delete only that endpoint. The key is resolved exclusively by the native host.
const assert=require('node:assert/strict'),http=require('node:http'),dns=require('node:dns/promises'),fs=require('node:fs/promises'),path=require('node:path');
const {createSetup}=require('../../host/security/setup.cjs'),createOast=require('../../host/security/oast.cjs'),host=require('../../host/ki-host.js');
const root=process.env.CERT_X_TEST_RUNTIME||process.argv[2],envFileRef=process.argv[3];if(!root||!envFileRef)throw Error('Provide managed runtime and explicit .env file paths');
let oast,server,connection,registration;const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const context={owner:'live-oast-fixture',runId:'live-'+Date.now(),scope:{origins:[],excludePaths:[]},config:{requestTimeoutMs:10000}};
async function run(action,args={}){return oast.dispatch('oast.'+action,{connection,...args},context);}
(async()=>{
 const python=await createSetup({root}).componentPath('webhook');connection={id:'cert-x-webhook-live-test',command:python,args:['-I','-c','from server import run_server; run_server()'],envFileRef:path.resolve(envFileRef)};
 const events=[];oast=createOast({root,admit:async request=>{events.push(request.request.kind);return {allow:true};},mcpCall:(server,name,args,signal)=>host.dispatch('mcp_call',{server,name,arguments:args},signal)});
 const readiness=await run('status',{check:true});assert.equal(readiness.available,true);
 registration=await run('create');const self=await run('probe',{oastId:registration.oastId,purpose:'self_test'});await fetch(self.url,{method:'POST',body:'cert-x self-test marker only',signal:AbortSignal.timeout(10000)});
 server=http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://fixture'),value=url.searchParams.get('url');if(url.pathname==='/vulnerable')await fetch(value,{signal:AbortSignal.timeout(10000)});res.end(value||'');}catch(error){res.statusCode=500;res.end(error.message);}});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;context.scope.origins=[origin];
 const positive=await run('probe',{oastId:registration.oastId,family:'ssrf',execute:true,request:{url:origin+'/vulnerable?url={{OAST_URL}}'}}),negative=await run('probe',{oastId:registration.oastId,family:'ssrf',execute:true,request:{url:origin+'/safe?url={{OAST_URL}}'}});
 const dnsProbe=await run('probe',{oastId:registration.oastId,family:'ssrf',variant:'dns',purpose:'self_test'});await dns.resolve4(dnsProbe.dns).catch(()=>{});
 let received;for(let attempt=0;attempt<8;attempt++){received=await run('events',{oastId:registration.oastId});if(received.events.some(e=>e.probeId===positive.probeId)&&received.events.some(e=>e.probeId===dnsProbe.probeId))break;await pause(1500);}
 assert.ok(received.events.some(e=>e.probeId===self.probeId&&e.source==='self_test'));assert.ok(received.events.some(e=>e.probeId===positive.probeId&&e.source==='server_candidate'));assert.ok(!received.events.some(e=>e.probeId===negative.probeId));assert.ok(received.events.some(e=>e.probeId===dnsProbe.probeId),'Provider captured the DNS marker');
 const evidence=await run('export',{oastId:registration.oastId});await fs.writeFile(path.join(root,'live-oast-evidence.json'),JSON.stringify(evidence,null,2),{mode:0o600});
 await run('cleanup',{oastId:registration.oastId});registration=null;
 console.log(JSON.stringify({liveProvider:true,httpCallback:true,dnsCallback:true,serverProbe:true,negativeControl:true,selfTestSeparated:true,providerCalls:events.filter(x=>x==='control').length,createdEndpoints:1,cleanedUp:true,evidenceFile:path.join(root,'live-oast-evidence.json')}));
})().catch(error=>{console.error(error.message);process.exitCode=1;}).finally(async()=>{if(registration)try{await run('cleanup',{oastId:registration.oastId});}catch(error){console.error('Owned test endpoint cleanup failed: '+error.message);}await oast?.close();if(connection)await host.dispatch('mcp_reset',{servers:[connection]}).catch(()=>{});if(server)await new Promise(resolve=>server.close(resolve));});

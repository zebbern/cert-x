const assert=require('node:assert/strict'),http=require('node:http'),path=require('node:path');
const {createSetup}=require('../../host/security/setup.cjs'),createZap=require('../../host/security/zap.cjs');
const runtimeRoot=process.env.CERT_X_TEST_RUNTIME||process.argv[2];if(!runtimeRoot)throw Error('Set CERT_X_TEST_RUNTIME to a prepared runtime');
let server,zap;const requests=[],admissions=[];let deny=false;
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
(async()=>{
 server=http.createServer((req,res)=>{requests.push(req.url);res.setHeader('Content-Type','text/html');res.setHeader('X-Powered-By','PHP/5.6.0');res.end('<!doctype html><title>ZAP fixture</title><body>'+new URL(req.url,'http://fixture').searchParams.get('q')+'</body>');});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 const installer=createSetup({root:runtimeRoot});zap=createZap({root:runtimeRoot,componentPath:installer.componentPath,admit:async value=>{admissions.push(value.request);if(deny)throw Error('Revoked');return {allow:true};}});
 const context={owner:'zap-fixture',runId:'zap-fixture-'+Date.now(),scope:{origins:[origin],excludePaths:['/excluded']},config:{requestTimeoutMs:5000}};
 const active=process.env.ZAP_ACTIVE==='1',ajax=process.env.ZAP_AJAX==='1';
 const start=await zap.dispatch('zap.start',{url:origin+'/?q=baseline',spider:false,active,ajax,...(active?{scannerIds:['40012']}:{})},context);let state;
 const deadline=Date.now()+120000;do{state=await zap.dispatch('zap.progress',{zapId:start.zapId},context);if(state.state!=='running')break;await pause(300);}while(Date.now()<deadline);
 assert.equal(state.state,'completed',JSON.stringify(state));assert.ok(requests.length>0,'Actual ZAP requests reached the local fixture');assert.equal(admissions.filter(x=>x.kind==='zap_probe').length,requests.length,'Every outbound ZAP request was admitted by the guard');
 const evidence=await zap.dispatch('zap.evidence',{zapId:start.zapId},context);assert.equal(evidence.total,requests.length);assert.ok(evidence.requests.every(x=>x.response.status===200));const findings=await zap.dispatch('zap.findings',{zapId:start.zapId},context);assert.ok(findings.total>0,'ZAP passive findings retained');
 await assert.rejects(zap.dispatch('zap.findings',{zapId:start.zapId},{...context,owner:'foreign'}),/belong/);
 await zap.dispatch('zap.stop',{zapId:start.zapId},context);
 if(active)assert.ok(findings.findings.some(item=>String(item.ruleId)==='40012'),'Selected reflected-XSS rule executed against the positive fixture');
 console.log(JSON.stringify({actualZap:true,active,ajax,version:state.version,requests:requests.length,findings:findings.total,guardAccounting:true,ownedEvidence:true,stop:true}));
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(async()=>{await zap?.close();if(server)await new Promise(resolve=>server.close(resolve));});

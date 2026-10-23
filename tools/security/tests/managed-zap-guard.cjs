const assert=require('node:assert/strict'),http=require('node:http'),https=require('node:https'),net=require('node:net'),tls=require('node:tls'),path=require('node:path');
const {createSetup}=require('../../host/security/setup.cjs'),{createGuard,createCertificates}=require('../../host/security/zap-guard.cjs');
const runtimeRoot=process.env.CERT_X_TEST_RUNTIME||process.argv[2];if(!runtimeRoot)throw Error('Set CERT_X_TEST_RUNTIME to a prepared managed runtime');
let guard,plain,secure;const wire=[];let denied=false;
const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
function request(port,url,auth){return new Promise((resolve,reject)=>{const req=http.request({host:'127.0.0.1',port,path:url,headers:{Host:new URL(url).host,...(auth?{'Proxy-Authorization':auth}:{})}},res=>{let body='';res.on('data',x=>body+=x);res.on('end',()=>resolve({status:res.statusCode,body}));});req.on('error',reject);req.end();});}
async function tunnel(port,target,auth,ca){const socket=net.connect(port,'127.0.0.1');await new Promise((resolve,reject)=>{socket.once('connect',resolve);socket.once('error',reject);});socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Authorization: ${auth}\r\n\r\n`);await new Promise((resolve,reject)=>{socket.once('error',reject);socket.once('data',chunk=>{assert.match(chunk.toString(),/200 Connection Established/);resolve();});});const connection=tls.connect({socket,servername:'localhost',ca});await new Promise((resolve,reject)=>{connection.once('secureConnect',resolve);connection.once('error',reject);});connection.write(`GET /tls HTTP/1.1\r\nHost: ${target}\r\nConnection: close\r\n\r\n`);return new Promise((resolve,reject)=>{let result='';connection.on('data',chunk=>result+=chunk);connection.on('end',()=>resolve(result));connection.on('error',reject);});}
(async()=>{
 const modules=await createSetup({root:runtimeRoot}).componentPath('node'),forge=require(path.join(modules,'node-forge')),cert=createCertificates(forge);
 const handler=(req,res)=>{wire.push(req.url);res.setHeader('Content-Type','text/plain');res.end('guard fixture');};plain=http.createServer(handler);await listen(plain);
 secure=https.createServer({key:cert.key,cert:cert.pem,SNICallback:(host,callback)=>callback(null,cert.context(host))},handler);await listen(secure);
 const origin='http://127.0.0.1:'+plain.address().port,tlsOrigin='https://localhost:'+secure.address().port;
 guard=await createGuard({context:{owner:'guard-test',runId:'guard-run',scope:{origins:[origin,tlsOrigin],excludePaths:['/excluded']}},forge,upstreamCa:cert.pem,admit:async()=>{if(denied)throw Error('User limit reached');return {allow:true};}});
 const reset=net.connect(guard.port,'127.0.0.1');await new Promise(resolve=>reset.once('connect',resolve));reset.on('error',()=>{});reset.resetAndDestroy();await new Promise(resolve=>setTimeout(resolve,20));
 assert.equal((await request(guard.port,origin+'/public')).status,407);assert.equal(wire.length,0);
 assert.equal((await request(guard.port,origin+'/public',guard.authorization)).status,200);assert.equal(wire.length,1);
 assert.equal((await request(guard.port,origin+'/%65xcluded',guard.authorization)).status,403);assert.equal(wire.length,1);
 assert.match(await tunnel(guard.port,'localhost:'+secure.address().port,guard.authorization,guard.caPem),/200 OK[\s\S]*guard fixture/);assert.equal(wire.length,2);
 denied=true;assert.equal((await request(guard.port,origin+'/revoked',guard.authorization)).status,502);assert.equal(wire.length,2);
 assert.equal(guard.evidence.length,2);assert.ok(guard.evidence.every(item=>item.response.status===200));
 console.log(JSON.stringify({http:true,https:true,privateCa:true,unauthenticatedBlocked:true,encodedScopeBlocked:true,revocationBeforeWire:true,evidence:true}));
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(async()=>{await guard?.stop();for(const server of [plain,secure])if(server)await new Promise(resolve=>server.close(resolve));});

const test=require('node:test'),assert=require('node:assert/strict');
const {checkScope,createTransports}=require('../security/transports.cjs');
const {validateHttp1}=require('../security/raw-wire.cjs');
test('explicit destination port zero cannot silently become a default port',async()=>{
 let admissions=0;const transport=createTransports({admit:async()=>{admissions++;}});
 await assert.rejects(transport.dispatch('transport.http1',{url:'http://127.0.0.1:0/',requestBase64:Buffer.from('GET / HTTP/1.1\r\nHost: 127.0.0.1:0\r\n\r\n').toString('base64')},{owner:'a',runId:'r',scope:{origins:['http://127.0.0.1:0']}}),/port/);
 assert.equal(admissions,0);
});
test('declared transport scope applies canonical decoded path exclusions',()=>{
 const context={scope:{origins:['https://app.test'],excludePaths:['/private']}};
 for(const url of ['https://app.test/private','https://app.test/%70rivate/x','wss://app.test/public/../private/x','https://app.test/private;session/x'])assert.throws(()=>checkScope(url,context),/scope/);
 assert.equal(checkScope('wss://app.test/public',context).pathname,'/public');
});
test('all routable HTTP1 interpretations must remain in scope',()=>{
 const target=new URL('http://app.test/'),context={scope:{origins:['http://app.test'],excludePaths:['/private']}};
 const raw=Buffer.from('POST /safe HTTP/1.1\r\nHost: app.test\r\nContent-Length: 61\r\n\r\nGET /private HTTP/1.1\r\nHost: app.test\r\n\r\n');
 assert.throws(()=>validateHttp1(raw,target,context),/scope/);
 assert.throws(()=>validateHttp1(Buffer.from('GET /safe HTTP/1.1\r\nHost: app.test\r\nHost: other.test\r\n\r\n'),target,context),/scope/);
 assert.throws(()=>validateHttp1(Buffer.from('GET /safe HTTP/1.1\r\nHost: app.test\r\n\r\n\nGET /private HTTP/1.1\n'),target,context),/bare-LF/);
});
test('malformed routing fails before admission',async()=>{
 let calls=0;const transport=createTransports({admit:async()=>{calls++;}}),context={owner:'a',runId:'r',scope:{origins:['https://app.test']}};
 await assert.rejects(transport.dispatch('transport.http1',{url:'https://app.test/',requestBase64:Buffer.from('arbitrary bytes').toString('base64')},context),/routable/);
 assert.equal(calls,0);
});

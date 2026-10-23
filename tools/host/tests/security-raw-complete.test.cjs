const test=require('node:test'),assert=require('node:assert/strict'),net=require('node:net'),http2=require('node:http2'),crypto=require('node:crypto'),path=require('node:path');
const {createTransports}=require('../security/transports.cjs');
const root=path.join(process.env.LOCALAPPDATA||process.cwd(),'cert-x','verification','raw-tests');
const modules=path.resolve(__dirname,'../../security/runtime/node_modules');
const b64=x=>Buffer.from(x).toString('base64');
const request=(host,p='/')=>b64(`GET ${p} HTTP/1.1\r\nHost: ${host}\r\n\r\n`);
function transport(admit=async()=>{}){return createTransports({admit,root,componentPath:async()=>modules});}
async function server(t,onSocket){const sockets=new Set(),s=net.createServer(socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));onSocket(socket);});await new Promise(resolve=>s.listen(0,'127.0.0.1',resolve));t.after(async()=>{for(const socket of sockets)socket.destroy();await new Promise(resolve=>s.close(resolve));});return {url:`http://127.0.0.1:${s.address().port}`,server:s};}
const context=url=>({owner:'raw-test-chat',runId:'raw-test-run',workspaceId:'raw-test-workspace',scope:{origins:[url]}});
// Local fixture parsers consume complete messages according to independent
// front and backend policies. They never identify requests by searching bodies.
function parseRequest(data,policy){
 const end=data.indexOf('\r\n\r\n');if(end<0)return null;
 const lines=data.subarray(0,end).toString('latin1').split('\r\n'),match=/^([A-Z]+) (\/[^ ]*) HTTP\/1\.1$/.exec(lines.shift());if(!match)throw Error('fixture request line');
 const headers=new Map(lines.map(line=>{const at=line.indexOf(':');if(at<1)throw Error('fixture header');return [line.slice(0,at).toLowerCase(),line.slice(at+1).trim()];}));
 const ambiguous=headers.has('content-length')&&headers.get('transfer-encoding')==='chunked';
 if(policy==='reject'&&ambiguous)throw Error('fixture rejects CL/TE');
 let consumed=end+4,body=Buffer.alloc(0);
 if(policy==='te'&&headers.get('transfer-encoding')==='chunked'){
  const parts=[];for(;;){const line=data.indexOf('\r\n',consumed);if(line<0)return null;const hex=data.subarray(consumed,line).toString('ascii');if(!/^[0-9a-f]+$/i.test(hex))throw Error('fixture chunk size');const size=parseInt(hex,16);consumed=line+2;if(size===0){if(data.length<consumed+2)return null;if(data.toString('ascii',consumed,consumed+2)!=='\r\n')throw Error('fixture chunk end');consumed+=2;break;}if(data.length<consumed+size+2)return null;parts.push(data.subarray(consumed,consumed+size));consumed+=size;if(data.toString('ascii',consumed,consumed+2)!=='\r\n')throw Error('fixture chunk boundary');consumed+=2;}
  body=Buffer.concat(parts);
 }else{const length=Number(headers.get('content-length')||0);if(!Number.isSafeInteger(length)||length<0)throw Error('fixture content length');if(data.length<consumed+length)return null;body=data.subarray(consumed,consumed+length);consumed+=length;}
 return {path:match[2],headers,body,consumed,raw:data.subarray(0,consumed)};
}
function response(route){const body=JSON.stringify({route,marker:'fixture:'+route});return Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);}
async function framingBackend(t){
 const seen=[];const fixture=await server(t,socket=>{let data=Buffer.alloc(0);socket.on('data',chunk=>{data=Buffer.concat([data,chunk]);try{for(;;){const item=parseRequest(data,'te');if(!item)break;data=data.subarray(item.consumed);if(item.path==='/reset'){seen.length=0;socket.end(response('/reset'));return;}if(item.path==='/observe'){const body=JSON.stringify({requests:seen.map(path=>({path}))});socket.end(`HTTP/1.1 200 OK\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);return;}seen.push(item.path);socket.write(response(item.path));}}catch{socket.destroy();}});});
 return {...fixture,seen};
}
async function framingFront(t,backend,{rejectAmbiguous=false}={}){
 return server(t,client=>{let data=Buffer.alloc(0),idle;const upstream=net.connect(new URL(backend.url).port,'127.0.0.1');upstream.on('data',chunk=>{client.write(chunk);clearTimeout(idle);idle=setTimeout(()=>client.end(),40);});upstream.on('error',()=>client.destroy());client.on('close',()=>{clearTimeout(idle);upstream.destroy();});client.on('data',chunk=>{data=Buffer.concat([data,chunk]);try{for(;;){const item=parseRequest(data,rejectAmbiguous?'reject':'cl');if(!item)break;data=data.subarray(item.consumed);upstream.write(item.raw);}}catch{client.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n');}});});
}
test('plumbing: WebSocket sends frames only after validated 101 and Accept',async t=>{
 let before101=null,after101=null;const fixture=await server(t,socket=>{let received=Buffer.alloc(0),upgraded=false;socket.on('data',chunk=>{if(upgraded){after101=chunk;socket.end();return;}received=Buffer.concat([received,chunk]);const end=received.indexOf('\r\n\r\n');if(end<0)return;before101=received.subarray(end+4);const key=/Sec-WebSocket-Key: ([^\r\n]+)/i.exec(received.toString('latin1'))[1],accept=crypto.createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');upgraded=true;socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);});});
 const frame=Buffer.from([0x81,0x82,1,2,3,4,0x69,0x6b]);const result=await transport().dispatch('transport.websocket',{url:fixture.url.replace('http:','ws:'),frames:[frame.toString('base64')],timeoutMs:1000},context(fixture.url));assert.equal(before101.length,0);assert.deepEqual(after101,frame);assert.equal(result.handshake.status,101);assert.equal(result.sent.length,2);
});
test('plumbing: WebSocket 200 and incorrect Accept refuse frame transmission',async t=>{
 for(const response of ['HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n','HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n']){
  let received=Buffer.alloc(0);const fixture=await server(t,socket=>socket.on('data',chunk=>{received=Buffer.concat([received,chunk]);if(received.includes(Buffer.from('\r\n\r\n')))socket.end(response);})),frame=Buffer.from([0x81,0x80,1,2,3,4]),ctx=context(fixture.url);
  await assert.rejects(transport().dispatch('transport.websocket',{url:fixture.url.replace('http:','ws:'),frames:[frame.toString('base64')],timeoutMs:500},ctx),/upgrade.*raw evidence/i);assert.ok(!received.includes(frame));
 }
});
test('plumbing: structured HTTP2 HPACK reaches local h2c server; unsupported routing fails before connection',async t=>{
 const seen=[];const sessions=new Set(),server=http2.createServer();server.on('session',session=>{sessions.add(session);session.on('close',()=>sessions.delete(session));});server.on('stream',(stream,headers)=>{seen.push(headers[':path']);stream.respond({':status':200,'content-length':'2'});stream.end('ok');});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(async()=>{for(const session of sessions)session.destroy();await new Promise(resolve=>server.close(resolve));});
 const url=`http://127.0.0.1:${server.address().port}`,ctx={...context(url),scope:{origins:[url],excludePaths:['/private']}},client=transport();
 const result=await client.dispatch('transport.http2',{url,requests:[{method:'GET',path:'/public'}],timeoutMs:250},ctx);assert.deepEqual(seen,['/public']);assert.equal(result.response.frames.some(f=>f.type===0),true);
 await assert.rejects(client.dispatch('transport.http2',{url,requests:[{method:'GET',path:'/%70rivate'}]},ctx),/scope/);
 await assert.rejects(client.dispatch('transport.http2',{url,frames:[{type:5,streamId:1,payloadBase64:''}]},ctx),/PUSH_PROMISE/);
 assert.deepEqual(seen,['/public']);
});
test('plumbing: raw evidence persists with owner/run/workspace binding and byte pagination',async t=>{
 const payload=crypto.randomBytes(450000);const fixture=await server(t,socket=>socket.on('data',()=>socket.end(payload))),ctx=context('pending');ctx.scope.origins=[fixture.url];const host=new URL(fixture.url).host;
 const result=await transport().dispatch('transport.http1',{url:fixture.url,requestBase64:request(host),maxResponseBytes:500000,timeoutMs:1000},ctx);assert.equal(result.response.bytes,payload.length);assert.equal(result.response.base64,undefined);const reader=transport(),pages=[];let offset=0;do{const page=await reader.dispatch('transport.evidence',{evidenceId:result.evidence.evidenceId,offset,limit:131072},ctx);pages.push(Buffer.from(page.base64,'base64'));offset=page.nextOffset;}while(offset!==null);const record=JSON.parse(Buffer.concat(pages).toString());assert.deepEqual(Buffer.from(record.result.response.base64,'base64'),payload);
 for(const wrong of [{...ctx,owner:'other'},{...ctx,runId:'other'},{...ctx,workspaceId:'other'}])await assert.rejects(reader.dispatch('transport.evidence',{evidenceId:result.evidence.evidenceId},wrong),/unavailable|belongs/);
});
test('plumbing: cancel and send denial settle with persisted partial evidence',async t=>{
 let connected,received=0;const fixture=await server(t,socket=>{connected=socket;socket.on('data',chunk=>{received+=chunk.length;});}),host=new URL(fixture.url).host,ctx=context(fixture.url),controller=new AbortController();const pending=transport().dispatch('transport.http1',{url:fixture.url,requestBase64:request(host),timeoutMs:10000},{...ctx,signal:controller.signal});await new Promise(resolve=>{const poll=setInterval(()=>{if(connected){clearInterval(poll);resolve();}},5);});controller.abort();const cancelled=await pending.then(()=>null,error=>error);assert.match(cancelled.message,/cancelled.*raw evidence/);const evidenceId=/raw evidence ([a-f0-9-]{36})/.exec(cancelled.message)[1],page=await transport().dispatch('transport.evidence',{evidenceId},ctx),partial=JSON.parse(Buffer.from(page.base64,'base64').toString());assert.match(partial.result.error.message,/cancelled/);assert.equal(partial.result.connections.length,1);
 const before=received,denied=transport(async x=>{if(x.request.kind==='raw_send')throw Error('budget exhausted');});await assert.rejects(denied.dispatch('transport.http1',{url:fixture.url,requestBase64:request(host),timeoutMs:500},ctx),/budget exhausted.*raw evidence/);assert.equal(received,before);
});
test('H1 CL-front/TE-back fixture confirms observed path and response queue with paired controls',async t=>{
 const backend=await framingBackend(t),front=await framingFront(t,backend),host=new URL(front.url).host,backHost=new URL(backend.url).host,ctx={...context(front.url),scope:{origins:[front.url,backend.url]}};
 const chunked='1\r\nx\r\n0\r\n\r\n',nested=`GET /injected HTTP/1.1\r\nHost: ${host}\r\n\r\n`,outer=body=>`POST /outer HTTP/1.1\r\nHost: ${host}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nTransfer-Encoding: chunked\r\n\r\n${body}`,followup=`GET /followup HTTP/1.1\r\nHost: ${host}\r\n\r\n`;
 const control=b64(outer(chunked)),probe=b64(outer('0\r\n\r\n'+nested)),base={url:front.url,requestBase64:probe,controlBase64:control,optIn:true,repeats:2,timeoutMs:1000};
 const observed=await transport().dispatch('transport.desync',{...base,reset:{url:backend.url,requestBase64:request(backHost,'/reset')},observation:{url:backend.url,requestBase64:request(backHost,'/observe'),expectedPath:'/injected'}},ctx);
 assert.equal(observed.classification,'confirmed_with_backend_observation');assert.equal(observed.attempts.length,4);
 const queueArgs={...base,requestBase64:b64(outer('0\r\n\r\n'+nested)+followup),controlBase64:b64(outer(chunked)+followup),responseQueue:{frontFraming:'cl',outer:{route:'/outer',marker:'fixture:/outer'},followup:{route:'/followup',marker:'fixture:/followup'},injected:{route:'/injected',marker:'fixture:/injected'}}},queue=await transport().dispatch('transport.desync',queueArgs,ctx);
 assert.equal(queue.classification,'confirmed_with_response_queue');assert.deepEqual(queue.boundaries,{controlBase64:{cl:['/outer','/followup'],te:['/outer','/followup']},requestBase64:{cl:['/outer','/followup'],te:['/outer','/injected','/followup']}});assert.deepEqual(queue.attempts.map(x=>x.responseCount),[2,3,2,3]);assert.equal(new Set(queue.attempts.map(x=>x.connection.localPort)).size,4);
 const normalized=await framingFront(t,backend,{rejectAmbiguous:true}),negative=await transport().dispatch('transport.desync',{...base,url:normalized.url,requestBase64:b64(outer('0\r\n\r\n'+nested).replaceAll(host,new URL(normalized.url).host)),controlBase64:b64(outer(chunked).replaceAll(host,new URL(normalized.url).host)),reset:{url:backend.url,requestBase64:request(backHost,'/reset')},observation:{url:backend.url,requestBase64:request(backHost,'/observe'),expectedPath:'/injected'}}, {...ctx,scope:{origins:[normalized.url,backend.url]}});
 assert.equal(negative.classification,'inconclusive');
 const negativeQueue=await transport().dispatch('transport.desync',{...queueArgs,url:normalized.url,requestBase64:b64((outer('0\r\n\r\n'+nested)+followup).replaceAll(host,new URL(normalized.url).host)),controlBase64:b64((outer(chunked)+followup).replaceAll(host,new URL(normalized.url).host))}, {...ctx,scope:{origins:[normalized.url,backend.url]}});
 assert.equal(negativeQueue.classification,'inconclusive');assert.ok(negativeQueue.attempts.every(x=>x.parseError));
});
test('response queue rejects an ordinary three-request pipeline before sending',async t=>{
 let connections=0;const fixture=await server(t,()=>{connections++;}),host=new URL(fixture.url).host,ctx=context(fixture.url),get=route=>`GET ${route} HTTP/1.1\r\nHost: ${host}\r\n\r\n`,spec={frontFraming:'cl',outer:{route:'/outer',marker:'controlled:outer'},injected:{route:'/injected',marker:'controlled:injected'},followup:{route:'/followup',marker:'controlled:followup'}};
 const args={url:fixture.url,optIn:true,requestBase64:b64(get('/outer')+get('/injected')+get('/followup')),controlBase64:b64(get('/outer')+get('/followup')),responseQueue:spec};
 await assert.rejects(transport().dispatch('transport.desync',{...args,responseQueue:{...spec,frontFraming:undefined}},ctx),/requires explicit frontFraming/);
 await assert.rejects(transport().dispatch('transport.desync',args,ctx),/requestBase64 under cl must parse complete outer,followup/);
 assert.equal(connections,0);
});
test('response queue rejects marker reflection from wire request bytes',async t=>{
 let connections=0;const fixture=await server(t,()=>{connections++;}),host=new URL(fixture.url).host,ctx=context(fixture.url),nested=`GET /injected HTTP/1.1\r\nHost: ${host}\r\nX-Reflect: controlled:injected\r\n\r\n`,outer=body=>`POST /outer HTTP/1.1\r\nHost: ${host}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nTransfer-Encoding: chunked\r\n\r\n${body}`,followup=`GET /followup HTTP/1.1\r\nHost: ${host}\r\n\r\n`;
 const args={url:fixture.url,optIn:true,requestBase64:b64(outer('0\r\n\r\n'+nested)+followup),controlBase64:b64(outer('1\r\nx\r\n0\r\n\r\n')+followup),responseQueue:{frontFraming:'cl',outer:{route:'/outer',marker:'controlled:outer'},injected:{route:'/injected',marker:'controlled:injected'},followup:{route:'/followup',marker:'controlled:followup'}}};
 await assert.rejects(transport().dispatch('transport.desync',args,ctx),/marker for injected must be absent from wire request bytes/);
 assert.equal(connections,0);
});
test('H2 downgrade uses stream length at front and chunked framing at backend',async t=>{
 const backend=await framingBackend(t),sessions=new Set();
 async function front(normalized){const h2=http2.createServer();h2.on('session',s=>{sessions.add(s);s.on('close',()=>sessions.delete(s));});h2.on('stream',(stream,headers)=>{const parts=[];stream.on('data',x=>parts.push(x));stream.on('end',()=>{const body=Buffer.concat(parts),host=headers[':authority'];const raw=Buffer.from(`POST ${headers[':path']} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: ${body.length}\r\n${normalized?'':'Transfer-Encoding: chunked\r\n'}\r\n`);const upstream=net.connect(new URL(backend.url).port,'127.0.0.1',()=>upstream.write(Buffer.concat([raw,body])));let done=false,timer;const reply=()=>{if(done)return;done=true;upstream.destroy();stream.respond({':status':200,'content-length':'0'});stream.end();};upstream.on('data',()=>{clearTimeout(timer);timer=setTimeout(reply,40);});upstream.on('error',reply);stream.on('close',()=>{clearTimeout(timer);upstream.destroy();});});});await new Promise(resolve=>h2.listen(0,'127.0.0.1',resolve));t.after(async()=>{for(const session of sessions)session.destroy();await new Promise(resolve=>h2.close(resolve));});return `http://127.0.0.1:${h2.address().port}`;}
 const url=await front(false),host=new URL(url).host,backHost=new URL(backend.url).host,ctx={...context(url),scope:{origins:[url,backend.url],excludePaths:['/private']}},nested=`GET /injected-h2 HTTP/1.1\r\nHost: ${host}\r\n\r\n`,probe={method:'POST',path:'/outer',bodyBase64:b64('0\r\n\r\n'+nested)},control={method:'POST',path:'/outer',bodyBase64:b64('1\r\nx\r\n0\r\n\r\n')};
 const args={protocol:'http2',url,requests:[probe],controlRequests:[control],optIn:true,repeats:2,timeoutMs:1000,reset:{url:backend.url,requestBase64:request(backHost,'/reset')},observation:{url:backend.url,requestBase64:request(backHost,'/observe'),expectedPath:'/injected-h2'}};
 assert.equal((await transport().dispatch('transport.desync',args,ctx)).classification,'confirmed_with_backend_observation');
 await assert.rejects(transport().dispatch('transport.http2',{url,requests:[{...probe,bodyBase64:b64(nested.replace('/injected-h2','/private'))}]},ctx),/scope/);
 const cleanUrl=await front(true),cleanCtx={...ctx,scope:{origins:[cleanUrl,backend.url]}},cleanProbe={...probe,bodyBase64:b64('0\r\n\r\n'+nested.replaceAll(host,new URL(cleanUrl).host))};
 assert.equal((await transport().dispatch('transport.desync',{...args,url:cleanUrl,requests:[cleanProbe]},cleanCtx)).classification,'inconclusive');
});
test('structured H2 splits a body above default max frame size and preserves raw frame identity',async t=>{
 const body=crypto.randomBytes(20000),seen=[];const sessions=new Set(),h2=http2.createServer();h2.on('session',s=>{sessions.add(s);s.on('close',()=>sessions.delete(s));});h2.on('stream',stream=>{const chunks=[];stream.on('data',x=>chunks.push(x));stream.on('end',()=>{seen.push(Buffer.concat(chunks));stream.respond({':status':200,'content-length':'0'});stream.end();});});await new Promise(resolve=>h2.listen(0,'127.0.0.1',resolve));t.after(async()=>{for(const session of sessions)session.destroy();await new Promise(resolve=>h2.close(resolve));});
 const url=`http://127.0.0.1:${h2.address().port}`,ctx=context(url),result=await transport().dispatch('transport.http2',{url,requests:[{method:'POST',path:'/',bodyBase64:body.toString('base64')}],timeoutMs:1000},ctx);
 assert.deepEqual(seen,[body]);const sent=result.sent.map(x=>Buffer.from(x.base64,'base64'));assert.equal(sent.filter(x=>x.length>=9&&x[3]===0).length,2);assert.ok(sent.filter(x=>x.length>=9&&x[3]===0).every(x=>x.readUIntBE(0,3)<=16384));
 await assert.rejects(transport().dispatch('transport.http2',{url,requests:[{method:'POST',bodyBase64:Buffer.alloc(65536).toString('base64')}]},ctx),/flow-control window/);
 const exact=Buffer.from([0,0,0,4,0,0,0,0,0]),raw=await transport().dispatch('transport.http2',{url,frames:[{rawBase64:exact.toString('base64')}],allowControlFrames:true,timeoutMs:50},ctx);
 assert.deepEqual(Buffer.from(raw.sent[1].base64,'base64'),exact);
});
test('structured H2 surfaces peer stream errors with persisted evidence',async t=>{
 const sessions=new Set(),h2=http2.createServer();h2.on('session',s=>{sessions.add(s);s.on('close',()=>sessions.delete(s));});h2.on('stream',stream=>{stream.on('error',()=>{});stream.close(http2.constants.NGHTTP2_PROTOCOL_ERROR);});await new Promise(resolve=>h2.listen(0,'127.0.0.1',resolve));t.after(async()=>{for(const session of sessions)session.destroy();await new Promise(resolve=>h2.close(resolve));});
 const url=`http://127.0.0.1:${h2.address().port}`;await assert.rejects(transport().dispatch('transport.http2',{url,requests:[{path:'/'}],timeoutMs:1000},context(url)),/RST_STREAM.*raw evidence/);
});

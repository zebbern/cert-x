'use strict';
// ZAP HTTP-sender listeners log exceptions and continue; admission belongs at
// the outgoing transport, before any target connection is opened.
const http = require('node:http'), https = require('node:https'), tls = require('node:tls'), net = require('node:net');
const { randomBytes, randomUUID } = require('node:crypto');
const inScope = require('./oast.cjs').inScope;
function createCertificates(forge) {
  const keys = forge.pki.rsa.generateKeyPair(2048), certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey; certificate.serialNumber = randomBytes(16).toString('hex');
  certificate.validity.notBefore = new Date(Date.now() - 300000); certificate.validity.notAfter = new Date(Date.now() + 86400000 * 30);
  const attrs = [{ name: 'commonName', value: 'cert-x owned ZAP transport' }];
  certificate.setSubject(attrs); certificate.setIssuer(attrs);
  certificate.setExtensions([{ name: 'basicConstraints', cA: true }, { name: 'keyUsage', keyCertSign: true, cRLSign: true }]); certificate.sign(keys.privateKey, forge.md.sha256.create());
  const pem = forge.pki.certificateToPem(certificate), key = forge.pki.privateKeyToPem(keys.privateKey), cache = new Map();
  return { pem, key, truststore: Buffer.from(forge.asn1.toDer(forge.pkcs12.toPkcs12Asn1(null, [certificate], 'cert-x-private-trust', { algorithm: '3des', friendlyName: 'cert-x transport CA' })).getBytes(), 'binary'),
    context(host) {
      if (cache.has(host)) return cache.get(host);
      const leaf = forge.pki.createCertificate(); leaf.publicKey = keys.publicKey; leaf.serialNumber = randomBytes(16).toString('hex'); leaf.validity.notBefore = certificate.validity.notBefore; leaf.validity.notAfter = certificate.validity.notAfter;
      leaf.setIssuer(certificate.subject.attributes); leaf.setSubject([{ name: 'commonName', value: host }]);
      leaf.setExtensions([{ name: 'basicConstraints', cA: false }, { name: 'keyUsage', digitalSignature: true, keyEncipherment: true }, { name: 'extKeyUsage', serverAuth: true }, { name: 'subjectAltName', altNames: [net.isIP(host) ? { type: 7, ip: host } : { type: 2, value: host }] }]); leaf.sign(keys.privateKey, forge.md.sha256.create());
      const context = tls.createSecureContext({ key, cert: forge.pki.certificateToPem(leaf) + pem }); cache.set(host, context); return context;
    }
  };
}
async function createGuard({ context, admit, forge, WebSocket, proxyPassword, requestKind = 'zap_probe', onEvidence = () => {}, maxEvidenceBytes = 8 * 1024 * 1024, upstreamCa }) {
  if(typeof admit!=='function')throw Error('ZAP requires a live admission bridge');
  if(proxyPassword!==undefined&&(typeof proxyPassword!=='string'||proxyPassword.length<24||/[\r\n\0]/.test(proxyPassword)))throw Error('Invalid private proxy credential');
  const certificates = createCertificates(forge), password = proxyPassword || randomBytes(24).toString('hex'), auth = 'Basic ' + Buffer.from('cert-x:' + password).toString('base64');
  const warmupUrl='http://cert-x-proxy.invalid/__warmup/'+randomBytes(24).toString('hex');
  const sockets = new Set(), outbound = new Set(), evidence = [], pending = new Set(); let revoked = false;
  const strip = headers => Object.fromEntries(Object.entries(headers).filter(([name]) => !['proxy-authorization', 'proxy-connection', 'connection', 'transfer-encoding'].includes(name.toLowerCase())));
  const server = http.createServer((req,res) => { res.on('error',()=>res.destroy());const task = forward(req,res).catch(error=>{if(res.destroyed)return;if(!res.headersSent)res.writeHead(502);res.end('cert-x transport: '+error.message);}); pending.add(task); task.finally(()=>pending.delete(task)); });
  server.on('connection',socket=>{sockets.add(socket);socket.on('error',()=>socket.destroy());socket.on('close',()=>sockets.delete(socket));});
  server.on('clientError',(error,socket)=>socket.destroy());
  async function forward(req,res) {
    if (revoked || context.signal?.aborted) { res.writeHead(503);res.end('Security operation stopped');return; }
    const authority = req.socket.certXAuthority;
    if (!authority && req.headers['proxy-authorization'] !== auth) { res.writeHead(407, {'Proxy-Authenticate':'Basic realm="cert-x"'});res.end();return; }
    let url;
    try { url = new URL(req.url, authority ? (req.socket.certXScheme || 'https:') + '//' + authority : undefined); } catch { res.writeHead(400);res.end('Absolute target URL required');return; }
    if(!authority&&url.href===warmupUrl){res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store'});res.end('<!doctype html><title>Local browser ready</title>');return;}
    if (!inScope(url.href, context.scope)) { res.writeHead(403);res.end('Target outside run scope: '+url.href+'. Review target scope in Workspace settings.');return; }
    if (authority && url.host !== authority) { res.writeHead(403);res.end('TLS tunnel target changed');return; }
    if (req.headers.host && req.headers.host !== url.host) { res.writeHead(403);res.end('Routing authority does not match target');return; }
    const chunks=[];let bytes=0;
    for await (const chunk of req) { bytes += chunk.length;if(bytes > (context.config?.maxRequestBytes || 8*1024*1024)){res.writeHead(413);res.end('Request exceeds configured transport size');return;} chunks.push(chunk); }
    const decision=await admit({ ...context, request: { kind: requestKind, url:url.href, method:req.method, bytes } });
    if(decision===false||decision?.allow===false)throw Error('ZAP request denied');
    if(revoked||context.signal?.aborted){res.writeHead(503);res.end();return;}
    const item={id:randomUUID(),url:url.href,method:req.method,startedAt:Date.now(),request:{headers:strip(req.headers),bodyBase64:Buffer.concat(chunks).toString('base64')},response:null};evidence.push(item);
    await new Promise((resolve,reject)=>{
      const transport=url.protocol==='https:'?https:http;
      const request=transport.request(url,{method:req.method,headers:strip(req.headers),agent:false,...(upstreamCa?{ca:upstreamCa}:{}),timeout:context.config?.requestTimeoutMs||30000},response=>{
        const body=[];let size=0;item.response={status:response.statusCode,headers:response.headers,bodyBase64:'',truncated:false};res.writeHead(response.statusCode,strip(response.headers));
        response.on('data',chunk=>{if(size<maxEvidenceBytes)body.push(chunk.subarray(0,maxEvidenceBytes-size));size+=chunk.length;if(!res.destroyed)res.write(chunk);});
        response.on('end',()=>{item.response.bodyBase64=Buffer.concat(body).toString('base64');item.response.bytes=size;item.response.truncated=size>maxEvidenceBytes;item.endedAt=Date.now();res.end();resolve();});response.on('error',reject);
      });
      outbound.add(request);request.on('close',()=>outbound.delete(request));request.on('timeout',()=>request.destroy(Error('Target request timed out')));request.on('error',reject);request.end(Buffer.concat(chunks));
    }).catch(error=>{item.error=error.message;item.endedAt=Date.now();throw error;}).finally(()=>onEvidence(item));
  }
  server.on('connect',(req,socket,head)=>{
    if(revoked||req.headers['proxy-authorization']!==auth){socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n');return;}
    let secureUrl,plainUrl;try{secureUrl=new URL('https://'+req.url);plainUrl=new URL('http://'+req.url);}catch{socket.destroy();return;}
    const encrypted=inScope(secureUrl.href,context.scope),plaintext=inScope(plainUrl.href,context.scope);
    // CONNECT carries an authority, not a scheme. Same-host mode selects HTTPS
    // for this TLS tunnel; ordinary HTTP proxy requests use absolute URLs.
    if(!encrypted&&!plaintext||encrypted&&plaintext&&context.scope?.matchMode!=='host'){socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');return;}
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head.length)socket.unshift(head);
    if(encrypted){const secure=new tls.TLSSocket(socket,{isServer:true,secureContext:certificates.context(secureUrl.hostname),ALPNProtocols:['http/1.1']});secure.certXAuthority=secureUrl.host;secure.certXScheme='https:';secure.on('error',()=>secure.destroy());sockets.add(secure);secure.on('close',()=>sockets.delete(secure));server.emit('connection',secure);}
    else{socket.certXAuthority=plainUrl.host;socket.certXScheme='http:';server.emit('connection',socket);}
  });
  const websocketPairs=new Set(),websocketServer=WebSocket?new WebSocket.WebSocketServer({noServer:true,maxPayload:context.config?.maxMessageBytes||8*1024*1024,handleProtocols:(protocols,req)=>req.certXProtocol||false}):null;
  server.on('upgrade',(req,socket,head)=>{
    const task=(async()=>{
      if(!websocketServer)throw Error('WebSocket codec is unavailable');
      if(revoked||context.signal?.aborted)throw Error('Security operation stopped');
      const authority=req.socket.certXAuthority;if(!authority&&req.headers['proxy-authorization']!==auth)throw Error('Proxy authentication required');
      const url=new URL(req.url,authority?(req.socket.certXScheme||'https:')+'//'+authority:undefined);if(url.protocol==='ws:')url.protocol='http:';if(url.protocol==='wss:')url.protocol='https:';
      if(!inScope(url.href,context.scope)||(authority&&url.host!==authority)||req.headers.host!==url.host)throw Error('WebSocket target outside scope');
      const result=await admit({...context,request:{url:url.href,method:'GET',kind:requestKind,resource:'websocket_handshake'}});if(result===false||result?.allow===false)throw Error('WebSocket denied');
      const target=new URL(url);target.protocol=url.protocol==='https:'?'wss:':'ws:';
      const headers=Object.fromEntries(Object.entries(req.headers).filter(([name])=>!['host','proxy-authorization','proxy-connection','connection','upgrade','sec-websocket-key','sec-websocket-version','sec-websocket-protocol','sec-websocket-extensions'].includes(name.toLowerCase())));
      const protocols=String(req.headers['sec-websocket-protocol']||'').split(',').map(x=>x.trim()).filter(Boolean);
      const upstream=new WebSocket(target,protocols,{headers,...(upstreamCa?{ca:upstreamCa}:{}),maxPayload:context.config?.maxMessageBytes||8*1024*1024,handshakeTimeout:context.config?.requestTimeoutMs||30000});
      const pair={upstream,client:null};websocketPairs.add(pair);
      await new Promise((resolve,reject)=>{upstream.once('open',resolve);upstream.once('error',reject);});req.certXProtocol=upstream.protocol;
      websocketServer.handleUpgrade(req,socket,head,client=>{
        pair.client=client;let queue=Promise.resolve();const close=()=>{websocketPairs.delete(pair);upstream.terminate();client.terminate();};
        client.on('error',close);upstream.on('error',close);client.on('close',close);upstream.on('close',close);
        upstream.on('message',(data,binary)=>{if(client.readyState===WebSocket.OPEN)client.send(data,{binary});});
        client.on('message',(data,binary)=>{
          client.pause();queue=queue.then(async()=>{
            if(revoked||context.signal?.aborted||!inScope(url.href,context.scope))throw Error('WebSocket authority revoked');
            const decision=await admit({...context,request:{url:url.href,method:'WS',kind:requestKind,resource:'websocket_message',bytes:data.length}});if(decision===false||decision?.allow===false)throw Error('WebSocket message denied');
            const item={id:randomUUID(),url:target.href,kind:'websocket_message',startedAt:Date.now(),request:{bodyBase64:Buffer.from(data).subarray(0,maxEvidenceBytes).toString('base64'),binary,bytes:data.length,truncated:data.length>maxEvidenceBytes}};evidence.push(item);
            await new Promise((resolve,reject)=>upstream.send(data,{binary},error=>error?reject(error):resolve()));item.sent=true;item.endedAt=Date.now();onEvidence(item);
          }).then(()=>client.resume(),close);
        });
      });
    })().catch(()=>socket.destroy());pending.add(task);task.finally(()=>pending.delete(task));
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const stop=async()=>{revoked=true;for(const pair of websocketPairs){pair.client?.terminate();pair.upstream.terminate();}for(const request of outbound)request.destroy(Error('Run stopped'));for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));await Promise.allSettled([...pending]);};
  const abort=()=>stop().catch(()=>{});context.signal?.addEventListener('abort',abort,{once:true});
  return {port:server.address().port,username:'cert-x',password,authorization:auth,warmupUrl,caPem:certificates.pem,truststore:certificates.truststore,evidence,stop:async()=>{context.signal?.removeEventListener('abort',abort);await stop();}};
}
module.exports={createGuard,createCertificates};

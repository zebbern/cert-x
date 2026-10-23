const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),net=require('node:net');
async function fixture(t){
 const temp=await fs.mkdtemp(path.join(os.tmpdir(),'cert-x-upgrade-test-')),runtime=path.join(temp,'runtime'),old=path.join(temp,'old'),next=path.join(temp,'new'),clients=[];
 await fs.mkdir(runtime);await fs.cp(path.join(__dirname,'../security'),old,{recursive:true});await fs.cp(old,next,{recursive:true});await fs.appendFile(path.join(next,'executor.cjs'),'\n// Installed revision fixture.\n');
 const create=(directory,options={})=>{let client;client=require(path.join(directory,'client.cjs')).createClient({root:runtime,onAdmission:message=>client.reply({requestId:message.requestId,allow:true}),...options});clients.push(client);return client;};
 t.after(async()=>{for(const client of clients)client.close();try{const descriptor=JSON.parse(await fs.readFile(path.join(runtime,'daemon.json')));process.kill(descriptor.pid);}catch{}await new Promise(resolve=>setTimeout(resolve,150));await fs.rm(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});});
 return {runtime,old,next,create,descriptor:async()=>JSON.parse(await fs.readFile(path.join(runtime,'daemon.json')))};
}
async function until(fn){for(let i=0;i<100;i++){if(await fn())return;await new Promise(resolve=>setTimeout(resolve,20));}throw Error('Lifecycle condition did not settle');}
test('updated installed code replaces only an authenticated idle daemon',async t=>{
 const f=await fixture(t),old=f.create(f.old);const first=await old.request('status',{}),before=await f.descriptor();assert.equal(first.needsRestart,undefined);old.close();await new Promise(resolve=>setTimeout(resolve,50));
 const next=f.create(f.next),second=await next.request('status',{}),after=await f.descriptor();assert.notEqual(before.pid,after.pid);assert.notEqual(first.runtimeRevision,second.runtimeRevision);assert.equal(second.runtimeRevision,second.clientRevision);assert.equal(second.lifecycle.idle,true);
});
test('an already loaded host detects replaced files and does not downgrade the daemon',async t=>{
 const f=await fixture(t),client=f.create(f.old);await client.request('status',{});const before=await f.descriptor();await fs.appendFile(path.join(f.old,'executor.cjs'),'\n// Changed during installation.\n');
 const status=await client.request('status',{});assert.equal(status.needsHostRestart,true);assert.match(status.reason,/reload cert-x/i);assert.equal((await f.descriptor()).pid,before.pid);
 await assert.rejects(client.request('dispatch',{action:'browser.list',args:{},context:{owner:'chat',runId:'new'}}),/updated.*reload cert-x/i);
});
test('active operations block upgrade, allow explicit cancellation, and are never replayed',async t=>{
 const f=await fixture(t),wire=[],sockets=new Set(),server=net.createServer(socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('data',data=>wire.push(data.toString()));socket.on('close',()=>sockets.delete(socket));});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(async()=>{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));});
 const url='http://127.0.0.1:'+server.address().port,old=f.create(f.old);await old.request('status',{});const before=await f.descriptor();
 const work=old.request('dispatch',{action:'transport.http1',args:{url,requestBase64:Buffer.from('POST /once HTTP/1.0\r\nContent-Length: 1\r\n\r\nx').toString('base64'),timeoutMs:30000},context:{owner:'chat',runId:'active-run',scope:{origins:[url]},lease:'lease'}});const ended=work.catch(error=>error);
 await until(()=>wire.length===1);const next=f.create(f.next),status=await next.request('status',{});assert.equal(status.needsRestart,true);assert.equal(status.lifecycle.activeOperations,1);assert.equal((await f.descriptor()).pid,before.pid);
 await assert.rejects(next.request('dispatch',{action:'transport.http1',args:{url},context:{owner:'chat',runId:'must-not-run'}}),/updated|reconnect/i);assert.equal(wire.length,1);
 await next.request('cancel',{runId:'active-run'});assert.ok(await ended instanceof Error);await until(async()=>{const value=await next.request('status',{});return !value.needsRestart;});assert.notEqual((await f.descriptor()).pid,before.pid);assert.equal(wire.length,1);
});
test('native connection loss rejects an in-flight operation and reconnect does not resend it',async t=>{
 const f=await fixture(t),wire=[],sockets=new Set(),server=net.createServer(socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('data',data=>wire.push(data.toString()));socket.on('close',()=>sockets.delete(socket));});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(async()=>{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));});
 const client=f.create(f.old),url='http://127.0.0.1:'+server.address().port;await client.request('status',{});const before=await f.descriptor();
 const work=client.request('dispatch',{action:'transport.http1',args:{url,requestBase64:Buffer.from('GET /once HTTP/1.0\r\n\r\n').toString('base64'),timeoutMs:30000},context:{owner:'chat',runId:'lost',scope:{origins:[url]},lease:'lease'}});const rejected=assert.rejects(work,/partial.*evidence/);
 await until(()=>wire.length===1);client.close();await rejected;await until(()=>sockets.size===0);const state=await client.request('status',{});assert.equal(state.lifecycle.idle,true);assert.equal((await f.descriptor()).pid,before.pid);assert.equal(wire.length,1);
});
test('an open managed browser survives a host update until explicitly closed',async t=>{
 const f=await fixture(t),installed=process.env.CERT_X_MANAGED_COMPONENTS||path.join(process.env.CERT_X_TEST_RUNTIME||path.join(process.env.LOCALAPPDATA||os.homedir(),'cert-x','security-runtime'),'installed.json');await fs.copyFile(installed,path.join(f.runtime,'installed.json'));
 const server=require('node:http').createServer((_req,res)=>res.end('<!doctype html><title>Persistent lifecycle</title><h1>Retained browser</h1>'));await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
 const url='http://127.0.0.1:'+server.address().port,context={owner:'owner',workspaceId:'workspace',runId:'browser-run',scope:{origins:[url]},lease:'persistent-lease'},old=f.create(f.old);
 const created=await old.request('dispatch',{action:'browser.create',args:{url,headless:true},context}),second=await old.request('dispatch',{action:'browser.create',args:{url,headless:true},context});assert.ok(created.sessionId);const before=await f.descriptor();old.close();await new Promise(resolve=>setTimeout(resolve,100));
 const next=f.create(f.next),busy=await next.request('status',{});assert.equal(busy.needsRestart,true);assert.equal(busy.lifecycle.retainedRuns.length,2);assert.equal((await f.descriptor()).pid,before.pid);
 await assert.rejects(next.request('dispatch',{action:'browser.navigate',args:{sessionId:created.sessionId,url},context}),/updated|reconnect/i);
 const closed=await next.request('dispatch',{action:'browser.close',args:{sessionId:created.sessionId},context});assert.equal(closed.state,'closed');
 assert.equal((await next.request('status',{})).needsRestart,true,'Closing one session cannot discard another session under the same run');
 await next.request('dispatch',{action:'browser.close',args:{sessionId:second.sessionId},context});
 const current=await next.request('status',{});assert.equal(current.needsRestart,undefined);assert.notEqual((await f.descriptor()).pid,before.pid);
 const retained=await next.request('dispatch',{action:'browser.list',args:{},context});assert.equal(retained.sessions.find(item=>item.sessionId===created.sessionId).state,'closed');
});
test('explicit authenticated restart stops active work instead of replaying it',async t=>{
 const f=await fixture(t),sockets=new Set(),wire=[],server=net.createServer(socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('data',data=>wire.push(data.toString()));socket.on('close',()=>sockets.delete(socket));});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(async()=>{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));});
 const client=f.create(f.old),url='http://127.0.0.1:'+server.address().port;await client.request('status',{});const before=await f.descriptor();
 const work=client.request('dispatch',{action:'transport.http1',args:{url,requestBase64:Buffer.from('POST /once HTTP/1.0\r\nContent-Length: 1\r\n\r\nx').toString('base64'),timeoutMs:30000},context:{owner:'chat',runId:'active',scope:{origins:[url]},lease:'lease'}});const ended=work.catch(error=>error);await until(()=>wire.length===1);
 await assert.rejects(client.request('restart',{}),/settings/);assert.equal((await client.request('status',{})).lifecycle.activeOperations,1);
 const result=await client.request('restart',{explicit:true});assert.equal(result.restarted,true);assert.ok(await ended instanceof Error);await until(()=>sockets.size===0);client.close();await new Promise(resolve=>setTimeout(resolve,50));
 await client.request('status',{});assert.notEqual((await f.descriptor()).pid,before.pid);assert.equal(wire.length,1);
});
async function legacy(t,invalidPid=false){
 const f=await fixture(t),{spawn}=require('node:child_process');
 // A real pre-handshake daemon fixture, under its exact owned installed path.
 await fs.writeFile(path.join(f.old,'daemon.cjs'),`const net=require('node:net'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');const root=process.argv[2],token=crypto.randomBytes(24).toString('hex'),pipe='\\\\\\\\.\\\\pipe\\\\cert-x-legacy-'+crypto.randomUUID();const server=net.createServer(s=>{let b='';s.on('error',()=>{});s.on('data',c=>{b+=c;let n;while((n=b.indexOf('\\n'))>=0){const m=JSON.parse(b.slice(0,n));b=b.slice(n+1);if(m.token===token)s.write(JSON.stringify({id:m.id,ok:true,result:{protocolVersion:1}})+'\\n');else if(m.op==='status')s.write(JSON.stringify({id:m.id,ok:true,result:{protocolVersion:1,components:{}}})+'\\n');}});});server.listen(pipe,()=>fs.writeFileSync(path.join(root,'daemon.json'),JSON.stringify({pid:process.pid,pipe,token,protocolVersion:1})));`);
 const child=spawn(process.execPath,[path.join(f.old,'daemon.cjs'),f.runtime],{windowsHide:true,stdio:'ignore'});t.after(()=>{try{child.kill();}catch{}});await until(async()=>{try{await f.descriptor();return true;}catch{return false;}});
 if(invalidPid){const descriptor=await f.descriptor();await fs.writeFile(path.join(f.runtime,'daemon.json'),JSON.stringify({...descriptor,pid:process.pid}));}
 return {...f,child,client:f.create(f.old)};
}
test('legacy restart requires live authentication and exact Windows process identity',async t=>{
 const f=await legacy(t);const status=await f.client.request('status',{});assert.equal(status.needsRestart,true);
 const result=await f.client.request('restart',{explicit:true});assert.equal(result.legacy,true);await until(()=>f.child.exitCode!==null||f.child.signalCode!==null);
 // Prevent cleanup from treating the now-exited fixture PID as a live owner.
 await fs.unlink(path.join(f.runtime,'daemon.json')).catch(()=>{});
});
test('legacy restart refuses a substituted PID despite a valid pipe token',async t=>{
 const f=await legacy(t,true);try{await f.client.request('status',{});await assert.rejects(f.client.request('restart',{explicit:true}),/identity does not match|could not be verified/);assert.equal(f.child.exitCode,null);}
 finally{await fs.writeFile(path.join(f.runtime,'daemon.json'),JSON.stringify({...await f.descriptor(),pid:f.child.pid}));}
});

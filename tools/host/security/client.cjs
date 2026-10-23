'use strict';
const net=require('node:net'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),{spawn}=require('node:child_process');
const {runtimeRevision}=require('./revision.cjs'),REVISION=runtimeRevision();
const RESTART='The local runtime was updated. Close active browser sessions and stop running security operations, then reconnect to apply it.';
function createClient({root=process.env.CERT_X_SECURITY_ROOT||path.join(process.env.LOCALAPPDATA||os.homedir(),'cert-x','security-runtime'),onAdmission,onEvent,mcpCall}={}) {
 let socket,connecting,hello,connectedDescriptor;
 const pending=new Map(),admissions=new Map(),mcpControllers=new Map();
 function rpc(stream,op,args,signal,auth) {
  signal?.throwIfAborted();
  return new Promise((resolve,reject)=>{
   const id=crypto.randomUUID();
   const abort=()=>{if(stream.writable)stream.write(JSON.stringify({id:crypto.randomUUID(),op:'cancel',args:op==='setup'?{setup:true}:{runId:args?.context?.runId||args?.runId}})+'\n');};
   signal?.addEventListener('abort',abort,{once:true});
   pending.set(id,{stream,resolve:value=>{signal?.removeEventListener('abort',abort);resolve(value);},reject:error=>{signal?.removeEventListener('abort',abort);reject(error);}});
   stream.write(JSON.stringify(auth?{id,token:auth.token,revision:REVISION}:{id,op,args})+'\n');
  });
 }
 async function attach(data) {
  const stream=net.connect(data.pipe);
  await new Promise((resolve,reject)=>{stream.once('connect',resolve);stream.once('error',reject);});
  socket=stream;let buffer='';
  stream.on('data',chunk=>{
   buffer+=chunk;if(buffer.length>4*1024*1024){stream.destroy(Error('Executor message exceeded the supported frame size'));return;}
   let at;while((at=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,at);buffer=buffer.slice(at+1);let message;try{message=JSON.parse(line);}catch{stream.destroy();return;}
    if(message.event==='admission'){admissions.set(message.requestId,stream);onAdmission?.({event:'security_admission',requestId:message.requestId,...message.payload});}
    else if(message.event==='mcp'){
     const controller=new AbortController();mcpControllers.set(message.requestId,{controller,stream});
     Promise.resolve().then(()=>mcpCall(message.payload.config,message.payload.name,message.payload.args,controller.signal)).finally(()=>mcpControllers.delete(message.requestId)).then(result=>{if(stream.writable)stream.write(JSON.stringify({replyTo:message.requestId,ok:true,result})+'\n');},error=>{if(stream.writable)stream.write(JSON.stringify({replyTo:message.requestId,ok:false,error:error.message})+'\n');});
    }else if(message.event==='mcp_cancel')mcpControllers.get(message.requestId)?.controller.abort();
    else if(message.event==='admission_cancel')admissions.delete(message.requestId);
    else if(message.event==='event')onEvent?.({event:'security_event',result:message.result});
    else {const entry=pending.get(message.id);if(entry?.stream===stream){pending.delete(message.id);message.ok?entry.resolve(message.result):entry.reject(Error(message.error));}}
   }
  });
  stream.on('error',()=>{});
  stream.on('close',()=>{
   if(socket===stream){socket=null;hello=null;}
   for(const [id,entry]of pending)if(entry.stream===stream){pending.delete(id);entry.reject(Error('Security executor disconnected. The operation outcome may be partial; inspect retained evidence before retrying.'));}
   for(const [id,owner]of admissions)if(owner===stream)admissions.delete(id);
   for(const [id,entry]of mcpControllers)if(entry.stream===stream){entry.controller.abort();mcpControllers.delete(id);}
  });
  try{hello=await rpc(stream,null,null,null,data);connectedDescriptor={...data};return hello;}catch(error){stream.destroy();throw error;}
 }
 async function negotiate() {
  if(runtimeRevision()!==REVISION)return false; // Loaded host code must not replace a newer daemon.
  if(hello?.revision===REVISION)return true;
  if(!hello?.lifecycleVersion)return false;
  const outcome=await rpc(socket,'upgrade_idle',{expectedRevision:hello.revision,nextRevision:REVISION});
  if(!outcome.accepted)return false;
  const old=socket;await new Promise(resolve=>{if(old.destroyed)return resolve();old.once('close',resolve);old.end();});return true;
 }
 async function connect() {
  if(connecting)return connecting;
  connecting=(async()=>{
   if(socket?.writable){await negotiate();if(socket?.writable)return;}
   await fs.mkdir(root,{recursive:true});let descriptor;
   try{descriptor=JSON.parse(await fs.readFile(path.join(root,'daemon.json'),'utf8'));}catch{}
   if(descriptor){try{await attach(descriptor);}catch(error){if(socket?.writable)throw error;}
    if(socket?.writable){await negotiate();if(socket?.writable)return;}}
   const child=spawn(process.execPath,[path.join(__dirname,'daemon.cjs'),root],{windowsHide:true,detached:true,stdio:'ignore'});child.unref();
   for(let i=0;i<100;i++){
    await new Promise(resolve=>setTimeout(resolve,100));
    try{descriptor=JSON.parse(await fs.readFile(path.join(root,'daemon.json'),'utf8'));await attach(descriptor);if(hello?.revision===REVISION)return;if(!await negotiate())return;}catch(error){if(socket?.writable)throw error;}
   }
   throw Error('Managed security executor did not start');
  })().finally(()=>{connecting=null;});return connecting;
 }
 return {
  async request(op,args,signal){
   await connect();signal?.throwIfAborted();const hostChanged=runtimeRevision()!==REVISION,outdated=hello?.revision!==REVISION||hostChanged;
   if(op==='restart'){
    if(args?.explicit!==true)throw Error('Restart the local runtime from Security testing settings.');
    if(hello?.lifecycleVersion)return rpc(socket,'restart_runtime',{explicit:true},signal);
    const result=await require('./restart.cjs').stopLegacyDaemon(connectedDescriptor,{root,script:path.join(__dirname,'daemon.cjs'),authenticated:!!hello});
    socket?.destroy();return result;
   }
   const cleanup=op==='cancel'||op==='dispatch'&&/\.(?:close|stop|cleanup|cancelJob)$/.test(args?.action||'');
   const reason=hostChanged?'The native host was updated. Stop existing local operations, then reload cert-x to reconnect the updated host.':RESTART;
   if(outdated&&op!=='status'&&!cleanup)throw Error(reason);
   const result=await rpc(socket,op,args,signal);
   return op==='status'?{...result,runtimeRevision:hello?.revision||null,clientRevision:REVISION,...(outdated?{needsRestart:true,needsHostRestart:hostChanged,reason}:{})}:result;
  },
  reply({requestId,allow,error}){const stream=admissions.get(requestId);if(!stream?.writable)throw Error('Admission request expired');admissions.delete(requestId);stream.write(JSON.stringify({replyTo:requestId,ok:allow===true,result:{allow:allow===true},error:error||'Security request denied'})+'\n');return {received:true};},
  close(){socket?.destroy();}
 };
}
module.exports={createClient};

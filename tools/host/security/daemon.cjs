'use strict';
const net=require('node:net'),fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {createSecurityExecutor}=require('./executor.cjs'),{AsyncLocalStorage}=require('node:async_hooks');
const REVISION=require('./revision.cjs').runtimeRevision();
async function start(root) {
 await fs.mkdir(root,{recursive:true});
 const token=crypto.randomBytes(32).toString('hex'),suffix=crypto.createHash('sha256').update(root).digest('hex').slice(0,20),pipe=process.platform==='win32'?'\\\\.\\pipe\\cert-x-security-'+suffix:path.join(root,'executor.sock');
 const clients=new Map(),pending=new Map(),dispatchClient=new AsyncLocalStorage();let closing=false;
 const send=(socket,message)=>{if(socket?.writable)socket.write(JSON.stringify(message)+'\n');};
 function request(kind,payload,signal,selected) {
  return new Promise((resolve,reject)=>{
   const socket=selected||dispatchClient.getStore();if(!socket?.writable)return reject(Error('Native security connection is unavailable'));signal?.throwIfAborted();
   const id=crypto.randomUUID(),duration=kind==='mcp'?Math.max(150000,(Number(payload.args?.timeoutSeconds||payload.args?.timeout_seconds||payload.args?.timeout||0)+30)*1000):30000;
   const settle=(error,result)=>{const item=pending.get(id);if(!item)return;clearTimeout(item.timer);signal?.removeEventListener('abort',abort);pending.delete(id);error?reject(error):resolve(result);};
   const abort=()=>{send(socket,{event:kind+'_cancel',requestId:id});settle(Error('Managed operation cancelled'));};
   const timer=setTimeout(()=>{send(socket,{event:kind+'_cancel',requestId:id});settle(Error('Managed bridge operation timed out'));},duration);
   pending.set(id,{socket,timer,settle});signal?.addEventListener('abort',abort,{once:true});send(socket,{event:kind,requestId:id,payload});
  });
 }
 const executor=createSecurityExecutor({root,admit:context=>request('admission',{owner:context.owner,workspaceId:context.workspaceId,runId:context.runId,lease:context.lease,request:context.request},context.signal,clients.get(context.connectionId)),mcpCall:(config,name,args,signal)=>request('mcp',{config,name,args},signal),onEvent:result=>{for(const client of clients.values())send(client,{event:'event',result});}});
 async function removeDescriptor(){try{const file=path.join(root,'daemon.json'),stored=JSON.parse(await fs.readFile(file,'utf8'));if(stored.token===token)await fs.unlink(file);}catch(error){if(error.code!=='ENOENT')throw error;}}
 async function close(beforeDisconnect){closing=true;try{await executor.close();await removeDescriptor();beforeDisconnect?.();for(const client of clients.values())client.end();await new Promise(resolve=>server.close(resolve));}catch(error){closing=false;throw error;}}
 const server=net.createServer(socket=>{
  const connectionId=crypto.randomUUID();let buffer='',authenticated=false,compatible=false;
  socket.on('data',chunk=>{
   buffer+=chunk;if(buffer.length>2*1024*1024){socket.destroy();return;}
   let at;while((at=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,at);buffer=buffer.slice(at+1);let message;try{message=JSON.parse(line);}catch{socket.destroy();return;}
    if(!authenticated){if(message.token!==token){socket.destroy();return;}authenticated=true;compatible=message.revision===REVISION;clients.set(connectionId,socket);send(socket,{id:message.id,ok:true,result:{protocolVersion:1,lifecycleVersion:1,revision:REVISION}});continue;}
    if(message.replyTo){const entry=pending.get(message.replyTo);if(entry?.socket===socket)entry.settle(message.ok===false?Error(message.error||'Denied'):null,message.result);continue;}
    void dispatchClient.run(socket,async()=>{
     try{
      if(closing)throw Error('Local runtime restart is in progress. Reconnect before starting work.');
      if(message.op==='restart_runtime'){
       if(message.args?.explicit!==true)throw Error('An explicit settings action is required to restart the local runtime.');
       await close(()=>send(socket,{id:message.id,ok:true,result:{restarted:true,stoppedActiveTesting:true}}));return;
      }
      if(message.op==='upgrade_idle'){
       if(message.args?.expectedRevision!==REVISION)throw Error('Daemon revision changed during upgrade negotiation.');
       closing=true;const activity=await executor.lifecycle();
       if(!activity.idle){closing=false;send(socket,{id:message.id,ok:true,result:{accepted:false,needsRestart:true,activity}});return;}
       await removeDescriptor();send(socket,{id:message.id,ok:true,result:{accepted:true,revision:REVISION}});
       setImmediate(()=>{void close().catch(()=>{for(const client of clients.values())client.destroy();server.close();});});return;
      }
      const cleanup=message.op==='cancel'||message.op==='dispatch'&&/\.(?:close|stop|cleanup|cancelJob)$/.test(message.args?.action||'');
      if(!compatible&&message.op!=='status'&&!cleanup)throw Error('Local host and executor revisions differ. Reconnect the updated native host before starting work.');
      let result;
      if(message.op==='status')result={...await executor.status(),revision:REVISION,lifecycle:await executor.lifecycle()};
      else if(message.op==='setup')result=await executor.setup(message.args);
      else if(message.op==='cancel')result=message.args?.setup===true?executor.cancelSetup():await executor.cancel(message.args?.runId);
      else if(message.op==='dispatch')result=await executor.dispatch(message.args.action,message.args.args,{...message.args.context,connectionId});
      else throw Error('Unknown security daemon operation');
      send(socket,{id:message.id,ok:true,result});
     }catch(error){send(socket,{id:message.id,ok:false,error:error.message});}
    });
   }
  });
  socket.on('error',()=>{});
  socket.on('close',()=>{clients.delete(connectionId);for(const entry of [...pending.values()])if(entry.socket===socket)entry.settle(Error('Native connection closed'));void executor.disconnect(connectionId).catch(()=>{});});
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(pipe,resolve);});
 await fs.writeFile(path.join(root,'daemon.json'),JSON.stringify({pid:process.pid,pipe,token,protocolVersion:1,lifecycleVersion:1,revision:REVISION}),{mode:0o600});
 process.on('SIGTERM',()=>{void close().finally(()=>process.exit(0));});
 return {close,revision:REVISION};
}
if(require.main===module)start(process.argv[2]).catch(()=>process.exit(1));module.exports={start};

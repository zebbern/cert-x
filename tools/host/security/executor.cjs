'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {createSetup}=require('./setup.cjs'),{createTransports,checkScope}=require('./transports.cjs'),{createBrowsers}=require('./browser.cjs');
function createSecurityExecutor({root=path.join(process.env.LOCALAPPDATA||os.homedir(),'cert-x','security-runtime'),admit,onEvent=()=>{},mcpCall,lockRoot}={}){
 const active=new Map(),retained=new Map();let settingUp=false,setupDone=Promise.resolve(),finishSetup;
 const emit=event=>{
  if(event.type==='candidate_complete'&&event.jobId)retained.delete('job:'+event.jobId);
  if(event.type==='lease_released'){
   const matches=[...retained].filter(([,item])=>item.runId===event.runId&&item.owner===event.owner&&item.lease===event.leaseId);
   // An ambiguous shared lease cannot prove that every session closed.
   if(matches.length===1)retained.delete(matches[0][0]);
  }
  onEvent(event);
 };
 const installer=createSetup({root,lockRoot,onEvent:emit});
 const admission=async payload=>{payload.signal?.throwIfAborted();if(!(payload.request.kind==='control'&&['oast','zap','browser','transport'].includes(payload.request.backend)))checkScope(payload.request.url,payload);if(typeof admit!=='function')throw Error('Security admission bridge is unavailable');const result=await admit(payload);if(result?.allow===false||result===false)throw Error(result?.error||'Security request denied');payload.signal?.throwIfAborted();return result;};
 const shared={root,componentPath:installer.componentPath,admit:admission,onEvent,mcpCall,resolveSecret:async ref=>{if(!ref||typeof ref!=='object')throw Error('Use an explicit private secret reference');if(ref.envFileRef){if(!path.isAbsolute(ref.envFileRef))throw Error('Secret file reference must be absolute');const content=await fs.readFile(ref.envFileRef,'utf8'),name=ref.name||'WEBHOOK_SITE_API_KEY';if(!/^[A-Z_][A-Z0-9_]*$/.test(name))throw Error('Invalid secret name');const line=content.split(/\r?\n/).find(x=>x.startsWith(name+'='));if(!line)throw Error('Requested secret is absent from the selected file');return line.slice(name.length+1).trim().replace(/^(['"])(.*)\1$/,'$2');}if(ref.secretRef){const id=String(ref.secretRef);if(!/^[a-f0-9-]{36}$/.test(id))throw Error('Invalid private secret reference');return fs.readFile(path.join(root,'secrets',id),'utf8');}throw Error('Unsupported secret reference');},storeSecret:async value=>{await fs.mkdir(path.join(root,'secrets'),{recursive:true});const id=crypto.randomUUID();await fs.writeFile(path.join(root,'secrets',id),String(value),{mode:0o600});return {secretRef:id};}};
 shared.onEvent=emit;
 const browsers=createBrowsers(shared),transports=createTransports(shared),plugins={};
 function plugin(name){if(!plugins[name]){const mod=require('./'+name+'.cjs'),factory=mod.createOast||mod.createZap||mod.createOastRuntime||mod.createZapRuntime||mod.default||mod;plugins[name]=factory(shared);}return plugins[name];}
 async function dispatch(action,args={},context={}){
  if(typeof context.owner!=='string'||!context.owner||typeof context.runId!=='string'||!context.runId)throw Error('Security operations require owner and runId');
  const controller=new AbortController(),abort=()=>controller.abort();context.signal?.addEventListener('abort',abort,{once:true});if(context.signal?.aborted)abort();
  const ctx={...context,signal:controller.signal},token=crypto.randomUUID();active.set(token,{runId:context.runId,connectionId:context.connectionId,controller});
  try{
   let result;if(action.startsWith('browser.'))result=await browsers.dispatch(action,args,ctx);
   else if(action.startsWith('transport.'))result=await transports.dispatch(action,args,ctx);
   else if(action.startsWith('oast.'))result=await plugin('oast').dispatch(action,args,ctx);
   else if(action.startsWith('zap.'))result=await plugin('zap').dispatch(action,args,ctx);
   else throw Error('Unknown managed security action');
   const resource=result?.jobId?'job:'+result.jobId:result?.sessionId?'browser:'+result.sessionId:result?.zapId?'zap:'+result.zapId:null;
   if(resource&&(result?.persistent===true||action==='zap.start')&&!retained.has(resource))retained.set(resource,{runId:context.runId,owner:context.owner,kind:action.split('.')[0],lease:result.leaseId||context.lease,connectionId:context.connectionId});
   if(resource&&/\.(?:close|stop|cleanup|cancelJob)$/.test(action))retained.delete(resource);
   return result;
  }finally{active.delete(token);context.signal?.removeEventListener('abort',abort);}
 }
 return {dispatch,async lifecycle(){return {idle:!settingUp&&active.size===0&&retained.size===0,setup:settingUp,activeOperations:active.size,retainedRuns:[...retained.values()].map(({runId,owner,kind})=>({runId,owner,kind}))};},async status(){const status=await installer.status(),c=status.components;return {...status,capabilities:['browser','http1','http2','websocket','oast','zap'],availability:{browser:!!(c.node?.ready&&c.chromium?.ready),http1:true,http2:!!c.node?.ready,websocket:true,oast:!!c.webhook?.ready,zap:!!(c.zap?.ready&&c.jre?.ready&&c.node?.ready)},nodeVersion:process.versions.node};},async setup(args={}){if(settingUp)throw Error('Security setup is already running');settingUp=true;setupDone=new Promise(resolve=>{finishSetup=resolve;});try{const result=await installer.setup({...args,components:(args.components||['browser','zap','webhook']).map(x=>x==='webhook'?'oast':x)});if(args.components?.includes('webhook')&&args.options?.webhook){const config=args.options.webhook;let secretRef;if(config.apiKey)secretRef=await shared.storeSecret(config.apiKey);result.mcpConnection={id:'cert-x-webhook',label:'Webhook callbacks',command:await installer.componentPath('webhook'),args:['-I','-c','from server import run_server; run_server()'],...(config.envFileRef?{envFileRef:config.envFileRef}:secretRef||{})};}return result;}finally{settingUp=false;finishSetup();}},cancelSetup(){installer.cancel();return {cancelled:true,setup:true};},async cancel(runId){for(const entry of active.values())if(entry.runId===runId)entry.controller.abort();await browsers.cancel(runId);for(const value of Object.values(plugins))await value.cancel?.(runId);for(const [key,item]of retained)if(item.runId===runId)retained.delete(key);return {cancelled:true,runId};},async disconnect(connectionId){for(const entry of active.values())if(!connectionId||entry.connectionId===connectionId)entry.controller.abort();await browsers.disconnect(connectionId);for(const value of Object.values(plugins))await value.disconnect?.(connectionId);},async close(){installer.cancel();await setupDone;await this.disconnect();await browsers.close();for(const value of Object.values(plugins))await value.close?.();retained.clear();},componentPath:installer.componentPath};
}
module.exports={createSecurityExecutor};

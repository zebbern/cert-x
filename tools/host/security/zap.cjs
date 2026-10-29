'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),http=require('node:http'),net=require('node:net');
const {spawn,execFile}=require('node:child_process'),{promisify}=require('node:util'),{randomUUID,randomBytes}=require('node:crypto');
const {createGuard}=require('./zap-guard.cjs'),inScope=require('./oast.cjs').inScope;
const exec=promisify(execFile),pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const alive=child=>child&&child.exitCode===null&&child.signalCode===null;
function checkedApi(result){if(!result||typeof result!=='object')throw Error('ZAP API returned no result');if(result.code||result.success===false||String(result.Result||result.result||'').toUpperCase()==='FAIL')throw Error('ZAP '+(result.code||'operation failed')+': '+(result.message||result.detail||''));return result;}
const escape=value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
const originPattern=(scope,origin)=>scope.matchMode==='host'?'https?://'+(scope.includeSubdomains&&!new URL(origin).hostname.startsWith('[')&&!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(new URL(origin).hostname)?'(?:[^./:]+\\.)*':'')+escape(new URL(origin).hostname)+'(?::[0-9]{1,5})?':escape(origin);
async function port(){const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});const value=server.address().port;await new Promise(resolve=>server.close(resolve));return value;}
module.exports=function createZap({root,componentPath,admit,onEvent=()=>{}}){
 const directory=path.join(root,'zap-runs'),runs=new Map(),live=new Map();let writes=Promise.resolve();
 const ready=(async()=>{await fs.mkdir(directory,{recursive:true,mode:0o700});for(const name of await fs.readdir(directory))if(/^[a-f0-9-]{36}$/.test(name)){try{const run=JSON.parse(await fs.readFile(path.join(directory,name,'run.json'),'utf8'));if(['starting','running','stopping'].includes(run.state)){run.state='interrupted';run.error='Local executor restarted. No scan was replayed.';}runs.set(run.zapId,run);}catch(error){if(error.code!=='ENOENT')throw error;}}})();
 const save=run=>{const task=writes.then(async()=>{const file=path.join(directory,run.zapId,'run.json');await fs.writeFile(file+'.tmp',JSON.stringify(run),{mode:0o600});await fs.rename(file+'.tmp',file);});writes=task.catch(()=>{});return task;};
 const publicRun=run=>{const {apiKey,home,...rest}=run;return rest;};
 function owned(id,context){const run=runs.get(id);if(!run||run.owner!==context.owner)throw Error('ZAP run does not belong to this chat');return run;}
 async function api(run,section,kind,name,params={}){
  const url=new URL(`http://127.0.0.1:${run.port}/JSON/${section}/${kind}/${name}/`);for(const[key,value]of Object.entries(params))if(value!=null)url.searchParams.set(key,String(value));
  const response=await fetch(url,{headers:{'X-ZAP-API-Key':run.apiKey},signal:AbortSignal.timeout(30000)});if(!response.ok)throw Error('ZAP API HTTP '+response.status);
  let result;try{result=await response.json();}catch{throw Error('ZAP API returned invalid JSON');}return checkedApi(result);
 }
 async function persistWire(run,guard){const task=writes.then(()=>fs.writeFile(path.join(run.home,'traffic.json'),JSON.stringify(guard.evidence),{mode:0o600}));writes=task.catch(()=>{});await task;run.requestCount=guard.evidence.length;await save(run);}
 async function status(){let available=true,reason;try{await componentPath('zap');await componentPath('java');await componentPath('node');}catch(error){available=false;reason=error.message;}return {available,reason,backend:'ZAP',features:['passive','spider','ajax','openapi','active','evidence'],version:'2.17.0'};}
 async function start(args,context){
  if(!context.owner||!context.runId)throw Error('Owned run required');if(!inScope(args.url||args.target,context.scope))throw Error('ZAP target is outside run scope: '+(args.url||args.target)+'. Review target scope in Workspace settings.');
  const existing=[...runs.values()].find(run=>run.owner===context.owner&&run.runId===context.runId&&['starting','running'].includes(run.state));if(existing)return publicRun(existing);
  await admit({...context,request:{kind:'control',backend:'zap'}});
  const jar=await componentPath('zap'),java=await componentPath('java'),modules=await componentPath('node'),forge=require(path.join(modules,'node-forge'));
  const run={zapId:randomUUID(),owner:context.owner,workspaceId:context.workspaceId||null,runId:context.runId,state:'starting',target:args.url||args.target,createdAt:Date.now(),port:await port(),apiKey:randomBytes(32).toString('hex'),scope:context.scope,options:args,stages:[],findings:[],requestCount:0};
  // Never retain account headers in public settings/metadata.
  run.options={...args};delete run.options.headers;delete run.options.account;delete run.options.cookies;
  run.home=path.join(directory,run.zapId);await fs.mkdir(run.home,{recursive:true,mode:0o700});runs.set(run.zapId,run);await save(run);
  const controller=new AbortController(),signal=AbortSignal.any([controller.signal,...(context.signal?[context.signal]:[])]);let guard,child;
  try{
   guard=await createGuard({context:{...context,signal},admit,forge,WebSocket:require(path.join(modules,'ws')),onEvidence:()=>{persistWire(run,guard).catch(error=>{run.evidenceError=error.message;});}});
   const ca=path.join(run.home,'guard-ca.pem'),trust=path.join(run.home,'guard-trust.p12');await fs.writeFile(ca,guard.caPem,{mode:0o600});
   const keytool=path.join(path.dirname(java),process.platform==='win32'?'keytool.exe':'keytool');
   await exec(keytool,['-importcert','-noprompt','-alias','cert-x-guard','-file',ca,'-keystore',trust,'-storetype','PKCS12','-storepass','cert-x-private-trust'],{windowsHide:true,timeout:30000});
   const options=['-Djavax.net.ssl.trustStore='+trust,'-Djavax.net.ssl.trustStorePassword=cert-x-private-trust','-jar',jar,'-daemon','-silent','-host','127.0.0.1','-port',String(run.port),'-dir',run.home,
    '-config','api.key='+run.apiKey,'-config','api.addrs.addr.name=127.0.0.1','-config','api.addrs.addr.regex=false','-config','connection.proxyChain.enabled=true','-config','connection.proxyChain.hostName=127.0.0.1','-config','connection.proxyChain.port='+guard.port,'-config','connection.proxyChain.skipName=','-config','connection.proxyChain.authEnabled=true','-config','connection.proxyChain.userName='+guard.username,'-config','connection.proxyChain.password='+guard.password,'-config','autoupdate.checkOnStart=false'];
   if(args.ajax===true)options.push('-config','selenium.chromeBinary='+await componentPath('chromium'),'-config','selenium.chromeDriver='+await componentPath('chromedriver'));
   child=spawn(java,options,{cwd:path.dirname(jar),windowsHide:true,stdio:['ignore','pipe','pipe']});const info={child,guard,controller,context,logs:'',pipeline:null};live.set(run.zapId,info);
   for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>{info.logs=(info.logs+String(chunk).replaceAll(run.apiKey,'[private]').replaceAll(guard.password,'[private]')).slice(-12000);});
   child.once('error',error=>{run.error=error.message;});child.once('exit',code=>{if(['starting','running'].includes(run.state)){run.state='error';run.error='ZAP exited '+code;save(run).catch(()=>{});}guard.stop().catch(()=>{});});
   const end=Date.now()+(args.startupTimeoutMs||90000);let boot=false;
   while(Date.now()<end){signal.throwIfAborted();if(child.exitCode!==null)throw Error('ZAP failed to start: '+info.logs);try{const value=await api(run,'core','view','version');if(value.version){run.version=value.version;boot=true;break;}}catch{}await pause(400);}
   if(!boot)throw Error('ZAP startup timed out: '+info.logs);
   const created=await api(run,'context','action','newContext',{contextName:'cert-x-'+run.zapId});if(created.contextId==null)throw Error('ZAP did not create the owned context');run.contextId=created.contextId;run.contextName='cert-x-'+run.zapId;
   for(const origin of context.scope.origins)await api(run,'context','action','includeInContext',{contextName:run.contextName,regex:originPattern(context.scope,origin)+'(?:/.*)?'});
   for(const origin of context.scope.origins)for(const excluded of context.scope.excludePaths||[])await api(run,'context','action','excludeFromContext',{contextName:run.contextName,regex:originPattern(context.scope,origin)+escape(excluded)+'(?:[/?].*)?'});
   const scanners=await api(run,'ascan','view','scanners');const recursive=(scanners.scanners||[]).filter(rule=>/penetration testing kit|owasp ptk/i.test(rule.name)).map(rule=>rule.id);
   if(recursive.length)await api(run,'ascan','action','disableScanners',{ids:recursive.join(',')});
   if(Array.isArray(args.scannerIds)){await api(run,'ascan','action','disableAllScanners');await api(run,'ascan','action','enableScanners',{ids:args.scannerIds.filter(id=>!recursive.includes(String(id))).join(',')});}
   run.state='running';await save(run);
   info.pipeline=pipeline(run,args,info).catch(async error=>{if(!['cancelled','stopping'].includes(run.state)){run.state='error';run.error=error.message;}info.controller.abort();await guard.stop().catch(()=>{});try{await api(run,'core','action','shutdown');}catch{}await save(run);}).finally(async()=>{await persistWire(run,guard);});
   return publicRun(run);
  }catch(error){run.state='error';run.error=error.message;await save(run);controller.abort();if(child&&!child.killed)child.kill();await guard?.stop().catch(()=>{});throw Object.assign(Error(error.message),{zapId:run.zapId});}
 }
 async function stage(run,info,name,execute,poll){
  info.controller.signal.throwIfAborted();const record={name,state:'running',startedAt:Date.now()};run.stages.push(record);await save(run);const result=await execute();record.native=result;if(['spider','active'].includes(name)&&result?.scan==null)throw Error('ZAP did not return the '+name+' scan identifier');
  if(poll)for(;;){info.controller.signal.throwIfAborted();await admit({...info.context,request:{kind:'control',backend:'zap'}});const value=await poll(result);record.progress=value;if(value===100||value==='stopped')break;await pause(300);}
  record.state='completed';record.endedAt=Date.now();await save(run);
 }
 async function pipeline(run,args,info){
  const headers=Array.isArray(args.headers)?args.headers:Object.entries(args.headers||{}).map(([name,value])=>({name,value}));
  // Account headers are installed only in this owned ZAP home and target context.
  for(let i=0;i<headers.length;i++)await api(run,'replacer','action','addRule',{description:'cert-x-account-'+i,enabled:true,matchType:'REQ_HEADER',matchRegex:false,matchString:headers[i].name,replacement:headers[i].value,url:run.scope.origins.map(origin=>originPattern(run.scope,origin)).join('|')});
  if(args.openApi){const file=path.join(run.home,'openapi.json');await fs.writeFile(file,typeof args.openApi==='string'?args.openApi:JSON.stringify(args.openApi),{mode:0o600});await stage(run,info,'openapi',()=>api(run,'openapi','action','importFile',{file,contextId:run.contextId,target:run.target}));}
  await stage(run,info,'seed',()=>api(run,'core','action','accessUrl',{url:run.target,followRedirects:true}));
  if(args.spider!==false)await stage(run,info,'spider',()=>api(run,'spider','action','scan',{url:run.target,contextName:run.contextName,recurse:true}),async start=>Number((await api(run,'spider','view','status',{scanId:start.scan})).status));
  if(args.ajax===true){
   await api(run,'selenium','action','setOptionChromeDriverPath',{String:await componentPath('chromedriver')});
   await stage(run,info,'ajax',()=>api(run,'ajaxSpider','action','scan',{url:run.target,inScope:true,contextName:run.contextName,browserId:'chrome-headless'}),async()=>String((await api(run,'ajaxSpider','view','status')).status));
  }
  if(args.active!==false)await stage(run,info,'active',()=>api(run,'ascan','action','scan',{url:run.target,recurse:true,inScopeOnly:true,contextId:run.contextId,...(args.policy?{scanPolicyName:args.policy}:{})}),async start=>Number((await api(run,'ascan','view','status',{scanId:start.scan})).status));
  await stage(run,info,'passive',async()=>({}),async()=>Number((await api(run,'pscan','view','recordsToScan')).recordsToScan)===0?100:0);
  await collectFindings(run);run.state='completed';run.endedAt=Date.now();await save(run);onEvent({owner:run.owner,runId:run.runId,backend:'zap',state:'completed'});
 }
 async function collectFindings(run){let offset=0;const findings=[];for(;;){const value=await api(run,'core','view','alerts',{start:offset,count:100});if(!Array.isArray(value.alerts))throw Error('ZAP omitted alert list');findings.push(...value.alerts.map(alert=>({...alert,backend:'zap',nativeId:alert.id,ruleId:alert.pluginId,runId:run.runId,confirmation:'candidate'})));if(value.alerts.length<100)break;offset+=100;}run.findings=findings;await save(run);return findings;}
 async function stop(run){const previous=run.state;if(['starting','running','stopping'].includes(previous))run.state='stopping';await save(run);const info=live.get(run.zapId);info?.controller.abort(Error('ZAP stopped'));let shutdownError;
  if(alive(info?.child))try{await collectFindings(run);}catch(error){run.evidenceError=error.message;}
  try{await api(run,'core','action','shutdown');}catch(error){if(alive(info?.child))shutdownError=error;}
  if(info){await info.guard.stop();if(alive(info.child)){await Promise.race([new Promise(resolve=>info.child.once('exit',resolve)),pause(3000)]);if(alive(info.child)){info.child.kill();await Promise.race([new Promise(resolve=>info.child.once('exit',resolve)),pause(3000)]);}}await Promise.allSettled([info.pipeline]);await persistWire(run,info.guard);}
  if(alive(info?.child))throw Error('ZAP process cleanup is unconfirmed');run.state=['starting','running','stopping'].includes(previous)?'cancelled':previous;run.endedAt=Date.now();if(shutdownError)run.shutdownWarning=shutdownError.message;live.delete(run.zapId);await save(run);return publicRun(run);
 }
 async function dispatch(action,args={},context={}){await ready;action=action.replace(/^zap\./,'');if(action==='status'&&!args.zapId)return status();if(action==='start')return start(args,context);const run=owned(args.zapId,context);
  if(action==='stop')return stop(run);if(action==='progress'||action==='status'){if(live.has(run.zapId)&&run.state==='running')await collectFindings(run);return publicRun(run);}
  if(action==='findings'){if(live.has(run.zapId)&&run.state==='running')await collectFindings(run);const offset=args.offset||0,limit=args.limit||50;if(!Number.isInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>500)throw Error('Invalid findings page');return {zapId:run.zapId,findings:run.findings.slice(offset,offset+limit),total:run.findings.length,nextOffset:offset+limit<run.findings.length?offset+limit:null};}
  if(action==='evidence'||action==='export'){const evidence=live.get(run.zapId)?.guard.evidence||JSON.parse(await fs.readFile(path.join(run.home,'traffic.json'),'utf8').catch(error=>{if(error.code==='ENOENT')return '[]';throw error;}));const offset=args.offset||0,limit=args.limit||20;return {zapId:run.zapId,run:publicRun(run),requests:evidence.slice(offset,offset+limit),total:evidence.length,nextOffset:offset+limit<evidence.length?offset+limit:null};}
  throw Error('Unknown ZAP action');
 }
 async function cancel(runId,connectionId){await ready;for(const run of runs.values())if(live.has(run.zapId)&&(!runId||run.runId===runId)&&(!connectionId||live.get(run.zapId).context.connectionId===connectionId)&&['starting','running','stopping'].includes(run.state))await stop(run);}
 return{dispatch,status,cancel,disconnect:connectionId=>cancel(null,connectionId),close:async()=>{for(const run of runs.values())if(live.has(run.zapId))await stop(run);await writes;}};
};
module.exports.checkedApi=checkedApi;

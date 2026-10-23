'use strict';
const net=require('node:net'),tls=require('node:tls'),crypto=require('node:crypto'),path=require('node:path');
const {constants:{MAX_LENGTH:MAX_BUFFER_LENGTH}}=require('node:buffer');
const wire=require('./raw-wire.cjs'),{createEvidenceStore}=require('./raw-evidence.cjs');
const {bytes,frame,checkScope,PREFACE}=wire;
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
function positive(value,label){if(!Number.isSafeInteger(value)||value<1)throw Error(label+' must be a positive integer');return value;}
function pause(ms,signal){if(!ms)return Promise.resolve();return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{signal?.removeEventListener('abort',abort);resolve();},ms);const abort=()=>{clearTimeout(timer);reject(Error('Security transport cancelled'));};signal?.addEventListener('abort',abort,{once:true});});}
function websocketHandshake(target,args){
 const key=crypto.randomBytes(16).toString('base64');
 const raw=args.handshakeBase64===undefined?Buffer.from(`GET ${target.pathname+target.search} HTTP/1.1\r\nHost: ${target.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`):bytes(args.handshakeBase64,'handshakeBase64');
 const head=raw.toString('latin1');if(!head.endsWith('\r\n\r\n'))throw Error('WebSocket handshake must be complete');
 const match=/^GET ([^\r\n ]+) HTTP\/1\.1\r\n/.exec(head);if(!match)throw Error('WebSocket handshake requires GET HTTP/1.1');
 const fields=head.slice(match[0].length,-4).split('\r\n').map(line=>{const i=line.indexOf(':');if(i<1)throw Error('Malformed WebSocket handshake header');return [line.slice(0,i).toLowerCase(),line.slice(i+1).trim()];});
 const values=name=>fields.filter(x=>x[0]===name).map(x=>x[1]);
 const keys=values('sec-websocket-key'),hosts=values('host');
 if(keys.length!==1||Buffer.from(keys[0],'base64').length!==16||keys[0]!==Buffer.from(keys[0],'base64').toString('base64'))throw Error('Invalid WebSocket key');
 if(hosts.length!==1||!values('upgrade').some(x=>x.toLowerCase()==='websocket')||!values('connection').some(x=>x.toLowerCase().split(',').map(y=>y.trim()).includes('upgrade'))||values('sec-websocket-version').length!==1||values('sec-websocket-version')[0]!=='13')throw Error('Invalid WebSocket upgrade request');
 return {raw,key:keys[0]};
}
function acceptHandshake(data,key){const end=data.indexOf('\r\n\r\n');if(end<0)return null;const lines=data.subarray(0,end).toString('latin1').split('\r\n');if(!/^HTTP\/1\.[01] 101(?: |$)/.test(lines.shift()))throw Error('WebSocket upgrade refused: expected HTTP 101');const fields=lines.map(x=>{const i=x.indexOf(':');if(i<1)throw Error('Malformed WebSocket upgrade response');return [x.slice(0,i).toLowerCase(),x.slice(i+1).trim()];});const values=name=>fields.filter(x=>x[0]===name).map(x=>x[1]);const expected=crypto.createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');if(values('sec-websocket-accept').length!==1||values('sec-websocket-accept')[0]!==expected||!values('upgrade').some(x=>x.toLowerCase()==='websocket')||!values('connection').some(x=>x.toLowerCase().split(',').map(y=>y.trim()).includes('upgrade')))throw Error('WebSocket upgrade response failed Accept/Upgrade validation');return {status:101,headerBytes:end+4};}
function createTransports({admit,root,componentPath}={}){
 if(typeof admit!=='function')throw Error('Raw transports require admission');
 const evidence=createEvidenceStore(root||path.join(process.env.LOCALAPPDATA||process.cwd(),'cert-x','security-runtime'));
 async function authorize(context,request){context.signal?.throwIfAborted();const result=await admit({...context,request});if(result===false||result?.allow===false)throw Error(result?.error||'Raw transport admission denied');context.signal?.throwIfAborted();}
 async function plan(kind,args,context){
  const target=checkScope(args.url,context);if(target.port==='0')throw Error('Raw destination port must be between 1 and 65535');let writes=[],routes=[],handshake=null;
  if(kind==='http1'||kind==='desync'){
   const raw=bytes(args.requestBase64,'requestBase64');routes=wire.validateHttp1(raw,target,context,{malformedOptIn:kind==='desync'&&args.optIn===true});writes=[raw];
  }else if(kind==='http2'){
   if(typeof componentPath!=='function')throw Error('Managed pinned HTTP/2 codec is unavailable');
   const hpack=require(path.join(await componentPath('node'),'hpack.js'));
   if(args.requests){if(!Array.isArray(args.requests)||!args.requests.length)throw Error('HTTP/2 requests must be a nonempty array');writes=[...(args.preface===false?[]:[PREFACE]),...wire.encodeRequests(args.requests,target,hpack)];}
   else writes=[...(args.preface===false?[]:[PREFACE]),...(args.frames||[]).map(item=>item.rawBase64!==undefined?bytes(item.rawBase64):frame(item)),...(args.bytesBase64===undefined?[]:[bytes(args.bytesBase64,'bytesBase64')])];
   const parsed=wire.validateHttp2(Buffer.concat(writes),target,context,hpack);routes=parsed.routes;
   if(!routes.length&&!args.allowControlFrames)throw Error('HTTP/2 operation has no validated request route');
  }else if(kind==='websocket'){
   handshake=websocketHandshake(target,args);routes=wire.validateHttp1(handshake.raw,target,context);
   writes=[handshake.raw,...(args.frames||[]).map(item=>bytes(typeof item==='string'?item:item.rawBase64,'WebSocket frame'))];
  }else throw Error('Unknown raw transport');
  if(!writes.length||writes.every(x=>x.length===0))throw Error('No outbound bytes provided');
  return {target,writes,routes,handshake};
 }
 async function exchange(kind,args,context){
  const {target,writes,routes,handshake}=await plan(kind,args,context);
  const secure=['https:','wss:'].includes(target.protocol),port=Number(target.port)||(secure?443:80),timeout=positive(args.timeoutMs??context.config?.transportTimeoutMs??10000,'timeoutMs'),cap=positive(args.maxResponseBytes??262144,'maxResponseBytes');
  if(cap>MAX_BUFFER_LENGTH)throw Error('maxResponseBytes exceeds the runtime buffer capacity');
  if(args.delayMs!==undefined&&(!Number.isSafeInteger(args.delayMs)||args.delayMs<0))throw Error('delayMs must be a non-negative integer');
  const started=Date.now(),record={transport:kind,url:target.href,logicalTargets:routes,sent:[],response:{},connections:[],timedOut:false,truncated:false,classification:'transport_evidence'};
  let socket,finished=false,size=0,handshakeDone=false,writeStarted=false,writeComplete=false,terminalError=null;const chunks=[];
  try{
   await authorize(context,{url:target.href,method:'CONNECT',kind:'raw_connect',bytes:0,targets:routes});
   await new Promise((resolve,reject)=>{
    const settle=error=>{if(finished)return;finished=true;clearTimeout(timer);context.signal?.removeEventListener('abort',abort);socket?.destroy();error?reject(error):resolve();};
    const abort=()=>settle(Error('Security transport cancelled'));
    const timer=setTimeout(()=>{record.timedOut=true;settle();},timeout);
    context.signal?.addEventListener('abort',abort,{once:true});
    const options={host:target.hostname.replace(/^\[|\]$/g,''),port};
    if(secure){Object.assign(options,{servername:net.isIP(options.host)?undefined:options.host,rejectUnauthorized:args.ignoreTlsErrors!==true,ALPNProtocols:kind==='http2'?['h2']:['http/1.1']});socket=tls.connect(options);}else socket=net.connect(options);
    const send=async(index)=>{if(finished)return;context.signal?.throwIfAborted();const data=writes[index];await authorize(context,{url:target.href,method:kind.toUpperCase(),kind:'raw_send',bytes:data.length,index,targets:routes});if(finished)return;writeStarted=true;const item={index,bytes:data.length,base64:data.toString('base64'),sha256:digest(data),atMs:Date.now()-started,state:'attempted'};record.sent.push(item);await new Promise((yes,no)=>socket.write(data,error=>error?no(error):yes()));item.state='write_completed';await pause(args.delayMs||0,context.signal);};
    socket.on('data',chunk=>{const left=cap-size;if(left>0){chunks.push(chunk.subarray(0,left));size+=Math.min(left,chunk.length);}if(chunk.length>left){record.truncated=true;settle();return;}if(handshake&&!handshakeDone){try{const value=acceptHandshake(Buffer.concat(chunks),handshake.key);if(value){handshakeDone=true;record.handshake=value;Promise.resolve().then(async()=>{for(let i=1;i<writes.length;i++)await send(i);writeComplete=true;if(args.endAfterWrite===true)socket.end();}).catch(settle);}}catch(error){settle(error);}}if(kind==='http2'&&args.requests){const parsed=wire.parseFrames(Buffer.concat(chunks),{allowIncomplete:true});const ended=new Set(parsed.frames.filter(x=>(x.type===0||x.type===1)&&(x.flags&1)).map(x=>x.streamId));if(parsed.frames.some(x=>x.type===3||x.type===7)||routes.filter(x=>x.streamId).every(x=>ended.has(x.streamId)))settle();}});
    socket.once('error',settle);socket.once('end',()=>settle());
    socket.once(secure?'secureConnect':'connect',()=>{record.connections.push({atMs:Date.now()-started,remoteAddress:socket.remoteAddress,remotePort:socket.remotePort,localAddress:socket.localAddress,localPort:socket.localPort,tls:secure?{protocol:socket.getProtocol(),alpn:socket.alpnProtocol,authorized:socket.authorized}:null});Promise.resolve().then(async()=>{if(kind==='http2'&&secure&&socket.alpnProtocol!=='h2')throw Error('Peer did not negotiate HTTP/2');const count=handshake?1:writes.length;for(let i=0;i<count;i++)await send(i);if(!handshake){writeComplete=true;if(args.endAfterWrite===true)socket.end();}}).catch(settle);});
   });
  }catch(error){terminalError=error;}finally{socket?.destroy();const response=Buffer.concat(chunks);record.response={bytes:response.length,base64:response.toString('base64'),sha256:digest(response)};if(kind==='websocket'&&!handshakeDone){record.handshake={confirmed:false};record.classification='inconclusive_no_upgrade';}if(kind==='http2'){const parsed=wire.parseFrames(response,{allowIncomplete:true});record.response.frames=parsed.frames.map(x=>({type:x.type,flags:x.flags,streamId:x.streamId,offset:x.offset,length:x.length,payloadBase64:x.payload.toString('base64')}));record.response.incompleteFrame=parsed.incomplete;if(args.requests&&!terminalError){const protocolError=parsed.frames.find(x=>x.type===3||x.type===7&&(x.payload.length<8||x.payload.readUInt32BE(4)!==0));const ended=new Set(parsed.frames.filter(x=>(x.type===0||x.type===1)&&(x.flags&1)).map(x=>x.streamId));const headed=new Set(parsed.frames.filter(x=>x.type===1).map(x=>x.streamId));if(protocolError)terminalError=Error('HTTP/2 peer reported '+(protocolError.type===3?'RST_STREAM':'GOAWAY'));else if(parsed.incomplete||record.truncated||routes.filter(x=>x.streamId).some(x=>!headed.has(x.streamId)||!ended.has(x.streamId)))terminalError=Error('Structured HTTP/2 request has no complete response');}}record.elapsedMs=Date.now()-started;record.writeStarted=writeStarted;record.writeComplete=writeComplete;if(terminalError)record.error={message:terminalError.message,code:terminalError.code||null};try{record.evidence=await evidence.save(record,context);}catch(saveError){if(!terminalError)terminalError=saveError;else terminalError.message+='; evidence persistence failed: '+saveError.message;}}
  if(terminalError){if(record.evidence)terminalError.message+='; raw evidence '+record.evidence.evidenceId;throw terminalError;}
  return Buffer.byteLength(JSON.stringify(record))<600000?record:{transport:kind,url:target.href,logicalTargetsCount:routes.length,primaryLogicalTargetSha256:routes[0]?digest(routes[0].url):null,response:{bytes:record.response.bytes,sha256:record.response.sha256},sentCount:record.sent.length,sentBytes:record.sent.reduce((sum,item)=>sum+item.bytes,0),timedOut:record.timedOut,truncated:record.truncated,elapsedMs:record.elapsedMs,classification:record.classification,evidence:record.evidence};
 }
 async function dispatch(action,args={},context={}){if(!context.owner||!context.runId)throw Error('Raw transport requires owner and runId');const kind=action.replace(/^transport\./,'');if(kind==='evidence'){await authorize(context,{kind:'control',backend:'transport',url:'raw-evidence://local',method:'READ',bytes:0});return evidence.read(args,context);}if(kind==='desync'){if(args.optIn!==true)throw Error('Desynchronization probes require explicit per-run opt-in');return desync(args,context);}return exchange(kind,args,context);}
 async function desync(args,context){
  if(args.responseQueue)return desyncResponseQueue(args,context);
  if(!args.observation?.url||!args.observation?.requestBase64||!args.observation?.expectedPath)throw Error('Desync requires a backend observation endpoint');
  const repeats=positive(args.repeats??2,'repeats');const observationTarget=checkScope(args.observation.url,context),observationRequest=bytes(args.observation.requestBase64,'observation.requestBase64');wire.validateHttp1(observationRequest,observationTarget,context);
  const protocol=args.protocol||'http1';if(!['http1','http2'].includes(protocol))throw Error('Desync protocol must be http1 or http2');
  if(protocol==='http1'){const control=bytes(args.controlBase64,'controlBase64');wire.validateHttp1(control,checkScope(args.url,context),context,{malformedOptIn:true});}
  else if(!args.controlFrames&&!args.controlRequests)throw Error('HTTP/2 desync requires controlFrames or controlRequests');
  if(typeof args.observation.expectedPath!=='string'||!args.observation.expectedPath.startsWith('/')||args.observation.expectedPath.startsWith('//'))throw Error('Observation expectedPath must be an origin-form path');
  checkScope(new URL(args.observation.expectedPath,args.url).href,context);
  if(repeats<2)throw Error('Desync confirmation requires at least two paired repetitions');
  const attempts=[];let error=null;
  try{for(let i=0;i<repeats;i++)for(const variant of ['control','probe']){
   context.signal?.throwIfAborted();
   if(args.reset){const resetTarget=checkScope(args.reset.url,context),resetRequest=bytes(args.reset.requestBase64,'reset.requestBase64');wire.validateHttp1(resetRequest,resetTarget,context);const reset=await exchange('http1',{url:args.reset.url,requestBase64:args.reset.requestBase64,timeoutMs:args.timeoutMs},context);const parsed=reset.response.base64&&wire.parseHttp1Responses(Buffer.from(reset.response.base64,'base64'));if(reset.timedOut||reset.truncated||parsed?.responses.length!==1||parsed.incomplete||parsed.responses[0].status!==200)throw Error('Desync fixture reset did not confirm HTTP 200');}
   const probeArgs=variant==='control'?(protocol==='http2'?{...args,frames:args.controlFrames,requests:args.controlRequests,bytesBase64:undefined}:{...args,requestBase64:args.controlBase64}):args;
   const sample=await exchange(protocol==='http2'?'http2':'desync',probeArgs,context);
   const observed=await exchange('http1',{url:args.observation.url,requestBase64:args.observation.requestBase64,timeoutMs:args.timeoutMs},context);
   let requests=null,observationError=null;try{const parsed=wire.parseHttp1Responses(Buffer.from(observed.response.base64,'base64'));if(parsed.responses.length!==1||parsed.incomplete||parsed.responses[0].status!==200)throw Error('Observation requires one complete HTTP 200 response');const body=JSON.parse(Buffer.from(parsed.responses[0].bodyBase64,'base64').toString('utf8'));if(!Array.isArray(body.requests)||body.requests.some(x=>typeof x.path!=='string'))throw Error('Observation body requires requests with paths');requests=body.requests;}catch(e){observationError=e.message;}
   attempts.push({index:i,variant,sampleEvidenceId:sample.evidence.evidenceId,observationEvidenceId:observed.evidence.evidenceId,requests,observationError,timedOut:sample.timedOut,truncated:sample.truncated,primaryLogicalTargetSha256:sample.primaryLogicalTargetSha256||digest(sample.logicalTargets?.[0]?.url||'')});
  }}catch(e){error=e;}
  const expected=args.observation.expectedPath;let confirmed=!!args.reset&&!error&&attempts.length===repeats*2;
  for(const item of attempts){const seen=item.requests?.some(x=>x.path===expected)||false;if(item.variant==='probe'?!seen:seen)confirmed=false;if(item.observationError||item.truncated||item.primaryLogicalTargetSha256===digest(new URL(expected,args.url).href))confirmed=false;}
  const result={transport:'desync',classification:confirmed?'confirmed_with_backend_observation':'inconclusive',repeats,attempts,error:error?.message||null,partial:!!error};result.evidence=await evidence.save(result,context);if(error){error.message+='; raw evidence '+result.evidence.evidenceId;throw error;}return Buffer.byteLength(JSON.stringify(result))<600000?result:{transport:'desync',classification:result.classification,repeats,attemptsCount:attempts.length,partial:false,evidence:result.evidence};
 }
 async function desyncResponseQueue(args,context){
  if((args.protocol||'http1')!=='http1')throw Error('Response queue mode currently supports HTTP/1 only');
  const spec=args.responseQueue,repeats=positive(args.repeats??2,'repeats');
  if(repeats<2)throw Error('Response queue confirmation requires at least two paired repetitions');
  if(!['cl','te'].includes(spec.frontFraming))throw Error('Response queue requires explicit frontFraming: cl or te');
  for(const key of ['outer','followup','injected'])if(!spec[key]||typeof spec[key].route!=='string'||!spec[key].route.startsWith('/')||spec[key].route.startsWith('//')||typeof spec[key].marker!=='string'||!spec[key].marker)throw Error('Response queue requires origin-form route and controlled marker for '+key);
  if(new Set(['outer','followup','injected'].map(key=>spec[key].route)).size!==3||new Set(['outer','followup','injected'].map(key=>spec[key].marker)).size!==3)throw Error('Response queue routes and markers must be distinct');
  const target=checkScope(args.url,context);
  for(const key of ['outer','followup','injected'])checkScope(new URL(spec[key].route,target).href,context);
  const admitted={},raw={};for(const key of ['requestBase64','controlBase64']){raw[key]=bytes(args[key],key);admitted[key]=wire.validateHttp1(raw[key],target,context,{malformedOptIn:true});}
  const routeUrl=key=>new URL(spec[key].route,target).href;
  for(const [variant,expected] of [['requestBase64',['outer','injected','followup']],['controlBase64',['outer','followup']]]){
   const actual=admitted[variant].map(x=>x.url),wanted=expected.map(routeUrl);
   if(actual.length!==wanted.length||actual.some((url,index)=>url!==wanted[index]))throw Error('Response queue '+variant+' must contain the expected ordered routes');
  }
  for(const key of ['outer','followup','injected'])for(const variant of ['requestBase64','controlBase64'])if(raw[variant].includes(Buffer.from(spec[key].marker,'utf8')))throw Error('Response queue marker for '+key+' must be absent from wire request bytes');
  const front=spec.frontFraming,alternate=front==='cl'?'te':'cl',framing={front,alternate},boundaries={};
  for(const variant of ['controlBase64','requestBase64']){
   boundaries[variant]={};
   for(const policy of [front,alternate])boundaries[variant][policy]=wire.parseHttp1Requests(raw[variant],policy).map(x=>x.route);
  }
  const expected={controlBase64:['outer','followup'],requestBase64:['outer','followup']};
  for(const variant of ['controlBase64','requestBase64'])for(const policy of [front,alternate]){
   const keys=variant==='requestBase64'&&policy===alternate?['outer','injected','followup']:expected[variant];
   const actual=boundaries[variant][policy],wanted=keys.map(key=>spec[key].route);
   if(actual.length!==wanted.length||actual.some((route,index)=>route!==wanted[index]))throw Error('Response queue '+variant+' under '+policy+' must parse complete '+keys.join(',')+' request boundaries');
  }
  const attempts=[];let error=null;
  try{for(let i=0;i<repeats;i++)for(const variant of ['control','probe']){
   context.signal?.throwIfAborted();
   const sample=await exchange('desync',{...args,requestBase64:variant==='control'?args.controlBase64:args.requestBase64},context);
   const parsed=wire.parseHttp1Responses(Buffer.from(sample.response.base64||'','base64'));
   let sequence=null,parseError=null;
   try{if(sample.timedOut||sample.truncated||!sample.writeComplete||parsed.incomplete)throw Error('Response queue requires complete writes and parsed responses without timeout or truncation');
    sequence=parsed.responses.map(response=>{if(response.status!==200)throw Error('Response queue requires HTTP 200 responses');const body=JSON.parse(Buffer.from(response.bodyBase64,'base64').toString('utf8'));if(typeof body.route!=='string'||typeof body.marker!=='string')throw Error('Response queue requires route and marker fields');return {route:body.route,marker:body.marker,status:response.status,bodySha256:response.bodySha256};});
   }catch(e){parseError=e.message;}
   attempts.push({index:i,variant,sampleEvidenceId:sample.evidence.evidenceId,connection:sample.connections[0]||null,responseCount:parsed.responses.length,sequence,parseError,timedOut:sample.timedOut,truncated:sample.truncated});
  }}catch(e){error=e;}
  const matches=(value,key)=>value?.route===spec[key].route&&value?.marker===spec[key].marker;
  let confirmed=!error&&attempts.length===repeats*2;
  const ports=new Set();
  for(const item of attempts){if(!item.connection?.localPort||ports.has(item.connection.localPort)||item.parseError)confirmed=false;else ports.add(item.connection.localPort);
   const expected=item.variant==='control'?['outer','followup']:['outer','injected','followup'];
   if(item.sequence?.length!==expected.length||expected.some((key,index)=>!matches(item.sequence[index],key)))confirmed=false;
  }
  const result={transport:'desync',mode:'response_queue',classification:confirmed?'confirmed_with_response_queue':'inconclusive',repeats,framing,boundaries,attempts,error:error?.message||null,partial:!!error};result.evidence=await evidence.save(result,context);if(error){error.message+='; raw evidence '+result.evidence.evidenceId;throw error;}return result;
 }
 return {dispatch};
}
module.exports={createTransports,checkScope,frame,bytes};

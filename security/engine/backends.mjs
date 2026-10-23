import '../compat/dast-inputs.js';
const copy=value=>JSON.parse(JSON.stringify(value));
export function prepareOastVectors(requests=[],candidates=[],explicit=[]) {
 const plans=[],gaps=[];
 for(const vector of explicit){const record=requests.find(r=>String(r.id)===String(vector.requestId));const request=record?.original?.request||record?.request||record;
  if(!request?.url||!vector.selector){gaps.push({requestId:vector.requestId,reason:'missing_request_or_exact_input'});continue;}
  try{const marker='CERTXOASTPLACEHOLDER',selected=globalThis.CertXDastInputs.replaceRequestInput({...request,body:request.body??request.requestBody?.raw??''},vector.selector,marker);const template=JSON.parse(JSON.stringify(selected).replaceAll(marker,'{{OAST_PAYLOAD}}'));plans.push({...copy(vector),request:template});}catch(error){gaps.push({requestId:vector.requestId,reason:error.message});}
 }
 for(const candidate of candidates){if(!/ssrf|server.side.request/i.test(JSON.stringify([candidate.title,candidate.family,candidate.category,candidate.why])))continue;
  const reference=candidate.evidenceRefs?.find(ref=>ref.type==='request'),record=requests.find(r=>String(r.id)===String(reference?.id)),request=record?.original?.request||record?.request;
  const parameter=candidate.targetParam?.name||String(candidate.paramKey||'').split(':').slice(1).join(':');if(!request?.url||!parameter){gaps.push({candidateId:candidate.id,reason:'missing_request_input'});continue;}
  const fields=globalThis.CertXDastInputs.parseEncoded(new URL(request.url).search.slice(1)).filter(field=>field.name===parameter);
  if(fields.length!==1){gaps.push({candidateId:candidate.id,reason:'select_exact_input_occurrence'});continue;}
  const generated=prepareOastVectors([record],[],[{candidateId:candidate.id,requestId:record.id,selector:{location:'query',name:parameter,index:fields[0].index},family:'ssrf'}]);plans.push(...generated.plans);gaps.push(...generated.gaps);
 }
 return {plans,gaps};
}
export function createSupplementalBackends(){
 const runs=new Map();
 async function begin(sessionId,args,context,{requests=[],candidates=[],url}={}){
  const result=runs.get(sessionId)?.result||{backends:{},gaps:[]};runs.set(sessionId,{context,result});
  if(context.config?.preset!=='thorough'&&!context.config?.backends&&!context.config?.oast)return result;
  if(!context.integrations?.oastConnectionId&&!context.integrations?.zapEnabled)return result;
  context.oastActions=['status','create','probe','events','wait','stop'];
  if(typeof context.localExecute!=='function'){result.gaps.push({backend:'local',reason:'local_executor_unavailable'});return result;}
  const settings=context.config.backends||{};
  if(settings.oast!==false&&context.integrations?.oastConnectionId&&!result.backends.oast){
   const vectors=prepareOastVectors(requests,candidates,context.config.oast?.probes||[]);result.gaps.push(...vectors.gaps.map(gap=>({backend:'oast',...gap})));
   if(!vectors.plans.length){if(!result.gaps.some(gap=>gap.reason==='no_applicable_exact_input'))result.gaps.push({backend:'oast',reason:'no_applicable_exact_input',note:'Select a captured input or investigate a candidate before sending an out-of-band probe.'});}
   else try{const ready=await context.localExecute('oast.status',{});if(!ready.available)result.gaps.push({backend:'oast',reason:'provider_not_configured'});else{const registration=await context.localExecute('oast.create',{});result.backends.oast={...registration,probes:[]};for(const vector of vectors.plans){await context.recheck?.();const probe=await context.localExecute('oast.probe',{oastId:registration.oastId,...vector,execute:true});result.backends.oast.probes.push(probe);}}}catch(error){result.gaps.push({backend:'oast',reason:error.message});}
  }
  if(settings.zap!==false&&context.integrations?.zapEnabled&&!result.backends.zap)try{result.backends.zap=await context.localExecute('zap.start',{url,...(settings.zapOptions||{})});}catch(error){result.gaps.push({backend:'zap',reason:error.message});}
  return copy(result);
 }
 async function update(id,stop=false,cleanupContext){const state=runs.get(id);if(!state)return null;if(stop)state.stopped=true;const {result}=state,context=cleanupContext||state.context;
  if(state.stopped&&!stop)return copy(result);
  for(const [backend,record]of Object.entries(result.backends))try{const current=await context.localExecute(backend+'.'+(stop?'stop':backend==='zap'?'progress':'events'),backend==='zap'?{zapId:record.zapId}:{oastId:record.oastId});result.backends[backend]={...record,...current};}catch(error){result.gaps.push({backend,reason:error.message});}
  return copy(result);
 }
 return {begin,async evidence(id){const state=runs.get(id);if(!state)return null;const result=state.result;if(!state.stopped&&result.backends.zap)try{result.backends.zap.findings=await state.context.localExecute('zap.findings',{zapId:result.backends.zap.zapId});}catch(error){result.gaps.push({backend:'zap',reason:error.message});}return copy(result);},async offer(id,inputs){const state=runs.get(id);if(!state||state.stopped||state.offering||state.result.backends.oast||!inputs.candidates?.length)return;state.offering=true;try{await begin(id,{},state.context,inputs);}finally{const current=runs.get(id);if(current)current.offering=false;}},status:id=>update(id),stop:(id,context)=>update(id,true,context)};
}

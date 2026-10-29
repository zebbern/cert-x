// Owned adapters around PTK's complete candidate/evidence/workflow services.
import {DastCandidateRunService} from '../ptk/background/dast/services/dastCandidateRunService.js';
import {applyScanAnalysis} from '../ptk/background/analysis/scanAnalysisEngine.js';
import {EvidencePackageStore} from '../ptk/background/bugbounty/evidencePackageStore.js';
import {WorkflowOverlayService} from '../ptk/background/bugbounty/workflowOverlayService.js';
import {sensitiveArtifactStorage} from '../ptk/background/sensitiveArtifactStore.js';
import '../compat/dast-inputs.js';
import {prepareCandidateJob} from './candidate-inputs.mjs';
const copy=value=>value==null?value:JSON.parse(JSON.stringify(value));
function describeReason(value){
 if(value==null)return '';
 if(Array.isArray(value))return value.map(describeReason).filter(Boolean).join(' ');
 if(typeof value!=='object')return String(value);
 for(const key of ['message','description','text'])if(typeof value[key]==='string')return value[key];
 if(value.signal)return String(value.signal)+(value.value==null?'':': '+(typeof value.value==='object'?JSON.stringify(value.value):String(value.value)));
 return JSON.stringify(value);
}
function publicEvidence(value,scan){
 const secrets=[];for(const record of scan.requests||[]){const headers=record?.original?.request?.headers||record?.request?.headers||{};for(const [name,value]of Array.isArray(headers)?headers.map(h=>[h.name,h.value]):Object.entries(headers))if(/^(authorization|cookie|proxy-authorization|x-api-key)$/i.test(name)&&String(value).length>=4)secrets.push(String(value));}
 const visit=value=>{if(typeof value==='string'){for(const secret of secrets)value=value.split(secret).join('[private captured credential]');return value;}if(Array.isArray(value))return value.map(visit);if(!value||typeof value!=='object')return value;if(value.name&&/^(authorization|cookie|set-cookie|proxy-authorization|x-api-key)$/i.test(value.name)&&Object.hasOwn(value,'value'))return {...value,value:'[private captured credential]'};return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,/^(authorization|cookie|set-cookie|proxy-authorization|x-api-key)$/i.test(key)?'[private captured credential]':visit(item)]));};return visit(value);
}
export function createCandidateWorkflows({privateStore=sensitiveArtifactStorage,replay,macro}={}) {
  const queues=new Map();
  async function invoke(operation,args,context,snapshot,recording=null) {
    if(!context.owner||!context.sourceRun?.runId)throw Error('Candidate operations require an owned source run.');
    const key='cert_x_investigation:'+encodeURIComponent(context.owner)+':'+encodeURIComponent(context.sourceRun.runId);
    const work=async()=>{
      const saved=await privateStore.getItem(key);
      const state=saved?.runId?saved:{owner:context.owner,runId:context.sourceRun.runId,snapshotId:crypto.randomUUID(),scan:copy(snapshot),suppressed:[],packages:{}};
      if(state.owner!==context.owner||state.runId!==context.sourceRun.runId)throw Error('Investigation ownership mismatch.');
      if(args.snapshotId&&args.snapshotId!==state.snapshotId)throw Error('Candidate snapshot changed; list the current candidates before continuing.');
      if(args.action==='recompute'&&snapshot){if(state.scan?.scanId!==snapshot.scanId)throw Error('Cannot replace a snapshot with another scan.');state.scan=copy(snapshot);state.snapshotId=crypto.randomUUID();}
      if(!state.scan?.scanId)throw Error('The selected run has no retained native scan snapshot.');
      if(!state.scan.analysis||args.action==='recompute') applyScanAnalysis(state.scan,{force:true});
      const scan=state.scan,candidates=scan.analysis?.candidates||[];
      const getCandidate=id=>candidates.find(candidate=>candidate.id===id)||null;
      const storage={getItem:async k=>copy(state.packages[k]??null),setItem:async(k,v)=>{state.packages[k]=copy(v);}};
      const workflowStorage={getItem:async k=>k==='ptk_recorder'?{recording:copy(recording)}:null};
      const local=async(action,payload)=>{if(typeof context.localExecute!=='function')throw Error('Local browser execution is unavailable.');return context.localExecute(action,payload);};
      const profiles=[];
      const resolveProfile=async id=>{if(typeof context.resolveAccount!=='function')throw Error('Account references are unavailable.');const profile=await context.resolveAccount(id);await profile.checkRevision?.();profiles.push(profile);return profile;};
      const service=new DastCandidateRunService({
        getScanResult:()=>scan,getCandidate,
        getRequestRecordById:id=>(scan.requests||[]).find(request=>String(request.id)===String(id)),
        evidencePackageStore:new EvidencePackageStore({storage}),
        workflowOverlayService:new WorkflowOverlayService({storage:workflowStorage,browserApi:null}),
        sessionProfileStore:{getProfile:resolveProfile},
        fetchImpl:async(url,options)=>{const value=await replay({request:{url,method:options.method},options:{follow_redirect:false}},context);if(value.response?.errorMessage)throw Error(value.response.errorMessage);return {status:Number(value.response?.statusCode)||0};},
        playwrightMcpClient:{createJob:job=>{if(!args.browserSessionId)throw Error('Select an explicit browser session for reproduction.');return local('browser.runCandidate',{sessionId:args.browserSessionId,job:prepareCandidateJob(job,args.selector)});},getJob:jobId=>local('browser.getJob',{jobId})},
        startWorkflowReplay:payload=>macro({...payload,action:'replay',tabId:args.tabId??context.tabId},context)
      });
      const input={...copy(args),runId:args.comparisonRunId||null};
      if(args.action==='compare'&&args.execute===true){
        if(!args.baselineSessionProfileId||!args.comparisonSessionProfileId)throw Error('Select both verified private account references.');
        const candidate=getCandidate(args.candidateId);if(!candidate)throw Error('Candidate does not belong to this run.');
        const request=service._resolveCandidateRequestSeed(candidate);if(!request)throw Error('The candidate has no reproducible request.');
        if(args.selector&&typeof args.replacement!=='string')throw Error('Provide a string replacement for the selected input.');
        const compareRequest=args.selector?globalThis.CertXDastInputs.replaceRequestInput(request,args.selector,args.replacement):request;
        const send=async(id,request)=>{const account=await resolveProfile(id),check=async()=>{await context.recheck?.();await account.checkRevision?.();};const outcome=await replay({request},{...context,account,recheck:check,checkRequest:async value=>{await check();return context.checkRequest(value);}});if(outcome.response?.errorMessage||Number(outcome.response?.statusCode)===0)throw Error(outcome.response?.errorMessage||'Comparison response unavailable.');return outcome.response;};
        input.baselineResponse=await send(args.baselineSessionProfileId,request);input.comparisonResponse=await send(args.comparisonSessionProfileId,compareRequest);
      }
      let result;
      const explicitAccounts=!!input.baselineSessionProfileId&&!!input.comparisonSessionProfileId;
      if(['create','draft'].includes(args.action)&&(input.baselineSessionProfileId||input.comparisonSessionProfileId)&&(!explicitAccounts||input.baselineSessionProfileId===input.comparisonSessionProfileId))throw Error('An authorization report requires two distinct verified account references.');
      if(['create','draft'].includes(args.action)&&!explicitAccounts){
        const candidate=getCandidate(args.candidateId);if(!candidate)throw Error('Candidate does not belong to this run.');
        let evidencePackage={kind:'candidate',candidateId:candidate.id,scanId:scan.scanId,host:scan.host,routeKey:candidate.routeKey,title:args.title||candidate.title||'Security investigation candidate',summary:describeReason(candidate.summary||candidate.why),sourceEvidence:{candidate:copy(candidate),findings:copy(scan.findings||[])},notes:args.notes||'',reproductionSteps:['Inspect the referenced source evidence and affected route.','Reproduce the suspected behavior using the selected account and permitted tools.','Record the observed effect and remaining uncertainty before claiming impact.']};
        if(input.baselineResponse||input.comparisonResponse){evidencePackage.baselineResponse=copy(input.baselineResponse);evidencePackage.comparisonResponse=copy(input.comparisonResponse);evidencePackage.sourceEvidence.responseProvenance={provenance:'caller_supplied',authorizationBoundaryVerified:false};}
        if(args.action==='create')evidencePackage=await service.evidencePackageStore.save(evidencePackage);
        result={success:true,evidencePackage,reportDraft:service.reportDraftBuilder.build({evidencePackage})};
      }else if(operation==='evidencePackage'){
        const methods={list:'listEvidencePackages',get:'getEvidencePackage',create:'createEvidencePackageFromAuthzDiff',export:'exportEvidencePackage',draft:'buildCandidateReportDraft'};
        if(!methods[args.action])throw Error('Unknown evidence package action.');
        result=await service[methods[args.action]]({...input,evidencePackageId:args.packageId||args.evidencePackageId});
      }else if(args.action==='list'||args.action==='recompute'){
        const offset=args.offset??0,limit=args.limit??50;if(!Number.isSafeInteger(offset)||offset<0||!Number.isSafeInteger(limit)||limit<1||limit>500)throw Error('Invalid candidate pagination.');
        const selected=candidates.filter(candidate=>args.includeSuppressed||!state.suppressed.includes(candidate.id));
        result={candidates:copy(selected.slice(offset,offset+limit)),total:selected.length,nextOffset:offset+limit<selected.length?offset+limit:null,coverage:copy(scan.analysis.coverage),snapshotScanId:scan.scanId};
      }else if(args.action==='get'||args.action==='suppress'){
        const candidate=getCandidate(args.candidateId);if(!candidate)throw Error('Candidate does not belong to this run.');
        if(args.action==='suppress')state.suppressed=args.suppressed===false?state.suppressed.filter(id=>id!==candidate.id):[...new Set([...state.suppressed,candidate.id])];
        result={candidate:copy(candidate),suppressed:state.suppressed.includes(candidate.id)};
      }else if(args.action==='status'||args.action==='stop'){
        if(!args.jobId)throw Error('Choose an owned reproduction job.');
        result=await local(args.action==='stop'?'browser.cancelJob':'browser.getJob',{jobId:args.jobId});
      }else {
        const methods={readiness:'getCandidatePlaywrightReadiness',reproduce:'runCandidateInPlaywright',objectswap:'suggestCandidateObjectSwap',compare:'compareCandidateAuthzDiff',workflow:'getWorkflowOverlaySummary',workflowReplay:'startWorkflowOverlayReplay',draft:'buildCandidateReportDraft'};
        if(!methods[args.action])throw Error('Unknown candidate action.');
        result=await service[methods[args.action]]({...input,skipNetwork:args.check!==true});
      }
      await privateStore.setItem(key,state);
      for(const profile of profiles)await profile.checkRevision?.();
      const jobId=result?.run?.jobId||result?.jobId,status=result?.run?.status||result?.status;
      const redactionScan={...scan,requests:[...(scan.requests||[]),...profiles.map(profile=>({original:{request:{headers:[...(Array.isArray(profile.headers)?profile.headers:Object.entries(profile.headers||{}).map(([name,value])=>({name,value}))),{name:'Cookie',value:profile.cookie||''}]}}}))]};
      return publicEvidence({...copy(result),...(jobId?{jobId,persistent:!['completed','failed','canceled','timed_out','cancelled'].includes(status),state:status}:{}),sourceRunId:state.runId,snapshotId:state.snapshotId,snapshotScanId:scan.scanId},redactionScan);
    };
    const task=(queues.get(key)||Promise.resolve()).catch(()=>{}).then(work);queues.set(key,task);try{return await task;}finally{if(queues.get(key)===task)queues.delete(key);}
  }
  return {invoke};
}

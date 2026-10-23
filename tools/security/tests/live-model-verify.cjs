// Validate retained live inference evidence independently of assistant prose.
const fs=require('node:fs'),path=require('node:path');
const file=process.argv[2]||path.join(process.env.LOCALAPPDATA,'cert-x','verification','cert-x-live-model-results.json');
const evidence=JSON.parse(fs.readFileSync(file,'utf8'));
const results=new Map(evidence.toolResults.map(item=>[item.id,item.result]));
const calls=evidence.requests.flatMap(request=>(request.toolCalls||[]).map(call=>{
 let argumentsValue={};try{argumentsValue=JSON.parse(call.arguments).arguments||{}}catch{}
 return {name:call.name,arguments:argumentsValue,result:results.get(call.id)};
}));
const find=(name,action)=>calls.find(call=>call.name===name&&call.arguments.action===action&&call.result&&!call.result.error);
const listed=find('security_candidates','list'),candidate=listed?.result?.candidates?.[0];
const inspected=find('security_candidates','get'),readiness=find('security_candidates','readiness');
const reproduced=find('security_candidates','reproduce'),status=find('security_candidates','status');
const artifact=find('security_browser','readArtifact'),pkg=find('security_evidence_package','create'),exported=find('security_evidence_package','export');
const impact=calls.find(call=>call.name==='security_browser'&&call.arguments.action==='inspect'&&call.result?.title==='XSS_EXEC_MARKER');
const control=calls.find(call=>call.name==='security_browser'&&call.arguments.action==='inspect'&&call.result?.url?.includes('q=hello')&&call.result?.title==='Managed application');
const report=exported?.result?.content||'';
const baselineUrl=status?.result?.observations?.find(item=>item.kind==='baseline')?.url;
const intendedMutationObserved=!!baselineUrl&&status.result.observations.some(item=>{
 if(item.kind!=='mutation'||!item.url)return false;
 const before=new URL(baselineUrl),after=new URL(item.url);
 return before.searchParams.has('q')&&after.searchParams.has('q')&&before.searchParams.get('q')!==after.searchParams.get('q')&&!after.searchParams.has('param:q');
});
const envLine=fs.readFileSync(path.resolve(__dirname,'../../../.env.local'),'utf8').split(/\r?\n/).find(line=>/^\s*OPENROUTER_API_KEY\s*=/.test(line));
const key=envLine?.slice(envLine.indexOf('=')+1).trim().replace(/^['"]|['"]$/g,'');
const checks={
 liveInference:evidence.kind==='live_model'&&evidence.inferenceRequests>0&&evidence.inferenceRequests<=24,
 requestedModel:evidence.model===(process.argv[3]||'xiaomi/mimo-v2.6-flash')&&evidence.requests.every(request=>request.model===evidence.model),
 spendingBound:evidence.model.endsWith(':free')||evidence.spendingLimitUSD===0.5&&evidence.accountedCostUSD<=0.5,
 providerSucceeded:evidence.requests.every(request=>request.httpStatus===200&&!request.providerError),
 providerResponsesComplete:evidence.requests.every(request=>request.settled===true&&request.sseDone===true&&!!request.finishReason&&!!request.usage),
 terminalModelTurn:evidence.requests.some(request=>request.finishReason==='stop'),
 outputBound:evidence.requests.every(request=>(request.usage?.completion_tokens??0)<=1200),
 timeBound:new Date(evidence.finishedAt)-new Date(evidence.liveStartedAt)<=600000,
 credentialExcluded:!!key&&!fs.readFileSync(file,'utf8').includes(key),
 advertisedTools:evidence.requests.every(request=>(request.toolCalls||[]).every(call=>request.advertisedToolNames.includes(call.name))),
 realScanSetup:!!evidence.setup?.scanRunId&&evidence.setup.scripted===true&&evidence.setup.stopResult?.state==='completed',
 candidateDiscovery:!!candidate&&!!inspected?.result?.candidate&&inspected.arguments.candidateId===candidate.id,
 readiness:readiness?.result?.readiness?.runInPlaywright==='ready',
 managedBrowser:!!find('security_browser','create')?.result?.sessionId,
 reproductionTerminal:status?.result?.status==='completed'&&status.result.summary?.classification==='candidate_observations'&&status.result.summary?.verifiedVulnerability===false&&reproduced?.result?.jobId===status.result.jobId&&status.arguments.executionRunId===reproduced.result.runId,
 intendedInputMutated:intendedMutationObserved,
 artifactRead:!!artifact?.result?.base64&&Buffer.from(artifact.result.base64,'base64').length>0,
 demonstratedImpact:!!impact&&!!control&&impact.result.url.includes('document.title'),
 evidenceExport:!!pkg?.result?.evidencePackage?.id&&!!report&&exported.arguments.packageId===pkg.result.evidencePackage.id,
 scanReportExport:calls.some(call=>call.name==='security_export_report'&&Array.isArray(call.result?.reports)&&call.result.reports.length>0),
 scanReportRetained:evidence.reportDownloads?.some(download=>download.state==='complete'&&download.bytes>0&&fs.existsSync(download.retainedPath)),
 reportAccurate:!!report&&!/Authenticate as baseline|different access outcome than baseline|different session/i.test(report),
 browserOperationsClean:!calls.some(call=>call.name==='security_browser'&&call.result?.error),
};
const failed=Object.entries(checks).filter(([,ok])=>!ok).map(([name])=>name);
console.log(JSON.stringify({checks,failed,requests:evidence.inferenceRequests,completionTokens:evidence.requests.reduce((n,request)=>n+(request.usage?.completion_tokens||0),0),evidenceFile:file},null,2));
if(failed.length)process.exitCode=1;

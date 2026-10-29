import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareApiRequest,resolveApiRefs,createApiOperations} from '../../../security/engine/openapi.mjs';
import {createCandidateWorkflows} from '../../../security/engine/candidates.mjs';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';
import path from 'node:path';
const {verify}=createRequire(import.meta.url)('../prepare-reference.cjs');
const reference=verify(process.env.PTK_REFERENCE_ROOT||path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../../../insp/pentestkit-10.0.0-release/src'));
const {DastCandidateRunService}=await import(pathToFileURL(path.join(reference.root,'ptk/background/dast/services/dastCandidateRunService.js')).href);
const scope={origins:['https://api.test'],excludePaths:['/private']};
const spec={openapi:'3.0.0',info:{title:'Fixture',version:'1'},servers:[{url:'https://api.test/v1'}],paths:{'/items/{id}':{get:{operationId:'getItem',parameters:[{in:'path',name:'id',required:true,schema:{type:'string'}},{in:'query',name:'q',required:true},{in:'header',name:'X-Mode',required:true},{in:'cookie',name:'scope',required:true}],responses:{}}},'/items':{post:{operationId:'createItem',requestBody:{required:true,content:{'application/json':{schema:{type:'object',required:['name']}}}},responses:{}}}}};
function store(){const data=new Map();return {getItem:async key=>structuredClone(data.get(key)||{}),setItem:async(key,value)=>data.set(key,structuredClone(value))};}
test('OpenAPI required path/query/header/cookie inputs produce concrete scoped requests',()=>{
  const result=prepareApiRequest(spec,{operationId:'getItem',values:{path:{id:'a/b'},query:{q:['a','b']},header:{'X-Mode':'one'},cookie:{scope:'private space'}}},scope);
  assert.equal(result.request.url,'https://api.test/v1/items/a%2Fb?q=a&q=b');assert.equal(result.request.headers['X-Mode'],'one');assert.equal(result.request.headers.Cookie,'scope=private%20space');
  assert.throws(()=>prepareApiRequest(spec,{operationId:'getItem',values:{path:{id:1}}},scope),/query.q/);
  assert.throws(()=>prepareApiRequest(spec,{operationId:'createItem',body:{}},scope),/body.name/);
  assert.throws(()=>prepareApiRequest(spec,{operationId:'createItem',body:{name:'a'},baseUrl:'https://foreign.test'},scope),/outside scope/);
});
test('JSON, form, multipart and Swagger formData retain exact supplied values',()=>{
  assert.equal(prepareApiRequest(spec,{operationId:'createItem',body:{name:'a'}},scope).request.body,'{"name":"a"}');
  const form=structuredClone(spec);form.paths['/items'].post.requestBody.content={'application/x-www-form-urlencoded':{schema:{required:['name']}}};
  assert.equal(prepareApiRequest(form,{operationId:'createItem',body:{name:'a b'}},scope).request.body,'name=a+b');
  form.paths['/items'].post.requestBody.content={'multipart/form-data':{schema:{required:['name']}}};
  const multi=prepareApiRequest(form,{operationId:'createItem',body:{name:'hello',file:{filename:'x.txt',content:'payload',contentType:'text/plain'}}},scope).request;
  assert.match(multi.headers['Content-Type'],/boundary=certx-/);assert.match(multi.body,/filename="x.txt"\r\nContent-Type: text\/plain\r\n\r\npayload/);
  const swagger={swagger:'2.0',host:'api.test',schemes:['https'],paths:{'/form':{post:{parameters:[{in:'formData',name:'name',required:true}],responses:{}}}}};
  assert.equal(prepareApiRequest(swagger,{path:'/form',method:'POST',values:{formData:{name:'x'}}},scope).request.body,'name=x');
});
test('external references require explicit scoped documents and never fetch implicitly',()=>{
  const source={...spec,components:{schemas:{Item:{$ref:'https://api.test/schema.json#/Item'}}}};
  assert.throws(()=>resolveApiRefs(source,{scope}),/Supply the external/);
  const resolved=resolveApiRefs(source,{scope,documents:{'https://api.test/schema.json':{Item:{type:'string'}}}});assert.equal(resolved.components.schemas.Item.type,'string');
  assert.throws(()=>resolveApiRefs(source,{scope:{origins:[]}}),/outside scope/);
});
test('API plans remain owner bound and batches preserve partial application failures',async()=>{
  let count=0;const manager=createApiOperations({privateStore:store(),replay:async()=>({response:++count===2?{statusCode:0,errorMessage:'transport lost'}:{statusCode:200}})}),ctx={owner:'a',scope};
  const imported=await manager.invoke({action:'import',data:JSON.stringify(spec)},ctx),plan=await manager.invoke({action:'prepare',specRef:imported.specRef,operationId:'createItem',body:{name:'a'}},ctx);
  await assert.rejects(manager.invoke({action:'execute',planRef:plan.planRef},{owner:'b',scope}),/another chat/);
  const result=await manager.invoke({action:'batch',planRefs:[plan.planRef,plan.planRef,plan.planRef]},ctx);assert.equal(result.success,false);assert.equal(result.completed,2);assert.equal(count,2);
});
const candidate={id:'candidate-a',routeKey:'api.test|GET|/items/1',targetParam:{location:'query',name:'id'},paramKey:'query:id',why:['An object identifier is exposed'],evidenceRefs:[{type:'request',id:'request-a'}]};
const scan={scanId:'scan-a',host:'api.test',analysis:{candidates:[candidate]},requests:[{id:'request-a',original:{request:{url:'https://api.test/items/1?id=1',method:'GET',headers:[]}}}]};

test('candidate report renders structured reasons and retains their original evidence',async()=>{
 const workflow=createCandidateWorkflows({privateStore:store()}),context={owner:'a',sourceRun:{runId:'source-a'},scope};
 const input=structuredClone(scan);input.analysis.candidates[0].why=[{signal:'DOM_HTML_GADGET',value:'innerHTML'},{message:'Inspect the source route.'}];
 const result=await workflow.invoke('evidencePackage',{action:'create',candidateId:candidate.id},context,input);
 assert.match(result.reportDraft.summary,/DOM_HTML_GADGET: innerHTML/);assert.match(result.reportDraft.summary,/Inspect the source route/);assert.ok(!result.reportDraft.markdown.includes('[object Object]'));
 assert.deepEqual(result.evidencePackage.sourceEvidence.candidate.why,input.analysis.candidates[0].why);assert.equal(result.reportDraft.impact,'Unconfirmed');
});
test('candidate readiness/object-swap retain original PTK outputs and explicit snapshot isolation',async()=>{
  const workflow=createCandidateWorkflows({privateStore:store(),replay:async()=>({response:{statusCode:200}})}),context={owner:'a',sourceRun:{runId:'source-a'},scope};
  const original=new DastCandidateRunService({getScanResult:()=>scan,getCandidate:id=>id===candidate.id?candidate:null,getRequestRecordById:()=>scan.requests[0]});
  const ready=await workflow.invoke('candidate',{action:'readiness',candidateId:candidate.id},context,scan);
  assert.deepEqual(ready.readiness,(await original.getCandidatePlaywrightReadiness({candidateId:candidate.id,skipNetwork:true})).readiness);
  const swap=await workflow.invoke('candidate',{action:'objectswap',candidateId:candidate.id},context,scan);
  assert.deepEqual(swap.objectSwap,(await original.suggestCandidateObjectSwap({candidateId:candidate.id})).objectSwap);
  await workflow.invoke('candidate',{action:'suppress',candidateId:candidate.id},context,scan);
  const hidden=await workflow.invoke('candidate',{action:'list'},context,{...scan,analysis:{candidates:[{id:'other'}]}});assert.equal(hidden.total,0);
  const isolated=await workflow.invoke('candidate',{action:'list'},{...context,owner:'b'},scan);assert.equal(isolated.total,1);
  await assert.rejects(workflow.invoke('candidate',{action:'get',candidateId:'foreign'},context,scan),/does not belong/);
});
test('candidate response comparisons and evidence draft preserve PTK analysis and private ownership',async()=>{
  const workflow=createCandidateWorkflows({privateStore:store()}),context={owner:'a',sourceRun:{runId:'source-a'},scope};
  const args={candidateId:candidate.id,baselineResponse:{status:200,body:'{"id":1,"owner":"A"}'},comparisonResponse:{status:403,body:'Denied'}};
  const original=new DastCandidateRunService({getScanResult:()=>scan,getCandidate:()=>candidate,getRequestRecordById:()=>scan.requests[0]});
  assert.deepEqual((await workflow.invoke('candidate',{...args,action:'compare'},context,scan)).diff,(await original.compareCandidateAuthzDiff(args)).diff);
  const created=await workflow.invoke('evidencePackage',{...args,action:'create'},context,scan);assert.equal(created.success,true);assert.ok(created.evidencePackage.id);assert.ok(created.reportDraft.markdown);
  assert.equal(created.evidencePackage.kind,'candidate');assert.deepEqual(created.evidencePackage.baselineResponse,args.baselineResponse);
  assert.equal(created.evidencePackage.sourceEvidence.responseProvenance.authorizationBoundaryVerified,false);assert.doesNotMatch(created.reportDraft.markdown,/## Sessions|receive equivalent access|authorization boundary weakness|different access outcome/);
  const exported=await workflow.invoke('evidencePackage',{action:'export',packageId:created.evidencePackage.id,format:'markdown'},context,scan);
  assert.equal(exported.success,true);assert.doesNotMatch(exported.content,/## Sessions|receive equivalent access|authorization boundary weakness|different access outcome/);
  await assert.rejects(workflow.invoke('evidencePackage',{...args,action:'create',baselineSessionProfileId:'same',comparisonSessionProfileId:'same'},context,scan),/distinct verified/);
  const foreign=await workflow.invoke('evidencePackage',{action:'get',packageId:created.evidencePackage.id},{...context,owner:'b'},scan);assert.equal(foreign.success,false);
});
test('account comparisons use private references, exact occurrence mutation and shared per-send admission',async()=>{
 const calls=[],admissions=[],workflow=createCandidateWorkflows({privateStore:store(),replay:async(args,context)=>{await context.checkRequest({url:args.request.url});calls.push({args,account:context.account.id});return {response:{statusCode:200,body:'account response '+context.account.cookie}};}});
 const context={owner:'a',sourceRun:{runId:'source-a'},scope,checkRequest:async request=>admissions.push(request),resolveAccount:async id=>({id,label:id,cookie:'private-cookie-'+id,checkRevision:async()=>{}})};
 const original=structuredClone(scan);original.requests[0].original.request.url='https://api.test/items/1?id=1&id=2';
 const result=await workflow.invoke('candidate',{action:'compare',execute:true,candidateId:candidate.id,baselineSessionProfileId:'baseline',comparisonSessionProfileId:'comparison',selector:{location:'query',name:'id',index:1},replacement:'9'},context,original);
 assert.equal(result.success,true);assert.equal(calls[0].account,'baseline');assert.equal(calls[1].account,'comparison');assert.equal(calls[1].args.request.url,'https://api.test/items/1?id=1&id=9');assert.equal(admissions.length,2);assert.ok(!JSON.stringify(result).includes('private-cookie-'));
 await assert.rejects(workflow.invoke('candidate',{action:'compare',execute:true,candidateId:candidate.id,baselineSessionProfileId:'baseline'},context,scan),/both verified/);
});

// Differential contracts against the hash-verified, unmodified supplied PTK.
// This is request planning/validation parity, not exhaustive live-target proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {fixtures,buildSchemas} from './fixtures/dast-evidence.mjs';

const require=createRequire(import.meta.url),{verify}=require('../prepare-reference.cjs');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const reference=verify(process.env.PTK_REFERENCE_ROOT||process.env.PTK_REFERENCE_EXTENSION||path.resolve(root,'../insp/pentestkit-10.0.0-release/src'));
globalThis.self=globalThis;
async function implementation(directory){
 const load=file=>import(pathToFileURL(path.join(directory,file)).href);
 const [{ptk_module},{ptk_request},{dastEngine},{ptk_utils}]=await Promise.all([load('background/dast/modules/module.js'),load('background/rbuilder.js'),load('background/dast/dastEngine.js'),load('background/utils.js')]);
 const modules=['modules.json','modules_cve.json'].flatMap(file=>JSON.parse(fs.readFileSync(path.join(directory,'background/dast/modules',file),'utf8')).modules);
 return {ptk_module,ptk_request,ptk_utils,engine:Object.create(dastEngine.prototype),modules};
}
const upstream=await implementation(path.join(reference.root,'ptk')),owned=await implementation(path.join(root,'security/ptk'));
const specialized=new Set(['jwt_injection','angularjs_client_template_injection','spa_dom_xss']);
function stableMarkers(api,action){
 const random=api.ptk_utils.attackParamId,uuid=api.ptk_utils.UUID;
 // Control only the explicit nondeterministic ID producers, equally in both
 // implementations. No request bytes or validation evidence are rewritten.
 api.ptk_utils.attackParamId=length=>'certxparitymarker0123456789'.repeat(6).slice(0,length||12);
 api.ptk_utils.UUID=()=> '11111111-2222-4333-8444-555555555555';
 try{return action();}finally{api.ptk_utils.attackParamId=random;api.ptk_utils.UUID=uuid;}
}
function outcome(api,id,fixture,positive,index){
 return stableMarkers(api,()=>{
  const module=new api.ptk_module(structuredClone(api.modules.find(item=>item.id===id)));
  const {original,executed}=buildSchemas(api,module,fixture,positive,index);
  return {original,executed,validation:module.validateAttack(executed,original)};
 });
}
const counts={modules:0,attackDefinitions:0,httpMutationCases:0,validationCases:0,intentionalDifferences:0};
test('reference is independently pinned and every local module has a declared differential disposition',()=>{
 assert.equal(reference.digest,JSON.parse(fs.readFileSync(new URL('../reference/baseline.json',import.meta.url),'utf8')).sha256);
 assert.deepEqual(owned.modules.map(module=>module.id).sort(),upstream.modules.map(module=>module.id).sort());
 assert.deepEqual(owned.modules.map(module=>module.id).sort(),[...Object.keys(fixtures),...specialized].sort());
});
for(const definition of upstream.modules)test('PTK differential module '+definition.id,t=>{
 const nativeDefinition=owned.modules.find(module=>module.id===definition.id);
 const expectedDefinition=structuredClone(definition),commandCorrection=definition.id==='os_command_injection';
 if(commandCorrection){
  assert.equal(definition.attacks[0].action.params[0].value,'|/bin/cat /etc/passwd|');
  expectedDefinition.attacks[0].action.params[0].value='|/bin/cat /etc/passwd';
  assert.deepEqual({...nativeDefinition,attacks:nativeDefinition.attacks.slice(0,1)},expectedDefinition,'Only the declared legacy command syntax correction is permitted');
  assert.deepEqual(nativeDefinition.attacks.slice(1).map(a=>a.id),['oscommand_inband_printf_pipe','oscommand_inband_printf_separator']);
  counts.intentionalDifferences++;t.diagnostic('Expected owned correction: remove dangling shell pipe; two randomized output-marker additions have dedicated reflection/control and real-shell browser tests.');
 }else assert.deepEqual(nativeDefinition,definition,'Other executable rulepack definitions must be preserved');counts.modules++;
 const a=new upstream.ptk_module(structuredClone(definition)),b=new owned.ptk_module(structuredClone(nativeDefinition));
 assert.equal(b.attacks.length,a.attacks.length+(commandCorrection?2:0));
 for(let index=0;index<a.attacks.length;index++){
  const referenceAttack=stableMarkers(upstream,()=>a.prepareAttack(a.attacks[index])),nativeAttack=stableMarkers(owned,()=>b.prepareAttack(b.attacks[index]));
  if(commandCorrection)referenceAttack.action.params[0].value='|/bin/cat /etc/passwd';
  assert.deepEqual(nativeAttack,referenceAttack,definition.id+' attack '+index+' preparation');counts.attackDefinitions++;
  if(specialized.has(definition.id))continue;
  for(const positive of [true,false]){
   const expectedApi=commandCorrection?{...upstream,modules:upstream.modules.map(m=>m.id===definition.id?expectedDefinition:m)}:upstream;
   const ref=outcome(expectedApi,definition.id,fixtures[definition.id],positive,index),native=outcome(owned,definition.id,fixtures[definition.id],positive,index);
   assert.deepEqual(native.original,ref.original,'Baseline request and evidence must match');
   assert.deepEqual(native.executed,ref.executed,definition.id+' attack '+index+' must preserve target selection, request bytes, payloads and metadata');counts.httpMutationCases++;
   if(definition.id==='recon_cache_privacy'&&positive&&ref.validation.success!==native.validation.success){
    assert.equal(ref.validation.success,false);assert.equal(native.validation.success,true);counts.intentionalDifferences++;
    t.diagnostic('Expected owned correction: nested JsonLogic header predicates retain declared metadata constants; original misses public authenticated cache posture.');
   }else assert.deepEqual(native.validation,ref.validation,definition.id+' attack '+index+' validation evidence differs');
   counts.validationCases++;
  }
 }
});
test('differential coverage summary preserves the explicitly documented corrections',t=>{
 assert.equal(counts.modules,34);assert.ok(counts.attackDefinitions>34);assert.ok(counts.httpMutationCases>=62);assert.equal(counts.validationCases,counts.httpMutationCases);assert.equal(counts.intentionalDifferences,2);
 t.diagnostic(JSON.stringify({...counts,referenceSha256:reference.digest,specializedExecutionElsewhere:[...specialized],addedCommandAttacksTestedSeparately:2,scope:'Every baseline executable attack definition, with explicit syntax correction; HTTP mutation and validator outputs on fixed positive/negative evidence fixtures. Added marker attacks have separate real-shell browser coverage. No exhaustive browser-hook parity claim.'}));
});

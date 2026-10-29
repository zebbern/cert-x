import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
globalThis.self=globalThis;
const {ptk_module}=await import('../../../security/ptk/background/dast/modules/module.js');
const {ptk_request}=await import('../../../security/ptk/background/rbuilder.js');
const {dastEngine}=await import('../../../security/ptk/background/dast/dastEngine.js');
const engine=Object.create(dastEngine.prototype);
const packs=['modules.json','modules_cve.json'].flatMap(f=>JSON.parse(fs.readFileSync(new URL('../../../security/ptk/background/dast/modules/'+f,import.meta.url))).modules);
import { fixtures, reply, header, buildSchemas } from './fixtures/dast-evidence.mjs';
const schemas=(module,fixture,positive)=>buildSchemas({ptk_request,engine},module,fixture,positive);
for(const [id,fixture]of Object.entries(fixtures))test(`native detector ${id}: positive and negative HTTP evidence`,()=>{
 const module=new ptk_module(structuredClone(packs.find(m=>m.id===id)));assert.ok(module.id,id);
 const positive=schemas(module,fixture,true),negative=schemas(module,fixture,false);
 assert.equal(module.validateAttack(positive.executed,positive.original).success,true,'positive evidence must match');
 assert.equal(module.validateAttack(negative.executed,negative.original).success,false,'negative evidence must not match');
});
test('every local DAST module has an explicit test disposition',()=>{
 const specialized={jwt_injection:'runtime-dastJwtModule.test.mjs',angularjs_client_template_injection:'browser confirmation required',spa_dom_xss:'browser confirmation required'};
 assert.deepEqual(packs.map(m=>m.id).sort(),[...Object.keys(fixtures),...Object.keys(specialized)].sort());
});
// Regression for a baseline defect: JsonLogic `some` changes data scope to a header.
// The original validator loses attack.metadata.regex there and misses public cookies.
test('cache privacy binds only declared constants and preserves no-store/static exclusions', async()=>{
 const {jsonLogic}=await import('../../../security/ptk/background/lib/json-logic-js.js');
 const module=new ptk_module(structuredClone(packs.find(m=>m.id==='recon_cache_privacy')));
 const {executed,original}=schemas(module,fixtures.recon_cache_privacy,true);
 assert.equal(!!jsonLogic.apply(executed.metadata.validation.rule,{attack:executed,original,module}),false,'Characterize the unmodified PTK validator defect');
 assert.equal(module.validateAttack(executed,original).success,true);
 for(const variant of [
   {...original,response:reply('normal',[header('Set-Cookie','test=fixture'),header('Cache-Control','no-store')])},
   {...original,response:reply('normal',[header('Cache-Control','public, max-age=60')])},
   {...original,request:{...original.request,url:'https://fixture.test/static/app.js'}}
 ])assert.equal(module.validateAttack(executed,variant).success,false);
});

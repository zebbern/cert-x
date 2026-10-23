import test from 'node:test';
import assert from 'node:assert/strict';
import {validateOptions,resolveConfig} from '../../../security/config.mjs';
import {createSecurityService} from '../../../security/service.mjs';

test('module selectors preserve native array semantics including aliases and explicit empty selection',()=>{
 const options={modules:['xss'],moduleIds:[],excludeModules:['owasp_secure_headers'],engineOptions:{DAST:{moduleIds:['sql_injection'],scanStrategy:'SMART'},IAST:{modules:[],customNativeOption:true}}};
 assert.deepEqual(validateOptions(options),options);assert.deepEqual(resolveConfig({},null,options).moduleIds,[]);
});
test('malformed module selections reject before native dispatch or run creation',async()=>{
 const data={},calls=[];const storage={get:async keys=>Object.fromEntries((Array.isArray(keys)?keys:[keys]).map(key=>[key,data[key]])),set:async value=>Object.assign(data,value)};
 const runtime={ready:Promise.resolve(),describe:async()=>({}),invoke:async(...args)=>{calls.push(args);return {sessionId:'unexpected'};}};
 const service=createSecurityService(runtime,{storage,privateStorage:null});const context={owner:'chat',scope:{origins:['https://fixture.test'],excludePaths:[]}};
 for(const key of ['modules','moduleIds','excludeModules'])for(const value of [{moduleIds:['xss']},'xss',null,[1],[''],['   ']]){
  await assert.rejects(service.handle('start',{tabId:1,engines:['DAST'],options:{[key]:value}},context),/array of module ID strings/);
  await assert.rejects(service.handle('start',{tabId:1,engines:['DAST'],options:{engineOptions:{DAST:{[key]:value}}}},context),/engineOptions\.DAST.*array of module ID strings/);
 }
 assert.equal(calls.length,0);assert.equal((await service.handle('runs',{},context)).total,0);
 assert.throws(()=>validateOptions({modules:{moduleIds:['xss']}}),error=>error.code==='invalid_scan_options'&&error.retryable===false&&/no scan was started/.test(error.recovery));
 assert.throws(()=>validateOptions({engineOptions:[]}),/object/);assert.throws(()=>validateOptions({engineOptions:{DAST:[]}}),/engineOptions.DAST.*object/);
});

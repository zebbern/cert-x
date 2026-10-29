import test from 'node:test';import assert from 'node:assert/strict';
import {prepareOastVectors,createSupplementalBackends} from '../../../security/engine/backends.mjs';
test('OAST vector preparation preserves exact input occurrences and unrelated bytes',()=>{
 const request={id:'r',original:{request:{url:'https://app.test/go?url=one&url=two&keep=%2f',method:'GET'}}};
 const result=prepareOastVectors([request],[],[{requestId:'r',selector:{location:'query',name:'url',index:1},family:'ssrf'}]);
 assert.equal(result.plans[0].request.url,'https://app.test/go?url=one&url={{OAST_PAYLOAD}}&keep=%2f');
 const automatic=prepareOastVectors([request],[{id:'candidate',title:'SSRF',targetParam:{name:'url'},evidenceRefs:[{type:'request',id:'r'}]}]);assert.equal(automatic.plans.length,0);assert.equal(automatic.gaps[0].reason,'select_exact_input_occurrence');
 const unrelated=prepareOastVectors([request],[{id:'candidate',title:'Reflected XSS',targetParam:{name:'url'},evidenceRefs:[{type:'request',id:'r'}]}]);assert.equal(unrelated.plans.length,0);
});
test('PTK defaults never launches optional backends while Thorough uses configured applicable backends',async()=>{
 const calls=[],manager=createSupplementalBackends(),context={config:{preset:'ptk-defaults'},integrations:{oastConnectionId:'selected',zapEnabled:true},localExecute:async(action,args)=>{calls.push({action,args});if(action==='oast.status')return {available:true};if(action==='oast.create')return {oastId:'owned-oast',state:'monitoring'};if(action==='oast.stop')return {state:'stopped'};if(action==='zap.start')return {zapId:'owned-zap',state:'running'};if(action==='zap.stop')return {state:'stopped'};return {state:'monitoring',classification:'callback_observed'};}};
 const inputs={url:'https://app.test',requests:[{id:'r',original:{request:{url:'https://app.test/?url=old',method:'GET'}}}],candidates:[{id:'c',title:'SSRF',targetParam:{name:'url'},evidenceRefs:[{type:'request',id:'r'}]}]};
 await manager.begin('baseline',{},context,inputs);assert.equal(calls.length,0);
 const result=await manager.begin('thorough',{}, {...context,config:{preset:'thorough'}},inputs);assert.equal(result.backends.oast.oastId,'owned-oast');assert.equal(calls.find(c=>c.action==='oast.probe').args.execute,true);assert.equal(calls.filter(c=>c.action==='zap.start').length,1);
 await manager.stop('thorough',{localExecute:context.localExecute});await manager.offer('thorough',inputs);assert.equal(calls.filter(c=>c.action==='oast.create').length,1);
});
test('missing vectors are recorded and optional dispatch failures do not become findings',async()=>{
 const manager=createSupplementalBackends(),context={config:{preset:'thorough'},integrations:{oastConnectionId:'selected',zapEnabled:true},localExecute:async()=>{throw Error('not installed');}};
 const result=await manager.begin('r',{},context,{url:'https://app.test'});assert.equal(result.backends.oast,undefined);assert.ok(result.gaps.some(g=>g.reason==='no_applicable_exact_input'));assert.ok(result.gaps.some(g=>g.reason==='not installed'));
});

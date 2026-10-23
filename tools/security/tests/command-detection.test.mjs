import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
globalThis.self=globalThis;
const {ptk_module}=await import('../../../security/ptk/background/dast/modules/module.js');
const {ptk_request}=await import('../../../security/ptk/background/rbuilder.js');
const {dastEngine}=await import('../../../security/ptk/background/dast/dastEngine.js');
const definition=JSON.parse(fs.readFileSync(new URL('../../../security/ptk/background/dast/modules/modules.json',import.meta.url))).modules.find(m=>m.id==='os_command_injection');
const engine=Object.create(dastEngine.prototype);
const response=body=>({body,statusCode:200,headers:[],length:body.length});
function build(index){
 const module=new ptk_module(structuredClone(definition));
 const original=ptk_request.parseRawRequest('POST https://fixture.test/command HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 12\r\n\r\nip=127.0.0.1');original.response=response('BASELINE');
 const attack=module.prepareAttack(module.attacks[index]);
 const executed=engine._enrichAttackPayload(module.buildAttack(structuredClone(original),attack),module,attack);
 return {module,original,executed,value:executed.request.body.params.find(p=>p.name==='ip').value};
}
test('legacy command rule keeps its ID and validator while removing the invalid trailing pipe',()=>{
 const f=build(0);assert.equal(f.executed.metadata.id,'oscommand_inband_pipe_passwd');
 assert.equal(f.value,'127.0.0.1|/bin/cat /etc/passwd');
 f.executed.response=response('root:x:0:0:fixture:/root:/bin/sh');assert.equal(f.module.validateAttack(f.executed,f.original).success,true);
 f.original.response=f.executed.response;assert.equal(f.module.validateAttack(f.executed,f.original).success,false,'A preexisting passwd-like body is not injection proof');
});
for(const index of [1,2])test('command marker '+index+' targets exact form input and rejects reflection/control evidence',()=>{
 const f=build(index),marker=f.executed.metadata.regex.replaceAll('\\b','');
 assert.match(marker,/^certx_[a-z0-9]{12}_exec$/);
 assert.equal(f.executed.metadata.attacked.location,'form');assert.equal(f.executed.metadata.attacked.name,'ip');
 assert.ok(!f.value.includes(marker),'A reflected submitted string must not already contain expected output');
 assert.ok(!new URLSearchParams(f.executed.request.body.params.map(p=>[p.name,p.value])).toString().includes(marker));
 f.executed.response=response(marker);assert.equal(f.module.validateAttack(f.executed,f.original).success,true);
 for(const body of [f.value,JSON.stringify(f.value),'BASELINE',marker.replace('_exec','_other')]){f.executed.response=response(body);assert.equal(f.module.validateAttack(f.executed,f.original).success,false,body);}
 f.executed.response=response(marker);f.original.response=response(marker);assert.equal(f.module.validateAttack(f.executed,f.original).success,false,'Original-response control excludes incidental markers');
});
test('each prepared command marker has an independent correlation value',()=>{assert.notEqual(build(1).executed.metadata.regex,build(1).executed.metadata.regex);});

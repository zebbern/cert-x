// Explicitly opted-in, bounded marker-only confirmation against the authorized public DVWA lab.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
assert.equal(process.env.CERT_X_PUBLIC_COMMAND_SMOKE,'1','Set CERT_X_PUBLIC_COMMAND_SMOKE=1 for the bounded public DVWA check.');
const root=path.resolve(__dirname,'../../..'),target='https://pentest-ground.com:4280/vulnerabilities/exec/';
const folder=path.join(process.env.LOCALAPPDATA||process.env.HOME,'cert-x/verification');fs.mkdirSync(folder,{recursive:true});
const file=path.join(folder,'command-dvwa-'+new Date().toISOString().replace(/[:.]/g,'-')+'.json'),evidence={target,startedAt:new Date().toISOString(),requestLimit:6,requests:[],results:[]};
let last=0;
async function send(ip){assert.ok(evidence.requests.length<6);await new Promise(r=>setTimeout(r,Math.max(0,last+500-Date.now())));last=Date.now();
 const body=new URLSearchParams({ip,Submit:'Submit'}).toString(),response=await fetch(target,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body,redirect:'manual',signal:AbortSignal.timeout(20000)});
 const text=await response.text(),record={url:target,method:'POST',body,status:response.status,headers:[...response.headers].map(([name,value])=>({name,value})),responseBody:text};evidence.requests.push(record);fs.writeFileSync(file,JSON.stringify(evidence,null,2));assert.equal(response.status,200,'Unexpected target response');return {body:text,statusCode:response.status,headers:record.headers,length:text.length};}
async function main(){
 globalThis.self=globalThis;
 const [{ptk_module},{ptk_request},{dastEngine}]=await Promise.all([import('../../../security/ptk/background/dast/modules/module.js'),import('../../../security/ptk/background/rbuilder.js'),import('../../../security/ptk/background/dast/dastEngine.js')]);
 const definition=JSON.parse(fs.readFileSync(path.join(root,'security/ptk/background/dast/modules/modules.json'))).modules.find(m=>m.id==='os_command_injection'),module=new ptk_module(definition),engine=Object.create(dastEngine.prototype);
 const baseline=await send('127.0.0.1');assert.match(baseline.body,/PING 127\.0\.0\.1|127\.0\.0\.1 ping statistics/,'Baseline must reach the command form, not a login/error page');
 for(const attack of module.attacks.filter(a=>a.id.includes('_printf_'))){
  const original=ptk_request.parseRawRequest('POST '+target+' HTTP/1.1\r\nHost: pentest-ground.com:4280\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nip=127.0.0.1&Submit=Submit');original.response=baseline;
  const prepared=module.prepareAttack(attack),executed=engine._enrichAttackPayload(module.buildAttack(structuredClone(original),prepared),module,prepared);
  const input=executed.request.body.params.find(p=>p.name==='ip').value,marker=executed.metadata.regex.replaceAll('\\b','');assert.ok(!input.includes(marker));
  executed.response=await send(input);const positive=module.validateAttack(executed,original);assert.equal(positive.success,true,attack.id+' must return computed marker');
  const negative=await send('127.0.0.1');const control=module.validateAttack({...executed,response:negative},original);assert.equal(control.success,false);
  evidence.results.push({attackId:attack.id,input,marker,markerAbsentFromInput:true,positive,control,markerInPositive:executed.response.body.includes(marker),markerInControl:negative.body.includes(marker)});
 }
 evidence.finishedAt=new Date().toISOString();fs.writeFileSync(file,JSON.stringify(evidence,null,2));console.log(JSON.stringify({file,requests:evidence.requests.length,results:evidence.results.map(r=>({attackId:r.attackId,positive:r.positive.success,control:r.control.success}))}));
}
main().catch(error=>{evidence.error=error.stack;fs.writeFileSync(file,JSON.stringify(evidence,null,2));console.error(error.message);process.exitCode=1;});

const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs/promises'), os = require('node:os'), path = require('node:path');
const createOast = require('../security/oast.cjs');
const token = '11111111-2222-4333-8444-555555555555', connection = { id: 'webhook', command: 'fixture-python', args: ['-m','server'] };
const context = { owner: 'chat', workspaceId: 'workspace', runId: 'run', scope: { origins: ['https://target.test'], excludePaths: ['/private'] }, config: {} };
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cert-x-oast-unit-')), calls = [], admissions = [], wire = [], events = [];
  const mcpCall = async (config, name, args, signal) => {
    calls.push({ name, args });
    if (options.rpc) { const override = await options.rpc(name,args,signal); if (override !== undefined) return override; }
    let data = {};
    if (name === 'configure_webhook') data = { token };
    if (name === 'get_webhook_info') data = { url: 'https://webhook.site/' + token, dns: token + '.dnshook.site' };
    if (name === 'get_webhook_requests') data = { requests: events.map(e => ({ uuid: e.uuid })), pagination: { is_last_page: true }, next_since: 42 };
    if (name === 'get_request') data = { request: events.find(e => e.uuid === args.request_id) };
    return { content: [{ type: 'text', text: JSON.stringify({ success: true, ...data }) }] };
  };
  const admit = async value => { admissions.push(value); if (options.denied) throw Error('revoked'); };
  const fetchImpl = async (url, options) => { wire.push({url,options}); return new Response('reflected only', {status:200}); };
  let runtime = createOast({ root, admit, mcpCall, fetchImpl });
  t.after(async()=>{await runtime.close();await fs.rm(root,{recursive:true,force:true});});
  const run = (action,args={},ctx=context) => runtime.dispatch('oast.'+action,{connection,...args},ctx);
  return {run,calls,events,admissions,wire,root,restart:async()=>{await runtime.close();runtime=createOast({root,admit,mcpCall,fetchImpl});}};
}
test('provider application failures are not transport success',()=>{
  for(const response of [{isError:true},{content:[{type:'text',text:'{"success":false,"message":"quota exceeded"}'}]},{content:[{type:'text',text:'not json'}]},{}])assert.throws(()=>createOast.unwrap(response));
});
test('endpoint creation is idempotent and callback events are correlated, deduplicated and retained',async t=>{
  const f=await fixture(t),created=await f.run('create'),again=await f.run('create');assert.equal(created.oastId,again.oastId);assert.equal(f.calls.filter(x=>x.name==='configure_webhook').length,1);assert.equal(f.calls[0].args.expiry,604800);
  const probe=await f.run('probe',{oastId:created.oastId,family:'ssrf'});f.events.push({uuid:'hit',url:probe.url,type:'web',headers:{},content:'marker'}, {uuid:'foreign',url:'https://unrelated.test',type:'dns'});
  const first=await f.run('events',{oastId:created.oastId});assert.equal(first.events[0].probeId,probe.probeId);assert.equal(first.events[0].source,'ambiguous');assert.equal(first.events[1].confirmation,'unmatched');
  await f.run('events',{oastId:created.oastId});await f.restart();const retained=await f.run('export',{oastId:created.oastId});assert.equal(retained.events.length,2);assert.equal(retained.cursor,42);
  await assert.rejects(f.run('export',{oastId:created.oastId},{...context,owner:'foreign'}),/belong/);
});
test('native probes retain actual target responses and scope every outgoing request',async t=>{
  const f=await fixture(t),created=await f.run('create'),probe=await f.run('probe',{oastId:created.oastId,execute:true,family:'ssrf',request:{url:'https://target.test/proxy?url={{OAST_URL}}'}});
  assert.equal(f.wire.length,1);assert.ok(f.wire[0].url.includes(probe.marker));assert.equal(probe.responses[0].status,200);assert.equal(f.admissions.filter(x=>x.request.kind==='oast_probe').length,1);
  f.events.push({uuid:'server',url:probe.url,headers:{'sec-fetch-mode':'cors'},type:'web'});const result=await f.run('events',{oastId:created.oastId});assert.equal(result.events[0].source,'server_candidate');assert.equal(result.events[0].confirmation,'callback_observed');
  await assert.rejects(f.run('probe',{oastId:created.oastId,execute:true,request:{url:'https://outside.test/?x={{OAST_URL}}'}}),/outside scope/);assert.equal(f.wire.length,1);
});
test('XSS probes are marker-only and self-test/browser events cannot become server proof',async t=>{
  const f=await fixture(t),created=await f.run('create'),a=await f.run('probe',{oastId:created.oastId,family:'xss'}),b=await f.run('probe',{oastId:created.oastId,purpose:'self_test'});
  assert.ok(!/document|cookie|localStorage/.test(a.payload));assert.ok(a.payload.includes('credentials:"omit"'));f.events.push({uuid:'browser',url:a.url,headers:{'Sec-Fetch-Mode':'no-cors'}},{uuid:'self',url:b.url});
  const result=await f.run('events',{oastId:created.oastId});assert.equal(result.events[0].source,'browser_candidate');assert.equal(result.events[1].confirmation,'self_test');
});
test('provider metadata failure preserves the allocated endpoint for cleanup',async t=>{
  const f=await fixture(t,{rpc:name=>name==='get_webhook_info'?{content:[{type:'text',text:'{"success":false,"message":"provider temporarily unavailable"}'}]}:undefined}),created=await f.run('create');assert.match(created.providerWarning,/unavailable/);await f.restart();assert.equal((await f.run('cleanup',{oastId:created.oastId})).state,'deleted');assert.equal((await f.run('export',{oastId:created.oastId})).state,'deleted');
});
test('stop interrupts a waiting provider call and leaves evidence readable',async t=>{
  let waiting;const entered=new Promise(resolve=>waiting=resolve);
  const f=await fixture(t,{rpc:(name,args,signal)=>name==='wait_for_request'?new Promise((resolve,reject)=>{waiting();signal.addEventListener('abort',()=>reject(signal.reason),{once:true});}):undefined}),created=await f.run('create');
  const wait=f.run('wait',{oastId:created.oastId});wait.catch(()=>{});await entered;assert.equal((await f.run('stop',{oastId:created.oastId})).state,'stopped');await assert.rejects(wait,/stopped/);assert.equal((await f.run('export',{oastId:created.oastId})).state,'stopped');
});
test('scope excludes normalized and encoded paths',()=>{for(const url of ['https://target.test/private/x','https://target.test/%70rivate/x','https://target.test/private;x/y','https://target.test/allowed/../private/x'])assert.equal(createOast.inScope(url,context.scope),false);});
test('listed events remain evidence when their detail endpoint is temporarily missing',async t=>{
  const f=await fixture(t,{rpc:name=>name==='get_request'?{content:[{type:'text',text:'{"success":false,"message":"HTTP 404 request not found"}'}]}:undefined}),created=await f.run('create');
  f.events.push({uuid:'partial'});const result=await f.run('events',{oastId:created.oastId});assert.equal(result.events[0].partial,true);assert.match(result.events[0].detailError,/404/);assert.equal(result.cursor,42);
});

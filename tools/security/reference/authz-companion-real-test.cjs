// Actual cert-x + paired PTK companion; all traffic and accounts are local fixtures.
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), companion = process.env.PTK_EXTENSION || path.join(process.env.LOCALAPPDATA, 'cert-x/ptk/v10/src');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-authz-real-')), events = [], outsideEvents = [], errors = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let browser, server, outside, poison = false, expiredB = false, phase = 'capture';
const identities = { A: { id:'A',tenant:'one' }, B: { id:'B',tenant:'one' } };
function identity(req) {
  const cookie = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '')?.[1], bearer = /^Bearer (.+)$/.exec(req.headers.authorization || '')?.[1], custom = req.headers['x-account-token'];
  if (!cookie && !bearer && !custom) return 'anonymous';
  return cookie === bearer && bearer === custom && identities[cookie] ? cookie : 'mixed';
}
async function main() {
  outside = http.createServer((req,res) => { outsideEvents.push(req.url); res.end('outside'); }); await new Promise(resolve => outside.listen(0,'127.0.0.1',resolve));
  server = http.createServer((req,res) => {
    const url = new URL(req.url,'http://fixture');
    if (url.pathname === '/app') { res.setHeader('Content-Type','text/html'); return res.end('<!doctype html><title>Account comparison fixture</title><h1>Compare accounts fixture</h1>'); }
    if (url.pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }
    let body = ''; req.on('data',chunk=>body+=chunk); req.on('end',()=>{
      const who = identity(req); events.push({at:Date.now(),path:url.pathname,url:req.url,method:req.method,body,who,phase});
      if (poison) res.setHeader('Set-Cookie','sid=POISON; Path=/; HttpOnly; SameSite=Lax');
      res.setHeader('Content-Type','application/json'); res.setHeader('Cache-Control','public,max-age=600');
      const json = (code,value) => {res.statusCode=code;res.end(JSON.stringify(value));};
      if (who === 'mixed') return json(409,{error:'mixed credentials'});
      if (url.pathname === '/me') return who === 'anonymous' || expiredB && who === 'B' ? json(401,{error:'not authenticated'}) : json(200,identities[who]);
      if (url.pathname === '/redirect') {res.writeHead(302,{Location:'http://127.0.0.1:'+outside.address().port+'/no-hop'});return res.end();}
      if (url.pathname === '/slow/a') return setTimeout(()=>json(200,{id:'a',secret:'fixture-private-object-A'}),700);
      if (who === 'anonymous') return json(401,{error:'not authenticated'});
      if (url.pathname === '/csrf/a' && who === 'B') return json(403,{error:'CSRF token invalid'});
      if (url.pathname === '/graphql/a' && who === 'B') return json(200,{data:null,errors:[{message:'Access denied'}]});
      if (url.pathname === '/own/a' && who === 'B') return json(200,{id:'b',secret:'fixture-private-object-B'});
      if (url.pathname === '/status-leak/a' && who === 'B') return json(403,{id:'a',secret:'fixture-private-object-A'});
      let object = url.pathname.endsWith('/b') ? 'b' : 'a';
      if (url.pathname === '/lookup') { try {object=JSON.parse(body).id;}catch{return json(400,{error:'invalid JSON'});} }
      const owner = object === 'b' || object === 202 ? 'B' : 'A';
      if (url.pathname === '/public/a') return json(200,{id:'a',secret:'fixture-shared-object'});
      if (who !== owner && (url.pathname.startsWith('/objects/') || url.pathname === '/lookup')) return json(403,{error:'forbidden'});
      return json(200,{id:object,secret:owner === 'A' ? 'fixture-private-object-A' : 'fixture-private-object-B'});
    });
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve)); const origin='http://127.0.0.1:'+server.address().port;
  const downloads=path.join(temp,'downloads'),profile=path.join(temp,'profile');fs.mkdirSync(path.join(profile,'Default'),{recursive:true});fs.mkdirSync(downloads);
  fs.writeFileSync(path.join(profile,'Default/Preferences'),JSON.stringify({download:{default_directory:downloads,prompt_for_download:false}}));
  browser=await chromium.launchPersistentContext(profile,{headless:true,downloadsPath:downloads,viewport:{width:720,height:1100},executablePath:process.env.CHROMIUM_PATH||path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),args:['--disable-extensions-except='+root+','+companion,'--load-extension='+root+','+companion]});
  for(let i=0;i<200&&browser.serviceWorkers().length<2;i++)await sleep(50);
  const cert=browser.serviceWorkers().find(worker=>worker.url().endsWith('/background/background.js')),ptk=browser.serviceWorkers().find(worker=>worker.url().endsWith('/app.js'));assert.ok(cert&&ptk);
  await ptk.evaluate(async()=>{for(let i=0;i<200&&!self.ptk_app?.ready;i++)await new Promise(resolve=>setTimeout(resolve,50));await self.ptk_app.ready;});
  const session='authz-real-chat',workspaceId='authz-real-workspace',extensionId=new URL(cert.url()).host;
  await cert.evaluate(()=>chrome.storage.local.set({sidepanel_language:'en',sidepanel_theme:'dark',sidepanel_approval_mode:'full_access'}));
  const settings=await browser.newPage();settings.on('pageerror',error=>errors.push(error.message));await settings.goto('chrome-extension://'+extensionId+'/providers/providers.html?section=authz&session='+session);await settings.waitForFunction(()=>!document.querySelector('main').inert);
  const raw=message=>settings.evaluate(message=>chrome.runtime.sendMessage(message),message);
  const call=async(op,args={})=>{const reply=await raw({type:'KI_AUTHZ',op,session,...args});assert.equal(reply?.ok,true,op+': '+JSON.stringify(reply));return reply.result;};
  const dast=async(op,args={})=>{const reply=await raw({type:'KI_DAST',op,session,...args});assert.equal(reply?.ok,true,op+': '+JSON.stringify(reply));return reply.result;};
  assert.equal((await raw({type:'KI_CONTEXT',op:'save_workspace',workspace:{id:workspaceId,name:'Account comparison fixture',profileId:'bugbounty',dastScope:{origins:[origin],excludePaths:['/excluded']}}})).ok,true);
  assert.equal((await raw({type:'KI_CONTEXT',op:'assign_chat',session,workspaceId,profileId:'bugbounty',modelExplicit:null})).ok,true);
  const page=await browser.newPage();page.on('pageerror',error=>errors.push(error.message));await page.goto(origin+'/app');await page.waitForFunction(()=>!!window.PTK_AUTOMATION);
  const tab=(await dast('tabs')).find(tab=>tab.url===origin+'/app');assert.ok(tab);await dast('capture',{action:'start',tabId:tab.tabId,expectedOrigin:origin});
  const accountIds={};
  for(const who of ['A','B']){
    await browser.addCookies([{name:'sid',value:who,url:origin,httpOnly:true,sameSite:'Lax'}]);
    const known=new Set((await dast('list')).requests.map(request=>request.requestId));
    await page.evaluate(async who=>{const headers={Authorization:'Bearer '+who,'X-Account-Token':who};await fetch('/me',{headers,cache:'no-store'}).then(r=>r.text());if(who==='A'){for(const endpoint of ['/objects/a','/leaky/a','/public/a','/own/a','/csrf/a','/graphql/a','/slow/a','/status-leak/a'])await fetch(endpoint,{headers,cache:'no-store'}).then(r=>r.text());await fetch('/lookup',{method:'POST',headers:{...headers,'Content-Type':'application/json'},body:'{ "id":101, "keep":90071992547409931234 }',cache:'no-store'}).then(r=>r.text());}},who);
    let probe;for(let i=0;i<100;i++){probe=(await dast('list')).requests.find(request=>!known.has(request.requestId)&&request.url===origin+'/me');if(probe)break;await sleep(50);}assert.ok(probe);
    const saved=await call('save_account',{requestId:probe.requestId,label:'Account '+who,role:'User',tenant:'one',credentialHeaders:['Authorization','X-Account-Token'],cookieNames:['sid'],claims:[{pointer:'/id',expected:who},{pointer:'/tenant',expected:'one'}],readOnly:true});assert.ok(saved.id);accountIds[who]=saved.id;
  }
  await dast('capture',{action:'stop'});await browser.addCookies([{name:'sid',value:'LIVE',url:origin,httpOnly:true,sameSite:'Lax'}]);poison=true;phase='verify';
  for(const who of ['A','B']){const verified=await call('verify',{accountId:accountIds[who]});assert.equal(verified.state,'verified',JSON.stringify(verified));}
  const state=await call('state'),capture=endpoint=>state.captures.find(request=>request.url===origin+endpoint||request.endpoint===origin+endpoint);
  for(const forbidden of ['Bearer A','Bearer B','fixture-private-object-A','sid=A','sid=B'])assert.equal(JSON.stringify(state).includes(forbidden),false);
  const evidence=(id='a',secret='fixture-private-object-A')=>({object:{pointer:'/id',expected:String(id)},protected:{pointer:'/secret',expected:secret}});
  const makeCase=(endpoint,label,expected='deny')=>({requestId:capture(endpoint).requestId,label,ownerAccountId:accountIds.A,readOnly:true,evidence:evidence(),expectations:[{accountId:accountIds.B,expected},{accountId:'anonymous',expected:'deny'}]});
  const statusFocused=process.env.AUTHZ_STATUS_FOCUSED==='1';
  const cases=statusFocused?[makeCase('/status-leak/a','status-leak')]:[makeCase('/objects/a','private'),makeCase('/leaky/a','leaky'),{...makeCase('/public/a','shared','allow'),evidence:evidence('a','fixture-shared-object')},makeCase('/own/a','wrong-object'),makeCase('/csrf/a','csrf'),makeCase('/graphql/a','graphql'),makeCase('/status-leak/a','status-leak')];
  let plan=await call('prepare',{cases,budget:{maxRequests:100,durationSeconds:300}});assert.equal(JSON.stringify(plan).includes('fixture-private-object'),false);
  assert.equal((await raw({type:'KI_AUTHZ',op:'run',session,planId:plan.planId,planHash:'changed'})).ok,false);
  phase='matrix';const offset=events.length;let batch=await call('run',{planId:plan.planId,planHash:plan.planHash});
  const guarded = await ptk.evaluate(async origin => {
    const failures=[];
    for (const operation of [()=>fetch(origin+'/objects/a'),()=>self.ptk_app.request_manager.msg_send_request({schema:{}}),()=>self.ptk_app.iast.runBackgroundScan({})]) {
      try { await operation(); failures.push('not blocked'); } catch (error) { failures.push(error.message); }
    }
    return failures;
  },origin);
  assert.ok(guarded.every(message=>/account comparison/i.test(message)),JSON.stringify(guarded));
  const blockedAnalysis=await raw({type:'KI_PTK',op:'start',session,tabId:tab.tabId,expectedOrigin:origin,engines:['SAST']});assert.equal(blockedAnalysis.ok,false);assert.match(blockedAnalysis.error,/comparison/i);
  const terminal=async batchId=>{let value;for(let i=0;i<600;i++){value=await call('status',{batchId});if(!['starting','running','stopping','unknown'].includes(value.state))return value;await sleep(250);}throw Error('Batch did not terminate: '+JSON.stringify(value));};
  let final=await terminal(batch.batchId);assert.equal(final.state,'completed',JSON.stringify(final));const sent=events.slice(offset);assert.equal(final.requestsSent,sent.length);assert.equal(sent.some(event=>['LIVE','mixed'].includes(event.who)),false);
  for(let i=1;i<sent.length;i++)assert.ok(sent[i].at-sent[i-1].at>=850,'Global 1 request/sec budget');
  const result=await call('findings',{batchId:batch.batchId});assert.ok(Array.isArray(result.cells));
  const cell=(label,id=accountIds.B)=>result.cells.find(item=>item.caseLabel===label&&item.accountId===id);
  assert.equal(cell('status-leak').outcome,'unexpected_access');assert.equal(cell('status-leak').evidence.status,403);
  if(statusFocused){assert.equal(cell('status-leak','anonymous').outcome,'expected_denial');assert.equal((await browser.cookies(origin)).find(cookie=>cookie.name==='sid').value,'LIVE');assert.deepEqual(errors,[]);console.log(JSON.stringify({actualPairedExtensions:true,statusFocused:true,denialStatusDataExposure:true,repeatedVerifiedIdentity:true,manualPtkIsolation:true,anonymousDenied:true,browserCookieUnchanged:true,cells:result.cells.length,errors}));return;}
  assert.equal(cell('private').outcome,'expected_denial');assert.equal(cell('leaky').outcome,'unexpected_access');assert.equal(cell('shared').outcome,'expected_access');
  for(const label of ['wrong-object','csrf','graphql'])assert.equal(cell(label).outcome,'inconclusive',label+': '+JSON.stringify(cell(label)));
  assert.ok(result.cells.filter(item=>item.accountId==='anonymous').every(item=>item.outcome==='expected_denial'));
  const exported=await call('export',{batchId:batch.batchId});assert.equal(exported.reports.length,1);const file=(await cert.evaluate(id=>chrome.downloads.search({id}),exported.reports[0].downloadId))[0];assert.equal(file.state,'complete');assert.ok(path.resolve(file.filename).startsWith(path.resolve(temp)+path.sep));const report=JSON.parse(fs.readFileSync(file.filename,'utf8'));assert.equal(report.schema,'cert-x-authz/v1');
  for(const forbidden of ['Bearer A','Bearer B','fixture-private-object-A','sid=A','sid=B'])assert.equal(JSON.stringify(report).includes(forbidden),false);
  assert.equal((await raw({type:'KI_AUTHZ',op:'findings',session:'other-chat',batchId:batch.batchId})).ok,false);
  const outputs=await raw({type:'KI_WORKSPACE',op:'outputs',session});assert.ok(outputs.result.some(item=>item.downloadId===file.id&&item.owner===session));
  // Known numeric JSON object substitution preserves type and untouched large numbers.
  plan=await call('prepare',{cases:[{requestId:capture('/lookup').requestId,label:'numeric-object',ownerAccountId:accountIds.B,readOnly:true,objectSwap:{location:'json',name:'/id',index:0,value:'202'},evidence:evidence(202,'fixture-private-object-B'),expectations:[{accountId:accountIds.A,expected:'deny'}]}],budget:{maxRequests:30,durationSeconds:60}});
  phase='json';batch=await call('run',{planId:plan.planId,planHash:plan.planHash});final=await terminal(batch.batchId);assert.equal(final.state,'completed');assert.equal((await call('findings',{batchId:batch.batchId})).cells.find(item=>item.accountId===accountIds.A).outcome,'expected_denial');
  assert.ok(events.filter(event=>event.phase==='json'&&event.path==='/lookup').every(event=>event.body==='{ "id":202, "keep":90071992547409931234 }'));
  // Cancellation settles in-flight transport and never sends queued account requests.
  phase='stop';plan=await call('prepare',{cases:[makeCase('/slow/a','stopped')],budget:{maxRequests:30,durationSeconds:60}});batch=await call('run',{planId:plan.planId,planHash:plan.planHash});
  for(let i=0;i<200&&!events.some(event=>event.phase==='stop'&&event.path==='/slow/a');i++)await sleep(20);
  assert.ok(events.some(event=>event.phase==='stop'&&event.path==='/slow/a'));await call('stop',{batchId:batch.batchId});final=await terminal(batch.batchId);assert.equal(final.state,'stopped');const afterStop=events.length;await sleep(1100);assert.equal(events.length,afterStop);
  phase='budget';plan=await call('prepare',{cases:[makeCase('/objects/a','budget')],budget:{maxRequests:1,durationSeconds:60}});batch=await call('run',{planId:plan.planId,planHash:plan.planHash});final=await terminal(batch.batchId);assert.equal(final.state,'budget_exhausted');assert.equal(final.requestsSent,1);assert.equal(events.filter(event=>event.phase==='budget').length,1);
  // Expiry after capture cannot be interpreted as a successful access-control check.
  expiredB=true;phase='expired';plan=await call('prepare',{cases:[makeCase('/objects/a','expired')],budget:{maxRequests:30,durationSeconds:60}});batch=await call('run',{planId:plan.planId,planHash:plan.planHash});await terminal(batch.batchId);assert.equal((await call('findings',{batchId:batch.batchId})).cells.find(item=>item.accountId===accountIds.B).outcome,'inconclusive');expiredB=false;
  // A stale account revision invalidates an already reviewed plan.
  plan=await call('prepare',{cases:[makeCase('/objects/a','stale')],budget:{maxRequests:30,durationSeconds:60}});const stalePlan=plan;
  phase='delete';const activePlan=await call('prepare',{cases:[makeCase('/objects/a','delete-active')],budget:{maxRequests:30,durationSeconds:60}});batch=await call('run',{planId:activePlan.planId,planHash:activePlan.planHash});await call('delete_account',{accountId:accountIds.B});assert.equal((await terminal(batch.batchId)).state,'stopped');
  const before=events.length;assert.equal((await raw({type:'KI_AUTHZ',op:'run',session,planId:stalePlan.planId,planHash:stalePlan.planHash})).ok,false);assert.equal(events.length,before);
  assert.equal((await browser.cookies(origin)).find(cookie=>cookie.name==='sid').value,'LIVE','No account replay or response may change the live browser session');assert.equal(outsideEvents.length,0);assert.deepEqual(errors,[]);
  await settings.reload();await settings.waitForFunction(()=>!document.querySelector('main').inert);await settings.screenshot({path:path.join(os.tmpdir(),'cert-x-authz-real.png'),fullPage:true});
  console.log(JSON.stringify({actualPairedExtensions:true,identityVerification:true,isolatedAccounts:true,anonymous:true,expectedDenial:true,repeatedUnexpectedAccess:true,sharedAccess:true,wrongObjectInconclusive:true,csrfAndGraphqlInconclusive:true,expiredIdentityInconclusive:true,numericJsonPreserved:true,budgetAccounting:true,smallBudget:true,cancellation:true,accountRevocation:true,manualPtkIsolation:true,reportParsed:true,chatOutputOwnership:true,browserCookieUnchanged:true,cells:result.cells.length,errors}));
}
main().catch(error=>{console.error(error);console.error(JSON.stringify({phase,errors,requests:events.map(({body,...event})=>event)}));process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));if(outside)await new Promise(resolve=>outside.close(resolve));if(path.resolve(temp).startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(temp).startsWith('cert-x-authz-real-'))fs.rmSync(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

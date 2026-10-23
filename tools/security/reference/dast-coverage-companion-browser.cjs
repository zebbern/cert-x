// Bounded end-to-end fixtures using real SQLite, Jinja2 and the prepared PTK v10.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),cp=require('node:child_process');
const { DatabaseSync }=require('node:sqlite');
const { chromium }=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),companion=process.env.PTK_EXTENSION||path.join(process.env.LOCALAPPDATA,'cert-x/ptk/v10/src');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-dast-coverage-')),events=[],errors=[],db=new DatabaseSync(':memory:');
db.exec("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT); INSERT INTO items VALUES(1,'alpha'),(2,'beta');");
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),auth='Bearer coverage-fixture',cookie='fixture_session=coverage-fixture';
let browser,server,phase='capture',dynamic=0;
function renderTemplate(value,safe){
  const program="import sys,json\nfrom jinja2.sandbox import SandboxedEnvironment\nx=json.load(sys.stdin)\ne=SandboxedEnvironment()\nprint(e.from_string('<p>{{ value }}</p>' if x['safe'] else '<p>'+x['value']+'</p>').render(value=x['value']),end='')";
  const result=cp.spawnSync(process.env.PYTHON_PATH||'python',['-c',program],{input:JSON.stringify({value,safe}),encoding:'utf8',windowsHide:true,timeout:3000,maxBuffer:128*1024});
  if(result.status!==0)throw Error('Template fixture failed: '+result.stderr);return result.stdout;
}
async function main(){
  assert.equal(renderTemplate('{{ 7*8 }}',false),'<p>56</p>');assert.equal(renderTemplate('{{ 7*8 }}',true),'<p>{{ 7*8 }}</p>');
  server=http.createServer((req,res)=>{
    const url=new URL(req.url,'http://fixture');if(url.pathname==='/favicon.ico'){res.writeHead(204);return res.end();}
    if(url.pathname==='/app'){res.setHeader('Content-Type','text/html');res.setHeader('Set-Cookie',cookie+'; Path=/; HttpOnly; SameSite=Lax');return res.end('<!doctype html><title>Expanded DAST fixture</title><h1>Expanded DAST</h1>');}
    let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{
      events.push({phase,at:Date.now(),method:req.method,url:req.url,path:url.pathname,body,authorization:req.headers.authorization,cookie:req.headers.cookie});
      res.setHeader('Content-Type','application/json');
      const q=url.searchParams.get('q')||'1';
      if(url.pathname.startsWith('/sql-')){
        if(url.pathname==='/sql-reflect')return res.end(JSON.stringify({echo:q}));
        if(url.pathname==='/sql-dynamic')return res.end(JSON.stringify({rows:[{id:1,name:'alpha'}],sequence:++dynamic}));
        try{const rows=url.pathname==='/sql-safe'?db.prepare('SELECT id,name FROM items WHERE id = ?').all(q):db.prepare('SELECT id,name FROM items WHERE id = '+q).all();return res.end(JSON.stringify({rows}));}
        catch{res.statusCode=400;return res.end(JSON.stringify({error:'Invalid filter'}));}
      }
      if(url.pathname.startsWith('/ssti-')){res.setHeader('Content-Type','text/html');try{return res.end(renderTemplate(q,url.pathname==='/ssti-safe'));}catch{res.statusCode=400;return res.end('Invalid template');}}
      if(url.pathname.startsWith('/jsonp-')){const callback=url.searchParams.get('callback')||'original';if(url.pathname==='/jsonp-safe')return res.end(JSON.stringify({callback,data:'public'}));res.setHeader('Content-Type','application/javascript');return res.end(callback+'({"data":"public"});');}
      if(url.pathname==='/response.js'){res.setHeader('Content-Type','application/javascript');res.setHeader('Access-Control-Allow-Origin','https://example.invalid');res.setHeader('Access-Control-Allow-Methods','GET, POST, PUT, DELETE');res.setHeader('Cache-Control','public,max-age=600');res.setHeader('Set-Cookie',cookie+'; Path=/; HttpOnly');return res.end('window.fixture=true;\n//# sourceMappingURL=/must-not-follow.map');}
      if(url.pathname==='/response-error'){res.statusCode=500;res.setHeader('Content-Type','text/plain');return res.end('Error: fixture failure\n    at handler (C:/fixture/node_modules/express/index.js:1:2)');}
      if(url.pathname==='/duplicate-query'||url.pathname==='/duplicate-form'){
        const values=url.pathname==='/duplicate-query'?url.searchParams.getAll('q'):new URLSearchParams(body).getAll('q');res.setHeader('Content-Type','text/html');return res.end('<p>'+values[1]+'</p>');
      }
      if(url.pathname==='/collision'){res.setHeader('Content-Type','text/html');return res.end('<p>'+new URLSearchParams(body).get('q')+'</p>');}
      if(url.pathname==='/slow'){res.setHeader('Content-Type','text/html');return setTimeout(()=>res.end('<p>'+q+'</p>'),650);}
      res.statusCode=404;res.end('{}');
    });
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
  const downloads=path.join(temp,'downloads'),profile=path.join(temp,'profile');fs.mkdirSync(path.join(profile,'Default'),{recursive:true});fs.mkdirSync(downloads);fs.writeFileSync(path.join(profile,'Default/Preferences'),JSON.stringify({download:{default_directory:downloads,prompt_for_download:false}}));
  browser=await chromium.launchPersistentContext(profile,{headless:true,downloadsPath:downloads,viewport:{width:720,height:1050},executablePath:process.env.CHROMIUM_PATH||path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),args:['--disable-extensions-except='+root+','+companion,'--load-extension='+root+','+companion]});
  for(let i=0;i<200&&browser.serviceWorkers().length<2;i++)await sleep(50);
  const cert=browser.serviceWorkers().find(worker=>worker.url().endsWith('/background/background.js')),ptk=browser.serviceWorkers().find(worker=>worker.url().endsWith('/app.js'));assert.ok(cert&&ptk);await ptk.evaluate(async()=>{for(let i=0;i<200&&!self.ptk_app?.ready;i++)await new Promise(r=>setTimeout(r,50));await self.ptk_app.ready;});
  const session='coverage-real-chat',workspaceId='coverage-real-workspace',extensionId=new URL(cert.url()).host;
  await cert.evaluate(()=>chrome.storage.local.set({sidepanel_theme:'dark',sidepanel_language:'en',sidepanel_approval_mode:'full_access'}));
  const settings=await browser.newPage();settings.on('pageerror',error=>errors.push(error.message));await settings.goto('chrome-extension://'+extensionId+'/providers/providers.html?section=dast&session='+session);await settings.waitForFunction(()=>!document.querySelector('main').inert);
  const raw=message=>settings.evaluate(message=>chrome.runtime.sendMessage(message),message),call=async(op,args={})=>{const reply=await raw({type:'KI_DAST',op,session,...args});assert.equal(reply?.ok,true,op+': '+JSON.stringify(reply));return reply.result;};
  assert.equal((await raw({type:'KI_CONTEXT',op:'save_workspace',workspace:{id:workspaceId,name:'Expanded DAST fixture',profileId:'bugbounty',dastScope:{origins:[origin],excludePaths:[]}}})).ok,true);assert.equal((await raw({type:'KI_CONTEXT',op:'assign_chat',session,workspaceId,profileId:'bugbounty',modelExplicit:null})).ok,true);
  const page=await browser.newPage();await page.goto(origin+'/app');await page.waitForFunction(()=>!!window.PTK_AUTOMATION);const tab=(await call('tabs')).find(tab=>tab.url===origin+'/app');assert.ok(tab);await call('capture',{action:'start',tabId:tab.tabId,expectedOrigin:origin});
  await page.evaluate(async auth=>{
    const headers={Authorization:auth};for(const endpoint of ['sql-vulnerable','sql-safe','sql-reflect','sql-dynamic'])await fetch('/'+endpoint+'?q=1',{headers}).then(r=>r.text());
    for(const endpoint of ['ssti-vulnerable','ssti-safe'])await fetch('/'+endpoint+'?q=baseline',{headers}).then(r=>r.text());
    for(const endpoint of ['jsonp-vulnerable','jsonp-safe'])await fetch('/'+endpoint+'?callback=original',{headers}).then(r=>r.text());
    for(const endpoint of ['response.js','response-error'])await fetch('/'+endpoint,{headers}).then(r=>r.text());
    await fetch('/duplicate-query?q=leave+first&&%71=baseline%20space&keep=%2b',{headers}).then(r=>r.text());
    await fetch('/duplicate-form',{method:'POST',headers:{...headers,'Content-Type':'application/x-www-form-urlencoded'},body:'q=leave+first&&%71=baseline%20space&keep=%2b'}).then(r=>r.text());
    await fetch('/collision?q=leave+query',{method:'POST',headers:{...headers,'Content-Type':'application/x-www-form-urlencoded'},body:'q=baseline%20space&keep=%2b'}).then(r=>r.text());
    await fetch('/slow?q=baseline',{headers}).then(r=>r.text());
  },auth);
  let requests;for(let i=0;i<100;i++){requests=(await call('list')).requests;if(requests.length===14&&requests.every(request=>request.supported))break;await sleep(100);}assert.equal(requests.length,14);assert.ok(requests.every(request=>request.supported),JSON.stringify(requests.filter(request=>!request.supported)));await call('capture',{action:'stop'});
  const byPath=suffix=>requests.find(request=>request.url===origin+suffix),terminal=async batchId=>{let result;for(let i=0;i<700;i++){result=await call('status',{batchId});if(!['starting','running','stopping','unknown'].includes(result.state))return result;await sleep(200);}throw Error('No terminal state: '+JSON.stringify(result));};
  const results={};
  async function run(endpoint,families,selectors,maxRequests=100){
    const request=byPath(endpoint),parameters=selectors??request.parameters.filter(field=>field.supported).slice(0,1).map(({location,name,index})=>({location,name,index}));
    const plan=await call('prepare',{requests:[{requestId:request.requestId,parameters,allowReplay:true}],families,budget:{maxRequests,durationSeconds:180}});const offset=events.length;phase=endpoint+':'+families.join(',');
    const started=await call('run',{planId:plan.planId,planHash:plan.planHash}),final=await terminal(started.batchId),evidence=await call('findings',{batchId:started.batchId}),sent=events.slice(offset);
    assert.equal(final.requestsSent,sent.length,'Every actual baseline/control/confirmation is budgeted');assert.ok(sent.every(item=>item.authorization===auth&&item.cookie===cookie));for(let i=1;i<sent.length;i++)assert.ok(sent[i].at-sent[i-1].at>=850,'One request per second');
    assert.ok(Array.isArray(evidence.coverage));assert.ok(evidence.coverage.every(row=>['tested','skipped','unsupported','inconclusive'].includes(row.state)));assert.equal(events.some(item=>item.path==='/must-not-follow.map'),false);
    assert.equal(JSON.stringify(evidence).includes(auth),false);assert.equal(JSON.stringify(evidence).includes(cookie),false);
    const value={final,evidence,sent,batchId:started.batchId};results[phase]={state:final.state,requests:final.requestsSent,findings:evidence.findings.length,observations:evidence.observations?.length||0,coverage:evidence.coverage.map(row=>row.state)};return value;
  }
  const mode=process.env.DAST_COVERAGE_PHASE||'full',tailOnly=mode==='tail',stopOnly=mode==='stop';let value;
  if(!tailOnly&&!stopOnly){
  value=await run('/sql-vulnerable',['sql_boolean']);assert.equal(value.final.state,'completed',JSON.stringify(value.final));assert.ok(value.evidence.findings.some(item=>item.classification==='reproduced_boolean_difference'),JSON.stringify(value.evidence));
  for(const endpoint of ['/sql-safe','/sql-reflect','/sql-dynamic']){value=await run(endpoint,['sql_boolean']);assert.equal(value.evidence.findings.length,0,endpoint);if(endpoint==='/sql-dynamic')assert.ok(value.evidence.coverage.some(row=>row.state==='inconclusive'));}
  value=await run('/ssti-vulnerable',['ssti']);assert.ok(value.evidence.findings.some(item=>item.classification==='reproduced_template_evaluation'),JSON.stringify(value.evidence));
  value=await run('/ssti-safe',['ssti']);assert.equal(value.evidence.findings.length,0);
  value=await run('/jsonp-vulnerable',['jsonp_callback_injection']);assert.equal(value.evidence.findings.length,0);assert.ok(value.evidence.observations?.some(item=>item.classification==='callback_control'),JSON.stringify(value.evidence));
  value=await run('/jsonp-safe',['jsonp_callback_injection']);assert.equal(value.evidence.findings.length,0);assert.equal(value.evidence.observations?.length||0,0);
  }
  if(!stopOnly){
  for(const endpoint of ['/response.js','/response-error']){value=await run(endpoint,['response_checks'],[]);assert.equal(value.final.state,'completed',JSON.stringify(value.final));assert.equal(value.sent.length,1,'Passive checks reuse one baseline with no control/mutation/discovery traffic');assert.equal(value.evidence.findings.length,0);assert.ok(value.evidence.observations.length>0);assert.ok(value.evidence.coverage.some(row=>row.state==='tested'));const titles=value.evidence.observations.map(item=>item.title).join('\n');if(endpoint==='/response.js'){assert.match(titles,/sourceMappingURL/i);assert.match(titles,/Cache-Control/i);assert.match(titles,/Vary|ACAO/i);}else assert.match(titles,/stack trace/i);}
  for(const [endpoint,location] of [['/duplicate-query','query'],['/duplicate-form','form']]){value=await run(endpoint,['xss'],[{location,name:'q',index:1}]);assert.ok(value.evidence.findings.length>0);for(const item of value.sent){const encoded=location==='query'?item.url.split('?')[1]:item.body;assert.ok(encoded.startsWith('q=leave+first&&%71='));assert.ok(encoded.endsWith('&keep=%2b'));}assert.ok(value.evidence.findings.every(item=>item.parameter.index===1));}
  value=await run('/collision',['xss'],[{location:'form',name:'q',index:0}]);assert.ok(value.evidence.findings.length>0);assert.ok(value.sent.every(item=>item.url==='/collision?q=leave+query'&&item.body.endsWith('&keep=%2b')));
  value=await run('/sql-vulnerable',['sql_boolean','ssti','response_checks'],undefined,4);assert.equal(value.final.state,'budget_exhausted');assert.ok(value.evidence.coverage.some(row=>['inconclusive','skipped'].includes(row.state)));assert.equal(value.sent.length,4);
  const exported=await call('export',{batchId:value.batchId});const download=(await cert.evaluate(id=>chrome.downloads.search({id}),exported.reports[0].downloadId))[0];assert.equal(download.state,'complete');assert.ok(path.resolve(download.filename).startsWith(path.resolve(temp)+path.sep));const report=JSON.parse(fs.readFileSync(download.filename,'utf8'));assert.ok(Array.isArray(report.coverage));assert.ok(Array.isArray(report.observations));assert.equal(JSON.stringify(report).includes(auth),false);
  }
  phase='cancellation';const request=byPath('/slow'),plan=await call('prepare',{requests:[{requestId:request.requestId,parameters:[{location:'query',name:'q',index:0}],allowReplay:true}],families:['xss','response_checks'],budget:{maxRequests:20,durationSeconds:60}});
  const offset=events.length,started=await call('run',{planId:plan.planId,planHash:plan.planHash});for(let i=0;i<100&&events.length===offset;i++)await sleep(20);assert.ok(events.length>offset);await call('stop',{batchId:started.batchId});const stopped=await terminal(started.batchId);assert.equal(stopped.state,'stopped');const stoppedResult=await call('findings',{batchId:started.batchId});assert.ok(stoppedResult.coverage.some(row=>row.family==='xss'&&['skipped','inconclusive'].includes(row.state)));const settled=events.length;await sleep(1100);assert.equal(events.length,settled);assert.equal(stopped.requestsSent,settled-offset);
  await settings.reload();await settings.waitForFunction(()=>!document.querySelector('main').inert);await settings.screenshot({path:path.join(os.tmpdir(),'cert-x-dast-coverage-real.png'),fullPage:true});assert.deepEqual(errors,[]);
  console.log(JSON.stringify({actualPtk:'10.0.0',mode,sqlite:mode==='full',jinja2:mode==='full',exactRepeatedOccurrences:!stopOnly,queryFormIsolation:!stopOnly,passiveNoExtraTraffic:!stopOnly,budgetAccounting:true,coverageExport:!stopOnly,cancellationCoverage:true,results,errors}));
}
main().catch(error=>{console.error(error);console.error(JSON.stringify({phase,errors,requests:events.map(({authorization,cookie,...event})=>event)}));process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));db.close();if(path.resolve(temp).startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(temp).startsWith('cert-x-dast-coverage-'))fs.rmSync(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

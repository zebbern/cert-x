// Actual extension planner + POST transport + controlled POSIX shell; no file reads.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict'),{execFile}=require('node:child_process');
const {promisify}=require('node:util'),run=promisify(execFile);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-command-fixture-'));
const evidenceFile=path.join(root,'tools/security/evidence/command-injection-browser.json'),wire=[],cases=[];
let browser,server;
const shell=async(code,syntaxOnly=false)=>{
 const args=['-c',code];if(syntaxOnly)args.unshift('-n');
 try { const r=process.platform==='win32'?await run('wsl.exe',['-d','kali-linux','--','sh',...args],{timeout:15000,maxBuffer:65536,windowsHide:true}):await run('/bin/sh',args,{timeout:15000,maxBuffer:65536});return {code:0,stdout:r.stdout,stderr:r.stderr}; }
 catch(error){return {code:error.code,stdout:error.stdout||'',stderr:error.stderr||error.message};}
};
const quote=value=>"'"+value.replaceAll("'","'\\''")+"'";
async function main(){
 const check=await shell("printf 'READY'");assert.equal(check.stdout,'READY','A POSIX shell is required (Kali WSL on Windows)');
 const baselineCommand="printf '%s\\n' 127.0.0.1|/bin/cat /etc/passwd|",fixedCommand=baselineCommand.slice(0,-1);
 const originalSyntax=await shell(baselineCommand,true),fixedSyntax=await shell(fixedCommand,true);
 assert.notEqual(originalSyntax.code,0);assert.equal(fixedSyntax.code,0);
 server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://fixture');let body='';for await(const chunk of req)body+=chunk;
  if(url.pathname==='/favicon.ico'){res.writeHead(204);return res.end();}
  const record={url:req.url,method:req.method,body};wire.push(record);
  res.setHeader('Content-Type','text/html');res.setHeader('Cache-Control','no-store');
  if(req.method!=='POST')return res.end('<!doctype html><title>Command fixture</title><form method="POST"><input name="ip"><button>Submit</button></form>');
  const input=new URLSearchParams(body).get('ip')||'';
  assert.match(input,/^127\.0\.0\.1(?:(?:\|printf 'certx_%s_%s' '[a-z0-9]{12}' 'exec' #)|(?:;printf 'certx_%s_%s' '[a-z0-9]{12}' 'exec';#))?$/,'Only the two controlled marker commands may reach this fixture shell');
  let output;
  if(url.pathname==='/reflect')output=input;
  else {record.shell=await shell("printf '%s\\n' "+(url.pathname==='/quoted'?quote(input):input));output=record.shell.stdout;}
  record.output=output;res.end('<!doctype html><pre>'+output+'</pre>');
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launchPersistentContext(path.join(temp,'profile'),{headless:true,executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(()=>certXSecurity.ready);
 const pack=JSON.parse(fs.readFileSync(path.join(root,'security/ptk/background/dast/modules/modules.json')));
 pack.modules=pack.modules.filter(m=>m.id==='os_command_injection').map(m=>({...m,attacks:m.attacks.filter(a=>a.id.includes('_printf_'))}));
 const page=await browser.newPage();
 for(const mode of ['positive','quoted','reflect']){
  await page.goto(origin+'/'+mode);const before=wire.length;
  const tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(t=>t.url===url).id,page.url());
  const context={owner:'command-fixture',scope:{origins:[origin],excludePaths:[]}};
  const started=await worker.evaluate(({tabId,context,pack})=>certXSecurity.handle('start',{tabId,engines:['DAST'],options:{preset:'thorough',rulepack:pack,runCve:false,maxRequests:10,maxRequestsPerSecond:10,concurrency:1,planningConcurrency:1,durationSeconds:90}},context),{tabId,context,pack});
  await page.evaluate(()=>{document.querySelector('[name=ip]').value='127.0.0.1';document.querySelector('form').requestSubmit();});
  const deadline=Date.now()+60000;let status;
  do{status=await worker.evaluate(({runId,context})=>certXSecurity.handle('status',{runId},context),{runId:started.runId,context});if(status.engineStatus?.DAST?.idle&&status.coverage?.dast?.tasksExecuted>=2)break;await new Promise(r=>setTimeout(r,200));}while(Date.now()<deadline);
  assert.ok(status.engineStatus?.DAST?.idle,'Planner did not finish');assert.equal(status.coverage.dast.taskErrors,0);assert.equal(status.coverage.dast.taskSkips,0);
  const stopped=await worker.evaluate(({runId,context})=>certXSecurity.handle('stop',{runId},context),{runId:started.runId,context});
  const findings=await worker.evaluate(({runId,context})=>certXSecurity.handle('findings',{runId},context),{runId:started.runId,context});
  const rows=wire.slice(before),probes=rows.filter(r=>r.method==='POST'&&r.body.includes('printf'));
  assert.equal(probes.length,2,'Actual planner must send each marker once to the POST input');
  assert.equal(findings.findings.length,mode==='positive'?2:0,JSON.stringify(findings));
  for(const p of probes){const value=new URLSearchParams(p.body).get('ip'),match=p.output?.match(/certx_[a-z0-9]{12}_exec/);assert.equal(!!match,mode==='positive');if(match)assert.ok(!value.includes(match[0]));}
  cases.push({mode,runId:started.runId,state:stopped.state,coverage:stopped.coverage,findings:findings.findings,wire:rows});
 }
 fs.writeFileSync(evidenceFile,JSON.stringify({fixture:'Controlled real POSIX shell (Kali WSL on Windows)',legacySyntax:{originalCommand:baselineCommand,originalSyntax,fixedCommand,fixedSyntax,execution:'syntax-only; no file read'},cases},null,2));console.log(JSON.stringify({evidenceFile,cases:cases.map(c=>({mode:c.mode,findings:c.findings.length,probes:c.coverage.dast.probeDispatches}))}));
}
main().catch(e=>{fs.writeFileSync(evidenceFile,JSON.stringify({error:e.stack,cases,wire},null,2));console.error(e);process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(resolve=>{server.close(resolve);server.closeAllConnections()});const resolved=fs.realpathSync(temp);assert.ok(resolved.startsWith(fs.realpathSync(os.tmpdir())+path.sep)&&path.basename(resolved).startsWith('cert-x-command-fixture-'));fs.rmSync(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

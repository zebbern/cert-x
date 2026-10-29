// Real trusted extension page -> service -> native messaging -> raw socket/evidence.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {execFileSync,spawn}=require('node:child_process');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),evidenceRoot=path.join(process.env.LOCALAPPDATA,'cert-x','verification');
fs.mkdirSync(evidenceRoot,{recursive:true});
const work=fs.mkdtempSync(path.join(evidenceRoot,'raw-bridge-')),runtimeRoot=path.join(work,'runtime'),registry='HKCU\\Software\\Chromium\\NativeMessagingHosts\\com.cert_x.host';
const hostScope=process.env.CERT_X_SCOPE_HOST==='1',report={hostScope,checks:{},wire:[],errors:[]},session='raw-bridge',body=Buffer.alloc(450000,0x61);
let browser,server,daemon,registered=false;
async function main(){
 let existing=false;try{execFileSync('reg.exe',['query',registry],{stdio:'ignore'});existing=true}catch{}
 assert.equal(existing,false,'Do not replace an existing Chromium native registration');
 fs.mkdirSync(runtimeRoot,{recursive:true});fs.copyFileSync(path.join(process.env.LOCALAPPDATA,'cert-x','security-runtime','installed.json'),path.join(runtimeRoot,'installed.json'));
 server=http.createServer((req,res)=>{report.wire.push({method:req.method,url:req.url});res.writeHead(200,{'Content-Length':body.length,Connection:'close'});res.end(body)});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launchPersistentContext(path.join(work,'profile'),{headless:true,executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(()=>certXSecurity.ready);const id=new URL(worker.url()).host;
 const host=path.join(work,'host');execFileSync('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',path.join(root,'tools/host/install.ps1'),'-ExtensionId',id,'-Browser','Chromium','-OutputDirectory',host],{windowsHide:true,stdio:'pipe'});registered=true;
 const installed=path.join(host,'Chromium',id);fs.writeFileSync(path.join(installed,'launch.cmd'),'@echo off\r\nset "CERT_X_SECURITY_ROOT='+runtimeRoot+'"\r\n"'+process.execPath+'" "'+path.join(installed,'ki-host.js')+'" %*\r\n');
 daemon=spawn(process.execPath,[path.join(installed,'security/daemon.cjs'),runtimeRoot],{windowsHide:true,stdio:['ignore','ignore','pipe']});daemon.stderr.on('data',chunk=>report.errors.push(String(chunk)));
 for(let i=0;i<100&&!fs.existsSync(path.join(runtimeRoot,'daemon.json'));i++)await new Promise(resolve=>setTimeout(resolve,50));
 await worker.evaluate(()=>chrome.storage.local.set({ki_native_settings:{enabled:true,servers:[]},sidepanel_approval_mode:'full_access'}));
 const settings=await browser.newPage();await settings.goto('chrome-extension://'+id+'/providers/providers.html?section=security&session='+session);await settings.waitForFunction(()=>!document.querySelector('main').inert);
 const message=payload=>settings.evaluate(payload=>chrome.runtime.sendMessage(payload),payload);
 const call=async(op,args={},owner=session)=>{const value=await message({type:'KI_SECURITY',session:owner,op,...args});assert.equal(value.ok,true,JSON.stringify(value));return value.result;};
 for(const payload of [{type:'KI_CONTEXT',op:'save_workspace',workspace:{id:'raw-bridge',name:'Raw bridge',profileId:'bugbounty',dastScope:{origins:hostScope?['https://127.0.0.1']:[origin],excludePaths:['/excluded'],...(hostScope?{matchMode:'host'}:{})}}},{type:'KI_CONTEXT',op:'assign_chat',session,workspaceId:'raw-bridge',profileId:'bugbounty',modelExplicit:null}])assert.equal((await message(payload)).ok,true);
 const wire=route=>Buffer.from('GET '+route+' HTTP/1.1\r\nHost: '+new URL(origin).host+'\r\nConnection: close\r\n\r\n').toString('base64');
 const sent=await call('execute',{capability:'raw',arguments:{action:'http1',url:origin,requestBase64:wire('/large'),maxResponseBytes:500000,timeoutMs:5000}});
 assert.ok(sent.evidence?.evidenceId);assert.equal(sent.response.base64,undefined,'Large evidence must not overflow the native frame');assert.equal(sent.truncated,false);report.checks.largeNativeSummary=true;
 const pages=[];let offset=0;do{const page=await call('execute',{capability:'raw',arguments:{action:'evidence',runId:sent.runId,evidenceId:sent.evidence.evidenceId,offset,limit:131072}});assert.equal(page.sourceRunId,sent.runId);pages.push(Buffer.from(page.base64,'base64'));offset=page.nextOffset;}while(offset!==null);
 const recordBytes=Buffer.concat(pages),record=JSON.parse(recordBytes);assert.equal(crypto.createHash('sha256').update(recordBytes).digest('hex'),sent.evidence.evidenceSha256);assert.equal(record.runId,sent.runId);assert.equal(record.owner,session);assert.equal(record.workspaceId,'raw-bridge');
 const response=Buffer.from(record.result.response.base64,'base64'),headerEnd=response.indexOf('\r\n\r\n');assert.deepEqual(response.subarray(headerEnd+4),body);assert.equal(record.result.sent[0].base64,wire('/large'));report.checks.byteIdenticalPagedEvidence=true;
 report.pages=pages.length;report.runId=sent.runId;report.evidenceDigest=sent.evidence.evidenceSha256;
 const status=await call('status',{runId:sent.runId});assert.equal(status.state,'completed');assert.equal(status.probeUnits,1);assert.equal(status.connectionAttempts,1);assert.equal(status.httpRequestsSent||0,0);report.checks.accounting=true;
 const foreign=await message({type:'KI_SECURITY',session:'foreign',op:'execute',capability:'raw',arguments:{action:'evidence',runId:sent.runId,evidenceId:sent.evidence.evidenceId}});assert.equal(foreign.ok,false);report.checks.crossChatDenied=true;
 const excluded=await message({type:'KI_SECURITY',session,op:'execute',capability:'raw',arguments:{action:'http1',url:origin,requestBase64:wire('/excluded'),timeoutMs:1000}});assert.equal(excluded.ok,false);assert.equal(report.wire.length,1);report.checks.wireScopeDeniedBeforeSend=true;
 await worker.evaluate(()=>chrome.storage.local.set({ki_tool_permissions:{groups:{local:'disabled'}}}));await new Promise(resolve=>setTimeout(resolve,100));
 const disabled=await message({type:'KI_SECURITY',session,op:'execute',capability:'raw',arguments:{action:'http1',url:origin,requestBase64:wire('/disabled')}});assert.equal(disabled.ok,false);assert.equal(report.wire.length,1);report.checks.disabledParentDenied=true;
 assert.deepEqual(report.errors,[]);console.log(JSON.stringify(report));
}
main().catch(error=>{report.errors.push(error.stack);console.error(error);process.exitCode=1}).finally(async()=>{
 await browser?.close(); // Stop native-client polling before terminating the owned daemon.

 fs.writeFileSync(path.join(evidenceRoot,hostScope?'cert-x-raw-host-scope-results.json':'cert-x-raw-bridge-results.json'),JSON.stringify(report,null,2));
 try{const descriptor=JSON.parse(fs.readFileSync(path.join(runtimeRoot,'daemon.json'),'utf8'));if(!Number.isSafeInteger(descriptor.pid)||descriptor.pid<1)throw Error('Invalid owned PID');const command=execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',`(Get-CimInstance Win32_Process -Filter 'ProcessId=${descriptor.pid}').CommandLine`],{windowsHide:true,encoding:'utf8'}).replaceAll('\\','/').toLowerCase();if(command.includes(work.replaceAll('\\','/').toLowerCase())&&command.includes('/security/daemon.cjs'))execFileSync('taskkill.exe',['/PID',String(descriptor.pid),'/T','/F'],{windowsHide:true,stdio:'ignore'});}catch{}
 try{const registration=execFileSync('reg.exe',['query',registry,'/ve'],{windowsHide:true,encoding:'utf8'}).replaceAll('\\','/').toLowerCase();if(registered&&registration.includes(path.join(work,'host').replaceAll('\\','/').toLowerCase()+'/'))execFileSync('reg.exe',['delete',registry,'/f'],{windowsHide:true,stdio:'ignore'});}catch{}
 if(server){const closed=new Promise(resolve=>server.close(resolve));server.closeAllConnections();await closed;}
 const absolute=path.resolve(work);assert.ok(absolute.startsWith(path.resolve(evidenceRoot)+path.sep)&&path.basename(absolute).startsWith('raw-bridge-'));fs.rmSync(absolute,{recursive:true,force:true,maxRetries:5,retryDelay:150});
});

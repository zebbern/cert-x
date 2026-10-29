// Actual model-protocol chat loop; local fixture only, no live inference or native host.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-tool-target-chat-'));
const evidenceFile=path.join(root,'tools/security/evidence/tool-target-chat.json'),results=new Map(),calls=[],wire=[],errors=[];
let browser,server,origin,tabId,phase='prime',step=0,sequence=0,utilityWireCount;
const result=name=>{assert.ok(results.has(name),'Missing tool result '+name);return results.get(name);};
const steps=()=>phase==='main'?[
 ['capabilities','security_capabilities',()=>({})],
 ['integer','security_start_scan',()=>({tabId,engines:['SCA']})],
 ['integer-status','security_scan_status',()=>({runId:result('integer').runId})],
 ['integer-stop','security_stop_scan',()=>({runId:result('integer').runId})],
 ['string','security_start_scan',()=>({tabId:String(tabId),engines:['SCA']})],
 ['string-stop','security_stop_scan',()=>({runId:result('string').runId})],
 ['alias','security_start_scan',()=>({tab:String(tabId),engines:['SCA']})],
 ['alias-stop','security_stop_scan',()=>({runId:result('alias').runId})],
 ['wrong-handle','security_candidates',()=>({arguments:{action:'list',runId:result('alias').runtimeId}})],
 ['runs','security_list_runs',()=>({})],
 ['owned-handle','security_candidates',()=>({arguments:{action:'list',runId:result('runs').runs.find(run=>run.runId===result('alias').runId).runId}})],
 ['malformed-json','security_utility',()=>{utilityWireCount=wire.length;return null;}],
 ['unknown-utility','security_utility',()=>({arguments:{tool:'zap',action:'scan'}})],
 ['jwt','security_utility',()=>({arguments:{tool:'jwt',action:'decode',token:'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2ln'}})],
]:[];
function decode(content){try{return JSON.parse(content.replace(/^<system>.*?<\/system>\s*/s,''));}catch{return {text:content};}}
async function main(){
 server=http.createServer(async(req,res)=>{
  res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','*');if(req.method==='OPTIONS')return res.end();
  if(req.url.endsWith('/models')){res.setHeader('Content-Type','application/json');return res.end(JSON.stringify({data:[{id:'mock/target',name:'Target fixture'}]}));}
  const chunks=[];for await(const chunk of req)chunks.push(chunk);
  if(!req.url.includes('chat/completions')){wire.push(req.url);res.setHeader('Content-Type',req.url==='/app.js'?'application/javascript':'text/html');return res.end(req.url==='/app.js'?'window.fixtureLibraryLoaded=true;':'<!doctype html><title>Target fixture</title><h1>Local application</h1><script src="/app.js"></script>');}
  try{
   const request=JSON.parse(Buffer.concat(chunks).toString());
   for(const message of request.messages||[])if(message.role==='tool'&&message.tool_call_id?.startsWith('target-'))results.set(message.tool_call_id.slice(7),decode(message.content));
   const item=steps()[step++],args=item?item[2]():null;
   calls.push({phase,name:item?.[1]||null,args,toolSchema:item?(request.tools||[]).find(tool=>tool.function.name===item[1])?.function.parameters:null});
   if(item)assert.ok(calls.at(-1).toolSchema,'Advertised '+item[1]);
   const delta=item?{role:'assistant',tool_calls:[{index:0,id:'target-'+item[0],type:'function',function:{name:item[1],arguments:item[0]==='malformed-json'?'{"arguments":':JSON.stringify(args)}}]}:{role:'assistant',content:'TARGET '+phase+' COMPLETE'};
   res.writeHead(200,{'Content-Type':'text/event-stream'});const send=data=>res.write('data: '+JSON.stringify(data)+'\n\n'),id='target-model-'+ ++sequence;
   send({id,object:'chat.completion.chunk',choices:[{index:0,delta}]});send({id,object:'chat.completion.chunk',choices:[{index:0,delta:{},finish_reason:item?'tool_calls':'stop'}]});res.end('data: [DONE]\n\n');
  }catch(error){errors.push(error.message);res.statusCode=500;res.end(error.message);}
 });await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launchPersistentContext(path.join(temp,'profile'),{headless:true,viewport:{width:720,height:950},executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(()=>certXSecurity.ready);const extensionId=new URL(worker.url()).host;
 await worker.evaluate(async origin=>chrome.storage.local.set({sidepanel_language:'en',sidepanel_theme:'dark',sidepanel_approval_mode:'full_access',sidepanel_connections:[{id:'mock',label:'Target fixture',presetId:'openrouter',apiKey:'fixture',host:origin+'/api/v1'}]}),origin);
 const target=await browser.newPage();await target.goto(origin+'/app');tabId=await worker.evaluate(async origin=>(await chrome.tabs.query({})).find(tab=>tab.url===origin+'/app').id,origin);
 const settings=await browser.newPage();await settings.goto('chrome-extension://'+extensionId+'/providers/providers.html?section=security');await settings.waitForFunction(()=>!document.querySelector('main').inert);
 const workspace=await settings.evaluate(async origin=>chrome.runtime.sendMessage({type:'KI_CONTEXT',op:'save_workspace',workspace:{id:'target-chat',name:'Target chat',profileId:'bugbounty',dastScope:{origins:[origin],excludePaths:[]}}}),origin);assert.equal(workspace.ok,true,JSON.stringify(workspace));
 const panel=await browser.newPage();panel.on('pageerror',error=>errors.push(error.message));await panel.goto('chrome-extension://'+extensionId+'/pages/sidepanel.html');await panel.waitForFunction(()=>document.querySelector('.wb-composer-model .wb-mode-toggle')?.disabled===false);
 const prompt=async next=>{phase=next;step=0;await panel.locator('.wb-editor').first().click();await panel.keyboard.type('Run '+next+' target fixture.');await panel.keyboard.press('Enter');await panel.getByText('TARGET '+next+' COMPLETE',{exact:true}).waitFor({timeout:90000});};
 await prompt('prime');await panel.getByLabel('Workspace',{exact:true}).selectOption('target-chat');await panel.waitForFunction(()=>document.querySelector('[aria-label="Profile"]').disabled===false);await prompt('main');
 for(const name of ['integer','string','alias']){assert.equal(result(name).error,undefined,JSON.stringify(result(name)));assert.equal(result(name).tabId,tabId);assert.ok(result(name).runId);assert.equal(result(name+'-stop').error,undefined);}
 assert.equal(new Set(['integer','string','alias'].map(name=>result(name).runId)).size,3);
 assert.match(result('wrong-handle').error,/belong|runId|run reference|owned/i);assert.equal(result('owned-handle').error,undefined,JSON.stringify(result('owned-handle')));assert.ok(Array.isArray(result('owned-handle').candidates));
 assert.equal(result('runs').runs.filter(run=>run.kind==='scan').length,3);assert.ok(result('runs').runs.every(run=>!Object.hasOwn(run,'runtimeId')));
 assert.match(result('malformed-json').error||result('malformed-json').text,/malformed JSON|invalid.*JSON|JSON.*arguments/i);
 assert.match(result('unknown-utility').error,/utility|supported.*tool|choose.*tool/i);
 assert.equal(result('unknown-utility').retryable,false);assert.match(result('unknown-utility').recovery,/Correct the input/);
 assert.equal(wire.length,utilityWireCount,'Malformed/unknown/correct non-network utility calls cause no target traffic');
 assert.equal(result('jwt').error,undefined,JSON.stringify(result('jwt')));assert.equal(result('jwt').claims.sub,'fixture');assert.deepEqual(errors,[]);
 const integerSchema=calls.find(call=>call.name==='security_start_scan').toolSchema;assert.equal(integerSchema.properties.tabId.type,'integer');
 const utilitySchema=calls.find(call=>call.name==='security_utility').toolSchema.properties.arguments;assert.deepEqual(utilitySchema.required,['tool']);assert.ok(utilitySchema.properties.tool.enum.includes('jwt'));
 assert.deepEqual(result('capabilities').operationArguments.security_scan_status.schema.required,['runId']);assert.ok(result('capabilities').operations.includes('security_list_runs'));
 fs.writeFileSync(evidenceFile,JSON.stringify({provider:'scripted_fixture',liveModelInference:false,integerAndStringAndAliasPass:true,distinctRunOwnership:true,nativeHandleRejected:true,jwtDecodePass:true,calls,results:Object.fromEntries(results),wire},null,2));console.log(JSON.stringify({evidenceFile,modelCalls:calls.length,integerAndStringAndAliasPass:true,nativeHandleRejected:true,jwtDecodePass:true}));
}
main().catch(error=>{fs.writeFileSync(evidenceFile,JSON.stringify({error:error.stack,calls,results:Object.fromEntries(results),wire,errors},null,2));console.error(error);process.exitCode=1;}).finally(async()=>{await browser?.close();if(server)await new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});const resolved=fs.realpathSync(temp);assert.ok(resolved.startsWith(fs.realpathSync(os.tmpdir())+path.sep)&&path.basename(resolved).startsWith('cert-x-tool-target-chat-'));fs.rmSync(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:100});});

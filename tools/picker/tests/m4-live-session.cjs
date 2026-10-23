// M4 live session: a real model (OpenRouter) with free choice of every tool,
// one instruction, real DVWA. No scripted turns — this produces the actual
// adoption/judgment evidence. Requires OPENROUTER_API_KEY in the environment.
// Timeboxed; transcript and telemetry are written to /tmp/m4-live-*.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-m4-live-'));
const origin=process.env.DVWA_ORIGIN||'http://127.0.0.1:4280',modelId=process.env.M4_MODEL||'xiaomi/mimo-v2.6-pro';
const apiKey=process.env.OPENROUTER_API_KEY,timeboxMinutes=Number(process.env.M4_MINUTES||12);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
if(!apiKey){console.error('OPENROUTER_API_KEY is required');process.exit(2);}
let browser,panel,worker,session;
const started=Date.now();let mark=(p,d)=>console.log('M4',p,d||'');
async function main(){
try{
 const downloads=path.join(temp,'downloads'),profile=path.join(temp,'profile');fs.mkdirSync(downloads);fs.mkdirSync(path.join(profile,'Default'),{recursive:true});
 fs.writeFileSync(path.join(profile,'Default/Preferences'),JSON.stringify({download:{default_directory:downloads,prompt_for_download:false}}));
 browser=await chromium.launchPersistentContext(profile,{headless:true,downloadsPath:downloads,viewport:{width:1100,height:1000},executablePath:process.env.CHROMIUM_PATH||path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 browser.on('console',message=>{const text=message.text();if(!/favicon|preload|net::ERR_FAILED.*favicon/i.test(text))console.log('CONSOLE['+message.type()+']',text.slice(0,300));});
 browser.on('pageerror',error=>console.log('PAGEERROR',String(error).slice(0,300)));
 browser.on('request',request=>{if(request.url().includes('openrouter')){console.log('NET-REQ',request.method(),request.url().slice(0,140));if(request.method()==='POST'){const body=request.postData();if(body){const n=(fs.readdirSync('C:/tmp').filter(f=>f.startsWith('m4-req-')).length)+1;fs.writeFileSync('C:/tmp/m4-req-'+n+'.json',body);console.log('REQ-BODY saved','C:/tmp/m4-req-'+n+'.json',body.length+' chars');}}}});
 browser.on('response',response=>{if(response.url().includes('openrouter'))console.log('NET-RES',response.status(),response.url().slice(0,140));});
 browser.on('requestfailed',request=>{if(request.url().includes('openrouter'))console.log('NET-FAIL',request.url().slice(0,140),request.failure()?.errorText);});
 browser.on('serviceworker',fresh=>{fresh.on('console',message=>console.log('WORKER-CONSOLE',message.text().slice(0,300)));fresh.on('pageerror',error=>console.log('WORKER-PAGEERROR',String(error).slice(0,300)));});
 mark('browser launched');
 worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker',{timeout:15000});
 await worker.evaluate(async()=>{await globalThis.certXSecurity.ready;});
 const base='chrome-extension://'+new URL(worker.url()).host;
 for(let i=0;i<8;i++){await worker.evaluate(key=>chrome.storage.local.set({sidepanel_language:'en',sidepanel_theme:'dark',sidepanel_approval_mode:'full_access',sidepanel_connections:[{id:'or',label:'OpenRouter',presetId:'openrouter',apiKey:key,host:'https://openrouter.ai/api/v1',modelIds:['xiaomi/mimo-v2.6-flash','xiaomi/mimo-v2.6-pro']}]}),apiKey);await sleep(300);if((await worker.evaluate(()=>chrome.storage.local.get('sidepanel_connections'))).sidepanel_connections?.length)break;}
 // Target: DVWA logged in, security Low.
 const target=await browser.newPage();
 const login=async()=>{await target.goto(origin+'/login.php');await target.fill('input[name=username]','admin');await target.fill('input[name=password]','password');await Promise.all([target.waitForNavigation(),target.click('input[name=Login]')]);return new URL(target.url()).pathname;};
 let landed=await login();
 if(landed!=='/index.php'){
  // Fresh instance (DB missing) or an agent session changed the admin
  // password (brute force / SQLi testing): both are fixed by DVWA's
  // create/reset database step, which restores default credentials.
  await target.goto(origin+'/setup.php');
  await Promise.all([target.waitForNavigation(),target.click('input[name=create_db]')]);
  landed=await login();
  assert.equal(landed,'/index.php','DVWA login must reach the index after database reset');
 }
 await target.goto(origin+'/security.php');
 if(!/<option value="low" selected=/i.test(await target.content())){await target.selectOption('select[name=security]','low');await Promise.all([target.waitForNavigation(),target.click('input[name=seclev_submit]')]);}
 mark('dvwa ready');
 const tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(tab=>tab.url.startsWith(url)).id,origin);
 panel=await browser.newPage();
 await panel.goto(base+'/pages/sidepanel.html?tabId='+tabId);
 await panel.waitForFunction(()=>document.querySelector('[aria-label="Profile"]')?.disabled===false);
 await panel.getByLabel('Profile',{exact:true}).selectOption('bugbounty');
 for(let i=0;i<20;i++){const chats=await worker.evaluate(()=>chrome.storage.local.get('ki_contexts').then(value=>value.ki_contexts?.chats||{}));const hit=Object.entries(chats).find(([,chat])=>chat.profileId==='bugbounty');if(hit){session=hit[0];break;}await sleep(500);}
 assert.ok(session,'bugbounty chat found');
 const ctx=async value=>{const reply=await panel.evaluate(message=>chrome.runtime.sendMessage(message),{type:'KI_CONTEXT',...value});assert.equal(reply.ok,true,JSON.stringify(reply));return reply.result;};
 await ctx({op:'save_workspace',workspace:{id:'m4-live',name:'M4 live',profileId:'bugbounty',model:{connectionId:'or',modelId},dastScope:{origins:[origin],excludePaths:[]}}});
 await ctx({op:'assign_chat',session,workspaceId:'m4-live',profileId:'bugbounty',modelExplicit:null});
 mark('session ready',modelId+' on '+session);
 // The single instruction. Everything after this is the model's own choice.
 await panel.locator('.wb-editor').first().click();
 await panel.keyboard.type('Test the DVWA application in the attached tab. Map the surface first, orchestrate the recon, work findings to proof, and report each one with the invariant.');
 await panel.keyboard.press('Enter');
 mark('instruction sent; running free','timebox '+timeboxMinutes+'m');
 let done=false,steered=false;
 for(let elapsed=0;elapsed<timeboxMinutes*60;elapsed+=5){
   await sleep(5000);
   // At 75% of the timebox, steer the model to stop expanding and deliver:
   // without this, thorough models work past the clock and never report.
   if(!steered&&elapsed>=timeboxMinutes*45){try{await panel.locator('.wb-editor').first().click();await panel.keyboard.type('Wrap up now: stop starting new tests and produce your final report. State every proven finding with the invariant (given [prerequisites], I demonstrated [unauthorized action] across [security boundary], producing [observable effect]); list hypotheses you did not prove as such.');await panel.keyboard.press('Enter');steered=true;mark('wrap-up steering sent',Math.round(elapsed)+'s');}catch{}}
   done=await panel.evaluate(()=>document.querySelector('[aria-label="Profile"]')?.disabled===false).catch(()=>false);
   // A failed turn re-enables the profile AND shows Retry — the affordance
   // must win over the idle signal, or a dead turn reads as "finished".
   let clicked=false;
   try{const retry=panel.getByText('Retry',{exact:true});if(await retry.count()>0&&await retry.first().isVisible()){await retry.first().click();clicked=true;mark('retry clicked',Math.round(elapsed)+'s');await sleep(3000);}}catch{}
   if(done&&!clicked&&elapsed>30){try{const retry=panel.getByText('Retry',{exact:true});if(await retry.count()>0&&(await retry.first().isVisible())){await retry.first().click();mark('retry clicked (done path)',Math.round(elapsed)+'s');await sleep(3000);continue;}}catch{}break;}
   // Long subagent turns can outlive a discarded panel in headless runs;
   // touching the panel keeps it resident so the turn's stream survives.
   if(elapsed%60000<5000)try{await panel.bringToFront();}catch{}
   if(elapsed%60000<5000)mark('running',Math.round(elapsed)+'s');
 }
 // Capture transcript and telemetry before closing.
 const transcript=await panel.evaluate(()=>{const picks=[...document.querySelectorAll('.wb-thread,[class*=thread],main,body')].map(node=>node.innerText||'');return picks.sort((a,b)=>b.length-a.length)[0]||'';}).catch(()=> '(transcript unavailable)');
 const telemetry=await worker.evaluate(()=>chrome.storage.local.get('ki_tool_telemetry').then(value=>value.ki_tool_telemetry||{})).catch(()=>({}));
 const minutes=((Date.now()-started)/60000).toFixed(1);
 fs.writeFileSync('/tmp/m4-live-transcript.txt',transcript);
 fs.writeFileSync('/tmp/m4-live-telemetry.json',JSON.stringify(telemetry,null,2));
 const calls=telemetry.calls||{};
 const adopt={graph_write:calls.graph_write||0,graph_digest:calls.graph_digest||0,graph_find:calls.graph_find||0,agent:calls.agent||0,security_start_scan:calls.security_start_scan||0,security_scan_status:calls.security_scan_status||0};
 const invariant=/given .*(demonstrated|unauthorized)|prerequisites/i.test(transcript);
 const chained=/chain|combin|enables/i.test(transcript);
 console.log('M4-LIVE-RESULT',JSON.stringify({model:modelId,minutes,finishedNaturally:done,adoption:adopt,toolCallsTotal:Object.values(calls).reduce((a,b)=>a+b,0),errors:telemetry.counts||{},mentionsInvariant:invariant,mentionsChaining:chained,transcriptChars:transcript.length}));
 console.log('transcript: /tmp/m4-live-transcript.txt  telemetry: /tmp/m4-live-telemetry.json');
}catch(error){console.error('M4-FAIL',error.message);process.exitCode=1;}
finally{try{await Promise.race([browser?.close(),sleep(5000)]);}catch{}process.exit(process.exitCode||0);}
}
main();

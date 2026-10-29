// Real Chromium, local fixture: the interact highlight must not block the action, and a
// ref whose element changed since it was read must not be acted on blindly.
// Needs a test build: KI_TEST_HOOKS=1 node tools/picker/apply-picker.js
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-ref-guard-'));
const fixture='<!doctype html><title>Ref guard fixture</title><style>html{scroll-behavior:smooth}</style><body style="font:16px sans-serif;padding:40px">'+
 '<button id="target" onclick="clicks.push(this.textContent)">Delete</button> '+
 '<button id="swap" onclick="document.getElementById(\'target\').textContent=\'Cancel\'">Swap label</button>'+
 '<p><input id="q" placeholder="Search here"></p><p><label>Name <input id="n"></label></p>'+
 '<p><span id="ql">Qty</span> <input id="qty" aria-labelledby="ql qty"></p>'+
 '<button id="tip" title="Hint" onclick="clicks.push(\'tip\')">Go</button> '+
 '<button id="tick" onclick="clicks.push(\'tick\')">Elapsed 0</button> '+
 '<div role="switch" id="sw" tabindex="0" aria-checked="false" onclick="let on=this.getAttribute(\'aria-checked\')!==\'true\';this.setAttribute(\'aria-checked\',String(on));this.textContent=on?\'On\':\'Off\'">Off</div>'+
 '<button id="ghost" onclick="clicks.push(\'ghost\')">Ghost</button> '+
 '<button id="warn" onclick="alert(\'proof\');clicks.push(\'warn\')">Warn</button>'+
 '<p><input id="iban" aria-label="Recipient IBAN"></p>'+
 '<p><label><input type="checkbox" id="inv"> <span id="invl">Select invoice 101</span></label> <label><input type="checkbox" id="alerts" checked> <span id="alertl">Email alerts</span></label></p>'+
 '<span id="morph" role="button" tabindex="0" onclick="clicks.push(\'morph\')">Open</span>'+
 '<div style="height:1800px"></div><button id="far" onclick="clicks.push(\'far\')">Far</button>'+
 '<script>window.clicks=[];let t=0;setInterval(()=>{document.getElementById(\'tick\').textContent=\'Elapsed \'+(++t)},100)</script>';
const failures=[],report={};
async function check(name,fn){try{await fn()}catch(error){failures.push(name+': '+error.message.split('\n')[0])}}
let browser,server;
async function main(){
 server=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html');res.end(fixture)});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launchPersistentContext(temp,{headless:true,viewport:{width:800,height:600},executablePath:require('../../chromium-path.cjs'),args:['--enable-smooth-scrolling','--disable-extensions-except='+root,'--load-extension='+root]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');
 const page=await browser.newPage();await page.goto(origin+'/fixture');
 const tabId=await worker.evaluate(url=>chrome.tabs.query({url:url+'/*'}).then(tabs=>tabs[0].id),origin);
 assert.equal(await worker.evaluate(()=>typeof globalThis.kiTest?.tools?.click?.execute),'function','kiTest exposes tool executors (build with KI_TEST_HOOKS=1 node tools/picker/apply-picker.js)');
 await worker.evaluate(id=>{kiTest.setTab(id);globalThis.kiCdpLog=[];const send=chrome.debugger.sendCommand.bind(chrome.debugger);chrome.debugger.sendCommand=(target,method,...rest)=>{kiCdpLog.push({t:Date.now(),method});return send(target,method,...rest)}},tabId);
 await worker.evaluate(id=>kiTest.tools.snapshot.execute({_tabId:id}),tabId);
 const entries=()=>worker.evaluate(id=>[...kiTest.refs(id).refs].map(([ref,entry])=>({ref:'@'+ref,role:entry.role,name:entry.name.trim(),dom:!!entry.dom})),tabId);
 const ref=Object.fromEntries((await entries()).map(entry=>[entry.name.replace(/^Elapsed \d+$/,'Elapsed'),entry.ref]));
 const qtyRef=Object.entries(ref).find(([name])=>name.startsWith('Qty'))?.[1];
 assert.ok(['Delete','Swap label','Search here','Name','Go','Elapsed','Off','Ghost','Warn','Far','Recipient IBAN','Select invoice 101','Email alerts','Open'].every(name=>ref[name])&&qtyRef,'snapshot registered the fixture refs: '+JSON.stringify(ref));
 const run=(tool,args)=>worker.evaluate(async([tool,args])=>{try{return {ok:await kiTest.tools[tool].execute(args)}}catch(error){return {error:error.message}}},[tool,{...args,_tabId:tabId}]);
 const mark=(tool,args)=>worker.evaluate(([tool,args])=>kiTest.kiMark(tool,args),[tool,args]);
 const clicks=()=>page.evaluate(()=>clicks);
 const logSince=t0=>worker.evaluate(t0=>kiCdpLog.filter(x=>x.t>=t0).map(x=>({method:x.method,at:x.t-t0})),t0);

 await check('highlight does not block the action',async()=>{
  const t0=Date.now();await mark('click',{target:ref.Delete});const returned=Date.now()-t0;await new Promise(r=>setTimeout(r,1100));
  const log=await logSince(t0),drawn=log.find(x=>x.method==='Overlay.highlightNode'),hidden=log.find(x=>x.method==='Overlay.hideHighlight');
  report.kiMarkMs=returned;report.highlightVisibleMs=drawn&&hidden?hidden.at-drawn.at:null;
  assert.ok(drawn,'highlight drawn');assert.ok(hidden,'highlight hidden by its timer');
  assert.ok(hidden.at>=returned,'hidden only after kiMark returned ('+returned+' ms)');
  assert.ok(hidden.at-drawn.at>=500,'visible for the user ('+report.highlightVisibleMs+' ms)');
  assert.ok(returned<400,'kiMark returned in '+returned+' ms');
 });
 await check('a capture hides a pending interact highlight',async()=>{
  const t0=Date.now();await mark('click',{target:ref.Delete});const before=Date.now()-t0;await mark('screenshot',{});
  const hidden=(await logSince(t0)).find(x=>x.method==='Overlay.hideHighlight');
  assert.ok(hidden&&hidden.at<before+300,'hidden before the capture: '+JSON.stringify(hidden));
 });
 await check('unchanged ref acts',async()=>{assert.equal((await run('click',{target:ref.Delete})).error,undefined);assert.deepEqual(await clicks(),['Delete'])});
 await check('changed ref is refused once, then the retry acts',async()=>{
  assert.equal((await run('click',{target:ref['Swap label']})).error,undefined);
  const refused=await run('click',{target:ref.Delete});report.refusal=refused.error||null;
  assert.match(refused.error||'',/changed since it was read: was button "Delete", now button "Cancel"\. Retry the same ref/,JSON.stringify(refused));
  assert.deepEqual(await clicks(),['Delete'],'nothing clicked on the changed element');
  assert.equal((await run('click',{target:ref.Delete})).error,undefined);assert.deepEqual((await clicks()).slice(-1),['Cancel']);
 });
 await check('a ticking name costs at most one refusal',async()=>{
  const errors=[];for(let i=0;i<3;i++){const r=await run('click',{target:ref.Elapsed});if(r.error)errors.push(r.error);await new Promise(r=>setTimeout(r,250))}
  assert.ok(errors.length<=1,JSON.stringify(errors));assert.ok((await clicks()).filter(x=>x==='tick').length>=2);
 });
 await check('refilling a field is not a change (placeholder, label, value in name)',async()=>{
  for(const target of [ref['Search here'],ref.Name,qtyRef])for(const value of ['first','second'])assert.equal((await run('fill',{target,value})).error,undefined,target+' '+value);
  assert.deepEqual(await page.evaluate(()=>[q.value,n.value,qty.value]),['second','second','second']);
 });
 await check('a relabelled field is refused before fill',async()=>{
  await page.evaluate(()=>iban.setAttribute('aria-label','Amount'));
  const r=await run('fill',{target:ref['Recipient IBAN'],value:'DE89'});assert.match(r.error||'',/was textbox "Recipient IBAN", now textbox "Amount"/,JSON.stringify(r));
  assert.equal(await page.evaluate(()=>iban.value),'');
 });
 await check('a relabelled checkbox is refused before click and before set_checked',async()=>{
  await page.evaluate(()=>{invl.textContent='Select invoice 205';alertl.textContent='SMS alerts'});
  const c=await run('click',{target:ref['Select invoice 101']});assert.match(c.error||'',/was checkbox "Select invoice 101", now checkbox "Select invoice 205"/,JSON.stringify(c));
  assert.equal(await page.evaluate(()=>inv.checked),false);
  const s=await run('set_checked',{target:ref['Email alerts'],checked:true});assert.match(s.error||'',/was checkbox "Email alerts", now checkbox "SMS alerts"/,JSON.stringify(s));
 });
 await check('a role change during the retry window is refused again',async()=>{
  await page.evaluate(()=>morph.textContent='Opened');
  assert.match((await run('click',{target:ref.Open})).error||'',/changed since it was read/);
  await page.evaluate(()=>morph.setAttribute('role','link'));
  const again=await run('click',{target:ref.Open});assert.match(again.error||'',/was button "Opened", now link "Opened"/,JSON.stringify(again));
  assert.equal(await page.evaluate(()=>clicks.includes('morph')),false);
 });
 await check('set_checked on a state-named switch succeeds',async()=>{
  const r=await run('set_checked',{target:ref.Off,checked:true});assert.equal(r.error,undefined,JSON.stringify(r));
  assert.equal(await page.evaluate(()=>sw.getAttribute('aria-checked')),'true');
 });
 await check('a hidden node keeps the previous behaviour and stays guarded',async()=>{
  await page.evaluate(()=>ghost.setAttribute('aria-hidden','true'));
  assert.equal((await run('click',{target:ref.Ghost})).error,undefined);assert.deepEqual((await clicks()).slice(-1),['ghost']);
  assert.equal((await entries()).find(entry=>entry.ref===ref.Ghost)?.role,'button','entry not overwritten with a hidden role');
 });
 await check('inspect_region never unguards a snapshot ref',async()=>{
  assert.equal((await run('inspect_region',{target:ref.Delete,max_ancestors:0})).error,undefined);
  assert.equal((await entries()).find(entry=>entry.ref===ref.Delete)?.dom,false);
 });
 await check('inspect_region refs (DOM-named) are not compared to accessibility names',async()=>{
  await page.evaluate(()=>document.body.insertAdjacentHTML('beforeend','<button id="late" title="Hint" onclick="clicks.push(\'late\')">Go</button>'));
  assert.equal((await run('inspect_region',{selector:'#late',max_ancestors:0})).error,undefined);
  const late=(await entries()).find(entry=>entry.name==='Hint');assert.ok(late,'inspect_region registered the DOM-named ref');
  assert.equal((await run('click',{target:late.ref})).error,undefined);assert.deepEqual((await clicks()).slice(-1),['late']);
 });
 await check('mouse_click after the highlight works on a smooth-scrolling page',async()=>{
  await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));await mark('mouse_click',{target:ref.Far});
  const r=await run('mouse_click',{target:ref.Far});assert.equal(r.error,undefined,JSON.stringify(r));assert.deepEqual((await clicks()).slice(-1),['far']);
 });
 await check('mouse_click without the highlight works on a smooth-scrolling page',async()=>{
  await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));
  const r=await run('mouse_click',{target:ref.Far});assert.equal(r.error,undefined,JSON.stringify(r));assert.deepEqual((await clicks()).slice(-1),['far']);
 });
 await check('a dialog opened by the action does not leave the highlight stuck',async()=>{
  await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));
  let dismissedAt=0;page.once('dialog',dialog=>setTimeout(()=>{dismissedAt=Date.now();dialog.dismiss().catch(()=>{})},1500));
  const t0=Date.now();await mark('click',{target:ref.Warn});const click=run('click',{target:ref.Warn});
  await new Promise(r=>setTimeout(r,3000));await click;
  const hides=(await logSince(t0)).filter(x=>x.method==='Overlay.hideHighlight').map(x=>x.at+t0);
  assert.ok(dismissedAt>0,'dialog was shown');assert.ok(hides.some(at=>at>=dismissedAt),'highlight hidden after the dialog closed: '+JSON.stringify({dismissedAt,hides}));
 });
 console.log(JSON.stringify({...report,failures}));
 assert.deepEqual(failures,[]);
}
main().catch(error=>{console.error(error.message);process.exitCode=1}).finally(async()=>{await browser?.close();if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}const folder=path.resolve(temp);assert.ok(folder.startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(folder).startsWith('cert-x-ref-guard-'));fs.rmSync(folder,{recursive:true,force:true,maxRetries:4,retryDelay:100})});

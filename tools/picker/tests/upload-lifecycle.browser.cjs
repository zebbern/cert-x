// Real agent-tool sequence for a file input: upload, save_file, upload again.
// This catches a stalled second DOM.setFileInputFiles call without a model.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');

const root = path.resolve(__dirname, '../../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-upload-lifecycle-'));
const invalidMix=process.env.CERT_X_UPLOAD_INVALID_MIX==='1',generatedOnly=invalidMix||process.env.CERT_X_UPLOAD_GENERATED_ONLY==='1';
let browser, server, origin, tabId, savedPath, workerRef, scanRun;
const calls = [], results = [];
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

function completion(res, tool, args) {
  res.writeHead(200, { 'Content-Type':'text/event-stream', 'Cache-Control':'no-cache' });
  const send = value => res.write('data: ' + JSON.stringify(value) + '\n\n');
  if (tool) {
    send({ choices:[{ index:0, delta:{ role:'assistant', tool_calls:[{ index:0, id:'call-'+calls.length, type:'function', function:{ name:tool, arguments:JSON.stringify(args) } }] } }] });
    send({ choices:[{ index:0, delta:{}, finish_reason:'tool_calls' }] });
  } else {
    send({ choices:[{ index:0, delta:{ role:'assistant', content:'Upload sequence complete.' } }] });
    send({ choices:[{ index:0, delta:{}, finish_reason:'stop' }], usage:{ prompt_tokens:10, completion_tokens:4, total_tokens:14 } });
  }
  res.end('data: [DONE]\n\n');
}

async function main() {
  server = http.createServer(async (req, res) => {
    if (req.url === '/upload') { res.setHeader('Content-Type','text/html');return res.end('<!doctype html><title>Upload fixture</title><input type="file" name="uploaded"><p>Ready</p>'); }
    if (req.url.endsWith('/models')) { res.setHeader('Content-Type','application/json');return res.end(JSON.stringify({ data:[{ id:'mock/upload', name:'Upload fixture' }] })); }
    if (!req.url.endsWith('/chat/completions')) { res.statusCode=404;return res.end(); }
    let body='';for await (const chunk of req) body+=chunk;
    const request=JSON.parse(body), messages=request.messages||[];
    for (const message of messages) if (message.role==='tool' && !results.some(item=>item.id===message.tool_call_id)) {
      let value;try{value=JSON.parse(message.content)}catch{value=message.content}
      results.push({ id:message.tool_call_id, value });
      if (value?.filename && value?.success) savedPath=value.filename;
    }
    const stage=calls.length;
    let tool,args;
    if(stage===0) { tool='navigate';args={ url:origin+'/upload' }; }
    if(stage===1 && !generatedOnly) { tool='upload';args={ selector:'input[name="uploaded"]', files:['/tmp/dvwa_probe.php'] }; }
    if(stage===2 && !generatedOnly) { tool='save_file';args={ filename:process.env.CERT_X_UPLOAD_FILENAME||'cert-x-upload-probe.php', content:'<?php echo "CERTX_UPLOAD_PROBE"; ?>\n' }; }
    if(stage===3 && !generatedOnly) {
      assert.ok(savedPath && fs.existsSync(savedPath),'The preceding save_file result must be available on disk.');
      tool='upload';args={ selector:'input[name="uploaded"]', files:[savedPath] };
    }
    if(generatedOnly && stage===1) { tool='upload';args={ selector:'input[name="uploaded"]', generated:{ filename:'generated-probe.php', content:'<?php echo "CERTX_GENERATED_PROBE"; ?>\n', mimeType:'application/x-httpd-php' },...(invalidMix?{ files:['/tmp/ignored.php'] }: {}) }; }
    calls.push({ stage, tool:tool||'finish', at:Date.now() });
    completion(res,tool,args);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
  browser=await chromium.launchPersistentContext(path.join(temp,'profile'),{headless:true,viewport:{width:720,height:900},acceptDownloads:true,executablePath:process.env.CHROMIUM_PATH||path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
  const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(()=>certXSecurity.ready);
  workerRef=worker;
  await worker.evaluate(origin=>chrome.storage.local.set({sidepanel_language:'en',sidepanel_approval_mode:'full_access',sidepanel_connections:[{id:'upload-fixture',label:'Upload fixture',presetId:'openrouter',apiKey:'fixture',host:origin+'/api/v1'}]}),origin);
  const target=await browser.newPage();await target.goto(origin+'/upload');tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(tab=>tab.url===url)?.id,target.url());assert.ok(Number.isInteger(tabId));
  if(process.env.CERT_X_UPLOAD_WITH_SCAN==='1'){
    scanRun=await worker.evaluate(({tabId,origin})=>certXSecurity.handle('start',{tabId,engines:['DAST'],options:{preset:'thorough',moduleIds:['headers'],runCve:false,maxRequests:20,maxRequestsPerSecond:5,concurrency:1,durationSeconds:60}},{owner:'upload-fixture-scan',scope:{origins:[origin],excludePaths:[]}}),{tabId,origin});
    assert.ok(scanRun.runId && scanRun.state==='running');
  }
  const panel=await browser.newPage();await panel.goto('chrome-extension://'+new URL(worker.url()).host+'/pages/sidepanel.html?tabId='+tabId);
  await panel.waitForFunction(()=>document.querySelector('.wb-composer-model .wb-mode-toggle')?.disabled===false);
  await panel.locator('.wb-editor').first().click();await panel.keyboard.type('Run the upload fixture sequence.');await panel.keyboard.press('Enter');
  const expectedCalls=generatedOnly?3:5,deadline=Date.now()+40000;while(calls.length<expectedCalls&&Date.now()<deadline)await pause(250);
  const panelTail=(await panel.locator('body').innerText()).slice(-2600);
  const first=results.find(item=>item.id==='call-2'),second=results.find(item=>item.id==='call-4'),generated=generatedOnly?first:null;
  assert.equal(calls.length,expectedCalls,'Agent turn stalled before receiving the upload result: '+JSON.stringify({calls,results:results.map(item=>item.id),panelTail}));
  if(!generatedOnly){
    assert.equal(first?.value?.success,true,'First upload should settle.');
    assert.equal(first?.value?.selectedFiles?.[0]?.size,0,'A nonexistent path can look like a selected empty file to Chrome.');
    assert.match(first?.value?.warning||'',/zero bytes/);
    assert.ok(second,'The path-based upload must settle with success or a bounded error.');
    if(second.value?.success!==true)assert.match(String(second.value),/upload failed: upload: .*timed out/);
    else {
      const selected=await target.locator('input[name="uploaded"]').evaluate(async input=>({count:input.files.length,text:await input.files[0]?.text()}));
      assert.equal(selected.count,1);assert.equal(selected.text,'<?php echo "CERTX_UPLOAD_PROBE"; ?>\n');
    }
  }
  if(generatedOnly){
    if(invalidMix){
      assert.match(String(generated?.value),/choose exactly one source/);
      assert.equal(await target.locator('input[name="uploaded"]').evaluate(input=>input.files.length),0,'Rejected mixed sources must not select a file.');
    }else{
      assert.equal(generated?.value?.success,true,'In-memory generated upload should succeed: '+JSON.stringify(generated?.value));
      const selected=await target.locator('input[name="uploaded"]').evaluate(async input=>({count:input.files.length,text:await input.files[0]?.text()}));
      assert.equal(selected.count,1);assert.equal(selected.text,'<?php echo "CERTX_GENERATED_PROBE"; ?>\n','The generated upload must select exact file bytes.');
      assert.equal(generated.value.selectedFiles?.[0]?.size,selected.text.length);
    }
  }
  console.log(JSON.stringify({calls:calls.map(item=>item.tool),pathUploadSettled:!!second,pathUploadSucceeded:second?.value?.success===true,generatedUploadSucceeded:generatedOnly&&!invalidMix?true:null,mixedSourceRejected:invalidMix?true:null,finalToolLatencyMs:calls.at(-1).at-calls.at(-2).at,scanActive:!!scanRun}));
}

main().catch(error=>{console.error(error.stack);process.exitCode=1}).finally(async()=>{
  if(workerRef&&scanRun)await workerRef.evaluate(runId=>certXSecurity.handle('stop',{runId},{owner:'upload-fixture-scan'}),scanRun.runId).catch(()=>{});
  await browser?.close();if(server)await new Promise(resolve=>{server.close(resolve);server.closeAllConnections()});
  if(savedPath && fs.existsSync(savedPath)) fs.unlinkSync(savedPath);
  const resolved=fs.realpathSync(temp),rootTemp=fs.realpathSync(os.tmpdir())+path.sep;
  assert.ok(resolved.startsWith(rootTemp)&&path.basename(resolved).startsWith('cert-x-upload-lifecycle-'));
  fs.rmSync(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:100});
});

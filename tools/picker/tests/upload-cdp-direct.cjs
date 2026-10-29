// Distinguish Chrome's file-input behavior from cert-x's debugger/tool bridge.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const file=path.join(os.tmpdir(),'cert-x-direct-upload-'+process.pid+'.txt');
let browser;
async function main(){
 fs.writeFileSync(file,'CERTX_DIRECT_UPLOAD');
 browser=await chromium.launch({headless:true,executablePath:require('../../chromium-path.cjs')});
 const page=await browser.newPage();await page.setContent('<input type="file" name="uploaded"><a id="download" href="data:text/plain,CERTX_DOWNLOAD_FILE" download="probe.txt">Download</a>');
 const cdp=await page.context().newCDPSession(page);
 const document=await cdp.send('DOM.getDocument'),node=await cdp.send('DOM.querySelector',{nodeId:document.root.nodeId,selector:'input[name="uploaded"]'});
 assert.ok(node.nodeId);
 const [download]=await Promise.all([page.waitForEvent('download'),page.locator('#download').click()]);
 const downloaded=await download.path();assert.ok(downloaded&&fs.existsSync(downloaded));
 for(const candidate of ['/tmp/dvwa_probe.php',file,downloaded]){
  const started=Date.now();
  const result=await Promise.race([cdp.send('DOM.setFileInputFiles',{nodeId:node.nodeId,files:[candidate]}).then(()=>({ok:true}),error=>({ok:false,error:error.message})),new Promise(resolve=>setTimeout(()=>resolve({timeout:true}),15000))]);
  const selected=await page.locator('input[name="uploaded"]').evaluate(async input=>({count:input.files.length,name:input.files[0]?.name,size:input.files[0]?.size,readable:await input.files[0]?.slice(0,1).arrayBuffer().then(()=>true,()=>false)}));
  console.log(JSON.stringify({candidate:candidate===file?'existing-local-file':candidate===downloaded?'browser-download-artifact':'nonexistent-posix-path',elapsedMs:Date.now()-started,...result,selected}));
  assert.equal(result.timeout,undefined,'Raw CDP file input stalled.');
 }
}
main().catch(error=>{console.error(error.stack);process.exitCode=1}).finally(async()=>{await browser?.close();if(fs.existsSync(file))fs.unlinkSync(file)});

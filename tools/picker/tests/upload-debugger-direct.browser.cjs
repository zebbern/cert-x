// Check Chrome's extension debugger API independently of the cert-x upload tool.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-upload-debugger-'));
const file=path.join(temp,'probe.txt');let browser,server;
async function main(){
 fs.writeFileSync(file,'CERTX_DEBUGGER_UPLOAD');
 server=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html');res.end('<input type="file" name="uploaded"><a id="download" href="data:text/plain,CERTX_DOWNLOADED" download="probe.txt">Download</a>')});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launchPersistentContext(path.join(temp,'profile'),{headless:true,acceptDownloads:true,executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(()=>certXSecurity.ready);
 const page=await browser.newPage();await page.goto(origin+'/upload');
 const [download]=await Promise.all([page.waitForEvent('download'),page.locator('#download').click()]);const downloaded=await download.path();assert.ok(fs.existsSync(downloaded));
 const tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(tab=>tab.url===url)?.id,page.url());assert.ok(Number.isInteger(tabId));
 const scripting=await worker.evaluate(async tabId=>{try{return {result:(await chrome.scripting.executeScript({target:{tabId},world:'ISOLATED',func:()=>document.title}))[0]?.result}}catch(error){return {error:error.message}}},tabId);
 console.log(JSON.stringify({scripting}));
 const results=await worker.evaluate(async({tabId,file,downloaded})=>{
  const target={tabId},out=[];await chrome.debugger.attach(target,'1.3');
  try{
   const document=await chrome.debugger.sendCommand(target,'DOM.getDocument');
   const node=await chrome.debugger.sendCommand(target,'DOM.querySelector',{nodeId:document.root.nodeId,selector:'input[name="uploaded"]'});
   for(const [label,candidate] of [['existing-file',file],['download-artifact',downloaded]]){
    const started=Date.now();
    const value=await Promise.race([chrome.debugger.sendCommand(target,'DOM.setFileInputFiles',{nodeId:node.nodeId,files:[candidate]}).then(()=>({ok:true}),error=>({ok:false,error:error.message})),new Promise(resolve=>setTimeout(()=>resolve({timeout:true}),15000))]);
    out.push({label,elapsedMs:Date.now()-started,...value});
   }
   const downloadId=await chrome.downloads.download({url:'data:text/plain;base64,Q0VSVFhfRVhURU5TSU9OX0RPV05MT0FE',filename:'cert-x-debugger-download.txt',saveAs:false});
   let saved;for(let attempt=0;attempt<100;attempt++){saved=(await chrome.downloads.search({id:downloadId}))[0];if(saved?.state==='complete')break;await new Promise(resolve=>setTimeout(resolve,100));}
   if(saved?.state!=='complete')throw Error('Extension download did not finish.');
   const started=Date.now();
   const value=await Promise.race([chrome.debugger.sendCommand(target,'DOM.getDocument').then(()=>({ok:true}),error=>({ok:false,error:error.message})),new Promise(resolve=>setTimeout(()=>resolve({timeout:true}),15000))]);
   out.push({label:'after-extension-download',elapsedMs:Date.now()-started,...value});
   const scripted=await chrome.scripting.executeScript({target:{tabId},world:'ISOLATED',func:()=>document.title}).then(value=>({ok:true,title:value[0]?.result}),error=>({ok:false,error:error.message}));
   out.push({label:'script-while-debugger',...scripted});
  }finally{await chrome.debugger.detach(target).catch(()=>{})}
  return out;
 },{tabId,file,downloaded});
 console.log(JSON.stringify(results));assert.ok(results.every(item=>item.ok===true&&!item.timeout),'Extension debugger file input stalled.');
}
main().catch(error=>{console.error(error.stack);process.exitCode=1}).finally(async()=>{
 await browser?.close();if(server)await new Promise(resolve=>{server.close(resolve);server.closeAllConnections()});
 const resolved=fs.realpathSync(temp),rootTemp=fs.realpathSync(os.tmpdir())+path.sep;
 assert.ok(resolved.startsWith(rootTemp)&&path.basename(resolved).startsWith('cert-x-upload-debugger-'));
 fs.rmSync(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:100});
});

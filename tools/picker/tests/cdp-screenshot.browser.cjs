// Scripted model, real Chrome CDP, canonical agent formatter and rendered images.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root=path.resolve(__dirname,'../../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'cert-x-screenshot-')),results=new Map(),images=[],errors=[];
let browser,server,panel,origin,step=0,advertised=[];
const decode=text=>{try{return JSON.parse(text.replace(/^<system>.*?<\/system>\s*/s,''))}catch{return {text}}};
async function main(){
 server=http.createServer(async(req,res)=>{
  res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','*');if(req.method==='OPTIONS')return res.end();
  if(req.url.endsWith('/models')){res.setHeader('Content-Type','application/json');return res.end(JSON.stringify({data:[{id:'fixture/image',name:'Image fixture'}]}));}
  if(!req.url.includes('/chat/completions')){res.setHeader('Content-Type','text/html');return res.end('<!doctype html><title>Image fixture</title><style>body{margin:0;background:#345}h1{color:white}</style><h1>Screenshot fixture</h1>');}
  try{
   let body='';for await(const chunk of req)body+=chunk;const request=JSON.parse(body);advertised=request.tools||[];
   for(const message of request.messages||[]){
    if(message.role==='tool'&&message.tool_call_id?.startsWith('shot-')){const content=typeof message.content==='string'?message.content:(message.content||[]).filter(part=>part.type==='text').map(part=>part.text).join('\n');assert.ok(content.length<3000,'Image base64 must not appear in textual tool results');if(!results.has(message.tool_call_id.slice(5)))results.set(message.tool_call_id.slice(5),decode(content));}
    if(Array.isArray(message.content))for(const part of message.content)if(part.type==='image_url'){const url=part.image_url?.url||part.imageUrl?.url;if(url&&!images.includes(url))images.push(url);}
   }
   const tasks=[['navigate','navigate',{url:origin+'/fixture',newTab:true}],...['png','jpeg','webp'].map((format,index)=>[format,'cdp',{method:'Page.captureScreenshot',params:{format,clip:{x:0,y:0,width:120+index*10,height:90+index*10,scale:1}}}]),['ordinary','screenshot',{}],['pdf','cdp',{method:'Page.printToPDF'}]];
   const task=tasks[step++];console.log('Screenshot fixture step',step,task?.[0]||'complete');if(task)assert.ok(advertised.some(item=>item.function.name===task[1]));
   const delta=task?{role:'assistant',tool_calls:[{index:0,id:'shot-'+task[0],type:'function',function:{name:task[1],arguments:JSON.stringify(task[2])}}]}:{role:'assistant',content:'SCREENSHOT FIXTURE COMPLETE'};
   res.writeHead(200,{'Content-Type':'text/event-stream'});res.write('data: '+JSON.stringify({id:'shot',object:'chat.completion.chunk',choices:[{index:0,delta}]})+'\n\n');res.write('data: '+JSON.stringify({id:'shot',object:'chat.completion.chunk',choices:[{index:0,delta:{},finish_reason:task?'tool_calls':'stop'}]})+'\n\n');res.end('data: [DONE]\n\n');
  }catch(error){errors.push(error.stack);console.error(error.message);res.writeHead(500);res.end(error.message);}
 });await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launchPersistentContext(temp,{headless:true,viewport:{width:720,height:900},executablePath:require('../../chromium-path.cjs'),args:['--disable-extensions-except='+root,'--load-extension='+root]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');await worker.evaluate(()=>certXSecurity.ready);const id=new URL(worker.url()).host;
 await worker.evaluate(async origin=>chrome.storage.local.set({sidepanel_language:'en',sidepanel_approval_mode:'full_access',sidepanel_connections:[{id:'fixture',label:'Image fixture',presetId:'openrouter',apiKey:'fixture',host:origin+'/api/v1'}]}),origin);
 panel=await browser.newPage();panel.on('pageerror',error=>errors.push(error.message));await panel.goto('chrome-extension://'+id+'/pages/sidepanel.html');await panel.waitForFunction(()=>document.querySelector('.wb-composer-model .wb-mode-toggle')?.disabled===false);
 await panel.locator('.wb-editor').first().click();await panel.keyboard.type('Exercise the screenshot fixture.');await panel.keyboard.press('Enter');await panel.getByText('SCREENSHOT FIXTURE COMPLETE',{exact:true}).waitFor({timeout:90000});
 for(const [index,format] of ['png','jpeg','webp'].entries()){const value=results.get(format);assert.equal(value?.error,undefined);assert.equal(value?.format,format,JSON.stringify(value));assert.equal(value.width,120+index*10);assert.equal(value.height,90+index*10);assert.equal(value.data,undefined);}
 assert.equal(results.get('ordinary').format,'png');assert.ok(images.length>=4,'Provider must receive actual image parts');
 const output=await worker.evaluate(()=>chrome.storage.local.get('ki_task_outputs'));assert.equal(output.ki_task_outputs?.length,5,'CDP PDF and both screenshot paths enter Outputs');const pdf=output.ki_task_outputs.find(item=>item.mime==='application/pdf');assert.equal(Buffer.from(pdf.data,'base64').subarray(0,5).toString(),'%PDF-');assert.equal(results.get('pdf').outputId,pdf.id);assert.equal(results.get('pdf').data,undefined);
 const render=await panel.locator('img').evaluateAll(nodes=>nodes.filter(node=>node.src.startsWith('data:image/')).map(node=>({loaded:node.complete&&node.naturalWidth>0,width:node.naturalWidth,height:node.naturalHeight})));
 assert.ok(render.filter(item=>item.loaded).length>=4,'Chat renders all image parts');assert.deepEqual(errors,[]);
 const evidence={formats:Object.fromEntries(results),providerImages:images.length,renderedImages:render,outputs:output.ki_task_outputs.map(item=>({name:item.name,kind:item.kind,mime:item.mime})),errors};
 // The tracked record changes only on request, so a routine run leaves the tree clean.
 fs.writeFileSync(process.env.CERT_X_REFRESH_EVIDENCE==='1'?path.join(root,'tools/security/evidence/cdp-screenshot.json'):path.join(os.tmpdir(),'cert-x-cdp-screenshot.json'),JSON.stringify(evidence,null,2));console.log(JSON.stringify({formats:3,ordinaryScreenshot:true,providerImages:images.length,renderedImages:render.length,outputs:5,pdfArtifact:true}));
}
main().catch(async error=>{console.error(error);console.error(JSON.stringify({step,results:Object.fromEntries(results),errors}));if(panel)console.error((await panel.locator('body').innerText()).slice(-4000));process.exitCode=1}).finally(async()=>{await browser?.close();if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}const folder=path.resolve(temp);assert.ok(folder.startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(folder).startsWith('cert-x-screenshot-'));fs.rmSync(folder,{recursive:true,force:true,maxRetries:4,retryDelay:100});});

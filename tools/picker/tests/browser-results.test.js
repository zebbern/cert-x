const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const context=vm.createContext({});vm.runInContext(fs.readFileSync(path.join(__dirname,'../src/ki-browser-results.js'),'utf8'),context);
test('CDP screenshots enter the existing image formatter for all supported formats',()=>{
 for(const [format,mime] of [['png','image/png'],['jpeg','image/jpeg'],['webp','image/webp']]){
  const raw={data:'image-bytes'},args={method:'Page.captureScreenshot',params:{format,clip:{width:80,height:60}}};
  const result=context.kiBrowserResult('cdp',args,raw);
  assert.equal(result.mimeType,mime);assert.equal(result.data,raw.data);assert.equal(result.format,format);assert.equal(raw.mimeType,undefined);
 }
 assert.equal(context.kiBrowserResult('cdp',{method:'Page.captureScreenshot'},{data:'x'}).mimeType,'image/png');
});
test('non-image CDP data and other tool contracts stay unchanged; empty captures fail explicitly',()=>{
 const raw={data:'protocol-data'};assert.equal(context.kiBrowserResult('cdp',{method:'IO.read'},raw),raw);assert.equal(context.kiBrowserResult('screenshot',{},raw),raw);
 assert.throws(()=>context.kiBrowserResult('cdp',{method:'Page.captureScreenshot'},{}),/no image/);
});
test('PDF results become owned Outputs metadata without embedding binary text',async()=>{
 const stored=[];const local=vm.createContext({atob,kiWorkspaceOutput:async(session,item)=>{stored.push({session,item});return {id:'pdf-id',...item};}});
 vm.runInContext(fs.readFileSync(path.join(__dirname,'../src/ki-browser-results.js'),'utf8'),local);
 const data=Buffer.from('%PDF-1.4\nfixture').toString('base64');
 const result=await local.kiBrowserAgentResult('cdp',{method:'Page.printToPDF'},{data},'chat');
 assert.equal(result.outputId,'pdf-id');assert.equal(result.data,undefined);assert.equal(result.bytes,16);assert.equal(stored[0].session,'chat');assert.equal(stored[0].item.data,data);
 const stream={stream:'io-handle',data:''};assert.equal(await local.kiBrowserAgentResult('cdp',{method:'Page.printToPDF'},stream,'chat'),stream);
 await assert.rejects(local.kiBrowserAgentResult('cdp',{method:'Page.printToPDF'},{data:'QUFBQQ=='},'chat'),/invalid data/);assert.equal(stored.length,1);
});
test('Fast browse hint: only while on, only on a page with a form, once per page per chat',async()=>{
 let ready=true;const local=vm.createContext({kiBrowseReady:()=>ready});
 vm.runInContext(fs.readFileSync(path.join(__dirname,'../src/ki-browser-results.js'),'utf8'),local);
 const form={url:'https://a.test/login',tree_text:'- textbox "Email" [ref=e1]\n- button "Sign in" [ref=e2]'},links={url:'https://a.test/',tree_text:'- link "Home" [ref=e1]'};
 const first=await local.kiBrowserAgentResult('snapshot',{},form,'chat');
 assert.match(first.hint,/^browse\(\{goal, values\}\)/);assert.equal(first.tree_text,form.tree_text);assert.equal(form.hint,undefined,'the original result is not mutated');
 assert.equal((await local.kiBrowserAgentResult('snapshot',{},form,'chat')).hint,undefined,'not repeated on the same page in the same chat');
 assert.ok((await local.kiBrowserAgentResult('snapshot',{},form,'other chat')).hint,'another chat gets it once');
 assert.equal((await local.kiBrowserAgentResult('snapshot',{},links,'chat2')).hint,undefined,'no form, no hint');
 assert.equal((await local.kiBrowserAgentResult('find',{},form,'chat3')).hint,undefined,'only snapshot reads');
 ready=false;assert.equal((await local.kiBrowserAgentResult('snapshot',{},form,'chat4')).hint,undefined,'not while Fast browse is off');
});

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

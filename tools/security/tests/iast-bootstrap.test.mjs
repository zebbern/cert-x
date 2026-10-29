import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { buildIastDocumentSource } from '../../../security/engine/iast-bootstrap.mjs';

test('document bootstrap acquires allowed frames and excludes foreign, opaque and encoded excluded paths',()=>{
 const source=buildIastDocumentSource(['globalThis.hooksInstalled=true;'],{origins:['https://app.test'],excludePaths:['/private']});
 for(const [href,allowed] of [['https://app.test/frame',true],['https://app.test/frame?q=private',true],['https://outside.test/frame',false],['https://app.test:444/frame',false],['about:blank',false],['https://app.test/private/frame',false],['https://app.test/%2570rivate/frame',false],['https://app.test/private;matrix/frame',false]]){
  const context={URL,location:new URL(href),window:{top:{}},hooksInstalled:false};
  vm.runInNewContext(source,context);assert.equal(context.hooksInstalled,allowed,href);
 }
});

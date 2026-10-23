const test=require('node:test'),assert=require('node:assert/strict'),{checkedApi}=require('../security/zap.cjs');
test('ZAP application failures are not accepted as successful HTTP responses',()=>{
 for(const value of [null,{code:'illegal_parameter',message:'Invalid option'},{Result:'FAIL'},{success:false}])assert.throws(()=>checkedApi(value));
 assert.deepEqual(checkedApi({Result:'OK'}),{Result:'OK'});assert.deepEqual(checkedApi({alerts:[]}),{alerts:[]});
});

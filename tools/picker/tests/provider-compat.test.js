const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const context=vm.createContext({});vm.runInContext(fs.readFileSync(path.join(__dirname,'../src/ki-provider-compat.js'),'utf8'),context);
test('MiMo Flash asks for feedback between tool calls without changing other models or explicit preferences',()=>{
 const adjust=context.kiProviderToolOptions;
 for(const model of ['xiaomi/mimo-v2.6-flash','mimo-v2.6-flash','xiaomi/mimo-v2.6-flash-20260921'])assert.equal(adjust({model,tools:[{}]}).parallel_tool_calls,false);
 assert.equal(adjust({model:'other/model',tools:[{}]}).parallel_tool_calls,undefined);
 assert.equal(adjust({model:'xiaomi/mimo-v2.6-flash'}).parallel_tool_calls,undefined);
 assert.equal(adjust({model:'xiaomi/mimo-v2.6-flash',tools:[{}],parallel_tool_calls:true}).parallel_tool_calls,true);
});

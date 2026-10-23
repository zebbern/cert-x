import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../../../security/ptk/offscreen/runtime_offscreen.js',import.meta.url),'utf8').replace(/^import .*\r?\n/gm,'');
function listener(){let onConnect;const context=vm.createContext({chrome:{runtime:{id:'extension',getURL:p=>'chrome-extension://extension/'+p,onConnect:{addListener:fn=>onConnect=fn},onMessage:{addListener(){}},sendMessage(){}}},Worker:class {postMessage(){}},sanitizeOneTimeDastProgressMessage:x=>x,DAST_RUNTIME_MESSAGE:{}});vm.runInContext(source,context);return onConnect;}
test('offscreen DAST listener ignores unrelated sidepanel/model/tool ports',()=>{const connect=listener();for(const name of ['sidepanel-mirror','cert-x-model-stream','mcp','']){let closed=false;connect({name,disconnect(){closed=true;}});assert.equal(closed,false,name);}});
test('offscreen DAST listener rejects an untrusted DAST controller only',()=>{const connect=listener();let closed=false;connect({name:'ptk_dast_runtime_v1',sender:{id:'foreign'},disconnect(){closed=true;}});assert.equal(closed,true);});

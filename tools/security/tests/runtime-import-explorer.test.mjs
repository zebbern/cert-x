import test from 'node:test';
import assert from 'node:assert/strict';
import {gzipSync} from 'node:zlib';
import {parseUploadedScanFile} from '../../../security/ptk/background/export/parseUploadedScanFile.js';
import {buildApiExplorer} from '../../../security/ptk/background/analysis/apiExplorerBuilder.js';
const scan={engine:'SAST',scanId:'fixture',host:'fixture.test',findings:[{id:'f',moduleId:'dom-xss',ruleId:'dom-xss-taint',location:{url:'https://fixture.test/app.js'},evidence:{source:'location.hash',sink:'innerHTML'}}],codeArtifacts:{sast:{gadgets:[{id:'g',routeKey:'fixture.test|*|/admin',gadgetType:'postmessage-emitter',label:'postMessage target',pageUrl:'https://fixture.test/admin'}]}}};
test('native report importer preserves raw JSON and compressed finding evidence',async()=>{for(const gzip of [false,true]){const text=JSON.stringify(scan),bytes=gzip?gzipSync(text):Buffer.from(text);const result=await parseUploadedScanFile({name:gzip?'scan.json.gz':'scan.json',bytes:Array.from(bytes)});assert.equal(result.ok,true);assert.equal(result.isGzip,gzip);assert.deepEqual(result.json,scan);}});
test('native importer reports malformed JSON rather than successful empty data',async()=>{const result=await parseUploadedScanFile({name:'invalid.json',bytes:Array.from(Buffer.from('{broken'))});assert.equal(result.ok,false);assert.ok(result.parseError);assert.equal(result.json,null);});
test('native API explorer includes scoped source-artifact evidence',()=>{const explorer=buildApiExplorer(scan);assert.equal(explorer.summary.gadgetCount,1);assert.equal(explorer.gadgets[0].engine,'SAST');assert.equal(explorer.gadgets[0].routeKey,'fixture.test|*|/admin');assert.equal(explorer.gadgets[0].evidenceRefs[0].id,'g');});

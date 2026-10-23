import test from 'node:test';
import assert from 'node:assert/strict';
import {OPERATION_SCHEMAS,validateOperationSelection} from '../../../security/engine/operation-arguments.mjs';

test('utility schema supplies the selector and actual typed fields the runtime requires',()=>{
 const s=OPERATION_SCHEMAS.utility.schema;
 assert.deepEqual(s.required,['tool']);assert.ok(s.properties.tool.enum.includes('decoder'));assert.ok(s.properties.tool.enum.includes('jwt'));
 assert.equal(s.properties.ports.items.type,'integer');assert.equal(s.properties.tabId.type,'integer');assert.ok(s.properties.cookie);assert.ok(s.properties.runId);
 for(const name of ['startScan','capture','listRequests','macro'])assert.equal(OPERATION_SCHEMAS[name].schema.properties.tabId.type,'integer');
 validateOperationSelection('utility',{tool:'decoder',action:'decode',method:'base64',text:'aGk='});
 validateOperationSelection('utility',{tool:'encode',text:'legacy'});validateOperationSelection('utility',{tool:'session',action:'list'});
 for(const [tool,args] of [['utility',{tool:'zap',action:'scan'}],['utility',{tool:'decoder',action:'scan'}],['zap',{action:'scan'}],['zap','{}']])assert.throws(()=>validateOperationSelection(tool,args),error=>error.retryable===false&&!!error.recovery);
});
test('managed browser schema advertises the actual host verification and login contract',()=>{
 const schema=OPERATION_SCHEMAS.browser.schema;
 assert.deepEqual(schema.properties.probe.required,['selector','expectedText']);
 assert.equal(schema.properties.probe.properties.expectedText.type,'string');
 assert.equal(schema.properties.expected,undefined);
 assert.deepEqual(schema.properties.actions.items.properties.type.enum,['fill','click','press']);
 assert.ok(schema.properties.action.enum.includes('readArtifact'));
 assert.equal(schema.properties.action.enum.includes('getJob'),false,'Candidate jobs use their own execution run, not the browser lease');
 assert.equal(schema.properties.action.enum.includes('cancelJob'),false);
 assert.ok(OPERATION_SCHEMAS.candidate.schema.properties.action.enum.includes('status'));
 assert.ok(OPERATION_SCHEMAS.candidate.schema.properties.executionRunId);
 assert.equal(schema.properties.limit.maximum,131072);
 assert.deepEqual(schema.anyOf,[{properties:{action:{enum:['create','list','reopen']}}},{required:['runId']}]);
});
test('managed transports expose the actual explicit HTTP/1 input and opt-in flags',()=>{
 const schema=OPERATION_SCHEMAS.raw.schema;
 assert.equal(schema.properties.requestBase64.type,'string');
 assert.equal(schema.properties.optIn.type,'boolean');
 assert.match(schema.properties.bytesBase64.description,/HTTP\/2/);
 assert.equal(schema.properties.requests.items.properties.headers.oneOf.length,2);
 assert.equal(schema.properties.maxResponseBytes.maximum,undefined);
 assert.ok(schema.properties.action.enum.includes('evidence'));
 assert.equal(schema.properties.limit.maximum,131072);
 assert.equal(schema.properties.repeats.minimum,2);
 assert.deepEqual(schema.properties.responseQueue.required,['frontFraming','outer','injected','followup']);
 assert.equal(schema.properties.endAfterWrite.type,'boolean');
});

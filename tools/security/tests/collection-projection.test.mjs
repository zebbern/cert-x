import test from 'node:test';
import assert from 'node:assert/strict';
import projection from './collection-projection.cjs';
test('later aggregated occurrence retains its own source and document in parity comparisons',()=>{
 const first='<b>FIRST</b>',later='<b>FIRST_LATER</b>';
 const finding={ruleId:'rule',moduleId:'module',evidence:{iast:{sinkId:'dom.innerHTML',sources:[{raw:first,sourceKind:'postMessage',location:'https://app.test/first'}],samples:[{matched:first,sourceKind:'postMessage',url:'https://app.test/first'},{matched:later,sourceKind:'postMessage',url:'https://app.test/later'}]}}};
 assert.deepEqual(projection.projectIast([finding],later),[{ruleId:'rule',moduleId:'module',sourceKinds:['postMessage'],sink:'dom.innerHTML',sourceLocations:['https://app.test/later']}]);
 assert.deepEqual(projection.projectIast([finding],first)[0].sourceLocations,['https://app.test/first']);
 assert.deepEqual(projection.projectIast([finding],'<b>ABSENT</b>'),[]);
});

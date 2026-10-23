import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareCandidateJob} from '../../../security/engine/candidate-inputs.mjs';
const job=(requestSeed,mutation)=>({requestSeed,playbook:{mutations:[{values:['changed'],...mutation}]}});
test('canonical PTK query keys mutate the existing input without adding a prefixed parameter',()=>{
 const source=job({url:'https://app.test/?q=base&keep=%2f',method:'GET',headers:{}},{location:'param',paramKey:'param:q'}),result=prepareCandidateJob(source);
 assert.equal(result.playbook.mutations[0].prepared[0].request.url,'https://app.test/?q=changed&keep=%2f');assert.equal(source.requestSeed.url,'https://app.test/?q=base&keep=%2f');
});
test('ambiguous duplicate inputs need explicit occurrence selection; absent inputs never get invented',()=>{
 const source=job({url:'https://app.test/?q=one&q=two',method:'GET'},{location:'param',paramKey:'param:q'});
 assert.match(prepareCandidateJob(source).playbook.mutations[0].prepared[0].error,/ambiguous/);
 assert.equal(prepareCandidateJob(source,{location:'query',name:'q',index:1}).playbook.mutations[0].prepared[0].request.url,'https://app.test/?q=one&q=changed');
 assert.match(prepareCandidateJob(job({url:'https://app.test/',method:'GET'},{location:'query',paramKey:'q'})).playbook.mutations[0].prepared[0].error,/missing/);
});
test('canonical form and nested JSON mutations preserve unrelated bytes and numeric precision',()=>{
 const form=prepareCandidateJob(job({url:'https://app.test/',method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'q=old&keep=%2f'},{location:'param',paramKey:'param:q'}));
 assert.equal(form.playbook.mutations[0].prepared[0].request.body,'q=changed&keep=%2f');
 const body='{ "user": {"id":7}, "large":90071992547409931234 }';
 const json=prepareCandidateJob(job({url:'https://app.test/',method:'POST',headers:{'Content-Type':'application/json'},body},{location:'json',paramKey:'json:user.id'}));
 assert.equal(json.playbook.mutations[0].prepared[0].request.body,'{ "user": {"id":"changed"}, "large":90071992547409931234 }');
 const array=prepareCandidateJob(job({url:'https://app.test/',method:'POST',headers:{'Content-Type':'application/json'},body:'[{"id":7}, {"id":8}]'},{location:'json',paramKey:'json:$[0].id'}));
 assert.equal(array.playbook.mutations[0].prepared[0].request.body,'[{"id":"changed"}, {"id":8}]');
 const ambiguous=prepareCandidateJob(job({url:'https://app.test/',method:'POST',headers:{'Content-Type':'application/json'},body:'{"user.id":"one","user":{"id":"two"}}'},{location:'json',paramKey:'json:user.id'}));
 assert.match(ambiguous.playbook.mutations[0].prepared[0].error,/ambiguous/);
});
test('header mutation resolves actual casing and identifies transport-owned headers as unsupported',()=>{
 const source=job({url:'https://app.test/',method:'GET',headers:{'Content-Type':'text/plain',Authorization:'private'}},{location:'header',paramKey:'header:content-type'});
 assert.equal(prepareCandidateJob(source).playbook.mutations[0].prepared[0].request.headers['Content-Type'],'changed');
 source.playbook.mutations[0].paramKey='header:Authorization';assert.match(prepareCandidateJob(source).playbook.mutations[0].prepared[0].error,/cannot be mutated/);
});

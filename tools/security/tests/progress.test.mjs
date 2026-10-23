import test from 'node:test';
import assert from 'node:assert/strict';
import { readProgressResponse } from '../../../security/engine/progress.mjs';
test('progress retains engine failure and terminal state inside a successful query', () => {
  const value = { ok:true, sessionId:'native', status:'cancelled', error:'DAST:planning failed', engines:{DAST:{status:'error'},SAST:{status:'stopped'}} };
  assert.equal(readProgressResponse(value), value);
  assert.equal(readProgressResponse({...value,status:'error'}).engines.SAST.status,'stopped');
});
test('a failed progress query is still rejected', () => {
  for (const value of [null, {ok:false,error:'session_not_found'}, {ok:true,success:false,error:'query failed'}, {error:'missing acknowledgement'}]) assert.throws(() => readProgressResponse(value));
});

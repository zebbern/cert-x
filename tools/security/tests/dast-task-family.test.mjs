import test from 'node:test';
import assert from 'node:assert/strict';

globalThis.self = globalThis;
const { dastEngine } = await import('../../../security/ptk/background/dast/dastEngine.js');

const context = {
  _moduleTaxonomy: module => module?.metadata?.taxonomy || {},
  _moduleRuntimeMode: () => 'standard',
};
function family(id, vulnId, tags = [], selectorFamily = 'sqli') {
  const task = { moduleId:id, module:{ id, metadata:{ taxonomy:{ vulnId, tags } }, _selectorFamily:() => selectorFamily } };
  return dastEngine.prototype._taskFamilyKey.call(context, task);
}

test('command injection uses its own scheduler family even when PTK parameter ranking falls back to SQLi', () => {
  assert.equal(family('os_command_injection','command_injection',['command','injection']), 'command');
  assert.equal(family('os_command_injection_blind','command_injection_blind',['command']), 'command');
  assert.equal(family('sql_injection','sql_injection',['sql']), 'sqli');
  assert.equal(family('xss','reflected_xss',['xss'],'xss'), 'xss');
  assert.equal(dastEngine.prototype._familyConcurrencyQuota('command'), 2);
  assert.equal(dastEngine.prototype._familyConcurrencyQuota('sqli'), 1);
});

test('Thorough gives a newly ready request-module group one representative turn before deep repeats', () => {
  const engine = Object.create(dastEngine.prototype);
  engine.settings = { schedulerBreadthFirst:true };
  engine._taskQueueGroupPriority = new Map([['repeated-xss',700],['new-command',0]]);
  engine._taskGroupDispatchCounts = new Map([['repeated-xss',1]]);
  engine._taskReadyGroups = ['repeated-xss'];
  engine._insertReadyGroup('new-command');
  assert.deepEqual(engine._taskReadyGroups,['new-command','repeated-xss']);
  engine.settings.schedulerBreadthFirst = false;
  engine._taskReadyGroups = ['repeated-xss'];
  engine._insertReadyGroup('new-command');
  assert.deepEqual(engine._taskReadyGroups,['repeated-xss','new-command'],'PTK defaults preserve priority ordering');
});

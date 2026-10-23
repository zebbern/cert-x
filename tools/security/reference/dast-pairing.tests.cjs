const test = require('node:test'), assert = require('node:assert/strict'), vm = require('node:vm'), fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, '../src/ki-dast-transport.js'), 'utf8');
function fixture(valid = true) {
  const secret = 'f'.repeat(64), id = 'b'.repeat(32), local = {}, calls = [], discoveries = [];
  const scope = vm.createContext({ crypto: crypto.webcrypto, TextEncoder, Uint8Array, URL, setTimeout, clearTimeout,
    fetch: async () => ({ ok: true, json: async () => ({ version: 1, certXExtensionId: 'a'.repeat(32), pairingSecret: secret }) }),
    chrome: { runtime: { id: 'a'.repeat(32), getURL: file => 'chrome-extension://' + 'a'.repeat(32) + '/' + file,
      sendMessage: async (receiver, message) => { calls.push({ receiver, message }); return message.op === 'hello' ? { ok: true, result: { protocol: 1, capabilities: ['targeted-dast'], proof: valid ? crypto.createHmac('sha256', secret).update(message.payload.nonce).digest('hex') : '0'.repeat(64) } } : { ok: true, result: { state: 'running' } }; } },
      tabs: { get: async () => ({ url: 'https://target.test/app' }) }, scripting: { executeScript: async () => { discoveries.push(1); return [{ frameId: 0, result: 'chrome-extension://' + id }]; } },
      storage: { session: { get: async () => local, set: async update => Object.assign(local, update) } } },
  });
  vm.runInContext(source, scope); return { scope, calls, local, discoveries, secret };
}
test('an untrusted page-supplied companion ID receives only a nonce until pairing verifies', async () => {
  const f = fixture(false);
  await assert.rejects(f.scope.kiDastCompanion('run', { tabId: 1, expectedOrigin: 'https://target.test', headers: { Cookie: 'private-capture' } }), /verification failed/);
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0].message.op, 'hello');
  assert.equal(JSON.stringify(f.calls).includes('private-capture'), false); assert.equal(JSON.stringify(f.calls).includes(f.secret), false);
  assert.equal(Object.keys(f.local).length, 0);
});
test('authenticated companion receives payload and persisted ID is reverified after worker restart', async () => {
  const f = fixture(); const args = { tabId: 1, expectedOrigin: 'https://target.test', privateBody: 'fixture-body' };
  assert.equal((await f.scope.kiDastCompanion('run', args)).state, 'running');
  f.scope.kiDastCompanionCache = null;
  await f.scope.kiDastCompanion('status', { batchId: 'fixture' });
  assert.equal(f.discoveries.length, 1); assert.deepEqual(f.calls.map(call => call.message.op), ['hello', 'run', 'hello', 'status']);
  assert.equal(JSON.stringify(f.calls).includes(f.secret), false); assert.equal(JSON.stringify(f.local).includes(f.secret), false);
});
test('target origin mismatch blocks even discovery', async () => {
  const f = fixture(); await assert.rejects(f.scope.kiDastCompanion('run', { tabId: 1, expectedOrigin: 'https://outside.test' }), /changed origin/);
  assert.equal(f.calls.length, 0); assert.equal(f.discoveries.length, 0);
});

test('revocation after pairing blocks the raw execution payload at the transport boundary', async () => {
  const f = fixture();
  await assert.rejects(f.scope.kiDastCompanion('run', { tabId: 1, expectedOrigin: 'https://target.test', body: 'private-body' }, undefined, async () => {
    assert.deepEqual(f.calls.map(call => call.message.op), ['hello']);
    throw Error('Permission revoked during pairing');
  }), /revoked during pairing/);
  assert.deepEqual(f.calls.map(call => call.message.op), ['hello']);
  assert.equal(JSON.stringify(f.calls).includes('private-body'), false);
});

const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const { prepare } = require('./pairing.cjs');
test('pairing preserves keys and companion identity, restricts callers, and refuses exposed secret files', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-pairing-')), root = path.join(temp, 'client'), output = path.join(temp, 'companion');
  try {
    fs.mkdirSync(path.join(output, 'src'), { recursive: true });
    const manifestFile = path.join(output, 'src/manifest.json'); fs.writeFileSync(manifestFile, JSON.stringify({ version: '10.0.0', name: 'PTK', web_accessible_resources: [{ resources: ['ptk/*.js'], matches: ['<all_urls>'] }] }));
    const result = prepare(root, output, 'a'.repeat(32)); assert.equal(result.certXExtensionId, 'a'.repeat(32));
    const first = fs.readFileSync(path.join(root, 'providers/ptk-connection.json'), 'utf8');
    prepare(root, output); assert.ok(first === fs.readFileSync(path.join(root, 'providers/ptk-connection.json'), 'utf8'));
    const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8')); assert.equal(manifest.key, undefined); assert.deepEqual(manifest.externally_connectable, { ids: ['a'.repeat(32)] });
    assert.ok(first === fs.readFileSync(path.join(output, 'src/cert-x-connection.json'), 'utf8'));
    manifest.web_accessible_resources[0].resources = ['cert*.json']; fs.writeFileSync(manifestFile, JSON.stringify(manifest));
    assert.throws(() => prepare(root, output), /exposes/); assert.ok(first === fs.readFileSync(path.join(root, 'providers/ptk-connection.json'), 'utf8'));
  } finally { if (path.resolve(temp).startsWith(path.resolve(os.tmpdir()) + path.sep)) fs.rmSync(temp, { recursive: true, force: true }); }
});

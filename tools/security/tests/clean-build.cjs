// Exercise the normal build from a source-only checkout, outside the inspiration tree.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '../../..');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-clean-build-'));
const outputs = ['background/background.js', 'chunks/sidepanel-CUbsl7eV.js', 'assets/sidepanel-DD7JAQkM.css'];
const hashes = base => Object.fromEntries(outputs.map(file => [file, crypto.createHash('sha256').update(fs.readFileSync(path.join(base, file))).digest('hex')]));
try {
  const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: root, encoding: 'utf8', windowsHide: true }).split('\0').filter(Boolean);
  for (const file of new Set(files)) {
    const source = path.resolve(root, file), target = path.resolve(directory, file);
    assert.ok(source.startsWith(root + path.sep) && target.startsWith(directory + path.sep));
    if (!fs.existsSync(source)) continue; // Deleted tracked files are absent in the resulting checkout.
    assert.ok(fs.lstatSync(source).isFile(), 'Only regular source files belong in this test: ' + file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(source, target);
  }
  assert.equal(fs.existsSync(path.join(directory, 'node_modules')), false);
  assert.equal(fs.existsSync(path.join(directory, 'providers/ptk-connection.json')), false);
  const expected = hashes(root);
  // The checkout includes generated products. Perturb them so a no-op cannot pass;
  // the package validator must still be able to parse the worker before rebuilding.
  for (const file of outputs) fs.appendFileSync(path.join(directory, file), '\n/* clean-build rewrite sentinel */\n');
  const build = () => execFileSync(process.execPath, ['tools/picker/apply-picker.js'], { cwd: directory, encoding: 'utf8', windowsHide: true, timeout: 120000 });
  build();
  const first = hashes(directory);
  assert.deepEqual(first, expected, 'Standalone source build must match the reviewed checkout');
  build();
  assert.deepEqual(hashes(directory), first, 'A second build must be byte-identical');
  console.log(JSON.stringify({ sourceFiles: new Set(files).size, standalone: true, deterministic: true, hashes: first }));
} finally {
  const resolved = fs.realpathSync(directory);
  assert.ok(resolved.startsWith(fs.realpathSync(os.tmpdir()) + path.sep) && path.basename(resolved).startsWith('cert-x-clean-build-'));
  fs.rmSync(resolved, { recursive: true, force: true });
}

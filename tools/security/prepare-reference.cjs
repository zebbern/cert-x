// Independent parity oracle: copy the original runnable extension, never the
// modified companion or the owned cert-x runtime. No original file is changed.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), crypto = require('node:crypto');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const baseline = JSON.parse(fs.readFileSync(path.join(__dirname, 'reference/baseline.json'), 'utf8'));
function inventory(root, relative = '') {
  return fs.readdirSync(path.join(root, relative), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en')).flatMap(entry => {
    const name = path.join(relative, entry.name);
    if (entry.isSymbolicLink()) throw Error('Reference source must not contain symlinks: ' + name);
    return entry.isDirectory() ? inventory(root, name) : [{ path: name.replaceAll('\\', '/'), sha256: sha(fs.readFileSync(path.join(root, name))) }];
  });
}
function verify(root) {
  root = fs.realpathSync(root);
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  if (manifest.version !== '10.0.0') throw Error('Reference must be the original supplied PTK 10.0.0.');
  if (fs.existsSync(path.join(root, 'cert-x-connection.json')) || fs.existsSync(path.join(root, 'ptk/cert-x'))) throw Error('A patched companion is not an independent reference.');
  const files = inventory(root), digest = sha(JSON.stringify(files));
  if (digest !== baseline.sha256 || files.length !== baseline.files) throw Error('The reference differs from the recorded supplied PTK baseline. Select the unmodified source; do not use the patched companion.');
  return { root, manifest, files, digest };
}
function prepare(source = path.resolve(__dirname, '../../../insp/pentestkit-10.0.0-release')) {
  source = fs.realpathSync(source);
  const { root, manifest, files, digest } = verify(path.join(source, 'src'));
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-security-reference-'));
  fs.cpSync(root, path.join(directory, 'src'), { recursive: true, errorOnExist: true });
  const copied = inventory(path.join(directory, 'src'));
  if (JSON.stringify(copied) !== JSON.stringify(files)) throw Error('Reference copy differs from source.');
  const metadata = { version: 1, ptkVersion: manifest.version, sha256: digest, files, source, extensionPath: path.join(directory, 'src') };
  fs.writeFileSync(path.join(directory, 'reference.json'), JSON.stringify(metadata, null, 2) + '\n');
  return { directory, ...metadata };
}
function resolveReference(extensionPath) { if (!extensionPath) return prepare(); const value = verify(extensionPath); return { extensionPath: value.root, sha256: value.digest, files: value.files }; }
module.exports = { prepare, inventory, verify, resolveReference };
if (require.main === module) {
  try { const result = prepare(process.argv[2]); console.log(JSON.stringify({ directory: result.directory, extensionPath: result.extensionPath, sha256: result.sha256, files: result.files.length })); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}

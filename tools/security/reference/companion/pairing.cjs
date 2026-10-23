// Private local pairing material is deliberately excluded from the repository.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
function read(file) { return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null; }
function validate(value) {
  if (value && (value.version !== 1 || !/^[a-p]{32}$/.test(value.certXExtensionId || '') || !/^[a-f0-9]{64}$/.test(value.pairingSecret || ''))) throw Error('Existing PTK pairing is invalid. Preserve it and resolve the configuration before preparing DAST.');
  return value;
}
function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const text = JSON.stringify(value, null, 2) + '\n';
  if (fs.existsSync(file) && fs.readFileSync(file, 'utf8') === text) return;
  const temporary = file + '.tmp'; fs.writeFileSync(temporary, text, { mode: 0o600 }); fs.renameSync(temporary, file);
}
function prepare(root, output, extensionId) {
  const clientFile = path.join(root, 'providers/ptk-connection.json'), serverFile = path.join(output, 'src/cert-x-connection.json');
  const client = validate(read(clientFile)), server = validate(read(serverFile));
  const id = extensionId || client?.certXExtensionId || server?.certXExtensionId;
  if (!/^[a-p]{32}$/.test(id || '')) throw Error('Use -ExtensionId with the cert-x extension ID. Copy the command from PTK settings.');
  if (client && server && client.pairingSecret !== server.pairingSecret) throw Error('The existing PTK and cert-x pairing keys differ. Neither was changed; use a new OutputDirectory with the current cert-x configuration.');
  const config = { version: 1, certXExtensionId: id, pairingSecret: client?.pairingSecret || server?.pairingSecret || crypto.randomBytes(32).toString('hex') };
  const manifestFile = path.join(output, 'src/manifest.json'), manifest = read(manifestFile);
  if (!manifest || manifest.version !== '10.0.0') throw Error('Prepare PTK v10 before pairing.');
  // Never expose the pairing file as a web-accessible resource.
  for (const entry of manifest.web_accessible_resources || []) for (const resource of entry.resources || []) {
    const pattern = String(resource).replace(/^\.?\//, '').replace(/[.+?^${}()|[\]\\]/g, '\\$&').replaceAll('*', '.*');
    if (new RegExp('^' + pattern + '$').test('cert-x-connection.json')) throw Error('The companion manifest exposes its private pairing file.');
  }
  manifest.externally_connectable = { ids: [id] };
  write(clientFile, config); write(serverFile, config); write(manifestFile, manifest);
  return { version: 1, certXExtensionId: id, transport: 'external-extension-messaging-with-HMAC-challenge' };
}
module.exports = { prepare };

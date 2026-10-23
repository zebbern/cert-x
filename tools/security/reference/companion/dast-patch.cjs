const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const revision = 5;
function apply(sourceRoot, outputRoot, previous = {}) {
  const relative = 'src/app.js', original = fs.readFileSync(path.join(sourceRoot, relative), 'utf8');
  const marker = 'worker.ptk_app = new ptk_app(JSON.parse(JSON.stringify(defaultSettings)))';
  if (original.indexOf(marker) < 0 || original.indexOf(marker) !== original.lastIndexOf(marker)) throw Error('PTK app initialization anchor changed.');
  const patched = "import { installCertXDast } from './ptk/cert-x/dast-companion.js'\n" + original.replace(marker, marker + '\ninstallCertXDast()');
  const files = [
    { relative, original, next: patched },
    ...['dast-companion.js', 'dast-core.mjs', 'dast-inputs.js', 'authz-core.mjs', 'authz-transport.mjs'].map(name => ({ relative: 'src/ptk/cert-x/' + name, next: fs.readFileSync(path.join(__dirname, name), 'utf8') })),
  ];
  for (const file of files) {
    file.target = path.join(outputRoot, file.relative);
    if (!fs.existsSync(file.target)) { if (file.original) throw Error('Prepared PTK app is missing.'); continue; }
    const current = fs.readFileSync(file.target, 'utf8');
    if (current !== file.original && current !== file.next && hash(current) !== previous?.files?.[file.relative]?.sha256) throw Error('Prepared DAST file has unrecognized edits: ' + file.relative);
  }
  for (const file of files) { fs.mkdirSync(path.dirname(file.target), { recursive: true }); fs.writeFileSync(file.target, file.next); }
  return { revision, purpose: 'Paired selected-request DAST and account comparisons with ordinal inputs, bounded confirmation, passive observations and coverage',
    files: Object.fromEntries(files.map(file => [file.relative, { ...(file.original ? { originalSha256: hash(file.original) } : {}), sha256: hash(file.next) }])) };
}
module.exports = { revision, apply };

// Build an auditable companion copy. Never modify the supplied source or live browser.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto'), cp = require('node:child_process');
const compat = require('./compat.cjs');
const pairing = require('./pairing.cjs');
const dastPatch = require('./dast-patch.cjs');
const args = process.argv.slice(2), value = name => args.includes(name) ? args[args.indexOf(name) + 1] : undefined;
const source = path.resolve(value('--source') || ''), output = path.resolve(value('--output') || '');
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const ignored = new Set(['.git', 'node_modules', 'dist']);
function canonicalPath(file) {
  let ancestor = file, tail = [];
  while (!fs.existsSync(ancestor)) { tail.unshift(path.basename(ancestor)); const parent = path.dirname(ancestor); if (parent === ancestor) throw Error('Cannot resolve output location.'); ancestor = parent; }
  return path.join(fs.realpathSync(ancestor), ...tail).toLowerCase();
}
function files(root, relative = '') {
  const result = [];
  for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true }).sort((a,b) => a.name.localeCompare(b.name, 'en'))) {
    const name = path.join(relative, entry.name);
    if (entry.isSymbolicLink()) throw Error('Source contains a symbolic link: ' + name);
    if (entry.isDirectory()) { if (!ignored.has(entry.name) && name.replaceAll('\\', '/') !== 'misc/tmp') result.push(...files(root, name)); }
    else if (entry.isFile()) result.push(name);
  }
  return result;
}
function run(file, params) {
  const result = cp.spawnSync(process.execPath, [file, ...params], { cwd: output, stdio: 'inherit', windowsHide: true, timeout: 15 * 60 * 1000,
    env: { ...process.env, CYPRESS_INSTALL_BINARY: '0', PUPPETEER_SKIP_DOWNLOAD: 'true', PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1' } });
  if (result.error) throw result.error;
  if (result.status !== 0) throw Error(path.basename(file) + ' failed with exit ' + result.status);
}
function verifyPrepared() {
  const extension = path.join(output, 'src');
  const manifest = JSON.parse(fs.readFileSync(path.join(extension, 'manifest.json'), 'utf8'));
  if (manifest.version !== '10.0.0') throw Error('Prepared manifest is not PTK v10.');
  if (JSON.parse(fs.readFileSync(path.join(extension, 'dev.local.json'), 'utf8')).automationEnabled !== true) throw Error('Prepared automation capability is not enabled.');
  for (const name of ['app.js', 'ptk/packages/browser-polyfill/browser-polyfill.min.js', 'ptk/ptkAgentAutomation.js', 'ptk/automationBridge.js', 'ptk/background/automation.js', 'LICENSE-PTK.txt']) {
    if (!fs.statSync(path.join(extension, name)).isFile()) throw Error('Missing prepared file: ' + name);
  }
}
try {
  if (!args.includes('--source') || !args.includes('--output')) throw Error('Specify --source and --output.');
  const canonicalSource = canonicalPath(source), canonicalOutput = canonicalPath(output);
  if (canonicalSource === canonicalOutput || canonicalOutput.startsWith(canonicalSource + path.sep) || canonicalSource.startsWith(canonicalOutput + path.sep)) throw Error('Source and output must be separate directories.');
  const pkg = JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8'));
  if (pkg.name !== 'owasp-pentestkit-extension' || pkg.version !== '10.0.0') throw Error('This adapter requires the supplied OWASP PTK 10.0.0 source.');
  const inventory = files(source).map(name => ({ path: name.replaceAll('\\', '/'), sha256: digest(fs.readFileSync(path.join(source, name))) }));
  const sourceSha256 = digest(JSON.stringify(inventory)), metadataPath = path.join(output, 'cert-x-build.json');
  const metadata = { schema: 1, version: pkg.version, source, sourceSha256, files: inventory, build: ['npm ci --ignore-scripts --no-audit --no-fund', 'webpack --config misc/webpack.config.js', 'node script/build_src.js'], automation: { automationEnabled: true } };
  if (fs.existsSync(output)) {
    if (!fs.existsSync(metadataPath)) throw Error('Output exists without cert-x provenance; choose a new OutputDirectory.');
    const previous = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    if (previous.sourceSha256 !== sourceSha256) throw Error('Source changed since this output was prepared; choose a new OutputDirectory.');
    if (previous.complete) {
      try { verifyPrepared(); } catch (error) { throw Error('Prepared PTK is incomplete or changed: ' + error.message + ' Choose a new OutputDirectory to prepare a fresh copy.'); }
      const integration = compat.apply(source, output, previous.integration);
      const dast = dastPatch.apply(source, output, previous.dast);
      const connection = pairing.prepare(path.resolve(__dirname, '../..'), output, value('--extension-id'));
      fs.writeFileSync(metadataPath, JSON.stringify({ ...previous, integration, dast, connection }, null, 2) + '\n');
      console.log('PTK 10.0.0 already prepared and checked: ' + path.join(output, 'src')); process.exit(0);
    }
  } else fs.mkdirSync(output, { recursive: true });
  fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2) + '\n');
  for (const entry of inventory) { const target = path.join(output, entry.path); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.copyFileSync(path.join(source, entry.path), target); }
  const npm = path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
  if (!fs.existsSync(npm)) throw Error('npm was not found alongside Node.js; install a standard Node.js distribution.');
  run(npm, ['ci', '--ignore-scripts', '--no-audit', '--no-fund']);
  if (digest(fs.readFileSync(path.join(output, 'package-lock.json'))) !== inventory.find(file => file.path === 'package-lock.json').sha256) throw Error('Dependency lock changed unexpectedly.');
  run(path.join(output, 'node_modules/webpack-cli/bin/cli.js'), ['--config', 'misc/webpack.config.js']);
  run(path.join(output, 'script/build_src.js'), []);
  // Use the supplied detection databases. build_waf updates them from moving upstream branches.
  fs.writeFileSync(path.join(output, 'src/dev.local.json'), JSON.stringify(metadata.automation, null, 2) + '\n');
  fs.copyFileSync(path.join(source, 'LICENSE.txt'), path.join(output, 'src/LICENSE-PTK.txt'));
  const manifest = JSON.parse(fs.readFileSync(path.join(output, 'src/manifest.json'), 'utf8'));
  if (manifest.version !== '10.0.0') throw Error('Built manifest version mismatch.');
  for (const name of ['app.js', 'ptk/packages/browser-polyfill/browser-polyfill.min.js', 'ptk/ptkAgentAutomation.js']) if (!fs.existsSync(path.join(output, 'src', name))) throw Error('Missing built file: ' + name);
  verifyPrepared();
  const integration = compat.apply(source, output);
  const dast = dastPatch.apply(source, output);
  const connection = pairing.prepare(path.resolve(__dirname, '../..'), output, value('--extension-id'));
  const finalInventory = files(source).map(name => ({ path: name.replaceAll('\\', '/'), sha256: digest(fs.readFileSync(path.join(source, name))) }));
  if (digest(JSON.stringify(finalInventory)) !== sourceSha256) throw Error('Source changed during preparation.');
  fs.writeFileSync(metadataPath, JSON.stringify({ ...metadata, integration, dast, connection, complete: true, builtAt: new Date().toISOString(), node: process.version, extensionPath: path.join(output, 'src') }, null, 2) + '\n');
  console.log('PTK 10.0.0 prepared. Load unpacked in chrome://extensions: ' + path.join(output, 'src'));
} catch (error) { console.error(error.message); process.exitCode = 1; }

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from '../../security/ptk/background/sast/acorn/acorn.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const visited = new Set();
function visit(file) {
  file = path.resolve(file);
  if (!file.startsWith(root + path.sep)) throw Error('Packaged import escapes the checkout: ' + file);
  if (visited.has(file)) return;
  if (!fs.existsSync(file)) throw Error('Missing packaged module: ' + path.relative(root, file));
  visited.add(file);
  if (!/\.(?:js|mjs)$/.test(file)) return;
  const tree = parse(fs.readFileSync(file, 'utf8'), { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true });
  for (const node of tree.body) {
    if (!['ImportDeclaration', 'ExportNamedDeclaration', 'ExportAllDeclaration'].includes(node.type) || !node.source) continue;
    const value = node.source.value;
    if (!value.startsWith('.')) throw Error('Non-packaged module dependency in ' + path.relative(root, file) + ': ' + value);
    visit(path.resolve(path.dirname(file), value));
  }
}
visit(path.join(root, 'background/entry.js'));
const inventory = JSON.parse(fs.readFileSync(path.join(root, 'security/capabilities.json'), 'utf8'));
const actual = [];
for (const [engine, name] of [['DAST', 'modules.json'], ['DAST', 'modules_cve.json'], ['SAST', 'modules.json'], ['IAST', 'modules.json']]) {
  const pack = JSON.parse(fs.readFileSync(path.join(root, 'security/ptk/background', engine.toLowerCase(), 'modules', name), 'utf8'));
  for (const item of pack.modules) {
    const key = engine + ':' + item.id; actual.push(key);
    if (!inventory.modules.some(record => record.engine === engine && record.id === item.id && record.executable === true)) throw Error('Executable module missing from capability inventory: ' + key);
  }
}
for (const item of inventory.modules) if (!actual.includes(item.engine + ':' + item.id)) throw Error('Inventory advertises missing module: ' + item.id);
if (new Set(actual).size !== actual.length) throw Error('Duplicate executable engine module IDs.');
for (const file of ['security/ptk/offscreen/runtime_offscreen.html', 'security/ptk/LICENSE-PTK.txt', 'security/skills/security-testing.md']) if (!fs.existsSync(path.join(root, file))) throw Error('Missing security runtime resource: ' + file);
console.log('security package OK (' + visited.size + ' module dependencies; ' + actual.length + ' executable modules; verification remains test-specific)');

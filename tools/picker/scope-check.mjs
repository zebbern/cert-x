// A name bound twice in a bundle's top scope. Minified code never does that on
// purpose: two different symbols got one name, and whichever assignment runs last
// replaces the other everywhere. The vendor background bundle shipped four, made by
// hand-added tools reusing minified names; one turned every failed model call into
// "Class constructor Rd cannot be invoked without 'new'".
//   node tools/picker/scope-check.mjs [--module] < bundle.js
// Exit 1: a clash (listed on stderr). Exit 2: the bundle could not be checked.
import { pathToFileURL } from 'node:url';
import { parse } from '../../security/ptk/background/sast/acorn/acorn.mjs';

const nested = node => /Function|Class|StaticBlock/.test(node.type);
const unwrap = node => node?.type === 'UnaryExpression' ? node.argument : node?.type === 'SequenceExpression' ? node.expressions.at(-1) : node;
const iife = node => { node = unwrap(node); return node?.type === 'CallExpression' && /Function/.test(node.callee.type) ? node.callee.body : null; };
const strict = body => body.body?.some(s => s.directive === 'use strict');

// Top scopes: the program, plus the body of a top-level IIFE (`var background=(function(){...})()`,
// `!function(){...}()`), where the background bundle keeps all of its module-level symbols.
// Inner function scopes are left alone: re-declaring a loop's `var i=0` there is one symbol, not two.
function topScopes(ast) {
  const scopes = [ast];
  for (const statement of ast.body) {
    const body = statement.type === 'ExpressionStatement' ? iife(statement.expression)
      : statement.type === 'VariableDeclaration' ? statement.declarations.map(d => iife(d.init)).find(Boolean) : null;
    if (body) scopes.push(body);
  }
  return scopes;
}

function patternNames(pattern, out = []) {
  if (!pattern) return out;
  if (pattern.type === 'Identifier') out.push(pattern);
  else if (pattern.type === 'ObjectPattern') pattern.properties.forEach(p => patternNames(p.type === 'RestElement' ? p.argument : p.value, out));
  else if (pattern.type === 'ArrayPattern') pattern.elements.forEach(e => patternNames(e, out));
  else if (pattern.type === 'AssignmentPattern') patternNames(pattern.left, out);
  else if (pattern.type === 'RestElement') patternNames(pattern.argument, out);
  return out;
}

// A binding defines a value when it is a function or class declaration, a var with an
// initializer (destructured names included), or a for-in/for-of var head; a bare
// `var x;` adds no second symbol. Block-level functions replace the scope's binding
// only in sloppy scripts (Annex B); in modules and strict code they stay in the block.
function definitions(scope, blockFunctions) {
  const found = new Map();
  const add = (name, at) => found.set(name, [...(found.get(name) || []), at]);
  (function walk(node, depth) {
    if (!node || typeof node.type !== 'string') return;
    if (node.type === 'FunctionDeclaration' || node.type === 'ClassDeclaration') {
      const inScopeBody = depth <= 1;
      if (node.id && (inScopeBody || (node.type === 'FunctionDeclaration' && blockFunctions))) add(node.id.name, node.start);
      return;
    }
    if (depth && nested(node)) return;
    if ((node.type === 'ForInStatement' || node.type === 'ForOfStatement') && node.left.type === 'VariableDeclaration' && node.left.kind === 'var')
      for (const id of patternNames(node.left.declarations[0].id)) add(id.name, id.start);
    else if (node.type === 'VariableDeclaration' && node.kind === 'var')
      for (const d of node.declarations) if (d.init) for (const id of patternNames(d.id)) add(id.name, id.start);
    for (const key in node) {
      const value = node[key];
      if (Array.isArray(value)) value.forEach(child => walk(child, depth + 1));
      else if (value && typeof value.type === 'string') walk(value, depth + 1);
    }
  })(scope, 0);
  return found;
}

export function scopeClashes(source, sourceType = 'script') {
  const ast = parse(source, { ecmaVersion: 'latest', sourceType });
  const clashes = [];
  for (const scope of topScopes(ast)) {
    const blockFunctions = sourceType === 'script' && !strict(ast) && !strict(scope);
    for (const [name, at] of definitions(scope, blockFunctions)) if (at.length > 1) clashes.push({ name, at });
  }
  return clashes;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const source = Buffer.concat(chunks).toString('utf8');
  try {
    const clashes = scopeClashes(source, process.argv.includes('--module') ? 'module' : 'script');
    for (const { name, at } of clashes) console.error('scope clash: ' + name + ' bound ' + at.length + ' times: ' + at.map(i => JSON.stringify(source.slice(i, i + 60))).join(' | '));
    process.exitCode = clashes.length ? 1 : 0;
  } catch (error) { console.error('scope check could not parse the bundle: ' + error.message); process.exitCode = 2; }
}

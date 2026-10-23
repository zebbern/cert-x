import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {parse} from '../../../security/ptk/background/sast/acorn/acorn.mjs';
const source=fs.readFileSync(new URL('../../../security/ptk/content/iast.js',import.meta.url),'utf8');
let fn;function visit(n){if(!n||typeof n!=='object')return;if(n.type==='FunctionDeclaration'&&n.id?.name==='propagateTaint')fn=n;for(const v of Object.values(n)){if(Array.isArray(v))v.forEach(visit);else if(v&&typeof v==='object')visit(v);}}visit(parse(source,{ecmaVersion:'latest'}));
const owned='let certXPropagationDepth=0;\n'+source.slice(fn.start,fn.end);
const original=fs.readFileSync(new URL('./fixtures/iast-propagation-original.js',import.meta.url),'utf8');
function harness(code){const context=vm.createContext({});vm.runInContext(`
var window={__PTK_IAST_PROPAGATION_ENABLED__:true,__PTK_IAST_HAS_TAINT__:true};
var IAST_TAINT_STORE={nextTaintId:1,stringMap:new Map(),objectMap:new WeakMap()};
var calls=0,fail=false;
function getIastPropagationSettings(){return {maxLineage:12,maxStringLength:8192,mode:'full'}}
function fingerprintValue(value){return String(value)}
function pruneTaintStore(){}
function getTaintEntry(value){if(++calls>50)throw Error('recursive_bookkeeping');if(fail)throw Error('fixture_failure');if(value==='tainted'){propagateTaint('internal','String.slice',[value]);return {taint:{sourceId:'source',sourceKind:'url',lineage:[]}}}return null;}
`+code,context);return context;}
test('characterizes the PTK comprehensive propagation reentrancy defect without an unbounded hang',()=>{const ctx=harness(original);assert.throws(()=>vm.runInContext("propagateTaint('derived','String.slice',['tainted'])",ctx,{timeout:1000}),/recursive_bookkeeping/);});
test('comprehensive propagation preserves application lineage and suppresses recursive bookkeeping',()=>{const ctx=harness(owned);vm.runInContext("propagateTaint('derived','String.slice',['tainted'])",ctx,{timeout:1000});assert.equal(vm.runInContext("IAST_TAINT_STORE.stringMap.get('derived').taint.sourceId",ctx),'source');assert.equal(vm.runInContext("IAST_TAINT_STORE.stringMap.has('internal')",ctx),false);assert.equal(vm.runInContext('calls',ctx),1);vm.runInContext("propagateTaint('safe-output','String.slice',['safe'])",ctx);assert.equal(vm.runInContext("IAST_TAINT_STORE.stringMap.has('safe-output')",ctx),false);});
test('propagation reentrancy guard is released after an exception',()=>{const ctx=harness(owned);assert.throws(()=>vm.runInContext("fail=true;propagateTaint('failed','String.slice',['tainted'])",ctx),/fixture_failure/);vm.runInContext("fail=false;propagateTaint('after','String.slice',['tainted'])",ctx);assert.equal(vm.runInContext("IAST_TAINT_STORE.stringMap.has('after')",ctx),true);});
test('boxed String receivers preserve source taint without coercing arbitrary objects',()=>{
 let lookup;function find(n){if(!n||typeof n!=='object')return;if(n.type==='FunctionDeclaration'&&n.id?.name==='getTaintEntry')lookup=n;for(const v of Object.values(n)){if(Array.isArray(v))v.forEach(find);else if(v&&typeof v==='object')find(v);}}find(parse(source,{ecmaVersion:'latest'}));
 const ctx=vm.createContext({});vm.runInContext(`var window={__PTK_IAST_HAS_TAINT__:true};var IAST_TAINT_TTL_MS=10000;var IAST_TAINT_STORE={objectMap:new WeakMap(),stringMap:new Map([['tainted',{taint:{sourceId:'source'},time:Date.now()}]])};function fingerprintValue(value){return String(value)};`+source.slice(lookup.start,lookup.end),ctx);
 assert.equal(vm.runInContext("getTaintEntry(new String('tainted')).taint.sourceId",ctx),'source');
 assert.equal(vm.runInContext("getTaintEntry({toString(){throw Error('do not invoke')}})",ctx),null);
});

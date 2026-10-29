// The build refuses a bundle whose top scope binds one name twice (scope-check.mjs).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");

const root = path.join(__dirname, "..", "..", "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const names = async (source, type) => (await import("../scope-check.mjs")).scopeClashes(source, type).map(clash => clash.name).sort();

test("a name defined twice in the top scope or its IIFE is a clash; inner scopes and bare re-declarations are not", async () => {
  assert.deepEqual(await names("var b=(function(){function Rd(e){return e}var Rd=class{};var Fd=[1];var Fd;var ok=1})()"), ["Rd"]);
  assert.deepEqual(await names("var a=1;function f(){var i=0;for(var i=0;;);}var a=2"), ["a"]);
  assert.deepEqual(await names("(function(){var x=1;(function(){var x=2})();if(1){var y=1}var y=2})()"), ["y"]);
});

test("destructured vars, for-of heads and !function wrappers count; strict and module block functions do not", async () => {
  assert.deepEqual(await names("var b=(function(){var {Environment:Zj,x:[Q]}=o;var Zj=1;var Q=2})()"), ["Q", "Zj"]);
  assert.deepEqual(await names("var b=(function(){function Rd(){}for(var Rd of [1]);})()"), ["Rd"]);
  assert.deepEqual(await names("!function(){function Rd(){}var Rd=class{}}()"), ["Rd"]);
  // Annex B: a block function replaces the binding in sloppy code only.
  assert.deepEqual(await names("(function(){function f(){return 1}if(1){function f(){return 2}}})()"), ["f"]);
  assert.deepEqual(await names("(function(){'use strict';function f(){return 1}if(1){function f(){return 2}}})()"), []);
  assert.deepEqual(await names("function f(){return 1}if(1){function f(){return 2}}export default function(){}", "module"), []);
});

test("the vendor bundle's four clashes are found, and the built bundles have none", async () => {
  assert.deepEqual(await names(read("tools/picker/original/background.js")), ["Ed", "Fd", "Rd", "XD"]);
  const built = read("background/background.js");
  assert.deepEqual(await names(built), []);
  assert.deepEqual(await names(read("chunks/sidepanel-CUbsl7eV.js"), "module"), []);
  // Undoing one rename brings back the clash behind BugStore run 2's "Class constructor Rd".
  assert.deepEqual(await names(built.replace("var kiReadFileTool=class{name=`read_file`;", "var Rd=class{name=`read_file`;")), ["Rd"]);
});

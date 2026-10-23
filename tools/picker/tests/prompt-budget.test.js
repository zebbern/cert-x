// Enforces the AGENTS.md prompt budget: the standing surface a Bug bounty chat
// sees every turn stays under 8,500 characters. Counted here: the security
// workflow system-prompt block, the security-testing skill, the security
// registry, targeted-DAST and account-comparison description maps, the
// appended prefixes, and the knowledge-graph tool descriptions. NOT counted:
// per-parameter schema descriptions and remote-MCP server descriptions, which
// are separate surfaces. The ceiling was raised once from 8,000 to complete
// accounting for the graph tools (previously uncounted, not new prose) —
// raise it only to correct accounting, never to fit new content.
// Measurement is static on the source text: description strings must not
// contain escaped quotes of their own quoting character (they do not today).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");

const src = file => fs.readFileSync(path.join(__dirname, "../src", file), "utf8");

function registryDescriptions() {
  const source = src("ki-security.js"), start = source.indexOf("var KI_SECURITY_REGISTRY = ["), end = source.indexOf("\n];", start);
  assert.ok(start >= 0 && end > start, "KI_SECURITY_REGISTRY block not found");
  return [...source.slice(start, end).matchAll(/description: '([^']*)'/g)].map(match => match[1]);
}

function descriptionMap(file) {
  const source = src(file), start = source.indexOf("const descriptions = {"), end = source.indexOf("};", start);
  assert.ok(start >= 0, file + " descriptions map not found");
  return [...source.slice(start, end).matchAll(/: "([^"]*)"/g)].map(match => match[1]);
}

function graphDescriptions() {
  const source = src("ki-graph.js");
  const found = [...source.matchAll(/name: "(graph_[a-z]+)", description: "([^"]*)"/g)].map(match => match[2]);
  assert.equal(found.length, 3, "expected the three graph tool descriptions");
  return found;
}

function workflowBlockLength() {
  const source = src("ki-context.js"), open = "[Security testing workflow]", close = "[/Security testing workflow]";
  const start = source.indexOf(open), end = source.indexOf(close, start);
  assert.ok(start >= 0 && end > start, "security workflow block not found in ki-context.js");
  return open.length + (end - start - open.length) + close.length;
}

function appendedPrefixLengths() {
  const source = src("ki-security.js");
  const account = source.match(/description: tool\.description \+ '([^']*)'/);
  const targeted = source.match(/description: '([^']*)' \+ tool\.description/);
  assert.ok(account && targeted, "appended description prefixes not found");
  return account[1].length + targeted[1].length;
}

test("Bug bounty standing prompt surface stays under the 8,500-character budget", () => {
  const skill = fs.readFileSync(path.join(__dirname, "..", "..", "..", "security", "skills", "security-testing.md"), "utf8");
  const registry = registryDescriptions(), dast = descriptionMap("ki-dast.js"), authz = descriptionMap("ki-authz.js"), graph = graphDescriptions();
  const workflow = workflowBlockLength(), prefixes = appendedPrefixLengths();
  const sum = list => list.reduce((total, text) => total + text.length, 0);
  const total = skill.length + workflow + prefixes + sum(registry) + sum(dast) + sum(authz) + sum(graph);
  console.log("prompt surface: skill " + skill.length + " + workflow " + workflow + " + prefixes " + prefixes +
    " + registry " + sum(registry) + " + dast " + sum(dast) + " + authz " + sum(authz) + " + graph " + sum(graph) + " = " + total);
  assert.ok(total < 8500, "standing prompt surface is " + total + " chars; budget is 8,500 — move prose into tool results or trim");
  assert.ok(workflow < 300, "the system-prompt workflow block must stay a pointer to the skill, not a rulebook");
  assert.ok(skill.length < 5000, "the skill file is growing past its share of the budget");
  assert.ok(sum(graph) < 500, "the graph tool descriptions must stay terse");
  assert.ok(registry.length >= 20, "expected the full security registry");
});

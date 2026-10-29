// Enforces the AGENTS.md prompt budget: the standing surface a Bug bounty chat
// sees every turn stays under 13,000 characters. Counted here: the
// [User-selected task context] block with the builtin Bug bounty instructions,
// the security workflow system-prompt block, the security-testing skill, the security
// registry, targeted-DAST and account-comparison description maps, the
// appended prefixes, the knowledge-graph tool descriptions, and every tool
// description cert-x writes for the browser surface (ki-tools.js specs, the
// upload override, get_capabilities). NOT counted: per-parameter schema
// descriptions, remote-MCP server descriptions, Local-computer tools (only
// present once the user turns local access on), and the vendor's own tool
// table and system prompt, which cert-x does not author.
// Ceiling history: 8,000 -> 8,500 to count the graph tools; 8,500 -> 13,000 on
// 2026-10-26: 8,415 counted before + 1,188 task context and 2,823 browser/product
// tool descriptions (both always sent, never counted) + 356 for browse(goal),
// which the user approved = 12,782, leaving 218 so new standing prose must
// displace old. Since then the [Fast browse] system-prompt line (213, sent while
// Fast browse is on; measured: without it 0/7 fixture tasks used browse) is
// counted too, paid for by a shorter browse description: 12,995. Raise it only to correct accounting or for a capability the
// user asked for, never to fit prose that belongs in tool results.
// Measurement is static on the source text: description strings must not
// contain escaped quotes of their own quoting character, except where a
// helper below unescapes them.
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

// The [User-selected task context] block a Bug bounty chat gets from kiContextPrompt:
// the fixed wrapper text plus the builtin profile's name and instructions (no workspace).
function bugBountyContextLength() {
  const source = src("ki-context.js");
  const instructions = source.match(/base\("bugbounty", "Bug bounty", "((?:[^"\\]|\\.)*)"/);
  const trailer = source.match(/"(\\nPinned references are references[^"]*\[\/User-selected task context\])"/);
  assert.ok(instructions && trailer, "Bug bounty profile instructions or task-context wrapper not found");
  const header = "\n\n[User-selected task context]\n";
  return header.length + JSON.stringify({ profile: "Bug bounty", instructions: JSON.parse('"' + instructions[1] + '"') }).length + JSON.parse('"' + trailer[1] + '"').length;
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

// The [Fast browse] system-prompt line, sent every turn while Fast browse is on.
function fastBrowsePromptLength() {
  const found = src("ki-browse.js").match(/var KI_BROWSE_PROMPT = "((?:[^"\\]|\\.)*)";/);
  assert.ok(found, "KI_BROWSE_PROMPT not found in ki-browse.js");
  return JSON.parse('"' + found[1] + '"').length;
}

function browserToolDescriptions() {
  const specs = Object.values(require("../src/ki-tools.js").specs).map(spec => spec.description);
  const upload = src("ki-upload.js").match(/pP\.upload\.description = '([^']*)'/);
  const capabilities = src("ki-workspace.js").match(/name: "get_capabilities", description: "((?:[^"\\]|\\.)*)"/);
  assert.ok(specs.length >= 10 && upload && capabilities, "browser tool descriptions not found");
  return [...specs, upload[1], JSON.parse('"' + capabilities[1] + '"')];
}

test("Bug bounty standing prompt surface stays under the 13,000-character budget", () => {
  const skill = fs.readFileSync(path.join(__dirname, "..", "..", "..", "security", "skills", "security-testing.md"), "utf8");
  const registry = registryDescriptions(), dast = descriptionMap("ki-dast.js"), authz = descriptionMap("ki-authz.js"), graph = graphDescriptions(), browser = browserToolDescriptions();
  const workflow = workflowBlockLength(), prefixes = appendedPrefixLengths(), context = bugBountyContextLength(), fast = fastBrowsePromptLength();
  const sum = list => list.reduce((total, text) => total + text.length, 0);
  const total = skill.length + context + workflow + fast + prefixes + sum(registry) + sum(dast) + sum(authz) + sum(graph) + sum(browser);
  console.log("prompt surface: skill " + skill.length + " + task context " + context + " + workflow " + workflow + " + fast browse " + fast + " + prefixes " + prefixes +
    " + registry " + sum(registry) + " + dast " + sum(dast) + " + authz " + sum(authz) + " + graph " + sum(graph) + " + browser tools " + sum(browser) + " = " + total);
  assert.ok(total < 13000, "standing prompt surface is " + total + " chars; budget is 13,000 — move prose into tool results or trim");
  assert.ok(workflow < 300, "the system-prompt workflow block must stay a pointer to the skill, not a rulebook");
  assert.ok(skill.length < 5000, "the skill file is growing past its share of the budget");
  assert.ok(sum(graph) < 500, "the graph tool descriptions must stay terse");
  assert.ok(sum(browser) < 3500, "cert-x browser tool descriptions are growing past their share of the budget");  assert.ok(registry.length >= 20, "expected the full security registry");
});

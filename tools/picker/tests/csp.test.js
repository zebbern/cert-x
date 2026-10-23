const { test } = require("node:test"), assert = require("node:assert/strict"), vm = require("node:vm"), fs = require("node:fs"), path = require("node:path");
const source = fs.readFileSync(path.join(__dirname, "../src/ki-csp.js"), "utf8");
function fixture(initial = {}) {
  const data = structuredClone(initial.data || {}), tabs = initial.tabs || [{ id: 1, url: "https://example.com/page", title: "One", active: true }, { id: 2, url: "https://example.com/other", title: "Two" }];
  let rules = structuredClone(initial.rules || []), failRules = false, failStorage = false, writes = 0;
  const listeners = {}, reloads = [];
  const event = name => ({ addListener: listener => { listeners[name] = listener; } });
  const context = vm.createContext({ URL, console, chrome: {
    runtime: { id: "test", getURL: file => "chrome-extension://test/" + file, onMessage: event("message") },
    storage: { session: { get: async key => ({ [key]: structuredClone(data[key]) }), set: async value => { if (failStorage) { failStorage = false; throw Error("Storage failed"); } writes++; Object.assign(data, structuredClone(value)); } } },
    tabs: { query: async () => structuredClone(tabs), get: async id => { const tab = tabs.find(tab => tab.id === id); if (!tab) throw Error("No tab"); return structuredClone(tab); }, reload: async (...args) => reloads.push(structuredClone(args)), onRemoved: event("removed"), onReplaced: event("replaced"), onUpdated: event("updated") },
    webNavigation: { onCommitted: event("committed") },
    declarativeNetRequest: { getSessionRules: async () => structuredClone(rules), updateSessionRules: async options => { if (failRules) { failRules = false; throw Error("DNR failed"); } rules = rules.filter(rule => !(options.removeRuleIds || []).includes(rule.id)).concat(structuredClone(options.addRules || [])); } },
  } });
  vm.runInContext(source, context);
  return { context, tabs, data, listeners, reloads, rules: () => rules, writes: () => writes, failRules: () => failRules = true, failStorage: () => failStorage = true,
    flush: () => context.kiCspQueue, request: (message, sender = { id: "test", url: "chrome-extension://test/providers/providers.html?section=tools" }) => new Promise(resolve => listeners.message({ type: "KI_CSP", ...message }, sender, resolve)) };
}
test("manual controls are tab and exact-origin scoped, session-only, and do not touch reporting headers", async () => {
  const f = fixture(); await f.flush(); assert.equal(f.rules().length, 0);
  const result = await f.request({ op: "set", tabId: 1, enabled: true }); assert.equal(result.ok, true); assert.equal(result.result.needsReload, true);
  const rule = f.rules()[0]; assert.deepEqual(rule.condition.tabIds, [1]); assert.equal(rule.condition.urlFilter, "|https://example.com/");
  assert.equal(rule.condition.isUrlFilterCaseSensitive, true); assert.equal(rule.action.responseHeaders.length, 6);
  assert.ok(!rule.action.responseHeaders.some(header => ["report-to", "reporting-endpoints"].includes(header.header)));
  assert.equal((await f.request({ op: "status", tabId: 2 })).result.selected.enabled, false);
  const count = f.writes(); await f.request({ op: "status" }); await f.request({ op: "status" }); assert.equal(f.writes(), count, "read polling must not emit storage events forever");
});
test("enabling/disabling require reload and commit confirms apply; reload never targets unsupported tabs", async () => {
  const f = fixture(); await f.request({ op: "set", tabId: 1, enabled: true });
  assert.equal((await f.request({ op: "reload", tabId: 1 })).ok, true); assert.deepEqual(f.reloads, [[1, { bypassCache: true }]]);
  f.listeners.committed({ tabId: 1, frameId: 2, url: f.tabs[0].url }); await f.flush(); assert.equal(f.data.ki_csp_tabs[1].needsReload, true);
  f.listeners.committed({ tabId: 1, frameId: 0, url: f.tabs[0].url }); await f.flush(); assert.equal(f.data.ki_csp_tabs[1].needsReload, false);
  await f.request({ op: "set", tabId: 1, enabled: false }); assert.equal(f.rules().length, 0); assert.equal(f.data.ki_csp_tabs[1].needsReload, true);
  f.listeners.committed({ tabId: 1, frameId: 0, url: f.tabs[0].url }); await f.flush(); assert.equal(f.data.ki_csp_tabs[1], undefined);
  f.tabs[0].url = "chrome://settings"; assert.equal((await f.request({ op: "reload", tabId: 1 })).ok, false);
});
test("cross-origin navigation, closed and replaced tabs clear only owned CSP rules", async () => {
  const unrelated = { id: 12, condition: {}, action: { type: "block" } }, f = fixture({ rules: [unrelated] });
  await f.request({ op: "set", tabId: 1, enabled: true });
  f.tabs[0].url = "https://elsewhere.test/"; f.listeners.updated(1, { url: f.tabs[0].url }); await f.flush(); assert.deepEqual(f.rules(), [unrelated]);
  await f.request({ op: "set", tabId: 1, enabled: true }); f.listeners.replaced(10, 1); await f.flush(); assert.deepEqual(f.rules(), [unrelated]);
  await f.request({ op: "set", tabId: 2, enabled: true }); f.listeners.removed(2); await f.flush(); assert.deepEqual(f.rules(), [unrelated]);
});
test("worker startup retains valid session rules and removes orphaned rules without restoring after restart", async () => {
  const f = fixture(); await f.request({ op: "set", tabId: 1, enabled: true });
  const resumed = fixture({ data: f.data, rules: f.rules() }); await resumed.flush(); assert.equal(resumed.rules().length, 1);
  const orphaned = fixture({ rules: f.rules() }); await orphaned.flush(); assert.equal(orphaned.rules().length, 0);
  const restarted = fixture({ data: f.data }); await restarted.flush(); assert.deepEqual(restarted.data.ki_csp_tabs, {});
});
test("reenabling a tab cannot take a rule ID reused by another tab", async () => {
  const f = fixture(); await f.request({ op: "set", tabId: 1, enabled: true }); await f.request({ op: "set", tabId: 1, enabled: false });
  await f.request({ op: "set", tabId: 2, enabled: true }); await f.request({ op: "set", tabId: 1, enabled: true });
  assert.equal(f.rules().length, 2); assert.equal(new Set(f.rules().map(rule => rule.id)).size, 2);
  assert.deepEqual(f.rules().map(rule => rule.condition.tabIds[0]).sort(), [1, 2]);
  assert.equal((await f.request({ op: "status" })).result.tabs.filter(tab => tab.enabled).length, 2);
});
test("failures preserve previous state; invalid arguments and untrusted senders are rejected", async () => {
  const f = fixture(); await f.flush(); f.failRules(); assert.equal((await f.request({ op: "set", tabId: 1, enabled: true })).ok, false); assert.equal(f.rules().length, 0);
  f.failStorage(); assert.equal((await f.request({ op: "set", tabId: 1, enabled: true })).ok, false); assert.equal(f.rules().length, 0);
  await f.request({ op: "set", tabId: 1, enabled: true }); f.failStorage(); assert.equal((await f.request({ op: "set", tabId: 1, enabled: false })).ok, false); assert.equal(f.rules().length, 1);
  for (const tabId of [-1, "1", 1.2]) assert.equal((await f.request({ op: "set", tabId, enabled: true })).ok, false);
  assert.equal((await f.request({ op: "set", tabId: 1, enabled: "true" })).ok, false);
  for (const url of ["https://example.com", "chrome-extension://test/content.html", "chrome-extension://test/providers/providers.html#forged"]) assert.equal((await f.request({ op: "set", tabId: 1, enabled: true }, { id: "test", url })).ok, false);
  assert.equal((await f.request({ op: "status" }, { id: "other", url: "chrome-extension://test/providers/providers.html" })).ok, false);
  f.tabs[0].pendingUrl = "https://other.test/"; assert.equal((await f.request({ op: "set", tabId: 1, enabled: true })).ok, false);
});

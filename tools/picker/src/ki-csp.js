// Manual, session-only CSP response-header controls. Never enabled by a profile.
var KI_CSP_KEY = "ki_csp_tabs", KI_CSP_FIRST = 830000001, KI_CSP_LAST = 830010000;
var kiCspQueue = Promise.resolve();
function kiCspWrite(action) { const result = kiCspQueue.then(action); kiCspQueue = result.catch(() => {}); return result; }
function kiCspOrigin(value) { try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.origin : null; } catch { return null; } }
function kiCspOwned(rule) { return rule.id >= KI_CSP_FIRST && rule.id <= KI_CSP_LAST; }
function kiCspRule(id, tabId, origin) {
  return { id, priority: 1, action: { type: "modifyHeaders", responseHeaders: ["content-security-policy", "content-security-policy-report-only", "x-webkit-csp", "x-content-security-policy", "x-content-security-policy-report-only", "x-webkit-csp-report-only"].map(header => ({ operation: "remove", header })) },
    condition: { tabIds: [tabId], urlFilter: "|" + origin + "/", isUrlFilterCaseSensitive: true, resourceTypes: ["main_frame", "sub_frame"] } };
}
async function kiCspData() { return (await chrome.storage.session.get(KI_CSP_KEY))[KI_CSP_KEY] || {}; }
async function kiCspSave(data) { await chrome.storage.session.set({ [KI_CSP_KEY]: data }); }
async function kiCspReconcile() {
  const data = await kiCspData(), rules = (await chrome.declarativeNetRequest.getSessionRules()).filter(kiCspOwned), tabs = await chrome.tabs.query({});
  const remove = [], kept = {};
  for (const rule of rules) {
    const entry = Object.values(data).find(item => item.enabled && item.ruleId === rule.id), tab = tabs.find(item => item.id === entry?.tabId);
    if (!entry || !tab || kiCspOrigin(tab.pendingUrl || tab.url) !== entry.origin || JSON.stringify(rule.condition.tabIds) !== JSON.stringify([entry.tabId]) || rule.condition.urlFilter !== "|" + entry.origin + "/") remove.push(rule.id);
    else kept[entry.tabId] = entry;
  }
  for (const entry of Object.values(data)) if (!entry.enabled && entry.needsReload && tabs.some(tab => tab.id === entry.tabId && kiCspOrigin(tab.pendingUrl || tab.url) === entry.origin)) kept[entry.tabId] = entry;
  if (remove.length) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: remove });
  if (JSON.stringify(data) !== JSON.stringify(kept)) await kiCspSave(kept); return kept;
}
async function kiCspTabs() {
  const data = await kiCspReconcile();
  return (await chrome.tabs.query({})).filter(tab => kiCspOrigin(tab.url)).map(tab => ({ tabId: tab.id, title: tab.title || tab.url, url: tab.url, origin: kiCspOrigin(tab.url), active: !!tab.active, enabled: !!data[tab.id]?.enabled, needsReload: !!data[tab.id]?.needsReload }));
}
async function kiCspSet(tabId, enabled) {
  if (!Number.isInteger(tabId) || tabId < 0 || typeof enabled !== "boolean") throw Error("Choose a tab and an on/off state.");
  const tab = await chrome.tabs.get(tabId), origin = kiCspOrigin(tab.url);
  if (!origin || tab.status === "loading" || (tab.pendingUrl && kiCspOrigin(tab.pendingUrl) !== origin)) throw Error("Choose a loaded HTTP or HTTPS page.");
  const data = await kiCspReconcile(), previous = data[tabId];
  if (!!previous?.enabled === enabled) return (await kiCspTabs()).find(item => item.tabId === tabId);
  const rules = await chrome.declarativeNetRequest.getSessionRules(), used = new Set(rules.map(rule => rule.id));
  let ruleId = previous?.enabled ? previous.ruleId : undefined;
  if (enabled && !ruleId) { ruleId = KI_CSP_FIRST; while (used.has(ruleId) && ruleId <= KI_CSP_LAST) ruleId++; if (ruleId > KI_CSP_LAST) throw Error("Too many CSP tab controls are active."); }
  const oldRule = previous?.enabled ? rules.find(rule => rule.id === previous.ruleId) : undefined;
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: oldRule ? [oldRule.id] : [], addRules: enabled ? [kiCspRule(ruleId, tabId, origin)] : [] });
  data[tabId] = { tabId, origin, ...(enabled ? { ruleId } : {}), enabled, needsReload: true };
  try { await kiCspSave(data); }
  catch (error) {
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: enabled ? [ruleId] : [], addRules: oldRule ? [oldRule] : [] });
    throw error;
  }
  return (await kiCspTabs()).find(item => item.tabId === tabId);
}
async function kiCspClear(tabId) {
  const data = await kiCspData(), rules = await chrome.declarativeNetRequest.getSessionRules();
  const ids = rules.filter(rule => kiCspOwned(rule) && rule.condition.tabIds?.includes(tabId)).map(rule => rule.id);
  if (ids.length) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids });
  delete data[tabId]; await kiCspSave(data);
}
async function kiCspReload(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) throw Error("Choose a tab to reload.");
  const tabs = await kiCspTabs(), tab = tabs.find(item => item.tabId === tabId);
  if (!tab) throw Error("Choose an HTTP or HTTPS page.");
  await chrome.tabs.reload(tabId, { bypassCache: true }); return tab;
}
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== "KI_CSP") return;
  const allowed = ["pages/sidepanel.html", "providers/providers.html"].map(path => chrome.runtime.getURL(path));
  if (sender.id !== chrome.runtime.id || !allowed.includes(sender.url?.split("?")[0])) { reply({ ok: false, error: "Open cert-x settings to change CSP controls." }); return; }
  kiCspWrite(async () => {
    if (message.op === "tabs") return kiCspTabs();
    if (message.op === "status") { const tabs = await kiCspTabs(); return { tabs: tabs.filter(tab => tab.enabled || tab.needsReload), selected: tabs.find(tab => tab.tabId === message.tabId) || null }; }
    if (message.op === "set") return kiCspSet(message.tabId, message.enabled);
    if (message.op === "reload") return kiCspReload(message.tabId);
    throw Error("Unknown CSP operation.");
  }).then(result => reply({ ok: true, result }), error => reply({ ok: false, error: error.message })); return true;
});
chrome.tabs.onRemoved.addListener(tabId => { void kiCspWrite(() => kiCspClear(tabId)).catch(() => {}); });
chrome.tabs.onReplaced.addListener((_added, removed) => { void kiCspWrite(() => kiCspClear(removed)).catch(() => {}); });
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (!change.url) return;
  void kiCspWrite(async () => { const entry = (await kiCspData())[tabId]; if (entry && kiCspOrigin(change.url) !== entry.origin) await kiCspClear(tabId); }).catch(() => {});
});
chrome.webNavigation.onCommitted.addListener(event => {
  if (event.frameId !== 0) return;
  void kiCspWrite(async () => {
    const data = await kiCspData(), entry = data[event.tabId]; if (!entry) return;
    if (kiCspOrigin(event.url) !== entry.origin) return kiCspClear(event.tabId);
    if (entry.enabled) entry.needsReload = false; else delete data[event.tabId];
    await kiCspSave(data);
  }).catch(() => {});
});
void kiCspWrite(kiCspReconcile).catch(() => {});

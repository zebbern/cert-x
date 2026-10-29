// Retained tool aliases and history. All new execution belongs to the native
// security service; there is no page bridge or separate extension connection.
var KI_PTK_KEY = 'ki_ptk_scans', kiPtkCache = [], kiPtkLocks = new Map();
var kiPtkActive = new Set(['starting', 'running', 'stopping', 'unknown']);
var kiPtkNames = { check: 'ptk_check', start: 'ptk_start_scan', status: 'ptk_scan_status', stop: 'ptk_stop_scan', extend: 'ptk_extend_scan', findings: 'ptk_get_findings', export: 'ptk_export_report' };
function kiPtkOwner(session) { if (typeof session !== 'string' || !session || session.length > 150) throw Error('Choose a chat before using security testing.'); return kiWorkspaceOwner(session); }
function kiPtkOrigin(url) { try { const parsed = new URL(url); return /^https?:$/.test(parsed.protocol) ? parsed.origin : null; } catch { return null; } }
function kiPtkRoute(url) { try { const value = new URL(url); return value.origin + value.pathname; } catch { return ''; } }
function kiPtkLock(key, operation) { const task = (kiPtkLocks.get(key) || Promise.resolve()).catch(() => {}).then(operation); kiPtkLocks.set(key, task); task.finally(() => { if (kiPtkLocks.get(key) === task) kiPtkLocks.delete(key); }).catch(() => {}); return task; }
function kiPtkMeta(name) {
  const labels = { ptk_check: 'Check security runtime', ptk_start_scan: 'Start security analysis', ptk_scan_status: 'Read security progress', ptk_stop_scan: 'Stop security testing', ptk_extend_scan: 'Extend observation', ptk_get_findings: 'Read security findings', ptk_export_report: 'Export security report' };
  const canonical = { ptk_check: 'security_capabilities', ptk_start_scan: 'security_start_scan', ptk_scan_status: 'security_scan_status', ptk_stop_scan: 'security_stop_scan', ptk_get_findings: 'security_get_findings', ptk_export_report: 'security_export_report', ptk_extend_scan: 'security_start_scan' };
  return { id: 'ptk:' + name, name, family: 'ptk', group: 'ptk', label: labels[name] || name, aliases: canonical[name] ? ['ptk:' + canonical[name]] : [], securityStop: name === 'ptk_stop_scan', defaultAsk: ['ptk_start_scan', 'ptk_extend_scan', 'ptk_export_report'].includes(name) };
}
function kiPtkHasScans(session) { return kiPtkCache.some(scan => scan.owner === kiWorkspaceOwner(session)); }
function kiPtkHealth(session) { return { native: true, readiness: 'Security testing is included in cert-x. Use security_capabilities for engine readiness and available modules.', history: kiPtkCache.filter(scan => !session || scan.owner === kiWorkspaceOwner(session)).map(({ scanId, state, engines, error }) => ({ scanId, state, engines, error })) }; }
async function kiPtkLoad() { await kiPtkReady; return kiPtkCache; }
async function kiPtkTab(tabId, session) {
  if (tabId == null && typeof Tt === 'function') tabId = Tt(session)?.primaryTabId;
  if (!Number.isInteger(tabId) || tabId < 0) throw Error('Choose an HTTP or HTTPS target tab.');
  const tab = await chrome.tabs.get(tabId), origin = kiPtkOrigin(tab.url);
  if (!origin || tab.status === 'loading' || tab.pendingUrl && kiPtkOrigin(tab.pendingUrl) !== origin) throw Error('Wait for the target page to finish loading.');
  return { tabId, origin, url: tab.url, title: String(tab.title || tab.url).slice(0, 300) };
}
async function kiPtkBridge() { throw Error('This record belongs to the earlier companion runtime. Live evidence is unavailable; saved reports remain in Outputs.'); }
async function kiPtkActivity(session, meta, args, result, timing = {}) {
  if (!globalThis.certXSecurity || meta?.family !== 'browser' || /^(get_|list_|read_|snapshot|screenshot|inspect_|find|highlight|clear_highlight|save_|agent$)/.test(meta.name)) return;
  const tabId = Number.isInteger(timing.tabId) ? timing.tabId : Number.isInteger(args?.tab) ? args.tab : Number.isInteger(args?.tabId) ? args.tabId : typeof Tt === 'function' ? Tt(session)?.primaryTabId : null;
  if (!Number.isInteger(tabId)) return;
  let tab; try { tab = await chrome.tabs.get(tabId); } catch { return; }
  const action = { id: crypto.randomUUID(), tool: String(meta.name).slice(0, 100), label: String(meta.label || meta.name).slice(0, 100), route: kiPtkRoute(tab.url), startedAt: timing.startedAt || Date.now(), endedAt: timing.endedAt || Date.now(), outcome: result?.isError ? 'error' : 'completed' };
  await globalThis.certXSecurity.handle('activity', { tabId, action }, { owner: kiPtkOwner(session) });
}
async function kiPtkDownload(name, data, mime, signal) {
  signal?.throwIfAborted(); const downloadId = await chrome.downloads.download({ url: 'data:' + mime + ';base64,' + data, filename: name, conflictAction: 'uniquify', saveAs: false }), deadline = Date.now() + 20000;
  try {
    while (Date.now() < deadline) { signal?.throwIfAborted(); const item = (await chrome.downloads.search({ id: downloadId }))[0]; if (item?.state === 'complete') return downloadId; if (!item || item.state === 'interrupted') throw Error('Report download failed: ' + (item?.error || 'download unavailable')); await new Promise(resolve => setTimeout(resolve, 150)); }
    throw Error('Report download completion is unconfirmed. Check Downloads before retrying.');
  } catch (error) { await chrome.downloads.cancel?.(downloadId)?.catch(() => {}); throw error; }
}
async function kiPtkOperate(op, args, session, signal, recheck) {
  if (!globalThis.certXSecurity) throw Error('The integrated security runtime is unavailable. Reload cert-x.');
  if (op === 'check') { const tab = await kiPtkTab(args.tabId, session), capabilities = await kiSecurityHealth(session); return { ...tab, version: capabilities.version || '10.0.0', ready: capabilities.ready !== false, automationEnabled: true, blockers: capabilities.error ? [capabilities.error] : [], native: true }; }
  if (op === 'start') {
    if (!Number.isInteger(args.tabId) || typeof args.expectedOrigin !== 'string') throw Error('Start requires tabId and expectedOrigin.');
    const engines = args.engines || ['SAST', 'SCA'];
    if (!Array.isArray(engines) || !engines.length || engines.some(engine => !['SAST', 'SCA', 'IAST'].includes(engine)) || engines.includes('IAST') && engines.length !== 1) throw Error('This legacy alias supports SAST/SCA or IAST alone. Use security_start_scan for full native engine selection.');
    const result = await kiSecurityOperate('start', { tabId: args.tabId, expectedOrigin: args.expectedOrigin, engines, options: { durationSeconds: args.durationSeconds ?? (engines.includes('IAST') ? 600 : 60) } }, session, signal, recheck);
    return { ...result, scanId: result.runId, mode: engines.includes('IAST') ? 'observe' : 'analyze' };
  }
  if (['status', 'stop', 'findings', 'export', 'extend'].includes(op)) {
    await kiPtkLoad(); const historical = kiPtkCache.find(scan => scan.scanId === args.scanId && scan.owner === kiPtkOwner(session));
    if (historical) { if (op === 'status') return { ...historical, historical: true }; return kiPtkBridge(); }
    const result = await kiSecurityOperate(op, { runId: args.scanId, limit: args.limit, changesOnly: args.changesOnly, durationSeconds: args.durationSeconds ?? 300 }, session, signal, recheck); return { ...result, scanId: args.scanId };
  }
  throw Error('Unknown security operation.');
}
function kiPtkToolDefs(session) {
  return Object.entries(kiPtkNames).map(([op, name]) => ({ name, kiPolicyMeta: kiPtkMeta(name), description: 'Compatibility alias for native security testing. New tasks use the security_* tools.', parameters: { type: 'object', properties: { tabId: { type: 'integer' }, expectedOrigin: { type: 'string' }, engines: { type: 'array', items: { type: 'string', enum: ['SAST', 'SCA', 'IAST'] } }, durationSeconds: { type: 'number', exclusiveMinimum: 0 }, scanId: { type: 'string' }, limit: { type: 'integer', minimum: 1, maximum: 500 }, changesOnly: { type: 'boolean' } }, additionalProperties: false }, resolveExecution(args) { return { approvalRule: 'allow', async execute(context) {
    try { const recheck = async () => { if (context[KI_POLICY_CONTEXT]) await kiPolicyRecheck(context[KI_POLICY_CONTEXT]); }; const result = await kiPtkOperate(op, args, session, context.signal, recheck); return { output: JSON.stringify(result), ...(['error', 'interrupted', 'unknown'].includes(result?.state) ? { isError: true } : {}) }; }
    catch (error) { return { output: JSON.stringify({ error: error.message, ...(error.runId ? { scanId: error.runId } : {}) }), isError: true }; }
  } }; } }));
}
var kiPtkReady = (async () => {
  kiPtkCache = (await chrome.storage.local.get(KI_PTK_KEY))[KI_PTK_KEY] || [];
  let changed = false;
  for (const scan of kiPtkCache) if (kiPtkActive.has(scan.state)) { changed = true; scan.state = 'interrupted'; scan.historical = true; scan.error = 'This run used the earlier companion runtime. Saved reports remain in Outputs; it will not be replayed.'; }
  if (changed) await chrome.storage.local.set({ [KI_PTK_KEY]: kiPtkCache });
})();
kiPtkReady.catch(error => console.warn('[security] History could not load:', error.message));
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== 'KI_PTK') return;
  const allowed = ['pages/sidepanel.html', 'providers/providers.html'].map(file => chrome.runtime.getURL(file));
  if (sender.id !== chrome.runtime.id || !allowed.includes(sender.url?.split('?')[0])) { reply({ ok: false, error: 'Open cert-x to use security testing.' }); return; }
  (async () => { try {
    await kiPtkLoad(); let result;
    if (message.op === 'state') { const state = message.session ? await kiSecurityOperate('state', {}, message.session) : { runs: [] }; result = { scans: [...state.runs.map(run => ({ ...run, scanId: run.runId })), ...kiPtkCache.filter(scan => !message.session || scan.owner === kiPtkOwner(message.session))] }; }
    else if (message.op === 'tabs') result = await kiSecurityTabs(message.session);
    else {
      const name = kiPtkNames[message.op]; if (!name) throw Error('Unknown security operation.');
      const recheck = async () => { if (message.op === 'stop') return; const meta = kiPtkMeta(name), policy = await kiPolicyState(meta), context = message.session && typeof kiContextResolve === 'function' ? await kiContextResolve(message.session) : null; if (!policy.parentEnabled || (context ? kiContextRule(meta, context, policy.rule) : policy.rule) === 'disabled') throw Error('This operation is disabled by the selected profile or Tools & permissions.'); };
      await recheck(); result = await kiPtkOperate(message.op, message, message.session, undefined, recheck);
    }
    reply({ ok: true, result });
  } catch (error) { reply({ ok: false, error: error.message, ...(error.runId ? { scanId: error.runId } : {}) }); } })(); return true;
});

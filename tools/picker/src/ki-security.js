// Native security tools use the same chat ownership, profiles and permissions as
// browser tools. The engine service lives only in the extension worker.
var KI_SECURITY_REGISTRY = [
  { name: 'security_capabilities', op: 'capabilities', legacy: 'ptk_check', label: 'Security capabilities', description: 'Read compact installed-engine/module readiness and effective settings. Pass tool:"security_tool_name" for one exact operation schema, or detail:"full" only when full provenance and verification metadata is needed.' },
  { name: 'security_list_runs', op: 'runs', label: 'List security runs', description: 'Recover paginated security run references owned by this chat. Use a scan runId for findings, candidates and evidence packages; native sessionId/runtimeId values are not public run references.' },
  { name: 'security_start_scan', op: 'start', legacy: 'ptk_start_scan', label: 'Start security testing', ask: true, description: 'Run the installed DAST, IAST, SAST or SCA engines on a target tab. Pass the integer tabId from list_browser_tabs. The result includes a scoped route/form inventory of the selected page, not tested coverage; use it to plan distinct workflows. Thorough DAST seeds captured GET requests or the selected page; PTK defaults waits for qualifying browser interaction. Submit POST forms using their declared method while the scan runs; query-string navigation does not exercise a POST input. Inspect application capture, task execution, scan request dispatches, errors and skips before assessing results. A successful start is not completion or a clean verdict. Configure native engine options per run, then stop to drain results. Do not repeat an unchanged failed call: follow its recovery guidance. If an error includes a runId, inspect that run before starting another.' },
  { name: 'security_scan_status', op: 'status', legacy: 'ptk_scan_status', label: 'Read security progress', description: 'Read a security run owned by this chat, including effective settings, coverage, engine readiness and partial failures. Set waitForIdle:true with optional timeoutMs (up to 30000) to await the current DAST queue without browser-page waits or repeated model calls. An idle queue does not mean the whole application was tested; a wait timeout does not stop or complete the scan. Follow coverage.actionableGaps recovery guidance and retain unresolved gaps in the report.' },
  { name: 'security_stop_scan', op: 'stop', legacy: 'ptk_stop_scan', label: 'Stop security testing', stop: true, description: 'Stop this chat’s security run and drain retained evidence. Remains available after tools are disabled. Check terminal status before claiming completion.' },
  { name: 'security_get_findings', op: 'findings', legacy: 'ptk_get_findings', label: 'Read security findings', description: 'Read paginated findings with native evidence and coverage. Scanner findings require independent reproduction and impact assessment.' },
  { name: 'security_get_evidence', op: 'evidence', legacy: 'ptk_get_findings', label: 'Inspect security evidence', description: 'Inspect a finding or retained engine evidence from this chat’s security run. Preserve evidence and distinguish observations from confirmed impact.' },
  { name: 'security_export_report', op: 'export', legacy: 'ptk_export_report', label: 'Export security report', ask: true, description: 'Export a security run, findings, evidence and effective configuration to a downloadable artifact in this chat’s Outputs.' },
  { name: 'security_capture', op: 'execute', capability: 'capture', legacy: 'ptk_capture_requests', label: 'Capture requests', ask: true, description: 'Start or stop request capture on the selected target tab. Use captured requests to plan scans or replay.' },
  { name: 'security_list_requests', op: 'execute', capability: 'listRequests', legacy: 'ptk_list_requests', label: 'Read captured requests', description: 'Read captured traffic for the selected tab through the owned security runtime.' },
  { name: 'security_replay_request', op: 'execute', capability: 'replay', legacy: 'ptk_run_dast', label: 'Replay a request', ask: true, description: 'Replay a request through the native request engine, preserving headers, method, body and configured redirect behavior. Use explicit account references when required.' },
  { name: 'security_macro', op: 'execute', capability: 'macro', label: 'Record or replay a workflow', ask: true, description: 'Record, list, import, export or replay a browser workflow using the installed macro engine. Discover supported actions with security_capabilities.' },
  { name: 'security_utility', op: 'execute', capability: 'utility', label: 'Use security utilities', ask: true, description: 'Use installed JWT, encoder/decoder, reconnaissance, cookie/session and port-check utilities. Cookie block/readonly policies retain their explicitly authorized effects until cleared or paused by changed permissions/scope. Discover exact supported actions and prerequisites first; browser timing observations are not proof of an open port.' },
  { name: 'security_clear_cookie_policy', op: 'clear_cookie_policy', label: 'Clear cookie policy', stop: true, description: 'Clear one cookie block/readonly policy owned by this chat. This stops future automatic effects and remains available after permissions or workspace scope change. It does not delete or restore browser cookies.' },
  { name: 'security_import', op: 'execute', capability: 'import', label: 'Import security data', ask: true, description: 'Import supported local security data through the installed engine. Supply the format and data; discover supported formats first.' },
  { name: 'security_export', op: 'execute', capability: 'export', label: 'Export security data', ask: true, description: 'Export engine data using an advertised format. For chat-owned scan reports prefer security_export_report.' },
  { name: 'security_candidates', op: 'execute', capability: 'candidate', label: 'Investigate security candidates', ask: true, description: 'List, inspect, reproduce or compare candidates from an owned scan. Use the original runId and candidateId; preserve observations separately from confirmed evidence.' },
  { name: 'security_evidence_package', op: 'execute', capability: 'evidencePackage', label: 'Prepare security evidence', ask: true, description: 'Create, inspect, draft or export an evidence package from this chat’s original scan and candidate references.' },
  { name: 'security_api', op: 'execute', capability: 'api', label: 'Test API operations', ask: true, description: 'Import supplied API descriptions, inspect operations, prepare concrete requests, and execute owned plans. Use returned specRef and planRef identifiers.' },
  { name: 'security_browser', op: 'execute', capability: 'browser', label: 'Use an isolated testing browser', ask: true, local: true, description: 'Create, navigate, sign in, inspect or close an isolated local browser session. Requires an enabled local runtime; installation is a user settings action.' },
  { name: 'security_raw', op: 'execute', capability: 'raw', label: 'Test raw network traffic', ask: true, local: true, description: 'Send exact HTTP/1, structured or frame-level HTTP/2, or WebSocket traffic through the local runtime. Decoded wire routes and connection targets must be in scope; unknown routing is rejected. Explicit desync probes require paired controls and repeated backend observation or controlled response queues. Timing alone does not confirm a vulnerability. Read large or partial evidence using action:evidence and the original runId.' },
  { name: 'security_oast', op: 'execute', capability: 'oast', label: 'Use callback testing', ask: true, local: true, description: 'Create callback payloads, run explicit target probes, and inspect correlated events using the selected saved callback connection. A payload or local request is not confirmation of a server-side callback.' },
  { name: 'security_zap', op: 'execute', capability: 'zap', label: 'Use ZAP testing', ask: true, local: true, description: 'Use the configured local ZAP runtime for scoped testing and inspect its progress and evidence. Discover readiness first; software installation is a user settings action.' },
];
var KI_SECURITY_INTEGRATIONS = 'ki_security_integrations', KI_SECURITY_OAST_GRANT = Symbol('Callback provider run grant');
var KI_SECURITY_OAST_METHODS = { status: ['server_status'], create: ['configure_webhook', 'get_webhook_info'], probe: [], events: ['get_webhook_requests', 'get_request'], wait: ['wait_for_request', 'get_webhook_requests', 'get_request'], stop: [], cleanup: ['delete_webhook'], export: [] };
async function kiSecurityIntegrations() {
  const value = (await chrome.storage.local.get(KI_SECURITY_INTEGRATIONS))[KI_SECURITY_INTEGRATIONS] || {};
  return { version: 1, oastConnectionId: typeof value.oastConnectionId === 'string' ? value.oastConnectionId : null, browserBackend: value.browserBackend === 'local' ? 'local' : 'extension', zapEnabled: value.zapEnabled === true };
}
async function kiSecurityConnection(required = true) {
  const selected = await kiSecurityIntegrations(), settings = await kiNativeSettings();
  if (!selected.oastConnectionId) { if (!required) return null; throw Error('Choose a callback connection in Security testing settings.'); }
  const connection = settings.servers.find(server => server.id === selected.oastConnectionId);
  if (!connection) { if (!required) return null; throw Error('The selected callback connection is missing. Choose an available connection in settings.'); }
  return JSON.parse(JSON.stringify(connection));
}
async function kiSecurityProviderPermission(connection, name, context) {
  const meta = { ...await kiPolicyMcpMeta(connection, name, 'local'), parentGroups: ['local', 'mcp'] }, state = await kiPolicyState(meta);
  const task = await kiContextResolve(context.session || context.owner);
  // Selecting a callback backend does not expose its generic MCP tools. It only
  // bypasses that visibility list; explicit capability/permission rules still apply.
  const rule = kiContextRule(meta, { ...task, mcp: null }, state.rule);
  if (!state.parentEnabled || rule === 'disabled') throw Error('Callback provider operation ' + name + ' is disabled in Tools & permissions or this profile.');
  return { rule, fullAccess: state.fullAccess };
}
async function kiSecurityOastGrant(action, args, context) {
  const connection = context.connectionSnapshot || context.oastConnection || await kiSecurityConnection();
  if (['oast.stop', 'oast.cleanup'].includes(action)) return connection;
  const actions = context.oastActions || [action.slice('oast.'.length)];
  const names = [...new Set(actions.flatMap(name => KI_SECURITY_OAST_METHODS[name] || []))];
  let grant = context[KI_SECURITY_OAST_GRANT];
  const added = names.filter(name => !grant?.names.has(name));
  if (!grant || added.length) {
    const states = await Promise.all((grant ? added : names).map(name => kiSecurityProviderPermission(connection, name, context)));
    // A prior action's approval does not authorize additional provider methods.
    const currentApproval = grant ? context.currentActionApproval : { approved: context.permissionApproved, userAction: context.userAction };
    let approved = currentApproval?.approved === true || currentApproval?.userAction === true;
    if (!approved && states.some(state => state.rule === 'ask' || state.rule === 'inherit' && !state.fullAccess)) {
      const decision = await KN.request({ local: true, policyPrompt: true, policyExplicit: states.some(state => state.rule === 'ask'), domain: connection.label || 'Callbacks', action: 'tool', toolCallId: context.toolCallId || 'security-provider-' + context.runId, toolName: 'security_oast', session: context.session || context.owner, preview: { text: (connection.label || 'Callbacks') + '\n' + action + '\nProvider operations: ' + names.join(', ') + '\n' + JSON.stringify(args || {}, null, 2) } }, context.signal);
      if (decision !== 'allow_once') throw Error('Callback operation denied by user.'); approved = true;
    }
    grant = { approvedNames: new Set([...(grant?.approvedNames || []), ...(approved ? added : [])]), names: new Set([...(grant?.names || []), ...names]) }; context[KI_SECURITY_OAST_GRANT] = grant;
    if (approved) context.permissionApproved = true;
  }
  context.connectionId = connection.id; context.connectionSnapshot = JSON.parse(JSON.stringify(connection));
  context.providerRecheck = async request => {
    const name = request.toolName || request.mcpTool;
    if (request.connectionId !== connection.id || !grant.names.has(name)) throw Error('The callback provider operation was not authorized for this run.');
    const latest = await kiSecurityProviderPermission(connection, name, context);
    if ((latest.rule === 'ask' || latest.rule === 'inherit' && !latest.fullAccess) && !grant.approvedNames.has(name)) throw Error('Callback permissions changed. Start a new operation for approval.');
  };
  return connection;
}
async function kiSecurityRegisterConnection(connection) {
  if (!connection || typeof connection.id !== 'string' || !connection.id || typeof connection.command !== 'string' || !connection.command) throw Error('The local runtime did not return a saved callback connection.');
  const descriptor = { id: connection.id, label: String(connection.label || 'Callbacks'), command: connection.command, args: Array.isArray(connection.args) ? connection.args : [], ...(connection.cwd ? { cwd: connection.cwd } : {}), ...(connection.envFileRef ? { envFileRef: connection.envFileRef } : {}), ...(connection.secretRef ? { secretRef: connection.secretRef } : {}), managedBy: 'cert-x-security' };
  const saved = (await chrome.storage.local.get(KI_NATIVE_KEY))[KI_NATIVE_KEY] || {}, servers = Array.isArray(saved.servers) ? saved.servers.slice() : [], index = servers.findIndex(server => server.id === descriptor.id);
  if (index < 0 && servers.length >= 8) throw Error('The local server list is full. Remove an unused server before connecting callbacks.');
  if (index < 0) servers.push(descriptor); else servers[index] = descriptor;
  await chrome.storage.local.set({ [KI_NATIVE_KEY]: { ...saved, servers }, [KI_SECURITY_INTEGRATIONS]: { ...await kiSecurityIntegrations(), oastConnectionId: descriptor.id } });
  return descriptor;
}
function kiSecurityService() { if (!globalThis.certXSecurity) throw Error('The integrated security runtime is unavailable. Reload cert-x and check Capability health.'); return globalThis.certXSecurity; }
function kiSecurityInputError(message, code = 'invalid_target_tab', recovery = 'Call list_browser_tabs and supply an available HTTP(S) tab as integer tabId. Do not retry unchanged arguments.') {
  return Object.assign(Error(message), { code, retryable: false, recovery });
}
function kiSecurityTabId(value) {
  // Model providers sometimes stringify integer arguments. Accept decimal IDs,
  // never coercible objects, booleans, empty strings, floats or exponent syntax.
  const id = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isInteger(id) || id < 0 || id > 2147483647) throw kiSecurityInputError('Select a valid browser tab: tabId must be a non-negative integer.');
  return id;
}
function kiSecurityTargetArgs(args, session, required = false) {
  const result = { ...args }, nested = args.arguments && typeof args.arguments === 'object' && !Array.isArray(args.arguments) ? { ...args.arguments } : null;
  const values = [];
  for (const object of [result, nested]) if (object) {
    for (const key of ['tabId', 'tab']) if (Object.hasOwn(object, key)) values.push(kiSecurityTabId(object[key]));
  }
  if (!values.length && required) {
    const selected = typeof Tt === 'function' ? Tt(session)?.primaryTabId : undefined;
    if (selected != null) values.push(kiSecurityTabId(selected));
    else throw kiSecurityInputError('No target tab was supplied or selected.');
  }
  if (values.some(id => id !== values[0])) throw kiSecurityInputError('Conflicting target tab IDs. Supply one tabId for this operation.');
  if (values.length) {
    result.tabId = values[0];
    if (nested && (Object.hasOwn(nested, 'tabId') || Object.hasOwn(nested, 'tab'))) nested.tabId = values[0];
  }
  delete result.tab;
  if (nested) { delete nested.tab; result.arguments = nested; }
  return result;
}
async function kiSecurityTargetTab(tabId) {
  let tab;
  try { tab = await chrome.tabs.get(kiSecurityTabId(tabId)); }
  catch (error) {
    if (error.code === 'invalid_target_tab') throw error;
    throw kiSecurityInputError('The selected browser tab is unavailable. It may have closed or been replaced.', 'target_tab_unavailable');
  }
  if (!/^https?:\/\//.test(tab.url || '')) throw kiSecurityInputError('Select an HTTP(S) target tab.', 'target_tab_unsupported');
  return tab;
}
function kiSecurityErrorResult(error) {
  return { error: error.message, ...(error.runId ? { runId: error.runId } : {}), ...(error.code ? { code: error.code } : {}), ...(error.retryable === false ? { retryable: false, recovery: error.recovery } : {}) };
}
function kiSecurityOwner(session) { if (typeof session !== 'string' || !/^[a-zA-Z0-9_-]{1,150}$/.test(session)) throw Error('Choose a chat before using security testing.'); return kiWorkspaceOwner(session); }
function kiSecurityScopeAllows(value, scope) {
  let url; try { url = new URL(value); } catch { return false; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return false;
  const allowed = (scope?.origins || []).some(origin => {
    if (scope.matchMode !== 'host') return origin === url.origin;
    const base = new URL(origin);
    return url.hostname === base.hostname || scope.includeSubdomains === true && !base.hostname.startsWith('[') && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(base.hostname) && url.hostname.endsWith('.' + base.hostname);
  });
  if (!allowed || scope.also && !kiSecurityScopeAllows(value, scope.also)) return false;
  return !(scope.excludePaths || []).some(path => path === '/' || url.pathname === path || url.pathname.startsWith(path.replace(/\/$/, '') + '/'));
}
async function kiSecuritySurfaceMap(tabId, scope) {
  if (!chrome.scripting?.executeScript) return { available:false, reason:'Page inventory is unavailable in this browser.' };
  let timer;
  try {
    const result = await Promise.race([
      chrome.scripting.executeScript({ target:{ tabId }, world:'ISOLATED', func:() => ({
        url:location.href,
        links:Array.from(document.querySelectorAll('a[href],area[href]')).slice(0,200).map(link => link.href),
        linkCount:document.querySelectorAll('a[href],area[href]').length,
        forms:Array.from(document.forms).slice(0,50).map(form => ({ action:form.action, method:form.method.toUpperCase(),
          fields:Array.from(form.elements).filter(field => field.name).slice(0,30).map(field => ({ name:field.name, type:field.type || field.tagName.toLowerCase() })) })),
        formCount:document.forms.length
      }) }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Page inventory timed out.')), 2000); })
    ]);
    const page = result?.[0]?.result;
    if (!page || !kiSecurityScopeAllows(page.url, scope)) return { available:false, reason:'The selected document changed or is outside the run scope.' };
    const route = value => {
      let url; try { url = new URL(value, page.url); } catch { return null; }
      if (!kiSecurityScopeAllows(url.href, scope)) return null;
      return { url:url.origin + url.pathname, queryKeys:[...new Set(url.searchParams.keys())].slice(0,12) };
    };
    const links = [], seen = new Set();
    for (const value of page.links || []) {
      const candidate = route(value); if (!candidate) continue;
      const key = candidate.url + '?' + candidate.queryKeys.join('&');
      if (seen.has(key)) continue; seen.add(key); links.push(candidate); if (links.length >= 60) break;
    }
    const forms = (page.forms || []).map(form => ({ ...route(form.action), method:form.method,
      fields:form.fields.filter(field => typeof field.name === 'string' && field.name.length <= 200).slice(0,20) })).filter(form => form.url).slice(0,25);
    return { available:true, source:'selected_tab_dom', url:new URL(page.url).origin + new URL(page.url).pathname, links, forms,
      linksTruncated:page.linkCount > 200 || links.length >= 60, formsTruncated:page.formCount > 50 || forms.length >= 25,
      note:'This is a page inventory, not proof that these routes or inputs were tested. Form values were not read.' };
  } catch (error) { return { available:false, reason:error.message || 'Page inventory failed.' }; }
  finally { clearTimeout(timer); }
}
function kiSecuritySelectedScope(args, tab) {
  const input = args?.arguments || {};
  if (!tab && input.tool === 'portscan' && typeof input.host === 'string') {
    let host; try { host = new URL('http://' + input.host); } catch { return null; }
    if (host.hostname && !host.port && host.pathname === '/' && !host.username && !host.password && !host.search && !host.hash) return { origins: [host.origin], excludePaths: [], matchMode: 'host' };
    return null;
  }
  const value = tab?.url || input.request?.url || input.url || input.baseUrl || input.targetUrl || input.target;
  if (typeof value !== 'string') return null;
  let url; try { url = new URL(value); } catch { return null; }
  return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? { origins: [url.origin], excludePaths: [] } : null;
}
function kiSecurityMeta(spec, args = {}) {
  if (typeof spec === 'string') spec = KI_SECURITY_REGISTRY.find(item => item.name === spec) || { name: spec };
  const aliases = spec.legacy ? ['ptk:' + spec.legacy] : [];
  if (spec.op === 'start' && (args.engines || ['DAST']).includes('DAST')) aliases.push('ptk:ptk_run_dast');
  const action = args.arguments?.action;
  const read = ['list', 'get', 'describe', 'status', 'events'].includes(action);
  const cleanup = ['browser', 'oast', 'zap'].includes(spec.capability) && ['close', 'stop', 'cleanup', 'cancel'].includes(action);
  return { id: 'ptk:' + spec.name, name: spec.name, group: 'ptk', family: 'ptk', label: spec.label || spec.name, description: spec.description || '', defaultAsk: !!spec.ask && !read, aliases, securityStop: !!spec.stop || cleanup, ...(spec.local ? { transport: 'local', parentGroups: spec.capability === 'oast' ? ['local', 'mcp'] : ['local'] } : {}) };
}
async function kiSecurityContext(session, signal, recheck, userAction = false) {
  const owner = kiSecurityOwner(session), resolved = typeof kiContextResolve === 'function' ? await kiContextResolve(session) : null;
  const scope = resolved?.workspace?.dastScope || { origins: [], excludePaths: [] };
  const configuredScope = scope.origins?.length > 0;
  const result = { owner, session, workspaceId: resolved?.workspace?.id || null, scope, signal, recheck, userAction, budgetGroup: owner };
  result.integrations = await kiSecurityIntegrations(); result.oastConnection = await kiSecurityConnection(false);
  result.resolveConnection = async id => { const connection = (await kiNativeSettings()).servers.find(server => server.id === id); if (!connection) throw Error('The callback connection used by this run is no longer saved. Restore it to continue.'); return JSON.parse(JSON.stringify(connection)); };
  result.localExecute = async (action, args, execution) => {
    if (!execution?.runId || typeof execution.checkRequest !== 'function') throw Error('A local operation requires a resolved security run.');
    let input = args || {};
    if (action.startsWith('oast.')) { const connection = await kiSecurityOastGrant(action, input, execution); input = { ...input, connection }; }
    return kiNativeSecurityExecute(action, input, execution);
  };
  result.resolveAccount = async id => {
    await kiAuthzLoad(); const account = kiAuthzPrivate.accounts[id];
    if (!account || account.workspaceId !== result.workspaceId) throw Error('The saved account does not belong to this workspace.');
    if (account.verification?.verified !== true && account.verification?.state !== 'verified') throw Error('Verify this saved account before comparing it.');
    const revision = account.revision;
    return { ...kiAuthzWireAccount(account), host: account.origin, checkRevision: async () => { const current = kiAuthzPrivate.accounts[id]; if (!current || current.revision !== revision || current.workspaceId !== result.workspaceId) throw Error('The saved account changed. Start a new comparison.'); } };
  };
  result.scopeNow = async () => {
    const latest = typeof kiContextResolve === 'function' ? await kiContextResolve(session) : null;
    if ((latest?.workspace?.id || null) !== result.workspaceId) throw Error('The chat workspace changed while testing. Start a new run in the selected workspace.');
    if (configuredScope || latest?.workspace?.dastScope?.origins?.length) return latest?.workspace?.dastScope || { origins: [], excludePaths: [] };
    return result.scope;
  };
  return result;
}
async function kiSecurityTabs(session) {
  const current = typeof Tt === 'function' ? Tt(session)?.primaryTabId : null;
  return (await chrome.tabs.query({})).filter(tab => /^https?:\/\//.test(tab.url || '')).map(tab => ({ tabId: tab.id, title: tab.title || tab.url, url: tab.url, origin: new URL(tab.url).origin, working: tab.id === current, active: !!tab.active }));
}
async function kiSecurityHealth(session) {
  try { return await kiSecurityOperate('capabilities', {}, session); }
  catch (error) { return { ready: false, error: error.message }; }
}
var kiSecurityCapabilities = kiSecurityHealth;
async function kiSecurityLocalAvailability() {
  const settings = await kiNativeSettings(), configured = await kiSecurityIntegrations(), connection = await kiSecurityConnection(false);
  return { enabled: settings.enabled, readiness: 'not_checked', reason: settings.enabled ? 'Use Security testing → Local runtime & connections to check or set up components.' : 'Enable Local computer access before using managed browser, raw transport, callback or ZAP operations.', browserBackend: configured.browserBackend, zapSelected: configured.zapEnabled, callbackConnection: connection ? { id: connection.id, label: connection.label || connection.command, selectedForSecurity: true } : null, ...(configured.oastConnectionId && !connection ? { callbackUnavailable: 'Selected callback connection is no longer saved.' } : {}) };
}
function kiSecurityScopeKey(scope) { return JSON.stringify({ origins: [...new Set(scope?.origins || [])].sort(), excludePaths: [...new Set(scope?.excludePaths || [])].sort(), matchMode: scope?.matchMode || 'origin', includeSubdomains: scope?.includeSubdomains === true }); }
async function kiSecurityCookiePermission(owner) {
  const meta = kiSecurityMeta('security_utility'), task = await kiContextResolve(owner), state = await kiPolicyState(meta);
  const rule = kiContextRule(meta, task, state.rule), mode = (await chrome.storage.local.get('sidepanel_approval_mode')).sidepanel_approval_mode || 'approve_for_me';
  if (!state.parentEnabled || rule === 'disabled' || !kiContextAllows(meta, task)) throw Error('Cookie policy effects are disabled by the current profile or Tools & permissions.');
  return { task, rule, mode, fullAccess: state.fullAccess, approvalRequired: rule === 'ask' || rule === 'inherit' && !state.fullAccess };
}
async function kiSecurityCookieGrant(context, permissionLease) {
  const permission = await kiSecurityCookiePermission(context.owner);
  const approvedForAsk = context.userAction === true || permissionLease?.token === KI_POLICY_TOKEN && permissionLease.approved === true;
  if (permission.approvalRequired && !approvedForAsk) throw Error('Approve this cookie policy before enabling persistent effects.');
  await context.recheck?.();
  return { version: 1, owner: context.owner, workspaceId: context.workspaceId || null, scopeKey: kiSecurityScopeKey(context.scope), configuredScope: !!permission.task.workspace?.dastScope?.origins?.length,
    rule: permission.rule, mode: permission.mode, fullAccess: permission.fullAccess, approvalRequired: permission.approvalRequired, approvedForAsk, createdAt: Date.now() };
}
async function kiSecurityCookiePolicyContext(record) {
  const grant = record?.grant;
  if (!grant || grant.version !== 1 || grant.owner !== record.owner || (grant.workspaceId || null) !== (record.workspaceId || null) || grant.scopeKey !== kiSecurityScopeKey(record.scope)) throw Error('This cookie policy requires a fresh explicit grant.');
  const validate = async () => {
    const permission = await kiSecurityCookiePermission(record.owner), workspaceId = permission.task.workspace?.id || null;
    if (workspaceId !== (record.workspaceId || null)) throw Error('The cookie policy owner moved to a different workspace.');
    if (permission.approvalRequired && (!grant.approvedForAsk || !grant.approvalRequired || permission.mode !== grant.mode || permission.rule !== grant.rule)) throw Error('Cookie policy permissions became stricter; approve the policy again.');
    const latest = permission.task.workspace?.dastScope;
    let scope = JSON.parse(JSON.stringify(record.scope));
    if (grant.configuredScope || latest?.origins?.length) {
      if (!latest?.origins?.length) throw Error('The cookie policy target is no longer in scope.');
      if (scope.matchMode === 'host' || latest?.matchMode === 'host') scope = { ...scope, also: latest || { origins: [], excludePaths: [] } };
      else scope = { origins: scope.origins.filter(origin => (latest?.origins || []).includes(origin)), excludePaths: [...new Set([...(scope.excludePaths || []), ...(latest?.excludePaths || [])])] };
    }
    if (!scope.origins.length) throw Error('The cookie policy target is no longer in scope.');
    return { owner: record.owner, workspaceId, scope };
  };
  const current = await validate();
  return { ...current, async recheck() { const next = await validate(); Object.keys(current.scope).forEach(key => delete current.scope[key]); Object.assign(current.scope, next.scope); } };
}
globalThis.certXSecurityCookiePolicyContext = kiSecurityCookiePolicyContext;
async function kiSecurityOperate(op, args, session, signal, recheck, userAction = false, permissionLease) {
  if (op === 'start' || op === 'execute') args = kiSecurityTargetArgs(args, session, op === 'start');
  if (op === 'local_status') return kiNativeSecurityStatus(signal);
  if (op === 'local_restart') { if (!userAction) throw Error('Restart the local runtime from Security testing settings.'); return kiNativeSecurityRestart(); }
  if (op === 'local_cancel_setup') { if (!userAction) throw Error('Cancel setup from Security testing settings.'); return kiNativeSecurityCancelSetup(); }
  if (op === 'local_setup') {
    if (!userAction) throw Error('Set up local components from Security testing settings.');
    const installed = await kiNativeSecuritySetup(args, { userAction, signal });
    const connection = installed.mcpConnection ? await kiSecurityRegisterConnection(installed.mcpConnection) : null;
    return { runtime: await kiNativeSecurityStatus(signal), ...(connection ? { connection: { id: connection.id, label: connection.label } } : {}) };
  }
  if (op === 'integrations') {
    const settings = await kiNativeSettings(), connections = [];
    for (const server of settings.servers) connections.push({ id: server.id || await kiPolicyServerGroup(server, 'local'), label: server.label || server.command, managed: server.managedBy === 'cert-x-security' });
    return { ...await kiSecurityIntegrations(), localAccessEnabled: settings.enabled, connections };
  }
  if (op === 'save_integrations') {
    if (!userAction) throw Error('Change testing backends from Security testing settings.');
    const value = { ...await kiSecurityIntegrations() };
    if (Object.hasOwn(args, 'browserBackend')) { if (!['extension', 'local'].includes(args.browserBackend)) throw Error('Choose an available browser backend.'); value.browserBackend = args.browserBackend; }
    if (Object.hasOwn(args, 'zapEnabled')) { if (typeof args.zapEnabled !== 'boolean') throw Error('ZAP selection must be a boolean.'); value.zapEnabled = args.zapEnabled; }
    if (Object.hasOwn(args, 'oastConnectionId')) {
      const id = args.oastConnectionId;
      if (id != null && typeof id !== 'string') throw Error('Choose a saved callback connection.');
      if (id) {
        const settings = (await chrome.storage.local.get(KI_NATIVE_KEY))[KI_NATIVE_KEY] || {}, servers = settings.servers || [];
        let index = -1;
        for (const [position, server] of servers.entries()) if ((server.id || await kiPolicyServerGroup(server, 'local')) === id) { index = position; break; }
        if (index < 0) throw Error('That callback connection is no longer saved.');
        if (!servers[index].id) await chrome.storage.local.set({ [KI_NATIVE_KEY]: { ...settings, servers: servers.map((server, position) => position === index ? { ...server, id } : server) } });
      }
      value.oastConnectionId = id || null;
    }
    await chrome.storage.local.set({ [KI_SECURITY_INTEGRATIONS]: value }); return value;
  }
  const service = kiSecurityService(), context = session ? await kiSecurityContext(session, signal, recheck, userAction) : { userAction, recheck, signal, workspaceId: null };
  context.permissionApproved = userAction === true || permissionLease?.approved === true;
  if (!session && !['state', 'tabs', 'settings', 'configure', 'capabilities'].includes(op)) throw Error('Choose a chat before using security testing.');
  if (op === 'clear_cookie_policy') { op = 'execute'; args = { capability: 'utility', arguments: { tool: 'cookies', action: 'unset', policyId: args.policyId } }; }
  if (op === 'tabs') return kiSecurityTabs(session);
  if (op === 'capabilities') {
    const value = await service.describe(context);
    const publicTools = kiSecurityToolDefs(session, { fullSchemas:true }).filter(tool => KI_SECURITY_REGISTRY.some(spec => spec.name === tool.name));
    if (args.detail != null && !['summary', 'full'].includes(args.detail)) throw kiSecurityInputError('Choose capabilities detail "summary" or "full".', 'invalid_capabilities_detail', 'Use detail:"summary", or tool:"security_tool_name" for an exact operation schema.');
    const requestedTool = args.tool == null ? null : publicTools.find(tool => tool.name === args.tool);
    if (args.tool != null && !requestedTool) throw kiSecurityInputError('That security tool is unavailable in this chat.', 'security_tool_unavailable', 'Call security_capabilities without tool to list currently available operations.');
    const common = { integrationBuild: globalThis.certXSecurityBuild || {contract:'unidentified',recovery:'Reload the rebuilt extension to identify its tool contract.'},
      runReferences: { scan:'Use runId returned by security_start_scan for status, findings, stop, candidates and report export.', recovery:'security_list_runs lists only this chat’s runs.', native:'sessionId/runtimeId are internal engine handles; do not pass them as runId.', reproduction:'Keep the source scan runId and the reproduction executionRunId separately.' } };
    if (requestedTool) return { ...common, tool:requestedTool.name, operationArguments: { [requestedTool.name]: { description:requestedTool.description, schema:requestedTool.parameters } } };
    const core = new Set(['security_capabilities','security_list_runs','security_scan_status','security_stop_scan','security_get_findings','security_get_evidence','security_export_report']);
    const result = args.detail === 'full' ? { ...value } : {
      version:value.version, baseline:value.baseline, configuration:value.configuration, presets:value.presets,
      transport:value.transport, accountReferences:value.accountReferences, engineConcurrency:value.engineConcurrency,
      acquisitionSupport:value.acquisitionSupport, targetScope:value.targetScope,
      modules:(value.modules || []).map(module => ({ id:module.id, engine:module.engine, name:module.name, executable:module.executable === true, checkCount:Array.isArray(module.checks) ? module.checks.length : 0 })),
      unavailable:(value.metadataOnly || []).slice(0,20).map(module => ({ id:module.id, engine:module.engine, executable:false, reason:module.reason })),
      unavailableTotal:(value.metadataOnly || []).length, unavailableTruncated:(value.metadataOnly || []).length>20,
      capabilities:(value.capabilities || []).map(capability => ({ id:capability.id, entryPoint:capability.entryPoint, ...(capability.actions ? {actions:capability.actions} : {}), ...(capability.formats ? {formats:capability.formats} : {}), ...(capability.limitations ? {limitations:capability.limitations} : {}) }))
    };
    return { ...result, ...common, detail:args.detail === 'full' ? 'full' : 'summary', operations:publicTools.map(tool => tool.name),
      operationArguments:Object.fromEntries(publicTools.filter(tool => args.detail === 'full' || core.has(tool.name)).map(tool => [tool.name, { schema:tool.parameters, ...(args.detail === 'full' ? {description:tool.description} : {}) }])),
      discovery:'Use security_capabilities({tool:"security_start_scan"}) or another exact tool name for its schema; detail:"full" includes unavailable reasons, provenance and verification metadata.', localRuntime:await kiSecurityLocalAvailability() };
  }
  if (op === 'state') {
    const result = await service.handle('state', args, context);
    const stored = await chrome.storage.local.get(['ki_ptk_scans', 'ki_dast_batches', 'ki_authz_batches']);
    result.history = [['ptk', stored.ki_ptk_scans], ['dast', stored.ki_dast_batches], ['authz', stored.ki_authz_batches]].flatMap(([source, records]) => (records || []).filter(record => context.owner && record.owner === context.owner).map(record => ({ ...record, runId: record.scanId || record.batchId, legacySource: source, historical: true })));
    if (session && typeof kiAuthzState === 'function') try { result.accounts = (await kiAuthzState(session)).accounts || []; } catch { result.accounts = []; }
    return result;
  }
  let surfaceMap;
  if (op === 'start') {
    args = JSON.parse(JSON.stringify(args));
    const tab = await kiSecurityTargetTab(args.tabId);
    if (args.expectedOrigin && new URL(tab.url).origin !== args.expectedOrigin) throw kiSecurityInputError('The target tab changed origin. Inspect its current URL before starting a new scan.', 'target_origin_changed');
    if (!context.scope.origins?.length) context.scope = kiSecuritySelectedScope(args, tab);
    if (!context.scope || !kiSecurityScopeAllows(tab.url, context.scope)) throw Error('Selected target is outside workspace scope: ' + tab.url + '. Review target scope in Workspace settings.');
    await recheck?.(); surfaceMap = await kiSecuritySurfaceMap(tab.id, context.scope);
    // Browser instrumentation needs a real prepared browser identity. DAST can
    // use an isolated verified header/cookie snapshot without changing that jar.
    if (args.accountId) {
      if ((args.engines || ['DAST']).some(engine => engine !== 'DAST')) throw Error('Saved account snapshots support DAST. IAST, SAST and SCA require the account’s prepared browser session.');
      await kiAuthzLoad(); const account = kiAuthzPrivate.accounts[args.accountId];
      if (!account || account.workspaceId !== context.workspaceId) throw Error('The saved account does not belong to this workspace.');
      context.account = kiAuthzWireAccount(account); context.accountId = account.id;
      const previous = context.recheck;
      context.recheck = async () => { await previous?.(); const current = kiAuthzPrivate.accounts[account.id]; if (!current || current.workspaceId !== context.workspaceId || current.revision !== account.revision) throw Error('The account changed while the operation was running.'); };
      context.prepare = async execution => {
        const verification = await kiAuthzVerify({ accountId: args.accountId }, session, execution.signal, context.recheck, execution.checkRequest);
        if (verification.verified !== true) throw Object.assign(Error('Account identity could not be verified: ' + (verification.reason || 'inconclusive identity probe')), { admitted: false });
      };
    }
  }
  if (op === 'execute') {
    const tabId = args.tabId ?? args.arguments?.tabId;
    if (!context.scope.origins?.length) context.scope = kiSecuritySelectedScope(args, Number.isInteger(tabId) ? await kiSecurityTargetTab(tabId) : null) || context.scope;
    const accountId = args.arguments?.accountId;
    if (accountId) {
      await kiAuthzLoad(); const account = kiAuthzPrivate.accounts[accountId];
      if (!account || account.workspaceId !== context.workspaceId) throw Error('The saved account does not belong to this workspace.');
      context.account = kiAuthzWireAccount(account);
      const previous = context.recheck;
      context.recheck = async () => { await previous?.(); const current = kiAuthzPrivate.accounts[accountId]; if (!current || current.workspaceId !== context.workspaceId || current.revision !== account.revision) throw Error('The account changed while the operation was running.'); };
    }
    if (args.capability === 'utility' && args.arguments?.tool === 'cookies' && ['block', 'readonly'].includes(args.arguments.action)) context.cookiePolicyGrant = await kiSecurityCookieGrant(context, permissionLease);
  }
  const result = await service.handle(op, args, context);
  if (op === 'start') return { ...result, surfaceMap };
  if (op !== 'export') return result;
  await recheck?.();
  const format = args.format || 'json', artifact = result.artifact;
  let bytes, extension = 'json', mime = 'application/json';
  if (format === 'json') bytes = new TextEncoder().encode(JSON.stringify(result.report, null, 2));
  else {
    if (!artifact || artifact.format !== format) throw Error('The requested report artifact is unavailable.');
    if (format === 'pdf') { if (artifact.mime !== 'application/pdf' || !Array.isArray(artifact.bytes) || !artifact.bytes.every(value => Number.isInteger(value) && value >= 0 && value <= 255)) throw Error('The engine returned an invalid PDF artifact.'); bytes = Uint8Array.from(artifact.bytes); if (new TextDecoder().decode(bytes.subarray(0, 5)) !== '%PDF-') throw Error('PDF output did not contain a PDF signature.'); extension = 'pdf'; mime = 'application/pdf'; }
    else { if (typeof artifact.text !== 'string' || !artifact.text.trim()) throw Error('The engine returned an empty Markdown artifact.'); bytes = new TextEncoder().encode(artifact.text); extension = 'md'; mime = 'text/markdown'; }
  }
  const name = 'cert-x-security-' + args.runId.replace(/[^a-zA-Z0-9_-]/g, '_') + '.' + extension;
  let binary = '';
  for (let index = 0; index < bytes.length; index += 32768) binary += String.fromCharCode(...bytes.subarray(index, index + 32768));
  const data = btoa(binary), downloadId = await chrome.downloads.download({ url: 'data:' + mime + ';base64,' + data, filename: name, saveAs: false });
  let download;
  for (let count = 0; count < 200; count++) { signal?.throwIfAborted(); download = (await chrome.downloads.search({ id: downloadId }))[0]; if (download?.state === 'complete') break; if (download?.state === 'interrupted') throw Error('Report download interrupted: ' + (download.error || 'unknown error')); await new Promise(resolve => setTimeout(resolve, 100)); }
  if (download?.state !== 'complete') throw Error('Report download completion is unconfirmed. Check Downloads before retrying.');
  await kiWorkspaceOutput(session, { name, path: download.filename, downloadId, size: bytes.length, kind: 'file', runId: args.runId, mime });
  return { reports: [{ name, downloadId, size: bytes.length }], summary: result.run?.summary, selectedEngines: result.run?.engines, coverageState: result.run?.state,
    requestBudget:{ used:result.run?.requestsSent ?? null, limit:result.run?.config?.maxRequests ?? null, exhausted:result.run?.config?.maxRequests != null && result.run.requestsSent >= result.run.config.maxRequests },
    warnings: result.warnings || [], reportingNote: 'Use summary.byModule for raw alert counts. Selected engines are the tested engines; an unselected engine is not necessarily unconfigured. Raw alerts are not distinct vulnerabilities. Tasks entered are not HTTP requests; only requestBudget.exhausted supports a request-budget exhaustion claim.' };
}
function kiSecurityAgentResult(op, args, result) {
  if (args?.detail === 'full' || !result || typeof result !== 'object') return result;
  if (result.kind === 'operation') return result;
  if (['start','status','stop'].includes(op)) {
    const engineStatus = Object.fromEntries(Object.entries(result.engineStatus || {}).map(([engine, value]) => [engine, {
      status:value.status, phase:value.phase, progress:value.progress, findingsCount:value.findingsCount, idle:value.idle,
      error:value.error || value.engineError || null, warnings:value.warnings || [],
      ...(engine === 'IAST' ? { agentReady:value.agentReady, modulesLoaded:value.modulesLoaded, runtimeEventsCount:value.runtimeEventsCount } : {}),
      ...(engine === 'SAST' || engine === 'SCA' ? { collectionState:value.collectionState, totalFiles:value.totalFiles, completedFiles:value.completedFiles } : {})
    }]));
    return { runId:result.runId, kind:result.kind || 'scan', state:result.state, tabId:result.tabId,
      engines:result.engines, workspaceId:result.workspaceId, createdAt:result.createdAt, updatedAt:result.updatedAt,
      requestsSent:result.requestsSent, inFlight:result.inFlight, config:result.config, scope:result.scope,
      summary:result.summary, coverage:result.coverage, engineStatus, ...(result.surfaceMap ? { surfaceMap:result.surfaceMap } : {}),
      requestBudget:{ used:result.requestsSent ?? null, limit:result.config?.maxRequests ?? null, exhausted:result.config?.maxRequests != null && result.requestsSent >= result.config.maxRequests },
      ...(result.wait ? { wait:result.wait } : {}), ...(result.error ? { error:result.error } : {}),
      detail:'summary', detailHint:'Tasks entered are not HTTP requests. Use requestBudget.exhausted for budget claims; detail:"full" returns native engine diagnostics.' };
  }
  if (op === 'findings') return { runId:result.runId, total:result.total, nextOffset:result.nextOffset, truncated:result.truncated,
    findings:(result.findings || []).map(item => ({ id:item.id || item.findingId, engine:item.engine, moduleId:item.moduleId,
      title:item.title || item.ruleName, severity:item.severity, confidence:item.confidence, findingKind:item.findingKind,
      ruleId:item.ruleId, location:item.location, description:typeof item.description === 'string' ? item.description.slice(0,240) : undefined,
      evidenceAvailable:!!item.evidence })),
    summary:result.summary, selectedEngines:result.selectedEngines, coverage:result.coverage, requestBudget:result.requestBudget, error:result.error,
    detail:'summary', detailHint:'Use security_get_evidence with this runId and a finding id for full request/response proof; detail:"full" returns complete finding records.' };
  return result;
}
function kiSecuritySchemaForModel(value) {
  if (Array.isArray(value)) return value.map(kiSecuritySchemaForModel);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'description').map(([key, item]) => [key, kiSecuritySchemaForModel(item)]));
}
function kiSecurityToolDefs(session, { fullSchemas = false } = {}) {
  const context = typeof kiContextFor === 'function' ? kiContextFor(session) : null;
  const selected = !context || context.tools.groups.ptk === true || Object.entries(context.tools.tools || {}).some(([name, enabled]) => enabled === true && (name.startsWith('ptk:') || name.startsWith('security_')));
  const owner = typeof kiWorkspaceOwner === 'function' ? kiWorkspaceOwner(session) : session;
  const owned = globalThis.certXSecurity?.hasRuns?.(owner) || (typeof kiPtkHasScans === 'function' && kiPtkHasScans(session)) || (typeof kiDastBatches !== 'undefined' && kiDastBatches.some(run => run.owner === owner)) || (typeof kiAuthzBatches !== 'undefined' && kiAuthzBatches.some(run => run.owner === owner));
  if (!selected && !owned) return [];
  const scopedWorkspace = !!context?.workspace?.dastScope?.origins?.length;
  const targetedOwned = typeof kiDastBatches !== 'undefined' && kiDastBatches.some(run => run.owner === owner);
  const accountOwned = typeof kiAuthzBatches !== 'undefined' && kiAuthzBatches.some(run => run.owner === owner);
  const nativeEnabled = typeof kiNativeCache !== 'object' || kiNativeCache.enabled !== false;
  const needsLocalRuntime = new Set(['security_browser','security_raw','security_oast','security_zap']);
  const page = { runId: { type: 'string' }, offset: { type: 'integer', minimum: 0 }, limit: { type: 'integer', minimum: 1, maximum: 500 } };
  const moduleSelection = { type:'array', items:{type:'string',minLength:1}, description:'Module IDs returned by security_capabilities, for example ["xss"]. Supply the array directly; no wrapper object.' };
  const selectionProperties = { moduleIds:moduleSelection, modules:{...moduleSelection,description:'Compatibility alias for moduleIds; supply an array of module ID strings.'}, excludeModules:{...moduleSelection,description:'Module ID strings to exclude.'} };
  const options = { type: 'object', description: 'Native engine settings: preset, scanStrategy, scanControlProfile, runCve, maxRequestsPerSecond, concurrency, planningConcurrency, optional maxRequests/durationSeconds, scanControls, modules, engineOptions, acquisition. Explicit user limits remain binding.', properties: {
    ...selectionProperties,
    preset:{type:'string',enum:['thorough','ptk-defaults']},
    scanStrategy:{type:'string',enum:['FAST','SMART','COMPREHENSIVE']}, dastScanStrategy:{type:'string',enum:['FAST','SMART','COMPREHENSIVE']},
    scanControlProfile:{type:'string',enum:['strict','safe','wide']}, safetyProfile:{type:'string',enum:['strict','safe','wide']},
    ...Object.fromEntries(['runCve','follow_redirect','followRedirect','override_headers','update_content_length','use_content_type','allowCaptureWithoutInteraction','enableHtmlLinkDiscovery','enableSyntheticRedirectRequests','schedulerBreadthFirst'].map(key=>[key,{type:'boolean'}])),
    maxRequestsPerSecond:{type:'number',exclusiveMinimum:0}, concurrency:{type:'integer',minimum:1}, planningConcurrency:{type:'integer',minimum:1},
    maxRequests:{type:['integer','null'],minimum:1,description:'Optional overall request budget. null leaves no overall preference limit; explicit user ceilings still apply.'},
    durationSeconds:{type:['number','null'],exclusiveMinimum:0,description:'Optional observation/run duration in seconds. null continues until stopped or work ends.'},
    requestTimeoutMs:{type:'number',exclusiveMinimum:0}, originalRequestTimeoutMs:{type:'number',exclusiveMinimum:0},
    engineOptions:{type:'object',description:'Native per-engine options. Module selectors are arrays, including inside each engine.',properties:Object.fromEntries(['DAST','IAST','SAST','SCA'].map(engine=>[engine,{type:'object',properties:selectionProperties,additionalProperties:true}])),additionalProperties:true},
    scanControls:{type:'object',additionalProperties:true}, globalExcludes:{type:['object','array']}, confirm:{type:'object',additionalProperties:true}, rulepack:{type:'object',additionalProperties:true}, cveRulepack:{type:'object',additionalProperties:true},
    acquisition: { type: 'object', description: 'Browser acquisition limits. A limit reached is a coverage gap, not a negative finding. Changes apply to the next scan.', properties: {
      maxResourceBytes: { type: 'integer', minimum: 1, maximum: 8388608, description: 'Maximum retained bytes per resource; platform ceiling 8 MiB.' },
      maxTotalBytes: { type: 'integer', minimum: 1, maximum: 33554432, description: 'Maximum aggregate retained bytes; platform ceiling 32 MiB per tab.' },
      maxScripts: { type: 'integer', minimum: 1, maximum: 4096, description: 'Maximum loaded executable scripts to acquire.' },
      drainTimeoutMs: { type: 'integer', minimum: 1, maximum: 60000, description: 'SCA pending-acquisition drain window after stop, in milliseconds. Unfinished work remains a gap. SAST retains its native stop timeout; see acquisitionSupport.' }
    }, additionalProperties: false }
  } };
  const tools = KI_SECURITY_REGISTRY.filter(spec => !needsLocalRuntime.has(spec.name) || nativeEnabled).filter(spec => !selected ? spec.stop || spec.op === 'status' : spec.stop || !context || kiContextAllows(kiSecurityMeta(spec), context)).map(spec => {
    const properties = spec.op === 'start' ? { tabId: { type: 'integer', minimum: 0 }, expectedOrigin: { type: 'string' }, engines: { type: 'array', items: { type: 'string', enum: ['DAST', 'IAST', 'SAST', 'SCA'] } }, accountId: { type: 'string' }, options, scope: { type: 'object' }, requests: { type: 'array', items: { type: 'object' } } }
      : spec.op === 'clear_cookie_policy' ? { policyId: { type: 'string' } } : spec.op === 'execute' ? { tabId: { type: 'integer', minimum: 0 }, arguments: fullSchemas ? globalThis.certXSecurity?.operationSchemas?.[spec.capability]?.schema || { type: 'object', description: 'Arguments for the advertised native operation.' } : kiSecuritySchemaForModel(globalThis.certXSecurity?.operationSchemas?.[spec.capability]?.schema || { type: 'object' }), options }
      : spec.op === 'capabilities' ? {detail:{type:'string',enum:['summary','full'],description:'Default summary omits provenance and verification bulk.'},tool:{type:'string',description:'Optional available security_* tool name to return only its exact argument schema.'}}
      : spec.op === 'runs' ? { offset:page.offset, limit:page.limit } : spec.op === 'findings' ? { ...page, detail:{type:'string',enum:['summary','full'],description:'Summary lists findings without large evidence bodies; use security_get_evidence for one finding.'} } : spec.op === 'evidence' ? { ...page, evidenceId: { type: 'string' } } : spec.op === 'export' ? { runId: { type: 'string' }, format: { type: 'string', enum: ['json', 'pdf', 'markdown'] }, options: { type: 'object', properties: { preset: { type: 'string', enum: ['technical', 'executive'] } }, additionalProperties: false } } : spec.op === 'status' ? { runId: { type: 'string' }, detail:{type:'string',enum:['summary','full'],description:'Default summary includes progress and gaps; full includes native engine diagnostics.'}, waitForIdle: { type: 'boolean', description: 'Wait for DAST queued work to become idle or the run to end. Does not stop the run.' }, timeoutMs: { type: 'integer', minimum: 1, maximum: 30000, default: 30000, description: 'Maximum status wait, in milliseconds; only used with waitForIdle.' } } : spec.op === 'stop' ? { runId: { type: 'string' } } : {};
    return { name: spec.name, description: spec.description, kiPolicyMeta: kiSecurityMeta(spec), kiPolicyMetaFor: args => kiSecurityMeta(spec, args), parameters: { type: 'object', properties, required: spec.op === 'start' ? ['tabId'] : spec.op === 'clear_cookie_policy' ? ['policyId'] : spec.op === 'execute' && properties.arguments.required?.length ? ['arguments'] : ['status', 'stop', 'findings', 'evidence', 'export'].includes(spec.op) ? ['runId'] : [], additionalProperties: false }, resolveExecution(args) { return { approvalRule: 'allow', async execute(execution) {
      try { const recheck = async () => { if (execution[KI_POLICY_CONTEXT]) await kiPolicyRecheck(execution[KI_POLICY_CONTEXT]); };
        const result = await kiSecurityOperate(spec.op, { ...args, ...(spec.capability ? { capability: spec.capability } : {}) }, session, execution.signal, recheck, false, execution[KI_POLICY_CONTEXT]); return { output: JSON.stringify(kiSecurityAgentResult(spec.op,args,result)), ...(['error', 'unknown', 'interrupted'].includes(result?.state) ? { isError: true } : {}) };
      } catch (error) { return { output: JSON.stringify(kiSecurityErrorResult(error)), isError: true }; }
    } }; } };
  });
  // Existing account execution keeps its private credential/identity safeguards.
  if ((scopedWorkspace || accountOwned) && typeof kiAuthzToolDefs === 'function') for (const tool of kiAuthzToolDefs(session)) tools.push({ ...tool, name: tool.name.replace(/^ptk_/, 'security_'), description: tool.description + ' Captured account request IDs come from security_capture_requests and security_list_targeted_requests.' });
  const targetedNames = { ptk_capture_requests: 'security_capture_requests', ptk_list_requests: 'security_list_targeted_requests', ptk_prepare_dast: 'security_prepare_targeted_test', ptk_run_dast: 'security_run_targeted_test', ptk_dast_status: 'security_targeted_status', ptk_stop_dast: 'security_stop_targeted_test', ptk_dast_findings: 'security_targeted_findings', ptk_dast_export: 'security_targeted_export' };
  if ((scopedWorkspace || targetedOwned) && typeof kiDastToolDefs === 'function') for (const tool of kiDastToolDefs(session)) tools.push({ ...tool, name: targetedNames[tool.name] || tool.name, description: 'Selected-request testing and account-capture workflow; use security_start_scan for full native engine coverage. ' + tool.description });
  return tools.map(tool => ({ ...tool, kiSecuritySession: session }));
}
function kiSecurityLegacyLookup(tools, name) {
  if (typeof name !== 'string' || !name.startsWith('ptk_')) return undefined;
  const session = tools?.find(tool => typeof tool.kiSecuritySession === 'string')?.kiSecuritySession;
  if (!session) return undefined;
  const definitions = [
    ...(typeof kiPtkToolDefs === 'function' ? kiPtkToolDefs(session) : []),
    ...(typeof kiDastToolDefs === 'function' ? kiDastToolDefs(session) : []),
    ...(typeof kiAuthzToolDefs === 'function' ? kiAuthzToolDefs(session) : []),
  ];
  const selected = definitions.find(tool => tool.name === name);
  return selected ? kiPolicyTools([selected], session)[0] : undefined;
}
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== 'KI_SECURITY') return;
  const allowed = ['providers/providers.html', 'pages/sidepanel.html'].map(file => chrome.runtime.getURL(file));
  if (sender.id !== chrome.runtime.id || !allowed.includes(sender.url?.split('?')[0])) { reply({ ok: false, error: 'Open cert-x to use security testing.' }); return; }
  (async () => { try {
    const spec = KI_SECURITY_REGISTRY.find(item => item.op === message.op && (message.op !== 'execute' || item.capability === message.capability));
    if (!spec && !['state', 'tabs', 'configure', 'settings', 'integrations', 'save_integrations', 'local_status', 'local_setup', 'local_cancel_setup', 'local_restart'].includes(message.op)) throw Error('Unknown security operation.');
    const recheck = async () => {
      if (spec?.stop) return;
      const meta = kiSecurityMeta(spec || KI_SECURITY_REGISTRY[0], message), policy = await kiPolicyState(meta);
      const resolved = message.session && typeof kiContextResolve === 'function' ? await kiContextResolve(message.session) : null;
      const rule = resolved ? kiContextRule(meta, resolved, policy.rule) : policy.rule;
      if (!policy.parentEnabled || rule === 'disabled') throw Error('This operation is disabled by the selected profile or Tools & permissions.');
    };
    if (!['state', 'tabs', 'settings', 'configure', 'integrations', 'save_integrations', 'local_status', 'local_setup', 'local_cancel_setup', 'local_restart'].includes(message.op)) await recheck();
    reply({ ok: true, result: await kiSecurityOperate(message.op, message, message.session, undefined, recheck, true) });
  } catch (error) { reply({ ok: false, ...kiSecurityErrorResult(error) }); } })(); return true;
});
chrome.alarms?.onAlarm?.addListener(alarm => { if (alarm.name === 'ki-security-monitor') globalThis.certXSecurity?.handle('refresh').catch(error => console.warn('[security]', error.message)); });
chrome.alarms?.create?.('ki-security-monitor', { periodInMinutes: 0.5 });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !['ki_contexts', 'ki_tool_permissions', 'sidepanel_approval_mode', 'ki_security_settings'].some(key => changes[key])) return;
  void globalThis.certXSecurity?.handle('revalidate').catch(error => console.warn('[security] Could not reconcile active testing:', error.message));
  void globalThis.certXSecurity?.runtime?.cookiePolicies?.reconcile().catch(error => console.warn('[security] Could not reconcile cookie policies:', error.message));
});
Promise.resolve(globalThis.certXSecurity?.ready).then(() => globalThis.certXSecurity?.runtime?.cookiePolicies?.reconcile()).catch(error => console.warn('[security] Cookie policy validation is unavailable:', error.message));

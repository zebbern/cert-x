import { ACQUISITION_DEFAULTS, ACQUISITION_MAXIMA } from '../security/config.mjs';
const ACTIVE = new Set(["queued", "starting", "running", "stopping"]);
const ACQUISITION_FIELDS = [
  ['maxResourceBytes', 'Per resource (MiB)', 1024 * 1024],
  ['maxTotalBytes', 'Total acquired (MiB)', 1024 * 1024],
  ['maxScripts', 'Loaded scripts', 1],
  ['drainTimeoutMs', 'Finish pending reads (seconds)', 1000],
];
const PRESETS = {
  thorough: { scanStrategy: "COMPREHENSIVE", scanControlProfile: "wide", maxRequestsPerSecond: 5, concurrency: 3, planningConcurrency: 2, runCve: true },
  "ptk-defaults": { scanStrategy: "SMART", scanControlProfile: "safe", maxRequestsPerSecond: 5, concurrency: 3, planningConcurrency: 2, runCve: true },
};
const el = (tag, text, className) => { const node = document.createElement(tag); if (text != null) node.textContent = text; if (className) node.className = className; return node; };
const readable = value => typeof value === "string" ? value : JSON.stringify(value, null, 2) || "";
const list = value => Array.isArray(value) ? value : [];
const failureText = value => typeof value === "string" ? value : value?.message || readable(value);
function findingAssessment(finding) {
  const parts = [];
  if (finding.classification === "observation") parts.push("Observation");
  if (finding.classification === "execution_observed" || finding.executionObserved === true) parts.push("Execution observed");
  else if (finding.executionObserved === false) parts.push("Execution not observed");
  return parts.join(" · ");
}
function coverageText(value) {
  const entries = Array.isArray(value) ? value : Array.isArray(value?.checks) ? value.checks : [];
  const counts = value?.counts || value || {};
  return ['tested', 'skipped', 'unsupported', 'inconclusive'].map(state => { const count = entries.length ? entries.filter(item => (item.state || item.status) === state).length : counts[state]; return Number.isFinite(count) && count > 0 ? count + ' ' + state : null; }).filter(Boolean).join(' · ');
}
function dastCoverageText(value) {
  const dast = value?.dast; if (!dast) return "";
  const phase = {
    waiting_for_interaction: "Waiting for page activity.",
    waiting_for_requests: "Waiting for application traffic.",
    waiting_for_attackable_inputs: "No testable inputs yet. Browse a form or a URL with inputs.",
    planning_or_waiting: "Preparing probes.",
    no_requests: "Not tested: no probes ran.",
    no_executed_probes: "Not tested: no probes ran.",
    no_active_probes: "Passive checks only.",
    dispatch_attribution_unknown: "Per-engine request counts unavailable.",
    engine_error: "Scan failed; coverage is incomplete.",
    partial_error: "Some checks failed.",
    probing_with_errors: "Testing with errors.",
    limited_by_skips: "Partial coverage: checks were skipped.",
    probing_with_skips: "Testing with skipped checks.",
    scanning: "Testing.",
    watching_for_activity: "Current checks finished; watching for page activity.",
    scan_requests_dispatched: "Selected checks finished."
  }[dast.phase] || readable(dast.phase);
  const counts = Number.isFinite(dast.probeDispatches) ? `${dast.probeDispatches} probes · ${dast.baselineDispatches || 0} baselines` : Number.isFinite(dast.runRequestsDispatched) ? `${dast.runRequestsDispatched} request dispatches` : "";
  return phase + (counts ? " " + counts : "");
}
function scaCoverageText(value) {
  if (!value?.scaAcquisition) return "";
  const bodies=value.scaBodies?.analyzed||0,sources=value.scaSources?.analyzed||0;
  if (!bodies&&!sources) return value.scaAcquisition.phase==='waiting_for_resources'?'SCA is waiting for JavaScript content.':'SCA analyzed no JavaScript content.';
  const gaps=(value.scaBodies?.gaps||0)+(value.scaSources?.gaps||0);
  return `SCA: ${bodies} captured responses · ${sources} loaded scripts`+(gaps?` · ${gaps} acquisition gaps`:"");
}
const label = state => ({ queued: "Queued", starting: "Starting", running: "Running", stopping: "Stopping", completed: "Completed", stopped: "Stopped", cancelled: "Stopped", canceled: "Stopped", interrupted: "Interrupted", incomplete: "Incomplete", unknown: "State unknown", failed: "Failed", error: "Failed" })[state] || readable(state).replaceAll("_", " ");
function button(text, action, className = "") { const node = el("button", text, className); node.type = "button"; node.onclick = action; return node; }
function field(text, input) { const row = el("label", null, "security-field"); row.append(el("span", text), input); return row; }
function select(name, choices) { const node = el("select"); node.setAttribute("aria-label", name); for (const [value, text] of choices) { const option = el("option", text); option.value = value; node.append(option); } return node; }
function number(name, optional = false) { const node = el("input"); node.type = "number"; node.min = "1"; node.step = "1"; node.setAttribute("aria-label", name); if (optional) node.placeholder = "No limit"; return node; }
function numeric(input, optional = false) { if (optional && !input.value.trim()) return null; const value = Number(input.value); if (!Number.isSafeInteger(value) || value < 1) throw Error(input.getAttribute("aria-label") + " must be a positive whole number."); return value; }
function acquisitionValue(inputs, optional = false) {
  return Object.fromEntries(ACQUISITION_FIELDS.map(([key, label, scale]) => {
    const input = inputs[key], value = Number(input.value) * scale;
    if (optional && !input.value.trim()) return [key, null];
    if (!Number.isSafeInteger(value) || value < 1 || value > ACQUISITION_MAXIMA[key]) throw Error(label + ' must be positive and at most ' + ACQUISITION_MAXIMA[key] / scale + '.');
    return [key, value];
  }));
}
function acquisitionFields(container, optional = false) {
  const inputs = {};
  for (const [key, label, scale] of ACQUISITION_FIELDS) {
    const input = number((optional ? 'Maximum acquisition: ' : 'Acquisition: ') + label, optional);
    input.step = scale === 1 ? '1' : 'any'; input.min = String(1 / scale); input.max = String(ACQUISITION_MAXIMA[key] / scale);
    inputs[key] = input; container.append(field(label, input));
  }
  return inputs;
}
function details(text, value) { const node = el("details"); node.append(el("summary", text), el("pre", readable(value))); return node; }
async function send(op, fields) {
  const reply = await chrome.runtime.sendMessage({ type: "KI_SECURITY", op, ...fields });
  if (!reply?.ok || reply.result?.ok === false || reply.result?.success === false) throw Error(failureText(reply?.error || reply.result?.error || reply.result?.message) || "Security operation failed.");
  if (reply.result == null) throw Error("Security operation returned no result.");
  return reply.result;
}

export async function initSecurity({ view = "scans" } = {}) {
  const root = document.getElementById("security-section"); if (!root) throw Error("Security settings panel is missing.");
  root.classList.add("security-root");
  if (!document.querySelector("link[data-security-style]")) { const link = el("link"); link.rel = "stylesheet"; link.href = new URL("./security.css", import.meta.url).href; link.dataset.securityStyle = ""; document.head.append(link); }
  const params = new URLSearchParams(location.search), session = params.get("session") || null;
  let state = { runs: [], accounts: [], config: {}, settings: {} }, tabs = [], busy = false, disposed = false, timer, revision = "", catalogueRevision = "", historyRevision = "", selectedRun = null, nextOffset = null;
  const reportChoices = new Map();
  const header = el("header"); header.append(el("h1", "Security testing"), el("p", "Test the application and investigate findings."));
  const main = el("section", null, "card security-card"), target = select("Target page", []), account = select("Account", [["", "Current browser session"]]);
  const preset = select("Testing preset", [["thorough", "Thorough"], ["ptk-defaults", "PTK defaults"]]);
  const notice = el("p", "", "security-notice"); notice.setAttribute("role", "status");
  const actions = el("div", null, "security-actions"), accountButton = button("Manage accounts", () => openAccounts());
  const start = button("Start scan", () => act(startScan), "primary"), refresh = button("Refresh", () => act(async () => { await loadTabs(); await loadState(); }));
  actions.append(start, accountButton, refresh);
  main.append(field("Target", target), field("Account", account), field("Preset", preset), actions);

  const advanced = el("details", null, "security-advanced"); advanced.append(el("summary", "Scan options"));
  const engines = new Set(["DAST", "IAST", "SAST", "SCA"]), toggles = [];
  for (const [id, name] of [["DAST", "Active testing (DAST)"], ["IAST", "Runtime observation (IAST)"], ["SAST", "Client-side code (SAST)"], ["SCA", "Dependencies (SCA)"]]) {
    const toggle = button("", () => { if (engines.has(id)) engines.delete(id); else engines.add(id); toggle.classList.toggle("is-on", engines.has(id)); toggle.setAttribute("aria-checked", String(engines.has(id))); update(); }, "wb-toggle wb-toggle--sm is-on");
    toggle.setAttribute("role", "switch"); toggle.setAttribute("aria-label", name); toggle.setAttribute("aria-checked", "true"); toggle.append(el("span", null, "wb-toggle-thumb")); toggles.push(toggle);
    const row = el("div", null, "security-field"); row.append(el("span", name), toggle); advanced.append(row);
  }
  const strategy = select("Scan strategy", [["COMPREHENSIVE", "Comprehensive"], ["SMART", "Smart"], ["FAST", "Fast"]]);
  const controls = select("Test controls", [["wide", "Wide"], ["safe", "Standard"], ["strict", "Strict"]]);
  const rate = number("Requests per second"), concurrency = number("Concurrent requests"), planning = number("Planning concurrency");
  const maxRequests = number("Run request budget", true), duration = number("Run duration in seconds", true);
  const cv = button("", () => { const on = cv.getAttribute("aria-checked") !== "true"; cv.classList.toggle("is-on", on); cv.setAttribute("aria-checked", String(on)); }, "wb-toggle wb-toggle--sm is-on");
  cv.setAttribute("role", "switch"); cv.setAttribute("aria-label", "CVE checks"); cv.setAttribute("aria-checked", "true"); cv.append(el("span", null, "wb-toggle-thumb")); toggles.push(cv);
  const cvRow = el("div", null, "security-field"); cvRow.append(el("span", "CVE checks"), cv);
  advanced.append(field("Strategy", strategy), field("Test controls", controls), cvRow, field("Requests / second", rate), field("Concurrent requests", concurrency), field("Planning concurrency", planning), field("Request budget", maxRequests), field("Duration (seconds)", duration));
  advanced.append(el("p", "Leave a budget blank for no overall limit. Observation continues until stopped.", "security-meta"));
  const acquisition = el('details', null, 'security-advanced'); acquisition.append(el('summary', 'Acquisition limits'));
  const acquisitionInputs = acquisitionFields(acquisition);
  acquisition.append(el('p', 'Browser retention supports up to 8 MiB per resource and 32 MiB per tab. Drain timeout applies to SCA capture. The agent reports missed content.', 'security-meta')); advanced.append(acquisition);
  const saveDefault = button("Save defaults", () => act(() => saveSettings(false))), saveWorkspace = button("Save for workspace", () => act(() => saveSettings(true)));
  const saveActions = el("div", null, "security-actions"); saveActions.append(saveDefault, saveWorkspace); advanced.append(saveActions);
  const hardLimits = el("details", null, "security-advanced"); hardLimits.append(el("summary", "Your limits"), el("p", "The agent can adjust scan options, but cannot exceed these limits.", "security-meta"));
  const limitRate = number("Maximum allowed requests per second", true), limitConcurrency = number("Maximum allowed concurrent requests", true), limitRequests = number("Maximum allowed run requests", true), limitDuration = number("Maximum allowed run seconds", true);
  const limitScope = select("Save limits for", [["global", "All workspaces"], ["workspace", "This workspace"]]);
  const limitSave = button("Save limits", () => act(saveLimits));
  hardLimits.append(field("Requests / second", limitRate), field("Concurrent requests", limitConcurrency), field("Requests per run", limitRequests), field("Seconds per run", limitDuration), field("Apply to", limitScope), limitSave);
  const acquisitionCeilings = el('details', null, 'security-advanced'); acquisitionCeilings.append(el('summary', 'Acquisition ceilings'));
  const acquisitionLimitInputs = acquisitionFields(acquisitionCeilings, true); hardLimits.insertBefore(acquisitionCeilings, limitSave);
  main.append(advanced, hardLimits);
  const connections = el('details', null, 'security-advanced'); connections.append(el('summary', 'Local runtime & connections'));
  const runtimeStatus = el('p', 'Not checked', 'security-meta'), runtimeActions = el('div', null, 'security-actions'); runtimeStatus.setAttribute('role', 'status');
  const localSettings = el('a', 'Local computer settings'); localSettings.href = '?section=local' + (session ? '&session=' + encodeURIComponent(session) : '');
  localSettings.onclick = event => { if (params.get('embed') === '1') { event.preventDefault(); parent.postMessage({ type: 'settings-section', section: 'local' }, location.origin); } };
  const checkRuntime = button('Check runtime', () => act(async () => { await loadConnections(); renderRuntime(await send('local_status', { session })); }));
  const setupBrowser = button('Set up browser', () => act(() => setupRuntime('browser'))), setupZap = button('Set up ZAP', () => act(() => setupRuntime('zap')));
  const cancelSetup = button('Cancel setup', async () => { cancelSetup.disabled = true; try { await send('local_cancel_setup', { session }); if (!cancelSetup.hidden) runtimeStatus.textContent = 'Cancelling setup…'; } catch (error) { message(error.message, true); cancelSetup.disabled = false; } }); cancelSetup.hidden = true;
  runtimeActions.append(checkRuntime, setupBrowser, setupZap, cancelSetup);
  const restartRuntime = button('Restart local runtime', () => act(async () => { const value = await send('local_restart', { session }); renderRuntime(value.runtime); await loadState(); message('Local runtime restarted. Previous local operations were stopped.'); }));
  const restartRow = el('div', null, 'security-actions'); restartRow.append(restartRuntime, el('span', 'Stops active local testing.', 'security-meta'));
  const callbackConnection = select('Callback connection', [['', 'Not connected']]);
  const zapToggle = button('', () => { const enabled = zapToggle.getAttribute('aria-checked') !== 'true'; zapToggle.setAttribute('aria-checked', String(enabled)); zapToggle.classList.toggle('is-on', enabled); }, 'wb-toggle wb-toggle--sm');
  zapToggle.setAttribute('role', 'switch'); zapToggle.setAttribute('aria-label', 'Include ZAP in Thorough'); zapToggle.setAttribute('aria-checked', 'false'); zapToggle.append(el('span', null, 'wb-toggle-thumb'));
  const zapRow = el('div', null, 'security-field'); zapRow.append(el('span', 'Include ZAP in Thorough'), zapToggle);
  const saveConnections = button('Save connections', () => act(async () => { await send('save_integrations', { session, oastConnectionId: callbackConnection.value || null, zapEnabled: zapToggle.getAttribute('aria-checked') === 'true' }); await loadConnections(); message('Testing connections saved.'); }));
  const callbackSetup = el('details', null, 'security-advanced'), envFile = el('input'), callbackKey = el('input'); callbackSetup.append(el('summary', 'Set up callbacks'));
  envFile.setAttribute('aria-label', 'Callback environment file'); envFile.placeholder = 'Absolute path to .env'; callbackKey.type = 'password'; callbackKey.autocomplete = 'off'; callbackKey.setAttribute('aria-label', 'Callback API key');
  const setupCallbacks = button('Connect callbacks', () => act(async () => {
    const file = envFile.value.trim(), apiKey = callbackKey.value.trim();
    if (!file && !apiKey) throw Error('Choose an environment file or enter a callback API key.');
    if (file && !/^(?:[A-Za-z]:[\\/]|\\\\|\/)/.test(file)) throw Error('Use an absolute environment file path.');
    await setupRuntime('webhook', { webhook: { ...(file ? { envFileRef: file } : {}), ...(apiKey ? { apiKey } : {}) } }); callbackKey.value = '';
  }));
  callbackSetup.append(field('Environment file', envFile), field('API key (optional)', callbackKey), el('p', 'Credentials stay in the local runtime. The saved connection is also available in MCP servers.', 'security-meta'), setupCallbacks);
  connections.append(runtimeStatus, localSettings, runtimeActions, restartRow, field('Callbacks', callbackConnection), zapRow, saveConnections, callbackSetup); main.append(connections);
  let integrations = { localAccessEnabled: false, connections: [] };
  const runs = el("section", null, "card security-card"), runList = el("div"); runs.append(el("h2", "Runs"), runList);
  const result = el("section", null, "card security-card security-results"); result.hidden = true;
  const resultHeading = el("h2", "Findings"), resultList = el("div"), resultNotice = el("p", "", "security-meta"), more = button("Load more", () => act(() => loadFindings(selectedRun, true)));
  result.append(button("Close results", () => { result.hidden = true; selectedRun = null; }), resultHeading, resultNotice, resultList, more);
  const history = el("details", null, "security-advanced"), historyList = el("div"); history.append(el("summary", "Earlier runs"), historyList); history.hidden = true;
  const capabilities = el("details", null, "security-advanced"), capabilityList = el("div"); capabilities.append(el("summary", "Capabilities and coverage"), capabilityList);
  const attribution = el("footer", null, "security-meta security-attribution");
  for (const [name, file] of [["Third-party notices", "../security/third-party-notices.json"], ["PTK license", "../security/ptk/LICENSE-PTK.txt"], ["Local runtime notices", "../tools/security/runtime/THIRD_PARTY_NOTICES.md"]]) {
    if (attribution.childNodes.length) attribution.append(document.createTextNode(" · "));
    const link = el("a", name); link.href = new URL(file, import.meta.url).href; link.target = "_blank"; link.rel = "noopener noreferrer"; attribution.append(link);
  }
  root.replaceChildren(header, main, notice, runs, result, history, capabilities, attribution);
  fillOptions({ preset: "thorough", ...PRESETS.thorough });

  function message(text, error = false) { notice.textContent = text; notice.classList.toggle("security-error", error); notice.setAttribute("role", error ? "alert" : "status"); }
  function workspaceId() { return state.workspaceId || state.workspace?.id || state.config?.workspaceId || null; }
  function update() {
    start.disabled = busy || !session || !target.value || !engines.size;
    for (const input of [target, account, preset, strategy, controls, rate, concurrency, planning, maxRequests, duration, ...Object.values(acquisitionInputs), ...Object.values(acquisitionLimitInputs), ...toggles, saveDefault, limitSave, limitScope, limitRate, limitConcurrency, limitRequests, limitDuration, refresh, checkRuntime, restartRuntime, callbackConnection, zapToggle, saveConnections, envFile, callbackKey]) input.disabled = busy;
    for (const control of [setupBrowser, setupZap, setupCallbacks]) control.disabled = busy || !integrations.localAccessEnabled;
    saveWorkspace.disabled = busy || !workspaceId();
    const workspaceOption = [...limitScope.options].find(option => option.value === "workspace"); if (workspaceOption) workspaceOption.disabled = !workspaceId();
    if (!workspaceId() && limitScope.value === "workspace") limitScope.value = "global";
    if (!session && !notice.textContent) message("Open a chat to start testing. You can still edit defaults.");
  }
  async function act(fn) { if (busy || disposed) return; busy = true; message(""); update(); try { await fn(); } catch (error) { message(error.message, true); } finally { busy = false; if (!disposed) update(); } }
  async function loadConnections() {
    integrations = await send('integrations', { session });
    callbackConnection.replaceChildren(new Option('Not connected', ''));
    for (const connection of list(integrations.connections)) callbackConnection.append(new Option(connection.label || connection.id, connection.id));
    if (integrations.oastConnectionId && !list(integrations.connections).some(item => item.id === integrations.oastConnectionId)) callbackConnection.append(new Option('Saved connection unavailable', integrations.oastConnectionId));
    callbackConnection.value = integrations.oastConnectionId || ''; zapToggle.setAttribute('aria-checked', String(integrations.zapEnabled === true)); zapToggle.classList.toggle('is-on', integrations.zapEnabled === true);
    if (!integrations.localAccessEnabled) runtimeStatus.textContent = 'Local computer access is off.'; update();
  }
  function renderRuntime(value) {
    if (value?.needsRestart) { runtimeStatus.textContent = value.reason || 'Close active local operations, then reconnect to apply the runtime update.'; return; }
    if (!value?.ready) { runtimeStatus.textContent = value?.needsUpdate ? 'Update local runtime from Local computer settings.' : value?.reason || 'Local runtime unavailable.'; return; }
    const parts = value.components || {}, browserReady = parts.node?.ready && parts.chromium?.ready, zapReady = parts.zap?.ready && parts.jre?.ready;
    runtimeStatus.textContent = ['Runtime connected', 'Browser: ' + (browserReady ? 'ready' : 'setup needed'), 'ZAP: ' + (zapReady ? 'ready' : 'setup needed'), 'Callbacks: ' + (parts.webhook?.ready ? 'ready' : 'setup needed')].join(' · ');
  }
  async function setupRuntime(component, options = {}) {
    runtimeStatus.textContent = 'Setting up ' + (component === 'webhook' ? 'callbacks' : component === 'zap' ? 'ZAP' : 'the browser') + '…';
    cancelSetup.hidden = false; cancelSetup.disabled = false;
    try { const result = await send('local_setup', { session, components: [component], options }); renderRuntime(result.runtime); await loadConnections(); message(component === 'webhook' ? 'Callback connection saved.' : 'Local runtime updated.'); }
    catch (error) { runtimeStatus.textContent = /cancel/i.test(error.message) ? 'Setup cancelled.' : 'Setup failed.'; throw error; }
    finally { cancelSetup.hidden = true; }
  }
  function options() { return { preset: preset.value, scanStrategy: strategy.value, scanControlProfile: controls.value, runCve: cv.getAttribute("aria-checked") === "true", maxRequestsPerSecond: numeric(rate), concurrency: numeric(concurrency), planningConcurrency: numeric(planning), maxRequests: numeric(maxRequests, true), durationSeconds: numeric(duration, true), acquisition: acquisitionValue(acquisitionInputs) }; }
  function fillOptions(value) {
    const config = { ...PRESETS[value?.preset || "thorough"], ...value }; preset.value = config.preset || "thorough";
    strategy.value = config.scanStrategy || config.dastScanStrategy || "COMPREHENSIVE"; controls.value = config.scanControlProfile || "wide";
    for (const [input, key] of [[rate, "maxRequestsPerSecond"], [concurrency, "concurrency"], [planning, "planningConcurrency"], [maxRequests, "maxRequests"], [duration, "durationSeconds"]]) input.value = config[key] == null ? "" : String(config[key]);
    for (const [key, , scale] of ACQUISITION_FIELDS) acquisitionInputs[key].value = String((config.acquisition?.[key] ?? ACQUISITION_DEFAULTS[key]) / scale);
    cv.setAttribute("aria-checked", String(config.runCve !== false)); cv.classList.toggle("is-on", config.runCve !== false);
  }
  function fillLimits() {
    const values = limitScope.value === "workspace" ? state.settings?.workspaces?.[workspaceId()]?.limits || {} : state.settings?.limits || {};
    for (const [input, key] of [[limitRate, "maxRequestsPerSecond"], [limitConcurrency, "concurrency"], [limitRequests, "maxRequests"], [limitDuration, "durationSeconds"]]) input.value = values[key] == null ? "" : String(values[key]);
    for (const [key, , scale] of ACQUISITION_FIELDS) acquisitionLimitInputs[key].value = values.acquisition?.[key] == null ? '' : String(values.acquisition[key] / scale);
  }
  preset.onchange = () => { const requests = maxRequests.value, seconds = duration.value, acquisition = acquisitionValue(acquisitionInputs); fillOptions({ preset: preset.value, ...PRESETS[preset.value], acquisition }); maxRequests.value = requests; duration.value = seconds; };
  limitScope.onchange = fillLimits;
  async function saveSettings(workspace) { await send("configure", { session, scope: workspace ? "workspace" : "global", ...(workspace ? { workspaceId: workspaceId() } : {}), defaults: options() }); await loadState(); message(workspace ? "Workspace defaults saved." : "Defaults saved."); }
  async function saveLimits() {
    await send("configure", { session, scope: limitScope.value, ...(limitScope.value === "workspace" ? { workspaceId: workspaceId() } : {}), limits: { maxRequestsPerSecond: numeric(limitRate, true), concurrency: numeric(limitConcurrency, true), maxRequests: numeric(limitRequests, true), durationSeconds: numeric(limitDuration, true), acquisition: acquisitionValue(acquisitionLimitInputs, true) } });
    await loadState(); message("Limits saved.");
  }
  async function loadTabs() {
    const old = target.value; const value = await send("tabs", { session }); if (!Array.isArray(value)) throw Error("Target page list is unavailable."); tabs = value; target.replaceChildren();
    for (const tab of tabs) { const option = el("option", (tab.title || tab.url || tab.origin) + (tab.origin ? " · " + tab.origin : "")); option.value = tab.tabId; target.append(option); }
    if (tabs.some(tab => String(tab.tabId) === old)) target.value = old;
    else if (tabs.length) target.value = String((tabs.find(tab => tab.working) || tabs.find(tab => tab.active) || tabs[0]).tabId);
    else { target.append(new Option("Open an HTTP or HTTPS page", "")); }
  }
  async function startScan() {
    const tab = tabs.find(tab => String(tab.tabId) === target.value); if (!tab) throw Error("Choose a target page.");
    const run = await send("start", { session, tabId: tab.tabId, engines: [...engines], options: options(), ...(account.value ? { accountId: account.value } : {}) });
    if (!run?.runId || !run.state) throw Error("Scan start was not confirmed. Refresh runs before trying again.");
    await loadState(); message(dastCoverageText(run.coverage) || "Scan " + label(run.state).toLowerCase() + ".", ["error", "failed", "unknown", "incomplete"].includes(run.state));
  }
  async function runAction(op, run, report = {}) {
    if (op === "findings") return loadFindings(run);
    if (op === 'investigate') return loadCandidates(run);
    const value = await send(op, { session, runId: run.runId, ...(op === "export" ? report : {}) });
    if (op === "export") { const outputs = list(value?.reports || value?.outputs); message((outputs.length ? "Saved " + outputs.length + (outputs.length === 1 ? " report to Outputs." : " reports to Outputs.") : "No report files were saved.") + (list(value?.warnings).length ? " " + value.warnings.map(readable).join(" · ") : "")); }
    await loadState();
  }
  async function execute(capability, args, run) {
    return send('execute', { session, capability, arguments: args, ...(run?.tabId != null ? { tabId: run.tabId } : {}) });
  }
  async function loadCandidates(run, offset = 0, snapshotId = null) {
    const value = await execute('candidate', { action: 'list', runId: run.runId, offset, limit: 50, ...(snapshotId ? { snapshotId } : {}) }, run);
    selectedRun = run; result.hidden = false; resultHeading.textContent = 'Investigate · ' + (run.title || run.origin || 'Scan'); more.hidden = true;
    if (!offset) resultList.replaceChildren();
    resultNotice.textContent = coverageText(value.coverage);
    if (!list(value.candidates).length && !offset) resultList.append(el('p', 'No investigation candidates in this scan. Review findings and coverage for remaining gaps.', 'security-meta'));
    for (const candidate of list(value.candidates)) {
      const item = el('article', null, 'security-finding'), outcome = el('div');
      const reference = { runId: run.runId, candidateId: candidate.id, snapshotId: value.snapshotId };
      item.append(el('h3', candidate.title || candidate.name || candidate.id), el('p', [candidate.severity, candidate.status, candidate.routeKey].filter(Boolean).join(' · '), 'security-meta'), details('Candidate evidence', candidate));
      const display = (heading, data) => { const content = details(heading, data); content.open = true; outcome.replaceChildren(content); };
      const reproduce = el('details', null, 'security-advanced'); reproduce.append(el('summary', 'Reproduce in browser'));
      const browserSession = el('input'); browserSession.setAttribute('aria-label', 'Browser session'); browserSession.placeholder = 'Owned session ID';
      const browserUrl = el('input'); browserUrl.type = 'url'; browserUrl.setAttribute('aria-label', 'Reproduction target'); browserUrl.value = run.url || tabs.find(tab => tab.tabId === run.tabId)?.url || run.origin || '';
      const reproductionActions = el('div', null, 'security-actions');
      reproductionActions.append(button('Create isolated browser', () => act(async () => {
        if (!browserUrl.value.trim()) throw Error('Choose the reproduction target.');
        const created = await execute('browser', { action: 'create', url: browserUrl.value.trim(), headless: false }, run);
        if (!created.sessionId) throw Error('Browser creation returned no session reference.');
        browserSession.value = created.sessionId; display('Browser session', created); await loadState();
      })), button('Reproduce candidate', () => act(async () => {
        if (!browserSession.value.trim()) throw Error('Create or choose an owned browser session first.');
        const started = await execute('candidate', { ...reference, action: 'reproduce', browserSessionId: browserSession.value.trim() }, run);
        display('Reproduction', started); await loadState();
        if (started.jobId && started.runId) {
          const jobs = el('div', null, 'security-actions');
          for (const [action, text] of [['status', 'Check reproduction'], ['stop', 'Stop reproduction']]) jobs.append(button(text, () => act(async () => { const response = await execute('candidate', { ...reference, action, executionRunId: started.runId, jobId: started.jobId }, run); display('Reproduction', response); outcome.append(jobs); await loadState(); })));
          outcome.append(jobs);
        }
      })));
      reproduce.append(field('Target', browserUrl), field('Browser session', browserSession), reproductionActions);
      const compare = el('details', null, 'security-advanced'); compare.append(el('summary', 'Compare accounts'));
      const choices = [['', 'Choose an account'], ...list(state.accounts).map(account => [account.accountId || account.id, account.label || account.name || account.id])];
      const baseline = select('Baseline account', choices), comparison = select('Comparison account', choices);
      compare.append(field('Baseline', baseline), field('Comparison', comparison), button('Compare candidate', () => act(async () => {
        if (!baseline.value || !comparison.value || baseline.value === comparison.value) throw Error('Choose two different verified accounts.');
        display('Account comparison', await execute('candidate', { ...reference, action: 'compare', execute: true, baselineSessionProfileId: baseline.value, comparisonSessionProfileId: comparison.value }, run)); await loadState();
      })));
      const evidenceActions = el('div', null, 'security-actions');
      evidenceActions.append(button('Save evidence package', () => act(async () => { display('Evidence package', await execute('evidencePackage', { ...reference, action: 'create' }, run)); await loadState(); })), button('Draft report', () => act(async () => { display('Report draft', await execute('evidencePackage', { ...reference, action: 'draft' }, run)); await loadState(); })));
      item.append(reproduce, compare, evidenceActions, outcome); resultList.append(item);
    }
    if (value.nextOffset != null) { const next = button('More candidates', () => act(async () => { next.remove(); await loadCandidates(run, value.nextOffset, value.snapshotId); })); resultList.append(next); }
  }
  async function loadFindings(run, append = false) {
    if (!run) return;
    const value = await send("findings", { session, runId: run.runId, offset: append ? nextOffset : 0, limit: 50 });
    if (disposed) return; selectedRun = run; result.hidden = false; resultHeading.textContent = "Findings · " + (run.title || run.origin || (run.engines || []).join(" + ") || "Scan");
    if (!append) resultList.replaceChildren();
    const findings = list(value?.findings || value?.items); if (!findings.length && !append) resultList.append(el("p", "No findings returned. Check coverage before drawing conclusions.", "security-meta"));
    for (const finding of findings) {
      const item = el("article", null, "security-finding"); item.append(el("h3", finding.title || finding.name || finding.ruleName || finding.id || "Finding"), el("p", [finding.engine, finding.severity, finding.confidence, findingAssessment(finding)].filter(Boolean).map(readable).join(" · "), "security-meta"));
      if (finding.url || finding.location) item.append(el("p", readable(finding.url || finding.location), "security-meta"));
      item.append(details("Evidence and details", finding));
      if (finding.evidenceId) item.append(button("View full evidence", () => act(async () => { const evidence = await send("evidence", { session, runId: run.runId, evidenceId: finding.evidenceId }); const content = details("Full evidence", evidence); content.open = true; item.append(content); })));
      resultList.append(item);
    }
    nextOffset = value?.nextOffset ?? null; more.hidden = nextOffset == null; more.disabled = nextOffset == null;
    const warnings = [...list(value?.warnings), ...list(value?.coverage?.warnings)];
    resultNotice.textContent = warnings.map(readable).join(" · ");
    if (value?.coverage && !append) resultList.prepend(details("Coverage", value.coverage));
    if (value?.truncated && nextOffset == null) resultNotice.textContent += (resultNotice.textContent ? " · " : "") + "Preview shortened. Export for retained evidence.";
  }
  function renderRuns() {
    const records = list(state.runs), key = JSON.stringify(records); if (key === revision) return; revision = key;
    const focused = document.activeElement?.closest("[data-run]")?.dataset.run, action = document.activeElement?.dataset.action;
    const opened = new Set([...runList.querySelectorAll("[data-run] details[open]")].map(node => node.closest("[data-run]").dataset.run));
    runList.replaceChildren();
    for (const run of [...records].reverse()) {
      const card = el("article", null, "security-run"); card.dataset.run = run.runId;
      card.append(el("h3", run.title || run.origin || run.url || (run.engines || []).join(" + ") || "Scan"));
      const count = run.summary?.findingsCount ?? run.summary?.totalFindings ?? run.summary?.vulnsCount ?? (typeof run.summary?.findings === "number" ? run.summary.findings : null);
      card.append(el("p", [label(run.state), (run.engines || []).join(" + "), Number.isFinite(count) ? count + (count === 1 ? " finding" : " findings") : null].filter(Boolean).join(" · "), "security-meta"));
      if (run.error) card.append(el("p", readable(run.error), "security-error"));
      const dastStatus = dastCoverageText(run.coverage); if (dastStatus) card.append(el('p', dastStatus, run.state === 'incomplete' || run.coverage?.dast?.phase === 'engine_error' ? 'security-error' : 'security-meta'));
      const scaStatus = scaCoverageText(run.coverage); if (scaStatus) card.append(el('p', scaStatus, 'security-meta'));
      const coverage = coverageText(run.coverage); if (coverage) card.append(el('p', coverage, 'security-meta'));
      const detail = details("Configuration and coverage", { config: run.config, coverage: run.coverage, warnings: run.warnings }); detail.open = opened.has(run.runId); card.append(detail);
      const row = el("div", null, "security-actions");
      const report = reportChoices.get(run.runId) || { format: "json", preset: "technical" };
      const format = select("Report format", [["json", "JSON"], ["pdf", "PDF"], ["markdown", "Markdown"]]); format.value = report.format; format.dataset.action = "format";
      const style = select("PDF report style", [["technical", "Technical report"], ["executive", "Executive summary"]]); style.value = report.preset; style.hidden = report.format !== "pdf"; style.dataset.action = "report-style";
      format.onchange = () => { report.format = format.value; reportChoices.set(run.runId, report); style.hidden = report.format !== "pdf"; };
      style.onchange = () => { report.preset = style.value; reportChoices.set(run.runId, report); };
      for (const [op, text] of [...(ACTIVE.has(run.state) || run.state === "unknown" ? [["stop", run.state === "stopping" ? "Stopping…" : "Stop"]] : []), ["findings", "Findings"], ...(run.kind === 'operation' ? [] : [["investigate", "Investigate"]]), ["export", "Export report"]]) {
        if (op === "export") row.append(format, style);
        const control = button(text, () => act(() => runAction(op, run, { format: report.format, ...(report.format === "pdf" ? { options: { preset: report.preset } } : {}) }))); control.dataset.action = op; control.disabled = op === "stop" && run.state === "stopping"; row.append(control);
      }
      card.append(row); runList.append(card);
    }
    if (!records.length) runList.append(el("p", session ? "No runs in this chat yet." : "Open a chat to view its runs.", "security-meta"));
    if (focused && action) [...runList.querySelectorAll("[data-run]")].find(node => node.dataset.run === focused)?.querySelector('[data-action="' + action + '"]')?.focus();
  }
  async function loadState(initial = false) {
    state = await send("state", { session }); if (disposed) return;
    if (initial) { fillOptions(state.config || { preset: "thorough", ...PRESETS.thorough }); fillLimits(); }
    const old = account.value; account.replaceChildren(new Option("Current browser session", ""));
    for (const item of list(state.accounts)) { const option = new Option([item.label || item.name || "Account", item.role].filter(Boolean).join(" · "), item.accountId || item.id); account.append(option); }
    if ([...account.options].some(option => option.value === old)) account.value = old;
    const catalogue = state.capabilities || {};
    if (catalogueRevision !== JSON.stringify(catalogue)) {
      catalogueRevision = JSON.stringify(catalogue); const open = !!capabilityList.querySelector("details[open]"); capabilityList.replaceChildren();
      for (const item of list(catalogue.unavailable || catalogue.blockers)) capabilityList.append(el("p", typeof item === "string" ? item : [item.name || item.id, item.reason].filter(Boolean).join(" · "), "security-meta"));
      const detail = details("Available capabilities", catalogue); detail.open = open; capabilityList.append(detail);
    }
    const earlier = list(state.history); history.hidden = !earlier.length;
    if (historyRevision !== JSON.stringify(earlier)) {
      historyRevision = JSON.stringify(earlier); historyList.replaceChildren();
      if (earlier.length) historyList.append(el("p", "Live evidence from earlier versions may be unavailable. Saved reports remain in Outputs.", "security-meta"));
      for (const record of [...earlier].reverse()) {
        const item = el("article", null, "security-run"); item.append(el("h3", record.title || record.origin || record.url || "Earlier run"), el("p", [label(record.state), list(record.engines).join(" + "), record.updatedAt ? new Date(record.updatedAt).toLocaleString() : null].filter(Boolean).join(" · "), "security-meta"));
        item.append(details("Retained details", { summary: record.summary, coverage: record.coverage, reports: record.reports, error: record.error })); historyList.append(item);
      }
    }
    renderRuns(); update();
  }
  async function openAccounts() {
    try {
      const panel = document.getElementById("authz-section"); if (!panel) throw Error("Account settings panel is missing.");
      root.hidden = true; panel.hidden = false;
      if (!panel.dataset.securityInitialized) { await (await import("./authz.js")).initAuthz({ config: state.config || {} }); panel.dataset.securityInitialized = "1"; const back = button("Back to security testing", () => { panel.hidden = true; root.hidden = false; void act(loadState); }); panel.prepend(back); }
    } catch (error) { root.hidden = false; message(error.message, true); }
  }
  async function poll() {
    if (disposed) return;
    try { if (!document.hidden && !busy && !root.hidden && session) { for (const run of list(state.runs).filter(run => ACTIVE.has(run.state))) await send("status", { session, runId: run.runId }); await loadState(); } }
    catch (error) { message(error.message, true); }
    finally { if (!disposed) timer = setTimeout(poll, 3000); }
  }
  const changed = (changes, area) => { if (area === "local" && !busy) { if (Object.keys(changes).some(key => /security|ptk_scans|authz/.test(key))) void loadState().catch(error => message(error.message, true)); if (changes.ki_security_integrations || changes.ki_native_settings) void loadConnections().catch(error => message(error.message, true)); } };
  chrome.storage.onChanged.addListener(changed);
  const setupProgress = (value, sender) => {
    if (value?.type !== 'KI_SECURITY_SETUP_PROGRESS' || sender.id !== chrome.runtime.id || cancelSetup.hidden) return;
    const progress = value.progress || {}; if (progress.type !== 'setup_progress') return;
    const percentage = Number.isFinite(progress.total) && progress.total > 0 && Number.isFinite(progress.bytes) ? ' · ' + Math.min(100, Math.floor(progress.bytes / progress.total * 100)) + '%' : '';
    runtimeStatus.textContent = (progress.phase === 'download' ? 'Downloading runtime' : 'Preparing runtime') + percentage;
  };
  chrome.runtime.onMessage.addListener(setupProgress);
  addEventListener("pagehide", () => { disposed = true; clearTimeout(timer); chrome.storage.onChanged.removeListener(changed); chrome.runtime.onMessage.removeListener(setupProgress); }, { once: true });
  try { await Promise.all([loadTabs(), loadState(true), loadConnections()]); } catch (error) { message(error.message, true); }
  update(); timer = setTimeout(poll, 3000);
  if (view === "accounts") await openAccounts();
}

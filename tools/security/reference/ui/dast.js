const ACTIVE = new Set(["starting", "running", "stopping", "unknown"]);
const CHECKS = [{ id: "xss", label: "Reflected XSS" }, { id: "sql_injection", label: "SQL errors" }, { id: "open_redirect", label: "Open redirect" }, { id: "sql_boolean", label: "Boolean SQLi" }, { id: "ssti", label: "Server-side template injection" }, { id: "jsonp_callback_injection", label: "JSONP callback control" }, { id: "response_checks", label: "Response checks", passive: true }];
const checkLabel = id => CHECKS.find(check => check.id === id)?.label || "Unknown check";
const fieldSupported = parameter => parameter.supported !== false && (parameter.location !== "json" || parameter.valueType === "string");
const fieldFamilies = parameter => fieldSupported(parameter) ? parameter.compatibleFamilies || ["xss"] : [];
const fieldLabel = parameter => (parameter.name || (parameter.location === "json" ? "(document root)" : "(empty name)")) + (parameter.location === "json" ? " · JSON pointer" + (parameter.valueType ? " · " + parameter.valueType : "") : " · " + parameter.location + " #" + (parameter.index + 1));
const node = (tag, text, className) => { const element = document.createElement(tag); if (text != null) element.textContent = text; if (className) element.className = className; return element; };
const text = (value, limit = 16000) => String(typeof value === "string" ? value : JSON.stringify(value, null, 2) || "").slice(0, limit);
function button(label, action, className = "") { const result = node("button", label, className); result.type = "button"; result.onclick = action; return result; }
function toggle(label, enabled, change) {
  const control = button("", () => { enabled = !enabled; draw(); change(enabled); }, "wb-toggle wb-toggle--sm");
  control.setAttribute("role", "switch"); control.setAttribute("aria-label", label); control.append(node("span", null, "wb-toggle-thumb"));
  function draw() { control.setAttribute("aria-checked", String(enabled)); control.classList.toggle("is-on", enabled); } control.setChecked = value => { enabled = value; draw(); }; draw(); return control;
}
async function request(op, args = {}) {
  const response = await chrome.runtime.sendMessage({ type: "KI_DAST", op, ...args });
  if (!response?.ok) throw Error(response?.error || "DAST request failed."); return response.result;
}
const parameterKey = value => JSON.stringify([value.location, value.name, value.index]);
function statusLabel(state) { return ({ starting: "Starting", running: "Running", stopping: "Stopping", completed: "Completed", cancelled: "Stopped", canceled: "Stopped", error: "Failed", failed: "Failed", incomplete: "Incomplete", unknown: "State unknown", interrupted: "Interrupted", budget_exhausted: "Request limit reached", auth_expired: "Authentication expired" })[state] || String(state || "Unknown").replaceAll("_", " "); }
function findingsView(container, result) {
  container.replaceChildren(); container.hidden = false;
  const sourceLabel = item => {
    const source = result.batch?.plan?.requests?.find(request => request.requestId === item.requestId);
    const endpoint = item.endpoint || source?.url || source?.endpoint;
    return endpoint ? [item.method || source?.method, endpoint].filter(Boolean).join(" ") : "Selected request";
  };
  container.append(button("Close findings", () => { container.hidden = true; }), node("p", "Candidates and reproduced behavior · impact still needs validation", "dast-meta"));
  for (const warning of [...new Set([...(result.warnings || []), ...(result.batch?.warnings || [])].map(value => text(value, 1200)))].slice(0, 20)) container.append(node("p", warning, "dast-meta"));
  const findings = Array.isArray(result.findings) ? result.findings : [];
  container.append(node("h2", "Findings"));
  if (!findings.length) container.append(node("p", "No findings returned. Review the batch outcome and coverage.", "dast-meta"));
  for (const finding of findings.slice(0, 100)) {
    const card = node("article", null, "dast-finding"), details = node("details");
    card.append(node("h3", text(finding.title || finding.name || finding.ruleName || "Finding", 300)));
    const classification = ({ reproduced_reflection: "Reproduced reflection", reproduced_sql_error: "Reproduced SQL error", reproduced_redirect: "Reproduced HTTP redirect", reproduced_boolean_difference: "Reproduced boolean difference", reproduced_template_evaluation: "Reproduced template evaluation" })[finding.classification] || (finding.family === "sql_injection" ? "SQL error candidate" : finding.family === "open_redirect" ? "Open redirect candidate" : "Candidate");
    const parameter = finding.parameter && typeof finding.parameter === "object" ? finding.parameter.location && Number.isInteger(finding.parameter.index) ? fieldLabel(finding.parameter) : finding.parameter.name || (finding.parameter.location === "json" ? "(document root)" : "(empty name)") : finding.parameter;
    card.append(node("p", [classification, finding.severity, parameter].filter(Boolean).map(value => text(value, 300)).join(" · "), "dast-meta"));
    if (finding.url) card.append(node("p", text(finding.url, 2000), "dast-url"));
    details.append(node("summary", "Baseline, mutation and confirmation"), node("pre", text(finding))); card.append(details); container.append(card);
  }
  const observations = Array.isArray(result.observations) ? result.observations : [];
  if (observations.length) {
    const section = node("section", null, "dast-observations"); section.append(node("h2", "Observations"), node("p", "Response behavior and configuration signals; these are separate from vulnerability findings.", "dast-meta"));
    for (const observation of observations.slice(0, 100)) {
      const card = node("article", null, "dast-finding"); card.append(node("h3", text(observation.title || "Observation", 300)));
      card.append(node("p", text(sourceLabel(observation), 2000), "dast-url dast-meta"));
      card.append(node("p", [checkLabel(observation.family), observation.classification === "callback_control" ? "Callback control" : null, observation.note].filter(Boolean).map(value => text(value, 1600)).join(" · "), "dast-meta")); section.append(card);
    }
    container.append(section);
  }
  const coverage = Array.isArray(result.coverage) ? result.coverage : [];
  if (coverage.length) {
    const section = node("section", null, "dast-coverage"); section.append(node("h2", "Coverage"), node("p", "Tested means the check completed for this request and field. It does not establish that the application is safe.", "dast-meta"));
    for (const item of coverage.slice(0, 200)) {
      const card = node("article", null, "dast-coverage-row"), state = ({ tested: "Tested", skipped: "Skipped", unsupported: "Unsupported", inconclusive: "Inconclusive" })[item.state] || "Unknown";
      const parameter = item.parameter && typeof item.parameter === "object" ? fieldLabel(item.parameter) : item.parameter || "Whole response";
      card.append(node("strong", [checkLabel(item.family), state].join(" · ")), node("p", [sourceLabel(item), parameter, Number.isFinite(item.probesSent) ? item.probesSent + " probes sent" : null].filter(Boolean).map(value => text(value, 2000)).join(" · "), "dast-meta"));
      if (item.reason) card.append(node("p", text(item.reason, 1600), "dast-meta")); section.append(card);
    }
    container.append(section);
  }
  if (result.truncated || findings.length > 100 || observations.length > 100 || coverage.length > 200) container.append(node("p", "Preview shortened. Export the report for retained evidence.", "dast-meta"));
}
export async function initDast() {
  const root = document.getElementById("dast-section"); if (!root) throw Error("DAST settings panel is missing."); root.classList.add("dast-root");
  if (!document.querySelector("link[data-dast-style]")) { const link = node("link"); link.rel = "stylesheet"; link.href = new URL("./dast.css", import.meta.url).href; link.dataset.dastStyle = ""; document.head.append(link); }
  const session = new URLSearchParams(location.search).get("session") || null;
  const header = node("header"); header.append(node("h1", "Test selected requests"), node("p", "Capture while browsing, then test only the requests and fields you choose."));
  const notice = node("p", "", "dast-notice"), scopeCard = node("section", null, "card dast-card"), captureCard = node("section", null, "card dast-card");
  notice.setAttribute("role", "status"); notice.setAttribute("aria-live", "polite");
  const tabs = node("select", null, "dast-tabs"); tabs.setAttribute("aria-label", "DAST target tab");
  const captureStatus = node("p", "", "dast-meta"), captureActions = node("div", null, "dast-actions");
  const capture = button("Capture requests", () => run(captureAction), "primary"), refresh = button("Refresh", () => run(async () => { await loadTabs(); await load(); }));
  captureActions.append(capture, refresh); captureCard.append(tabs, captureStatus, captureActions);
  const requestsCard = node("section", null, "card dast-card"), requestList = node("div", null, "dast-request-list"), requestHeading = node("h2", "Captured requests"), selectionCount = node("p", "", "dast-meta");
  const options = node("details", null, "dast-options"), maxRequests = node("input"), minutes = node("input");
  maxRequests.type = minutes.type = "number"; maxRequests.min = minutes.min = "1"; maxRequests.max = "100"; minutes.max = "5"; maxRequests.value = "100"; minutes.value = "5";
  maxRequests.setAttribute("aria-label", "Maximum DAST requests"); minutes.setAttribute("aria-label", "Maximum DAST duration in minutes");
  options.append(node("summary", "Test options"));
  for (const [label, control] of [["Request limit", maxRequests], ["Time limit (minutes)", minutes]]) { const row = node("label", null, "dast-setting-row"); row.append(node("span", label), control); options.append(row); }
  options.append(node("p", "1 request/second · one at a time. Baseline and confirmation requests count toward the limit.", "dast-meta"));
  const checks = node("div", null, "dast-checks"), checkControls = new Map(), selectedChecks = new Set(["xss"]);
  checks.append(node("h3", "Checks"));
  for (const check of CHECKS) {
    const row = node("div", null, "dast-setting-row"), control = toggle(check.label, selectedChecks.has(check.id), enabled => { if (enabled) selectedChecks.add(check.id); else selectedChecks.delete(check.id); invalidatePlan(); });
    row.append(node("span", check.label), control); checks.append(row); checkControls.set(check.id, control);
  }
  const checkHint = node("p", "", "dast-meta"); checks.append(checkHint);
  const prepare = button("Review test plan", () => run(preparePlan), "primary"); requestsCard.append(requestHeading, node("p", "Selected requests will be replayed. Choose only requests you intend to test.", "dast-meta"), requestList, selectionCount, checks, options, prepare);
  const planCard = node("section", null, "card dast-card dast-plan"), planBody = node("div"), planActions = node("div", null, "dast-actions"), start = button("Run tests", () => run(runPlan), "primary");
  planCard.hidden = true; planActions.append(button("Change selection", () => { invalidatePlan(); prepare.focus(); }), start); planCard.append(node("h2", "Test plan"), planBody, planActions);
  const batchesCard = node("section", null, "card dast-card"), batchesList = node("div"), results = node("section", null, "card dast-card dast-results");
  batchesCard.append(node("h2", "Batches"), batchesList); results.hidden = true;
  const setup = node("details", null, "dast-setup"), setupCommand = node("pre");
  setupCommand.textContent = "powershell -NoProfile -ExecutionPolicy Bypass -File .\\tools\\ptk\\build.ps1 -ExtensionId " + (chrome.runtime.id || "YOUR_EXTENSION_ID");
  setup.append(node("summary", "Set up targeted testing"), node("p", "Run from the cert-x repository to pair the prepared PTK companion with this extension, then reload PTK and cert-x.", "dast-meta"), setupCommand,
    button("Copy setup command", async () => { try { await navigator.clipboard.writeText(setupCommand.textContent); message("Setup command copied."); } catch { message("Select and copy the setup command above."); } }));
  root.replaceChildren(header, scopeCard, captureCard, requestsCard, planCard, notice, batchesCard, results, setup);
  let state = { requests: [], batches: [] }, tabList = [], plan = null, busy = false, disposed = false, timer, lastRequests = "", lastBatches = "", lastScope = "";
  const selections = new Map();
  const scopeReady = () => !!session && !!state.workspace && Array.isArray(state.scope?.origins) && state.scope.origins.length > 0;
  const chosenTab = () => tabList.find(tab => String(tab.tabId) === tabs.value);
  const activeBatch = () => (state.batches || []).some(batch => ACTIVE.has(batch.state));
  function message(value, error = false) { notice.textContent = value; notice.classList.toggle("dast-error", error); }
  async function run(action) { if (busy) return; busy = true; message(""); update(); try { await action(); } catch (error) { message(error.message, true); } finally { busy = false; update(); } }
  function invalidatePlan() { plan = null; planCard.hidden = true; update(); }
  function update() {
    const selected = [...selections.values()];
    for (const check of CHECKS) {
      const compatible = selected.length > 0 && selected.every(value => check.passive ? (state.requests.find(item => item.requestId === value.requestId)?.compatibleFamilies || []).includes(check.id) : [...value.parameters.values()].some(parameter => fieldFamilies(parameter).includes(check.id)));
      if (selected.length && !compatible && selectedChecks.delete(check.id)) { plan = null; planCard.hidden = true; }
      const control = checkControls.get(check.id); control.disabled = busy || !compatible; control.setChecked(selectedChecks.has(check.id));
      control.title = compatible ? "" : check.passive ? "Choose requests that support response checks." : "Choose a compatible field in every selected request.";
    }
    checkHint.textContent = !selected.length ? "Select requests to choose checks." : !selectedChecks.size ? "Choose response checks, or select compatible fields in every request for an active check." : selectedChecks.size === 1 && selectedChecks.has("response_checks") ? "Response checks replay selected requests without mutating inputs." : "Active checks need a compatible selected field in every request. Results still need validation.";
    capture.textContent = state.capture?.active ? "Stop capture" : "Capture requests";
    capture.disabled = busy || (!state.capture?.active && (!scopeReady() || !chosenTab() || !state.scope.origins.includes(chosenTab().origin)));
    tabs.disabled = busy || !!state.capture?.active || !tabList.length; refresh.disabled = busy;
    prepare.disabled = busy || !scopeReady() || !selected.length || !selectedChecks.size || activeBatch();
    start.disabled = busy || !scopeReady() || !plan || plan.state !== "prepared" || Date.now() >= plan.expiresAt || activeBatch();
    start.title = plan && Date.now() >= plan.expiresAt ? "This plan expired. Prepare a new plan." : "";
    maxRequests.disabled = minutes.disabled = busy;
    selectionCount.textContent = selected.length + (selected.length === 1 ? " request selected" : " requests selected");
    captureStatus.textContent = state.capture?.active ? "Capturing · browse the selected application to collect requests." : "Capture is off.";
    root.querySelectorAll(".dast-request button, .dast-request input, .dast-batch button").forEach(control => { control.disabled = busy || control.dataset.unavailable === "true"; });
  }
  function renderScope() {
    const signature = JSON.stringify([state.workspace, state.scope, session]); if (signature === lastScope) return; lastScope = signature; scopeCard.replaceChildren();
    scopeCard.append(node("h2", state.workspace?.name || "Workspace scope"));
    if (!session) scopeCard.append(node("p", "Open a Bug bounty chat to prepare a test batch.", "dast-meta"));
    else if (!scopeReady()) scopeCard.append(node("p", state.workspace ? "Add target origins to this workspace before capturing requests." : "Choose a workspace with a target scope before capturing requests.", "dast-meta"));
    else {
      scopeCard.append(node("p", state.scope.origins.join(" · "), "dast-url"));
      if (state.scope.excludePaths?.length) { const excluded = node("details"); excluded.append(node("summary", "Excluded paths"), node("pre", state.scope.excludePaths.join("\n"))); scopeCard.append(excluded); }
    }
    const link = node("a", "Manage workspace scope", "section-link"); link.href = "?section=workspaces" + (session ? "&session=" + encodeURIComponent(session) : "");
    if (new URLSearchParams(location.search).get("embed") === "1") link.onclick = event => { event.preventDefault(); parent.postMessage({ type: "settings-section", section: "workspaces" }, location.origin); };
    scopeCard.append(link);
  }
  function renderRequests() {
    const signature = JSON.stringify(state.requests || []); if (signature === lastRequests) return; lastRequests = signature;
    const focused = document.activeElement?.dataset?.dastFocus, opened = new Set([...requestList.querySelectorAll("details[open]")].map(element => element.dataset.requestId));
    requestList.replaceChildren();
    let selectionChanged = false;
    for (const [id, choice] of selections) {
      const item = (state.requests || []).find(item => item.requestId === id);
      if (!item || item.supported === false) { selections.delete(id); selectionChanged = true; continue; }
      for (const [key, previous] of choice.parameters) {
        const current = item.parameters?.find(parameter => parameterKey(parameter) === key);
        if (!current || !fieldSupported(current)) { choice.parameters.delete(key); selectionChanged = true; }
        else { if (JSON.stringify(previous) !== JSON.stringify(current)) selectionChanged = true; choice.parameters.set(key, current); }
      }
    }
    if (selectionChanged) { plan = null; planCard.hidden = true; }
    for (const item of state.requests || []) {
      const row = node("article", null, "dast-request"), head = node("div", null, "dast-request-head"), description = node("div");
      description.append(node("strong", item.method + " " + item.url), node("small", [item.statusCode ? "HTTP " + item.statusCode : null, item.reason].filter(Boolean).join(" · ")));
      const eligible = item.supported !== false && (item.parameters?.some(fieldSupported) || item.compatibleFamilies?.includes("response_checks"));
      const select = button(selections.has(item.requestId) ? "Selected" : "Select", () => {
        if (selections.has(item.requestId)) selections.delete(item.requestId);
        else selections.set(item.requestId, { requestId: item.requestId, parameters: new Map((item.parameters || []).filter(fieldSupported).map(parameter => [parameterKey(parameter), parameter])), allowReplay: true });
        invalidatePlan(); lastRequests = ""; renderRequests(); update();
      });
      select.setAttribute("aria-label", "Select " + item.method + " " + item.url); select.setAttribute("aria-pressed", String(selections.has(item.requestId))); select.dataset.dastFocus = item.requestId + ":select";
      select.disabled = !eligible; select.dataset.unavailable = String(!eligible); head.append(description, select); row.append(head);
      if (selections.has(item.requestId)) {
        const choice = selections.get(item.requestId), detail = node("details"); detail.dataset.requestId = item.requestId; detail.open = opened.has(item.requestId); detail.append(node("summary", "Fields to test"));
        if (!(item.parameters || []).some(fieldSupported)) detail.append(node("p", "No selectable inputs. Choose Response checks to inspect this request's response.", "dast-meta"));
        for (const parameter of item.parameters || []) {
          const key = parameterKey(parameter), field = node("div", null, "dast-setting-row"), label = fieldLabel(parameter);
          const control = toggle("Test " + label, choice.parameters.has(key), enabled => { if (enabled) choice.parameters.set(key, parameter); else choice.parameters.delete(key); invalidatePlan(); }); control.dataset.dastFocus = item.requestId + ":" + key;
          control.dataset.unavailable = String(!fieldSupported(parameter)); control.disabled = !fieldSupported(parameter);
          field.append(node("span", label), control); detail.append(field);
          if (parameter.reason) detail.append(node("p", parameter.reason, "dast-meta"));
        }
        if (item.requiresReplayConsent) {
          const replay = node("div", null, "dast-setting-row"), control = toggle("Allow replay of " + item.method + " " + item.url, choice.allowReplay, enabled => { choice.allowReplay = enabled; invalidatePlan(); });
          control.dataset.dastFocus = item.requestId + ":replay"; replay.append(node("span", "Allow replay of this request"), control); detail.append(replay, node("p", "This request may change application state.", "dast-meta")); detail.open = true;
        }
        row.append(detail);
      }
      requestList.append(row);
    }
    if (!requestList.children.length) requestList.append(node("p", "No captured requests yet.", "dast-meta"));
    if (focused) [...requestList.querySelectorAll("[data-dast-focus]")].find(control => control.dataset.dastFocus === focused)?.focus();
  }
  function renderPlan() {
    planBody.replaceChildren(); planCard.hidden = !plan; if (!plan) return;
    planBody.append(node("p", (plan.requests || []).length + " requests · " + (plan.families || ["xss"]).map(checkLabel).join(" · "), "dast-meta"));
    const budget = plan.budget || {}; planBody.append(node("p", `${budget.maxRequests} requests maximum · ${budget.maxRequestsPerSecond}/second · ${Math.ceil(budget.durationSeconds / 60)} minutes`, "dast-meta"));
    planBody.append(node("p", "Scope: " + (plan.scope?.origins || []).join(" · "), "dast-url"));
    if (plan.scope?.excludePaths?.length) { const excluded = node("details"); excluded.append(node("summary", "Excluded paths"), node("pre", plan.scope.excludePaths.join("\n"))); planBody.append(excluded); }
    for (const item of plan.requests || []) {
      const summary = node("div", null, "dast-plan-request"); summary.append(node("strong", item.method + " " + item.url));
      summary.append(node("p", (item.parameters || []).map(fieldLabel).join(", "), "dast-meta"));
      if (item.allowReplay) summary.append(node("small", "Request replay selected")); planBody.append(summary);
    }
    planBody.append(node("p", "Prepared from the selected captured requests. Changing the selection requires a new plan.", "dast-meta"));
    if (Number.isFinite(plan.expiresAt)) planBody.append(node("p", "Expires " + new Date(plan.expiresAt).toLocaleTimeString(), "dast-meta"));
  }
  function renderBatches() {
    const list = state.batches || [], signature = JSON.stringify(list); if (signature === lastBatches) return; lastBatches = signature;
    const focused = document.activeElement?.dataset?.dastBatchFocus; batchesList.replaceChildren();
    for (const batch of list.slice().reverse()) {
      const row = node("article", null, "dast-batch"), actions = node("div", null, "dast-actions"); row.append(node("h3", (batch.families?.length ? batch.families.map(checkLabel).join(" · ") : "DAST") + " batch"));
      row.append(node("p", [statusLabel(batch.state), Number.isFinite(batch.requestsSent) ? batch.requestsSent + " requests sent" : null, batch.inFlight > 0 ? batch.inFlight + " in flight" : null, Number.isFinite(batch.findingsCount) ? batch.findingsCount + " candidates" : null].filter(Boolean).join(" · "), "dast-meta"));
      for (const value of [batch.error, batch.reason, ...(batch.errors || []), ...(batch.warnings || [])].filter(Boolean).slice(0, 10)) row.append(node("p", text(value, 1000), "dast-meta"));
      for (const [op, label] of [["stop", batch.state === "stopping" ? "Stopping…" : "Stop"], ["findings", "Findings"], ["export", "Export report"]]) {
        if (op === "stop" && !ACTIVE.has(batch.state)) continue;
        const control = button(label, () => run(() => batchAction(op, batch))); control.dataset.dastBatchFocus = batch.batchId + ":" + op;
        control.dataset.unavailable = String((op === "stop" && batch.state === "stopping") || (op === "export" && ACTIVE.has(batch.state)));
        control.disabled = busy || control.dataset.unavailable === "true"; actions.append(control);
      }
      row.append(actions); batchesList.append(row);
    }
    if (!list.length) batchesList.append(node("p", "No test batches yet.", "dast-meta"));
    if (focused) [...batchesList.querySelectorAll("[data-dast-batch-focus]")].find(control => control.dataset.dastBatchFocus === focused)?.focus();
  }
  async function load() {
    state = session ? await request("state", { session }) : { requests: [], batches: [] };
    if (plan && JSON.stringify(plan.scope) !== JSON.stringify(state.scope)) { invalidatePlan(); message("Workspace scope changed. Prepare a new plan."); }
    if (disposed) return; renderScope(); renderRequests(); renderBatches(); update();
  }
  async function loadTabs() {
    const selected = tabs.value; tabList = await request("tabs", { session }); tabs.replaceChildren();
    for (const item of tabList) { const option = node("option", item.title + " · " + item.origin); option.value = item.tabId; tabs.append(option); }
    if (tabList.some(item => String(item.tabId) === selected)) tabs.value = selected;
    else if (tabList.length) tabs.value = String((tabList.find(item => item.working) || tabList.find(item => item.active) || tabList[0]).tabId);
    if (!tabList.length) { const option = node("option", "Open an HTTP or HTTPS page first"); option.value = ""; tabs.append(option); } update();
  }
  async function captureAction() {
    const target = chosenTab();
    await request("capture", { session, action: state.capture?.active ? "stop" : "start", ...(state.capture?.active ? {} : { tabId: target.tabId, expectedOrigin: target.origin }) });
    invalidatePlan(); await load();
  }
  async function preparePlan() {
    const count = Number(maxRequests.value), seconds = Number(minutes.value) * 60;
    if (!Number.isInteger(count) || count < 1 || count > 100 || !Number.isInteger(Number(minutes.value)) || seconds < 60 || seconds > 300) throw Error("Choose 1–100 requests and 1–5 minutes.");
    const selected = (state.requests || []).filter(item => selections.has(item.requestId)).map(item => {
      const value = selections.get(item.requestId);
      if (item.requiresReplayConsent && !value.allowReplay) throw Error("Select Allow replay for " + item.method + " " + item.url + " before preparing the batch.");
      return { requestId: item.requestId, parameters: [...value.parameters.values()].map(({ location, name, index }) => ({ location, name, index })), allowReplay: value.allowReplay };
    });
    if (!selectedChecks.size) throw Error("Choose at least one compatible check.");
    const prepared = await request("prepare", { session, requests: selected, budget: { maxRequests: count, maxRequestsPerSecond: 1, concurrency: 1, durationSeconds: seconds }, families: CHECKS.filter(check => selectedChecks.has(check.id)).map(check => check.id) });
    if (typeof prepared?.planId !== "string" || typeof prepared.planHash !== "string" || prepared.state !== "prepared") throw Error(prepared?.error || "The test plan was not prepared.");
    plan = prepared; renderPlan();
  }
  async function runPlan() {
    const selectedPlan = plan; if (!selectedPlan) return;
    invalidatePlan();
    try {
      const batch = await request("run", { session, planId: selectedPlan.planId, planHash: selectedPlan.planHash });
      if (!batch?.batchId || !batch.state) throw Error(batch?.error || "The batch start was not confirmed.");
      message("Batch " + statusLabel(batch.state).toLowerCase() + "." + (batch.error ? " " + batch.error : ""), ["error", "failed", "unknown"].includes(batch.state));
    } finally { await load(); }
  }
  async function batchAction(op, batch) {
    const value = await request(op, { session, batchId: batch.batchId });
    if (op === "findings") findingsView(results, value);
    if (op === "export") message(value.reports?.length ? "Saved " + value.reports.length + (value.reports.length === 1 ? " report to Outputs." : " reports to Outputs.") : "No report files were saved.");
    await load();
  }
  tabs.onchange = () => { invalidatePlan(); update(); };
  maxRequests.oninput = minutes.oninput = invalidatePlan;
  const changed = (changes, area) => { if (area === "local" && (changes.ki_dast_batches || changes.ki_contexts)) void load().catch(error => message(error.message, true)); };
  const poll = async () => {
    if (disposed) return;
    try {
      if (!document.hidden && !busy) {
        for (const batch of (state.batches || []).filter(batch => ACTIVE.has(batch.state))) await request("status", { session, batchId: batch.batchId });
        if (state.capture?.active || activeBatch()) await load();
        update();
      }
    } catch (error) { message(error.message, true); }
    timer = setTimeout(poll, 3000);
  };
  const visible = () => { if (!document.hidden) void run(async () => { await loadTabs(); await load(); }); };
  chrome.storage.onChanged.addListener(changed); document.addEventListener("visibilitychange", visible);
  window.addEventListener("pagehide", () => { disposed = true; clearTimeout(timer); chrome.storage.onChanged.removeListener(changed); document.removeEventListener("visibilitychange", visible); }, { once: true });
  try { await load(); await loadTabs(); } catch (error) { message(error.message, true); } finally { update(); }
  timer = setTimeout(poll, 3000);
}

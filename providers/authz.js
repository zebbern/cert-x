const ACTIVE = new Set(["starting", "running", "stopping", "unknown"]);
const LABELS = { expected_access: "Expected access", expected_denial: "Expected denial", unexpected_access: "Unexpected access", inconclusive: "Inconclusive", verified: "Verified", unknown: "State unknown", running: "Running", starting: "Starting", stopping: "Stopping", stopped: "Stopped", completed: "Completed", failed: "Failed" };
const label = value => LABELS[value] || String(value || "Unknown").replaceAll("_", " ");
const el = (tag, value, cls) => { const node = document.createElement(tag); if (value != null) node.textContent = value; if (cls) node.className = cls; return node; };
const btn = (text, action, cls) => { const node = el("button", text, cls); node.type = "button"; node.onclick = action; return node; };
const input = (name, value = "") => { const node = el("input"); node.type = "text"; node.value = value; node.setAttribute("aria-label", name); node.autocomplete = "off"; return node; };
const select = name => { const node = el("select"); node.setAttribute("aria-label", name); return node; };
function row(name, control) { const node = el("label", null, "authz-field"); node.append(el("span", name), control); return node; }
function toggle(name, value, change) { const node = btn("", () => { value = !value; draw(); change(value); }, "wb-toggle wb-toggle--sm"); node.setAttribute("role", "switch"); node.setAttribute("aria-label", name); node.append(el("span", null, "wb-toggle-thumb")); function draw() { node.setAttribute("aria-checked", String(value)); node.classList.toggle("is-on", value); } node.setChecked = next => { value = next; draw(); }; draw(); return node; }
function options(control, values, placeholder) { const previous = control.value; control.replaceChildren(); if (placeholder) { const item = el("option", placeholder); item.value = ""; control.append(item); } for (const [value, text] of values) { const item = el("option", text); item.value = value; control.append(item); } if (values.some(([value]) => value === previous)) control.value = previous; }
const endpoint = item => item.method + " " + (item.url || item.endpoint || "");
const safeText = value => String(typeof value === "string" ? value : JSON.stringify(value, null, 2) || "").slice(0, 12000);
const validPointer = value => (value === "" || value.startsWith("/")) && !/~(?![01])/.test(value);

export async function initAuthz({ config = {} } = {}) {
  const root = document.getElementById("authz-section"); if (!root) throw Error("Compare accounts panel is missing."); root.classList.add("authz-root");
  if (!document.querySelector("link[data-authz-style]")) { const style = el("link"); style.rel = "stylesheet"; style.href = new URL("./authz.css", import.meta.url).href; style.dataset.authzStyle = ""; document.head.append(style); }
  const session = new URLSearchParams(location.search).get("session");
  let state = { accounts: [], captures: [], batches: [] }, tabs = [], cases = [], plan = null, busy = false, disposed = false, timer, readOnly = false, probeReadOnly = false, lastSignature = "", lastCredentialSource = "";
  const credentials = { headers: new Set(), cookies: new Set() }, expectations = new Map();
  async function api(op, args = {}, type = "KI_AUTHZ") { const response = await chrome.runtime.sendMessage({ type, op, session, ...args }); if (!response?.ok) throw Error(response?.error || "Account comparison failed."); return response.result; }
  const header = el("header"); header.append(el("h1", "Compare accounts"), el("p", "Verify accounts, choose a read request, and compare the access you expect."));
  const notice = el("p", "", "authz-notice"); notice.setAttribute("role", "status"); notice.setAttribute("aria-live", "polite");
  const scope = el("section", null, "card authz-card"), captureCard = el("section", null, "card authz-card"), target = select("Capture target tab");
  const capture = btn("Capture requests", () => run(async () => { const tab = tabs.find(item => String(item.tabId) === target.value); await api("capture", { action: state.capture?.active ? "stop" : "start", ...(state.capture?.active ? {} : { tabId: tab.tabId, expectedOrigin: tab.origin }) }, "KI_DAST"); await load(); }), "primary");
  const captureActions = el("div", null, "authz-actions"); captureActions.append(capture, btn("Refresh", () => run(async () => { await loadTabs(); await load(); }))); captureCard.append(el("h2", "Capture"), target, el("p", "Capture an identity response and the read requests you want to compare while signed in.", "authz-meta"), captureActions);
  const accountsCard = el("section", null, "card authz-card"), accountList = el("div"), accountForm = el("details"), probe = select("Identity request"), accountName = input("Account label"), expectedIdentity = input("Expected account ID"), identityPointer = input("Account ID JSON pointer", "/id");
  const accountRole = input("Account role"), accountTenant = input("Account tenant"), credentialFields = el("div"), accountAdvanced = el("details");
  const probeConsent = toggle("Identity request is read-only", false, value => { probeReadOnly = value; });
  accountAdvanced.append(el("summary", "Account details and credentials"), row("Role (optional)", accountRole), row("Tenant (optional)", accountTenant), credentialFields);
  const saveAccount = btn("Save account", () => run(async () => {
    if (!probe.value || !accountName.value.trim() || !expectedIdentity.value || !validPointer(identityPointer.value)) throw Error("Choose an identity request and enter its account label, JSON pointer and expected account ID.");
    if (!probeReadOnly) throw Error("Declare the identity request read-only before saving.");
    await api("save_account", { requestId: probe.value, label: accountName.value.trim(), ...(accountRole.value ? { role: accountRole.value } : {}), ...(accountTenant.value ? { tenant: accountTenant.value } : {}), credentialHeaders: [...credentials.headers], cookieNames: [...credentials.cookies], claims: [{ pointer: identityPointer.value, expected: expectedIdentity.value }], readOnly: true });
    invalidate(); expectedIdentity.value = ""; accountName.value = ""; accountForm.open = false; probeReadOnly = false; probeConsent.setChecked(false); await load(); message("Account saved. Verify it before preparing a comparison.");
  }), "primary");
  accountForm.open = true; accountForm.append(el("summary", "Add account"), row("Identity request", probe), row("Label", accountName), row("Account ID JSON pointer", identityPointer), row("Expected account ID", expectedIdentity), row("Identity request is read-only", probeConsent), accountAdvanced, saveAccount);
  accountsCard.append(el("h2", "Accounts"), accountList, accountForm);
  const caseCard = el("section", null, "card authz-card"), caseForm = el("details"), captured = select("Read request"), owner = select("Request owner"), objectPointer = input("Object JSON pointer", "/id"), expectedObject = input("Expected object value"), protectedPointer = input("Protected JSON pointer", "/secret"), expectedProtected = input("Expected protected value");
  const consent = toggle("Request is read-only", false, value => { readOnly = value; invalidate(); }), matrix = el("div", null, "authz-matrix"), caseList = el("div");
  const swapDetails = el("details"), swapLocation = select("Object replacement location"), swapName = input("Object replacement name or JSON pointer"), swapIndex = input("Object replacement index", "0"), swapValue = input("Object replacement value");
  options(swapLocation, [["", "No replacement"], ["path", "Path segment"], ["query", "Query field"], ["form", "Form field"], ["json", "JSON field"]]); swapIndex.type = "number"; swapIndex.min = "0"; swapIndex.step = "1";
  swapDetails.append(el("summary", "Replace one object ID"), el("p", "Optional explicit replacement. Index starts at zero; JSON names use JSON Pointer.", "authz-meta"), row("Location", swapLocation), row("Name or JSON pointer", swapName), row("Index", swapIndex), row("Value", swapValue));
  const addCase = btn("Add request case", () => run(async () => {
    if (!captured.value || !owner.value || !readOnly) throw Error("Choose a request and owner, then declare the request read-only.");
    if (!validPointer(objectPointer.value) || !validPointer(protectedPointer.value) || objectPointer.value === protectedPointer.value || !expectedObject.value || !expectedProtected.value.trim()) throw Error("Enter distinct object and protected JSON pointers with expected values.");
    if (cases.length >= 10) throw Error("A comparison can contain up to 10 request cases.");
    const selected = [...expectations].filter(([, expected]) => expected).map(([accountId, expected]) => ({ accountId, expected }));
    if (!selected.length) throw Error("Choose the expected access for at least one account.");
    const value = { requestId: captured.value, ownerAccountId: owner.value, readOnly: true, evidence: { object: { pointer: objectPointer.value, expected: expectedObject.value }, protected: { pointer: protectedPointer.value, expected: expectedProtected.value } }, expectations: selected };
    if (swapLocation.value) { const index = Number(swapIndex.value); if (!Number.isInteger(index) || index < 0 || !swapValue.value) throw Error("Enter a replacement value and a nonnegative field index."); value.objectSwap = { location: swapLocation.value, name: swapName.value, index, value: swapValue.value }; }
    cases.push(value); invalidate(); renderCases(); caseForm.open = false; readOnly = false; consent.setChecked(false); expectedObject.value = expectedProtected.value = swapValue.value = ""; swapLocation.value = ""; message("Request case added.");
  }));
  caseForm.open = true; caseForm.append(el("summary", "Add read request"), row("Read request", captured), row("Owner", owner), row("Request is read-only", consent), row("Object JSON pointer", objectPointer), row("Expected object value", expectedObject), row("Protected JSON pointer", protectedPointer), row("Expected protected value", expectedProtected), el("p", "Use an application-specific protected value. Expected values stay private.", "authz-meta"), matrix, swapDetails, addCase);
  caseCard.append(el("h2", "Requests and expected access"), caseForm, caseList);
  const limits = el("details"), maxRequests = input("Maximum comparison requests", String(config.maxRequests || 100)), minutes = input("Maximum comparison minutes", String(config.durationSeconds ? config.durationSeconds / 60 : 5)), rate = input("Comparison requests per second", String(config.maxRequestsPerSecond || 5));
  maxRequests.type = minutes.type = rate.type = "number"; maxRequests.min = "1"; minutes.min = rate.min = "0.001"; maxRequests.step = "1"; minutes.step = rate.step = "any";
  limits.append(el("summary", "Test options"), row("Request limit", maxRequests), row("Time limit (minutes)", minutes), row("Requests / second", rate), el("p", "One account request at a time. Identity checks and confirmations count toward these limits.", "authz-meta"));
  const prepare = btn("Review comparison", () => run(async () => {
    const count = Number(maxRequests.value), duration = Number(minutes.value), requestsPerSecond = Number(rate.value); if (!Number.isSafeInteger(count) || count < 1 || !Number.isFinite(duration) || duration <= 0 || !Number.isFinite(requestsPerSecond) || requestsPerSecond <= 0) throw Error("Enter a positive whole request limit, duration and request rate.");
    const prepared = await api("prepare", { cases, budget: { maxRequests: count, maxRequestsPerSecond: requestsPerSecond, concurrency: 1, durationSeconds: duration * 60 } });
    if (!prepared?.planId || !prepared.planHash || prepared.state !== "prepared") throw Error("Comparison plan was not prepared."); plan = prepared; renderPlan();
  }), "primary"); caseCard.append(limits, prepare);
  const planCard = el("section", null, "card authz-card authz-plan"), planBody = el("div"), start = btn("Run comparison", () => run(async () => { const frozen = plan; invalidate(); try { const batch = await api("run", { planId: frozen.planId, planHash: frozen.planHash }); if (!batch?.batchId || !batch.state) throw Error("Comparison start was not confirmed."); message("Comparison " + label(batch.state).toLowerCase() + ".", ["unknown", "failed"].includes(batch.state)); } finally { await load(); } }), "primary");
  planCard.hidden = true; planCard.append(el("h2", "Comparison plan"), planBody, start);
  const batchesCard = el("section", null, "card authz-card"), batchList = el("div"), results = el("section", null, "card authz-card authz-results"); results.hidden = true; batchesCard.append(el("h2", "Comparisons"), batchList);
  root.replaceChildren(header, scope, captureCard, accountsCard, caseCard, planCard, notice, batchesCard, results);

  const scopeReady = () => !!session && !!state.workspace && !!state.scope?.origins?.length;
  const tabInScope = tab => state.scope.origins.some(origin => {
    if (state.scope.matchMode !== "host") return origin === tab.origin;
    const base = new URL(origin).hostname, host = new URL(tab.url).hostname;
    return host === base || state.scope.includeSubdomains === true && !base.startsWith("[") && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(base) && host.endsWith("." + base);
  });
  const active = () => state.batches?.some(batch => ACTIVE.has(batch.state));
  function message(value, error = false) { notice.textContent = value; notice.classList.toggle("authz-error", error); }
  function invalidate() { plan = null; planCard.hidden = true; update(); }
  async function run(action) { if (busy) return; busy = true; update(); message(""); try { await action(); } catch (error) { message(error.message, true); } finally { busy = false; update(); } }
  function update() {
    root.querySelectorAll("button").forEach(control => { control.disabled = busy || control.dataset.unavailable === "true"; });
    const tab = tabs.find(item => String(item.tabId) === target.value);
    capture.textContent = state.capture?.active ? "Stop capture" : "Capture requests"; capture.disabled = busy || (!state.capture?.active && (!scopeReady() || !tab || !tabInScope(tab)));
    target.disabled = busy || !!state.capture?.active; saveAccount.disabled = busy || !scopeReady() || state.accounts.length >= 4;
    addCase.disabled = busy || !scopeReady() || !state.accounts.length || !state.captures.length;
    prepare.disabled = busy || !scopeReady() || !cases.length || active(); start.disabled = busy || !plan || active() || Date.now() >= plan.expiresAt;
  }
  function renderCredentials() {
    const source = state.captures.find(item => item.requestId === probe.value), signature = JSON.stringify([probe.value, source?.credentialHeaders, source?.cookieNames]); if (signature === lastCredentialSource) return; lastCredentialSource = signature;
    credentialFields.replaceChildren(); credentials.headers.clear(); credentials.cookies.clear();
    for (const name of source?.credentialHeaders || []) if (name.toLowerCase() === "authorization") credentials.headers.add(name);
    for (const name of source?.cookieNames || []) credentials.cookies.add(name);
    for (const [kind, names] of [["headers", (source?.credentialHeaders || []).filter(name => /^(authorization|x-.+)$/i.test(name))], ["cookies", source?.cookieNames || []]]) {
      for (const name of names) credentialFields.append(row((kind === "cookies" ? "Cookie: " : "Header: ") + name, toggle("Use " + kind + " " + name, credentials[kind].has(name), enabled => { if (enabled) credentials[kind].add(name); else credentials[kind].delete(name); })));
    }
    if (!credentialFields.children.length) credentialFields.append(el("p", "No credential names were captured for this request.", "authz-meta"));
  }
  function renderMatrix() {
    matrix.replaceChildren(el("h3", "Expected access"));
    const ids = new Set([...state.accounts.map(account => account.id), "anonymous"]); for (const id of expectations.keys()) if (!ids.has(id)) expectations.delete(id);
    for (const account of [...state.accounts, { id: "anonymous", label: "Anonymous" }]) {
      const choice = select("Expected access for " + account.label); options(choice, [["", "Do not compare"], ["allow", "Allow"], ["deny", "Deny"]]);
      choice.value = expectations.get(account.id) || ""; choice.onchange = () => { expectations.set(account.id, choice.value); invalidate(); }; matrix.append(row(account.label, choice));
    }
  }
  function renderCases() {
    caseList.replaceChildren(); cases.forEach((item, index) => { const source = state.captures.find(source => source.requestId === item.requestId), card = el("article", null, "authz-item"); card.append(el("strong", (index + 1) + ". " + (source ? endpoint(source) : "Captured request")), el("p", item.expectations.map(value => (state.accounts.find(account => account.id === value.accountId)?.label || value.accountId) + ": " + value.expected).join(" · "), "authz-meta"), btn("Remove case " + (index + 1), () => { cases.splice(index, 1); invalidate(); renderCases(); })); caseList.append(card); });
  }
  function renderPlan() {
    planCard.hidden = !plan; planBody.replaceChildren(); if (!plan) return;
    planBody.append(el("p", (plan.cases?.length || cases.length) + " read request cases · " + plan.budget.maxRequests + " requests maximum · " + plan.budget.maxRequestsPerSecond + "/second · " + Math.ceil(plan.budget.durationSeconds / 60) + " minutes", "authz-meta"), el("p", "Scope: " + (plan.scope?.origins || []).join(" · "), "authz-meta"));
    if (plan.scope?.excludePaths?.length) { const excluded = el("details"); excluded.append(el("summary", "Excluded paths"), el("p", plan.scope.excludePaths.join(" · "), "authz-meta")); planBody.append(excluded); }
    for (const item of plan.cases || []) { const card = el("article", null, "authz-item"); card.append(el("strong", item.label || endpoint(item)), el("p", "Owner: " + (state.accounts.find(account => account.id === item.ownerAccountId)?.label || item.ownerAccountId || "Captured account"), "authz-meta"), el("p", (item.expectations || []).map(value => (value.accountLabel || state.accounts.find(account => account.id === value.accountId)?.label || value.accountId) + ": " + value.expected).join(" · "), "authz-meta"));
      if (item.evidence) card.append(el("p", "Object: " + (item.evidence.object?.pointer || "(document root)") + " · Protected value: " + (item.evidence.protected?.pointer || "(document root)"), "authz-meta"));
      if (item.objectSwap) card.append(el("p", "Object replacement: " + item.objectSwap.location + " " + (item.objectSwap.name || "") + " #" + item.objectSwap.index, "authz-meta")); planBody.append(card);
    }
    planBody.append(el("p", "Account revisions, requests and expected access are frozen. Private credentials and expected evidence values are not shown.", "authz-meta"));
  }
  function renderFindings(value) {
    results.hidden = false; results.replaceChildren(el("h2", "Access results"), btn("Close results", () => { results.hidden = true; }));
    for (const warning of value.warnings || []) results.append(el("p", safeText(warning), "authz-meta"));
    const cells = value.cells || value.findings || [];
    if (!cells.length) results.append(el("p", "No account comparison results yet.", "authz-meta"));
    for (const cell of cells) { const card = el("article", null, "authz-item"), details = el("details"); card.append(el("h3", label(cell.outcome || cell.state || cell.status)), el("p", [cell.accountLabel || cell.accountId, cell.caseLabel || cell.endpoint || cell.url, cell.reason].filter(Boolean).map(safeText).join(" · "), "authz-meta")); details.append(el("summary", "Identity and access evidence"), el("pre", safeText(cell))); card.append(details); results.append(card); }
    results.append(el("p", "These results cover the selected requests and identities. An expected denial does not establish that every authorization path is secure.", "authz-meta"));
  }
  function renderBatches() {
    batchList.replaceChildren(); for (const batch of [...state.batches].reverse()) { const card = el("article", null, "authz-item"), actions = el("div", null, "authz-actions"); card.append(el("h3", label(batch.state)), el("p", [Number.isFinite(batch.requestsSent) ? batch.requestsSent + " requests sent" : null, batch.reason, batch.error, ...(batch.warnings || [])].filter(Boolean).map(safeText).join(" · "), "authz-meta"));
      for (const [op, text] of [["stop", batch.state === "stopping" ? "Stopping…" : "Stop"], ["findings", "Results"], ["export", "Export report"]]) {
        if (op === "stop" && !ACTIVE.has(batch.state)) continue;
        const control = btn(text, () => run(async () => { const value = await api(op, { batchId: batch.batchId }); if (op === "findings") renderFindings(value); if (op === "export") message(value.reports?.length ? "Saved " + value.reports.length + " report(s) to Outputs." : "No report files were saved."); await load(); })); control.dataset.unavailable = String((op === "stop" && batch.state === "stopping") || (op === "export" && ACTIVE.has(batch.state))); actions.append(control);
      } card.append(actions); batchList.append(card);
    } if (!state.batches.length) batchList.append(el("p", "No comparisons yet.", "authz-meta"));
  }
  async function load() {
    const next = session ? await api("state") : { accounts: [], captures: [], batches: [] }; if (disposed) return; state = next;
    const signature = JSON.stringify([state.scope, state.accounts.map(account => [account.id, account.revision]), state.captures.map(item => [item.requestId, item.credentialHeaders, item.cookieNames])]);
    if (lastSignature && signature !== lastSignature) invalidate();
    scope.replaceChildren(el("h2", state.workspace?.name || "Workspace scope")); scope.append(el("p", scopeReady() ? state.scope.origins.join(" · ") : "Open a Bug bounty chat in a workspace with target origins.", "authz-meta")); const link = el("a", "Manage workspace scope", "section-link"); link.href = "?section=workspaces" + (session ? "&session=" + encodeURIComponent(session) : ""); if (new URLSearchParams(location.search).get("embed") === "1") link.onclick = event => { event.preventDefault(); parent.postMessage({ type: "settings-section", section: "workspaces" }, location.origin); }; scope.append(link);
    accountList.replaceChildren(); for (const account of state.accounts) { const card = el("article", null, "authz-item"), actions = el("div", null, "authz-actions"); card.append(el("strong", account.label), el("p", [account.role, account.tenant, account.verification ? label(account.verification.state || account.verification.status) : "Not verified"].filter(Boolean).join(" · "), "authz-meta")); actions.append(btn("Verify " + account.label, () => run(async () => { const value = await api("verify", { accountId: account.id }); message(label(value.state || value.status || (value.verified ? "verified" : "inconclusive")) + (value.reason ? ": " + value.reason : "")); await load(); })), btn("Delete " + account.label, () => run(async () => { await api("delete_account", { accountId: account.id }); cases = cases.filter(item => item.ownerAccountId !== account.id && !item.expectations.some(value => value.accountId === account.id)); invalidate(); await load(); }))); card.append(actions); accountList.append(card); }
    if (signature !== lastSignature) { options(probe, state.captures.map(item => [item.requestId, endpoint(item)]), "Choose identity request"); options(captured, state.captures.filter(item => item.supported !== false).map(item => [item.requestId, endpoint(item)]), "Choose read request"); options(owner, state.accounts.map(account => [account.id, account.label]), "Choose owner"); renderCredentials(); renderMatrix(); renderCases(); lastSignature = signature; }
    renderBatches(); update();
  }
  async function loadTabs() { const previous = target.value; tabs = await api("tabs", {}, "KI_DAST"); options(target, tabs.map(item => [String(item.tabId), item.title + " · " + item.origin])); if (!tabs.some(item => String(item.tabId) === previous) && tabs.length) target.value = String((tabs.find(item => item.working) || tabs.find(item => item.active) || tabs[0]).tabId); update(); }
  probe.onchange = renderCredentials; owner.onchange = () => { if (owner.value && !expectations.has(owner.value)) expectations.set(owner.value, "allow"); renderMatrix(); invalidate(); };
  for (const control of [captured, objectPointer, expectedObject, protectedPointer, expectedProtected, swapLocation, swapName, swapIndex, swapValue, maxRequests, minutes, rate]) control.addEventListener("input", invalidate);
  target.onchange = update;
  const changed = (changes, area) => { if (area === "local" && (changes.ki_authz_batches || changes.ki_authz_accounts || changes.ki_contexts)) void load().catch(error => message(error.message, true)); };
  async function poll() { if (disposed) return; try { if (!document.hidden && !busy) { for (const batch of state.batches.filter(item => ACTIVE.has(item.state))) await api("status", { batchId: batch.batchId }); if (state.capture?.active || active()) await load(); update(); } } catch (error) { message(error.message, true); } timer = setTimeout(poll, 3000); }
  chrome.storage.onChanged.addListener(changed); window.addEventListener("pagehide", () => { disposed = true; clearTimeout(timer); chrome.storage.onChanged.removeListener(changed); }, { once: true });
  try { await load(); await loadTabs(); } catch (error) { message(error.message, true); } update(); timer = setTimeout(poll, 3000);
}

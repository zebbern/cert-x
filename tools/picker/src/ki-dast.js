// Targeted DAST captures and immutable plans. Raw requests remain in trusted
// extension session storage and travel only inside the owned compatibility runtime.
var KI_DAST_PRIVATE = "ki_dast_private", KI_DAST_BATCHES = "ki_dast_batches", KI_DAST_ALARM = "ki-dast:";
var KI_DAST_FAMILIES = Object.freeze(["xss", "sql_injection", "open_redirect", "sql_boolean", "ssti", "jsonp_callback_injection", "response_checks"]);
var KI_DAST_ACTIVE_FAMILIES = Object.freeze(KI_DAST_FAMILIES.filter(family => family !== "response_checks"));
var KI_DAST_REVISION5_FAMILIES = Object.freeze(["sql_boolean", "ssti", "jsonp_callback_injection", "response_checks"]);
var kiDastPrivate = { captures: {}, requests: {}, plans: {} }, kiDastBatches = [], kiDastWrites = Promise.resolve(), kiDastRunQueue = Promise.resolve(), kiDastNetwork = new Map(), kiDastExtra = new Map(), kiDastRedirects = new Set();
var kiDastActive = new Set(["starting", "running", "stopping", "unknown"]), kiDastEpoch;
var kiDastNames = { capture: "ptk_capture_requests", list: "ptk_list_requests", prepare: "ptk_prepare_dast", run: "ptk_run_dast", status: "ptk_dast_status", stop: "ptk_stop_dast", findings: "ptk_dast_findings", export: "ptk_dast_export" };
function kiDastMeta(name) {
  const labels = { ptk_capture_requests: "Capture selected-tab requests", ptk_list_requests: "List captured requests", ptk_prepare_dast: "Prepare targeted DAST", ptk_run_dast: "Run DAST tests", ptk_dast_status: "Read DAST status", ptk_stop_dast: "Stop DAST tests", ptk_dast_findings: "Read DAST findings", ptk_dast_export: "Export DAST evidence" };
  return { id: "ptk:" + name, group: "ptk", family: "ptk", name, label: labels[name] || name, securityStop: name === kiDastNames.stop, defaultAsk: ["ptk_run_dast", "ptk_dast_export"].includes(name) };
}
function kiDastOwner(session) { if (typeof session !== "string" || !/^[a-zA-Z0-9_-]{1,150}$/.test(session)) throw Error("Choose a chat before using targeted DAST."); return kiWorkspaceOwner(session); }
function kiDastClone(value) { return JSON.parse(JSON.stringify(value)); }
function kiDastWrite(action) { const task = kiDastWrites.then(async () => { await kiDastReady; return action(); }); kiDastWrites = task.catch(() => {}); return task; }
async function kiDastLoad() { await kiDastReady; await kiDastWrites; return kiDastBatches; }
function kiDastHasActiveBatch() { return kiDastBatches.some(batch => batch.epoch === kiDastEpoch && kiDastActive.has(batch.state)); }
async function kiDastSavePrivate() {
  const encoded = JSON.stringify(kiDastPrivate);
  if (new TextEncoder().encode(encoded).length > 6 * 1024 * 1024) throw Error("DAST capture storage is full. Stop capture and start a fresh capture after finishing existing plans.");
  await chrome.storage.session.set({ [KI_DAST_PRIVATE]: kiDastPrivate });
}
async function kiDastHash(value) { return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(value)))), byte => byte.toString(16).padStart(2, "0")).join(""); }
function kiDastPath(url) {
  let value = new URL(url).pathname;
  for (let i = 0; i < 4; i++) { if (/%(?:2f|5c|2e)/i.test(value)) throw Error("Encoded path separators or dot segments are not supported."); const decoded = decodeURIComponent(value); if (decoded === value) break; value = decoded; if (i === 3) throw Error("Encoded request path is ambiguous."); }
  if (/[\\\x00-\x20]/.test(value) || /(?:^|\/)\.{1,2}(?:\/|$)/.test(value)) throw Error("Request path is ambiguous.");
  return value;
}
function kiDastScopeAllows(url, scope) {
  try {
    const parsed = new URL(url); if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) return false;
    if (!(scope?.origins || []).some(origin => {
      if (scope.matchMode !== "host") return origin === parsed.origin;
      const base = new URL(origin);
      return parsed.hostname === base.hostname || scope.includeSubdomains === true && !base.hostname.startsWith("[") && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(base.hostname) && parsed.hostname.endsWith("." + base.hostname);
    })) return false;
    const decoded = kiDastPath(url), within = (value, prefix) => prefix === "/" || value === prefix || value.startsWith(prefix.replace(/\/$/, "") + "/");
    return !(scope.excludePaths || []).some(prefix => within(parsed.pathname, prefix) || within(decoded, prefix));
  } catch { return false; }
}
async function kiDastContext(session) {
  const owner = kiDastOwner(session), context = await kiContextResolve(owner), workspace = context.workspace;
  const scope = workspace?.dastScope;
  if (!workspace || !Array.isArray(scope?.origins) || !scope.origins.length) throw Error("Configure target origins in this workspace before capturing or testing requests.");
  return { owner, workspaceId: workspace.id, scope: kiDastClone(scope) };
}
async function kiDastCurrentPolicy(name, session) {
  const meta = kiDastMeta(name), global = await kiPolicyState(meta), context = await kiContextResolve(session);
  return { ...global, rule: kiContextRule(meta, context, global.rule) };
}
function kiDastPublicUrl(url) { try { const value = new URL(url); return value.origin + value.pathname; } catch { return "Unavailable URL"; } }
function kiDastHeaders(headers) {
  const result = Array.isArray(headers) ? headers.map(item => ({ name: String(item.name), value: String(item.value) })) : Object.entries(headers || {}).map(([name, value]) => ({ name, value: String(value) }));
  if (result.length > 100 || JSON.stringify(result).length > 65536) throw Error("Request headers exceed the capture limit.");
  return result.filter(item => !item.name.startsWith(":"));
}
function kiDastContentType(request) { return (request.headers?.find(item => item.name.toLowerCase() === "content-type")?.value || "").split(";")[0].trim().toLowerCase(); }
function kiDastJsonType(type) { return /^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)$/i.test(type); }
function kiDastProtectedInput(name) { return /^(?:csrf|xsrf|_csrf|session|sessionid|authorization|access_token|refresh_token|password|passwd|secret|api[_-]?key)$/i.test(name); }
function kiDastInputFamilies(name, value) {
  // Inspect decoded values only here; public metadata contains family names, never values.
  return KI_DAST_ACTIVE_FAMILIES.filter(family => family === "sql_boolean" ? typeof value === "string" && value.length > 0 && value.length <= 128 && !/[\r\n'";\\]/.test(value)
    : family === "jsonp_callback_injection" ? /^(?:callback|cb|jsonp|jsoncallback|json_callback|callbackfn|callback_fn)$/i.test(name) : true);
}
function kiDastFamilies(value) {
  if (value == null) return ["xss"];
  if (!Array.isArray(value) || !value.length || value.length > KI_DAST_FAMILIES.length || value.some(family => !KI_DAST_FAMILIES.includes(family)) || new Set(value).size !== value.length) throw Error("Select distinct supported DAST checks from the available families.");
  return [...value];
}
function kiDastRequestInfo(request) {
  const header = name => request.headers?.find(item => item.name.toLowerCase() === name)?.value || "";
  const fields = [], reasons = [];
  if (!["GET", "POST"].includes(request.method)) reasons.push("This preset supports GET and POST only.");
  if (!request.complete) reasons.push("Request has not finished.");
  if (request.expectExtra && !request.extraReceived) reasons.push("Exact request headers are still pending.");
  const originalRedirect = request.redirected && request.redirectHeadersExact === true && request.statusCode >= 300 && request.statusCode < 400;
  if (request.redirected && !originalRedirect) reasons.push("Redirected capture lacks unambiguous original request headers. Capture it again; late redirect headers cannot be used.");
  if (request.failed && !originalRedirect) reasons.push("The captured request did not complete successfully.");
  if ([401, 403].includes(request.statusCode)) reasons.push("Authentication or access must be restored before testing.");
  if (request.bodyMissing) reasons.push("Exact request body was unavailable; it will not be reconstructed.");
  const type = kiDastContentType(request), isJson = kiDastJsonType(type);
  if (request.body != null && new TextEncoder().encode(request.body).length > 65536) reasons.push("Request body exceeds the 64 KiB capture limit.");
  if (request.body != null && type === "application/x-www-form-urlencoded" && /[^\x20-\x7e]/.test(request.body)) reasons.push("Only ASCII URL-encoded form bodies are supported; JSON string fields may use UTF-8.");
  if (request.body != null && type !== "application/x-www-form-urlencoded" && !isJson) reasons.push("Only URL-encoded forms and application/json or application/*+json bodies are supported; multipart and other bodies are not.");
  if (isJson) {
    const contentType = header("content-type");
    if (contentType.includes(";") && !/^\s*charset\s*=\s*(?:utf-8|"utf-8"|'utf-8')\s*$/i.test(contentType.slice(contentType.indexOf(";") + 1))) reasons.push("JSON bodies require UTF-8 without unsupported media parameters.");
    if (request.body == null) reasons.push("Exact JSON body was unavailable; it will not be reconstructed.");
    else {
      try {
        if (typeof CertXDastInputs !== "object" || typeof CertXDastInputs.parseJson !== "function") throw Error("JSON selection support is unavailable. Reload cert-x.");
        for (const leaf of CertXDastInputs.parseJson(request.body)) {
          const key = leaf.name.split("/").at(-1).replaceAll("~1", "/").replaceAll("~0", "~"), protectedName = kiDastProtectedInput(key), supported = leaf.valueType === "string" && !protectedName;
          fields.push({ location: "json", name: leaf.name, index: leaf.index, valueType: leaf.valueType, supported, compatibleFamilies: supported ? kiDastInputFamilies(key, leaf.value) : [],
            ...(!supported ? { reason: protectedName ? "Authentication and session inputs are preserved, not mutated." : "Only JSON string fields can be tested; numbers, booleans and null are preserved." } : {}) });
        }
      } catch (error) { reasons.push(error.message); }
    }
  }
  for (const [location, raw] of [["query", new URL(request.url).search.slice(1)], ["form", request.body != null && type === "application/x-www-form-urlencoded" ? request.body : null]]) {
    if (raw == null) continue;
    try {
      for (const { name, index, value } of CertXDastInputs.parseEncoded(raw)) {
        const protectedName = kiDastProtectedInput(name), supported = !protectedName && !!name && name.length <= 200;
        fields.push({ location, name, index, valueType: "string", supported, compatibleFamilies: supported ? kiDastInputFamilies(name, value) : [],
          ...(protectedName ? { reason: "Authentication and session inputs are preserved, not mutated." } : {}) });
      }
    } catch { reasons.push("The encoded inputs could not be selected exactly. Capture a supported request after reloading cert-x."); }
  }
  if (originalRedirect) for (const field of fields) if (field.supported) field.compatibleFamilies = ["open_redirect"];
  if (originalRedirect && !fields.some(field => field.supported)) reasons.push("A first-hop redirect needs a supported input for an open-redirect check.");
  const compatibleFamilies = reasons.length ? [] : originalRedirect ? ["open_redirect"] : ["response_checks", ...KI_DAST_ACTIVE_FAMILIES.filter(family => fields.some(field => field.supported && field.compatibleFamilies.includes(family)))];
  return { requestId: request.id, method: request.method, url: kiDastPublicUrl(request.url), parameters: fields, statusCode: request.statusCode ?? null,
    compatibleFamilies, requiresReplayConsent: true, supported: reasons.length === 0, reason: reasons.join(" "), capturedAt: request.capturedAt };
}
function kiDastPublicPlan(plan) { return { planId: plan.planId, planHash: plan.planHash, createdAt: plan.createdAt, expiresAt: plan.expiresAt, scope: plan.scope, budget: plan.budget, families: plan.families, requests: plan.requests.map(request => {
  const info = kiDastRequestInfo(request);
  return { ...info, parameters: request.parameters.map(selected => { const field = info.parameters.find(field => field.location === selected.location && field.name === selected.name && field.index === selected.index); return { ...selected, valueType: field?.valueType || "string", compatibleFamilies: field?.compatibleFamilies || ["xss"] }; }), allowReplay: true };
}), state: plan.state }; }
async function kiDastTab(tabId, origin) {
  if (!Number.isInteger(tabId) || tabId < 0 || typeof origin !== "string" || new URL(origin).origin !== origin) throw Error("Choose an explicit tab and exact HTTP(S) origin.");
  const tab = await chrome.tabs.get(tabId);
  if (new URL(tab.url).origin !== origin || (tab.pendingUrl && new URL(tab.pendingUrl).origin !== origin)) throw Error("The selected tab changed origin. Capture it again before testing.");
  return tab;
}
async function kiDastCapture(args, session) {
  const owner = kiDastOwner(session); await kiDastLoad();
  if (args.action === "stop") return kiDastWrite(async () => { const capture = kiDastPrivate.captures[owner]; if (capture) capture.active = false; await kiDastSavePrivate(); return capture || { active: false }; });
  if (args.action !== "start") throw Error("Choose start or stop for capture.");
  const context = await kiDastContext(session), tab = await kiDastTab(args.tabId, args.expectedOrigin);
  if (!kiDastScopeAllows(tab.url, context.scope)) throw Error("Selected target is outside workspace scope: " + tab.url + ". Review target scope in Workspace settings.");
  if (Object.values(kiDastPrivate.captures).some(capture => capture.active && capture.tabId === args.tabId && capture.owner !== owner)) throw Error("Another chat is capturing this tab.");
  if (typeof mP !== "object" || !mP.cdp?.execute) throw Error("Browser request capture is unavailable.");
  const enabled = await mP.cdp.execute({ _tabId: args.tabId, method: "Network.enable", params: {} });
  if (enabled?.isError || enabled?.error) throw Error("Browser request capture could not enable network events.");
  return kiDastWrite(async () => {
    const fresh = await kiDastContext(session); if (JSON.stringify(fresh) !== JSON.stringify(context)) throw Error("Workspace scope changed before capture. Try again.");
    for (const [id, request] of Object.entries(kiDastPrivate.requests)) if (request.owner === owner) delete kiDastPrivate.requests[id];
    const capture = { ...context, tabId: args.tabId, origin: args.expectedOrigin, active: true, startedAt: Date.now(), count: 0, truncated: false };
    kiDastPrivate.captures[owner] = capture; await kiDastSavePrivate(); return kiDastClone(capture);
  });
}
async function kiDastNetworkEvent(source, method, data) {
  if (!Number.isInteger(source?.tabId) || !["Network.requestWillBeSent", "Network.requestWillBeSentExtraInfo", "Network.responseReceived", "Network.loadingFinished", "Network.loadingFailed"].includes(method)) return;
  await kiDastLoad(); const capture = Object.values(kiDastPrivate.captures).find(item => item.active && item.tabId === source.tabId);
  if (!capture || !data?.requestId) return;
  const key = source.tabId + ":" + data.requestId;
  return kiDastWrite(async () => {
    if (!capture.active) return;
    const current = await kiDastContext(capture.owner).catch(() => null);
    const policy = await kiDastCurrentPolicy(kiDastNames.capture, capture.owner);
    if (!current || !policy.parentEnabled || policy.rule === "disabled" || current.workspaceId !== capture.workspaceId || JSON.stringify(current.scope) !== JSON.stringify(capture.scope)) { capture.active = false; await kiDastSavePrivate(); return; }
    let request = kiDastPrivate.requests[kiDastNetwork.get(key)];
    if (method === "Network.requestWillBeSent") {
      if (data.redirectResponse) {
        // Freeze the first hop before any next-hop headers or response can replace it.
        // Late ExtraInfo is ambiguous because CDP reuses requestId across redirects.
        if (request && !request.redirected) { request.redirected = true; request.redirectHeadersExact = request.extraReceived === true; request.complete = true; request.statusCode = data.redirectResponse.status; }
        kiDastRedirects.add(key); kiDastExtra.delete(key); await kiDastSavePrivate(); return;
      }
      if (kiDastRedirects.has(key) || !["XHR", "Fetch", "Document"].includes(data.type) || !kiDastScopeAllows(data.request?.url, capture.scope) || new URL(data.request.url).origin !== capture.origin) return;
      if (capture.count >= 100 || Object.keys(kiDastPrivate.requests).length >= 256) { capture.truncated = true; await kiDastSavePrivate(); return; }
      const raw = data.request, body = typeof raw.postData === "string" ? raw.postData : null;
      if (body && new TextEncoder().encode(body).length > 65536) return;
      request = { id: crypto.randomUUID(), owner: capture.owner, workspaceId: capture.workspaceId, tabId: source.tabId, origin: capture.origin, url: raw.url, method: String(raw.method).toUpperCase(), headers: kiDastHeaders(raw.headers), body,
        bodyMissing: raw.hasPostData === true && body == null, capturedAt: Date.now(), complete: false };
      if (kiDastExtra.has(key)) { request.headers = kiDastExtra.get(key); request.extraReceived = true; kiDastExtra.delete(key); }
      kiDastPrivate.requests[request.id] = request; kiDastNetwork.set(key, request.id); capture.count++;
    } else if (method === "Network.requestWillBeSentExtraInfo") {
      if (kiDastRedirects.has(key)) return;
      const headers = kiDastHeaders(data.headers); if (request) { request.headers = headers; request.extraReceived = true; if (request.complete) kiDastNetwork.delete(key); } else if (kiDastExtra.size < 256) kiDastExtra.set(key, headers);
    } else if (request) {
      if (method === "Network.responseReceived" && !request.redirected) { request.statusCode = data.response?.status; request.expectExtra = data.hasExtraInfo === true; }
      if (method === "Network.loadingFinished" || method === "Network.loadingFailed") { request.complete = true; if (!request.redirected) request.failed = method === "Network.loadingFailed"; if (request.redirected || !request.expectExtra || request.extraReceived || request.failed) kiDastNetwork.delete(key); kiDastRedirects.delete(key); kiDastExtra.delete(key); }
    }
    try { await kiDastSavePrivate(); } catch (error) { if (request && !request.complete) { delete kiDastPrivate.requests[request.id]; kiDastNetwork.delete(key); } capture.active = false; capture.truncated = true; await kiDastSavePrivate(); }
  });
}
function kiDastBudget(raw = {}) {
  const maxRequests = raw.maxRequests ?? 100, durationSeconds = raw.durationSeconds ?? 300;
  if (!Number.isInteger(maxRequests) || maxRequests < 1 || !Number.isInteger(durationSeconds) || durationSeconds < 1 || (raw.maxRequestsPerSecond != null && (!Number.isFinite(raw.maxRequestsPerSecond) || raw.maxRequestsPerSecond <= 0)) || (raw.concurrency != null && raw.concurrency !== 1)) throw Error("Use positive request and duration budgets; isolated comparisons require concurrency 1.");
  return { maxRequests, maxRequestsPerSecond: raw.maxRequestsPerSecond ?? 5, concurrency: 1, durationSeconds };
}
async function kiDastPrepare(args, session, signal) {
  await kiDastLoad(); const context = await kiDastContext(session), selections = args.requests;
  if (!Array.isArray(selections) || !selections.length || selections.length > 10) throw Error("Select between one and ten captured requests.");
  const families = kiDastFamilies(args.families), activeFamilies = families.filter(family => family !== "response_checks");
  const requests = [], used = new Set();
  for (const selection of selections) {
    const request = kiDastPrivate.requests[selection?.requestId];
    if (!request || request.owner !== context.owner || request.workspaceId !== context.workspaceId || Date.now() - request.capturedAt > 30 * 60 * 1000) throw Error("A selected capture is missing, expired or belongs to another workspace.");
    if (used.has(request.id)) throw Error("Select each request once."); used.add(request.id);
    if (!kiDastScopeAllows(request.url, context.scope)) throw Error("Selected target is outside current workspace scope: " + request.url + ". Review target scope in Workspace settings.");
    if (new URL(request.url).origin !== request.origin) throw Error("A selected request is not from the captured tab's origin. Capture that origin separately.");
    const info = kiDastRequestInfo(request); if (!info.supported) throw Error(info.reason);
    if (families.some(family => !info.compatibleFamilies.includes(family))) throw Error("A selected request does not support every selected check. Response checks can run without inputs; active checks need compatible string inputs.");
    if (selection.allowReplay !== true) throw Error("Explicitly select replay for every request, including GET requests.");
    if (!Array.isArray(selection.parameters) || selection.parameters.length > 20 || (activeFamilies.length && !selection.parameters.length)) throw Error("Select at least one input for every active-check request, or no inputs for response checks alone (maximum twenty inputs).");
    const parameters = [], selectedFields = [], seen = new Set();
    for (const selected of selection.parameters) {
      const field = info.parameters.find(field => field.location === selected.location && field.name === selected.name && field.index === selected.index);
      if (!field?.supported) throw Error(field?.reason || "A selected input does not match the captured request.");
      const key = field.location + ":" + field.index; if (seen.has(key)) throw Error("Select each input once."); seen.add(key); selectedFields.push(field); parameters.push({ location: field.location, name: field.name, index: field.index });
    }
    if (activeFamilies.some(family => !selectedFields.some(field => field.compatibleFamilies.includes(family)))) throw Error("Select a compatible input for every active check in each request.");
    requests.push({ ...kiDastClone(request), parameters, allowReplay: true });
  }
  if (requests.some(request => request.tabId !== requests[0].tabId || request.origin !== requests[0].origin)) throw Error("A batch must use one captured tab and origin.");
  const capabilities = await kiDastCompanion("capabilities", { tabId: requests[0].tabId, expectedOrigin: requests[0].origin }, signal);
  if (capabilities?.ready !== true || families.some(family => !capabilities.families?.includes(family))) throw Error("The prepared PTK companion does not support every selected check. Update and reload it before preparing this plan.");
  const usesJson = requests.some(request => kiDastJsonType(kiDastContentType(request)));
  const needsOrdinals = requests.some(request => { const fields = kiDastRequestInfo(request).parameters.filter(field => field.location !== "json"); return new Set(fields.map(field => field.name)).size !== fields.length; });
  if ((needsOrdinals || families.some(family => KI_DAST_REVISION5_FAMILIES.includes(family))) && (!(Number.isInteger(capabilities.revision) && capabilities.revision >= 5) || capabilities.ordinalInputs !== true)) throw Error("These checks or repeated input names require PTK companion revision 5 with exact ordinal inputs. Update and reload it before preparing this plan.");
  if ((usesJson || families.some(family => family !== "xss")) && !(Number.isInteger(capabilities.revision) && capabilities.revision >= 3)) throw Error("These checks require PTK companion revision 3 or newer. Update and reload it before preparing this plan.");
  if (usesJson && !capabilities.inputLocations?.includes("json")) throw Error("The prepared PTK companion does not support exact JSON input selection. Update and reload it before preparing this plan.");
  signal?.throwIfAborted();
  const createdAt = Date.now(), plan = { ...context, planId: crypto.randomUUID(), tabId: requests[0].tabId, origin: requests[0].origin, expectedOrigin: requests[0].origin, createdAt, expiresAt: createdAt + 15 * 60 * 1000, scope: context.scope, budget: kiDastBudget(args.budget), families, requests, state: "prepared" };
  if (globalThis.certXSecurity) await globalThis.certXSecurity.resolveConfig(context.workspaceId, plan.budget);
  plan.planHash = await kiDastHash(plan);
  return kiDastWrite(async () => { for (const [id, old] of Object.entries(kiDastPrivate.plans)) if (old.expiresAt < Date.now() && old.state === "prepared") delete kiDastPrivate.plans[id]; if (Object.keys(kiDastPrivate.plans).length >= 20) throw Error("Too many retained DAST plans. Finish existing plans or restart the browser to discard private captures."); kiDastPrivate.plans[plan.planId] = plan; try { await kiDastSavePrivate(); } catch (error) { delete kiDastPrivate.plans[plan.planId]; throw error; } return kiDastPublicPlan(plan); });
}
async function kiDastPlanCheck(plan, session) {
  const fresh = await kiDastContext(session);
  if (!plan || plan.owner !== fresh.owner || plan.workspaceId !== fresh.workspaceId) throw Error("DAST plan does not belong to this chat and workspace.");
  if (JSON.stringify(plan.scope) !== JSON.stringify(fresh.scope)) throw Error("Workspace scope changed. Prepare a new test plan.");
  await kiDastTab(plan.tabId, plan.origin);
  for (const request of plan.requests) if (!kiDastScopeAllows(request.url, fresh.scope) || new URL(request.url).origin !== plan.origin) throw Error("A selected request is no longer in the plan's exact-origin scope.");
  return fresh;
}
async function kiDastStoreBatch(batchId, patch) { return kiDastWrite(async () => {
  const old = kiDastBatches.find(item => item.batchId === batchId), next = { ...old, ...patch, batchId, updatedAt: Date.now() };
  if (old && !kiDastActive.has(old.state)) next.state = old.state;
  kiDastBatches = kiDastBatches.filter(item => item.batchId !== batchId).concat(next).slice(-50);
  await chrome.storage.local.set({ [KI_DAST_BATCHES]: kiDastBatches });
  // The sanitized approved plan remains on the batch. Raw credentials are no
  // longer needed once its execution is terminal and must not fill the plan store.
  if (!kiDastActive.has(next.state) && kiDastPrivate.plans[next.planId]?.batchId === batchId) { delete kiDastPrivate.plans[next.planId]; await kiDastSavePrivate(); }
  return next;
}); }
async function kiDastBatch(batchId, session) { await kiDastLoad(); const batch = kiDastBatches.find(item => item.batchId === batchId); if (!batch || batch.owner !== kiDastOwner(session)) throw Error("DAST batch does not belong to this chat."); return batch; }
function kiDastPublicStatus(value, batch) {
  if (!value || value.batchId !== batch.batchId || value.owner !== batch.owner || typeof value.state !== "string") throw Error("DAST companion returned an unrelated or invalid batch.");
  const states = ["starting", "running", "stopping", "completed", "stopped", "failed", "budget_exhausted", "expired", "auth_expired", "interrupted", "unknown"];
  if (!states.includes(value.state)) throw Error("DAST companion returned an unknown lifecycle state.");
  const result = { state: value.state, requestsSent: Number(value.requestsSent) || 0, inFlight: Number(value.inFlight) || 0, findingsCount: Number(value.findingsCount) || 0,
    progress: value.progress ? { tested: Number(value.progress.tested) || 0, total: Number(value.progress.total) || 0 } : null,
    warnings: Array.isArray(value.warnings) ? value.warnings.slice(0, 20).map(item => String(item).slice(0, 1000)) : [], errors: Array.isArray(value.errors) ? value.errors.slice(0, 20).map(item => String(item).slice(0, 1000)) : [] };
  const count = value => Number.isInteger(value) && value >= 0 ? Math.min(value, 10000) : 0;
  if (value.observationsCount != null) result.observationsCount = count(value.observationsCount);
  if (value.coverageSummary && typeof value.coverageSummary === "object" && !Array.isArray(value.coverageSummary)) result.coverageSummary = Object.fromEntries(["tested", "skipped", "unsupported", "inconclusive"].map(state => [state, count(value.coverageSummary[state])]));
  if (result.requestsSent > batch.budget.maxRequests || result.inFlight > 1) throw Error("DAST companion exceeded the approved budget contract."); return result;
}
async function kiDastRun(args, session, signal, recheck) {
  const task = kiDastRunQueue.then(() => typeof kiPtkLock === "function" ? kiPtkLock("scan-start", () => kiDastRunSelected(args, session, signal, recheck)) : kiDastRunSelected(args, session, signal, recheck)); kiDastRunQueue = task.catch(() => {}); return task;
}
async function kiDastRunSelected(args, session, signal, recheck) {
  await kiDastLoad(); const plan = kiDastPrivate.plans[args.planId]; await kiDastPlanCheck(plan, session);
  if (args.planHash !== plan.planHash || plan.expiresAt <= Date.now()) throw Error("The test plan changed or expired. Prepare it again.");
  if (plan.state !== "prepared") throw Error("This plan was already dispatched. Inspect its batch; it will not be replayed.");
  if (kiDastBatches.some(batch => kiDastActive.has(batch.state) && batch.epoch === kiDastEpoch)) throw Error("A DAST batch is already active. Stop or resolve it first.");
  if (typeof kiPtkLoad === "function") await kiPtkLoad();
  if (typeof kiAuthzLoad === "function") await kiAuthzLoad();
  if (typeof kiAuthzHasActiveBatch === "function" && kiAuthzHasActiveBatch()) throw Error("Finish the account comparison before running DAST.");
  if (typeof kiPtkCache === "object" && kiPtkCache.some(scan => ["starting", "running", "stopping", "unknown"].includes(scan.state))) throw Error("Finish the active PTK analysis or observation before running DAST.");
  await recheck?.(); signal?.throwIfAborted();
  const batchId = crypto.randomUUID(), startedAt = Date.now();
  await kiDastWrite(async () => { if (plan.state !== "prepared") throw Error("This plan was already dispatched."); plan.state = "dispatched"; plan.batchId = batchId; await kiDastSavePrivate(); });
  const batch = await kiDastStoreBatch(batchId, { owner: plan.owner, workspaceId: plan.workspaceId, epoch: kiDastEpoch, planId: plan.planId, planHash: plan.planHash, tabId: plan.tabId, origin: plan.origin,
    scope: plan.scope, budget: plan.budget, families: plan.families, plan: kiDastPublicPlan(plan), state: "starting", startedAt, deadline: startedAt + plan.budget.durationSeconds * 1000, requestsSent: 0, findingsCount: 0, reports: [] });
  let dispatched = false;
  try {
    await kiDastPlanCheck(plan, session); await recheck?.(); signal?.throwIfAborted();
    const beforeDispatch = async () => {
      await kiDastPlanCheck(plan, session); await recheck?.(); signal?.throwIfAborted();
      if (plan.expiresAt <= Date.now()) throw Error("The test plan expired while connecting. Prepare a new plan.");
      if (kiDastBatches.find(item => item.batchId === batchId)?.stopRequestedAt) throw Object.assign(Error("DAST batch was stopped before dispatch."), { cancelledBeforeDispatch: true });
      dispatched = true;
    };
    const result = await kiDastCompanion("run", { batchId, owner: plan.owner, tabId: plan.tabId, expectedOrigin: plan.origin, origin: plan.origin, requests: plan.requests.map(({ id, url, method, headers, body, parameters, allowReplay }) => ({ id, url, method, headers, body, parameters, allowReplay })), scope: plan.scope, budget: plan.budget, families: plan.families }, signal, beforeDispatch);
    if (result?.accepted !== true || result.batchId !== batchId) throw Error("The DAST companion did not confirm this batch.");
    const status = kiDastPublicStatus(result, batch);
    if (kiDastActive.has(status.state)) await chrome.alarms.create(KI_DAST_ALARM + batchId, { when: Math.min(batch.deadline, Date.now() + 30000) });
    return kiDastStoreBatch(batchId, status);
  } catch (error) { await kiDastStoreBatch(batchId, { state: dispatched ? "unknown" : error.cancelledBeforeDispatch ? "stopped" : "failed", error: dispatched ? "DAST start outcome is unknown; inspect the batch before another test. " + error.message : error.message }); error.batchId = batchId; throw error; }
}
async function kiDastStatus(batchId, session, signal) {
  const batch = await kiDastBatch(batchId, session);
  if (batch.epoch !== kiDastEpoch || !kiDastActive.has(batch.state)) return batch;
  try {
    const plan = kiDastPrivate.plans[batch.planId];
    try { await kiDastPlanCheck(plan, session); const policy = await kiDastCurrentPolicy(kiDastNames.run, session); if (!policy.parentEnabled || policy.rule === "disabled") throw Error("DAST permission was disabled."); }
    catch (error) { await kiDastStop(batchId, session); return kiDastStoreBatch(batchId, { warning: "Stop requested: " + error.message }); }
    const result = await kiDastCompanion("status", { batchId, owner: batch.owner, tabId: batch.tabId, expectedOrigin: batch.origin }, signal), patch = kiDastPublicStatus(result, batch);
    if (!kiDastActive.has(patch.state)) await chrome.alarms.clear(KI_DAST_ALARM + batchId);
    return kiDastStoreBatch(batchId, patch);
  } catch (error) { signal?.throwIfAborted(); return kiDastStoreBatch(batchId, { state: "unknown", error: error.message }); }
}
async function kiDastStop(batchId, session, signal) {
  const batch = await kiDastBatch(batchId, session); if (!kiDastActive.has(batch.state)) return batch;
  await kiDastStoreBatch(batchId, { state: "stopping", stopRequestedAt: Date.now() });
  const result = await kiDastCompanion("stop", { batchId, owner: batch.owner, tabId: batch.tabId, expectedOrigin: batch.origin }, signal);
  return kiDastStoreBatch(batchId, kiDastPublicStatus(result, batch));
}
async function kiDastResult(batchId, session, signal) {
  const batch = await kiDastBatch(batchId, session), result = await kiDastCompanion("result", { batchId, owner: batch.owner, tabId: batch.tabId, expectedOrigin: batch.origin }, signal);
  const patch = kiDastPublicStatus(result, batch); if (!Array.isArray(result.findings) || (result.coverage != null && !Array.isArray(result.coverage)) || (result.observations != null && !Array.isArray(result.observations)) || JSON.stringify(result).length > 4 * 1024 * 1024) throw Error("DAST companion returned an invalid evidence result.");
  const coverage = (result.coverage || []).slice(0, 2000).map(entry => {
    if (!entry || !["tested", "skipped", "unsupported", "inconclusive"].includes(entry.state)) throw Error("DAST companion returned invalid coverage state.");
    return kiDastClone(entry);
  }), observations = kiDastClone((result.observations || []).slice(0, 100));
  const saved = await kiDastStoreBatch(batchId, patch); return { batch: saved, findings: result.findings.slice(0, 100), coverage, observations, warnings: patch.warnings, truncated: result.findings.length > 100 || (result.coverage?.length || 0) > 2000 || (result.observations?.length || 0) > 100, report: result.report };
}
async function kiDastExport(batchId, session, signal, recheck) {
  const result = await kiDastResult(batchId, session, signal); if (kiDastActive.has(result.batch.state)) throw Error("Stop the batch and wait for its in-flight request to finish before exporting.");
  if (!result.report || typeof result.report !== "object") throw Error("The DAST companion did not return an evidence report.");
  await recheck?.(); signal?.throwIfAborted(); const text = JSON.stringify(result.report, null, 2), bytes = new TextEncoder().encode(text); let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 32768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
  const name = "cert-x-dast-" + batchId + ".json", downloadId = await kiPtkDownload(name, btoa(binary), "application/json", signal), report = { downloadId, name, size: bytes.length };
  await kiWorkspaceOutput(result.batch.owner, { ...report, kind: "file" });
  const batch = await kiDastStoreBatch(batchId, { reports: [...(result.batch.reports || []), report] }); return { batch, reports: [report], warnings: result.warnings };
}
async function kiDastState(session) {
  await kiDastLoad(); const owner = kiDastOwner(session), context = await kiContextResolve(owner), workspace = context.workspace;
  return { workspace: workspace ? { id: workspace.id, name: workspace.name } : null, scope: workspace?.dastScope || null, capture: kiDastPrivate.captures[owner] || null,
    requests: Object.values(kiDastPrivate.requests).filter(request => request.owner === owner).map(kiDastRequestInfo), plans: Object.values(kiDastPrivate.plans).filter(plan => plan.owner === owner).map(kiDastPublicPlan), batches: kiDastBatches.filter(batch => batch.owner === owner) };
}
async function kiDastOperate(op, args, session, signal, recheck) {
  if (op === "capture") return kiDastCapture(args, session);
  if (op === "list") return { requests: (await kiDastState(session)).requests, capture: kiDastPrivate.captures[kiDastOwner(session)] || null };
  if (op === "prepare") return kiDastPrepare(args, session, signal);
  if (op === "run") return kiDastRun(args, session, signal, recheck);
  if (op === "status") return kiDastStatus(args.batchId, session, signal);
  if (op === "stop") return kiDastStop(args.batchId, session, signal);
  if (op === "findings") { const { report, ...result } = await kiDastResult(args.batchId, session, signal); return result; }
  if (op === "export") return kiDastExport(args.batchId, session, signal, recheck);
  throw Error("Unknown DAST operation.");
}
function kiDastToolDefs(session) {
  const context = kiContextFor(session), owned = kiDastBatches.some(batch => batch.owner === kiWorkspaceOwner(session));
  const descriptions = { capture: "Start/stop explicit request capture on a scoped workspace tab. Does not send test payloads.", list: "List this chat's captured request summaries and selectable input identities. Credentials and input values remain private.", prepare: "Freeze a selected-request test plan (XSS by default; also SQL error/boolean, SSTI, JSONP, redirect, passive checks). Select exact ordinals or JSON pointers from capture summaries; every request needs allowReplay:true and GET is not assumed harmless. The returned plan shows scope and budgets.", run: "Execute the frozen plan once within its fixed budget; redirects are not followed. Candidate reflection is not verified XSS; never replay a plan after uncertain start.", status: "Read this chat's DAST batch status, budget consumption and in-flight work.", stop: "Cancel queued DAST work; state remains stopping while a bounded in-flight request settles.", findings: "Per-check evidence and coverage states (tested, skipped, unsupported, inconclusive). Reflection alone does not establish XSS exploitability.", export: "Save completed DAST evidence to Downloads and workspace Outputs; reports omit authentication headers." };
  const properties = { capture: { action: { type: "string", enum: ["start", "stop"] }, tabId: { type: "integer" }, expectedOrigin: { type: "string" } }, list: {}, prepare: { requests: { type: "array", minItems: 1, maxItems: 10, items: { type: "object", properties: { requestId: { type: "string" }, allowReplay: { type: "boolean" }, parameters: { type: "array", minItems: 0, maxItems: 20, items: { type: "object", properties: { location: { type: "string", enum: ["query", "form", "json"] }, name: { type: "string" }, index: { type: "integer", minimum: 0 } }, required: ["location", "name", "index"], additionalProperties: false } } }, required: ["requestId", "allowReplay", "parameters"], additionalProperties: false } }, families: { type: "array", minItems: 1, maxItems: KI_DAST_FAMILIES.length, uniqueItems: true, items: { type: "string", enum: [...KI_DAST_FAMILIES] } }, budget: { type: "object", properties: { maxRequests: { type: "integer", minimum: 1 }, durationSeconds: { type: "integer", minimum: 1 } }, additionalProperties: false } }, run: { planId: { type: "string" }, planHash: { type: "string" } } };
  return Object.entries(kiDastNames).filter(([op, name]) => ["status", "stop"].includes(op) ? context.tools.groups.ptk === true || owned : kiContextAllows(kiDastMeta(name), context)).map(([op, name]) => ({ name, kiPolicyMeta: kiDastMeta(name), description: descriptions[op], parameters: { type: "object", properties: properties[op] || { batchId: { type: "string" } }, required: op === "capture" ? ["action"] : op === "list" ? [] : op === "prepare" ? ["requests"] : op === "run" ? ["planId", "planHash"] : ["batchId"], additionalProperties: false },
    ...(op === "run" ? { kiApprovalArgs(args) { const plan = kiDastPrivate.plans[args.planId]; if (!plan || plan.owner !== kiWorkspaceOwner(session) || plan.planHash !== args.planHash) throw Error("Prepare this chat's test plan before requesting execution."); return { planId: plan.planId, planHash: plan.planHash, testPlan: kiDastPublicPlan(plan) }; } } : {}),
    resolveExecution(args) { const snapshot = kiDastClone(args || {}); return { approvalRule: "allow", async execute(context) { try { const recheck = async () => { if (context[KI_POLICY_CONTEXT]) await kiPolicyRecheck(context[KI_POLICY_CONTEXT]); }; await recheck(); const result = await kiDastOperate(op, snapshot, session, context.signal, recheck); return { output: JSON.stringify(result), ...(["failed", "unknown", "auth_expired"].includes(result.state) || result.error ? { isError: true } : {}) }; } catch (error) { return { output: JSON.stringify({ error: error.message, ...(error.batchId ? { batchId: error.batchId } : {}) }), isError: true }; } } }; } }));
}
var kiDastReady = (async () => {
  const stored = await chrome.storage.session.get([KI_DAST_PRIVATE, "ki_dast_epoch"]); kiDastEpoch = stored.ki_dast_epoch || crypto.randomUUID();
  kiDastPrivate = stored[KI_DAST_PRIVATE] || { captures: {}, requests: {}, plans: {} };
  kiDastBatches = (await chrome.storage.local.get(KI_DAST_BATCHES))[KI_DAST_BATCHES] || [];
  for (const capture of Object.values(kiDastPrivate.captures)) capture.active = false; // Network event identities do not survive worker reconstruction.
  for (const batch of kiDastBatches) if (kiDastActive.has(batch.state) && batch.epoch !== kiDastEpoch) { batch.state = "interrupted"; batch.error = "Browser restarted; its old requests ended and this batch will not be replayed."; }
  await chrome.storage.session.set({ ki_dast_epoch: kiDastEpoch, [KI_DAST_PRIVATE]: kiDastPrivate }); await chrome.storage.local.set({ [KI_DAST_BATCHES]: kiDastBatches });
})();
kiDastReady.catch(error => console.warn("[DAST] State could not load:", error.message));
chrome.debugger?.onEvent?.addListener((source, method, params) => { void kiDastNetworkEvent(source, method, params).catch(() => {}); });
chrome.debugger?.onDetach?.addListener(source => { void kiDastWrite(async () => { for (const capture of Object.values(kiDastPrivate.captures)) if (capture.tabId === source?.tabId && capture.active) { capture.active = false; capture.error = "Browser debugger detached. Start capture again when ready."; } await kiDastSavePrivate(); }).catch(() => {}); });
chrome.tabs.onRemoved.addListener(tabId => { void kiDastWrite(async () => { for (const capture of Object.values(kiDastPrivate.captures)) if (capture.tabId === tabId) capture.active = false; await kiDastSavePrivate(); }).catch(() => {}); });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !["ki_contexts", "ki_tool_permissions", "sidepanel_approval_mode"].some(key => changes[key])) return;
  void kiDastLoad().then(async () => {
    for (const capture of Object.values(kiDastPrivate.captures).filter(item => item.active)) {
      const context = await kiDastContext(capture.owner).catch(() => null), policy = await kiDastCurrentPolicy(kiDastNames.capture, capture.owner);
      if (!context || !policy.parentEnabled || policy.rule === "disabled" || JSON.stringify(context.scope) !== JSON.stringify(capture.scope) || context.workspaceId !== capture.workspaceId) await kiDastCapture({ action: "stop" }, capture.owner);
    }
    for (const batch of kiDastBatches.filter(batch => kiDastActive.has(batch.state))) await kiDastStatus(batch.batchId, batch.owner);
  }).catch(() => {});
});
chrome.alarms.onAlarm.addListener(alarm => {
  if (!alarm.name.startsWith(KI_DAST_ALARM)) return;
  void kiDastLoad().then(async () => { const batch = kiDastBatches.find(batch => batch.batchId === alarm.name.slice(KI_DAST_ALARM.length)); if (!batch || !kiDastActive.has(batch.state)) return; if (Date.now() >= batch.deadline) await kiDastStop(batch.batchId, batch.owner); else await kiDastStatus(batch.batchId, batch.owner); const current = kiDastBatches.find(item => item.batchId === batch.batchId); if (current && kiDastActive.has(current.state)) await chrome.alarms.create(alarm.name, { when: Date.now() + 30000 }); }).catch(() => {});
});
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== "KI_DAST") return;
  const allowed = ["providers/providers.html", "pages/sidepanel.html"].map(file => chrome.runtime.getURL(file));
  if (sender.id !== chrome.runtime.id || !allowed.includes(sender.url?.split("?")[0])) { reply({ ok: false, error: "Open cert-x to use targeted DAST." }); return; }
  (async () => { try {
    await kiDastLoad(); let result;
    if (message.op === "state") result = await kiDastState(message.session);
    else if (message.op === "tabs") { const current = typeof Tt === "function" ? Tt(message.session)?.primaryTabId : null; result = (await chrome.tabs.query({})).filter(tab => /^https?:\/\//.test(tab.url || "")).map(tab => ({ tabId: tab.id, title: tab.title || tab.url, url: kiDastPublicUrl(tab.url), origin: new URL(tab.url).origin, active: !!tab.active, working: tab.id === current })); }
    else {
      const name = kiDastNames[message.op]; if (!name) throw Error("Unknown DAST operation.");
      const recheck = async () => { const policy = await kiDastCurrentPolicy(name, message.session); if (!policy.parentEnabled || policy.rule === "disabled") throw Error("This DAST operation is disabled by the profile or Tools & permissions."); };
      if (!(message.op === "capture" && message.action === "stop")) await recheck();
      result = await kiDastOperate(message.op, message, message.session, undefined, recheck);
    }
    reply({ ok: true, result });
  } catch (error) { reply({ ok: false, error: error.message, ...(error.batchId ? { batchId: error.batchId } : {}) }); } })(); return true;
});

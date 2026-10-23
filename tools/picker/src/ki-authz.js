// Account comparison keeps credential snapshots and evidence expectations private.
var KI_AUTHZ_PRIVATE = "ki_authz_private", KI_AUTHZ_BATCHES = "ki_authz_batches", KI_AUTHZ_ALARM = "ki-authz:";
var kiAuthzPrivate = { accounts: {}, plans: {} }, kiAuthzBatches = [], kiAuthzWrites = Promise.resolve(), kiAuthzStarts = Promise.resolve(), kiAuthzVerifying = new Set();
var kiAuthzNames = { state: "ptk_list_accounts", save_account: "ptk_save_account", verify: "ptk_verify_account", prepare: "ptk_prepare_access_test", run: "ptk_run_access_test", status: "ptk_access_status", stop: "ptk_stop_access_test", findings: "ptk_access_findings", export: "ptk_access_export" };
function kiAuthzMeta(name) {
  const labels = { ptk_list_accounts: "List comparison accounts", ptk_save_account: "Save comparison account", ptk_verify_account: "Verify comparison account", ptk_prepare_access_test: "Prepare access comparison", ptk_run_access_test: "Run access comparison", ptk_access_status: "Read comparison status", ptk_stop_access_test: "Stop access comparison", ptk_access_findings: "Read comparison findings", ptk_access_export: "Export comparison evidence" };
  return { id: "ptk:" + name, group: "ptk", family: "ptk", name, label: labels[name] || name, securityStop: name === kiAuthzNames.stop, defaultAsk: [kiAuthzNames.save_account, kiAuthzNames.verify, kiAuthzNames.run, kiAuthzNames.export].includes(name) };
}
function kiAuthzWrite(operation) { const task = kiAuthzWrites.then(async () => { await kiAuthzReady; return operation(); }); kiAuthzWrites = task.catch(() => {}); return task; }
async function kiAuthzLoad() { await kiAuthzReady; await kiAuthzWrites; await kiDastLoad(); return kiAuthzBatches; }
async function kiAuthzSave() { if (new TextEncoder().encode(JSON.stringify(kiAuthzPrivate)).length > 6 * 1024 * 1024) throw Error("Account comparison storage is full. Remove unused accounts or finish existing plans."); await chrome.storage.session.set({ [KI_AUTHZ_PRIVATE]: kiAuthzPrivate }); }
function kiAuthzHasActiveBatch() { return kiAuthzVerifying.size > 0 || kiAuthzBatches.some(batch => batch.epoch === kiDastEpoch && kiDastActive.has(batch.state)); }
async function kiAuthzPolicy(name, session) {
  const meta = kiAuthzMeta(name), policy = await kiPolicyState(meta), context = await kiContextResolve(session);
  return { ...policy, rule: kiContextRule(meta, context, policy.rule) };
}
async function kiAuthzCheckPolicy(name, session) { if (name === kiAuthzNames.stop) return; const policy = await kiAuthzPolicy(name, session); if (!policy.parentEnabled || policy.rule === "disabled") throw Error("This account comparison operation is disabled by Tools & permissions or the profile."); }
function kiAuthzText(value, name, required = true) { if ((!required && value == null) || (!required && value === "")) return ""; if (typeof value !== "string" || !value.trim() || value.length > 100 || /[\x00-\x1f]/.test(value)) throw Error("Enter a short " + name + "."); return value.trim(); }
function kiAuthzClaim(value) {
  if (!value || typeof value.pointer !== "string" || value.pointer.length > 1000 || (value.pointer !== "" && !value.pointer.startsWith("/")) || /~(?![01])/.test(value.pointer) || typeof value.expected !== "string" || !value.expected.length || value.expected.length > 2000) throw Error("Provide a JSON pointer and exact scalar value for each evidence claim.");
  return { pointer: value.pointer, expected: value.expected };
}
function kiAuthzCookieParts(request) {
  const headers = request.headers.filter(header => header.name.toLowerCase() === "cookie");
  if (headers.length > 1) throw Error("Multiple Cookie headers are ambiguous. Capture a request with one Cookie header.");
  if (!headers.length) return [];
  const parts = headers[0].value.split(";").map(raw => { const index = raw.indexOf("="); if (index < 1) throw Error("Captured Cookie header could not be selected exactly."); return { name: raw.slice(0, index).trim(), raw: raw.trim() }; });
  if (parts.some(part => !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(part.name)) || new Set(parts.map(part => part.name)).size !== parts.length) throw Error("Repeated or malformed cookie names cannot be selected unambiguously.");
  return parts;
}
function kiAuthzEmbeddedCredential(name) { return /^(?:auth|authorization|authentication|authtoken|accesstoken|refreshtoken|idtoken|token|tokentype|session|sessionid|csrf|csrftoken|xsrf|xsrftoken|password|passwd|apikey|jwt|bearer|credential|credentials|secret)$/.test(String(name).toLowerCase().replace(/[^a-z0-9]/g, "")); }
function kiAuthzCheckCredentialCarriers(request) {
  const names = [...new URL(request.url).searchParams.keys()], type = kiDastContentType(request);
  if (type === "application/x-www-form-urlencoded" && request.body) names.push(...new URLSearchParams(request.body).keys());
  if (kiDastJsonType(type) && request.body) for (const leaf of CertXDastInputs.parseJson(request.body)) names.push(...leaf.name.split("/").slice(1).map(part => part.replaceAll("~1", "/").replaceAll("~0", "~")));
  if (names.some(kiAuthzEmbeddedCredential)) throw Error("This request carries authentication or CSRF fields in its URL or body. Account comparison currently supports credentials in selected headers and cookies only.");
}
function kiAuthzCaptured(request) {
  if (!request || !["GET", "POST"].includes(request.method) || !request.complete || request.failed || request.redirected || request.bodyMissing || (request.expectExtra && !request.extraReceived)) throw Error("Use a completed GET or read-only POST capture with exact headers/body and no redirects.");
  const headerNames = new Set(); let headerSize = 0;
  for (const header of request.headers || []) { if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(header.name) || typeof header.value !== "string" || /[\r\n\x00]/.test(header.value) || headerNames.has(header.name.toLowerCase())) throw Error("Captured headers are malformed or repeated."); headerNames.add(header.name.toLowerCase()); headerSize += header.name.length + header.value.length; }
  if (!Array.isArray(request.headers) || request.headers.length > 100 || headerSize > 32768) throw Error("Captured headers exceed the supported limit.");
  if (request.method === "GET" && request.body) throw Error("GET requests with bodies are not supported.");
  if (request.body != null && new TextEncoder().encode(request.body).length > 65536) throw Error("Captured request body exceeds 64 KiB.");
  const type = kiDastContentType(request);
  if (request.body != null && !kiDastJsonType(type) && type !== "application/x-www-form-urlencoded") throw Error("Only exact URL-encoded forms or JSON request bodies are supported.");
  if (kiDastJsonType(type)) {
    const contentType = request.headers.find(header => header.name.toLowerCase() === "content-type")?.value || "";
    if (contentType.includes(";") && !/^\s*charset\s*=\s*(?:utf-8|"utf-8"|'utf-8')\s*$/i.test(contentType.slice(contentType.indexOf(";") + 1))) throw Error("JSON bodies require UTF-8 without unsupported media parameters.");
    CertXDastInputs.parseJson(request.body);
  }
  kiAuthzCheckCredentialCarriers(request);
  return request;
}
async function kiAuthzCapture(requestId, context) {
  const request = kiDastPrivate.requests[requestId]; kiAuthzCaptured(request);
  if (request.owner !== context.owner || request.workspaceId !== context.workspaceId || Date.now() - request.capturedAt > 30 * 60 * 1000) throw Error("Select a recent capture from this chat and workspace.");
  if (new URL(request.url).origin !== request.origin || !kiDastScopeAllows(request.url, context.scope)) throw Error("The captured request is outside this workspace's exact target scope.");
  return request;
}
function kiAuthzRequest(request) { return { url: request.url, method: request.method, headers: kiDastClone(request.headers), body: request.body }; }
function kiAuthzCaptureInfo(request) {
  let reason = "", cookies = []; try { kiAuthzCaptured(request); cookies = kiAuthzCookieParts(request).map(part => part.name); } catch (error) { reason = error.message; }
  const parameters = [];
  try {
    const url = new URL(request.url), segments = url.pathname.split("/").filter(Boolean);
    segments.forEach((segment, index) => parameters.push({ location: "path", name: String(index), index, valueType: "string", supported: true }));
    for (const [location, values] of [["query", [...url.searchParams]], ["form", kiDastContentType(request) === "application/x-www-form-urlencoded" ? [...new URLSearchParams(request.body || "")] : []]]) values.forEach(([name], index) => parameters.push({ location, name, index, valueType: "string", supported: !kiDastProtectedInput(name) }));
    if (kiDastJsonType(kiDastContentType(request))) for (const leaf of CertXDastInputs.parseJson(request.body)) parameters.push({ location: "json", name: leaf.name, index: leaf.index, valueType: leaf.valueType, supported: ["string", "number"].includes(leaf.valueType) && !kiDastProtectedInput(leaf.name.split("/").at(-1)) });
  } catch (error) { reason ||= error.message; }
  return { requestId: request.id, method: request.method, url: kiDastPublicUrl(request.url), endpoint: kiDastPublicUrl(request.url), credentialHeaders: [...new Set(request.headers.filter(header => !/^(?:cookie|host|content-length|connection|transfer-encoding|origin|referer|content-type)$/i.test(header.name)).map(header => header.name))], cookieNames: cookies, parameters, supported: !reason, reason };
}
function kiAuthzPublicAccount(account) { return { id: account.id, workspaceId: account.workspaceId, label: account.label, role: account.role, tenant: account.tenant, revision: account.revision, credentialHeaders: account.headers.filter(header => header.name.toLowerCase() !== "cookie").map(header => header.name), cookieNames: account.cookieNames, probe: { url: kiDastPublicUrl(account.probe.request.url), method: account.probe.request.method, claims: account.probe.claims.map(({ pointer }) => ({ pointer })) }, verification: account.verification || null }; }
function kiAuthzWireAccount(account) { const { id, label, role, tenant, revision, headers, probe } = account; return kiDastClone({ id, label, role, tenant, revision, headers, probe }); }
async function kiAuthzSaveAccount(args, session) {
  await kiAuthzLoad(); const context = await kiDastContext(session), request = await kiAuthzCapture(args.requestId, context);
  if (args.readOnly !== true) throw Error("Explicitly declare the identity probe read-only, including GET probes.");
  const label = kiAuthzText(args.label, "account label"), role = kiAuthzText(args.role, "role", false), tenant = kiAuthzText(args.tenant, "tenant", false);
  if (!Array.isArray(args.claims) || !args.claims.length || args.claims.length > 8) throw Error("Add between one and eight exact identity claims.");
  const claims = args.claims.map(kiAuthzClaim); if (!claims.some(claim => claim.expected !== "null")) throw Error("An account needs a non-null principal identity claim."); if (new Set(claims.map(claim => claim.pointer)).size !== claims.length) throw Error("Select each identity pointer once.");
  if (!Array.isArray(args.credentialHeaders) || !Array.isArray(args.cookieNames)) throw Error("Select credential header and cookie names from the captured probe.");
  const headers = [], names = new Set(), cookies = kiAuthzCookieParts(request);
  for (const name of args.credentialHeaders) {
    if (typeof name !== "string" || names.has(name.toLowerCase()) || /^(?:cookie|host|content-length|connection|transfer-encoding|origin|referer|content-type)$/i.test(name) || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name)) throw Error("Select distinct credential headers; select cookies by their cookie names.");
    const found = request.headers.filter(header => header.name.toLowerCase() === name.toLowerCase()); if (found.length !== 1) throw Error("A selected credential header is missing or repeated.");
    headers.push(kiDastClone(found[0])); names.add(name.toLowerCase());
  }
  if (new Set(args.cookieNames).size !== args.cookieNames.length) throw Error("Select each cookie once.");
  const selectedCookies = args.cookieNames.map(name => { const cookie = cookies.find(cookie => cookie.name === name); if (!cookie) throw Error("A selected cookie is missing from the captured probe."); return cookie; });
  if (selectedCookies.length) headers.push({ name: "Cookie", value: selectedCookies.map(cookie => cookie.raw).join("; ") });
  if (!headers.length) throw Error("Select at least one captured credential header or cookie. Anonymous is available separately.");
  const id = args.id || crypto.randomUUID();
  const result = await kiAuthzWrite(async () => {
    const old = kiAuthzPrivate.accounts[id]; if (args.id && (!old || old.workspaceId !== context.workspaceId)) throw Error("This account is not in the current workspace.");
    if (!old && Object.values(kiAuthzPrivate.accounts).filter(account => account.workspaceId === context.workspaceId).length >= 4) throw Error("Use up to four accounts per workspace.");
    const account = { id, label, role, tenant, revision: (old?.revision || 0) + 1, workspaceId: context.workspaceId, origin: request.origin, tabId: request.tabId, headers, cookieNames: selectedCookies.map(cookie => cookie.name), probe: { request: kiAuthzRequest(request), claims, readOnly: true } };
    kiAuthzPrivate.accounts[id] = account; try { await kiAuthzSave(); } catch (error) { if (old) kiAuthzPrivate.accounts[id] = old; else delete kiAuthzPrivate.accounts[id]; throw error; }
    return kiAuthzPublicAccount(account);
  });
  await kiAuthzRevokeAccount(id); return result;
}
async function kiAuthzDeleteAccount(args, session) { return kiAuthzExclusive(async () => {
  await kiAuthzLoad(); const context = await kiDastContext(session), account = kiAuthzPrivate.accounts[args.accountId];
  if (!account || account.workspaceId !== context.workspaceId) throw Error("Account not found in this workspace.");
  // Cancel admission before removing the snapshot, so a queued identity check
  // observes cancellation rather than racing into an unrelated missing-account error.
  await kiAuthzRevokeAccount(args.accountId);
  await kiAuthzWrite(async () => { const current = kiAuthzPrivate.accounts[args.accountId]; if (!current || current.workspaceId !== context.workspaceId) throw Error("Account not found in this workspace."); delete kiAuthzPrivate.accounts[args.accountId]; await kiAuthzSave(); });
  return { deleted: true };
}); }
async function kiAuthzRevokeAccount(id) { for (const batch of kiAuthzBatches.filter(batch => kiDastActive.has(batch.state) && batch.accounts.some(account => account.id === id))) await kiAuthzStop(batch.batchId, batch.owner).catch(() => {}); }
function kiAuthzSwap(request, swap) {
  if (!swap) return kiDastClone(request);
  if (!swap || typeof swap.value !== "string" || !swap.value.length || swap.value.length > 2000 || !Number.isInteger(swap.index) || swap.index < 0 || typeof swap.name !== "string") throw Error("Choose one captured object input and a single replacement ID.");
  const info = kiAuthzCaptureInfo({ ...request, id: "swap", complete: true }), field = info.parameters.find(field => field.location === swap.location && field.index === swap.index && field.name === swap.name);
  if (!field?.supported) throw Error("The object replacement does not match a selectable captured input.");
  const result = kiDastClone(request);
  if (swap.location === "path") {
    if (/[\\/\x00-\x20]/.test(swap.value) || /^\.{1,2}$/.test(swap.value) || /%/.test(swap.value)) throw Error("Path object IDs cannot contain separators, dot segments or encoded ambiguity.");
    const parsed = new URL(request.url), parts = parsed.pathname.split("/"); let index = -1;
    const pathname = parts.map(part => part && ++index === swap.index ? encodeURIComponent(swap.value) : part).join("/");
    result.url = request.url.replace(parsed.origin + parsed.pathname, parsed.origin + pathname);
  } else if (swap.location === "query" || swap.location === "form") {
    const query = swap.location === "query", mark = request.url.indexOf("?"), hash = request.url.indexOf("#", mark), raw = query ? request.url.slice(mark + 1, hash < 0 ? undefined : hash) : request.body;
    const parts = raw.split("&"), rawIndex = parts.map((part, index) => part ? index : -1).filter(index => index >= 0)[swap.index], part = parts[rawIndex]; if (part == null) throw Error("The captured input ordinal changed.");
    parts[rawIndex] = part.split("=")[0] + "=" + encodeURIComponent(swap.value);
    if (query) result.url = request.url.slice(0, mark + 1) + parts.join("&") + (hash < 0 ? "" : request.url.slice(hash)); else result.body = parts.join("&");
  } else if (swap.location === "json") {
    const leaf = CertXDastInputs.parseJson(request.body).find(leaf => leaf.name === swap.name && leaf.index === swap.index);
    if (leaf.valueType === "number") {
      if (!/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(swap.value)) throw Error("Numeric JSON object IDs require an exact JSON number token.");
      result.body = request.body.slice(0, leaf.start) + swap.value + request.body.slice(leaf.end); CertXDastInputs.parseJson(result.body);
    } else result.body = CertXDastInputs.replaceJson(request.body, swap, swap.value);
  } else throw Error("Unsupported object input location.");
  return result;
}
function kiAuthzPublicPlan(plan) { return { planId: plan.planId, planHash: plan.planHash, state: plan.state, createdAt: plan.createdAt, expiresAt: plan.expiresAt, workspaceId: plan.workspaceId, scope: plan.scope, budget: plan.budget, accounts: plan.accounts.map(kiAuthzPublicAccount), cases: plan.cases.map(item => ({ id: item.id, label: item.label, requestId: item.requestId, method: item.request.method, url: kiDastPublicUrl(item.request.url), endpoint: kiDastPublicUrl(item.request.url), ownerAccountId: item.ownerAccountId, readOnly: true, evidence: { object: { pointer: item.evidence.object.pointer }, protected: { pointer: item.evidence.protected.pointer } }, expectations: item.expectations, ...(item.objectSwap ? { objectSwap: { location: item.objectSwap.location, name: item.objectSwap.name, index: item.objectSwap.index } } : {}) })) }; }
async function kiAuthzCapabilities(tabId, origin, signal) { const value = await kiDastCompanion("capabilities", { tabId, expectedOrigin: origin }, signal); if (value?.ready !== true || !Number.isInteger(value.revision) || value.revision < 4 || value.authz !== true) throw Error("The integrated account-comparison runtime is unavailable. Reload cert-x."); }
async function kiAuthzPrepare(args, session, signal) {
  await kiAuthzLoad(); const context = await kiDastContext(session);
  if (!Array.isArray(args.cases) || !args.cases.length || args.cases.length > 10) throw Error("Select between one and ten read-only cases.");
  const cases = [], accountIds = new Set(); let tabId, origin;
  for (const selection of args.cases) {
    if (selection.readOnly !== true) throw Error("Declare every selected request read-only, including GET requests.");
    const captured = await kiAuthzCapture(selection.requestId, context), request = kiAuthzSwap(captured, selection.objectSwap);
    tabId ??= captured.tabId; origin ??= captured.origin; if (captured.tabId !== tabId || captured.origin !== origin || !kiDastScopeAllows(request.url, context.scope)) throw Error("Cases must remain in one captured tab and exact scoped origin.");
    const owner = kiAuthzPrivate.accounts[selection.ownerAccountId]; if (!owner || owner.workspaceId !== context.workspaceId) throw Error("Select a real owner account from this workspace."); accountIds.add(owner.id);
    const evidence = { object: kiAuthzClaim(selection.evidence?.object), protected: kiAuthzClaim(selection.evidence?.protected) }; if (evidence.protected.expected === "null") throw Error("Protected evidence requires a non-null application-specific value."); if (evidence.object.pointer === evidence.protected.pointer) throw Error("Object identity and protected evidence must use distinct JSON pointers.");
    if (!Array.isArray(selection.expectations) || !selection.expectations.length || selection.expectations.length > 5) throw Error("Set expected access for each selected comparison account.");
    const expected = new Set(), expectations = selection.expectations.map(item => { if (!item || !["allow", "deny"].includes(item.expected) || typeof item.accountId !== "string" || expected.has(item.accountId)) throw Error("Choose allow or deny once per comparison account."); if (item.accountId === owner.id && item.expected === "deny") throw Error("The owner account must have allowed access to establish the legitimate baseline. Choose allow for the owner or select a different comparison account."); expected.add(item.accountId); if (item.accountId !== "anonymous") accountIds.add(item.accountId); return { accountId: item.accountId, expected: item.expected }; });
    cases.push({ id: crypto.randomUUID(), label: selection.label ? kiAuthzText(selection.label, "case label") : "Case " + (cases.length + 1), requestId: selection.requestId, request: kiAuthzRequest(request), ownerAccountId: owner.id, readOnly: true, evidence, expectations, ...(selection.objectSwap ? { objectSwap: kiDastClone(selection.objectSwap) } : {}) });
  }
  if (accountIds.size > 4) throw Error("Use up to four real accounts.");
  const accounts = [...accountIds].map(id => { const account = kiAuthzPrivate.accounts[id]; if (!account || account.workspaceId !== context.workspaceId || account.origin !== origin || !kiDastScopeAllows(account.probe.request.url, context.scope)) throw Error("A selected account is missing or its identity probe is outside the scoped origin."); return kiDastClone(account); });
  await kiDastTab(tabId, origin); await kiAuthzCapabilities(tabId, origin, signal); signal?.throwIfAborted();
  const createdAt = Date.now(), plan = { ...context, tabId, origin, cases, accounts, budget: kiDastBudget(args.budget), createdAt, expiresAt: createdAt + 15 * 60 * 1000, planId: crypto.randomUUID(), state: "prepared" };
  if (globalThis.certXSecurity) await globalThis.certXSecurity.resolveConfig(context.workspaceId, plan.budget);
  plan.planHash = await kiDastHash(plan);
  return kiAuthzWrite(async () => { for (const [id, old] of Object.entries(kiAuthzPrivate.plans)) if (old.state === "prepared" && old.expiresAt < Date.now()) delete kiAuthzPrivate.plans[id]; if (Object.keys(kiAuthzPrivate.plans).length >= 20) throw Error("Finish or discard existing comparison plans before preparing more."); kiAuthzPrivate.plans[plan.planId] = plan; try { await kiAuthzSave(); } catch (error) { delete kiAuthzPrivate.plans[plan.planId]; throw error; } return kiAuthzPublicPlan(plan); });
}
async function kiAuthzPlanCheck(plan, session) {
  const context = await kiDastContext(session); if (!plan || plan.owner !== context.owner || plan.workspaceId !== context.workspaceId || JSON.stringify(plan.scope) !== JSON.stringify(context.scope)) throw Error("Workspace or target scope changed. Prepare a new comparison plan.");
  await kiDastTab(plan.tabId, plan.origin);
  for (const snapshot of plan.accounts) { const current = kiAuthzPrivate.accounts[snapshot.id]; if (!current || current.workspaceId !== plan.workspaceId || current.revision !== snapshot.revision) throw Error("An account changed or was removed. Prepare a new comparison plan."); if (!kiDastScopeAllows(snapshot.probe.request.url, context.scope)) throw Error("An identity probe is no longer in scope."); }
  for (const item of plan.cases) if (new URL(item.request.url).origin !== plan.origin || !kiDastScopeAllows(item.request.url, context.scope)) throw Error("A comparison request is no longer in scope.");
}
async function kiAuthzExclusive(operation) { const task = kiAuthzStarts.then(() => typeof kiPtkLock === "function" ? kiPtkLock("scan-start", operation) : operation()); kiAuthzStarts = task.catch(() => {}); return task; }
async function kiAuthzIdle() { await kiAuthzLoad(); if (typeof kiPtkLoad === "function") await kiPtkLoad(); if (kiAuthzHasActiveBatch() || kiDastHasActiveBatch() || (typeof kiPtkCache === "object" && kiPtkCache.some(item => kiDastActive.has(item.state)))) throw Error("Finish or stop the active PTK analysis, DAST batch or account verification first."); }
async function kiAuthzVerify(args, session, signal, recheck, parentRequestGuard) { return kiAuthzExclusive(async () => {
  await kiAuthzIdle(); const context = await kiDastContext(session), account = kiAuthzPrivate.accounts[args.accountId]; if (!account || account.workspaceId !== context.workspaceId) throw Error("Select an account from this workspace.");
  const snapshot = kiDastClone(account), token = crypto.randomUUID(); kiAuthzVerifying.add(token);
  try {
    const check = async () => { signal?.throwIfAborted(); await recheck?.(); await kiAuthzCheckPolicy(kiAuthzNames.verify, session); const fresh = await kiDastContext(session), current = kiAuthzPrivate.accounts[snapshot.id]; if (!current || current.revision !== snapshot.revision || current.workspaceId !== fresh.workspaceId || JSON.stringify(fresh.scope) !== JSON.stringify(context.scope) || !kiDastScopeAllows(snapshot.probe.request.url, fresh.scope)) throw Error("Account or scope changed during verification."); await kiDastTab(snapshot.tabId, snapshot.origin); };
    await check(); await kiAuthzCapabilities(snapshot.tabId, snapshot.origin, signal);
    const result = await kiDastCompanion("authz_verify", { owner: context.owner, account: kiAuthzWireAccount(snapshot), scope: context.scope, origin: snapshot.origin, expectedOrigin: snapshot.origin, tabId: snapshot.tabId, workspaceId: context.workspaceId, budget: kiDastBudget({ maxRequests: 10, durationSeconds: 60 }) }, signal, check, parentRequestGuard);
    if (!result || !["verified", "inconclusive"].includes(result.state || result.status)) throw Error("The security engine returned an invalid identity verification result.");
    await check(); const verification = { state: result.state || result.status, verified: (result.state || result.status) === "verified", reason: String(result.reason || "").slice(0, 1000), checkedAt: Date.now() };
    return kiAuthzWrite(async () => { const current = kiAuthzPrivate.accounts[snapshot.id]; if (!current || current.revision !== snapshot.revision) throw Error("Account changed during verification."); current.verification = verification; await kiAuthzSave(); return { account: kiAuthzPublicAccount(current), ...verification }; });
  } finally { kiAuthzVerifying.delete(token); }
}); }
async function kiAuthzStore(batchId, patch) { return kiAuthzWrite(async () => { const old = kiAuthzBatches.find(batch => batch.batchId === batchId), next = { ...old, ...patch, batchId, updatedAt: Date.now() }; if (old && !kiDastActive.has(old.state)) next.state = old.state; kiAuthzBatches = kiAuthzBatches.filter(batch => batch.batchId !== batchId).concat(next).slice(-50); await chrome.storage.local.set({ [KI_AUTHZ_BATCHES]: kiAuthzBatches }); if (!kiDastActive.has(next.state) && kiAuthzPrivate.plans[next.planId]?.batchId === batchId) { delete kiAuthzPrivate.plans[next.planId]; await kiAuthzSave(); } return next; }); }
async function kiAuthzBatch(id, session) { await kiAuthzLoad(); const batch = kiAuthzBatches.find(batch => batch.batchId === id); if (!batch || batch.owner !== kiDastOwner(session)) throw Error("Comparison batch does not belong to this chat."); return batch; }
async function kiAuthzRun(args, session, signal, recheck) { return kiAuthzExclusive(async () => {
  await kiAuthzIdle(); const plan = kiAuthzPrivate.plans[args.planId]; await kiAuthzPlanCheck(plan, session);
  if (plan.planHash !== args.planHash || plan.expiresAt <= Date.now() || plan.state !== "prepared") throw Error("The comparison plan changed, expired or was already dispatched. It will not be replayed.");
  await kiAuthzCheckPolicy(kiAuthzNames.run, session); await recheck?.(); signal?.throwIfAborted();
  const batchId = crypto.randomUUID(), startedAt = Date.now(); plan.state = "dispatched"; plan.batchId = batchId; await kiAuthzWrite(kiAuthzSave);
  const batch = await kiAuthzStore(batchId, { owner: plan.owner, workspaceId: plan.workspaceId, epoch: kiDastEpoch, planId: plan.planId, planHash: plan.planHash, tabId: plan.tabId, origin: plan.origin, scope: plan.scope, budget: plan.budget, accounts: plan.accounts.map(account => ({ id: account.id, label: account.label, revision: account.revision })), plan: kiAuthzPublicPlan(plan), state: "starting", startedAt, deadline: startedAt + plan.budget.durationSeconds * 1000, requestsSent: 0, reports: [] });
  let dispatched = false;
  try {
    const check = async () => { await kiAuthzPlanCheck(plan, session); await kiAuthzCheckPolicy(kiAuthzNames.run, session); await recheck?.(); signal?.throwIfAborted(); if (plan.expiresAt <= Date.now()) throw Error("Comparison plan expired while connecting."); if (kiAuthzBatches.find(batch => batch.batchId === batchId)?.stopRequestedAt) throw Object.assign(Error("Comparison stopped before dispatch."), { cancelledBeforeDispatch: true }); dispatched = true; };
    const result = await kiDastCompanion("authz_run", { batchId, owner: plan.owner, workspaceId: plan.workspaceId, origin: plan.origin, expectedOrigin: plan.origin, tabId: plan.tabId, scope: plan.scope, budget: plan.budget, accounts: plan.accounts.map(kiAuthzWireAccount), cases: plan.cases.map(({ id, label, request, ownerAccountId, readOnly, evidence, expectations }) => ({ id, label, request, ownerAccountId, readOnly, evidence, expectations })) }, signal, check);
    // Only this explicit pre-admission refusal proves that nothing executed.
    // A missing, malformed or unrelated reply still leaves the start uncertain.
    if (result?.accepted === false && result.state === "failed" && result.batchId === batchId && result.owner === plan.owner && result.requestsSent === 0 && result.inFlight === 0 && typeof result.error === "string" && result.error.trim()) {
      const error = result.error.slice(0, 1000);
      return kiAuthzStore(batchId, { state: "failed", requestsSent: 0, inFlight: 0, error, errors: [error] });
    }
    if (result?.accepted !== true) throw Error("The companion did not acknowledge the comparison batch."); const patch = kiDastPublicStatus(result, batch); if (kiDastActive.has(patch.state)) await chrome.alarms.create(KI_AUTHZ_ALARM + batchId, { when: Math.min(batch.deadline, Date.now() + 30000) }); return kiAuthzStore(batchId, patch);
  } catch (error) { await kiAuthzStore(batchId, { state: dispatched ? "unknown" : error.cancelledBeforeDispatch ? "stopped" : "failed", error: dispatched ? "Comparison start outcome is unknown. Inspect or stop it; never replay this plan." : error.message }); error.batchId = batchId; throw error; }
}); }
async function kiAuthzStop(batchId, session, signal) { const batch = await kiAuthzBatch(batchId, session); if (!kiDastActive.has(batch.state)) return batch; await kiAuthzStore(batchId, { state: "stopping", stopRequestedAt: Date.now() }); const result = await kiDastCompanion("authz_stop", { batchId, owner: batch.owner, tabId: batch.tabId, expectedOrigin: batch.origin }, signal); return kiAuthzStore(batchId, kiDastPublicStatus(result, batch)); }
async function kiAuthzStatus(batchId, session, signal) {
  const batch = await kiAuthzBatch(batchId, session); if (!kiDastActive.has(batch.state) || batch.epoch !== kiDastEpoch) return batch;
  try {
    try { await kiAuthzPlanCheck(kiAuthzPrivate.plans[batch.planId], session); await kiAuthzCheckPolicy(kiAuthzNames.run, session); } catch { return await kiAuthzStop(batchId, session, signal); }
    const result = await kiDastCompanion("authz_status", { batchId, owner: batch.owner, tabId: batch.tabId, expectedOrigin: batch.origin }, signal), patch = kiDastPublicStatus(result, batch); if (!kiDastActive.has(patch.state)) await chrome.alarms.clear(KI_AUTHZ_ALARM + batchId); return kiAuthzStore(batchId, patch);
  } catch { signal?.throwIfAborted(); return kiAuthzStore(batchId, { state: "unknown", error: "Companion status unavailable. Stop or inspect this batch before another comparison." }); }
}
async function kiAuthzResult(batchId, session, signal) { const batch = await kiAuthzBatch(batchId, session), result = await kiDastCompanion("authz_result", { batchId, owner: batch.owner, tabId: batch.tabId, expectedOrigin: batch.origin }, signal), patch = kiDastPublicStatus(result, batch); if (!Array.isArray(result.cells) || JSON.stringify(result).length > 4 * 1024 * 1024) throw Error("The companion returned invalid comparison evidence."); return { batch: await kiAuthzStore(batchId, patch), cells: result.cells.slice(0, 50), findings: Array.isArray(result.findings) ? result.findings.slice(0, 50) : [], warnings: patch.warnings, report: result.report }; }
async function kiAuthzExport(batchId, session, signal, recheck) {
  const result = await kiAuthzResult(batchId, session, signal); if (kiDastActive.has(result.batch.state)) throw Error("Stop the comparison and wait for in-flight work before exporting."); if (!result.report || typeof result.report !== "object") throw Error("Comparison report unavailable."); await recheck?.(); signal?.throwIfAborted();
  const bytes = new TextEncoder().encode(JSON.stringify(result.report, null, 2)); let binary = ""; for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
  const name = "cert-x-access-" + batchId + ".json", downloadId = await kiPtkDownload(name, btoa(binary), "application/json", signal), report = { name, downloadId, size: bytes.length };
  await kiWorkspaceOutput(result.batch.owner, { ...report, kind: "file" }); return { batch: await kiAuthzStore(batchId, { reports: [...(result.batch.reports || []), report] }), reports: [report], warnings: result.warnings };
}
async function kiAuthzState(session) { await kiAuthzLoad(); const owner = kiDastOwner(session), context = await kiContextResolve(owner), workspace = context.workspace; return { workspace: workspace ? { id: workspace.id, name: workspace.name } : null, scope: workspace?.dastScope || null, accounts: Object.values(kiAuthzPrivate.accounts).filter(account => account.workspaceId === workspace?.id).map(kiAuthzPublicAccount), captures: Object.values(kiDastPrivate.requests).filter(request => request.owner === owner && request.workspaceId === workspace?.id).map(kiAuthzCaptureInfo), capture: kiDastPrivate.captures[owner]?.workspaceId === workspace?.id ? kiDastPrivate.captures[owner] : null, plans: Object.values(kiAuthzPrivate.plans).filter(plan => plan.owner === owner && plan.workspaceId === workspace?.id).map(kiAuthzPublicPlan), batches: kiAuthzBatches.filter(batch => batch.owner === owner) }; }
async function kiAuthzOperate(op, args, session, signal, recheck) { if (op === "state") return kiAuthzState(session); if (op === "save_account") return kiAuthzSaveAccount(args, session); if (op === "delete_account") return kiAuthzDeleteAccount(args, session); if (op === "verify") return kiAuthzVerify(args, session, signal, recheck); if (op === "prepare") return kiAuthzPrepare(args, session, signal); if (op === "run") return kiAuthzRun(args, session, signal, recheck); if (op === "status") return kiAuthzStatus(args.batchId, session, signal); if (op === "stop") return kiAuthzStop(args.batchId, session, signal); if (op === "findings") { const { report, ...result } = await kiAuthzResult(args.batchId, session, signal); return result; } if (op === "export") return kiAuthzExport(args.batchId, session, signal, recheck); throw Error("Unknown account comparison operation."); }
function kiAuthzToolDefs(session) {
  const context = kiContextFor(session), owned = kiAuthzBatches.some(batch => batch.owner === kiWorkspaceOwner(session)), string = { type: "string" }, claim = { type: "object", properties: { pointer: string, expected: string }, required: ["pointer", "expected"], additionalProperties: false };
  const properties = { state: {}, save_account: { requestId: string, label: string, role: string, tenant: string, id: string, credentialHeaders: { type: "array", items: string }, cookieNames: { type: "array", items: string }, claims: { type: "array", minItems: 1, maxItems: 8, items: claim }, readOnly: { type: "boolean" } }, verify: { accountId: string }, prepare: { cases: { type: "array", minItems: 1, maxItems: 10, items: { type: "object", properties: { requestId: string, label: string, ownerAccountId: string, readOnly: { type: "boolean" }, evidence: { type: "object", properties: { object: claim, protected: claim }, required: ["object", "protected"], additionalProperties: false }, expectations: { type: "array", minItems: 1, maxItems: 5, items: { type: "object", properties: { accountId: string, expected: { type: "string", enum: ["allow", "deny"] } }, required: ["accountId", "expected"], additionalProperties: false } }, objectSwap: { type: "object", properties: { location: { type: "string", enum: ["path", "query", "form", "json"] }, name: string, index: { type: "integer", minimum: 0 }, value: string }, required: ["location", "name", "index", "value"], additionalProperties: false } }, required: ["requestId", "ownerAccountId", "readOnly", "evidence", "expectations"], additionalProperties: false } }, budget: { type: "object", properties: { maxRequests: { type: "integer", minimum: 1 }, durationSeconds: { type: "integer", minimum: 1 }, maxRequestsPerSecond: { type: "number", exclusiveMinimum: 0 } }, additionalProperties: false } }, run: { planId: string, planHash: string } };
  const descriptions = { state: "List workspace comparison accounts and this chat's captured request identities, plans and batches. Secrets and expected evidence values remain private.", save_account: "Save a workspace comparison account from an explicitly read-only captured identity probe. Select credential header/cookie names; never provide passwords or raw credentials. Configure exact scalar JSON identity claims.", verify: "Verify a saved identity using its read-only probe and exact claims. A failed or ambiguous identity remains inconclusive.", prepare: "Freeze an access-comparison plan with explicit read-only cases, owner identity, exact object/protected JSON evidence and expected allow/deny policy. Optionally replace one specified object ID; never enumerate IDs.", run: "Run the exact approved comparison once, within its scope and budget. Unknown starts must never be replayed.", status: "Read comparison progress and per-batch request consumption.", stop: "Stop queued comparison work; bounded in-flight work may still finish.", findings: "Read expected access/denial, reproduced unexpected access or inconclusive comparison cells. A denied case does not establish general authorization security.", export: "Export sanitized comparison evidence after work settles and register the completed download in chat Outputs." };
  return Object.entries(kiAuthzNames).filter(([op, name]) => ["status", "stop"].includes(op) ? context.tools.groups.ptk === true || owned : kiContextAllows(kiAuthzMeta(name), context)).map(([op, name]) => ({ name, kiPolicyMeta: kiAuthzMeta(name), description: descriptions[op], parameters: { type: "object", properties: properties[op] || { batchId: string }, required: op === "state" ? [] : op === "save_account" ? ["requestId", "label", "credentialHeaders", "cookieNames", "claims", "readOnly"] : op === "verify" ? ["accountId"] : op === "prepare" ? ["cases"] : op === "run" ? ["planId", "planHash"] : ["batchId"], additionalProperties: false },
    ...(op === "run" ? { kiApprovalArgs(args) { const plan = kiAuthzPrivate.plans[args.planId]; if (!plan || plan.owner !== kiWorkspaceOwner(session) || plan.planHash !== args.planHash) throw Error("Prepare this chat's comparison plan first."); return { planId: plan.planId, planHash: plan.planHash, testPlan: kiAuthzPublicPlan(plan) }; } } : {}),
    ...(op === "save_account" ? { kiApprovalPreview(args) { return { requestId: args.requestId, label: args.label, credentialHeaders: args.credentialHeaders, cookieNames: args.cookieNames, identityPointers: (args.claims || []).map(claim => claim.pointer), readOnly: args.readOnly }; } } : {}),
    resolveExecution(args) { const snapshot = kiDastClone(args || {}); return { approvalRule: "allow", async execute(context) { try { const recheck = async () => { if (context[KI_POLICY_CONTEXT]) await kiPolicyRecheck(context[KI_POLICY_CONTEXT]); await kiAuthzCheckPolicy(name, session); }; await recheck(); const result = await kiAuthzOperate(op, snapshot, session, context.signal, recheck); return { output: JSON.stringify(result), ...(["failed", "unknown", "inconclusive"].includes(result.state) ? { isError: true } : {}) }; } catch (error) { return { output: JSON.stringify({ error: error.message, ...(error.batchId ? { batchId: error.batchId } : {}) }), isError: true }; } } }; } }));
}
var kiAuthzReady = (async () => { await kiDastReady; const stored = await chrome.storage.session.get(KI_AUTHZ_PRIVATE); kiAuthzPrivate = stored[KI_AUTHZ_PRIVATE] || { accounts: {}, plans: {} }; kiAuthzBatches = (await chrome.storage.local.get(KI_AUTHZ_BATCHES))[KI_AUTHZ_BATCHES] || []; for (const batch of kiAuthzBatches) if (kiDastActive.has(batch.state) && batch.epoch !== kiDastEpoch) { batch.state = "interrupted"; batch.error = "Browser restarted. This comparison will not be replayed."; } await chrome.storage.local.set({ [KI_AUTHZ_BATCHES]: kiAuthzBatches }); })();
kiAuthzReady.catch(() => console.warn("[Access comparison] State unavailable."));
chrome.storage.onChanged.addListener((changes, area) => { if (area !== "local" || !["ki_contexts", "ki_tool_permissions", "sidepanel_approval_mode"].some(key => changes[key])) return; void kiAuthzLoad().then(async () => { for (const batch of kiAuthzBatches.filter(batch => kiDastActive.has(batch.state))) await kiAuthzStatus(batch.batchId, batch.owner); }).catch(() => {}); });
chrome.alarms.onAlarm.addListener(alarm => { if (!alarm.name.startsWith(KI_AUTHZ_ALARM)) return; void kiAuthzLoad().then(async () => { const batch = kiAuthzBatches.find(batch => batch.batchId === alarm.name.slice(KI_AUTHZ_ALARM.length)); if (!batch || !kiDastActive.has(batch.state)) return; if (Date.now() >= batch.deadline) await kiAuthzStop(batch.batchId, batch.owner); else await kiAuthzStatus(batch.batchId, batch.owner); if (kiDastActive.has(kiAuthzBatches.find(item => item.batchId === batch.batchId)?.state)) await chrome.alarms.create(alarm.name, { when: Date.now() + 30000 }); }).catch(() => {}); });
chrome.runtime.onMessage.addListener((message, sender, reply) => { if (message?.type !== "KI_AUTHZ") return; const allowed = ["providers/providers.html", "pages/sidepanel.html"].map(file => chrome.runtime.getURL(file)); if (sender.id !== chrome.runtime.id || !allowed.includes(sender.url?.split("?")[0])) { reply({ ok: false, error: "Open cert-x to compare accounts." }); return; } (async () => { try { await kiAuthzLoad(); const name = kiAuthzNames[message.op] || (message.op === "delete_account" ? kiAuthzNames.save_account : null); if (!name) throw Error("Unknown account comparison operation."); const recheck = () => kiAuthzCheckPolicy(name, message.session); if (message.op !== "state") await recheck(); const result = await kiAuthzOperate(message.op, message, message.session, undefined, recheck); reply({ ok: true, result }); } catch (error) { reply({ ok: false, error: error.message, ...(error.batchId ? { batchId: error.batchId } : {}) }); } })(); return true; });

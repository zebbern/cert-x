const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm"), { webcrypto } = require("node:crypto");
const inputCode = fs.readFileSync(path.join(__dirname, "../../../security/compat/dast-inputs.js"), "utf8");
const code = fs.readFileSync(path.join(__dirname, "../src/ki-dast.js"), "utf8"), plain = value => JSON.parse(JSON.stringify(value));
function fixture(initial = {}) {
  const local = structuredClone(initial.local || {}), sessionData = structuredClone(initial.session || {}), events = {}, calls = [], outputs = [], downloads = [], alarms = new Map();
  let disabled = false, failRun = false, loseReply = false, failExport = false, beforeRun, runReply;
  const contexts = { chat: { workspace: { id: "workspace", name: "Target", dastScope: { origins: ["https://target.test"], excludePaths: ["/logout", "/admin"] } }, tools: { groups: { ptk: true } } } };
  const tabs = [{ id: 7, url: "https://target.test/app", active: true, status: "complete", title: "Target" }, { id: 8, url: "https://other.test/app", active: false, status: "complete", title: "Other" }];
  const storage = data => ({ get: async key => typeof key === "string" ? { [key]: structuredClone(data[key]) } : Object.fromEntries(key.map(key => [key, structuredClone(data[key])])), set: async value => Object.assign(data, structuredClone(value)) });
  const event = name => ({ addListener: listener => { (events[name] ||= []).push(listener); } });
  let engine, capabilities = { ready: true, authz: true, revision: 4, families: ["xss", "sql_injection", "open_redirect"], inputLocations: ["query", "form", "json"] };
  const scope = vm.createContext({ console, crypto: webcrypto, URL, URLSearchParams, TextEncoder, Uint8Array, Date, AbortController, atob, btoa,
    kiWorkspaceOwner: owner => owner === "child" ? "chat" : owner,
    kiContextResolve: async session => structuredClone(contexts[session] || { workspace: null, tools: { groups: { ptk: false } } }), kiContextFor: () => contexts.chat,
    kiContextAllows: () => true, kiContextRule: (meta, context, rule) => context.tools.groups.ptk ? rule : "disabled",
    kiPolicyState: async () => ({ parentEnabled: true, rule: disabled ? "disabled" : "inherit" }), KI_POLICY_CONTEXT: Symbol(),
    kiWorkspaceOutput: async (owner, output) => outputs.push({ owner, ...plain(output) }), kiPtkDownload: async (name, data) => { if (failExport) throw Error("Download failed"); downloads.push({ name, data }); return 44; }, kiPtkCache: [],
    Tt: () => ({ primaryTabId: 7 }), mP: { cdp: { execute: async args => { calls.push({ cdp: plain(args) }); return {}; } } },
    kiDastCompanion: async (op, payload, signal, beforeDispatch) => {
      if (op === "authz_run" || op === "authz_verify") { await beforeRun?.(); await beforeDispatch?.(); }
      calls.push({ op, payload: plain(payload) });
      if (op === "capabilities") return structuredClone(capabilities);
      if (op === "authz_run") { if (failRun) throw Error("Transport disconnected"); if (runReply) return runReply(payload); engine = { batchId: payload.batchId, owner: payload.owner, state: "running", requestsSent: 0, inFlight: 0, findingsCount: 0, warnings: [], errors: [] }; if (loseReply) throw Error("Accepted reply was lost"); return { accepted: true, ...structuredClone(engine) }; }
      if (op === "authz_stop") { if (!engine) throw Error("Batch is not yet known by companion"); engine.state = "stopped"; }
      if (op === "authz_result") return { ...engine, cells: [{ caseId: "case", accountId: "anonymous", expected: "deny", outcome: "unexpected_access" }], findings: [], report: { schema: "cert-x-authz/v1", cells: [] } };
      if (op === "authz_verify") return { state: "verified", verified: true, reason: "Exact identity claims matched", requestsSent: 1 };
      return structuredClone(engine);
    },
    chrome: { storage: { local: storage(local), session: storage(sessionData), onChanged: event("changed") }, runtime: { id: "test", getURL: file => "chrome-extension://test/" + file, onMessage: event("message") },
      debugger: { onEvent: event("network"), onDetach: event("detached") }, tabs: { get: async id => { const tab = tabs.find(tab => tab.id === id); if (!tab) throw Error("Tab closed"); return structuredClone(tab); }, query: async () => structuredClone(tabs), onRemoved: event("removed") },
      alarms: { create: async (name, value) => alarms.set(name, value), clear: async name => alarms.delete(name), onAlarm: event("alarm") } },
  });
  vm.runInContext(inputCode, scope);
  vm.runInContext(code, scope);
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../src/ki-authz.js"), "utf8"), scope);
  const request = (op, extra = {}, sender = { id: "test", url: "chrome-extension://test/pages/sidepanel.html" }) => new Promise(resolve => events.message.forEach(listener => listener({ type: "KI_AUTHZ", op, session: "chat", ...extra }, sender, resolve)));
  async function capture() { await scope.kiDastCapture({ action: "start", tabId: 7, expectedOrigin: "https://target.test" }, "chat"); }
  async function network(raw = {}, eventId = "net-1") {
    const request = { url: "https://target.test/search?q=private-value&csrf=secret-token", method: "GET", headers: { Authorization: "Bearer PRIVATE-CREDENTIAL", Cookie: "session=PRIVATE-COOKIE" }, ...raw };
    await scope.kiDastNetworkEvent({ tabId: 7 }, "Network.requestWillBeSent", { requestId: eventId, type: "Fetch", request });
    await scope.kiDastNetworkEvent({ tabId: 7 }, "Network.responseReceived", { requestId: eventId, response: { status: 200 } });
    await scope.kiDastNetworkEvent({ tabId: 7 }, "Network.loadingFinished", { requestId: eventId });
    return (await scope.kiDastState("chat")).requests.at(-1);
  }
  async function account(extra = {}) {
    const item = await network({ url: "https://target.test/me", headers: { Authorization: "Bearer PRIVATE-CREDENTIAL", Cookie: "sid=PRIVATE-COOKIE; other=OTHER-COOKIE" } }, "identity-" + calls.length);
    const args = { requestId: item.requestId, label: "Owner", credentialHeaders: ["Authorization"], cookieNames: ["sid"], claims: [{ pointer: "/id", expected: "PRIVATE-IDENTITY" }], readOnly: true, ...extra };
    const reply = await request("save_account", args); assert.equal(reply.ok, true, reply.error); return { ...reply.result, args };
  }
  async function prepare(owner, item, extra = {}) {
    item ||= await network({ url: "https://target.test/objects?id=1" }, "object");
    const args = { cases: [{ requestId: item.requestId, ownerAccountId: owner.id, readOnly: true, evidence: { object: { pointer: "/id", expected: "PRIVATE-OBJECT" }, protected: { pointer: "/secret", expected: "PRIVATE-EVIDENCE" } }, expectations: [{ accountId: "anonymous", expected: "deny" }] }], ...extra };
    const reply = await request("prepare", args); assert.equal(reply.ok, true, reply.error); return { ...reply.result, args };
  }
  return { scope, request, capture, network, account, prepare, local, sessionData, contexts, tabs, calls, outputs, downloads, events, alarms,
    capabilities: value => capabilities = value, disable: () => disabled = true, runFailure: () => failRun = true, runReply: fn => runReply = fn, loseReply: () => loseReply = true, downloadFailure: () => failExport = true, beforeRun: fn => beforeRun = fn,
    complete: () => { engine.state = "completed"; engine.requestsSent = 4; engine.findingsCount = 1; }, setEngine: patch => Object.assign(engine, patch),
  };
}

test("account snapshots select captured credentials by name and never expose values in state or approvals", async () => {
  const f = fixture(); await f.capture(); const owner = await f.account(); const plan = await f.prepare(owner);
  const state = (await f.request("state")).result;
  assert.equal(state.accounts[0].id, owner.id); assert.deepEqual(plain(state.accounts[0].credentialHeaders), ["Authorization"]); assert.deepEqual(plain(state.accounts[0].cookieNames), ["sid"]);
  const saved = f.scope.kiAuthzPrivate.accounts[owner.id]; assert.equal(saved.headers.find(header => header.name === "Cookie").value, "sid=PRIVATE-COOKIE");
  const tools = f.scope.kiAuthzToolDefs("chat"), approval = tools.find(tool => tool.name === "ptk_run_access_test").kiApprovalArgs(plan), accountApproval = tools.find(tool => tool.name === "ptk_save_account").kiApprovalPreview(owner.args);
  const publicText = JSON.stringify({ state, approval, accountApproval });
  for (const secret of ["PRIVATE-CREDENTIAL", "PRIVATE-COOKIE", "OTHER-COOKIE", "PRIVATE-IDENTITY", "PRIVATE-OBJECT", "PRIVATE-EVIDENCE"]) assert.equal(publicText.includes(secret), false, secret);
  assert.equal(tools.length, 9); assert.equal(JSON.stringify(f.local).includes("PRIVATE-CREDENTIAL"), false);
  assert.match(JSON.stringify(f.sessionData), /PRIVATE-CREDENTIAL/);
});

test("wrapped agent save preserves private claims while approval shows only the safe preview", async () => {
  const f = fixture(); await f.capture(); const account = await f.account();
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../src/ki-permissions.js"), "utf8"), f.scope);
  const approvals = []; f.scope.KN = { request: async value => { approvals.push(plain(value)); return "allow_once"; } };
  const tool = f.scope.kiPolicyWrap(f.scope.kiAuthzToolDefs("chat").find(tool => tool.name === "ptk_save_account"), "chat");
  const args = { ...account.args, id: account.id, role: "Reader", tenant: "Workspace A" };
  const execution = tool.resolveExecution(args); args.claims = [{ pointer: "/id", expected: "MUTATED-AFTER-RESOLVE" }];
  const result = await execution.execute({ signal: new AbortController().signal, toolCallId: "agent-save" });
  assert.equal(result.isError, undefined, result.output); assert.equal(JSON.parse(result.output).revision, 2);
  const saved = f.scope.kiAuthzPrivate.accounts[account.id]; assert.equal(saved.probe.claims[0].expected, "PRIVATE-IDENTITY"); assert.equal(saved.role, "Reader"); assert.equal(saved.tenant, "Workspace A");
  assert.equal(approvals.length, 1); assert.doesNotMatch(approvals[0].preview.text, /PRIVATE-IDENTITY|PRIVATE-CREDENTIAL|PRIVATE-COOKIE|MUTATED-AFTER-RESOLVE/); assert.match(approvals[0].preview.text, /identityPointers/);
  f.scope.KN.request = async () => "deny";
  const denied = await tool.resolveExecution({ ...account.args, id: account.id }).execute({ signal: new AbortController().signal, toolCallId: "denied-save" }); assert.equal(denied.isError, true); assert.equal(f.scope.kiAuthzPrivate.accounts[account.id].revision, 2);
});

test("accounts are workspace-scoped; captures and plans remain chat-owned", async () => {
  const f = fixture(); await f.capture(); const account = await f.account();
  f.contexts.peer = structuredClone(f.contexts.chat);
  assert.equal((await f.request("state", { session: "peer" })).result.accounts[0].id, account.id);
  assert.equal((await f.request("save_account", { ...account.args, session: "peer" })).ok, false);
  const plan = await f.prepare(account); assert.equal((await f.request("run", { ...plan, session: "peer" })).ok, false);
  f.contexts.peer.workspace.id = "another"; assert.equal((await f.request("state", { session: "peer" })).result.accounts.length, 0);
  assert.equal((await f.request("delete_account", { accountId: account.id, session: "peer" })).ok, false);
  delete f.contexts.chat.workspace; const ordinary = await f.request("state"); assert.equal(ordinary.ok, true); assert.deepEqual(plain(ordinary.result.accounts), []); assert.deepEqual(plain(ordinary.result.captures), []); assert.equal(ordinary.result.scope, null);
});

test("save requires read-only declaration, exact headers/cookies and unambiguous identity claims", async () => {
  const f = fixture(); await f.capture(); const account = await f.account();
  for (const patch of [{ readOnly: false }, { credentialHeaders: ["Cookie"] }, { cookieNames: ["missing"] }, { credentialHeaders: ["Authorization", "authorization"] }, { claims: [{ pointer: "/id", expected: "A" }, { pointer: "/id", expected: "B" }] }, { claims: [{ pointer: "bad", expected: "A" }] }]) assert.equal((await f.request("save_account", { ...account.args, ...patch })).ok, false);
  const request = f.scope.kiDastPrivate.requests[account.args.requestId]; request.headers.push({ name: "cookie", value: "sid=second" });
  assert.equal((await f.request("save_account", account.args)).ok, false);
});

test("URL/body credential carriers are refused before account save or comparison approval", async () => {
  const f = fixture(); await f.capture(); const owner = await f.account(), baseline = await f.prepare(owner);
  const carriers = [
    { url: "https://target.test/me?access_token=PRIVATE" },
    { url: "https://target.test/me", method: "POST", headers: { Authorization: "Bearer PRIVATE", "Content-Type": "application/x-www-form-urlencoded" }, postData: "object=1&csrf-token=PRIVATE" },
    { url: "https://target.test/me", method: "POST", headers: { Authorization: "Bearer PRIVATE", "Content-Type": "application/json" }, postData: '{"authentication":{"value":"PRIVATE"},"id":1}' },
    { url: "https://target.test/me", method: "POST", headers: { Authorization: "Bearer PRIVATE", "Content-Type": "application/json" }, postData: '{"nested":{"api_key":"PRIVATE"},"id":1}' },
  ];
  for (const [index, raw] of carriers.entries()) {
    const item = await f.network(raw, "carrier-" + index);
    const save = await f.request("save_account", { ...owner.args, requestId: item.requestId }); assert.equal(save.ok, false); assert.match(save.error, /selected headers and cookies only/);
    const args = structuredClone(baseline.args); args.cases[0].requestId = item.requestId;
    const prepared = await f.request("prepare", args); assert.equal(prepared.ok, false); assert.match(prepared.error, /selected headers and cookies only/);
    assert.equal((await f.request("state")).result.captures.find(capture => capture.requestId === item.requestId).supported, false);
  }
});

test("account revisions invalidate pending plans and deletion stops active comparisons", async () => {
  const f = fixture(); await f.capture(); const account = await f.account(), plan = await f.prepare(account);
  const updated = await f.request("save_account", { ...account.args, id: account.id, label: "Updated" }); assert.equal(updated.result.revision, 2);
  const stale = await f.request("run", plan); assert.equal(stale.ok, false); assert.match(stale.error, /account changed/i);
  const next = await f.prepare(updated.result); const running = await f.request("run", next); assert.equal(running.ok, true, running.error);
  assert.equal((await f.request("delete_account", { accountId: account.id })).ok, true);
  assert.equal(f.local.ki_authz_batches[0].state, "stopped"); assert.equal(f.calls.filter(call => call.op === "authz_stop").length, 1);
});

test("object replacement preserves exact query/form bytes and numeric JSON type", async () => {
  const f = fixture(); await f.capture(); const owner = await f.account();
  const inputs = [
    { raw: { url: "https://target.test/items/old?q=a%2Bb&&id=old&tail=%20" }, swap: { location: "query", name: "id", index: 1, value: "new id" }, url: "https://target.test/items/old?q=a%2Bb&&id=new%20id&tail=%20" },
    { raw: { url: "https://target.test/items/old?keep=%2F" }, swap: { location: "path", name: "1", index: 1, value: "new-id" }, url: "https://target.test/items/new-id?keep=%2F" },
    { raw: { url: "https://target.test/items", method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, postData: "keep=%2f&&id=old&tail=a+b" }, swap: { location: "form", name: "id", index: 1, value: "new" }, body: "keep=%2f&&id=new&tail=a+b" },
    { raw: { url: "https://target.test/items", method: "POST", headers: { "Content-Type": "application/json" }, postData: ' {"id":9007199254740993123, "untouched":"\\u0061"}\n' }, swap: { location: "json", name: "/id", index: 0, value: "9007199254740993999" }, body: ' {"id":9007199254740993999, "untouched":"\\u0061"}\n' },
  ];
  for (const [index, input] of inputs.entries()) {
    const item = await f.network(input.raw, "swap-" + index), seed = await f.prepare(owner, item);
    const args = structuredClone(seed.args); args.cases[0].objectSwap = input.swap; const reply = await f.request("prepare", args); assert.equal(reply.ok, true, reply.error);
    const request = f.scope.kiAuthzPrivate.plans[reply.result.planId].cases[0].request;
    if (input.body) assert.equal(request.body, input.body); if (input.url) assert.equal(request.url, input.url);
    assert.equal("value" in reply.result.cases[0].objectSwap, false);
  }
});

test("object replacement rejects ambiguous paths, wrong selectors, nonnumeric tokens and scope escapes", async () => {
  const f = fixture(); await f.capture(); const owner = await f.account(), item = await f.network({ url: "https://target.test/items/old", method: "POST", headers: { "Content-Type": "application/json" }, postData: '{"id":1,"flag":true}' });
  const base = await f.prepare(owner, item);
  for (const swap of [{ location: "path", name: "1", index: 1, value: "../admin" }, { location: "path", name: "1", index: 1, value: "%2fadmin" }, { location: "json", name: "/id", index: 0, value: "1,\"new\":2" }, { location: "json", name: "/id", index: 1, value: "2" }, { location: "json", name: "/flag", index: 1, value: "false" }, { location: "path", name: "0", index: 0, value: "admin" }]) {
    const args = structuredClone(base.args); args.cases[0].objectSwap = swap; assert.equal((await f.request("prepare", args)).ok, false);
  }
});

test("plans require explicit read-only/evidence/expectations and companion revision four", async () => {
  const f = fixture(); await f.capture(); const owner = await f.account(), base = await f.prepare(owner);
  for (const patch of [{ readOnly: false }, { evidence: { object: { pointer: "/id", expected: "1" }, protected: { pointer: "/id", expected: "same" } } }, { expectations: [{ accountId: "missing", expected: "deny" }] }, { expectations: [{ accountId: "anonymous", expected: "deny" }, { accountId: "anonymous", expected: "allow" }] }]) { const args = structuredClone(base.args); Object.assign(args.cases[0], patch); assert.equal((await f.request("prepare", args)).ok, false); }
  f.capabilities({ ready: true, revision: 3, authz: true }); assert.equal((await f.request("prepare", base.args)).ok, false);
  f.capabilities({ ready: true, revision: 4, authz: false }); assert.equal((await f.request("verify", { accountId: owner.id })).ok, false);
});

test("owner denial contradicts the legitimate baseline and is refused before companion RPC", async () => {
  const f = fixture(); await f.capture(); const owner = await f.account(), baseline = await f.prepare(owner);
  const args = structuredClone(baseline.args); args.cases[0].expectations = [{ accountId: owner.id, expected: "deny" }];
  const before = f.calls.length, plansBefore = Object.keys(f.scope.kiAuthzPrivate.plans).length;
  const refused = await f.request("prepare", args); assert.equal(refused.ok, false); assert.match(refused.error, /owner account must have allowed access/i);
  assert.equal(f.calls.length, before); assert.equal(Object.keys(f.scope.kiAuthzPrivate.plans).length, plansBefore);
  args.cases[0].expectations[0].expected = "allow";
  assert.equal((await f.request("prepare", args)).ok, true, "The owner's expected-allow control remains valid");
});

test("verification uses captured probe and checks final policy/account/scope before dispatch", async () => {
  const f = fixture(); await f.capture(); const owner = await f.account();
  const verified = await f.request("verify", { accountId: owner.id }); assert.equal(verified.ok, true, verified.error); assert.equal(verified.result.verified, true);
  assert.equal(f.calls.find(call => call.op === "authz_verify").payload.account.probe.request.url, "https://target.test/me");
  const before = f.calls.length; f.beforeRun(() => f.disable()); assert.equal((await f.request("verify", { accountId: owner.id })).ok, false);
  assert.equal(f.calls.slice(before).some(call => call.op === "authz_verify"), false); assert.equal(f.scope.kiAuthzHasActiveBatch(), false);
});

test("authenticated dispatch revocation sends no run; unknown starts never replay", async () => {
  for (const change of [f => f.disable(), f => f.contexts.chat.workspace.dastScope.excludePaths.push("/objects"), (f, owner) => f.scope.kiAuthzPrivate.accounts[owner.id].revision++]) {
    const f = fixture(); await f.capture(); const owner = await f.account(), plan = await f.prepare(owner); f.beforeRun(() => change(f, owner));
    assert.equal((await f.request("run", plan)).ok, false); assert.equal(f.calls.filter(call => call.op === "authz_run").length, 0); assert.equal(f.local.ki_authz_batches[0].state, "failed");
  }
  const f = fixture(); await f.capture(); const plan = await f.prepare(await f.account()); f.loseReply();
  assert.equal((await f.request("run", plan)).ok, false); assert.equal(f.local.ki_authz_batches[0].state, "unknown"); assert.equal((await f.request("run", plan)).ok, false);
  f.disable(); for (const listener of f.events.changed) listener({ ki_tool_permissions: { newValue: {} } }, "local");
  for (let i = 0; i < 30 && f.local.ki_authz_batches[0].state !== "stopped"; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.local.ki_authz_batches[0].state, "stopped");
});

test("typed zero-request refusals terminate failed without locking future plans or replaying the consumed plan", async () => {
  const f = fixture(); await f.capture(); const owner = await f.account(), plan = await f.prepare(owner);
  f.runReply(payload => ({ accepted: false, state: "failed", batchId: payload.batchId, owner: payload.owner, requestsSent: 0, inFlight: 0, error: "A manual PTK analysis is active." }));
  const refused = await f.request("run", plan); assert.equal(refused.ok, true); assert.equal(refused.result.state, "failed"); assert.match(refused.result.error, /manual PTK/);
  assert.equal(f.scope.kiAuthzHasActiveBatch(), false); assert.equal(f.local.ki_authz_batches[0].requestsSent, 0);
  assert.equal((await f.request("run", plan)).ok, false); assert.equal(f.calls.filter(call => call.op === "authz_run").length, 1);
  const next = await f.prepare(owner), tool = f.scope.kiAuthzToolDefs("chat").find(tool => tool.name === "ptk_run_access_test");
  const result = await tool.resolveExecution(next).execute({ signal: new AbortController().signal }); assert.equal(result.isError, true); assert.equal(JSON.parse(result.output).state, "failed"); assert.equal(f.scope.kiAuthzHasActiveBatch(), false);
});

test("ambiguous or unrelated refusal replies remain unknown and block retries", async () => {
  for (const patch of [{ owner: "other" }, { batchId: "unrelated" }, { requestsSent: 1 }, { requestsSent: "0" }, { inFlight: 1 }, { error: null }, { state: "stopped" }]) {
    const f = fixture(); await f.capture(); const plan = await f.prepare(await f.account());
    f.runReply(payload => ({ accepted: false, state: "failed", batchId: payload.batchId, owner: payload.owner, requestsSent: 0, inFlight: 0, error: "Refused", ...patch }));
    assert.equal((await f.request("run", plan)).ok, false); assert.equal(f.local.ki_authz_batches[0].state, "unknown"); assert.equal(f.scope.kiAuthzHasActiveBatch(), true); assert.equal((await f.request("run", plan)).ok, false);
  }
});

test("cross-mode lock, pending stop and ownership prevent simultaneous or stale execution", async () => {
  const f = fixture(); await f.capture(); const plan = await f.prepare(await f.account());
  f.scope.kiPtkCache.push({ state: "running" }); assert.equal((await f.request("run", plan)).ok, false); f.scope.kiPtkCache.length = 0;
  const keys = []; f.scope.kiPtkLock = async (key, operation) => { keys.push(key); return operation(); };
  let release, arrived; const pending = new Promise(resolve => arrived = resolve); f.beforeRun(async () => { arrived(); await new Promise(resolve => release = resolve); });
  const running = f.request("run", plan); await pending; const batchId = f.local.ki_authz_batches[0].batchId;
  assert.equal((await f.request("stop", { batchId, session: "other" })).ok, false);
  assert.equal((await f.request("stop", { batchId })).ok, false); release(); assert.equal((await running).ok, false);
  assert.equal(f.local.ki_authz_batches[0].state, "stopped"); assert.deepEqual(keys, ["scan-start"]); assert.equal(f.calls.some(call => call.op === "authz_run"), false);
});

test("exports wait for completed downloads; state and management reject untrusted senders", async () => {
  const f = fixture(); await f.capture(); const run = await f.request("run", await f.prepare(await f.account())); assert.equal(run.ok, true, run.error);
  const batchId = run.result.batchId; assert.equal((await f.request("export", { batchId })).ok, false); assert.equal(f.outputs.length, 0);
  f.complete(); const result = await f.request("findings", { batchId }); assert.equal(result.result.cells[0].outcome, "unexpected_access"); assert.equal("report" in result.result, false);
  const exported = await f.request("export", { batchId }); assert.equal(exported.ok, true, exported.error); assert.equal(f.outputs[0].owner, "chat"); assert.equal(JSON.parse(Buffer.from(f.downloads[0].data, "base64").toString()).schema, "cert-x-authz/v1");
  assert.equal((await f.request("state", {}, { id: "test", url: "https://target.test/" })).ok, false);
  assert.equal(Object.keys(f.scope.kiAuthzPrivate.plans).length, 0);
});

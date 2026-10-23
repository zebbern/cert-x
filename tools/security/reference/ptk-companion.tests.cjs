const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm"), crypto = require("node:crypto");
const source = fs.readFileSync(path.join(__dirname, "../src/ki-ptk.js"), "utf8");
const plain = value => JSON.parse(JSON.stringify(value));
function fixture(initial = {}) {
  const local = structuredClone(initial.local || {}), sessionData = structuredClone(initial.session || {}), events = {}, calls = [], outputs = [], downloads = [], alarms = new Map();
  let current = null, enabled = initial.enabled !== false, disabled = false, corruptChunk = false, failDownload = false, failBridge = null, missingEngine = false;
  const iastRuntime = { agentReady: true, modulesLoaded: true, readyEvidence: "agent_modules_ready", pendingFindingReports: 0, modulesSentError: 0, runtimeHealthState: "normal", runtimeUrl: "https://target.test/app", agentBootAfterLoad: false };
  const tabs = [{ id: 1, url: "https://target.test/app", title: "Target", active: true, status: "complete" }, { id: 2, url: "https://target.test/other", title: "Other", status: "complete" }];
  const buffers = { SAST: Buffer.from('{"engine":"SAST","findings":[]}'), SCA: Buffer.from('{"engine":"SCA","findings":[]}'), IAST: Buffer.from('{"engine":"IAST","findings":[]}') };
  const event = name => ({ addListener: listener => { events[name] = listener; } });
  const storage = data => ({ get: async key => typeof key === "string" ? { [key]: structuredClone(data[key]) } : Object.fromEntries(key.map(key => [key, structuredClone(data[key])])), set: async value => Object.assign(data, structuredClone(value)) });
  const page = { PTK_AGENT: {
    describe: () => ({ ok: true, api: "PTK_AGENT", agentApiVersion: 1, ptkVersion: "10.0.0", certXIntegrationRevision: 1, capabilities: ["startScan", "scanStatus", "stopScan", "getFindings", "getAnalysisSnapshot", "exportFullReport"] }),
    preflight: () => ({ ok: true, ready: enabled, automationEnabled: enabled, blockers: enabled ? [] : ["automation_disabled"] }),
    startScan: options => { current = { sessionId: "session-" + options.testRunId, status: "running", engines: options.engines }; return { ok: true, ...current }; },
    scanStatus: options => options.sessionId && options.sessionId !== current?.sessionId ? { ok: false, code: "session_not_found" } : { ok: true, sessionId: current?.sessionId || null, status: current?.status || "none", engines: current?.engines?.includes("IAST") ? { IAST: { status: current.status, completionStatus: current.status === "completed" ? "completed" : null, drained: current.status === "completed", ...iastRuntime } } : {}, summary: { findingsCount: 1 }, warnings: ["SAST coverage partial"] },
    stopScan: () => { current.status = "completed"; return { ok: true, status: "stopping" }; },
    getFindings: () => ({ ok: true, findings: [{ id: "candidate-1", severity: "high", evidence: "source to sink" }], truncated: false }),
    getAnalysisSnapshot: () => ({ ok: true, summary: { coverage: "partial" }, warnings: ["Collection gap"] }),
    exportFullReport: () => ({ ok: true, mode: "retrieval-plan", scans: current.engines.filter(engine => !missingEngine || engine !== "SCA").map(engine => ({ engine, exportMode: "chunked", exportId: "export-" + engine, fileName: "../../" + engine + ".json", size: buffers[engine].length, chunkSize: 8, chunkCount: Math.ceil(buffers[engine].length / 8), contentType: "application/json", expiresAt: Date.now() + 60000 })), warnings: [], truncatedAny: false }),
  }, PTK_AUTOMATION: {
    ping: () => ({ ok: enabled, version: "10.0.0", automationEnabled: enabled }),
    requestActivation: () => { enabled = true; return { ok: true, allowed: true }; },
    exportScanChunk: options => { const part = buffers[options.engine].subarray(options.index * 8, options.index * 8 + 8); return { ok: true, exportId: options.exportId, index: options.index, chunkCount: Math.ceil(buffers[options.engine].length / 8), encoding: "base64", byteLength: corruptChunk ? part.length + 1 : part.length, chunkBase64: part.toString("base64") }; },
    releaseExportScan: () => ({ ok: true }),
  }, __PTK_IAST_AGENT_LOADED__: true, __PTK_IAST_DEBUG_STATE__: () => ({ enabledHookGroups: ["hook.dom.htmlAssignments"], activeModuleIds: ["module.dom"], degradedHookGroups: [], runtimeHealthState: "normal" }) };
  const scope = vm.createContext({ console, URL, crypto: crypto.webcrypto, setTimeout, clearTimeout, Uint8Array, TextEncoder, AbortController, Date, atob, btoa,
    kiWorkspaceOwner: owner => owner === "child" ? "chat" : owner, kiWorkspaceOutput: async (owner, output) => outputs.push({ owner, ...plain(output) }),
    kiContextFor: () => ({ tools: { groups: { ptk: !disabled } } }), kiPolicyState: async () => ({ parentEnabled: true, rule: disabled ? "disabled" : "inherit" }), KI_POLICY_CONTEXT: Symbol("policy"),
    Tt: () => ({ primaryTabId: 1 }), window: page, location: { origin: "https://target.test" },
    chrome: {
      runtime: { id: "test", getURL: file => "chrome-extension://test/" + file, onMessage: event("message") },
      storage: { local: storage(local), session: storage(sessionData) },
      tabs: { get: async id => { const tab = tabs.find(tab => tab.id === id); if (!tab) throw Error("Tab closed"); return structuredClone(tab); }, query: async () => structuredClone(tabs), update: async (id, value) => { Object.assign(tabs.find(tab => tab.id === id), value); }, onRemoved: event("removed") },
      scripting: { executeScript: async detail => {
        const [origin, method, options] = detail.args; calls.push({ origin, method, options: plain(options), tabId: detail.target.tabId });
        scope.location = { origin: new URL(tabs.find(tab => tab.id === detail.target.tabId).url).origin };
        if (failBridge === method) return [{ frameId: 0, result: { ok: false, message: "Fixture PTK application failure" } }];
        return [{ frameId: 0, result: await detail.func(...detail.args) }];
      } },
      alarms: { create: async (name, value) => alarms.set(name, value), clear: async name => alarms.delete(name), onAlarm: event("alarm") },
      webNavigation: { onCommitted: event("committed") },
      downloads: { download: async options => { downloads.push(options); return downloads.length; }, search: async ({ id }) => [{ id, state: failDownload ? "interrupted" : "complete", error: failDownload ? "FILE_FAILED" : undefined }], cancel: async () => {} },
    },
  });
  vm.runInContext(source, scope);
  const request = (op, fields = {}, sender = { id: "test", url: "chrome-extension://test/pages/sidepanel.html" }) => new Promise(resolve => events.message({ type: "KI_PTK", op, session: "chat", ...fields }, sender, resolve));
  return { scope, local, sessionData, page, calls, outputs, downloads, alarms, tabs, events, request, iastRuntime,
    disable: () => disabled = true, corrupt: () => corruptChunk = true, failDownload: () => failDownload = true, missingEngine: () => missingEngine = true,
    fail: method => failBridge = method, setCurrent: value => current = value,
    start: extra => request("start", { tabId: 1, expectedOrigin: "https://target.test", durationSeconds: 60, ...extra }),
    complete: async scanId => { await request("stop", { scanId }); return request("status", { scanId }); },
  };
}

test("readiness distinguishes installed from ready and check never activates", async () => {
  const f = fixture({ enabled: false });
  const check = await f.request("check", { tabId: 1 }); assert.equal(check.ok, true); assert.equal(check.result.ready, false); assert.equal(check.result.version, "10.0.0"); assert.deepEqual(f.calls.map(call => call.method), ["check"]);
  const started = await f.start(); assert.equal(started.ok, true, started.error); assert.equal(started.result.state, "running"); assert.ok(f.calls.some(call => call.method === "activate"));
  f.page.PTK_AGENT.describe = () => ({ ok: true, api: "PTK_AGENT", agentApiVersion: 1, ptkVersion: "9.9.9", capabilities: [] });
  assert.equal((await f.request("check", { tabId: 2 })).result.ready, false);
});
test("real v10 disabled low-level bridge can activate before PTK_AGENT exists", async () => {
  const f = fixture({ enabled: false }), agent = f.page.PTK_AGENT, activate = f.page.PTK_AUTOMATION.requestActivation;
  delete f.page.PTK_AGENT;
  f.page.PTK_AUTOMATION.requestActivation = () => { const result = activate(); f.page.PTK_AGENT = agent; return result; };
  const check = await f.request("check", { tabId: 1 }); assert.equal(check.result.version, "10.0.0"); assert.equal(check.result.ready, false); assert.deepEqual(plain(check.result.blockers), ["automation_disabled"]);
  const started = await f.start(); assert.equal(started.ok, true, started.error); assert.equal(started.result.state, "running");
});
test("start requires explicit origin, restricts engines and never replaces a scan", async () => {
  const f = fixture();
  assert.equal((await f.start({ expectedOrigin: "https://other.test" })).ok, false);
  assert.equal((await f.start({ engines: ["DAST"] })).ok, false); assert.equal((await f.start({ durationSeconds: 301 })).ok, false);
  const result = await f.start(); assert.equal(result.ok, true); assert.equal(result.result.owner, "chat");
  assert.equal((await f.start()).ok, false); assert.equal(f.calls.filter(call => call.method === "startScan").length, 1);
  assert.ok(f.alarms.has("ki-ptk:" + result.result.scanId));
  f.disable(); assert.equal((await f.request("findings", { scanId: result.result.scanId })).ok, false);
});
test("direct UI uses fresh profile selection without changing the active model snapshot", async () => {
  const f = fixture(); let prepared = 0;
  f.scope.kiContextFor = () => ({ tools: { groups: { ptk: false } } });
  f.scope.kiContextResolve = async () => ({ tools: { groups: { ptk: true } } });
  f.scope.kiContextPrepare = () => prepared++;
  f.scope.kiContextRule = (_meta, context, rule) => rule === "disabled" || context.tools.groups.ptk === false ? "disabled" : rule;
  f.scope.kiPolicyState = async (_meta, session) => ({ parentEnabled: true, rule: session ? "disabled" : "inherit" });
  assert.equal((await f.request("check", { tabId: 1 })).result.ready, true);
  assert.equal((await f.start()).ok, true); assert.equal(prepared, 0);
  f.scope.kiPolicyState = async () => ({ parentEnabled: true, rule: "disabled" });
  assert.equal((await f.request("check", { tabId: 1 })).ok, false);
});
test("ownership and origin changes cannot adopt another PTK session", async () => {
  const f = fixture(), result = await f.start(), scanId = result.result.scanId;
  assert.equal((await f.request("status", { scanId, session: "other-chat" })).ok, false);
  assert.equal((await f.request("status", { scanId, session: "child" })).ok, true);
  f.setCurrent({ sessionId: "foreign-session", status: "completed" });
  const mismatched = await f.request("status", { scanId }); assert.match(mismatched.result.error, /session_not_found/); assert.equal(mismatched.result.state, "running");
  f.page.PTK_AGENT.scanStatus = () => ({ ok: true, sessionId: "foreign-session", status: "completed" });
  assert.match((await f.request("status", { scanId })).result.error, /different scan/);
  f.tabs[0].url = "https://elsewhere.test/"; const calls = f.calls.length;
  assert.equal((await f.request("stop", { scanId })).ok, false); assert.equal(f.calls.length, calls);
});
test("findings preserve candidates and coverage; application errors do not become success", async () => {
  const f = fixture(), scanId = (await f.start()).result.scanId;
  const findings = await f.request("findings", { scanId, limit: 10 }); assert.equal(findings.ok, true); assert.equal(findings.result.analysis.summary.coverage, "partial"); assert.match(findings.result.note, /candidates/);
  f.fail("getFindings"); const failed = await f.request("findings", { scanId }); assert.equal(failed.ok, false); assert.match(failed.error, /application failure/);
  f.fail("stopScan"); assert.equal((await f.request("stop", { scanId })).ok, false); assert.equal(f.scope.kiPtkCache[0].state, "running");
});
test("optional analysis failure retains findings and oversized metadata is bounded", async () => {
  const f = fixture(), scanId = (await f.start()).result.scanId;
  f.fail("getAnalysisSnapshot"); const result = await f.request("findings", { scanId });
  assert.equal(result.ok, true); assert.equal(result.result.findings.length, 1); assert.match(result.result.warnings[0], /summary unavailable/);
  assert.equal(f.scope.kiPtkSmall({ body: "x".repeat(100000) }).truncated, true);
});
test("permission revocation during activation blocks the subsequent scan start", async () => {
  const f = fixture({ enabled: false });
  const activate = f.page.PTK_AUTOMATION.requestActivation;
  f.page.PTK_AUTOMATION.requestActivation = () => { const result = activate(); f.disable(); return result; };
  // Activation may take time; a direct backend recheck must reject before starting.
  let checks = 0;
  await assert.rejects(f.scope.kiPtkStart({ tabId: 1, expectedOrigin: "https://target.test" }, "chat", undefined, async () => {
    if (++checks > 1) throw Error("Disabled during approval");
  }), /Disabled during approval/);
  assert.equal(checks, 2);
  assert.equal(f.calls.some(call => call.method === "startScan"), false);
  assert.equal(f.scope.kiPtkCache[0].state, "error");
  assert.match(f.scope.kiPtkCache[0].error, /Scan was not started/);
  f.scope.kiPolicyState = async () => ({ parentEnabled: true, rule: "inherit" });
  assert.equal((await f.start()).ok, true, "A known pre-dispatch failure must not block a later authorized start");
});
test("scan lifecycle distinguishes stopping from completed and marks restart interruption", async () => {
  const f = fixture(), scanId = (await f.start()).result.scanId;
  const stop = await f.request("stop", { scanId }); assert.equal(stop.result.state, "stopping");
  assert.equal((await f.request("export", { scanId })).ok, false);
  const status = await f.request("status", { scanId }); assert.equal(status.result.state, "completed"); assert.equal(f.alarms.has("ki-ptk:" + scanId), false);
  const running = fixture(), runningId = (await running.start()).result.scanId;
  const restart = fixture({ local: running.local }); await restart.scope.kiPtkLoad(); assert.equal(restart.scope.kiPtkCache[0].state, "interrupted");
  assert.equal((await restart.request("export", { scanId: runningId })).ok, false);
});
test("complete exports verify every chunk, save bytes and release all handles", async () => {
  const f = fixture(), scanId = (await f.start()).result.scanId; await f.complete(scanId);
  const result = await f.request("export", { scanId }); assert.equal(result.ok, true, result.error); assert.equal(result.result.reports.length, 2); assert.equal(f.outputs.length, 2);
  const data = f.downloads[0].url.split(",")[1]; assert.deepEqual(JSON.parse(Buffer.from(data, "base64").toString()), { engine: "SAST", findings: [] });
  assert.equal(f.downloads[0].filename.includes(".."), false);
  assert.equal(f.calls.filter(call => call.method === "releaseExportScan").length, 2);
  assert.ok(f.outputs.every(output => output.owner === "chat" && output.downloadId));
});
test("incomplete plans/chunks and failed downloads never register successful output", async () => {
  for (const failure of ["corrupt", "failDownload", "missingEngine"]) {
    const f = fixture(), scanId = (await f.start()).result.scanId; await f.complete(scanId); f[failure]();
    const result = await f.request("export", { scanId }); assert.equal(result.ok, false, failure); assert.equal(f.outputs.length, 0, failure);
    assert.ok(f.calls.some(call => call.method === "releaseExportScan"), failure);
  }
});
test("aborted exports release handles and cannot save output", async () => {
  const f = fixture(), scanId = (await f.start()).result.scanId; await f.complete(scanId);
  const controller = new AbortController(), original = f.page.PTK_AUTOMATION.exportScanChunk;
  f.page.PTK_AUTOMATION.exportScanChunk = options => { controller.abort(Error("Stop export")); return original(options); };
  await assert.rejects(f.scope.kiPtkExport(scanId, "chat", controller.signal), /Stop export/); assert.equal(f.outputs.length, 0); assert.equal(f.calls.filter(call => call.method === "releaseExportScan").length, 2);
});
test("unknown start failures are recorded without retrying and sender guards reject pages", async () => {
  const f = fixture(); f.fail("startScan"); const failed = await f.start(); assert.equal(failed.ok, false); assert.equal(f.scope.kiPtkCache[0].state, "unknown");
  assert.equal((await f.start()).ok, false); assert.equal(f.calls.filter(call => call.method === "startScan").length, 1);
  for (const url of ["https://target.test", "chrome-extension://test/content.html", "chrome-extension://test/pages/sidepanel.html#fake"]) assert.equal((await f.request("state", {}, { id: "test", url })).ok, false);
});
test("deadline monitoring requests stop and does not confuse stopping with completion", async () => {
  const f = fixture(), scanId = (await f.start()).result.scanId;
  await f.scope.kiPtkStore(scanId, { deadline: Date.now() - 1 });
  f.events.alarm({ name: "ki-ptk:" + scanId });
  for (let attempt = 0; attempt < 100 && !f.calls.some(call => call.method === "stopScan"); attempt++) await new Promise(resolve => setTimeout(resolve, 1));
  await f.scope.kiPtkWrites;
  assert.ok(f.calls.some(call => call.method === "stopScan")); assert.equal(f.scope.kiPtkCache[0].state, "stopping");
  assert.equal((await f.request("status", { scanId })).result.state, "completed");
});

test("IAST requires patched companion and confirmed current-document instrumentation", async () => {
  const f = fixture(), describe = f.page.PTK_AGENT.describe;
  f.page.PTK_AGENT.describe = () => ({ ...describe(), certXIntegrationRevision: 0 });
  assert.equal((await f.start({ engines: ["IAST"] })).ok, false); assert.equal(f.calls.some(call => call.method === "startScan"), false);
  f.page.PTK_AGENT.describe = describe;
  assert.equal((await f.start({ engines: ["IAST", "SAST"] })).ok, false);
  f.iastRuntime.agentReady = false;
  let result = await f.start({ engines: ["IAST"], durationSeconds: undefined });
  assert.equal(result.ok, true, result.error); const scanId = result.result.scanId;
  assert.equal(result.result.mode, "observe"); assert.equal(result.result.deadline - result.result.startedAt, 600000);
  assert.equal(result.result.observationState, "starting");
  await f.scope.kiPtkStore(scanId, { startedAt: Date.now() - 20000 });
  result = await f.request("status", { scanId }); assert.equal(result.result.observationState, "degraded");
  f.iastRuntime.agentReady = true; f.page.__PTK_IAST_AGENT_LOADED__ = false;
  result = await f.request("status", { scanId }); assert.equal(result.result.observationState, "degraded", "Stale background health cannot assert fresh page instrumentation");
  f.page.__PTK_IAST_AGENT_LOADED__ = true;
  result = await f.request("status", { scanId }); assert.equal(result.result.observationState, "observing");
  f.iastRuntime.modulesSentError = 1;
  result = await f.request("status", { scanId }); assert.equal(result.result.observationState, "degraded");
});

test("IAST startup is single-owner across tabs and extension is bounded and permission checked", async () => {
  const f = fixture();
  const results = await Promise.all([f.start({ engines: ["IAST"], durationSeconds: undefined }), f.start({ engines: ["IAST"], tabId: 2, session: "other-chat" })]);
  assert.equal(results.filter(result => result.ok).length, 1); assert.equal(f.calls.filter(call => call.method === "startScan").length, 1);
  const scan = results.find(result => result.ok).result;
  let extended = await f.request("extend", { scanId: scan.scanId }); assert.equal(extended.result.deadline, scan.deadline + 300000);
  assert.equal((await f.request("extend", { scanId: scan.scanId, session: "other-chat" })).ok, false);
  const before = extended.result.deadline;
  await assert.rejects(f.scope.kiPtkExtend(scan.scanId, "chat", undefined, async () => { throw Error("Revoked"); }), /Revoked/);
  assert.equal(f.scope.kiPtkCache[0].deadline, before);
  await f.scope.kiPtkStore(scan.scanId, { deadline: scan.startedAt + 1790000 });
  extended = await f.request("extend", { scanId: scan.scanId }); assert.equal(extended.result.deadline, scan.startedAt + 1800000);
  assert.equal((await f.request("extend", { scanId: scan.scanId })).ok, false);
  await f.scope.kiPtkStore(scan.scanId, { deadline: Date.now() - 1 });
  assert.equal((await f.request("extend", { scanId: scan.scanId })).ok, false);
});

test("IAST navigation invalidates readiness and never controls another origin", async () => {
  const f = fixture(), scanId = (await f.start({ engines: ["IAST"] })).result.scanId;
  f.tabs[0].url = "https://target.test/next"; f.page.__PTK_IAST_AGENT_LOADED__ = false;
  f.events.committed({ tabId: 1, frameId: 0, url: f.tabs[0].url });
  for (let attempt = 0; attempt < 10 && !f.scope.kiPtkCache[0].navigationAt; attempt++) await new Promise(resolve => setTimeout(resolve, 1));
  assert.equal(f.scope.kiPtkCache[0].observationState, "starting"); assert.equal(f.scope.kiPtkCache[0].readiness, null);
  let state = await f.request("status", { scanId }); assert.notEqual(state.result.observationState, "observing");
  f.page.__PTK_IAST_AGENT_LOADED__ = true; f.iastRuntime.runtimeUrl = f.tabs[0].url;
  state = await f.request("status", { scanId }); assert.equal(state.result.observationState, "observing");
  f.tabs[0].url = "https://foreign.test/"; const calls = f.calls.length;
  state = await f.request("status", { scanId }); assert.equal(state.result.observationState, "degraded"); assert.equal(f.calls.length, calls);
  assert.equal((await f.request("stop", { scanId })).ok, false);
});

test("IAST stop waits for a complete drain and exports only original engine report", async () => {
  const f = fixture(), scanId = (await f.start({ engines: ["IAST"] })).result.scanId;
  f.iastRuntime.pendingFindingReports = 2;
  await f.request("stop", { scanId });
  let state = await f.request("status", { scanId }); assert.equal(state.result.state, "stopping"); assert.equal(state.result.exportReady, false);
  assert.equal((await f.request("export", { scanId })).ok, false);
  f.iastRuntime.pendingFindingReports = 0; f.iastRuntime.drained = false;
  assert.equal((await f.request("export", { scanId })).ok, false);
  f.iastRuntime.drained = true;
  state = await f.request("status", { scanId }); assert.equal(state.result.state, "completed"); assert.equal(state.result.exportReady, true); assert.equal(state.result.cleanup.reloadNeeded, true);
  const exported = await f.request("export", { scanId }); assert.equal(exported.ok, true, exported.error); assert.equal(exported.result.reports.length, 1); assert.equal(exported.result.reports[0].engine, "IAST");
  assert.deepEqual(JSON.parse(Buffer.from(f.downloads[0].url.split(",")[1], "base64").toString()), { engine: "IAST", findings: [] });
  assert.equal(f.calls.filter(call => call.method === "releaseExportScan").length, 1);
});

test("IAST changesOnly preserves unreturned items and nearby actions never capture typed input", async () => {
  const f = fixture(), scanId = (await f.start({ engines: ["IAST"] })).result.scanId;
  f.tabs[0].url = "https://target.test/search?secret=TYPED-SECRET#TYPED-SECRET";
  await f.scope.kiPtkActivity("chat", { family: "browser", name: "fill", label: "Fill field" }, { text: "TYPED-SECRET", selector: "#secret" }, { output: "TYPED-SECRET" }, { tabId: 1, startedAt: Date.now() - 30, endedAt: Date.now() });
  await f.scope.kiPtkActivity("other-chat", { family: "browser", name: "click" }, {}, {}, { tabId: 1 });
  let findings = [{ id: "one", title: "One", severity: "low" }, { id: "two", title: "Two", severity: "high" }];
  f.page.PTK_AGENT.getFindings = () => ({ ok: true, findings, truncated: false });
  const full = await f.request("findings", { scanId }); assert.equal(full.result.findings.length, 2);
  assert.equal(full.result.nearbyActions.length, 1); assert.equal(full.result.nearbyActions[0].route, "https://target.test/search");
  assert.equal(JSON.stringify(full.result.nearbyActions).includes("TYPED-SECRET"), false); assert.match(full.result.associationNote, /not proof of causation/);
  let delta = await f.request("findings", { scanId, limit: 1, changesOnly: true }); assert.equal(delta.result.findings[0].id, "one"); assert.equal(delta.result.truncated, true);
  delta = await f.request("findings", { scanId, limit: 1, changesOnly: true }); assert.equal(delta.result.findings[0].id, "two");
  delta = await f.request("findings", { scanId, changesOnly: true }); assert.equal(delta.result.findings.length, 0);
  findings[0].severity = "high";
  delta = await f.request("findings", { scanId, changesOnly: true }); assert.equal(delta.result.findings.length, 1); assert.equal(delta.result.findings[0].id, "one");
});

test("IAST refuses reported foreign-engine ownership and stale deadline alarms do not stop an extension", async () => {
  const f = fixture(), scanId = (await f.start({ engines: ["IAST"] })).result.scanId;
  const extended = await f.request("extend", { scanId });
  f.events.alarm({ name: "ki-ptk:" + scanId }); await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(f.calls.some(call => call.method === "stopScan"), false); assert.equal(f.alarms.get("ki-ptk:" + scanId).when, extended.result.deadline);
  f.iastRuntime.ownerTabId = 2;
  let state = await f.request("status", { scanId }); assert.equal(state.result.foreignEngine, true); assert.equal(state.result.observationState, "degraded");
  const calls = f.calls.length;
  assert.equal((await f.request("stop", { scanId })).ok, false); assert.equal((await f.request("findings", { scanId })).ok, false); assert.equal(f.calls.length, calls);
});

test("late IAST status cannot restore observing after confirmed completion", async () => {
  const f = fixture(), scanId = (await f.start({ engines: ["IAST"] })).result.scanId;
  await f.complete(scanId); const before = plain(f.scope.kiPtkCache[0]);
  await f.scope.kiPtkStore(scanId, { state: "running", observationState: "observing", exportReady: false, coverage: { warnings: [] } });
  const after = f.scope.kiPtkCache[0]; assert.equal(after.state, "completed"); assert.equal(after.observationState, "completed"); assert.equal(after.exportReady, true); assert.deepEqual(plain(after.coverage), before.coverage);
});

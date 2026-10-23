const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm"), { webcrypto } = require("node:crypto");
const inputCode = fs.readFileSync(path.join(__dirname, "../../../security/compat/dast-inputs.js"), "utf8");
const code = fs.readFileSync(path.join(__dirname, "../src/ki-dast.js"), "utf8"), plain = value => JSON.parse(JSON.stringify(value));
function fixture(initial = {}) {
  const local = structuredClone(initial.local || {}), sessionData = structuredClone(initial.session || {}), events = {}, calls = [], outputs = [], downloads = [], alarms = new Map();
  let disabled = false, failRun = false, loseReply = false, failExport = false, beforeRun;
  const contexts = { chat: { workspace: { id: "workspace", name: "Target", dastScope: { origins: ["https://target.test"], excludePaths: ["/logout", "/admin"] } }, tools: { groups: { ptk: true } } } };
  const tabs = [{ id: 7, url: "https://target.test/app", active: true, status: "complete", title: "Target" }, { id: 8, url: "https://other.test/app", active: false, status: "complete", title: "Other" }];
  const storage = data => ({ get: async key => typeof key === "string" ? { [key]: structuredClone(data[key]) } : Object.fromEntries(key.map(key => [key, structuredClone(data[key])])), set: async value => Object.assign(data, structuredClone(value)) });
  const event = name => ({ addListener: listener => { (events[name] ||= []).push(listener); } });
  let engine, capabilities = { ready: true, revision: 5, ordinalInputs: true, families: ["xss", "sql_injection", "open_redirect", "sql_boolean", "ssti", "jsonp_callback_injection", "response_checks"], inputLocations: ["query", "form", "json"] };
  const scope = vm.createContext({ console, crypto: webcrypto, URL, URLSearchParams, TextEncoder, Uint8Array, Date, AbortController, atob, btoa,
    kiWorkspaceOwner: owner => owner === "child" ? "chat" : owner,
    kiContextResolve: async session => structuredClone(contexts[session] || { workspace: null, tools: { groups: { ptk: false } } }), kiContextFor: () => contexts.chat,
    kiContextAllows: () => true, kiContextRule: (meta, context, rule) => context.tools.groups.ptk ? rule : "disabled",
    kiPolicyState: async () => ({ parentEnabled: true, rule: disabled ? "disabled" : "inherit" }), KI_POLICY_CONTEXT: Symbol(),
    kiWorkspaceOutput: async (owner, output) => outputs.push({ owner, ...plain(output) }), kiPtkDownload: async (name, data) => { if (failExport) throw Error("Download failed"); downloads.push({ name, data }); return 44; }, kiPtkCache: [],
    Tt: () => ({ primaryTabId: 7 }), mP: { cdp: { execute: async args => { calls.push({ cdp: plain(args) }); return {}; } } },
    kiDastCompanion: async (op, payload, signal, beforeDispatch) => {
      if (op === "run") { await beforeRun?.(); await beforeDispatch?.(); }
      calls.push({ op, payload: plain(payload) });
      if (op === "capabilities") return structuredClone(capabilities);
      if (op === "run") { if (failRun) throw Error("Transport disconnected"); engine = { batchId: payload.batchId, owner: payload.owner, state: "running", requestsSent: 0, inFlight: 0, findingsCount: 0, warnings: [], errors: [] }; if (loseReply) throw Error("Accepted reply was lost"); return { accepted: true, ...structuredClone(engine) }; }
      if (op === "stop") { if (!engine) throw Error("Batch is not yet known by companion"); engine.state = "stopped"; }
      if (op === "result") return { ...engine, findings: [{ id: "candidate", classification: "candidate", evidence: "reflected marker" }], report: { schema: "cert-x-dast/v1", findings: [{ id: "candidate" }] } };
      return structuredClone(engine);
    },
    chrome: { storage: { local: storage(local), session: storage(sessionData), onChanged: event("changed") }, runtime: { id: "test", getURL: file => "chrome-extension://test/" + file, onMessage: event("message") },
      debugger: { onEvent: event("network"), onDetach: event("detached") }, tabs: { get: async id => { const tab = tabs.find(tab => tab.id === id); if (!tab) throw Error("Tab closed"); return structuredClone(tab); }, query: async () => structuredClone(tabs), onRemoved: event("removed") },
      alarms: { create: async (name, value) => alarms.set(name, value), clear: async name => alarms.delete(name), onAlarm: event("alarm") } },
  });
  vm.runInContext(inputCode, scope);
  vm.runInContext(code, scope);
  const request = (op, extra = {}, sender = { id: "test", url: "chrome-extension://test/pages/sidepanel.html" }) => new Promise(resolve => events.message[0]({ type: "KI_DAST", op, session: "chat", ...extra }, sender, resolve));
  async function capture() { const result = await request("capture", { action: "start", tabId: 7, expectedOrigin: "https://target.test" }); assert.equal(result.ok, true, result.error); }
  async function network(raw = {}, eventId = "net-1") {
    const request = { url: "https://target.test/search?q=private-value&csrf=secret-token", method: "GET", headers: { Authorization: "Bearer PRIVATE-CREDENTIAL", Cookie: "session=PRIVATE-COOKIE" }, ...raw };
    await scope.kiDastNetworkEvent({ tabId: 7 }, "Network.requestWillBeSent", { requestId: eventId, type: "Fetch", request });
    await scope.kiDastNetworkEvent({ tabId: 7 }, "Network.responseReceived", { requestId: eventId, response: { status: 200 } });
    await scope.kiDastNetworkEvent({ tabId: 7 }, "Network.loadingFinished", { requestId: eventId });
    return (await scope.kiDastState("chat")).requests.at(-1);
  }
  async function prepare(item, extra = {}) { const reply = await request("prepare", { ...extra, requests: [{ requestId: item.requestId, parameters: item.parameters.filter(field => field.supported).map(({ location, name, index }) => ({ location, name, index })), allowReplay: true }] }); assert.equal(reply.ok, true, reply.error); return reply.result; }
  return { scope, request, capture, network, prepare, local, sessionData, contexts, tabs, calls, outputs, downloads, events, alarms,
    capabilities: value => capabilities = value, disable: () => disabled = true, runFailure: () => failRun = true, loseReply: () => loseReply = true, downloadFailure: () => failExport = true, beforeRun: fn => beforeRun = fn,
    complete: () => { engine.state = "completed"; engine.requestsSent = 4; engine.findingsCount = 1; }, setEngine: patch => Object.assign(engine, patch),
  };
}
test("capture requires workspace scope, uses existing CDP and never captures unrelated tabs/origins", async () => {
  const f = fixture(); await f.capture(); assert.equal(f.calls[0].cdp.method, "Network.enable");
  await f.scope.kiDastNetworkEvent({ tabId: 8 }, "Network.requestWillBeSent", { requestId: "foreign", type: "Fetch", request: { url: "https://target.test/search?q=x", method: "GET" } });
  await f.network({ url: "https://other.test/search?q=x" }); await f.network({ url: "https://target.test/admin/secret?q=x" });
  assert.equal((await f.request("list")).result.requests.length, 0);
  delete f.contexts.chat.workspace; assert.equal((await f.request("capture", { action: "start", tabId: 7, expectedOrigin: "https://target.test" })).ok, false);
  assert.equal((await f.request("capture", { action: "stop" })).ok, true);
});
test("capture and persisted selections stay on the selected origin even when workspace allows another API origin", async () => {
  const f = fixture(); f.contexts.chat.workspace.dastScope.origins.push("https://api.target.test"); await f.capture();
  await f.network({ url: "https://api.target.test/search?q=other-origin" }, "api");
  assert.equal((await f.request("list")).result.requests.length, 0);
  const item = await f.network(); f.scope.kiDastPrivate.requests[item.requestId].url = "https://api.target.test/search?q=old-capture";
  const refused = await f.request("prepare", { requests: [{ requestId: item.requestId, parameters: [{ location: "query", name: "q", index: 0 }], allowReplay: true }] });
  assert.equal(refused.ok, false); assert.match(refused.error, /captured tab's origin/);
});
test("summaries and approval plan omit credentials and values while private baseline remains exact", async () => {
  const f = fixture(); await f.capture(); const item = await f.network(), plan = await f.prepare(item);
  const publicText = JSON.stringify((await f.request("state")).result);
  for (const secret of ["PRIVATE-CREDENTIAL", "PRIVATE-COOKIE", "private-value", "secret-token"]) assert.equal(publicText.includes(secret), false);
  assert.match(JSON.stringify(f.sessionData), /PRIVATE-CREDENTIAL/); assert.equal(JSON.stringify(f.local).includes("PRIVATE-CREDENTIAL"), false);
  const runTool = f.scope.kiDastToolDefs("chat").find(tool => tool.name === "ptk_run_dast"), approval = runTool.kiApprovalArgs({ planId: plan.planId, planHash: plan.planHash });
  assert.equal(approval.testPlan.requests[0].allowReplay, true); assert.equal(approval.testPlan.budget.maxRequests, 100); assert.equal(JSON.stringify(approval).includes("private-value"), false);
});
test("exact form bodies and repeated inputs are preserved; missing raw bodies are not reconstructed", async () => {
  const f = fixture(); await f.capture();
  const item = await f.network({ method: "POST", url: "https://target.test/form", headers: { "Content-Type": "application/x-www-form-urlencoded" }, hasPostData: true, postData: "q=a%2Bb+space&csrf=secret" });
  const plan = await f.prepare(item); assert.equal(f.scope.kiDastPrivate.plans[plan.planId].requests[0].body, "q=a%2Bb+space&csrf=secret");
  const duplicate = await f.network({ url: "https://target.test/search?q=one&q=two" }, "duplicate"); assert.equal(duplicate.supported, true); assert.deepEqual(plain(duplicate.parameters.map(field => field.index)), [0, 1]);
  const missing = await f.network({ method: "POST", hasPostData: true, headers: { "Content-Type": "application/x-www-form-urlencoded" } }, "missing"); assert.match(missing.reason, /not be reconstructed/);
});

test("repeated and cross-location inputs keep decoded names with exact independent ordinals", async () => {
  const f = fixture(); await f.capture();
  const body = "q=FORM-FIRST&&%71=FORM-SECOND&keep=a%2Bb", url = "https://target.test/search?q=QUERY-FIRST&&%71=QUERY-SECOND&keep=%2f&callback=fn";
  const item = await f.network({ url, method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, postData: body });
  assert.equal(item.supported, true, item.reason);
  assert.deepEqual(plain(item.parameters.map(({ location, name, index }) => ({ location, name, index }))), [
    { location: "query", name: "q", index: 0 }, { location: "query", name: "q", index: 1 }, { location: "query", name: "keep", index: 2 }, { location: "query", name: "callback", index: 3 },
    { location: "form", name: "q", index: 0 }, { location: "form", name: "q", index: 1 }, { location: "form", name: "keep", index: 2 },
  ]);
  const selected = [{ location: "query", name: "q", index: 1 }, { location: "form", name: "q", index: 0 }, { location: "query", name: "callback", index: 3 }];
  const prepared = await f.request("prepare", { families: ["xss", "sql_boolean", "ssti", "jsonp_callback_injection"], requests: [{ requestId: item.requestId, parameters: selected, allowReplay: true }] });
  assert.equal(prepared.ok, true, prepared.error); assert.equal((await f.request("run", prepared.result)).ok, true);
  const wire = f.calls.find(call => call.op === "run").payload.requests[0]; assert.deepEqual(wire.parameters, selected); assert.equal(wire.url, url); assert.equal(wire.body, body);
  const serialized = JSON.stringify(prepared.result); assert.doesNotMatch(serialized, /QUERY-FIRST|QUERY-SECOND|FORM-FIRST|FORM-SECOND|rawIndex|"start"|"end"/);
});

test("expanded families and repeated inputs require revision five with ordinal support", async () => {
  const f = fixture(); await f.capture(); const simple = await f.network({ url: "https://target.test/search?q=private-value&callback=fn" }), repeated = await f.network({ url: "https://target.test/search?q=one&q=two" }, "repeated"), collision = await f.network({ url: "https://target.test/search?q=one", method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, postData: "q=two" }, "collision");
  const families = ["xss", "sql_injection", "open_redirect", "sql_boolean", "ssti", "jsonp_callback_injection", "response_checks"];
  const selection = (item, name = "q", index = 0) => ({ requests: [{ requestId: item.requestId, allowReplay: true, parameters: [{ location: "query", name, index }] }] });
  for (const caps of [{ revision: 4, ordinalInputs: true }, { revision: 5, ordinalInputs: false }]) {
    f.capabilities({ ready: true, families, inputLocations: ["query", "form", "json"], ...caps });
    for (const family of ["sql_boolean", "ssti", "jsonp_callback_injection", "response_checks"]) assert.match((await f.request("prepare", { ...selection(simple, family === "jsonp_callback_injection" ? "callback" : "q", family === "jsonp_callback_injection" ? 1 : 0), families: [family] })).error, /revision 5 with exact ordinal inputs/);
    for (const item of [repeated, collision]) assert.match((await f.request("prepare", selection(item))).error, /revision 5 with exact ordinal inputs/);
    assert.equal((await f.request("prepare", selection(simple))).ok, true, "Existing unique-input XSS does not require revision five");
  }
});

test("field compatibility privately applies boolean value limits and PTK callback-name matching", async () => {
  const f = fixture(); await f.capture();
  const rejected = { empty: "", long: "x".repeat(129), cr: "PRIVATE\rVALUE", lf: "PRIVATE\nVALUE", single: "PRIVATE'VALUE", double: 'PRIVATE"VALUE', semi: "PRIVATE;VALUE", slash: "PRIVATE\\VALUE" };
  const pairs = new URLSearchParams({ valid: "PRIVATE-GOOD", boundary: "x".repeat(128), ...rejected, callback: "render", CB: "render", jsonp: "render", jsoncallback: "render", json_callback: "render", callbackfn: "render", callback_fn: "render", notcallback: "render" });
  const item = await f.network({ url: "https://target.test/endpoint?" + pairs });
  for (const field of item.parameters) {
    assert.equal(field.supported, true);
    assert.equal(field.compatibleFamilies.includes("sql_boolean"), !Object.hasOwn(rejected, field.name), field.name);
    assert.equal(field.compatibleFamilies.includes("jsonp_callback_injection"), /^(callback|cb|jsonp|jsoncallback|json_callback|callbackfn|callback_fn)$/i.test(field.name), field.name);
    for (const family of ["xss", "sql_injection", "open_redirect", "ssti"]) assert.ok(field.compatibleFamilies.includes(family));
    assert.equal("value" in field, false);
  }
  assert.equal(JSON.stringify(item).includes("PRIVATE"), false); assert.ok(item.compatibleFamilies.includes("response_checks"));
  const form = await f.network({ url: "https://target.test/form", method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, postData: "%63allback=PRIVATE%27QUOTE&q=PRIVATE-GOOD" }, "form-compatibility");
  assert.ok(form.parameters[0].compatibleFamilies.includes("jsonp_callback_injection")); assert.equal(form.parameters[0].compatibleFamilies.includes("sql_boolean"), false);
  const both = await f.request("prepare", { families: ["sql_boolean", "jsonp_callback_injection"], requests: [{ requestId: form.requestId, parameters: form.parameters.map(({ location, name, index }) => ({ location, name, index })), allowReplay: true }] });
  assert.equal(both.ok, true, both.error, "Different selected fields may support different checks in the same request");
  const wrongField = await f.request("prepare", { families: ["sql_boolean"], requests: [{ requestId: form.requestId, parameters: [{ location: "form", name: "callback", index: 0 }], allowReplay: true }] }); assert.match(wrongField.error, /compatible input/);
  const json = await f.network({ url: "https://target.test/json", method: "POST", headers: { "Content-Type": "application/json" }, postData: '{"nested":{"CallbackFn":"PRIVATE\\nVALUE","ordinary":"PRIVATE-GOOD"},"cb":42}' }, "json-compatibility");
  assert.ok(json.parameters[0].compatibleFamilies.includes("jsonp_callback_injection")); assert.equal(json.parameters[0].compatibleFamilies.includes("sql_boolean"), false);
  assert.equal(json.parameters[1].compatibleFamilies.includes("jsonp_callback_injection"), false); assert.ok(json.parameters[1].compatibleFamilies.includes("sql_boolean"));
  assert.equal(json.parameters[2].supported, false); assert.deepEqual(plain(json.parameters[2].compatibleFamilies), []);
  const incompatible = await f.network({ url: "https://target.test/endpoint?ordinary=PRIVATE%27QUOTE" }, "incompatible");
  assert.equal(incompatible.compatibleFamilies.includes("sql_boolean"), false); assert.equal(incompatible.compatibleFamilies.includes("jsonp_callback_injection"), false); assert.ok(incompatible.compatibleFamilies.includes("response_checks"));
});

test("passive response plans accept endpoints without inputs while active checks need fields on every request", async () => {
  const f = fixture(); await f.capture();
  const endpoint = await f.network({ url: "https://target.test/about" }, "no-input"), numeric = await f.network({ url: "https://target.test/api", method: "POST", headers: { "Content-Type": "application/json" }, postData: '{"n":123,"b":true,"nothing":null}' }, "numeric"), active = await f.network({}, "active");
  assert.equal(endpoint.supported, true); assert.deepEqual(plain(endpoint.parameters), []); assert.deepEqual(plain(endpoint.compatibleFamilies), ["response_checks"]);
  assert.equal(numeric.supported, true); assert.deepEqual(plain(numeric.compatibleFamilies), ["response_checks"]); assert.ok(numeric.parameters.every(field => field.supported === false));
  const requests = [endpoint, numeric].map(item => ({ requestId: item.requestId, parameters: [], allowReplay: true }));
  const passive = await f.request("prepare", { families: ["response_checks"], requests }); assert.equal(passive.ok, true, passive.error); assert.ok(passive.result.requests.every(request => request.parameters.length === 0));
  assert.equal((await f.request("prepare", { requests })).ok, false, "Default remains XSS and cannot silently become passive");
  const mixed = [{ requestId: active.requestId, parameters: [{ location: "query", name: "q", index: 0 }], allowReplay: true }, requests[0]];
  assert.equal((await f.request("prepare", { families: ["xss", "response_checks"], requests: mixed })).ok, false, "Every active-check request requires compatible fields");
  const missing = await f.request("prepare", { families: ["ssti"], requests: [{ requestId: active.requestId, parameters: [], allowReplay: true }] }); assert.match(missing.error, /at least one input/);
  assert.equal((await f.request("run", passive.result)).ok, true); const payload = f.calls.find(call => call.op === "run").payload; assert.deepEqual(payload.families, ["response_checks"]); assert.ok(payload.requests.every(request => request.parameters.length === 0));
  const tool = f.scope.kiDastToolDefs("chat").find(tool => tool.name === "ptk_prepare_dast"); assert.equal(tool.parameters.properties.requests.items.properties.parameters.minItems, 0); assert.equal(tool.parameters.properties.families.maxItems, 7);
});

test("malformed encoded input remains unsupported even for passive checks", async () => {
  const f = fixture(); await f.capture(); const item = await f.network({ url: "https://target.test/api?q=%ZZ" });
  assert.equal(item.supported, false); assert.match(item.reason, /encoded inputs could not be selected exactly/);
  assert.equal((await f.request("prepare", { families: ["response_checks"], requests: [{ requestId: item.requestId, parameters: [], allowReplay: true }] })).ok, false);
});

test("JSON summaries identify string pointers without values and preserve the exact baseline through dispatch", async () => {
  const f = fixture(); await f.capture();
  const body = ' { "a/b~c": ["PRIVATE-JSON-ä", 9007199254740993123, true, null], "escaped":"\\u0061", "password":"PRIVATE-PASSWORD" }\n';
  const item = await f.network({ method: "POST", url: "https://target.test/api?query=PRIVATE-QUERY", headers: { "Content-Type": "application/problem+json; charset=utf-8", Authorization: "Bearer PRIVATE-JSON-AUTH" }, hasPostData: true, postData: body });
  assert.equal(item.supported, true, item.reason);
  const jsonFields = item.parameters.filter(field => field.location === "json");
  assert.deepEqual(plain(jsonFields.map(({ name, index, valueType, supported }) => ({ name, index, valueType, supported }))), [
    { name: "/a~1b~0c/0", index: 0, valueType: "string", supported: true },
    { name: "/a~1b~0c/1", index: 1, valueType: "number", supported: false },
    { name: "/a~1b~0c/2", index: 2, valueType: "boolean", supported: false },
    { name: "/a~1b~0c/3", index: 3, valueType: "null", supported: false },
    { name: "/escaped", index: 4, valueType: "string", supported: true },
    { name: "/password", index: 5, valueType: "string", supported: false },
  ]);
  assert.match(jsonFields[1].reason, /Only JSON string fields/); assert.deepEqual(plain(jsonFields[1].compatibleFamilies), []);
  assert.match(jsonFields[5].reason, /Authentication and session/);
  const families = ["xss", "sql_injection", "open_redirect"], plan = await f.prepare(item, { families }); families.splice(0, 3, "invalid");
  const approval = f.scope.kiDastToolDefs("chat").find(tool => tool.name === "ptk_run_dast").kiApprovalArgs(plan);
  assert.deepEqual(plain(approval.testPlan.families), ["xss", "sql_injection", "open_redirect"]);
  assert.ok(approval.testPlan.requests[0].parameters.every(field => field.valueType === "string" && field.compatibleFamilies.length === 5));
  const publicText = JSON.stringify({ state: (await f.request("state")).result, approval });
  for (const secret of ["PRIVATE-JSON", "PRIVATE-QUERY", "9007199254740993123", "PRIVATE-PASSWORD", "\\u0061"]) assert.equal(publicText.includes(secret), false);
  assert.ok(jsonFields.every(field => !("value" in field) && !("start" in field) && !("end" in field)));
  assert.equal((await f.request("run", plan)).ok, true);
  const payload = f.calls.find(call => call.op === "run").payload;
  assert.equal(payload.requests[0].body, body); assert.deepEqual(payload.families, ["xss", "sql_injection", "open_redirect"]);
  assert.deepEqual(payload.requests[0].parameters[0], { location: "json", name: "/a~1b~0c/0", index: 0 });
  assert.equal(JSON.stringify(f.local).includes("PRIVATE-JSON"), false);
});

test("JSON selection rejects wrong ordinals and non-string fields, and accepts the root string pointer", async () => {
  const f = fixture(); await f.capture();
  const item = await f.network({ method: "POST", headers: { "Content-Type": "application/json" }, postData: '{"n":1,"s":"value"}' });
  const selection = parameters => f.request("prepare", { requests: [{ requestId: item.requestId, allowReplay: true, parameters }] });
  assert.equal((await selection([{ location: "json", name: "/s", index: 0 }])).ok, false);
  const numeric = await selection([{ location: "json", name: "/n", index: 0 }]); assert.equal(numeric.ok, false); assert.match(numeric.error, /Only JSON string/);
  const root = await f.network({ method: "POST", url: "https://target.test/root", headers: { "Content-Type": "application/json" }, postData: '"root secret"' }, "root");
  const plan = await f.prepare(root); assert.equal(plan.requests[0].parameters[0].name, ""); assert.equal(plan.requests[0].parameters[0].index, 0);
});

test("malformed, duplicate-key, overdeep and non-UTF8 JSON cannot be prepared even through a query field", async () => {
  const f = fixture(); await f.capture();
  const cases = [
    ['{"q":"a",}', "application/json", /Malformed/],
    ['{"q":"a","\\u0071":"b"}', "application/json", /Repeated JSON/],
    ["[".repeat(33) + '"value"' + "]".repeat(33), "application/json", /depth/],
    ['{"q":"value"}', "application/json; charset=iso-8859-1", /UTF-8/],
  ];
  for (const [i, [postData, contentType, reason]] of cases.entries()) {
    const item = await f.network({ method: "POST", url: "https://target.test/api" + (i === 4 ? "" : "?q=value"), headers: { "Content-Type": contentType }, postData }, "json-invalid-" + i);
    assert.equal(item.supported, false); assert.match(item.reason, reason);
    const refused = await f.request("prepare", { requests: [{ requestId: item.requestId, allowReplay: true, parameters: [{ location: "query", name: "q", index: 0 }] }] });
    assert.equal(refused.ok, false); assert.match(refused.error, reason);
  }
});

test("JSON media parameter validation matches the companion before plan approval", async () => {
  const f = fixture(); await f.capture(); let index = 0;
  for (const contentType of ['application/json ; charset=utf-8', 'application/vnd.example+json; charset="UTF-8"', "application/vnd!example+json; charset='utf-8'"]) {
    const item = await f.network({ method: "POST", headers: { "Content-Type": contentType }, postData: '{"s":"value"}' }, "media-" + index++);
    assert.equal(item.supported, true, item.reason); await f.prepare(item);
  }
  for (const contentType of ['application/json; charset=utf8', 'application/json; charset=utf-8; arbitrary=value', 'application/json; charset=utf-8; charset=utf-8', 'application/json;']) {
    const item = await f.network({ method: "POST", headers: { "Content-Type": contentType }, postData: '{"s":"value"}' }, "media-" + index++);
    assert.equal(item.supported, false); assert.match(item.reason, /UTF-8 without unsupported media parameters/);
    const result = await f.request("prepare", { requests: [{ requestId: item.requestId, allowReplay: true, parameters: [{ location: "json", name: "/s", index: 0 }] }] });
    assert.equal(result.ok, false); assert.match(result.error, /media parameters/);
  }
});

test("new families and JSON require revision 3 capabilities while omitted checks preserve old XSS compatibility", async () => {
  const f = fixture(); await f.capture(); const item = await f.network();
  f.capabilities({ ready: true, revision: 2, families: ["xss"] });
  assert.deepEqual(plain((await f.prepare(item)).families), ["xss"]);
  const selected = { requests: [{ requestId: item.requestId, allowReplay: true, parameters: [{ location: "query", name: "q", index: 0 }] }] };
  for (const families of [[], ["unknown"], ["xss", "xss"], ["sql_injection"]]) assert.equal((await f.request("prepare", { ...selected, families })).ok, false);
  f.capabilities({ ready: true, revision: 2, families: ["xss", "sql_injection", "open_redirect"], inputLocations: ["query", "form", "json"] });
  const oldRevision = await f.request("prepare", { ...selected, families: ["sql_injection"] }); assert.match(oldRevision.error, /revision 3/);
  const json = await f.network({ method: "POST", headers: { "Content-Type": "application/json" }, postData: '{"s":"value"}' }, "json");
  const jsonSelected = { requests: [{ requestId: json.requestId, allowReplay: true, parameters: [{ location: "query", name: "q", index: 0 }] }] };
  assert.match((await f.request("prepare", jsonSelected)).error, /revision 3/);
  f.capabilities({ ready: true, revision: 3, families: ["xss", "sql_injection", "open_redirect"], inputLocations: ["query", "form"] });
  assert.match((await f.request("prepare", jsonSelected)).error, /JSON input selection/);
  f.capabilities({ ready: true, revision: 3, families: ["xss", "sql_injection"], inputLocations: ["query", "form", "json"] });
  assert.match((await f.request("prepare", { ...selected, families: ["xss", "open_redirect"] })).error, /every selected check/);
  const tool = f.scope.kiDastToolDefs("chat").find(tool => tool.name === "ptk_prepare_dast");
  assert.deepEqual(plain(tool.parameters.properties.families.items.enum), ["xss", "sql_injection", "open_redirect", "sql_boolean", "ssti", "jsonp_callback_injection", "response_checks"]);
  assert.deepEqual(plain(tool.parameters.properties.requests.items.properties.parameters.items.properties.location.enum), ["query", "form", "json"]);
});
test("redirect chains and pending extra headers fail closed; form/query index is exact", async () => {
  const f = fixture(); await f.capture();
  await f.scope.kiDastNetworkEvent({ tabId: 7 }, "Network.requestWillBeSent", { requestId: "r", type: "Fetch", request: { url: "https://target.test/path?q=a", method: "GET", headers: {} } });
  await f.scope.kiDastNetworkEvent({ tabId: 7 }, "Network.requestWillBeSent", { requestId: "r", type: "Fetch", request: { url: "https://other.test/path", method: "GET" }, redirectResponse: { status: 302 } });
  assert.match((await f.request("list")).result.requests[0].reason, /Redirected/);
  const item = await f.network({}, "good");
  const bad = await f.request("prepare", { requests: [{ requestId: item.requestId, parameters: [{ location: "query", name: "q", index: 1 }], allowReplay: true }] }); assert.equal(bad.ok, false);
  assert.equal((await f.request("prepare", { requests: [{ requestId: item.requestId, parameters: [{ location: "query", name: "q", index: 0 }], allowReplay: false }] })).ok, false);
});

test("manual-redirect loadingFailed preserves exact first-hop replay exclusively for open redirect", async () => {
  const f = fixture(); await f.capture();
  const emit = (method, data = {}) => f.scope.kiDastNetworkEvent({ tabId: 7 }, "Network." + method, { requestId: "redirect", ...data });
  const original = { url: "https://target.test/redirect?next=%2Flanding", method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, postData: "destination=%2Flanding", hasPostData: true };
  await emit("requestWillBeSent", { type: "Fetch", request: original });
  await emit("requestWillBeSentExtraInfo", { headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: "session=ORIGINAL" } });
  await emit("requestWillBeSent", { type: "Fetch", request: { url: "https://target.test/landing", method: "GET", headers: { Cookie: "session=NEXT-HOP" } }, redirectResponse: { status: 302 } });
  await emit("requestWillBeSentExtraInfo", { headers: { Cookie: "session=NEXT-HOP" } });
  await emit("loadingFailed", { errorText: "net::ERR_ABORTED", canceled: true });
  const item = (await f.request("list")).result.requests[0]; assert.equal(item.supported, true, item.reason); assert.equal(item.statusCode, 302);
  assert.ok(item.parameters.every(field => JSON.stringify(field.compatibleFamilies) === '["open_redirect"]'));
  const selections = { requests: [{ requestId: item.requestId, allowReplay: true, parameters: [{ location: "query", name: "next", index: 0 }] }] };
  for (const families of [["xss"], ["sql_injection"], ["open_redirect", "xss"], ["response_checks"]]) assert.match((await f.request("prepare", { ...selections, families })).error, /does not support every selected check/);
  const plan = await f.prepare(item, { families: ["open_redirect"] }); assert.equal((await f.request("run", plan)).ok, true);
  const seed = f.calls.find(call => call.op === "run").payload.requests[0];
  assert.equal(seed.url, original.url); assert.equal(seed.method, original.method); assert.equal(seed.body, original.postData);
  assert.equal(seed.headers.find(header => header.name === "Cookie").value, "session=ORIGINAL"); assert.equal(JSON.stringify(seed).includes("NEXT-HOP"), false);
});

test("redirect captures reject ambiguous late headers and never adopt subsequent-hop status", async () => {
  for (const earlyHeaders of [false, true]) {
    const f = fixture(); await f.capture();
    const emit = (method, data = {}) => f.scope.kiDastNetworkEvent({ tabId: 7 }, "Network." + method, { requestId: "redirect", ...data });
    await emit("requestWillBeSent", { type: "Fetch", request: { url: "https://target.test/redirect?next=%2Flanding", method: "GET", headers: {} } });
    if (earlyHeaders) await emit("requestWillBeSentExtraInfo", { headers: { Cookie: "session=ORIGINAL" } });
    await emit("requestWillBeSent", { type: "Fetch", request: { url: "https://target.test/landing", method: "GET" }, redirectResponse: { status: 302 } });
    await emit("requestWillBeSentExtraInfo", { headers: { Cookie: "session=AMBIGUOUS" } });
    await emit("requestWillBeSent", { type: "Fetch", request: { url: "https://other.test/next", method: "GET" }, redirectResponse: { status: 307 } });
    await emit("responseReceived", { response: { status: 200 }, hasExtraInfo: true });
    await emit("loadingFinished");
    const item = (await f.request("list")).result.requests[0]; assert.equal(item.statusCode, 302); assert.equal(item.supported, earlyHeaders);
    if (!earlyHeaders) {
      assert.match(item.reason, /unambiguous original request headers/);
      const refused = await f.request("prepare", { families: ["open_redirect"], requests: [{ requestId: item.requestId, allowReplay: true, parameters: [{ location: "query", name: "next", index: 0 }] }] });
      assert.equal(refused.ok, false); assert.match(refused.error, /unambiguous original request headers/);
    }
    assert.equal(JSON.stringify(f.scope.kiDastPrivate.requests[item.requestId]).includes("AMBIGUOUS"), false);
  }
});
test("late exact request headers are awaited before a capture can be selected", async () => {
  const f = fixture(); await f.capture();
  await f.scope.kiDastNetworkEvent({ tabId: 7 }, "Network.requestWillBeSent", { requestId: "late", type: "Fetch", request: { url: "https://target.test/path?q=a", method: "GET", headers: {} } });
  await f.scope.kiDastNetworkEvent({ tabId: 7 }, "Network.responseReceived", { requestId: "late", response: { status: 200 }, hasExtraInfo: true });
  await f.scope.kiDastNetworkEvent({ tabId: 7 }, "Network.loadingFinished", { requestId: "late" });
  assert.match((await f.request("list")).result.requests[0].reason, /headers are still pending/);
  await f.scope.kiDastNetworkEvent({ tabId: 7 }, "Network.requestWillBeSentExtraInfo", { requestId: "late", headers: { Cookie: "session=late-secret" } });
  const item = (await f.request("list")).result.requests[0]; assert.equal(item.supported, true);
  const plan = await f.prepare(item); assert.equal(f.scope.kiDastPrivate.plans[plan.planId].requests[0].headers[0].value, "session=late-secret");
});
test("capture revocation and debugger detachment stop collection; CDP application errors do not claim enabled", async () => {
  const f = fixture(); await f.capture(); f.disable(); await f.network(); assert.equal((await f.scope.kiDastState("chat")).capture.active, false);
  assert.equal((await f.scope.kiDastState("chat")).requests.length, 0);
  const other = fixture(); await other.capture(); other.events.detached[0]({ tabId: 7 }); await other.scope.kiDastLoad();
  assert.equal((await other.scope.kiDastState("chat")).capture.active, false);
  const failed = fixture(); failed.scope.mP.cdp.execute = async () => ({ error: "capture unavailable" });
  assert.equal((await failed.request("capture", { action: "start", tabId: 7, expectedOrigin: "https://target.test" })).ok, false);
});
test("immutable plans reject changed scope, changed origin, expired hashes and replay", async () => {
  const f = fixture(); await f.capture(); const plan = await f.prepare(await f.network());
  assert.equal((await f.request("run", { planId: plan.planId, planHash: "wrong" })).ok, false);
  f.contexts.chat.workspace.dastScope.excludePaths.push("/search"); assert.equal((await f.request("run", plan)).ok, false); f.contexts.chat.workspace.dastScope.excludePaths.pop();
  f.tabs[0].url = "https://other.test/"; assert.equal((await f.request("run", plan)).ok, false); f.tabs[0].url = "https://target.test/app";
  const running = await f.request("run", plan); assert.equal(running.ok, true, running.error); assert.equal(running.result.state, "running");
  assert.equal((await f.request("run", plan)).ok, false); assert.equal(f.calls.filter(call => call.op === "run").length, 1);
  assert.equal(JSON.stringify(f.local).includes("PRIVATE-CREDENTIAL"), false);
});
test("concurrent plan starts dispatch one batch and uncertain starts never replay", async () => {
  const f = fixture(); await f.capture(); const item = await f.network(), first = await f.prepare(item), second = await f.prepare(item);
  const result = await Promise.all([f.request("run", first), f.request("run", second)]); assert.equal(result.filter(item => item.ok).length, 1); assert.equal(f.calls.filter(call => call.op === "run").length, 1);
  const other = fixture(); await other.capture(); const plan = await other.prepare(await other.network()); other.runFailure();
  assert.equal((await other.request("run", plan)).ok, false); assert.equal(other.local.ki_dast_batches[0].state, "unknown");
  assert.equal((await other.request("run", plan)).ok, false); assert.equal(other.calls.filter(call => call.op === "run").length, 1);
});
test("DAST startup shares the PTK scan-start lock and observes competing PTK initialization", async () => {
  const f = fixture(); await f.capture(); const plan = await f.prepare(await f.network());
  const locks = [], queued = [];
  f.scope.kiPtkLock = (key, operation) => { locks.push(key); return new Promise((resolve, reject) => queued.push(() => Promise.resolve(operation()).then(resolve, reject))); };
  const start = f.request("run", plan);
  for (let attempt = 0; attempt < 20 && !queued.length; attempt++) await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(locks, ["scan-start"]);
  f.scope.kiPtkCache.push({ state: "running" }); await queued.shift()();
  const rejected = await start; assert.equal(rejected.ok, false); assert.match(rejected.error, /active PTK/);
  assert.equal(f.calls.some(call => call.op === "run"), false); assert.equal(f.scope.kiDastHasActiveBatch(), false);
  f.scope.kiPtkCache.length = 0; f.scope.kiPtkLock = async (key, operation) => operation();
  assert.equal((await f.request("run", plan)).ok, true); assert.equal(f.scope.kiDastHasActiveBatch(), true);
});
test("run dispatch rechecks policy and scope after delayed companion authentication", async () => {
  for (const change of [f => f.disable(), f => f.contexts.chat.workspace.dastScope.excludePaths.push("/search")]) {
    const f = fixture(); await f.capture(); const plan = await f.prepare(await f.network()); f.beforeRun(() => change(f));
    const result = await f.request("run", plan); assert.equal(result.ok, false);
    assert.equal(f.calls.filter(call => call.op === "run").length, 0, "No private run payload may cross after the handshake-time revocation");
    assert.equal(f.local.ki_dast_batches[0].state, "failed", "A pre-dispatch refusal is not an uncertain execution");
  }
});
test("Stop while authentication is pending prevents a later run even before companion knows the batch", async () => {
  const f = fixture(); await f.capture(); const plan = await f.prepare(await f.network());
  let release, arrived; const pending = new Promise(resolve => arrived = resolve);
  f.beforeRun(async () => { arrived(); await new Promise(resolve => release = resolve); });
  const running = f.request("run", plan); await pending;
  const batchId = f.local.ki_dast_batches[0].batchId;
  assert.equal((await f.request("stop", { batchId })).ok, false, "Missing remote batch cannot be reported as remotely stopped");
  release(); const outcome = await running; assert.equal(outcome.ok, false); assert.equal(f.local.ki_dast_batches[0].state, "stopped");
  assert.equal(f.calls.filter(call => call.op === "run").length, 0);
});
test("storage revocation stops an accepted batch whose start reply was lost", async () => {
  for (const key of ["ki_tool_permissions", "ki_contexts"]) {
    const f = fixture(); await f.capture(); const plan = await f.prepare(await f.network()); f.loseReply();
    assert.equal((await f.request("run", plan)).ok, false); assert.equal(f.local.ki_dast_batches[0].state, "unknown");
    if (key === "ki_tool_permissions") f.disable(); else f.contexts.chat.workspace.dastScope.origins = [];
    for (const listener of f.events.changed) listener({ [key]: { newValue: {} } }, "local");
    for (let attempt = 0; attempt < 30 && f.local.ki_dast_batches[0].state !== "stopped"; attempt++) await new Promise(resolve => setImmediate(resolve));
    assert.equal(f.local.ki_dast_batches[0].state, "stopped"); assert.ok(f.calls.some(call => call.op === "stop"));
  }
});
test("browser restart interrupts old batches and startup awaits persisted PTK state", async () => {
  const f = fixture({ local: { ki_dast_batches: [{ batchId: "old", owner: "chat", epoch: "old-epoch", state: "unknown" }] } });
  await f.scope.kiDastLoad(); assert.equal(f.local.ki_dast_batches[0].state, "interrupted"); assert.equal(f.scope.kiDastHasActiveBatch(), false);
  await f.capture(); const plan = await f.prepare(await f.network());
  f.scope.kiPtkLoad = async () => { f.scope.kiPtkCache.push({ state: "running" }); };
  assert.equal((await f.request("run", plan)).ok, false); assert.equal(f.calls.some(call => call.op === "run"), false);
});
test("permission/scope revocation requests stop; status preserves authentication failure and in-flight stopping", async () => {
  const f = fixture(); await f.capture(); const plan = await f.prepare(await f.network()), run = await f.request("run", plan);
  f.setEngine({ state: "auth_expired", errors: ["Baseline authentication expired"] }); const auth = await f.request("status", { batchId: run.result.batchId }); assert.equal(auth.result.state, "auth_expired");
  const other = fixture(); await other.capture(); const second = await other.request("run", await other.prepare(await other.network())); other.disable();
  const stopped = await other.scope.kiDastStatus(second.result.batchId, "chat"); assert.equal(stopped.state, "stopped"); assert.ok(other.calls.some(call => call.op === "stop"));
});
test("export waits for terminal result and completed download before registering output", async () => {
  const f = fixture(); await f.capture(); const running = await f.request("run", await f.prepare(await f.network())), batchId = running.result.batchId;
  assert.equal((await f.request("export", { batchId })).ok, false); assert.equal(f.outputs.length, 0);
  f.complete(); const exported = await f.request("export", { batchId }); assert.equal(exported.ok, true, exported.error); assert.equal(f.outputs[0].owner, "chat");
  assert.equal(Object.keys(f.scope.kiDastPrivate.plans).length, 0, "Terminal batches release private plan copies while preserving public evidence metadata");
  assert.equal(JSON.parse(Buffer.from(f.downloads[0].data, "base64").toString()).schema, "cert-x-dast/v1");
  f.downloadFailure(); assert.equal((await f.request("export", { batchId })).ok, false); assert.equal(f.outputs.length, 1);
});

test("coverage and observations are bounded and status only persists known summary counts", async () => {
  const f = fixture(); await f.capture(); const running = await f.request("run", await f.prepare(await f.network())); f.complete();
  const coverage = Array.from({ length: 2001 }, (_, index) => ({ requestId: "request", family: "xss", state: ["tested", "skipped", "unsupported", "inconclusive"][index % 4], probesSent: 0 }));
  const observations = Array.from({ length: 101 }, (_, index) => ({ id: "observation-" + index, family: "response_checks", classification: "observation", title: "Observed response property", verifiedImpact: false }));
  f.setEngine({ coverage, observations, observationsCount: 101, coverageSummary: { tested: 1, skipped: -1, unsupported: "unsafe", inconclusive: 2, arbitrary: "PRIVATE" } });
  const result = await f.request("findings", { batchId: running.result.batchId }); assert.equal(result.ok, true, result.error); assert.equal(result.result.coverage.length, 2000); assert.equal(result.result.observations.length, 100); assert.equal(result.result.truncated, true); assert.equal("report" in result.result, false);
  assert.equal(result.result.batch.observationsCount, 101); assert.deepEqual(plain(result.result.batch.coverageSummary), { tested: 1, skipped: 0, unsupported: 0, inconclusive: 2 }); assert.equal(JSON.stringify(f.local).includes("PRIVATE"), false);
  f.setEngine({ coverage: [{ state: "pending" }] }); assert.equal((await f.request("findings", { batchId: running.result.batchId })).ok, false, "Coverage uses explicit terminal test outcomes, never ambiguous pending");
  f.setEngine({ coverage: [], observations: {} }); assert.equal((await f.request("findings", { batchId: running.result.batchId })).ok, false);
});
test("sender and ownership checks reject pages and unrelated chats; encoded scope bypasses fail", async () => {
  const f = fixture(); assert.equal((await f.request("state", {}, { id: "test", url: "https://target.test" })).ok, false);
  await f.capture(); const plan = await f.prepare(await f.network()); assert.equal((await f.request("run", { ...plan, session: "other" })).ok, false);
  for (const url of ["https://target.test/%61dmin/x", "https://target.test/%252e%252e/admin", "https://target.test/a%2fb/../admin", "https://target.test/a%2fb"]) assert.equal(f.scope.kiDastScopeAllows(url, f.contexts.chat.workspace.dastScope), false, url);
  assert.equal(f.scope.kiDastScopeAllows("https://target.test/administer", f.contexts.chat.workspace.dastScope), true, "Exclusions match a path and descendants, not unrelated prefix names");
});

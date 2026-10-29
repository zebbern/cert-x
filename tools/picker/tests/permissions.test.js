const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), vm = require("node:vm"), path = require("node:path");
const source = fs.readFileSync(path.join(__dirname, "../src/ki-permissions.js"), "utf8");
const flush = () => new Promise(resolve => setImmediate(resolve));
function fixture() {
  const data = { sidepanel_approval_mode: "full_access", ki_native_settings: { enabled: true, servers: [] }, ki_mcp_servers: [] };
  const approvals = [], calls = [], changes = [], listeners = [];
  let decision = "allow_once", beforeDecision;
  const context = vm.createContext({ console, URL, TextEncoder, AbortController, setTimeout, clearTimeout, crypto: require("node:crypto").webcrypto,
    pP: { click: { permissionAction: "interact" }, snapshot: { permissionAction: "read_page" } }, Ra: new Map(), kiNativeSpecs: [],
    chrome: { storage: { local: { get: async () => ({ ...data }), set: async update => { Object.assign(data, update); for (const listener of changes) listener(Object.fromEntries(Object.entries(update).map(([k,v]) => [k,{newValue:v}])), "local"); } }, onChanged: { addListener: fn => changes.push(fn) } },
      runtime: { id: "test", getURL: file => "chrome-extension://test/" + file, onMessage: { addListener: fn => listeners.push(fn) } } },
    KN: { request: async request => { approvals.push(request); await beforeDecision?.(); return decision; } },
  });
  vm.runInContext(source, context);
  const spec = (name, meta) => ({ name, kiPolicyMeta: meta, resolveExecution: args => ({ execute: async () => { calls.push(args); return { output: "ok" }; } }) });
  return { context, data, approvals, calls, decision: value => decision = value, beforeDecision: fn => beforeDecision = fn,
    rules: (groups = {}, tools = {}) => { data.ki_tool_permissions = { groups, tools }; },
    tool: (name, meta = context.kiPolicyLocalMeta(name)) => context.kiPolicyWrap(spec(name, meta), "session"),
    run: tool => tool.resolveExecution({ command: "echo fixture" }).execute({ signal: new AbortController().signal, toolCallId: "test" }),
    request: message => new Promise(resolve => listeners[0]({ type: "KI_PERMISSIONS", ...message }, { id: "test", url: "chrome-extension://test/providers/providers.html?section=tools" }, resolve)),
  };
}
test("individual rules override groups; parent disabled still wins", async () => {
  const f = fixture(), tool = f.tool("local_run_command");
  f.rules({ local: "disabled" }, { "local:local_run_command": "allow" });
  assert.equal((await f.run(tool)).isError, undefined);
  f.data.ki_native_settings.enabled = false;
  assert.equal((await f.run(tool)).isError, true); assert.equal(f.calls.length, 1);
});
test("Always ask overrides Full access and never uses persistent domain grants", async () => {
  const f = fixture(); f.rules({}, { "local:local_run_command": "ask" });
  assert.equal((await f.run(f.tool("local_run_command"))).isError, undefined);
  assert.equal(f.approvals.length, 1); assert.equal(f.approvals[0].policyExplicit, true);
  f.decision("allow_for_domain"); assert.equal((await f.run(f.tool("local_run_command"))).isError, true);
  assert.equal(f.calls.length, 1);
});

test("managed security tools retain explicit parent local restrictions", async () => {
  const f = fixture(), meta = { id: "ptk:security_raw", name: "security_raw", group: "ptk", family: "ptk", transport: "local", parentGroups: ["local"], defaultAsk: true };
  const tool = f.tool("security_raw", meta);
  f.rules({ local: "disabled" }, { "ptk:security_raw": "allow" });
  assert.equal((await f.run(tool)).isError, true); assert.equal(f.calls.length, 0);
  f.rules({ local: "ask" }, { "ptk:security_raw": "allow" });
  assert.equal((await f.run(tool)).isError, undefined); assert.equal(f.approvals.length, 1);
  f.data.ki_native_settings.enabled = false;
  assert.equal((await f.run(tool)).isError, true); assert.equal(f.calls.length, 1);
});

test("IAST activity records completed browser calls only after permission, without changing tool outcomes", async () => {
  const f = fixture(), activities = [];
  f.context.kiPtkActivity = async (...args) => { activities.push(args); };
  const tool = f.tool("click", f.context.kiPolicyBrowserMeta("click"));
  f.rules({}, { "browser:click": "disabled" }); assert.equal((await f.run(tool)).isError, true); assert.equal(activities.length, 0);
  f.rules(); assert.equal((await f.run(tool)).output, "ok"); assert.equal(activities.length, 1);
  assert.equal(activities[0][0], "session"); assert.equal(activities[0][1].name, "click");
  assert.ok(activities[0][4].endedAt >= activities[0][4].startedAt);
  await f.run(f.tool("local_read_file")); assert.equal(activities.length, 1);
  f.context.kiPtkActivity = async () => { throw Error("metadata unavailable"); };
  assert.equal((await f.run(tool)).output, "ok", "Evidence bookkeeping must not change the browser action result");
});

test("DAST approval previews the trusted immutable plan without adopting model-supplied summaries", async () => {
  const f = fixture(), publicPlan = { requests: [{ method: "GET", endpoint: "https://target.test/search" }], budget: { maxRequests: 100 } };
  f.data.sidepanel_approval_mode = "approve_for_me"; const executed = [];
  const tool = f.context.kiPolicyWrap({ name: "ptk_run_dast", kiPolicyMeta: { id: "ptk:ptk_run_dast", family: "ptk", group: "ptk", name: "ptk_run_dast", label: "Run DAST tests", defaultAsk: true },
    kiApprovalArgs: args => ({ planId: args.planId, plan: publicPlan }),
    resolveExecution: args => ({ execute: async () => { executed.push(args); return { output: "started" }; } }),
  }, "session");
  f.beforeDecision(() => { publicPlan.budget.maxRequests = 999; });
  const result = await tool.resolveExecution({ planId: "plan", plan: { endpoint: "forged" } }).execute({ signal: new AbortController().signal, toolCallId: "test" });
  assert.equal(result.output, "started"); assert.equal(executed[0].plan.budget.maxRequests, 100);
  assert.match(f.approvals[0].preview.text, /target\.test\/search/); assert.doesNotMatch(f.approvals[0].preview.text, /forged|999/);
  f.decision("deny"); await tool.resolveExecution({ planId: "plan" }).execute({ signal: new AbortController().signal, toolCallId: "denied" });
  assert.equal(executed.length, 1);
});
test("Allow skips approval in Requires approval; inherited local access asks", async () => {
  const f = fixture(); f.data.sidepanel_approval_mode = "approve_for_me";
  f.rules({ local: "allow" }); await f.run(f.tool("local_read_file")); assert.equal(f.approvals.length, 0);
  f.rules(); await f.run(f.tool("local_read_file")); assert.equal(f.approvals.length, 1);
});

test("private approval previews retain frozen execution arguments and still enforce denial", async () => {
  const f = fixture(), executed = []; f.data.sidepanel_approval_mode = "approve_for_me";
  const args = { label: "Account A", claims: [{ pointer: "/id", expected: "private-principal" }] };
  const tool = f.context.kiPolicyWrap({ name: "ptk_save_account", kiPolicyMeta: { id: "ptk:ptk_save_account", family: "ptk", group: "ptk", name: "ptk_save_account", label: "Save account", defaultAsk: true },
    kiApprovalPreview: value => ({ label: value.label, identityPointers: value.claims.map(claim => claim.pointer) }),
    resolveExecution: value => ({ execute: async () => { executed.push(value); return { output: "saved" }; } }),
  }, "session");
  f.beforeDecision(() => { args.claims[0].expected = "changed-after-snapshot"; });
  assert.equal((await tool.resolveExecution(args).execute({ signal: new AbortController().signal })).output, "saved");
  assert.equal(executed[0].claims[0].expected, "private-principal");
  assert.match(f.approvals[0].preview.text, /Account A/); assert.doesNotMatch(f.approvals[0].preview.text, /private-principal|changed-after/);
  f.decision("deny"); assert.equal((await tool.resolveExecution(args).execute({ signal: new AbortController().signal })).isError, true); assert.equal(executed.length, 1);
});
test("already-resolved and subagent definitions enforce new disabled rules", async () => {
  const f = fixture(), tool = f.tool("local_run_command");
  const resolved = tool.resolveExecution({ command: "echo before" });
  f.rules({}, { "local:local_run_command": "disabled" });
  const result = await resolved.execute({ signal: new AbortController().signal });
  assert.equal(result.isError, true); assert.equal(f.calls.length, 0);
  await f.context.kiPolicyLoad();
  const list = f.context.kiPolicyTools([{ name: "local_run_command", kiPolicyMeta: f.context.kiPolicyLocalMeta("local_run_command"), resolveExecution: () => ({}) }], "subagent-session");
  assert.equal(list.length, 0);
});
test("revocation while approval is open blocks the operation", async () => {
  const f = fixture(); f.rules({ local: "ask" }); f.beforeDecision(() => f.rules({ local: "disabled" }));
  assert.equal((await f.run(f.tool("local_write_file"))).isError, true); assert.equal(f.calls.length, 0);
});
test("browser inherited risky calls defer to existing approval; explicit Allow bypasses it", async () => {
  const f = fixture(); f.data.sidepanel_approval_mode = "approve_for_me";
  const meta = f.context.kiPolicyBrowserMeta("click");
  assert.equal((await f.context.kiPolicyGuard(meta, {}, {})).authorized, false);
  f.rules({ browser: "allow" });
  assert.equal((await f.context.kiPolicyGuard(meta, {}, {})).authorized, true);
});
test("MCP permissions use server identity and original tool name, independent of list order", async () => {
  const f = fixture(), server = { command: "node", args: ["x.js"], env: { A: "1", B: "2" } };
  f.data.ki_native_settings.servers = [server];
  const first = await f.context.kiPolicyMcpMeta(server, "echo", "local");
  const reordered = await f.context.kiPolicyMcpMeta({ ...server, label: "Renamed", env: { B: "2", A: "1" } }, "echo", "local");
  assert.equal(first.id, reordered.id);
  const accountA = await f.context.kiPolicyServerGroup({ id: "account-a", url: "https://example.com/mcp" }, "remote");
  const accountB = await f.context.kiPolicyServerGroup({ id: "account-b", url: "https://example.com/mcp" }, "remote");
  assert.notEqual(accountA, accountB);
  f.rules({ mcp: "disabled" }, { [first.id]: "allow" });
  assert.equal((await f.run(f.tool("local_mcp_new_index", first))).isError, undefined);
  f.data.ki_native_settings.servers = [];
  assert.equal((await f.run(f.tool("local_mcp_new_index", first))).isError, true);
});
test("external Browser control obeys disabled and pending approvals, including cancellation", async () => {
  const f = fixture(); f.rules({ browser: "disabled" });
  await assert.rejects(f.context.kiPolicyExternal("snapshot", {}, undefined, () => f.calls.push("ran")), /disabled/);
  f.rules({}, { "browser:snapshot": "ask" });
  const waiting = f.context.kiPolicyExternal("snapshot", {}, undefined, () => f.calls.push("ran"));
  await flush(); const [pending] = f.context.kiPolicyPending.values(); assert.ok(pending);
  await f.request({ op: "decide", id: pending.id, allow: true }); await waiting; assert.equal(f.calls.length, 1);
  assert.equal((await f.request({ op: "decide", id: pending.id, allow: true })).ok, false);
  const controller = new AbortController();
  const cancelled = f.context.kiPolicyExternal("snapshot", {}, controller.signal, () => f.calls.push("ran"));
  await flush(); controller.abort(); await assert.rejects(cancelled, /denied/);
  assert.equal(f.context.kiPolicyPending.size, 0); assert.equal(f.calls.length, 1);
});
test("parallel settings writes preserve distinct rules and reset removes overrides", async () => {
  const f = fixture();
  await Promise.all([f.request({ op: "set", bucket: "groups", id: "browser", value: "ask" }), f.request({ op: "set", bucket: "groups", id: "local", value: "allow" })]);
  assert.equal(f.data.ki_tool_permissions.groups.browser, "ask"); assert.equal(f.data.ki_tool_permissions.groups.local, "allow");
  await f.request({ op: "reset" }); assert.equal(Object.keys(f.data.ki_tool_permissions.groups).length, 0);
});

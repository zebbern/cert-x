const { test } = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const source = fs.readFileSync(path.join(__dirname, "../../picker/src/ki-native.js"), "utf8");
function bridge() {
  const listeners = [], storageListeners = [], sent = [], approvals = [];
  let settings = { enabled: true, servers: [] }, mode, decision = "allow_once", response = { ok: true, result: { exitCode: 0 } }, onDecision, onRead;
  const port = { onMessage: { addListener(fn) { port.message = fn; } }, onDisconnect: { addListener(fn) { port.disconnected = fn; } },
    postMessage(message) { sent.push(message); if (response) queueMicrotask(() => port.message({ id: message.id, ...response })); }, disconnect() { port.disconnected(); } };
  const context = vm.createContext({ console, setTimeout, clearTimeout, TextEncoder, AbortController,
    KI_POLICY_CONTEXT: Symbol("unit-policy"), kiPolicyLocalMeta: name => ({ name }), kiPolicyApproved: () => false, kiPolicyRecordMcp: async () => {},
    kiWorkspaceOwner: session => session, kiWorkspaceHostLost: async () => {},
    chrome: { runtime: { id: "test", getURL: file => "chrome-extension://test/" + file, connectNative: () => port,
      onMessage: { addListener: fn => listeners.push(fn) } }, storage: { local: { get: async () => { const result = { ki_native_settings: settings, sidepanel_approval_mode: mode }; onRead?.(); return result; } }, onChanged: { addListener: fn => storageListeners.push(fn) } } },
    KN: { request: async request => { approvals.push(request); await onDecision?.(); return decision; } }, kiMcpCache: { at: 1 }, kiMcpSlug: s => s });
  vm.runInContext(source, context);
  return { context, sent, approvals, port, settings: s => settings = s, decision: d => decision = d,
    mode: value => mode = value, onRead: fn => onRead = fn,
    response: r => response = r, onDecision: fn => onDecision = fn,
    change: () => storageListeners[0]({ ki_native_settings: {} }, "local"),
    message: (m, sender) => new Promise(resolve => listeners[0](m, sender, resolve)),
    execute: (index = 0, args = { command: "echo test", cwd: "C:\\" }, signal = new AbortController().signal) =>
      context.kiNativeTool(context.kiNativeSpecs[index], "session").resolveExecution(args).execute({ toolCallId: "call", signal }) };
}
test("native tools require approval, including reads; denial never reaches host", async () => {
  const b = bridge(); b.decision("deny");
  for (let i = 0; i < 4; i++) assert.equal((await b.execute(i)).isError, true);
  assert.equal(b.sent.length, 0); assert.equal(b.approvals.length, 4);
  assert.equal(b.approvals[0].local, true);
  assert.ok(b.approvals[0].preview.text.includes("echo test"));
  b.decision("allow_for_domain"); assert.equal((await b.execute()).isError, true); assert.equal(b.sent.length, 0);
});

test("Full access skips prompts for all native tools and local MCP", async () => {
  const b = bridge(); b.mode("full_access"); b.decision("deny");
  for (let i = 0; i < 4; i++) assert.equal((await b.execute(i)).isError, undefined);
  const server = { command: "node", args: ["server.js"] };
  b.settings({ enabled: true, servers: [server] });
  const tool = b.context.kiNativeTool({ name: "local_mcp_echo", op: "mcp_call", server, original: "echo" }, "session");
  assert.equal((await tool.resolveExecution({}).execute({ toolCallId: "mcp", signal: new AbortController().signal })).isError, undefined);
  assert.equal(b.approvals.length, 0); assert.equal(b.sent.length, 5);
  b.settings({ enabled: false });
  assert.equal((await b.execute()).isError, true); assert.equal(b.sent.length, 5);
});

test("mode changes apply to existing tools and revoking Full access before dispatch prevents execution", async () => {
  const b = bridge(); b.mode("full_access");
  assert.equal((await b.execute()).isError, undefined);
  b.mode("approve_for_me"); b.decision("deny");
  assert.equal((await b.execute()).isError, true);
  b.mode("unknown"); assert.equal((await b.execute()).isError, true);
  assert.equal(b.approvals.length, 2); assert.equal(b.sent.length, 1);
  b.mode("full_access"); b.onRead(() => b.mode("approve_for_me"));
  assert.match((await b.execute()).output, /Approval mode changed/);
  assert.equal(b.sent.length, 1);
});
test("disabled access and revocation during approval prevent execution", async () => {
  const b = bridge(); b.settings({ enabled: false });
  assert.equal((await b.execute()).isError, true); assert.equal(b.approvals.length, 0);
  b.settings({ enabled: true }); b.onDecision(() => b.settings({ enabled: false }));
  assert.equal((await b.execute()).isError, true); assert.equal(b.sent.length, 0);
});
test("approval uses a snapshot, propagates success and nested command failures", async () => {
  const b = bridge(), args = { command: "echo approved", cwd: "C:\\" };
  b.onDecision(() => { args.command = "different command"; });
  assert.equal((await b.execute(0, args)).isError, undefined);
  assert.equal(b.sent[0].params.command, "echo approved");
  b.response({ ok: true, result: { exitCode: 7 } }); assert.equal((await b.execute()).isError, true);
  b.response({ ok: false, error: "host application error" }); assert.match((await b.execute()).output, /host application error/);
  b.response({ ok: true }); assert.match((await b.execute()).output, /Invalid native/);
});
test("MCP result.isError is an error and changed server config is rejected", async () => {
  const b = bridge(), server = { command: "node", args: ["server.js"] };
  const spec = { name: "local_mcp_echo", op: "mcp_call", server, original: "echo", parameters: {} };
  const execute = () => b.context.kiNativeTool(spec, "session").resolveExecution({ text: "x" }).execute({ toolCallId: "mcp", signal: new AbortController().signal });
  b.settings({ enabled: true, servers: [server] });
  b.response({ ok: true, result: { isError: true, content: [{ type: "text", text: "bad" }] } });
  assert.equal((await execute()).isError, true);
  b.settings({ enabled: true, servers: [] });
  assert.match((await execute()).output, /configuration changed/);
  assert.equal(b.sent.length, 1);
});
test("settings endpoint rejects content scripts and arbitrary native operations", async () => {
  const b = bridge();
  assert.equal((await b.message({ type: "KI_NATIVE", op: "status" }, { id: "test", url: "https://example.com/" })).ok, false);
  assert.equal((await b.message({ type: "KI_NATIVE", op: "command" }, { id: "test", url: "chrome-extension://test/providers/providers.html" })).ok, false);
  assert.equal(b.sent.length, 0);
});
test("abort sends cancellation; disconnect rejects pending without replay", async () => {
  const b = bridge(); b.response(null);
  const controller = new AbortController();
  const running = b.context.kiNativeRpc("command", {}, controller.signal);
  controller.abort(); await assert.rejects(running, /cancelled/);
  assert.equal(b.sent[1].op, "cancel");
  const other = b.context.kiNativeRpc("status");
  b.port.disconnected(); await assert.rejects(other, /disconnected/);
  assert.equal(b.context.kiNativePending.size, 0); assert.equal(b.sent.length, 3);
});
test("settings change invalidates tool cache and disconnects active operations", async () => {
  const b = bridge(); b.response(null);
  const pending = b.context.kiNativeRpc("command");
  b.change(); await assert.rejects(pending, /disconnected/);
  assert.equal(b.context.kiNativeToolDefs("session").length, 0);
});

test("revocation during discovery does not launch remaining old servers", async () => {
  const b = bridge(); b.settings({ enabled: true, servers: [{ command: "first" }, { command: "second" }] });
  b.response(null);
  const refresh = b.context.kiNativeRefresh();
  await new Promise(resolve => setImmediate(resolve));
  b.change();
  await refresh;
  assert.equal(b.sent.length, 1);
  assert.equal(b.context.kiNativeToolDefs("session").length, 0);
});

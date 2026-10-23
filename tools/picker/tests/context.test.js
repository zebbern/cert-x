const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm"), { webcrypto } = require("node:crypto");
const plain = value => JSON.parse(JSON.stringify(value));
test('profile and workspace parent-group rules remain binding for derived security capabilities',()=>{
 const f=fixture(),meta={id:'security_oast',name:'security_oast',group:'ptk',family:'ptk',parentGroups:['local','mcp']};
 const context={tools:{groups:{local:false},tools:{security_oast:true}},permissions:{groups:{},tools:{}},mcp:null};
 assert.equal(f.context.kiContextAllows(meta,context),false);
 context.tools.groups.local=true;context.permissions.groups.mcp='ask';context.permissions.tools.security_oast='allow';
 assert.equal(f.context.kiContextRule(meta,context,'allow'),'ask');context.permissions.groups.mcp='disabled';assert.equal(f.context.kiContextRule(meta,context,'allow'),'disabled');
});
function fixture() {
  const data = { sidepanel_approval_mode: "full_access", ki_native_settings: { enabled: true, servers: [] }, ki_mcp_servers: [] };
  const listeners = [], changes = [], approvals = [], calls = [], discoveries = [], parents = new Map();
  let beforeApproval, beforeWrite, decision = "allow_once";
  const chrome = { runtime: { id: "test", getURL: file => "chrome-extension://test/" + file, getManifest: () => ({ version: "1" }), onMessage: { addListener: fn => listeners.push(fn) } },
    storage: { local: { get: async () => structuredClone(data), set: async update => { await beforeWrite?.(update); Object.assign(data, structuredClone(update)); for (const fn of changes) fn(Object.fromEntries(Object.entries(update).map(([key, value]) => [key, { newValue: value }])), "local"); } }, onChanged: { addListener: fn => changes.push(fn) } } };
  const context = vm.createContext({ chrome, console, crypto: webcrypto, URL, TextEncoder, AbortController, setTimeout, clearTimeout,
    pP: { snapshot: { permissionAction: "read_page" }, evaluate: { permissionAction: "execute_js" }, agent: {} }, Ra: new Map(),
    kiWorkspaceOwner: session => parents.get(session) || session || "browser-control", kiWorkspaceCapture: async () => {}, kiWorkspaceHostLost: async () => {},
    KN: { request: async request => { approvals.push(request); await beforeApproval?.(); return decision; } },
    pu: async () => ({ models: [{ connectionId: "provider", modelId: "fixture", label: "Fixture", apiKey: "DO-NOT-EXPOSE" }] }),
    XB: { snapshot: async () => ({ state: "disconnected" }) },
  });
  for (const name of ["ki-context.js", "ki-permissions.js", "ki-background.js", "ki-native.js"]) vm.runInContext(fs.readFileSync(path.join(__dirname, "../src", name), "utf8"), context);
  context.kiMcpList = async server => { discoveries.push("remote:" + server.id); return [{ name: "echo", inputSchema: { type: "object" } }]; };
  context.kiNativeRpc = async (op, args) => {
    if (op === "mcp_list") { discoveries.push("local:" + args.server.command); return { tools: [{ name: "echo", inputSchema: { type: "object" } }] }; }
    calls.push({ op, args }); return op === "status" ? { version: 1, revision: 2, features: ["command_jobs"] } : { exitCode: 0 };
  };
  const request = (message, url = "chrome-extension://test/providers/providers.html?section=profiles") => new Promise(resolve => {
    for (const fn of listeners) if (fn(message, { id: "test", url }, resolve) === true) break;
  });
  const mutate = async message => { const reply = await request({ type: "KI_CONTEXT", ...message }); assert.equal(reply.ok, true, reply.error); return reply.result; };
  return { context, data, calls, discoveries, parents, approvals, request, mutate, beforeApproval: fn => beforeApproval = fn, beforeWrite: fn => beforeWrite = fn, decision: value => decision = value,
    saveProfile: async (id, patch) => mutate({ op: "save_profile", profile: { ...context.kiContextBuiltins()[id], ...patch, id } }),
    saveWorkspace: async (id, patch = {}) => mutate({ op: "save_workspace", workspace: { id, name: id, profileId: "default", ...patch } }),
    assign: async (session, patch) => mutate({ op: "assign_chat", session, ...patch }),
    run: async (name = "local_run_command", args = { command: "echo test" }, session = "chat") => context.kiPolicyWrap(context.kiNativeTool(context.kiNativeSpecs.find(spec => spec.name === name), session), session).resolveExecution(args).execute({ signal: new AbortController().signal, toolCallId: "fixture" }),
    workspaceModule: () => vm.runInContext(fs.readFileSync(path.join(__dirname, "../src/ki-workspace.js"), "utf8"), context),
  };
}

test("four lazy presets preserve Default and focus Research without changing grants", async () => {
  const f = fixture(), state = await f.context.kiContextLoad();
  assert.deepEqual(Object.keys(state.profiles), ["default", "research", "coding", "bugbounty"]);
  assert.equal(f.data.ki_contexts, undefined);
  await f.assign("chat", { profileId: "research", modelExplicit: null });
  const context = await f.context.kiContextPrepare("chat");
  assert.equal(f.context.kiContextAllows(f.context.kiPolicyLocalMeta("local_run_command"), context), false);
  assert.equal(f.context.kiContextAllows(f.context.kiPolicyLocalMeta("local_read_file"), context), true);
  assert.deepEqual(plain(context.mcp), []); assert.equal(f.data.sidepanel_approval_mode, "full_access");
  assert.equal(f.data.ki_native_settings.enabled, true); assert.equal(f.calls.length, 0);
});

test("PTK starts in Bug bounty only; migration preserves explicit availability and global restrictions", async () => {
  const f = fixture(), start = { id: "ptk:ptk_start_scan", name: "ptk_start_scan", family: "ptk", group: "ptk" }, stop = { ...start, id: "ptk:ptk_stop_scan", name: "ptk_stop_scan" };
  for (const profileId of ["default", "research", "coding", "bugbounty"]) {
    await f.assign(profileId, { profileId }); const context = await f.context.kiContextPrepare(profileId);
    assert.equal(f.context.kiContextAllows(start, context), profileId === "bugbounty");
  }
  await f.saveProfile("bugbounty", { tools: { groups: {}, tools: {} } });
  let context = await f.context.kiContextPrepare("bugbounty"); assert.equal(context.tools.groups.ptk, true);
  await f.saveProfile("bugbounty", { tools: { groups: { ptk: false }, tools: { ptk_check: true } } });
  context = await f.context.kiContextPrepare("bugbounty"); assert.equal(f.context.kiContextAllows(start, context), false);
  assert.equal(f.context.kiContextAllows({ ...start, id: "ptk:ptk_check", name: "ptk_check" }, context), true);
  assert.equal(f.context.kiContextAllows(stop, context), true);
  assert.equal(f.context.kiContextRule(stop, context, "disabled"), "disabled");
  assert.equal(f.context.kiContextRule(start, f.context.kiContextFor("default"), "allow"), "disabled");
  assert.equal(f.data.sidepanel_approval_mode, "full_access"); assert.equal(f.calls.length, 0);
});

test("workspace DAST scope accepts exact origins and literal exclusions without implicitly widening scope", async () => {
  const f = fixture(); await f.saveWorkspace("target", { dastScope: { origins: ["https://TARGET.test/", "https://target.test"], excludePaths: ["/admin/", "/logout"] } });
  await f.assign("chat", { workspaceId: "target" }); const value = await f.context.kiContextResolve("chat");
  assert.deepEqual(plain(value.workspace.dastScope), { origins: ["https://target.test"], excludePaths: ["/admin", "/logout"] });
  for (const origin of ["https://*.target.test", "https://user:password@target.test", "https://target.test/path", "file:///C:/temp"]) assert.throws(() => f.context.kiContextDastScope({ origins: [origin], excludePaths: [] }));
  for (const excluded of ["admin", "/x/../admin", "/admin%2fsecret", "/admin?x=1"]) assert.throws(() => f.context.kiContextDastScope({ origins: ["https://target.test"], excludePaths: [excluded] }));
  assert.deepEqual(plain(f.context.kiContextDastScope(null)), { origins: [], excludePaths: [] });
});

test("workspace target scope persists only explicitly selected host matching", async () => {
  const f = fixture(); await f.saveWorkspace("target", { dastScope: { origins: ["https://APP.test:8443"], excludePaths: ["/admin"], matchMode: "host", includeSubdomains: true } });
  const saved = (await f.context.kiContextLoad()).workspaces.target.dastScope;
  assert.deepEqual(plain(saved), { origins: ["https://app.test:8443"], excludePaths: ["/admin"], matchMode: "host", includeSubdomains: true });
  for (const scope of [{ matchMode: "wide" }, { includeSubdomains: true }, { matchMode: "host", includeSubdomains: "yes" }]) assert.throws(() => f.context.kiContextDastScope({ origins: ["https://app.test"], excludePaths: [], ...scope }));
});

test("workspace overrides, explicit pins, parallel saves and metadata deletion round-trip", async () => {
  const f = fixture();
  await Promise.all([f.saveWorkspace("first", { profileId: "research", folder: "C:\\repo", notes: "Evidence only", pins: [{ kind: "file", path: "C:\\repo\\notes.md" }, { kind: "page", url: "https://example.com/page", title: "Reference" }], mcp: "all" }), f.saveWorkspace("second")]);
  await f.assign("chat", { workspaceId: "first" });
  let effective = await f.context.kiContextPrepare("chat");
  assert.equal(effective.profile.id, "research"); assert.equal(effective.folder, "C:\\repo"); assert.equal(effective.mcp, null);
  assert.equal(effective.pins.length, 2); assert.equal(f.calls.length, 0); assert.match(f.context.kiContextPrompt("chat"), /not already-read evidence/);
  assert.equal((await f.context.kiContextLoad()).workspaces.second.name, "second");
  f.data.ki_task_outputs = [{ owner: "chat", path: "C:\\repo\\output.md" }];
  await f.mutate({ op: "delete_workspace", id: "first" });
  effective = await f.context.kiContextResolve("chat"); assert.equal(effective.workspace, null); assert.equal(effective.profile.id, "default");
  assert.equal(f.data.ki_task_outputs.length, 1); assert.equal(f.calls.length, 0);
});

test("model precedence preserves legacy choices and supports explicit inheritance", async () => {
  const f = fixture(); f.data.sidepanel_session_models = { legacy: { connectionId: "old", modelId: "manual" } };
  await f.saveProfile("coding", { model: { connectionId: "p", modelId: "profile" } });
  await f.saveWorkspace("repo", { profileId: "coding", model: { connectionId: "p", modelId: "workspace" } });
  await f.assign("legacy", { workspaceId: "repo" });
  assert.equal((await f.context.kiContextResolve("legacy")).model.modelId, "manual");
  await f.assign("chat", { workspaceId: "repo", modelExplicit: null });
  assert.equal((await f.context.kiContextResolve("chat")).modelSource, "workspace");
  await f.assign("chat", { modelExplicit: { connectionId: "p", modelId: "explicit" } });
  assert.equal((await f.context.kiContextResolve("chat")).model.modelId, "explicit");
  const catalog = await f.request({ type: "KI_CONTEXT", op: "models" }); assert.equal(catalog.ok, true); assert.equal(JSON.stringify(catalog).includes("DO-NOT-EXPOSE"), false);
});

test("profile duplicate/reset/delete keeps associations valid and validates trusted input", async () => {
  const f = fixture();
  await f.saveProfile("research", { instructions: "Custom research" });
  const duplicate = await f.mutate({ op: "duplicate_profile", id: "research" }); const custom = duplicate.profiles.find(profile => !profile.builtin);
  await f.saveWorkspace("researching", { profileId: custom.id }); await f.assign("chat", { profileId: custom.id });
  await f.mutate({ op: "delete_profile", id: custom.id }); assert.equal((await f.context.kiContextResolve("chat")).profile.id, "default");
  await f.mutate({ op: "reset_profile", id: "research" }); assert.notEqual((await f.context.kiContextLoad()).profiles.research.instructions, "Custom research");
  assert.equal((await f.request({ type: "KI_CONTEXT", op: "delete_profile", id: "default" })).ok, false);
  assert.equal((await f.request({ type: "KI_CONTEXT", op: "state" }, "https://example.com/")).ok, false);
  for (const patch of [{ folder: "relative" }, { pins: [{ kind: "page", url: "javascript:alert(1)" }] }, { mcp: ["fake"] }]) assert.equal((await f.request({ type: "KI_CONTEXT", op: "save_workspace", workspace: { name: "invalid", ...patch } })).ok, false);
});

test("concurrent chat initialization cannot erase explicit model choices or move legacy chats", async () => {
  const f = fixture();
  await f.saveWorkspace("repo", { profileId: "coding" }); await f.assign("previous", { workspaceId: "repo" });
  const initialize = session => f.mutate({ op: "initialize_chat", session, previousSession: "previous" });
  await Promise.all([initialize("new-chat"), f.assign("new-chat", { modelExplicit: { connectionId: "p", modelId: "manual" } }), initialize("new-chat")]);
  let resolved = await f.context.kiContextResolve("new-chat");
  assert.equal(resolved.workspace.id, "repo"); assert.equal(resolved.model.modelId, "manual");
  await Promise.all([f.assign("second-chat", { modelExplicit: { connectionId: "p", modelId: "selected-first" } }), initialize("second-chat")]);
  resolved = await f.context.kiContextResolve("second-chat"); assert.equal(resolved.model.modelId, "selected-first"); assert.equal(resolved.workspace, null);
  f.data.sidepanel_session_models = { legacy: { connectionId: "old", modelId: "preserved" } };
  await initialize("legacy"); resolved = await f.context.kiContextResolve("legacy");
  assert.equal(resolved.model.modelId, "preserved"); assert.equal(resolved.workspace, null);
});

test("state and effective reads wait for earlier queued model writes", async () => {
  const f = fixture(); await f.assign("chat", { modelExplicit: null });
  let release, entered, stateDone = false, effectiveDone = false;
  const writing = new Promise(resolve => entered = resolve), blocked = new Promise(resolve => release = resolve);
  f.beforeWrite(async () => { entered(); await blocked; });
  const change = f.assign("chat", { modelExplicit: { connectionId: "chosen", modelId: "manual" } });
  await writing;
  const stateRead = f.request({ type: "KI_CONTEXT", op: "state" }).then(value => { stateDone = true; return value; });
  const effectiveRead = f.request({ type: "KI_CONTEXT", op: "effective", session: "chat" }).then(value => { effectiveDone = true; return value; });
  const turnPrepare = f.context.kiContextPrepare("chat");
  await new Promise(resolve => setImmediate(resolve)); assert.equal(stateDone, false); assert.equal(effectiveDone, false);
  release(); await change;
  assert.equal((await stateRead).result.chats.chat.modelExplicit.modelId, "manual");
  assert.equal((await effectiveRead).result.model.modelId, "manual");
  assert.equal((await turnPrepare).model.modelId, "manual");
});

test("subagents share the turn snapshot; restrictions block stale calls immediately", async () => {
  const f = fixture(); await f.assign("chat", { profileId: "coding" }); await f.context.kiContextPrepare("chat"); f.parents.set("child", "chat");
  await f.saveProfile("coding", { instructions: "Changed for next message", tools: { groups: {}, tools: { local_run_command: false } } });
  const child = await f.context.kiContextPrepare("child"); assert.notEqual(child.instructions, "Changed for next message");
  const result = await f.run("local_run_command", { command: "echo test", cwd: "C:\\" }, "child"); assert.equal(result.isError, true); assert.equal(f.calls.length, 0);
  await f.context.kiContextPrepare("chat"); assert.equal(f.context.kiContextFor("child").instructions, "Changed for next message");
});

test("profile Allow cannot relax global Ask/Disabled; revocation during approval aborts", async () => {
  const f = fixture(); await f.saveProfile("coding", { permissions: { groups: { local: "allow" }, tools: {} } }); await f.assign("chat", { profileId: "coding" }); await f.context.kiContextPrepare("chat");
  f.data.ki_tool_permissions = { groups: { local: "ask" }, tools: {} };
  assert.equal((await f.run("local_run_command", { command: "echo test", cwd: "C:\\" })).isError, undefined); assert.equal(f.approvals.length, 1);
  f.beforeApproval(() => f.assign("chat", { profileId: "research" }));
  assert.equal((await f.run("local_run_command", { command: "echo test", cwd: "C:\\" })).isError, true); assert.equal(f.calls.length, 1);
  f.data.ki_tool_permissions = { groups: { local: "disabled" }, tools: {} };
  assert.equal((await f.run("local_read_file", { path: "C:\\file" })).isError, true); assert.equal(f.calls.length, 1);
});

test("workspace cwd is optional in schema and resolved into the exact approval payload", async () => {
  const f = fixture(); await f.saveWorkspace("repo", { profileId: "coding", folder: "C:\\repository" }); await f.assign("chat", { workspaceId: "repo" }); await f.context.kiContextPrepare("chat");
  f.data.sidepanel_approval_mode = "approve_for_me";
  const command = f.context.kiNativeTool(f.context.kiNativeSpecs[0], "chat"); assert.deepEqual(plain(command.parameters.required), ["command"]);
  f.beforeApproval(() => f.saveWorkspace("repo", { profileId: "coding", folder: "C:\\other" }));
  await f.run(); assert.match(f.approvals[0].preview.text, /repository/); assert.equal(f.calls[0].args.cwd, "C:\\repository");
  assert.equal(f.context.kiNativeTool(f.context.kiNativeSpecs[0], "ordinary").parameters.required.includes("cwd"), true);
});

test("job controls remain available after command deselection, but global rules still win", async () => {
  const f = fixture(); await f.saveProfile("research", { tools: { groups: { local: false }, tools: { local_cancel_job: false } }, permissions: { groups: { local: "disabled" }, tools: {} } });
  await f.assign("chat", { profileId: "research" }); await f.context.kiContextPrepare("chat");
  const meta = f.context.kiPolicyLocalMeta("local_cancel_job");
  assert.equal(f.context.kiContextRule(meta, f.context.kiContextFor("chat"), "inherit"), "inherit");
  assert.equal(f.context.kiContextRule(meta, f.context.kiContextFor("chat"), "disabled"), "disabled");
});

test("concurrent task discovery starts only selected servers and caches each connection", async () => {
  const f = fixture(), first = { command: "first" }, second = { command: "second" }, third = { command: "unused" }, remote = { id: "remote", url: "https://example.com/mcp" };
  f.data.ki_native_settings.servers = [first, second, third]; f.data.ki_mcp_servers = [remote];
  const ids = await Promise.all([first, second].map(server => f.context.kiPolicyServerGroup(server, "local"))), remoteId = await f.context.kiPolicyServerGroup(remote, "remote");
  await f.saveWorkspace("a", { mcp: [ids[0]] }); await f.saveWorkspace("b", { mcp: [ids[1], remoteId] });
  await f.assign("chat-a", { workspaceId: "a" }); await f.assign("chat-b", { workspaceId: "b" });
  await Promise.all([f.context.kiContextPrepare("chat-a"), f.context.kiContextPrepare("chat-b")]);
  await Promise.all([f.context.kiMcpRefresh("chat-a"), f.context.kiMcpRefresh("chat-b"), f.context.kiMcpRefresh("chat-a")]);
  assert.deepEqual(f.discoveries.sort(), ["local:first", "local:second", "remote:remote"]);
  assert.equal(f.context.kiMcpToolDefs("chat-a").length, 0); assert.equal(f.context.kiMcpToolDefs("chat-b").length, 1);
  assert.equal(f.context.kiNativeToolDefs("chat-a").filter(tool => tool.name.startsWith("local_mcp_")).length, 1);
  await f.context.kiMcpRefresh("chat-b"); assert.equal(f.discoveries.length, 3);
});

test("removing a server selection during discovery prevents later process startup", async () => {
  const f = fixture(), servers = [{ command: "first" }, { command: "second" }]; f.data.ki_native_settings.servers = servers;
  await f.assign("chat", { modelExplicit: null }); await f.context.kiContextPrepare("chat");
  f.context.kiNativeRpc = async (op, args) => { f.discoveries.push(args.server.command); await f.assign("chat", { profileId: "research" }); return { tools: [] }; };
  await f.context.kiMcpRefresh("chat"); assert.deepEqual(f.discoveries, ["first"]);
});

test("explicit MCP tool selections discover their server under disabled availability defaults", async () => {
  const f = fixture(), local = { command: "selected" }, remote = { id: "remote", url: "https://example.com/mcp" };
  f.data.ki_native_settings.servers = [local]; f.data.ki_mcp_servers = [remote];
  const localGroup = await f.context.kiPolicyServerGroup(local, "local"), remoteGroup = await f.context.kiPolicyServerGroup(remote, "remote");
  await f.saveWorkspace("repo", { mcp: [localGroup, remoteGroup], tools: { groups: { mcp: false, [localGroup]: false }, tools: { [localGroup + ":echo"]: true, [remoteGroup + ":echo"]: true } } });
  await f.assign("chat", { workspaceId: "repo" }); await f.context.kiContextPrepare("chat");
  await f.context.kiMcpRefresh("chat");
  assert.deepEqual(f.discoveries.sort(), ["local:selected", "remote:remote"]);
  assert.equal(f.context.kiNativeToolDefs("chat").filter(tool => tool.name.startsWith("local_mcp_")).length, 1);
  assert.equal(f.context.kiMcpToolDefs("chat").length, 1);
  await f.saveWorkspace("repo", { mcp: [], tools: { groups: { mcp: false }, tools: { [localGroup + ":echo"]: true, [remoteGroup + ":echo"]: true } } });
  assert.equal(await f.context.kiContextServerSelected(local, "local", "chat"), false);
  assert.equal(await f.context.kiContextServerSelected(remote, "remote", "chat"), false);
  await f.context.kiContextPrepare("chat");
  assert.equal(f.context.kiMcpToolDefs("chat").length, 0);
});

test("remote tool aliases remain unique across ambiguous and truncated server slugs", async () => {
  const f = fixture(); f.data.ki_mcp_servers = ["a_b", "a", "x".repeat(30) + "1", "x".repeat(30) + "2"].map((id, index) => ({ id, url: "https://example.com/mcp/" + index }));
  f.context.kiMcpList = async server => [{ name: server.id === "a_b" ? "c" : server.id === "a" ? "b_c" : "echo", inputSchema: { type: "object" } }];
  await f.context.kiContextPrepare("chat"); await f.context.kiMcpRefresh("chat");
  const names = f.context.kiMcpToolDefs("chat").map(tool => tool.name);
  assert.equal(new Set(names).size, 4); assert.ok(names.every(name => name.length <= 64));
  const status = await f.request({ type: "KI_MCP", op: "status" }); assert.equal(status.ok, true); assert.ok(status.servers.every(server => server.toolCount === 1));
});

test("connection changes during discovery cannot publish or launch remaining stale servers", async () => {
  const f = fixture(), next = { id: "new", url: "https://example.com/new" };
  f.data.ki_mcp_servers = [{ id: "first", url: "https://example.com/first" }, { id: "second", url: "https://example.com/second" }];
  let changed = false;
  f.context.kiMcpList = async server => { f.discoveries.push(server.id); if (!changed) { changed = true; await f.context.chrome.storage.local.set({ ki_mcp_servers: [next] }); } return [{ name: "echo", inputSchema: {} }]; };
  await f.context.kiContextPrepare("chat"); await f.context.kiMcpRefresh("chat");
  assert.deepEqual(f.discoveries, ["first"]); assert.equal(f.context.kiMcpToolDefs("chat").length, 0);
  await f.context.kiMcpRefresh("chat"); assert.deepEqual(f.discoveries, ["first", "new"]); assert.equal(f.context.kiMcpToolDefs("chat").length, 1);
  f.data.ki_native_settings.servers = [{ command: "old-local" }];
  f.context.kiContextServerSelected = async (server, transport) => { if (transport === "local") await f.context.chrome.storage.local.set({ ki_native_settings: { enabled: false, servers: [] } }); return true; };
  await f.context.kiNativeRefresh("chat"); assert.equal(f.discoveries.includes("local:old-local"), false);
});

test("cached remote tools use current credentials and propagate application failures", async () => {
  const f = fixture(), server = { id: "remote", url: "https://example.com/mcp", token: "initial-fixture-token" };
  f.data.ki_mcp_servers = [server]; await f.context.kiContextPrepare("chat"); await f.context.kiMcpRefresh("chat");
  const tool = f.context.kiPolicyWrap(f.context.kiMcpToolDefs("chat")[0], "chat");
  await f.context.chrome.storage.local.set({ ki_mcp_servers: [{ ...server, token: "replacement-fixture-token" }] });
  f.context.kiMcpCall = async current => { assert.equal(current.token, "replacement-fixture-token"); throw Error("MCP fixture reported isError"); };
  const result = await tool.resolveExecution({}).execute({ signal: new AbortController().signal });
  assert.equal(result.isError, true); assert.match(result.output, /reported isError/);
});

test("workspace output aggregation and capability reasons retain chat ownership", async () => {
  const f = fixture(); f.workspaceModule();
  await f.saveWorkspace("repo", { profileId: "research" }); await f.assign("one", { workspaceId: "repo" }); await f.assign("two", { workspaceId: "repo" }); await f.context.kiContextPrepare("one");
  f.data.ki_task_outputs = [{ id: "a", owner: "one", name: "A" }, { id: "b", owner: "two", name: "B" }, { id: "c", owner: "other", name: "C" }];
  const reply = await f.request({ type: "KI_WORKSPACE", op: "outputs", workspaceId: "repo" }); assert.equal(reply.ok, true); assert.deepEqual(plain(reply.result.map(item => item.owner)), ["one", "two"]);
  const health = await f.context.kiWorkspaceHealth("local_run_command", "main", "one"); assert.equal(health.task.profile.id, "research"); assert.equal(health.permissions.tools[0].available, false); assert.match(health.permissions.tools[0].reasons.join(" "), /Not selected/);
  await f.assign("two", { workspaceId: null }); const moved = await f.request({ type: "KI_WORKSPACE", op: "outputs", workspaceId: "repo" }); assert.equal(moved.result.length, 1); assert.equal(f.data.ki_task_outputs.length, 3);
});

test("general capability discovery does not advertise security tools excluded by the active profile", async () => {
  const f = fixture(); f.workspaceModule();
  let detailedCalls = 0;
  f.context.kiSecurityHealth = async () => { detailedCalls++; return { unavailable: "x".repeat(30000) }; };
  f.context.kiPtkHealth = () => ({ readiness: "Use security_capabilities" });
  f.context.kiPolicyInventory = async () => ({ tools: ["security_capabilities", "security_start_scan"].map(name => ({ id: name, name, family: "ptk", group: "ptk" })) });
  const ordinary = await f.context.kiWorkspaceHealth("security_start_scan", "main", "chat");
  assert.equal(ordinary.security.available, false);
  assert.match(ordinary.security.reason, /not selected/i);
  assert.equal(ordinary.permissions.tools[0].available, false);
  assert.equal(ordinary.ptk, undefined);
  await f.assign("chat", { profileId: "bugbounty" });
  const selected = await f.context.kiWorkspaceHealth("security_start_scan", "main", "chat");
  assert.equal(selected.security.available, true);
  assert.equal(selected.security.discoveryTool, "security_capabilities");
  assert.equal(detailedCalls, 0, "general health must not embed detailed security schemas");
  assert.ok(JSON.stringify(selected).length < 3000);
  const summary = f.context.kiWorkspaceAgentHealth(selected, "", "summary");
  assert.equal(summary.permissions.tools, undefined);
  assert.ok(summary.permissions.availableTools.includes("security_start_scan"));
  assert.equal(f.context.kiWorkspaceAgentHealth(selected, "", "full"), selected);
  assert.equal(f.context.kiWorkspaceAgentHealth(ordinary, "security_start_scan", "summary").permissions.tools[0].available, false);
});

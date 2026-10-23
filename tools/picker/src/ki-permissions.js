var KI_POLICY_KEY = "ki_tool_permissions", KI_POLICY_CATALOG = "ki_tool_catalog";
var KI_POLICY_CONTEXT = Symbol("cert-x tool permission"), KI_POLICY_TOKEN = Symbol("approved tool");
var kiPolicyCache = { groups: {}, tools: {} }, kiPolicyCatalog = new Map(), kiPolicyPending = new Map();
var kiPolicyModes = new Set(["inherit", "ask", "allow", "disabled"]);
var kiPolicyWrites = Promise.resolve();
function kiPolicyWrite(operation) { const result = kiPolicyWrites.then(operation); kiPolicyWrites = result.catch(() => {}); return result; }
function kiPolicyClean(raw) {
  const result = { version: 1, groups: {}, tools: {} };
  for (const bucket of ["groups", "tools"]) for (const [key, value] of Object.entries(raw?.[bucket] || {})) {
    if (kiPolicyModes.has(value) && value !== "inherit" && key !== "__proto__") result[bucket][key] = value;
  }
  return result;
}
async function kiPolicyLoad() {
  kiPolicyCache = kiPolicyClean((await chrome.storage.local.get(KI_POLICY_KEY))[KI_POLICY_KEY]);
  return kiPolicyCache;
}
function kiPolicyRule(meta, policy) {
  const direct = policy.tools[meta.id] || policy.groups[meta.group] || (meta.family === "mcp" ? policy.groups.mcp : undefined) || "inherit";
  const inherited = [...(meta.aliases || []).map(id => policy.tools[id]), ...(meta.parentGroups || []).map(id => policy.groups[id])].filter(Boolean);
  if ([direct, ...inherited].includes('disabled')) return 'disabled';
  if ([direct, ...inherited].includes('ask')) return 'ask';
  return direct;
}
function kiPolicyBrowserMeta(name) {
  const action = typeof pP === "object" ? pP[name]?.permissionAction : undefined;
  return { id: "browser:" + name, group: "browser", family: "browser", name, label: kiPolicyLabel(name),
    description: typeof pP === "object" ? pP[name]?.description || "" : "",
    defaultAsk: ["interact", "execute_js"].includes(action) || (!action && !/^(list_|get_|read_|snapshot|screenshot|find|inspect)/.test(name)) };
}
function kiPolicyLocalMeta(name) { return { id: "local:" + name, group: "local", family: "local", name, label: kiPolicyLabel(name), defaultAsk: !["local_read_job", "local_cancel_job"].includes(name) }; }
function kiPolicyLabel(name) {
  const labels = { local_run_command: "Run commands", local_read_file: "Read files", local_write_file: "Write files", local_list_directory: "List folders", navigate: "Open pages", evaluate: "Run page scripts", cdp: "DevTools commands", agent: "Run a subagent" };
  return labels[name] || name.replace(/^local_/, "").replaceAll("_", " ").replace(/^./, char => char.toUpperCase());
}
async function kiPolicyServerGroup(server, transport) {
  const identity = transport === "remote" ? ["remote", server.id || server.url, server.url] : ["local", server.command, server.args || [], server.cwd || "", Object.entries(server.env || {}).sort(([a], [b]) => a.localeCompare(b))];
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(identity)));
  return "mcp:" + transport + ":" + Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
}
async function kiPolicyMcpMeta(server, name, transport) {
  const group = await kiPolicyServerGroup(server, transport);
  return { id: group + ":" + name, group, family: "mcp", transport,
    name, label: kiPolicyLabel(name), groupLabel: server.label || (transport === "remote" ? new URL(server.url).host : server.command), defaultAsk: true };
}
function kiPolicyRegister(meta) { kiPolicyCatalog.set(meta.id, meta); return meta; }
async function kiPolicyRecordMcp(server, tools, transport) {
  for (const tool of tools) if (typeof tool?.name === "string") kiPolicyRegister({ ...await kiPolicyMcpMeta(server, tool.name, transport), description: String(tool.description || "").slice(0, 500) });
  await chrome.storage.local.set({ [KI_POLICY_CATALOG]: [...kiPolicyCatalog.values()].filter(meta => meta.family === "mcp").slice(-2048) });
}
async function kiPolicyState(meta, session) {
  const data = await chrome.storage.local.get([KI_POLICY_KEY, "sidepanel_approval_mode", "ki_native_settings", "ki_mcp_servers"]);
  const policy = kiPolicyClean(data[KI_POLICY_KEY]);
  let parentEnabled = true;
  if (meta.family === "local" || meta.transport === "local") parentEnabled = data.ki_native_settings?.enabled === true;
  if (meta.family === "mcp") {
    const list = meta.transport === "local" ? data.ki_native_settings?.servers || [] : data.ki_mcp_servers || [];
    parentEnabled &&= (await Promise.all(list.map(server => kiPolicyServerGroup(server, meta.transport)))).includes(meta.group);
  }
  let rule = kiPolicyRule(meta, policy);
  if (session && typeof kiContextResolve === "function") {
    const current = kiContextRule(meta, await kiContextResolve(session), rule), snapshot = kiContextRule(meta, kiContextFor(session), rule);
    rule = [current, snapshot].includes("disabled") ? "disabled" : [current, snapshot].includes("ask") ? "ask" : [current, snapshot].includes("inherit") ? "inherit" : "allow";
  }
  return { rule, fullAccess: data.sidepanel_approval_mode === "full_access", parentEnabled };
}
function kiPolicyDenied(meta) { return Error('Tool "' + meta.label + '" is disabled in Tools & permissions.'); }
function kiPolicyExternalAsk(meta, args, signal) {
  signal?.throwIfAborted();
  return new Promise(resolve => {
    const id = crypto.randomUUID(), notificationId = "ki-policy:" + id;
    let settled = false;
    const clearNotification = () => { chrome.notifications?.clear?.(notificationId)?.catch(() => {}); };
    const finish = allowed => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener("abort", abort); kiPolicyPending.delete(id); clearNotification(); resolve(allowed); };
    const abort = () => finish(false);
    const timer = setTimeout(() => finish(false), 120000);
    kiPolicyPending.set(id, { id, label: meta.label, tool: meta.name, preview: JSON.stringify(args, null, 2), finish });
    signal?.addEventListener("abort", abort, { once: true });
    chrome.notifications?.create?.(notificationId, { type: "basic", iconUrl: chrome.runtime.getURL("icon/128.png"), title: "Browser control needs approval", message: meta.label + ". Open Tools & permissions to review." })?.then(() => { if (settled) clearNotification(); }).catch(() => {});
  });
}
async function kiPolicyGuard(meta, args, context = {}, external = false) {
  if (meta.securityStop) return { meta, approved: false, authorized: true, external, session: context.session, token: KI_POLICY_TOKEN };
  const state = await kiPolicyState(meta, context.session);
  if (!state.parentEnabled) throw Error("The parent capability or MCP server is disabled or unavailable.");
  if (state.rule === "disabled") throw kiPolicyDenied(meta);
  const legacy = !external && meta.family === "browser" && state.rule === "inherit" && !state.fullAccess && meta.defaultAsk;
  const ask = !legacy && (state.rule === "ask" || (state.rule === "inherit" && !state.fullAccess && meta.defaultAsk));
  let approved = false;
  if (ask) {
    if (external) approved = await kiPolicyExternalAsk(meta, args, context.signal);
    else approved = await KN.request({ local: true, policyPrompt: true, policyExplicit: state.rule === "ask", domain: meta.groupLabel || (meta.family === "local" ? "Local computer" : "Browser"),
      action: "tool", toolCallId: context.toolCallId, toolName: meta.name, session: context.session,
      preview: { text: meta.label + " (" + meta.name + ")\n" + JSON.stringify(args, null, 2) } }, context.signal) === "allow_once";
    if (!approved) throw Error("Tool operation denied by user.");
  }
  context.signal?.throwIfAborted();
  const lease = { meta, approved, authorized: !legacy, external, session: context.session, token: KI_POLICY_TOKEN };
  await kiPolicyRecheck(lease);
  return lease;
}
async function kiPolicyRecheck(lease) {
  if (!lease || lease.token !== KI_POLICY_TOKEN) throw Error("Missing tool permission context.");
  if (lease.meta.securityStop) return;
  const state = await kiPolicyState(lease.meta, lease.session);
  if (!state.parentEnabled) throw Error("The parent capability or MCP server is disabled or unavailable.");
  if (state.rule === "disabled") throw kiPolicyDenied(lease.meta);
  const needsAsk = state.rule === "ask" || (state.rule === "inherit" && !state.fullAccess && lease.meta.defaultAsk);
  if (needsAsk && !lease.approved && lease.authorized) throw Error("Tool permissions changed before execution; retry for approval.");
  if (state.rule === "ask" && !lease.approved && !lease.authorized) throw Error("Tool permissions changed before execution; retry for approval.");
}
function kiPolicyApproved(context) { const lease = context?.[KI_POLICY_CONTEXT]; return lease?.token === KI_POLICY_TOKEN && lease.authorized; }
function kiPolicyWrap(tool, session) {
  const meta = kiPolicyRegister(tool.kiPolicyMeta || kiPolicyBrowserMeta(tool.name));
  return { ...tool, resolveExecution(args) {
    const supplied = typeof kiContextArgs === "function" ? kiContextArgs(tool.name, args, session) : JSON.parse(JSON.stringify(args || {}));
    const snapshot = tool.kiApprovalArgs ? JSON.parse(JSON.stringify(tool.kiApprovalArgs(supplied, session))) : supplied;
    const preview = tool.kiApprovalPreview ? JSON.parse(JSON.stringify(tool.kiApprovalPreview(snapshot, session))) : snapshot;
    const resolved = tool.resolveExecution(snapshot);
    return { ...resolved, async execute(context) {
      try {
        const executionMeta = tool.kiPolicyMetaFor ? tool.kiPolicyMetaFor(snapshot) : meta;
        const lease = await kiPolicyGuard(executionMeta, preview, { ...context, session });
        const activityStartedAt = Date.now();
        const result = await resolved.execute({ ...context, [KI_POLICY_CONTEXT]: lease });
        const activityEndedAt = Date.now();
        try { await kiWorkspaceCapture(meta, snapshot, result, session); } catch {}
        if (meta.family === "browser" && typeof kiPtkActivity === "function") {
          try { await kiPtkActivity(session, meta, snapshot, result, { startedAt: activityStartedAt, endedAt: activityEndedAt }); } catch {}
        }
        return result;
      } catch (error) { return { output: error.message, isError: true }; }
    } };
  } };
}
function kiPolicyTools(tools, session) {
  return tools.map(tool => kiPolicyWrap(tool, session)).filter(tool => {
    const meta = tool.kiPolicyMeta || kiPolicyBrowserMeta(tool.name), rule = kiPolicyRule(meta, kiPolicyCache);
    return meta.securityStop || (session && typeof kiContextFor === "function" ? kiContextRule(meta, kiContextFor(session), rule) : rule) !== "disabled";
  });
}
async function kiPolicyExternal(name, args, signal, execute) {
  const lease = await kiPolicyGuard(kiPolicyBrowserMeta(name), args, { signal }, true);
  await kiPolicyRecheck(lease); signal?.throwIfAborted();
  return execute(lease);
}
async function kiPolicyInventory() {
  const data = await chrome.storage.local.get([KI_POLICY_KEY, KI_POLICY_CATALOG, "ki_native_settings", "ki_mcp_servers"]);
  for (const entry of data[KI_POLICY_CATALOG] || []) if (entry?.family === "mcp") kiPolicyRegister(entry);
  const names = new Set([...Object.keys(pP), ...Ra.keys()]);
  for (const name of names) kiPolicyRegister(kiPolicyBrowserMeta(name));
  for (const spec of kiNativeSpecs) kiPolicyRegister({ ...kiPolicyLocalMeta(spec.name), description: spec.description });
  for (const tool of kiProductTools()) kiPolicyRegister(tool.kiPolicyMeta);
  if (typeof kiPtkMeta === "function") for (const name of ["ptk_check", "ptk_start_scan", "ptk_scan_status", "ptk_stop_scan", "ptk_get_findings", "ptk_export_report", "ptk_extend_scan"]) kiPolicyRegister(kiPtkMeta(name));
  if (typeof kiDastMeta === "function") for (const name of ["ptk_capture_requests", "ptk_list_requests", "ptk_prepare_dast", "ptk_run_dast", "ptk_dast_status", "ptk_stop_dast", "ptk_dast_findings", "ptk_dast_export"]) kiPolicyRegister(kiDastMeta(name));
  if (typeof kiAuthzMeta === "function") for (const name of ["ptk_list_accounts", "ptk_save_account", "ptk_verify_account", "ptk_prepare_access_test", "ptk_run_access_test", "ptk_access_status", "ptk_stop_access_test", "ptk_access_findings", "ptk_access_export"]) kiPolicyRegister(kiAuthzMeta(name));
  if (typeof KI_SECURITY_REGISTRY !== 'undefined') for (const spec of KI_SECURITY_REGISTRY) kiPolicyRegister(kiSecurityMeta(spec));
  const groups = [{ id: "browser", label: "Browser" }, { id: "local", label: "Local computer" }, { id: "mcp", label: "MCP servers" }, ...(typeof kiPtkMeta === "function" ? [{ id: "ptk", label: "Security testing" }] : [])];
  for (const [transport, list] of [["remote", data.ki_mcp_servers || []], ["local", data.ki_native_settings?.servers || []]]) for (const server of list) {
    const id = await kiPolicyServerGroup(server, transport);
    if (!groups.some(group => group.id === id)) groups.push({ id, label: server.label || server.url || server.command, parent: "mcp" });
  }
  const active = new Set(groups.map(group => group.id));
  return { policy: kiPolicyClean(data[KI_POLICY_KEY]), groups, tools: [...kiPolicyCatalog.values()].filter(meta => active.has(meta.group)) };
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes[KI_POLICY_KEY]) kiPolicyCache = kiPolicyClean(changes[KI_POLICY_KEY].newValue);
});
chrome.notifications?.onClicked?.addListener(id => {
  if (!id.startsWith("ki-policy:")) return;
  chrome.notifications.clear(id).catch(() => {});
  if (kiPolicyPending.has(id.slice("ki-policy:".length))) chrome.tabs.create({ url: chrome.runtime.getURL("providers/providers.html?section=tools") }).catch(() => {});
});
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== "KI_PERMISSIONS") return;
  if (sender.id !== chrome.runtime.id || sender.url?.split("?")[0] !== chrome.runtime.getURL("providers/providers.html")) { reply({ ok: false, error: "Open Tools & permissions to manage rules." }); return; }
  (async () => {
    try {
      if (message.op === "inventory") reply({ ok: true, result: await kiPolicyInventory() });
      else if (message.op === "pending") reply({ ok: true, result: [...kiPolicyPending.values()].map(({ finish, ...item }) => item) });
      else if (message.op === "decide") { const pending = kiPolicyPending.get(message.id); if (!pending) throw Error("This approval is no longer pending."); pending.finish(message.allow === true); reply({ ok: true }); }
      else if (message.op === "reset") { await kiPolicyWrite(() => chrome.storage.local.set({ [KI_POLICY_KEY]: { version: 1, groups: {}, tools: {} } })); reply({ ok: true }); }
      else if (message.op === "set") {
        if (!["groups", "tools"].includes(message.bucket) || typeof message.id !== "string" || message.id === "__proto__" || !kiPolicyModes.has(message.value)) throw Error("Invalid rule");
        await kiPolicyWrite(async () => {
          const policy = await kiPolicyLoad();
          if (message.value === "inherit") delete policy[message.bucket][message.id]; else policy[message.bucket][message.id] = message.value;
          await chrome.storage.local.set({ [KI_POLICY_KEY]: policy });
        }); reply({ ok: true });
      } else throw Error("Unknown permission operation");
    } catch (error) { reply({ ok: false, error: error.message }); }
  })(); return true;
});

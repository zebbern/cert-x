// User-authored task context. Credentials and chat transcripts remain in their existing stores.
var KI_CONTEXT_KEY = "ki_contexts", kiContextWrites = Promise.resolve(), kiContextTurns = new Map();
function kiContextBuiltins() {
  const base = (id, name, instructions, mcp, tools = {}) => ({ id, name, builtin: true, instructions, model: null, tools: { groups: { ptk: id === "bugbounty" }, tools }, mcp, permissions: { groups: {}, tools: {} } });
  return {
    default: base("default", "Default", "", null),
    research: base("research", "Research", "Compare relevant sources and preserve citations or source URLs. Distinguish directly observed evidence, inference, and uncertainty. Use the workspace's notes and pinned references when relevant; read them through available tools. Produce sourced, useful outputs and do not claim to have checked material you have not read.", [], { local_run_command: false }),
    coding: base("coding", "Coding", "Inspect the repository and relevant project instructions before making changes. Make targeted, maintainable edits; preserve unrelated work. Review the resulting diff and run checks relevant to the change. Report what changed, observed verification, and any remaining limitations. Use the working folder as a default, not as a filesystem sandbox.", []),
    bugbounty: base("bugbounty", "Bug bounty", "Follow the workspace's target, exclusion, account/role, and testing instructions. For a broad vulnerability request, map reachable routes and input types quickly; batch independent read-only checks and feed representative form/API requests into the scan before deepening one alert family. Use the scanners for breadth and depth while testing relevant classes without executable scanner checks directly. Track hypotheses separately from confirmed findings, preserve useful evidence, and verify reproducibility and impact. Never call a finding unauthenticated unless it was reproduced logged out; verify restoration after state-changing tests. Retain negative results where they narrow the investigation. Produce findings with concrete reproduction steps and evidence; do not treat a scanner result as independent confirmation.", []),
  };
}
function kiContextText(value, limit, label, required = false) {
  if (typeof value !== "string") { if (value == null && !required) return ""; throw Error(label + " must be text."); }
  const text = value.trim(); if ((required && !text) || text.length > limit) throw Error(label + (text ? " is too long." : " is required.")); return text;
}
function kiContextId(value) { return typeof value === "string" && /^[a-zA-Z0-9_-]{1,100}$/.test(value) && !["__proto__", "constructor", "prototype"].includes(value); }
function kiContextModel(value) {
  if (value == null) return null;
  return { connectionId: kiContextText(value.connectionId, 200, "Model connection", true), modelId: kiContextText(value.modelId, 300, "Model", true) };
}
function kiContextBuckets(value, permissions = false) {
  const result = { groups: {}, tools: {} };
  for (const bucket of ["groups", "tools"]) {
    if (value?.[bucket] != null && (typeof value[bucket] !== "object" || Array.isArray(value[bucket]))) throw Error("Invalid tool settings.");
    const entries = Object.entries(value?.[bucket] || {}); if (entries.length > 2048) throw Error("Too many tool settings.");
    for (const [key, item] of entries) {
      if (!key || key.length > 300 || ["__proto__", "constructor", "prototype"].includes(key)) throw Error("Invalid tool identifier.");
      if (permissions ? ["ask", "allow", "disabled"].includes(item) : typeof item === "boolean") result[bucket][key] = item;
      else if (item !== "inherit" && item != null) throw Error("Invalid tool setting.");
    }
  }
  return result;
}
function kiContextMcp(value) {
  if (value == null) return null;
  if (!Array.isArray(value) || value.length > 100 || value.some(id => typeof id !== "string" || !/^mcp:(local|remote):[a-f0-9]{64}$/.test(id))) throw Error("Invalid MCP connection selection.");
  return [...new Set(value)];
}
function kiContextAbsolute(value, label) {
  const path = kiContextText(value, 4096, label);
  if (path && (!/^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+|\/)/.test(path) || /[\x00-\x1f]/.test(path))) throw Error(label + " must be an absolute path.");
  return path;
}
function kiContextProfile(value, id) {
  if (!kiContextId(id)) throw Error("Invalid profile identifier.");
  const tools = kiContextBuckets(value?.tools);
  if (!Object.hasOwn(tools.groups, "ptk")) tools.groups.ptk = id === "bugbounty";
  return { id, name: kiContextText(value?.name, 80, "Profile name", true), builtin: Object.hasOwn(kiContextBuiltins(), id),
    instructions: kiContextText(value?.instructions, 12000, "Instructions"), model: kiContextModel(value?.model),
    tools, mcp: kiContextMcp(value?.mcp), permissions: kiContextBuckets(value?.permissions, true) };
}
function kiContextWorkspace(value, id) {
  if (!kiContextId(id)) throw Error("Invalid workspace identifier.");
  const pins = value?.pins || []; if (!Array.isArray(pins) || pins.length > 50) throw Error("A workspace supports up to 50 pinned references.");
  return { id, name: kiContextText(value?.name, 80, "Workspace name", true), profileId: value?.profileId || "default",
    folder: kiContextAbsolute(value?.folder, "Working folder"), notes: kiContextText(value?.notes, 20000, "Workspace notes"), model: kiContextModel(value?.model), dastScope: kiContextDastScope(value?.dastScope),
    tools: value?.tools == null ? null : kiContextBuckets(value.tools), mcp: value?.mcp === "all" ? "all" : kiContextMcp(value?.mcp),
    permissions: value?.permissions == null ? null : kiContextBuckets(value.permissions, true),
    pins: pins.map(pin => {
      if (pin?.kind === "file") { const path = kiContextAbsolute(pin.path, "Pinned file"); if (!path) throw Error("Pinned file is required."); return { kind: "file", path }; }
      if (pin?.kind === "page") { let url; try { url = new URL(pin.url); } catch { throw Error("Invalid pinned page URL."); }
        if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw Error("Pinned pages require an HTTP(S) URL without credentials.");
        return { kind: "page", url: url.href, title: kiContextText(pin.title, 500, "Page title") }; }
      throw Error("Invalid pinned reference.");
    }) };
}
function kiContextDastScope(value) {
  if (value == null) return { origins: [], excludePaths: [] };
  if (!Array.isArray(value.origins) || !Array.isArray(value.excludePaths)) throw Error("Testing scope requires origin and excluded-path lists.");
  if (value.matchMode != null && !["origin", "host"].includes(value.matchMode)) throw Error("Choose exact origins or same host for target scope.");
  if (value.includeSubdomains != null && typeof value.includeSubdomains !== "boolean") throw Error("Subdomain selection must be on or off.");
  if (value.includeSubdomains && value.matchMode !== "host") throw Error("Select same-host matching before including subdomains.");
  const origins = value.origins.map(value => {
    let url; try { url = new URL(value); } catch { throw Error("Use exact HTTP(S) origins for DAST scope."); }
    if (typeof value !== "string" || !["http:", "https:"].includes(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash || url.hostname.includes("*")) throw Error("DAST origins must include only scheme, hostname and optional port.");
    return url.origin;
  });
  const excludePaths = value.excludePaths.map(value => {
    if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.length > 2048 || /[\\%?#\s\x00-\x1f]/.test(value) || value.split("/").some(segment => segment === "." || segment === "..")) throw Error("DAST exclusions must be literal absolute paths without escapes, queries or dot segments.");
    return value.length > 1 ? value.replace(/\/+$/, "") : value;
  });
  return { origins: [...new Set(origins)], excludePaths: [...new Set(excludePaths)], ...(value.matchMode === "host" ? { matchMode: "host", ...(value.includeSubdomains ? { includeSubdomains: true } : {}) } : {}) };
}
async function kiContextLoad() {
  const stored = await chrome.storage.local.get([KI_CONTEXT_KEY, "sidepanel_session_models"]), raw = stored[KI_CONTEXT_KEY];
  if (raw?.version != null && raw.version !== 1) throw Error("This workspace configuration needs a newer cert-x version.");
  const state = { version: 1, profiles: kiContextBuiltins(), workspaces: {}, chats: {}, legacyModels: stored.sidepanel_session_models || {} };
  // Ignore individual malformed legacy records, without rewriting the stored source on read.
  for (const [id, value] of Object.entries(raw?.profiles || {})) try { state.profiles[id] = kiContextProfile(value, id); } catch {}
  for (const [id, value] of Object.entries(raw?.workspaces || {})) try { const record = kiContextWorkspace(value, id); if (!Object.hasOwn(state.profiles, record.profileId)) record.profileId = "default"; state.workspaces[id] = record; } catch {}
  for (const [id, value] of Object.entries(raw?.chats || {})) if (kiContextId(id) && value && typeof value === "object") {
    let modelExplicit = null; try { modelExplicit = kiContextModel(value.modelExplicit); } catch {}
    state.chats[id] = { workspaceId: Object.hasOwn(state.workspaces, value.workspaceId) ? value.workspaceId : null,
      profileId: Object.hasOwn(state.profiles, value.profileId) ? value.profileId : null, ...(Object.hasOwn(value, "modelExplicit") ? { modelExplicit } : {}) };
  }
  return state;
}
function kiContextOwner(session) { return typeof kiWorkspaceOwner === "function" ? kiWorkspaceOwner(session) : session; }
function kiContextMergeBuckets(base, extra) { return { groups: { ...base.groups, ...extra?.groups }, tools: { ...base.tools, ...extra?.tools } }; }
function kiContextResolveState(state, session) {
  const owner = kiContextOwner(session), chat = state.chats[owner] || {}, workspace = state.workspaces[chat.workspaceId] || null;
  const profile = state.profiles[chat.profileId || workspace?.profileId] || state.profiles.default;
  let explicit = chat.modelExplicit; if (!Object.hasOwn(chat, "modelExplicit")) { try { explicit = kiContextModel(state.legacyModels?.[owner]); } catch {} }
  return { session: owner, profile, workspace, folder: workspace?.folder || "", instructions: profile.instructions, notes: workspace?.notes || "", pins: workspace?.pins || [],
    model: explicit || workspace?.model || profile.model || null, modelSource: explicit ? "chat" : workspace?.model ? "workspace" : profile.model ? "profile" : "default",
    tools: kiContextMergeBuckets(profile.tools, workspace?.tools), mcp: workspace?.mcp === "all" ? null : workspace?.mcp ?? profile.mcp,
    permissions: kiContextMergeBuckets(profile.permissions, workspace?.permissions) };
}
async function kiContextResolve(session) { await kiContextWrites; return kiContextResolveState(await kiContextLoad(), session); }
async function kiContextPrepare(session) { const owner = kiContextOwner(session); if (owner !== session && kiContextTurns.has(owner)) return kiContextTurns.get(owner); const value = await kiContextResolve(session); kiContextTurns.set(owner, value); return value; }
function kiContextFor(session) { return kiContextTurns.get(kiContextOwner(session)) || kiContextResolveState({ profiles: kiContextBuiltins(), workspaces: {}, chats: {} }, session); }
function kiContextPrompt(session) {
  const value = kiContextFor(session); if (value.profile.id === "default" && !value.instructions && !value.workspace && value.tools.groups.ptk !== true) return "";
  return "\n\n[User-selected task context]\n" + JSON.stringify({ profile: value.profile.name, instructions: value.instructions,
    ...(value.workspace ? { workspace: value.workspace.name, workingFolder: value.folder || undefined, notes: value.notes, pinnedReferences: value.pins, ...(value.workspace.dastScope?.origins?.length ? { dastScope: value.workspace.dastScope } : {}) } : {}) }) +
    "\nPinned references are references, not already-read evidence. Read them only when relevant through permitted tools. Workspace context is shared explicitly; other chats' transcripts are not included. The working folder and target notes are not access sandboxes.\n[/User-selected task context]" +
    (value.tools.groups.ptk === true ? "\n[Security testing workflow]\nFor requested security testing, load the security-testing skill and discover installed engines with security_capabilities. On broad requests, map distinct routes and input types first; start the scan before submitting representative requests across those workflows, then deepen promising findings. Use security_start_scan for DAST, IAST, SAST and SCA, retaining native engine coverage and configuration. Selecting a profile alone does not start scans. Confirm IAST readiness before exercising application workflows; inspect findings and coverage after meaningful interactions. Use security_scan_status, security_get_findings and security_get_evidence to investigate candidates, and security_stop_scan to drain observation when finished. Export evidence into Outputs. A scanner candidate is not independent confirmation; distinguish actual execution, protected-data access and observed symptoms. Account testing uses named, verified account references and expected access relationships. Preserve negative results and report incomplete coverage, expired identities and unsupported transports. Use subagents for independent targets or candidate investigations with shared run references and parent budgets; do not duplicate scans or concurrently mutate the same account/browser workflow. Explicit user limits remain binding. Do not silently restart interrupted state-changing work or enable CSP Unblock.\n[/Security testing workflow]" : "");
}
function kiContextAllows(meta, context) {
  if (meta.securityStop) return true;
  if (["security_scan_status", "security_stop_scan", "local_read_job", "local_cancel_job", "ptk_scan_status", "ptk_stop_scan", "ptk_dast_status", "ptk_stop_dast", "ptk_access_status", "ptk_stop_access_test", "get_capabilities"].includes(meta.name)) return true;
  if (meta.family === "mcp" && context.mcp !== null && !context.mcp.includes(meta.group)) return false;
  const tools = context.tools;
  if ((meta.parentGroups || []).some(group => tools.groups[group] === false)) return false;
  if ((meta.aliases || []).some(id => tools.tools[id] === false || tools.tools[id.replace(/^ptk:/, "")] === false)) return false;
  return tools.tools[meta.id] ?? tools.tools[meta.name] ?? tools.groups[meta.group] ?? tools.groups[meta.family] ?? true;
}
function kiContextRule(meta, context, globalRule) {
  if (meta.securityStop) return "allow";
  if (globalRule === "disabled" || !kiContextAllows(meta, context)) return "disabled";
  // Job control remains available after deselection; only explicit global rules constrain it.
  if (["local_read_job", "local_cancel_job", "ptk_scan_status", "ptk_stop_scan", "ptk_dast_status", "ptk_stop_dast", "ptk_access_status", "ptk_stop_access_test"].includes(meta.name)) return globalRule;
  const policy = context.permissions;
  const parentRules = (meta.parentGroups || []).map(group => policy.groups[group]).filter(Boolean);
  const aliasRules = (meta.aliases || []).map(id => policy.tools[id] || policy.tools[id.replace(/^ptk:/, "")]).filter(Boolean);
  const directRule = policy.tools[meta.id] || policy.tools[meta.name] || policy.groups[meta.group] || policy.groups[meta.family] || "inherit";
  const rule = [directRule, ...aliasRules, ...parentRules].includes("disabled") ? "disabled" : [directRule, ...aliasRules, ...parentRules].includes("ask") ? "ask" : directRule;
  if (rule === "disabled") return "disabled";
  if (globalRule === "ask") return "ask";
  return rule === "inherit" ? globalRule : rule;
}
function kiContextArgs(name, args, session) {
  const result = JSON.parse(JSON.stringify(args || {}));
  if (name === "local_run_command" && result.cwd == null) { const folder = kiContextFor(session).folder; if (folder) result.cwd = folder; }
  return result;
}
async function kiContextServerSelected(server, transport, session) {
  if (session == null) return true; // Explicit settings discovery tests all configured connections.
  const context = kiContextFor(session); const group = await kiPolicyServerGroup(server, transport);
  const meta = { id: group, name: "", family: "mcp", group, transport };
  const selected = value => {
    if (value.mcp !== null && !value.mcp.includes(group)) return false;
    if (kiContextAllows(meta, value)) return true;
    // A server must be discovered to expose an individually enabled tool even
    // when its family/server availability default is off. Names alone cannot
    // identify a server; only its stable, namespaced tool IDs qualify here.
    return Object.entries(value.tools.tools).some(([id, enabled]) => enabled === true && id.startsWith(group + ":"));
  };
  return selected(context) && selected(await kiContextResolve(session));
}
async function kiContextMutation(message) {
  const state = await kiContextLoad();
  if (message.op === "save_profile") {
    const id = message.profile?.id || crypto.randomUUID(); const value = kiContextProfile(message.profile, id); state.profiles[id] = value;
  } else if (message.op === "duplicate_profile") {
    const original = state.profiles[message.id]; if (!original) throw Error("Profile not found.");
    const id = crypto.randomUUID(); state.profiles[id] = { ...original, id, builtin: false, name: (original.name.slice(0, 70) + " copy") };
  } else if (message.op === "reset_profile") {
    const original = kiContextBuiltins()[message.id]; if (!original) throw Error("Only built-in profiles can be reset."); state.profiles[message.id] = original;
  } else if (message.op === "delete_profile") {
    if (!Object.hasOwn(state.profiles, message.id) || state.profiles[message.id].builtin) throw Error("Only custom profiles can be deleted.");
    delete state.profiles[message.id];
    for (const workspace of Object.values(state.workspaces)) if (workspace.profileId === message.id) workspace.profileId = "default";
    for (const chat of Object.values(state.chats)) if (chat.profileId === message.id) chat.profileId = null;
  } else if (message.op === "save_workspace") {
    const id = message.workspace?.id || crypto.randomUUID(), value = kiContextWorkspace(message.workspace, id);
    if (!Object.hasOwn(state.profiles, value.profileId)) throw Error("Profile not found."); state.workspaces[id] = value;
  } else if (message.op === "delete_workspace") {
    if (!Object.hasOwn(state.workspaces, message.id)) throw Error("Workspace not found."); delete state.workspaces[message.id];
    for (const chat of Object.values(state.chats)) if (chat.workspaceId === message.id) chat.workspaceId = null;
  } else if (message.op === "initialize_chat") {
    if (!kiContextId(message.session) || (message.previousSession != null && !kiContextId(message.previousSession))) throw Error("Invalid chat identifier.");
    // Initialization and picker writes share the same queue. Never overwrite a
    // choice made while another sidepanel/new-chat initialization was awaiting IO.
    if (Object.hasOwn(state.chats, message.session)) return state;
    let legacyModel = null; try { legacyModel = kiContextModel(state.legacyModels?.[message.session]); } catch {}
    state.chats[message.session] = { workspaceId: legacyModel ? null : state.chats[message.previousSession]?.workspaceId || null,
      profileId: null, modelExplicit: legacyModel };
  } else if (message.op === "assign_chat") {
    if (!kiContextId(message.session)) throw Error("Invalid chat identifier.");
    let legacyModel = null; try { legacyModel = kiContextModel(state.legacyModels?.[message.session]); } catch {}
    const value = { workspaceId: null, profileId: null, modelExplicit: legacyModel, ...state.chats[message.session] };
    for (const [field, records] of [["workspaceId", state.workspaces], ["profileId", state.profiles]]) if (Object.hasOwn(message, field)) {
      if (message[field] != null && !Object.hasOwn(records, message[field])) throw Error(field === "workspaceId" ? "Workspace not found." : "Profile not found."); value[field] = message[field] || null;
    }
    if (Object.hasOwn(message, "modelExplicit")) value.modelExplicit = kiContextModel(message.modelExplicit);
    state.chats[message.session] = value;
  } else throw Error("Unknown profile/workspace operation.");
  const { legacyModels, ...persisted } = state; await chrome.storage.local.set({ [KI_CONTEXT_KEY]: persisted }); return state;
}
function kiContextPublicState(state) { return { version: 1, profiles: Object.values(state.profiles), workspaces: Object.values(state.workspaces), chats: state.chats }; }
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== "KI_CONTEXT") return;
  const trusted = ["providers/providers.html", "pages/sidepanel.html"].map(path => chrome.runtime.getURL(path));
  if (sender.id !== chrome.runtime.id || !trusted.includes(sender.url?.split("?")[0])) { reply({ ok: false, error: "Open cert-x to manage profiles and workspaces." }); return; }
  (async () => {
    try {
      let result;
      // A read requested after a mutation must observe that mutation's result,
      // even if Chrome's storage write or a preceding queued update is pending.
      if (["state", "effective", "models"].includes(message.op)) await kiContextWrites;
      if (message.op === "state") result = kiContextPublicState(await kiContextLoad());
      else if (message.op === "models") { const catalog = await pu(); result = catalog.models.map(model => ({ connectionId: model.connectionId, modelId: model.modelId, label: model.label || model.name || model.modelId })); }
      else if (message.op === "effective") result = await kiContextResolve(message.session);
      else { const task = kiContextWrites.then(() => kiContextMutation(message)); kiContextWrites = task.catch(() => {}); result = kiContextPublicState(await task); }
      reply({ ok: true, result });
    } catch (error) { reply({ ok: false, error: error.message }); }
  })(); return true;
});

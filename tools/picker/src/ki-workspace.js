var KI_OUTPUTS_KEY = "ki_task_outputs", KI_JOBS_KEY = "ki_command_jobs", kiWorkspaceWrites = Promise.resolve(), kiWorkspaceParents = new Map();
function kiWorkspaceOwner(session) {
  return kiWorkspaceParents.get(session) || session || "browser-control";
}
function kiWorkspaceWrite(operation) { const task = kiWorkspaceWrites.then(operation); kiWorkspaceWrites = task.catch(() => {}); return task; }
async function kiWorkspaceOutput(session, item) {
  return kiWorkspaceWrite(async () => {
    const stored = (await chrome.storage.local.get(KI_OUTPUTS_KEY))[KI_OUTPUTS_KEY] || [];
    const owner = kiWorkspaceOwner(session), previous = stored.find(old => old.owner === owner && ((item.path && old.path === item.path) || (item.downloadId && old.downloadId === item.downloadId)));
    if (item.jobId && previous?.jobId === item.jobId && previous.size === item.size) return previous;
    const record = { id: previous?.id || crypto.randomUUID(), owner, at: Date.now(), ...item };
    const next = stored.filter(old => !(old.owner === owner && ((item.path && old.path === item.path) || (item.downloadId && old.downloadId === item.downloadId))));
    next.push(record);
    // Bound retained previews separately from lightweight file references.
    let bytes = 0; const keep = [];
    for (const entry of next.reverse()) {
      const size = entry.data?.length || 0;
      if (keep.length < 100 && bytes + size <= 12 * 1024 * 1024) { keep.push(entry); bytes += size; }
    }
    await chrome.storage.local.set({ [KI_OUTPUTS_KEY]: keep.reverse() });
    return record;
  });
}
function kiWorkspaceName(path) { return String(path).split(/[\\/]/).pop() || "Output"; }
async function kiWorkspaceJob(result) {
  if (!result?.jobId) return;
  const { chunks, command, ...metadata } = result;
  const completed = await kiWorkspaceWrite(async () => {
    const stored = (await chrome.storage.local.get(KI_JOBS_KEY))[KI_JOBS_KEY] || [];
    const previous = stored.find(job => job.jobId === result.jobId);
    if (["completed", "failed", "cancelled", "timed_out"].includes(previous?.state) && ["running", "cancelling"].includes(result.state)) return;
    const next = stored.filter(job => job.jobId !== result.jobId);
    next.push({ ...metadata, command: String(command || "").slice(0, 180) });
    await chrome.storage.local.set({ [KI_JOBS_KEY]: next.slice(-64) });
    return ["completed", "failed", "cancelled", "timed_out"].includes(result.state) && !["completed", "failed", "cancelled", "timed_out"].includes(previous?.state);
  });
  for (const output of result.outputs || []) await kiWorkspaceOutput(result.owner, { path: output.path, name: kiWorkspaceName(output.path), size: output.size, kind: "file", jobId: result.jobId });
  if (completed && typeof UI === "object" && typeof Q === "function") {
    const conversation = UI.get(result.owner);
    if (conversation) Q(conversation, { type: "notice", id: crypto.randomUUID(), level: ["failed", "timed_out"].includes(result.state) ? "error" : "info", text: "Background command " + result.state.replaceAll("_", " ") + "." });
  }
}
async function kiWorkspaceHostLost() {
  await kiWorkspaceWrite(async () => {
    const stored = (await chrome.storage.local.get(KI_JOBS_KEY))[KI_JOBS_KEY] || [];
    await chrome.storage.local.set({ [KI_JOBS_KEY]: stored.map(job => ["running", "cancelling"].includes(job.state) ? { ...job, state: "interrupted", error: "Native host disconnected." } : job) });
  });
}
async function kiWorkspaceCapture(meta, args, result, session) {
  if (!["local", "browser"].includes(meta.family)) return;
  let data = result;
  if (typeof result?.output === "string") { try { data = JSON.parse(result.output); } catch { data = null; } }
  if (meta.family === "local" && data?.jobId) await kiWorkspaceJob(data);
  if (meta.name === "local_write_file" && data?.path) await kiWorkspaceOutput(session, { name: kiWorkspaceName(data.path), path: data.path, size: data.bytesWritten, kind: "file" });
  if (meta.name === "local_run_command" && !data?.jobId) for (const output of data?.outputs || []) await kiWorkspaceOutput(session, { name: kiWorkspaceName(output.path), path: output.path, size: output.size, kind: "file" });
  if (["save_file", "save_as_pdf"].includes(meta.name) && Number.isInteger(data?.downloadId)) await kiWorkspaceOutput(session, { name: kiWorkspaceName(args.filename || args.file_name || data.filename), path: data.filename, downloadId: data.downloadId, kind: "file" });
  if (meta.name === "screenshot" || meta.name === "cdp" && args?.method === "Page.captureScreenshot") {
    const part = Array.isArray(result?.output) ? result.output.find(part => part.type === "image_url") : null;
    const url = part?.imageUrl?.url || part?.image_url?.url;
    if (typeof url === "string" && /^data:image\/(png|jpeg|webp|gif);base64,/.test(url) && url.length <= 2 * 1024 * 1024) await kiWorkspaceOutput(session, { name: "Screenshot." + url.split(";")[0].split("/")[1], kind: "image", data: url.split(",")[1], encoding: "base64", mime: url.slice(5, url.indexOf(";")) });
  }
  if (meta.name === "download" && data?.body && !data.truncated && data.body.length <= 2 * 1024 * 1024) {
    const name = (() => { try { return decodeURIComponent(new URL(data.url).pathname.split("/").pop()) || "download"; } catch { return "download"; } })();
    await kiWorkspaceOutput(session, { name, kind: "download", data: data.body, encoding: data.encoding, mime: data.mimeType });
  }
}
async function kiWorkspaceHealth(query = "", profile = "main", session) {
  const taskContext = session && typeof kiContextResolve === "function" ? await kiContextResolve(session) : null;
  const owner = session ? kiWorkspaceOwner(session) : null;
  const scopedWorkspace = !!taskContext?.workspace?.dastScope?.origins?.length;
  const targetedOwned = typeof kiDastBatches !== "undefined" && kiDastBatches.some(run => run.owner === owner);
  const accountOwned = typeof kiAuthzBatches !== "undefined" && kiAuthzBatches.some(run => run.owner === owner);
  const localSecurityTools = new Set(["security_browser","security_raw","security_oast","security_zap"]);
  const targetedTools = new Set(["security_capture_requests","security_list_targeted_requests","security_prepare_targeted_test","security_run_targeted_test","security_targeted_status","security_stop_targeted_test","security_targeted_findings","security_targeted_export"]);
  const accountTools = new Set(["security_list_accounts","security_save_account","security_verify_account","security_prepare_access_test","security_run_access_test","security_access_status","security_stop_access_test","security_access_findings","security_access_export"]);
  const securitySelected = !taskContext || taskContext.tools.groups.ptk === true || Object.entries(taskContext.tools.tools || {}).some(([name, enabled]) => enabled === true && (name.startsWith("ptk:") || name.startsWith("security_")));
  const ptk = securitySelected && typeof kiPtkHealth === "function" ? kiPtkHealth(session) : undefined;
  const data = await chrome.storage.local.get(["ki_native_settings", "ki_mcp_servers", "sidepanel_connections", "sidepanel_approval_mode", KI_POLICY_KEY]);
  let host;
  try {
    const result = await kiNativeRpc("status", {}, undefined, 5000);
    host = { state: "connected", version: result.version, revision: result.revision || 1, platform: result.platform, node: result.node, jobs: result.features?.includes("command_jobs") === true, updateNeeded: !result.features?.includes("command_jobs") };
  } catch (error) { host = { state: "unavailable", error: error.message }; }
  const policy = kiPolicyClean(data[KI_POLICY_KEY]), inventory = await kiPolicyInventory();
  const configuredMcp = taskContext ? (await Promise.all([["remote", data.ki_mcp_servers || []], ["local", data.ki_native_settings?.servers || []]].flatMap(([transport, servers]) => servers.map(async server => ({ id: await kiPolicyServerGroup(server, transport), label: server.label || (transport === "local" ? server.command : new URL(server.url).host), transport }))))).filter(server => taskContext.mcp === null || taskContext.mcp.includes(server.id)) : [];
  const discovered = [...kiMcpCache.tools, ...kiNativeCache.tools];
  const tools = inventory.tools.map(tool => {
    const live = discovered.find(entry => entry.kiPolicyMeta?.id === tool.id);
    const parentEnabled = ![tool.family, tool.transport].includes("local") || data.ki_native_settings?.enabled === true;
    const globalRule = kiPolicyRule(tool, policy), rule = taskContext ? kiContextRule(tool, taskContext, globalRule) : globalRule;
    const reasons = [];
    if (!parentEnabled) reasons.push("Local computer access is disabled.");
    if (globalRule === "disabled") reasons.push("Disabled in Tools & permissions.");
    if (taskContext && !kiContextAllows(tool, taskContext)) reasons.push("Not selected by this profile or workspace.");
    else if (rule === "disabled" && globalRule !== "disabled") reasons.push("Disabled by profile or workspace permissions.");
    if (tool.family === "mcp" && !live) reasons.push("This MCP tool has not been discovered in the current worker.");
    if ([tool.family, tool.transport].includes("local") && host.state !== "connected") reasons.push("Native host is unavailable.");
    if (["local_read_job", "local_cancel_job"].includes(tool.name) && !host.jobs) reasons.push("Native host needs an update for command jobs.");
    if (localSecurityTools.has(tool.name) && data.ki_native_settings?.enabled !== true) reasons.push("Local computer access is disabled.");
    if (targetedTools.has(tool.name) && !scopedWorkspace && !targetedOwned) reasons.push("Selected-request testing needs target origins in a workspace.");
    if (accountTools.has(tool.name) && !scopedWorkspace && !accountOwned) reasons.push("Account comparison needs target origins in a workspace.");
    return { reasons, name: tool.name, callName: live?.name || tool.name, group: tool.groupLabel || tool.family, rule, parentEnabled,
      available: parentEnabled && rule !== "disabled" && reasons.length === 0 };
  }).filter(tool => (profile === "main" || tool.name !== "agent") && (!query || [tool.name, tool.callName].some(name => name.toLowerCase().includes(query.toLowerCase()))));
  const securityMeta = inventory.tools.find(tool => tool.name === "security_capabilities");
  const securityRule = securityMeta ? taskContext ? kiContextRule(securityMeta, taskContext, kiPolicyRule(securityMeta, policy)) : kiPolicyRule(securityMeta, policy) : "disabled";
  const selectedSecurityTool = query && /^security_|^ptk_/.test(query) ? tools.find(tool => tool.name === query || tool.callName === query) : null;
  const securityAvailable = securitySelected && securityRule !== "disabled" && (selectedSecurityTool?.available ?? true);
  const security = { available: securityAvailable, selected: securitySelected,
    ...(securityAvailable ? { discoveryTool: "security_capabilities" } : { reason: !securitySelected ? "Security tools are not selected by this profile or workspace." : selectedSecurityTool?.reasons.join(" ") || "Security tools are disabled in Tools & permissions." }) };
  return { ...(ptk ? { ptk } : {}), ...(security ? { security } : {}), ...(taskContext ? { task: { profile: { id: taskContext.profile.id, name: taskContext.profile.name }, workspace: taskContext.workspace ? { id: taskContext.workspace.id, name: taskContext.workspace.name } : null, folder: taskContext.folder, selectedMcp: taskContext.mcp, connections: configuredMcp, missingMcp: (taskContext.mcp || []).filter(id => !configuredMcp.some(server => server.id === id)), modelSource: taskContext.modelSource } } : {}), checkedAt: Date.now(), extensionVersion: chrome.runtime.getManifest().version,
    modelProviders: { configured: (data.sidepanel_connections || []).length, scope: "Custom providers only; built-in account models are not counted." },
    local: { enabled: data.ki_native_settings?.enabled === true, host },
    browserControl: await XB.snapshot(),
    mcp: { remoteConfigured: (data.ki_mcp_servers || []).length, localConfigured: (data.ki_native_settings?.servers || []).length,
      discoveredTools: discovered.length, discoveryErrors: [...kiMcpCache.errors, ...kiNativeCache.errors].map(item => ({ label: item.label, error: item.error })), note: "Discovery reflects this worker's most recent agent turn; configured does not mean connected." },
    permissions: { mode: data.sidepanel_approval_mode || "approve_for_me", overrides: Object.keys(policy.groups).length + Object.keys(policy.tools).length,
      toolCount: tools.length, truncated: tools.length > 200, tools: tools.slice(0, 200) } };
}
function kiWorkspaceAgentHealth(value, query, detail) {
  if (query || detail === "full") return value;
  const { tools, ...permissions } = value.permissions;
  return { ...value, permissions: { ...permissions,
    availableTools:tools.filter(tool => tool.available).map(tool => tool.callName),
    unavailableCount:tools.filter(tool => !tool.available).length,
    details:'Use get_capabilities({tool:"tool_name"}) for a tool’s availability and reasons, or detail:"full" for the full inventory.' } };
}
function kiProductTools(profile = "main", session) {
  return [{ name: "get_capabilities", description: "Read extension setup, host compatibility, MCP discovery and tool rules. Optional tool filter matches an original or generated tool name. Use to diagnose missing tools instead of guessing. Does not connect Browser control or run MCP tools. Model providers are reported as configured, not credential-tested.", parameters: { type: "object", properties: { tool: { type: "string" }, detail: { type:"string", enum:["summary","full"], description:"Default summary lists available tool names; full includes all tool rules." } } },
    kiPolicyMeta: { ...kiPolicyBrowserMeta("get_capabilities"), label: "Check capabilities", defaultAsk: false }, resolveExecution(args) { return { approvalRule: "allow", async execute() { const query=typeof args?.tool === "string" ? args.tool : ""; return { output: JSON.stringify(kiWorkspaceAgentHealth(await kiWorkspaceHealth(query, profile, session),query,args?.detail)) }; } }; } }];
}
async function kiWorkspaceJobs() {
  const observedAt = Date.now();
  let current = [], available = false, error = "";
  const enabled = (await kiNativeSettings()).enabled;
  if (enabled) try { current = await kiNativeRpc("job_list", { all: true }); available = true; } catch (failure) { error = failure.message; }
  for (const job of current) await kiWorkspaceJob(job);
  const stored = await kiWorkspaceWrite(async () => {
    const records = (await chrome.storage.local.get(KI_JOBS_KEY))[KI_JOBS_KEY] || [];
    const updated = records.map(job => job.startedAt < observedAt - 2000 && !current.some(active => active.jobId === job.jobId) && ["running", "cancelling"].includes(job.state) ? { ...job, state: "interrupted", error: "Native host disconnected or restarted." } : job);
    await chrome.storage.local.set({ [KI_JOBS_KEY]: updated }); return updated;
  });
  return { jobs: stored, available, error: enabled ? error : "Local access is disabled." };
}
async function kiWorkspaceReadOutput(id) {
  const item = ((await chrome.storage.local.get(KI_OUTPUTS_KEY))[KI_OUTPUTS_KEY] || []).find(item => item.id === id);
  if (!item) throw Error("Output is no longer in the tray.");
  if (item.data !== undefined) return { name: item.name, content: item.data, encoding: item.encoding, mime: item.mime || "application/octet-stream" };
  if (!(await kiNativeSettings()).enabled) throw Error("Enable Local computer to preview this file, or open it directly.");
  let path = item.path;
  if (item.downloadId) { const found = (await chrome.downloads.search({ id: item.downloadId }))[0]; if (found?.state !== "complete") throw Error("Download has not completed."); path = found.filename; }
  let offset = 0, content = "", size;
  // Base64 chunks must be concatenated as bytes, not encoded strings.
  const buffers = [];
  do {
    if (!(await kiNativeSettings()).enabled) throw Error("Local access was disabled while reading the output.");
    const part = await kiNativeRpc("read_file", { path, offset, max_bytes: 131072, encoding: "base64" });
    size = part.size; if (size > 8 * 1024 * 1024) throw Error("This file exceeds the 8 MiB preview/attachment limit. Open it directly.");
    buffers.push(atob(part.content)); offset = part.nextOffset;
    if (!part.truncated) break;
    if (!part.bytesRead) throw Error("File changed while being read. Try again.");
  } while (offset < size);
  content = btoa(buffers.join(""));
  const extension = item.name.split(".").pop().toLowerCase();
  const mime = ({ png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp", gif: "image/gif", pdf: "application/pdf" })[extension] || (/^(txt|md|json|csv|log|js|ts|py|ps1|html|css|xml|yaml|yml)$/.test(extension) ? "text/plain" : "application/octet-stream");
  return { name: item.name, encoding: "base64", content, mime };
}
async function kiWorkspaceSavePdf(data, name) {
  const filename = kiWorkspaceName(name || "page.pdf").replace(/[<>:"|?*\x00-\x1f]/g, "_");
  return new kiSaveFileTool().execute({ filename: /\.pdf$/i.test(filename) ? filename : filename + ".pdf", content: data, encoding: "base64" });
}
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== "KI_WORKSPACE") return;
  const path = sender.url?.split("?")[0], allowed = ["providers/providers.html", "pages/sidepanel.html"].map(path => chrome.runtime.getURL(path));
  if (sender.id !== chrome.runtime.id || !allowed.includes(path)) { reply({ ok: false, error: "Open cert-x to use this feature." }); return; }
  (async () => {
    try {
      let result;
      if (message.op === "health") result = await kiWorkspaceHealth("", "main", message.session);
      else if (message.op === "outputs") {
        const contextState = message.workspaceId && typeof kiContextLoad === "function" ? await kiContextLoad() : null;
        if (message.workspaceId && !contextState?.workspaces[message.workspaceId]) throw Error("Workspace not found.");
        result = ((await chrome.storage.local.get(KI_OUTPUTS_KEY))[KI_OUTPUTS_KEY] || []).filter(item => message.workspaceId ? contextState.chats[item.owner]?.workspaceId === message.workspaceId : !message.session || item.owner === kiWorkspaceOwner(message.session)).map(({ data, ...item }) => item);
        if (message.workspaceId && typeof QL === "function") {
          const titles = new Map(await Promise.all([...new Set(result.map(item => item.owner))].slice(0, 100).map(async owner => [owner, await QL(owner).catch(() => undefined)])));
          result = result.map(item => ({ ...item, chatTitle: titles.get(item.owner) || item.owner }));
        }
      }
      else if (message.op === "output_read") result = await kiWorkspaceReadOutput(message.id);
      else if (message.op === "jobs") result = await kiWorkspaceJobs();
      else if (["job_read", "job_cancel"].includes(message.op)) {
        if (!(await kiNativeSettings()).enabled) throw Error("Local access is disabled.");
        const job = (await kiNativeRpc("job_list", { all: true })).find(job => job.jobId === message.id);
        if (!job) throw Error("Job output is no longer available; the host may have restarted.");
        result = await kiNativeRpc(message.op, { job_id: job.jobId, owner: job.owner, cursor: message.cursor }); await kiWorkspaceJob(result);
      } else throw Error("Unknown workspace operation");
      reply({ ok: true, result });
    } catch (error) { reply({ ok: false, error: error.message }); }
  })(); return true;
});

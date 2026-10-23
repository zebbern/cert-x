// Local-computer capabilities use a dedicated native port, never a page relay.
var KI_NATIVE_HOST = "com.cert_x.host", KI_NATIVE_KEY = "ki_native_settings";
var kiNativePort = null, kiNativePending = new Map(), kiNativeSequence = 0;
var kiNativeCache = { enabled: false, tools: [], errors: [] }, kiNativeGeneration = 0;
var kiNativeSecurityLeases = new Map();
var KI_NATIVE_SECURITY_GRANT = Symbol('Local security run approval');
var kiNativeSecuritySetupActive = false;

function kiNativeSecurityRelease(lease) {
  const entry = kiNativeSecurityLeases.get(lease); if (!entry) return;
  entry.context.signal?.removeEventListener('abort', entry.abort); kiNativeSecurityLeases.delete(lease);
}
function kiNativeSecurityLost(reason) {
  const contexts = [...kiNativeSecurityLeases.values()];
  for (const entry of contexts) kiNativeSecurityRelease(entry.lease);
  if (contexts.length) Promise.resolve(globalThis.certXSecurity?.localLost?.(reason)).catch(() => {});
}
async function kiNativeSecurityMessage(message, port) {
  if (kiNativePort !== port) return;
  if (message.event === 'security_event') {
    const value = message.result || {}, lease = value.leaseId || value.lease;
    if (kiNativeSecuritySetupActive && /^setup_(?:progress|complete|failed)$/.test(value.type || '')) {
      void chrome.runtime.sendMessage({ type: 'KI_SECURITY_SETUP_PROGRESS', progress: { type: value.type, phase: value.phase, bytes: value.bytes, total: value.total, error: value.error } }).catch(() => {}); return;
    }
    const entry = lease ? kiNativeSecurityLeases.get(lease) : [...kiNativeSecurityLeases.values()].find(item => item.context.owner === value.owner && item.context.runId === value.runId);
    if (!entry || entry.port !== port || entry.context.owner !== value.owner || entry.context.runId !== value.runId) return;
    if (value.type === 'lease_released') kiNativeSecurityRelease(entry.lease);
    await globalThis.certXSecurity?.localEvent?.(value); return;
  }
  if (message.event !== 'security_admission' || typeof message.requestId !== 'string') return;
  const entry = kiNativeSecurityLeases.get(message.lease); let allow = false, error;
  try {
    if (!entry || entry.port !== port || entry.context.owner !== message.owner || entry.context.runId !== message.runId) throw Error('Local execution lease is no longer active.');
    if (!message.request || typeof message.request !== 'object' || Array.isArray(message.request)) throw Error('Invalid local request admission.');
    const cleanup = entry.cleanupOnly && message.request.kind === 'control';
    if (!cleanup) await kiNativeSecurityRecheck(entry.context);
    if (message.request.backend === 'oast' && !cleanup) { if (typeof entry.context.providerRecheck !== 'function') throw Error('Callback provider admission is unavailable.'); await entry.context.providerRecheck(message.request); }
    await entry.context.checkRequest(message.request);
    if (!cleanup) await kiNativeSecurityRecheck(entry.context);
    if (kiNativePort !== port || !kiNativeSecurityLeases.has(entry.lease)) throw Error('Local execution was cancelled before dispatch.');
    allow = true;
  } catch (failure) { error = failure.message || String(failure); }
  if (kiNativePort === port) port.postMessage({ id: 'admission-' + (++kiNativeSequence), op: 'security_admission_result', params: { requestId: message.requestId, allow, ...(error ? { error } : {}) } });
}
async function kiNativeSecurityRecheck(context) {
  context.signal?.throwIfAborted();
  if (!(await kiNativeSettings()).enabled) throw Error('Local computer access is disabled.');
  await context.recheck?.();
  if (typeof kiPolicyState === 'function') {
    const policy = await kiPolicyState({ id: 'local:security_runtime', group: 'local', family: 'local', label: 'Local security runtime', defaultAsk: true }, context.session);
    if (!policy.parentEnabled || policy.rule === 'disabled') throw Error('Local security testing is disabled in Tools & permissions.');
    const needsApproval = policy.rule === 'ask' || policy.rule === 'inherit' && !policy.fullAccess;
    if (needsApproval && !context[KI_NATIVE_SECURITY_GRANT]?.approved) throw Error('Local security permissions changed. Start a new operation for approval.');
  }
  if (context.connectionSnapshot && typeof context.connectionId === 'string') {
    const settings = await kiNativeSettings();
    const current = settings.servers.find(server => server.id === context.connectionId);
    if (!current || JSON.stringify(current) !== JSON.stringify(context.connectionSnapshot)) throw Error('The callback connection changed. Start a new operation.');
  }
}
async function kiNativeSecurityAuthorize(context, action, args) {
  if (!(await kiNativeSettings()).enabled) throw Error('Local computer access is disabled.');
  await context.recheck?.();
  if (context[KI_NATIVE_SECURITY_GRANT]) return kiNativeSecurityRecheck(context);
  const meta = { id: 'local:security_runtime', group: 'local', family: 'local', label: 'Local security runtime', defaultAsk: true };
  const policy = typeof kiPolicyState === 'function' ? await kiPolicyState(meta, context.session) : { rule: 'inherit', fullAccess: (await kiNativeSettings()).fullAccess, parentEnabled: true };
  if (!policy.parentEnabled || policy.rule === 'disabled') throw Error('Local security testing is disabled in Tools & permissions.');
  let approved = context.userAction === true || context.permissionApproved === true;
  if (!approved && (policy.rule === 'ask' || policy.rule === 'inherit' && !policy.fullAccess)) {
    const decision = await KN.request({ local: true, policyPrompt: true, policyExplicit: policy.rule === 'ask', domain: 'Local computer', action: 'local_access', toolCallId: context.toolCallId || 'security-local-' + context.runId, toolName: 'security_local_runtime', session: context.session || context.owner, preview: { text: action + '\n' + JSON.stringify(args || {}, null, 2) } }, context.signal);
    if (decision !== 'allow_once') throw Error('Local operation denied by user.'); approved = true;
  }
  context[KI_NATIVE_SECURITY_GRANT] = { approved, owner: context.owner, runId: context.runId };
  await kiNativeSecurityRecheck(context);
}
async function kiNativeSecurityStatus(signal, allowDisabled = false) {
  const enabled = (await kiNativeSettings()).enabled;
  if (!enabled && !allowDisabled) return { enabled: false, ready: false, reason: 'Enable local computer access to use the local runtime.' };
  try {
    const value = await kiNativeRpc('security_status', {}, signal, 15000);
    if (value?.protocolVersion !== 1) return { enabled, ready: false, needsUpdate: true, reason: 'Update local runtime from Local computer settings.' };
    if (value.ok === false || value.success === false) throw Error(value.error || 'The local runtime reported an error.');
    return { ...value, enabled, ready: true };
  } catch (error) {
    return { enabled, ready: false, needsUpdate: /unknown|unsupported|not implemented/i.test(error.message), needsInstall: /not found|not installed/i.test(error.message), reason: /unknown|unsupported|not implemented/i.test(error.message) ? 'Update local runtime from Local computer settings.' : error.message };
  }
}
async function kiNativeSecuritySetup(params, { userAction, signal } = {}) {
  if (!userAction) throw Error('Install runtime components from Security testing settings.');
  if (kiNativeSecuritySetupActive) throw Error('Local runtime setup is already running.');
  if (!(await kiNativeSettings()).enabled) throw Error('Enable local computer access before setting up the local runtime.');
  const status = await kiNativeSecurityStatus(signal); if (!status.ready) throw Error(status.reason || 'Update local runtime from Local computer settings.');
  const components = params.components || [];
  if (!Array.isArray(components) || !components.length || components.some(name => !['browser', 'zap', 'webhook'].includes(name))) throw Error('Choose supported local runtime components.');
  kiNativeSecuritySetupActive = true;
  try { const result = await kiNativeRpc('security_setup', { components, options: params.options || {} }, signal, 900000);
    if (result?.ok === false || result?.success === false) throw Error(result.error || 'Local runtime setup failed.');
    return result;
  } finally { kiNativeSecuritySetupActive = false; }
}
async function kiNativeSecurityCancelSetup() {
  if (!kiNativeSecuritySetupActive) return { cancelled: false, reason: 'No local setup is running.' };
  return kiNativeRpc('security_cancel', { setup: true }, undefined, 15000);
}
async function kiNativeSecurityRestart() {
  const host = await kiNativeRpc('status', {}, undefined, 15000);
  if (!host.features?.includes('security_runtime_restart')) throw Error('Update the local runtime from Local computer settings before restarting it.');
  const result = await kiNativeRpc('security_restart', {}, undefined, 60000);
  if (result?.restarted !== true) throw Error('Local runtime restart was not confirmed.');
  kiNativeSecurityLost('Local runtime was restarted by the user. Previous operations were interrupted and were not replayed.');
  kiNativeDisconnect();
  return { ...result, runtime: await kiNativeSecurityStatus() };
}
async function kiNativeSecurityExecute(action, args, context) {
  if (!context?.owner || !context.runId || typeof context.checkRequest !== 'function') throw Error('Local security execution requires an owned run and request admission context.');
  if (action === 'browser.runCandidate' && args?.job?.certXPreparedMutations === true) {
    const host = await kiNativeRpc('status', {}, context.signal, 15000);
    if (!host.features?.includes('security_candidate_replay_v2')) throw Error('Update the local runtime from Local computer settings to reproduce exact candidate inputs.');
  }
  const stop = action === 'browser.close' || action.endsWith('.stop') || action.endsWith('.cleanup') || action.endsWith('.cancel');
  if (!stop && (context.scope?.matchMode === 'host' || context.scope?.also?.matchMode === 'host')) {
    const host = await kiNativeRpc('status', {}, context.signal, 15000);
    if (!host.features?.includes('security_scope_v2')) throw Error('Update the local runtime from Local computer settings to use same-host testing scope.');
  }
  if (action.startsWith('transport.')) {
    const host = await kiNativeRpc('status', {}, context.signal, 15000);
    if (!host.features?.includes('security_raw_v2')) throw Error('Update the local runtime from Local computer settings to use raw protocol tools.');
  }
  if (!stop) await kiNativeSecurityAuthorize(context, action, args);
  const status = await kiNativeSecurityStatus(stop ? undefined : context.signal, stop);
  if (!status.ready) throw Error(status.reason || 'Update local runtime from Local computer settings.');
  const lease = crypto.randomUUID(), port = kiNativeConnect();
  const entry = { lease, port, context, cleanupOnly: stop, abort: null };
  entry.abort = () => {
    kiNativeSecurityRelease(lease);
    if (kiNativePort === port) { try { port.postMessage({ id: 'security-cancel-' + (++kiNativeSequence), op: 'security_cancel', params: { runId: context.runId, owner: context.owner, lease } }); } catch {} }
  };
  kiNativeSecurityLeases.set(lease, entry); if (!stop) context.signal?.addEventListener('abort', entry.abort, { once: true });
  let persistent = false;
  try {
    const duration = Number(args?.timeoutMs || args?.timeout_ms || (context.config?.durationSeconds ? context.config.durationSeconds * 1000 : 0));
    const timeout = Number.isFinite(duration) && duration > 0 ? Math.max(135000, duration + 30000) : 135000;
    const result = await kiNativeRpc('security_dispatch', { action, args: args || {}, context: { owner: context.owner, workspaceId: context.workspaceId || null, runId: context.runId, scope: context.scope, config: context.config, lease } }, stop ? undefined : context.signal, timeout);
    if (result?.ok === false || result?.success === false || result?.isError === true) throw Error(result.error || result.message || 'Local security operation failed.');
    if (result?.persistent === true) {
      const retained = kiNativeSecurityLeases.get(result.leaseId);
      if (!retained || retained.port !== port || retained.context.owner !== context.owner || retained.context.runId !== context.runId || (retained.context.workspaceId || null) !== (context.workspaceId || null)) throw Error('Local runtime returned an invalid persistent lease.');
      // Browser follow-ups retain their original session lease; their temporary
      // dispatch lease covers only this action and is released below.
      persistent = result.leaseId === lease;
    }
    return result;
  } finally { if (!persistent) kiNativeSecurityRelease(lease); }
}

function kiNativeDisconnect() {
  const port = kiNativePort;
  kiNativePort = null;
  kiNativeSecurityLost('Local host disconnected.');
  if (port) kiWorkspaceHostLost().catch(() => {});
  for (const pending of [...kiNativePending.values()]) pending.reject(Error("Local host disconnected. Check installation and reconnect."));
  port?.disconnect();
}
function kiNativeConnect() {
  if (kiNativePort) return kiNativePort;
  const port = chrome.runtime.connectNative(KI_NATIVE_HOST);
  kiNativePort = port;
  port.onMessage.addListener(message => {
    if (kiNativePort !== port) return;
    if (message?.event === "job_update") { kiWorkspaceJob(message.result).catch(() => {}); return; }
    if (message?.event === 'security_admission' || message?.event === 'security_event') { void kiNativeSecurityMessage(message, port).catch(error => console.warn('[security] Local runtime event failed:', error.message)); return; }
    const pending = kiNativePending.get(message?.id);
    if (!pending) return;
    if (message.ok === true && Object.prototype.hasOwnProperty.call(message, "result")) pending.resolve(message.result);
    else pending.reject(Error(message.error || "Invalid native host response"));
  });
  port.onDisconnect.addListener(() => {
    const reason = chrome.runtime.lastError?.message || "Local host disconnected";
    if (kiNativePort !== port) return;
    kiNativePort = null;
    kiNativeSecurityLost(reason);
    kiWorkspaceHostLost().catch(() => {});
    for (const pending of [...kiNativePending.values()]) pending.reject(Error(reason + ". Install the host from Local computer settings."));
  });
  return port;
}
function kiNativeRpc(op, params = {}, signal, timeout = 135000) {
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const id = String(++kiNativeSequence);
    let port, timer;
    const finish = (error, result) => {
      clearTimeout(timer); signal?.removeEventListener("abort", abort); kiNativePending.delete(id);
      error ? reject(error) : resolve(result);
    };
    const abort = () => {
      try { port?.postMessage({ id: "cancel-" + id, op: "cancel", params: { id } }); } catch {}
      finish(Error("Local operation cancelled"));
    };
    kiNativePending.set(id, { resolve: value => finish(null, value), reject: error => finish(error) });
    signal?.addEventListener("abort", abort, { once: true });
    timer = setTimeout(() => {
      abort();
      // Do not replay an operation whose outcome is unknown.
      kiNativeDisconnect();
    }, timeout);
    try {
      port = kiNativeConnect();
      const message = { id, op, params };
      if (new TextEncoder().encode(JSON.stringify(message)).length > 900 * 1024) throw Error("Request exceeds native message limit");
      port.postMessage(message);
    } catch (error) { finish(error); }
  });
}
async function kiNativeSettings() {
  const values = await chrome.storage.local.get([KI_NATIVE_KEY, "sidepanel_approval_mode"]);
  const stored = values[KI_NATIVE_KEY];
  return { enabled: stored?.enabled === true, fullAccess: values.sidepanel_approval_mode === "full_access", servers: Array.isArray(stored?.servers) ? stored.servers.slice(0, 8) : [] };
}
var kiNativeSpecs = [
  { name: "local_run_command", op: "command", description: "Run a local command using the selected approval mode. Windows uses PowerShell; Unix uses /bin/sh. Set an absolute cwd. Foreground: up to 120 seconds, returns stdout/stderr. Set background:true for longer work (default 30 minutes, max 1 hour); returns a jobId for local_read_job/local_cancel_job. Optional outputs lists up to 16 absolute file paths to collect into this task's output tray after completion. Jobs end when the native host disconnects. No interactive stdin.",
    properties: { command: { type: "string" }, cwd: { type: "string" }, background: { type: "boolean" }, outputs: { type: "array", items: { type: "string" }, maxItems: 16 }, timeout_ms: { type: "integer", minimum: 100, maximum: 3600000 }, max_output_bytes: { type: "integer", minimum: 1, maximum: 131072 } }, required: ["command", "cwd"] },
  { name: "local_read_file", op: "read_file", description: "Read a local file using the selected approval mode using an absolute path. Read up to 128 KiB per call; offset and nextOffset are byte offsets. Use base64 for lossless binary data or UTF-8 split across chunks.",
    properties: { path: { type: "string" }, offset: { type: "integer", minimum: 0 }, max_bytes: { type: "integer", minimum: 1, maximum: 131072 }, encoding: { type: "string", enum: ["text", "base64"] } }, required: ["path"] },
  { name: "local_write_file", op: "write_file", description: "Write a local file using the selected approval mode, up to 512 KiB. Absolute path and existing parent directory required. Fails if file exists unless overwrite is explicitly true. Use local_run_command to create directories.",
    properties: { path: { type: "string" }, content: { type: "string" }, encoding: { type: "string", enum: ["text", "base64"] }, overwrite: { type: "boolean" } }, required: ["path", "content"] },
  { name: "local_list_directory", op: "list_directory", description: "List a local directory using the selected approval mode. Absolute path required. Returns names, types and nextOffset for pagination; ordering is filesystem-dependent.",
    properties: { path: { type: "string" }, offset: { type: "integer", minimum: 0 }, limit: { type: "integer", minimum: 1, maximum: 1000 } }, required: ["path"] },
  { name: "local_read_job", op: "job_read", description: "Read status and incremental output from a background command belonging to this task. Pass nextCursor from the previous result. The host retains the latest 1 MiB; truncated indicates older output was evicted. Do not repeatedly poll unchanged jobs in a tight loop.", properties: { job_id: { type: "string" }, cursor: { type: "integer", minimum: 0 }, max_bytes: { type: "integer", minimum: 16384, maximum: 131072 } }, required: ["job_id"] },
  { name: "local_cancel_job", op: "job_cancel", description: "Stop a background command belonging to this task and return its final status. Completed jobs are unchanged.", properties: { job_id: { type: "string" } }, required: ["job_id"] },
];
function kiNativeTool(spec, session) {
  return { name: spec.name, kiPolicyMeta: spec.kiPolicyMeta || kiPolicyLocalMeta(spec.name), description: spec.description, parameters: spec.parameters || { type: "object", properties: spec.properties, required: spec.name === "local_run_command" && typeof kiContextFor === "function" && kiContextFor(session).folder ? spec.required.filter(key => key !== "cwd") : spec.required },
    resolveExecution(args) {
      // Snapshot the exact approved payload, including an MCP server's config.
      const params = JSON.parse(JSON.stringify(spec.server ? { server: spec.server, name: spec.original, arguments: args || {} } : args || {}));
      return { approvalRule: "allow", async execute(context) {
        try {
          const initialSettings = await kiNativeSettings();
          if (!initialSettings.enabled) throw Error("Local computer access is disabled");
          let approvedOnce = kiPolicyApproved(context);
          if (!initialSettings.fullAccess && !approvedOnce) {
            const preview = JSON.stringify(params, null, 2);
            const decision = await KN.request({ domain: "Local computer", action: "local_access", local: true, toolCallId: context.toolCallId,
              toolName: spec.name, session, preview: { text: spec.name + "\n" + preview } }, context.signal);
            if (decision !== "allow_once") return { output: "Local operation denied by user.", isError: true };
            approvedOnce = true;
          }
          context.signal.throwIfAborted();
          const settings = await kiNativeSettings();
          if (!settings.enabled) throw Error("Local computer access was disabled");
          if (!approvedOnce && !settings.fullAccess) throw Error("Approval mode changed before execution; retry to request approval");
          if (spec.server && !settings.servers.some(server => JSON.stringify(server) === JSON.stringify(spec.server))) throw Error("Local MCP configuration changed; retry with the current tool list");
          if (context[KI_POLICY_CONTEXT]) await kiPolicyRecheck(context[KI_POLICY_CONTEXT]);
          if (params.background || params.outputs?.length || spec.op.startsWith("job_")) {
            const host = await kiNativeRpc("status", {}, context.signal);
            if (!host.features?.includes("command_jobs")) throw Error("Update the native host from Local computer settings to use jobs and command outputs.");
          }
          const result = await kiNativeRpc(spec.op, { ...params, owner: kiWorkspaceOwner(session) }, context.signal);
          const failed = result.jobId ? ["failed", "timed_out"].includes(result.state) : spec.op === "command" ? result.exitCode !== 0 || result.timedOut || result.cancelled : result?.isError === true;
          return { output: JSON.stringify(result), ...(failed ? { isError: true } : {}) };
        } catch (error) { return { output: spec.name + " failed: " + error.message, isError: true }; }
      } };
    } };
}
var kiNativeServerCache = new Map();
function kiNativeServerKey(server) { return JSON.stringify([server.command, server.args || [], server.cwd || '', Object.entries(server.env || {}).sort(([a], [b]) => a.localeCompare(b)), server.envFileRef || '', server.secretRef || null]); }
function kiNativeToolDefs(session) {
  const specs = [...kiNativeSpecs, ...kiNativeCache.tools].filter(spec => !session || typeof kiContextFor !== "function" || kiContextAllows(spec.kiPolicyMeta || kiPolicyLocalMeta(spec.name), kiContextFor(session)));
  return kiNativeCache.enabled ? specs.map(spec => kiNativeTool(spec, session)) : [];
}
async function kiNativeRefresh(session) {
  const generation = kiNativeGeneration, settings = await kiNativeSettings(), active = new Set();
  if (settings.enabled) for (const server of settings.servers) {
    if (generation !== kiNativeGeneration) return kiNativeCache;
    const key = kiNativeServerKey(server); active.add(key);
    if (typeof kiContextServerSelected === "function" && !await kiContextServerSelected(server, "local", session)) continue;
    if (generation !== kiNativeGeneration) return kiNativeCache;
    let entry = kiNativeServerCache.get(key);
    if (entry && Date.now() - entry.at < 20000) continue;
    if (entry?.pending) { await entry.pending; continue; }
    entry = { at: 0, tools: [], errors: [] }; kiNativeServerCache.set(key, entry);
    const refresh = (async () => {
      try {
        const result = await kiNativeRpc("mcp_list", { server }, undefined, 45000);
        if (generation !== kiNativeGeneration) return;
        await kiPolicyRecordMcp(server, result.tools, "local");
        if (generation !== kiNativeGeneration) return;
        for (const [index, tool] of result.tools.entries()) {
          if (!tool || typeof tool.name !== "string") continue;
          entry.tools.push({ name: "local_mcp_" + settings.servers.indexOf(server) + "_" + index + "_" + kiMcpSlug(tool.name),
            op: "mcp_call", original: tool.name, server, kiPolicyMeta: await kiPolicyMcpMeta(server, tool.name, "local"), parameters: tool.inputSchema || { type: "object", properties: {} },
            description: ("[Local MCP: " + (server.label || server.command) + "] " + (tool.description || tool.name)).slice(0, 1024) });
        }
      } catch (error) { entry.errors.push({ label: server.label || server.command, error: error.message }); }
      finally { entry.at = Date.now(); delete entry.pending; }
    })(); entry.pending = refresh; await refresh;
  }
  if (generation !== kiNativeGeneration) return kiNativeCache;
  for (const key of kiNativeServerCache.keys()) if (!active.has(key)) kiNativeServerCache.delete(key);
  kiNativeCache = { enabled: settings.enabled, tools: [...kiNativeServerCache.values()].flatMap(entry=>entry.tools), errors: [...kiNativeServerCache.values()].flatMap(entry=>entry.errors) };
  return kiNativeCache;
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes[KI_NATIVE_KEY]) return;
  kiNativeGeneration++;
  kiNativeServerCache.clear();
  kiNativeCache = { enabled: false, tools: [], errors: [] };
  kiMcpCache.at = 0;
  if (changes[KI_NATIVE_KEY].newValue?.enabled !== true) kiNativeDisconnect();
  else if (kiNativePort) {
    const before = changes[KI_NATIVE_KEY].oldValue?.servers || [], after = changes[KI_NATIVE_KEY].newValue?.servers || [];
    const retired = before.filter(server => !after.some(next => kiNativeServerKey(next) === kiNativeServerKey(server)));
    if (retired.length) void kiNativeRpc('status', {}, undefined, 10000).then(status => kiNativeRpc('mcp_reset', status.features?.includes('mcp_selective_reset') ? { servers: retired } : {})).catch(() => kiNativeDisconnect());
  }
});
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== "KI_NATIVE") return;
  // Content scripts share the extension ID: also require an exact extension page.
  if (sender.id !== chrome.runtime.id || sender.url?.split("?")[0] !== chrome.runtime.getURL("providers/providers.html")) {
    reply({ ok: false, error: "Local settings requests require the providers page" }); return;
  }
  (async () => {
    try {
      if (message.op === "status") { reply({ ok: true, result: await kiNativeRpc("status", {}, undefined, 10000) }); return; }
      if (message.op === "test") {
        if (!(await kiNativeSettings()).enabled) throw Error("Enable local computer access first");
        reply({ ok: true, result: await kiNativeRpc("mcp_list", { server: message.server }, undefined, 45000) }); return;
      }
      throw Error("Unsupported local settings operation");
    } catch (error) { reply({ ok: false, error: error.message }); }
  })();
  return true;
});

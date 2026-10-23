// Compatibility calls stay inside cert-x. Captured requests never transit a page
// or another extension. The coordinator retains the original targeted contracts.
async function kiDastCompanion(op, payload = {}, signal, beforeDispatch, parentRequestGuard) {
  signal?.throwIfAborted();
  const runtime = globalThis.certXSecurityCompatibility;
  if (!runtime) throw Error("The integrated account and targeted-testing runtime is unavailable. Reload cert-x.");
  await runtime.ready;
  await beforeDispatch?.();
  signal?.throwIfAborted();
  let requests = 0; const startedAt = Date.now();
  if (payload.budget && globalThis.certXSecurity && !parentRequestGuard) await globalThis.certXSecurity.resolveConfig(payload.workspaceId, payload.budget);
  const checkRequest = async request => {
    signal?.throwIfAborted(); await beforeDispatch?.();
    if (payload.scope && !kiDastScopeAllows(request.url, payload.scope)) throw Error('The request is outside the selected target scope.');
    if (globalThis.certXSecurity) {
      const config = await globalThis.certXSecurity.resolveConfig(payload.workspaceId), limits = config.limits || {};
      if (requests >= (limits.maxRequests ?? Infinity) || Date.now() - startedAt >= (limits.durationSeconds ?? Infinity) * 1000) throw Error('The explicit user testing budget was exhausted.');
      if (limits.maxRequestsPerSecond != null && payload.budget?.maxRequestsPerSecond > limits.maxRequestsPerSecond) throw Error('The request rate exceeds the updated user limit.');
    }
    await parentRequestGuard?.(request);
    requests++;
  };
  const result = await runtime.invoke(op, payload, { owner: payload.owner, workspaceId: payload.workspaceId, tabId: payload.tabId, scope: payload.scope, signal, recheck: beforeDispatch, checkRequest });
  if (result == null || result.ok === false || result.success === false) throw Error(result?.error || result?.message || "Security operation failed.");
  return result;
}

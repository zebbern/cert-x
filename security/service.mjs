import { SETTINGS_KEY, cleanSettings, resolveConfig, validateOptions, validateLimits, validateScope, scopeAllows, scopeWithin, copy } from './config.mjs';
import { OPERATION_SCHEMAS, validateOperationSelection } from './engine/operation-arguments.mjs';
import { actionableCoverage } from './engine/coverage.mjs';

export const RUNS_KEY = 'ki_security_runs';
export const EVIDENCE_KEY = 'ki_security_evidence';
export const PRIVATE_EVIDENCE_KEY = 'ki_security_private_evidence';
const ACTIVE = new Set(['starting', 'running', 'stopping']);
function checked(value) {
  const transportError = value?.response?.errorMessage || value?.response?.errorName || (value?.response && Object.hasOwn(value.response, 'statusCode') && Number(value.response.statusCode) === 0 ? 'The HTTP response is opaque or unavailable; completion could not be confirmed.' : null);
  if (value == null || value.ok === false || value.success === false || value.result?.ok === false || value.result?.success === false || transportError) throw Object.assign(Error(transportError || value?.error?.message || value?.error || value?.message || value?.result?.error || 'Security engine returned no successful result.'), { nativeResult: copy(value) });
  return value;
}
function runState(result, fallback = 'running') {
  const value = String(result?.state || result?.status || result?.scan?.state || result?.scan?.status || fallback).toLowerCase();
  return ({ complete: 'completed', done: 'completed', finished: 'completed', closed: 'cancelled', canceled: 'cancelled', stopped: 'cancelled', paused:'interrupted', failed: 'error', pending: 'starting', queued:'starting', open:'running', scanning: 'running', observing: 'running' })[value] || (['starting', 'running', 'stopping', 'completed', 'cancelled', 'error', 'interrupted', 'incomplete', 'unknown'].includes(value) ? value : fallback);
}
function publicRun(run) { const { runtimeHandle, ...rest } = run; return copy({ ...rest, coverage: actionableCoverage(run.coverage, run) }); }
function idFrom(result) { return result.sessionId || result.scanId || result.runId || result.id || result.session?.sessionId || result.session?.id; }
function errorText(error) { return error?.message || String(error); }
function page(values, offset = 0, limit = 50) {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw Error('Use a non-negative offset and a limit from 1 to 500.');
  return { items: values.slice(offset, offset + limit), total: values.length, nextOffset: offset + limit < values.length ? offset + limit : null };
}
export function createSecurityService(runtime, { storage = globalThis.chrome?.storage?.local, privateStorage = globalThis.chrome?.storage?.session, now = Date.now, uuid = () => crypto.randomUUID() } = {}) {
  if (!storage?.get || !storage?.set) throw Error('Security persistence is unavailable.');
  const runs = new Map(), evidence = new Map(), live = new Map(), groups = new Map(), privateEvidence = new Map(), privateAccounts = new Map();
  let settings = cleanSettings(), writes = Promise.resolve(), starts = Promise.resolve(), settingsWrites = Promise.resolve();
  const persist = () => { const task = writes.then(async () => { await storage.set({ [RUNS_KEY]: [...runs.values()], [EVIDENCE_KEY]: Object.fromEntries(evidence) }); if (privateStorage) await privateStorage.set({ [PRIVATE_EVIDENCE_KEY]: Object.fromEntries(privateEvidence) }); }); writes = task.catch(() => {}); return task; };
  function protect(value, runId, context = {}) {
    const account = context.account || privateAccounts.get(runId); if (!account) return value;
    privateAccounts.set(runId, account); privateEvidence.set(runId, { native: copy(value), capturedAt: now() });
    const names = new Set(['authorization', 'cookie', ...(Array.isArray(account.headers) ? account.headers.map(header => String(header.name).toLowerCase()) : Object.keys(account.headers || {}).map(name => name.toLowerCase()))]);
    const values = (Array.isArray(account.headers) ? account.headers.map(header => String(header.value)) : Object.values(account.headers || {}).map(String)).concat(account.cookie || '').filter(value => value.length >= 4);
    const redact = input => {
      if (typeof input === 'string') { for (const secret of values) input = input.split(secret).join('[private account credential]'); return input; }
      if (Array.isArray(input)) return input.map(redact);
      if (!input || typeof input !== 'object') return input;
      if (typeof input.name === 'string' && names.has(input.name.toLowerCase()) && Object.hasOwn(input, 'value')) return { ...input, value: '[private account credential]' };
      return Object.fromEntries(Object.entries(input).map(([key, child]) => [key, names.has(key.toLowerCase()) && typeof child === 'string' ? '[private account credential]' : redact(child)]));
    };
    return redact(copy(value));
  }
  const remember = async (run, patch) => {
    if (!ACTIVE.has(run.state) && run.state !== 'unknown' && ACTIVE.has(patch.state)) { patch = { ...patch }; for (const key of ['state', 'engineStatus', 'lastStatus', 'progress', 'summary']) delete patch[key]; }
    Object.assign(run, patch, { updatedAt: now() }); await persist(); return publicRun(run);
  };
  function scanCoverage(run, result, state = runState(result)) {
    const nativeCoverage = copy(result.coverage || run.coverage || {});
    const coverage = Array.isArray(nativeCoverage) ? { checks: nativeCoverage } : nativeCoverage && typeof nativeCoverage === 'object' ? nativeCoverage : {};
    const engineStates = result.engines || result.engineStatus;
    if (engineStates) coverage.engineFailures = run.engines.filter(engine => {
      const value = engineStates[engine];
      return value && (value.error || ['error', 'failed', 'interrupted'].includes(value.status || value.state));
    }).map(engine => ({ engine, error: engineStates[engine].error || engineStates[engine].status || engineStates[engine].state }));
    const dast = result.engines?.DAST || result.engineStatus?.DAST;
    const finish = error => {
      const resolved = actionableCoverage(coverage, { ...run, state });
      // Coverage gaps invalidate a clean "completed" verdict only when they
      // represent unfinished assessment (limits, drains, errors, nothing
      // analyzed). Basis caveats that accompany any successful scan stay in
      // actionableGaps without flipping the run state; no_client_source_analyzed
      // is also advisory here because stop-time snapshots can predate the
      // analysis counters settling.
      const advisory = new Set(['original_html_unavailable', 'no_client_source_analyzed']);
      if (state === 'completed' && resolved.actionableGaps.some(gap => !advisory.has(gap.code))) state = 'incomplete';
      return { state, coverage: resolved, error: error || null };
    };
    if (!run.engines.includes('DAST') || !dast) return finish(null);
    const count = value => Number.isFinite(value) && value >= 0 ? value : null;
    const planned = count(dast.progress?.total), executed = count(dast.progress?.done);
    const plannedMinusEntered = planned !== null && executed !== null ? Math.max(0, planned - executed) : null;
    const observed = count(dast.captureStats?.observedRequestsStarted);
    const queued = count(dast.captureStats?.observedRequestsQueued);
    const proxySeeded = count(dast.proxySeededRequests) || 0;
    const selectedTargetSeeded = count(dast.selectedTargetSeededRequests) || 0;
    const probeDispatches = count(run.dastProbeDispatches);
    const baselineDispatches = count(run.dastBaselineDispatches);
    const dispatches = probeDispatches !== null && baselineDispatches !== null ? probeDispatches + baselineDispatches : run.engines.length === 1 ? run.requestsSent : null;
    const hasInput = (observed || 0) > 0 || proxySeeded > 0 || selectedTargetSeeded > 0;
    const terminal = !ACTIVE.has(state);
    const engineError = dast.engineError || dast.error || null;
    const seedError = dast.seedError || null;
    const taskErrors = count(dast.taskErrorsCount) || 0;
    const taskSkips = count(dast.taskSkipsCount) || 0;
    let phase;
    if (engineError) phase = 'engine_error';
    else if (taskErrors) phase = terminal ? 'partial_error' : 'probing_with_errors';
    else if (taskSkips) phase = terminal ? 'limited_by_skips' : 'probing_with_skips';
    else if (!hasInput && !planned && !executed && !dispatches) phase = terminal ? 'no_requests' : dast.waitingForInteraction ? 'waiting_for_interaction' : 'waiting_for_requests';
    else if (terminal && executed === 0) phase = 'no_executed_probes';
    else if (!terminal && dast.idle === true && executed === 0) phase = 'waiting_for_attackable_inputs';
    else if (dispatches === 0 && !executed) phase = terminal ? 'no_executed_probes' : 'planning_or_waiting';
    else if (dispatches === 0 || probeDispatches === 0) phase = terminal ? 'no_active_probes' : 'passive_execution';
    else if (dispatches == null) phase = 'dispatch_attribution_unknown';
    else if (!terminal && dast.idle === true) phase = 'watching_for_activity';
    else phase = terminal ? 'scan_requests_dispatched' : 'scanning';
    coverage.dast = {
      phase, applicationRequestsObserved: observed, applicationRequestsQueued: queued,
      proxySeededRequests: proxySeeded, selectedTargetSeededRequests: selectedTargetSeeded,
      seedCandidates: count(dast.seedCandidates), unsafeSeedSkipped: count(dast.unsafeSeedSkipped),
      tasksPlanned: planned, tasksExecuted: executed,
      taskCounterMeaning: 'Tasks entered execution before any transport attempt',
      plannedMinusEntered, plannedMinusEnteredMeaning:'Accounting difference only; this is not an exact count of skipped HTTP requests. Inspect stop state, strategy skips and retained task errors.',
      probeDispatches, baselineDispatches, dastRequestsDispatched: dispatches, runRequestsDispatched: run.requestsSent,
      skippedDueToStrategy: count(dast.skippedDueToStrategy),
      taskErrors, lastTaskError: dast.lastTaskError || null,
      taskSkips, lastTaskSkip: dast.lastTaskSkip || null,
      captureErrors: count(dast.captureStats?.observedRequestsErrored),
      waitingForInteraction: dast.waitingForInteraction === true,
      ...(engineError || seedError || dast.lastTaskError ? { error: engineError || seedError || dast.lastTaskError } : {})
    };
    if (engineError && ACTIVE.has(state) && run.engines.length === 1) state = 'unknown';
    else if (engineError && state === 'completed') state = run.engines.length === 1 ? 'error' : 'incomplete';
    else if ((taskErrors || taskSkips) && state === 'completed') state = 'incomplete';
    if (terminal && state === 'completed' && run.engines.length === 1 && executed === 0) state = 'incomplete';
    return finish(engineError || seedError || dast.lastTaskError);
  }
  function owned(id, context) { const run = runs.get(id); if (!run || !context?.owner || run.owner !== context.owner) throw Object.assign(Error('This security run does not belong to this chat. Use the public runId returned by security_start_scan, not its native sessionId/runtimeId. Use security_list_runs to recover this chat’s run references.'), { code:'run_reference_unavailable', retryable:false, recovery:'List this chat’s runs with security_list_runs and use the source scan runId. Do not substitute a run from another chat.' }); return run; }
  function argumentsFor(run, args = {}) { return { ...copy(run.runtimeHandle || {}), ...args, tabId: run.tabId, sessionId: run.runtimeId, scanId: run.runtimeId, runId: run.runId, engines: run.engines }; }
  function contextFor(run, context = {}) { return { ...context, owner: run.owner, workspaceId: run.workspaceId, tabId: run.tabId, scope: run.scope, config: run.config, runId: run.runId }; }
  function bindBackends(runtimeContext, caller) {
    if (typeof caller.localExecute === 'function') runtimeContext.localExecute = (action, args) => caller.localExecute(action, args, runtimeContext);
    return runtimeContext;
  }
  const external = new Set(['browser', 'raw', 'oast', 'zap', 'candidate']);
  const externalStatusAction = operation => operation === 'zap' ? 'progress' : 'status';
  const externalStopAction = operation => operation === 'browser' ? 'close' : 'stop';
  function externalArguments(run, action, extra = {}) {
    // A browser response URL describes current state, not a request to navigate.
    // Carry only the session identity; replaying create/login arguments on an
    // inspect, screenshot, or status call can navigate or repeat login actions.
    if (run.operation === 'browser') return { sessionId: run.runtimeHandle?.sessionId || run.operationArguments?.sessionId, ...extra, action, runId: run.runId };
    if (run.operation === 'raw' && action === 'evidence') return { ...extra, action, runId: run.runId };
    return { ...copy(run.operationArguments || {}), ...copy(run.runtimeHandle || {}), ...extra, action, runId: run.runId };
  }
  function retainedArguments(input) { return Object.fromEntries(['action','sessionId','browserSessionId','candidateId','jobId','oastId','zapId','accountRef','accountId','url','tabId'].filter(key=>Object.hasOwn(input,key)).map(key=>[key,copy(input[key])])); }
  async function collect(run, context) {
    const pages = [], findings = [], visited = new Set(); let offset = 0, response;
    do {
      if (visited.has(offset)) throw Error('The engine repeated a findings cursor.'); visited.add(offset);
      response = checked(protect(await runtime.invoke('getFindings', argumentsFor(run, { limit: 500, offset }), contextFor(run, context)), run.runId, context)); pages.push(copy(response));
      findings.push(...(Array.isArray(response.findings) ? response.findings : Array.isArray(response.items) ? response.items : Array.isArray(response.result?.findings) ? response.result.findings : []));
      offset = Number.isSafeInteger(response.nextOffset) && response.nextOffset >= 0 ? response.nextOffset : null;
    } while (offset !== null);
    const prior = evidence.get(run.runId) || {};
    // Keep the native envelope as evidence; normalization never discards engine fields.
    const truncated = response.truncated === true && offset === null;
    const retained = new Map((prior.findings || []).map(item => [item.id || item.findingId || JSON.stringify(item), item]));
    for (const item of findings) retained.set(item.id || item.findingId || JSON.stringify(item), item);
    const merged = [...retained.values()];
    evidence.set(run.runId, { ...prior, findings: merged, nativeFindings: pages.length === 1 ? pages[0] : { pages }, truncated, capturedAt: now() });
    const byModule = Object.create(null);
    for (const finding of merged) { const moduleId = finding.moduleId || finding.engine || 'unclassified'; byModule[moduleId] = (byModule[moduleId] || 0) + 1; }
    run.summary = { ...(run.summary || {}), findings: merged.length, byModule, countsBasis: truncated ? 'retained_sample' : 'retained_findings' };
    if (response.coverage) run.coverage = { ...run.coverage, ...copy(response.coverage) };
    run.coverage = actionableCoverage(run.coverage, run);
    if (truncated) run.evidenceError = 'The engine returned a truncated finding sample without a continuation cursor. Export the native report for full evidence.';
    else delete run.evidenceError;
    await persist(); return response;
  }
  async function status(id, context, observation = {}) {
    const run = owned(id, context); if (!ACTIVE.has(run.state) && run.state !== 'unknown') return publicRun(run);
    try {
      const current = await service.resolveConfig(run.workspaceId), duration = Math.min(run.config.durationSeconds ?? Infinity, current.limits.durationSeconds ?? Infinity);
      if (observation.active && !observation.active()) return publicRun(run);
      if (run.state !== 'stopping' && now() - run.createdAt >= duration * 1000) return stop(id, context, 'Configured duration reached.');
      if (run.kind === 'operation') {
        if (external.has(run.operation)) {
          // Creation may still be awaiting a local session/job handle while the
          // UI polls. Do not send a status request with an undefined identity.
          if (!run.runtimeHandle) return publicRun(run);
          const execution = live.get(id); if (!execution) throw Error('The original local execution context is unavailable. Reopen explicitly.');
          const result = checked(await runtime.invoke(run.operation, externalArguments(run, externalStatusAction(run.operation)), execution.context));
          const state = result.persistent === true || result.active === true ? 'running' : runState(result, run.state);
          evidence.set(id, { operation: run.operation, result: copy(result), capturedAt: now() });
          await remember(run, { state, result: copy(result) }); if (!ACTIVE.has(run.state)) release(run);
        }
        if (['macro', 'capture'].includes(run.operation)) {
          const result = checked(await runtime.invoke(run.operation, { action: 'status', tabId: run.tabId }, contextFor(run, { ...(live.get(id)?.context || context), signal: context.signal })));
          let state;
          if (run.operation === 'capture') { if (typeof result.active !== 'boolean') throw Error('Capture activity is unconfirmed.'); state = result.active ? run.state === 'stopping' ? 'stopping' : 'running' : run.stopReason ? 'cancelled' : 'completed'; }
          else { if (!Object.hasOwn(result, 'mode')) throw Error('Recorder activity is unconfirmed.'); state = result.mode ? run.state === 'stopping' ? 'stopping' : 'running' : result.replayResult?.status === 'failed' ? 'error' : result.replayResult?.status === 'stopped' || run.stopReason ? 'cancelled' : 'completed'; }
          evidence.set(run.runId, { operation: run.operation, result: copy(result), capturedAt: now() });
          await remember(run, { state, summary: copy(result), ...(state === 'error' ? { error: result.replayResult?.error || result.replayResult?.reason || 'Workflow replay failed.' } : {}) });
          if (!ACTIVE.has(run.state)) release(run);
        }
        return publicRun(run);
      }
      const response = await runtime.invoke('scanStatus', argumentsFor(run), contextFor(run, { ...(live.get(id)?.context || context), signal: context.signal }));
      if (observation.active && !observation.active()) return publicRun(run);
      const result = checked(protect(response, run.runId, context));
      // An older in-flight poll cannot reopen or invalidate a completed stop.
      if (!ACTIVE.has(run.state) && run.state !== 'unknown') return publicRun(run);
      const assessment = scanCoverage(run, result);
      await remember(run, { state: assessment.state, summary: copy(result.summary || result.scan?.summary || run.summary), coverage: assessment.coverage, engineStatus: copy(result.engines || result.engineStatus), progress: copy(result.progress), lastStatus: copy(result), ...(assessment.error ? { error: assessment.error } : {}) });
      try { await collect(run, context); } catch (error) { await remember(run, { evidenceError: errorText(error) }); }
      if (!ACTIVE.has(run.state) && run.state !== 'unknown') release(run);
    } catch (error) { if ((!observation.active || observation.active()) && (ACTIVE.has(run.state) || run.state === 'unknown')) await remember(run, { state: 'unknown', error: errorText(error) }); }
    return publicRun(run);
  }
  async function waitForDastIdle(args, context) {
    const run = owned(args.runId, context);
    const invalid = message => { throw Object.assign(Error(message), { code: 'invalid_status_wait', retryable: false, recovery: 'Use {runId,waitForIdle:true,timeoutMs:30000} for a DAST scan; omit waitForIdle/timeoutMs for an ordinary status read. Correct the arguments before retrying.' }); };
    if (typeof args.waitForIdle !== 'boolean') invalid('waitForIdle must be a boolean.');
    const timeoutMs = args.timeoutMs ?? 30000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) invalid('timeoutMs must be an integer from 1 to 30000.');
    if (!args.waitForIdle) return status(args.runId, context);
    if (run.kind === 'operation' || !run.engines.includes('DAST')) invalid('waitForIdle waits for a DAST scan queue. Use ordinary status for other operations.');
    const started = Date.now(), deadline = started + timeoutMs;
    let ended = false, timer, pauseTimer, wake, abort, last = publicRun(run);
    const active = () => !ended && Date.now() < deadline && !context.signal?.aborted;
    const result = outcome => {
      const current = publicRun(run);
      if (!ACTIVE.has(current.state) && current.state !== 'unknown') outcome = 'terminal';
      const snapshot = outcome === 'idle' ? last : current;
      return { ...snapshot, wait: { condition: 'dast_idle', outcome, idle: outcome === 'idle', timedOut: outcome === 'timeout', waitedMs: Math.max(0, Date.now() - started) } };
    };
    const abortError = () => context.signal?.reason || Error('Status wait cancelled.');
    try {
      context.signal?.throwIfAborted();
      const aborted = new Promise((_, reject) => { abort = () => reject(abortError()); context.signal?.addEventListener('abort', abort, { once: true }); });
      const timeout = new Promise(resolve => { timer = setTimeout(() => resolve(result('timeout')), timeoutMs); });
      const poll = (async () => {
        while (active()) {
          await context.recheck?.(); context.signal?.throwIfAborted();
          if (!active()) break;
          last = await status(args.runId, context, { active });
          // A restriction changed during the native read must be observed before
          // returning that read to the agent. Waiting itself never stops a run.
          await context.recheck?.(); context.signal?.throwIfAborted();
          if (!active()) break;
          if (!ACTIVE.has(last.state) && last.state !== 'unknown') return result('terminal');
          if (last.state === 'unknown') return result('unavailable');
          if (last.state === 'running' && last.engineStatus?.DAST?.idle === true) return result('idle');
          await new Promise(resolve => { wake = resolve; pauseTimer = setTimeout(resolve, Math.min(1000, Math.max(1, deadline - Date.now()))); });
          wake = null;
        }
        return result('timeout');
      })();
      const observed = await Promise.race([poll, timeout, aborted]);
      ended = true;
      // Include timeout returns: a permission change during the final pause
      // cannot be bypassed merely because no further native poll was needed.
      await context.recheck?.(); context.signal?.throwIfAborted();
      return result(observed.wait.outcome);
    } finally {
      ended = true; clearTimeout(timer); clearTimeout(pauseTimer); wake?.();
      if (abort) context.signal?.removeEventListener('abort', abort);
    }
  }
  function release(run) { const execution = live.get(run.runId); clearTimeout(execution?.timer); execution?.unlink?.(); live.delete(run.runId); const group = groups.get(execution?.groupKey); if (group) { group.runs.delete(run.runId); if (!group.runs.size && !group.inFlight) groups.delete(execution.groupKey); } }
  function withRequest(run, execution, context) {
    return async (_request, operation) => {
      if (typeof operation !== 'function') throw Error('A request operation is required.');
      const group = groups.get(execution.groupKey); if (!group) throw Error('The request execution context has ended.');
      group.waiters ||= new Set();
      for (;;) {
        execution.controller.signal.throwIfAborted(); await context.recheck?.();
        const latest = await service.resolveConfig(run.workspaceId);
        const cap = Math.min(run.config.limits.concurrency ?? Infinity, latest.limits.concurrency ?? Infinity);
        const ownCap = Math.min(run.config.concurrency, cap);
        if ((execution.inFlight || 0) < ownCap && (group.inFlight || 0) < cap) { execution.inFlight = (execution.inFlight || 0) + 1; group.inFlight = (group.inFlight || 0) + 1; run.inFlight = execution.inFlight; break; }
        await new Promise((resolve, reject) => {
          const finish = error => { clearTimeout(timer); group.waiters.delete(wake); execution.controller.signal.removeEventListener('abort', abort); error ? reject(error) : resolve(); };
          const wake = () => finish(), abort = () => finish(execution.controller.signal.reason || Error('Cancelled'));
          const timer = setTimeout(wake, 250); group.waiters.add(wake); execution.controller.signal.addEventListener('abort', abort, { once: true });
        });
      }
      try { execution.controller.signal.throwIfAborted(); await context.recheck?.(); return await operation(); }
      finally { execution.inFlight--; group.inFlight--; run.inFlight = execution.inFlight; for (const wake of [...group.waiters]) wake(); if (!group.runs.size && !group.inFlight) groups.delete(execution.groupKey); await persist(); }
    };
  }
  async function stop(id, context, reason = 'Stopped by user.', actionOverride) {
    const run = owned(id, context); if (!ACTIVE.has(run.state) && run.state !== 'unknown' && !actionOverride) return publicRun(run);
    const execution = live.get(id); execution?.controller.abort(Error(reason));
    await remember(run, { state: 'stopping', stopReason: reason });
    try {
      const stopContext = contextFor(run, { ...(execution?.context || context), signal: undefined });
      stopContext.checkRequest = async request => { if (request?.kind !== 'control') throw Error('A stopped operation cannot send target requests.'); return { runId: run.runId, control: true, cleanup: true }; };
      bindBackends(stopContext, execution?.caller || context);
      if (run.kind === 'operation') {
        // A finite local request has no persistent stop endpoint. Await its
        // aborted invocation before acknowledging cleanup; creation may not
        // have produced a browser/session handle yet either.
        if (external.has(run.operation) && !run.runtimeHandle) {
          await execution?.pending?.catch(() => {});
          if (!run.runtimeHandle || run.operation === 'raw') {
            await remember(run, { state: 'cancelled' }); release(run); return publicRun(run);
          }
        }
        const cleanupContext = contextFor(run, { ...(execution?.context || context), signal: undefined });
        cleanupContext.checkRequest = async request => { if (request?.kind !== 'control') throw Error('A stopped operation cannot send target requests.'); return { runId: run.runId, control: true, cleanup: true }; };
        bindBackends(cleanupContext, execution?.caller || context);
        const result = external.has(run.operation) ? checked(await runtime.invoke(run.operation, externalArguments(run, actionOverride || externalStopAction(run.operation)), cleanupContext)) : ['macro', 'capture'].includes(run.operation) ? checked(await runtime.invoke(run.operation, { action: 'stop', tabId: run.tabId }, cleanupContext)) : { cancelled: true };
        const ended = run.operation === 'capture' ? result.active === false : run.operation === 'macro' ? Object.hasOwn(result, 'mode') && result.mode === null : external.has(run.operation) ? ['completed','stopped','closed','canceled','cancelled','deleted'].includes(result.state||result.status) || result.active===false || result.persistent===false : true;
        evidence.set(run.runId, { operation: run.operation, result: copy(result), capturedAt: now() });
        await remember(run, { state: ended ? 'cancelled' : 'stopping', summary: copy(result) }); if (ended) release(run); return publicRun(run);
      }
      const result = checked(await runtime.invoke('stopScan', argumentsFor(run), stopContext));
      await remember(run, { state: runState(result, 'stopping'), lastStatus: copy(result), summary: copy(result.summary || run.summary), engineStatus: copy(result.engines || result.engineStatus || result.summary?.engines || run.engineStatus) });
      if (!ACTIVE.has(run.state)) { try { const final = checked(await runtime.invoke('scanStatus', argumentsFor(run), contextFor(run, context))); const assessment = scanCoverage(run, final, run.state); await remember(run, { state: assessment.state, engineStatus: copy(final.engines || final.engineStatus || run.engineStatus), lastStatus: copy(final), coverage: assessment.coverage, ...(assessment.error ? { error: assessment.error } : {}) }); } catch (error) { await remember(run, { evidenceError: 'Final scan status unavailable: ' + errorText(error) }); } }
      try { await collect(run, context); } catch (error) { await remember(run, { evidenceError: errorText(error) }); }
      if (!ACTIVE.has(run.state)) release(run);
    } catch (error) {
      try {
        const final = checked(await runtime.invoke('scanStatus', argumentsFor(run), contextFor(run, context)));
        const assessment = scanCoverage(run, final, 'unknown');
        await remember(run, { engineStatus: copy(final.engines || final.engineStatus || run.engineStatus), lastStatus: copy(final), coverage: assessment.coverage });
      } catch (_) { }
      await remember(run, { state: 'unknown', error: errorText(error) });
    }
    return publicRun(run);
  }
  function requestGuard(run, execution, context) {
    return request => {
      if (request?.kind === 'control') return Promise.resolve().then(async () => { execution.controller.signal.throwIfAborted(); await context.recheck?.(); return { runId: run.runId, control: true }; });
      const group = groups.get(execution.groupKey) || { requestsSent: 0, lastRequestAt: null };
      run.requestsReserved = (run.requestsReserved || 0) + 1;
      const check = async () => {
        execution.controller.signal.throwIfAborted(); await context.recheck?.();
        const currentSettings = cleanSettings((await storage.get(SETTINGS_KEY))[SETTINGS_KEY] || settings);
        const current = resolveConfig(currentSettings, run.workspaceId, {}), limits = { ...run.config.limits };
        for (const [key, value] of Object.entries(current.limits)) if (key !== 'acquisition') limits[key] = Math.min(limits[key] ?? Infinity, value);
        const raw = /^raw_(connect|send)$/.test(request?.kind || '');
        if (raw && request.targets != null && (!Array.isArray(request.targets) || request.targets.some(item => typeof item?.url !== 'string'))) throw Error('Invalid raw routing targets.');
        const targets = [request?.url || request?.request?.url, ...(raw ? (request.targets || []).map(item => item.url) : [])].filter(Boolean).map(target => raw && typeof target === 'string' ? target.replace(/^ws(?=:)/, 'http').replace(/^wss(?=:)/, 'https') : target);
        for (const target of targets) if (!scopeAllows(target, run.scope)) throw Error('Target is outside run scope: ' + target + '. Review the target scope in Workspace settings.');
        if (context.scopeNow) { const latest = await context.scopeNow(); for (const target of targets) if (!scopeAllows(target, latest)) throw Error('The workspace scope changed; target is outside current workspace scope: ' + target + '. Review target scope in Workspace settings.'); }
        const max = Math.min(run.config.maxRequests ?? Infinity, limits.maxRequests ?? Infinity);
        if (run.requestsSent >= max || group.requestsSent >= (limits.maxRequests ?? Infinity)) throw Error('Request budget exhausted.');
        const duration = Math.min(run.config.durationSeconds ?? Infinity, limits.durationSeconds ?? Infinity);
        if (now() - run.createdAt >= duration * 1000) throw Error('Duration budget exhausted.');
        return Math.min(run.config.maxRequestsPerSecond, limits.maxRequestsPerSecond ?? Infinity);
      };
      const dispatch = async () => {
        try {
          for (;;) {
            const rate = await check();
            const wait = group.lastRequestAt == null ? 0 : group.lastRequestAt + 1000 / rate - now();
            if (wait <= 0) break;
            await new Promise((resolve, reject) => { const abort = () => { clearTimeout(timer); reject(execution.controller.signal.reason); }; const timer = setTimeout(() => { execution.controller.signal.removeEventListener('abort', abort); resolve(); }, Math.min(wait, 2147483647)); execution.controller.signal.addEventListener('abort', abort, { once: true }); });
          }
          // The loop re-reads policy, scope, account revision and user limits after
          // every rate wait. Queued/cancelled work is not counted as dispatched.
          execution.controller.signal.throwIfAborted(); await context.recheck?.();
          if (request?.kind === 'raw_connect') {
            run.connectionAttempts = (run.connectionAttempts || 0) + 1;
            await persist(); return { runId: run.runId, connectionNumber: run.connectionAttempts };
          }
          run.requestsSent++; group.requestsSent++; group.lastRequestAt = now();
          if (request?.kind === 'dast_probe' || request?.kind === 'dast_baseline') {
            run.dastProbeDispatches ??= 0; run.dastBaselineDispatches ??= 0;
            if (request.kind === 'dast_probe') run.dastProbeDispatches++; else run.dastBaselineDispatches++;
          }
          if (request?.kind === 'raw_send') run.probeUnits = (run.probeUnits || 0) + 1;
          else run.httpRequestsSent = (run.httpRequestsSent || 0) + 1;
          await persist(); return { runId: run.runId, requestNumber: run.requestsSent };
        } catch (error) {
          if (/budget exhausted/.test(errorText(error))) { execution.controller.abort(error); queueMicrotask(() => stop(run.runId, context, errorText(error)).catch(() => {})); }
          throw error;
        } finally { run.requestsReserved--; await persist(); }
      };
      const task = (group.dispatchTail || Promise.resolve()).then(dispatch); group.dispatchTail = task.catch(() => {}); return task;
    };
  }
  async function start(args, context) {
    if (!context?.owner) throw Error('Choose a chat before starting security testing.');
    if (!Number.isInteger(args.tabId) || args.tabId < 0) throw Error('Select a target tab.');
    const engines = [...new Set(args.engines || ['DAST'])]; if (!engines.length || engines.some(engine => !['DAST', 'IAST', 'SAST', 'SCA'].includes(engine))) throw Error('Choose supported security engines.');
    settings = cleanSettings((await storage.get(SETTINGS_KEY))[SETTINGS_KEY] || settings);
    const config = resolveConfig(settings, context.workspaceId, args.options || {}), scope = validateScope(args.scope || context.scope);
    if (context.scope?.origins?.length && !scopeWithin(scope, context.scope)) throw Error('Run target scope exceeds the selected workspace: ' + scope.origins.join(', ') + (scope.matchMode === 'host' ? ' (same host' + (scope.includeSubdomains ? ' and subdomains' : '') + ')' : '') + '. Review target scope in Workspace settings.');
    if (context.scope?.excludePaths?.length) scope.excludePaths = [...new Set([...scope.excludePaths, ...context.scope.excludePaths])];
    await context.recheck?.(); context.signal?.throwIfAborted();
    const identity = JSON.stringify({ owner: context.owner, tabId: args.tabId, engines, config, scope, requests: args.requests || [], accountId: args.accountId || null });
    const duplicate = [...live.values()].find(item => item.identity === identity); if (duplicate) return { ...publicRun(runs.get(duplicate.runId)), reused: true };
    const run = { runId: uuid(), owner: context.owner, workspaceId: context.workspaceId || null, tabId: args.tabId, engines, state: 'starting', config, scope, accountId: args.accountId || null, accountRevision: context.account?.revision ?? null, createdAt: now(), updatedAt: now(), requestsSent: 0, coverage: {}, summary: {} };
    runs.set(run.runId, run);
    if (context.account) privateAccounts.set(run.runId, context.account);
    const groupKey = context.budgetGroup || context.owner, group = groups.get(groupKey) || { requestsSent: 0, nextRequestAt: 0, runs: new Set() }; group.runs.add(run.runId); groups.set(groupKey, group);
    const execution = { runId: run.runId, identity, groupKey, controller: new AbortController(), context }; live.set(run.runId, execution);
    const abort = () => { void stop(run.runId, context, 'Parent task cancelled.').catch(() => {}); };
    context.signal?.addEventListener('abort', abort, { once: true }); execution.unlink = () => context.signal?.removeEventListener('abort', abort);
    const runtimeContext = bindBackends(contextFor(run, { ...context, signal: execution.controller.signal, checkRequest: requestGuard(run, execution, context), withRequest: withRequest(run, execution, context), onProgress: async progress => { if (!ACTIVE.has(run.state)) return; await remember(run, { progress: copy(progress), coverage: copy(progress?.coverage || run.coverage) }); } }), context); execution.context = runtimeContext; execution.caller = context;
    await persist();
    try {
      if (config.durationSeconds != null) execution.timer = setTimeout(() => stop(run.runId, context, 'Configured duration reached.').catch(() => {}), Math.min(config.durationSeconds * 1000, 2147483647));
      if (context.prepare) {
        try { await context.prepare(runtimeContext); execution.controller.signal.throwIfAborted(); }
        catch (error) { error.admitted = false; throw error; }
      }
      const response = checked(await runtime.invoke('startScan', { ...copy(args), ...config, config, tabId: run.tabId, engines, scope, runId: run.runId }, runtimeContext));
      const runtimeId = idFrom(response); if (!runtimeId) throw Error('Security engine did not return a run identifier; inspect status before retrying.');
      await remember(run, { runtimeId, runtimeHandle: copy(response), state: runState(response), engineStatus: copy(response.engines), coverage: copy(response.coverage || {}), summary: copy(response.summary || {}) });
      if (!ACTIVE.has(run.state)) { await collect(run, context); release(run); }
      return ACTIVE.has(run.state) ? status(run.runId, context) : publicRun(run);
    } catch (error) {
      const refused = error?.admitted === false || error?.nativeResult?.admitted === false;
      await remember(run, { state: refused ? 'error' : 'unknown', error: errorText(error) });
      if (refused) release(run);
      throw Object.assign(Error(errorText(error)), { runId: run.runId });
    }
  }
  const ready = (async () => {
    const stored = await storage.get([SETTINGS_KEY, RUNS_KEY, EVIDENCE_KEY]); settings = cleanSettings(stored[SETTINGS_KEY] || {});
    if (privateStorage) for (const [id, value] of Object.entries((await privateStorage.get(PRIVATE_EVIDENCE_KEY))[PRIVATE_EVIDENCE_KEY] || {})) privateEvidence.set(id, value);
    for (const record of stored[RUNS_KEY] || []) if (record?.runId && record.owner) runs.set(record.runId, record);
    for (const [id, record] of Object.entries(stored[EVIDENCE_KEY] || {})) evidence.set(id, record);
    await runtime.ready;
    for (const run of runs.values()) if (ACTIVE.has(run.state)) {
      if (typeof runtime.recoverInterrupted === 'function' && run.runtimeId) {
        try {
          const recovery = await runtime.recoverInterrupted({ sessionId: run.runtimeId }, contextFor(run));
          if (recovery != null) {
            if (recovery.sessionId !== run.runtimeId) throw Error('Recovered evidence belongs to a different engine session.');
            let account;
            if (run.accountId && privateStorage) {
              const candidate = (await privateStorage.get('ki_authz_private')).ki_authz_private?.accounts?.[run.accountId];
              if (candidate?.workspaceId === run.workspaceId && run.accountRevision != null && candidate.revision === run.accountRevision) account = candidate;
            }
            if (run.accountId && !account) {
              privateEvidence.set(run.runId, { native: copy(recovery), capturedAt: now() });
              run.recoveryError = 'Recovered account evidence is retained privately; its original account revision is unavailable for a public export.';
            } else {
              const recovered = protect(recovery, run.runId, account ? { account } : {}), previous = evidence.get(run.runId) || {};
              const retained = new Map((previous.findings || []).map(item => [item.id || item.findingId || JSON.stringify(item), item]));
              for (const item of recovered.findings || []) retained.set(item.id || item.findingId || JSON.stringify(item), item);
              const findings = [...retained.values()];
              evidence.set(run.runId, { ...previous, findings, nativeFindings: { findings, recovered: true }, nativeEvidence: recovered, capturedAt: now(), recovered: true });
              run.summary = { ...(run.summary || {}), findings: findings.length }; run.recoveredEvidence = true;
            }
          }
        } catch (error) { run.recoveryError = errorText(error); }
      }
      // Never replay a start across worker recreation. Stop adopted work until the
      // original permission lease and per-dispatch budget can be re-established.
      try { if (run.runtimeId) await runtime.invoke('stopScan', argumentsFor(run), contextFor(run)); } catch {}
      run.state = 'interrupted'; run.error = 'Worker restarted. Previous evidence remains available; requests were not replayed.'; run.updatedAt = now();
    }
    if (runs.size) await persist();
  })();
  const service = {
    ready, runtime, operationSchemas: OPERATION_SCHEMAS,
    async localEvent(event) { await ready; const run = runs.get(event?.runId); if (!run || run.owner !== event.owner || !external.has(run.operation)) return false; if (event.type === 'lease_released') { await remember(run, { state: 'cancelled', stopReason: 'Local session closed.' }); release(run); } return true; },
    async localLost(error = 'Local executor disconnected.') { await ready; for (const run of runs.values()) if (external.has(run.operation) && ACTIVE.has(run.state)) { live.get(run.runId)?.controller.abort(Error(String(error))); await remember(run, { state: 'interrupted', error: String(error) }); release(run); } },
    hasRuns(owner) { return [...runs.values()].some(run => run.owner === owner); },
    async resolveConfig(workspaceId, options) { await ready; settings = cleanSettings((await storage.get(SETTINGS_KEY))[SETTINGS_KEY] || {}); return resolveConfig(settings, workspaceId, options); },
    async describe(context = {}) { await ready; return { ...copy(await runtime.describe()), configuration: await service.resolveConfig(context.workspaceId), presets: ['thorough', 'ptk-defaults'], acquisitionSupport: { SCA:'Resource/total content limits, preloaded script count and bounded drainTimeoutMs.', SAST:'Resource/total content limits before analysis and preloaded script count. Stop retains the native SAST timeout; acquisition.drainTimeoutMs is the SCA drain preference.' }, targetScope: { configured: !!context.scope?.origins?.length, scope: copy(context.scope || { origins: [], excludePaths: [] }), whenUnset: 'Use the explicitly selected target for each new operation.', matchingModes: { origin: 'Exact HTTP(S) origins', host: 'Same host across HTTP(S) and ports; optional subdomains' }, settings: 'Workspaces → Testing scope' } }; },
    async handle(op, args = {}, context = {}) {
      await ready;
      if (op === 'capabilities') return service.describe(context);
      if (op === 'settings') return cleanSettings((await storage.get(SETTINGS_KEY))[SETTINGS_KEY] || {});
      if (op === 'state') return { capabilities: await service.describe(context), settings: await service.handle('settings'), workspaceId: context.workspaceId || null, config: await service.resolveConfig(context.workspaceId), runs: [...runs.values()].filter(run => run.owner === context.owner).map(publicRun) };
      if (op === 'runs') {
        if (!context.owner) throw Error('Choose a chat to list its security runs.');
        const selected = [...runs.values()].filter(run => run.owner === context.owner).sort((a,b) => b.createdAt - a.createdAt);
        const result = page(selected, args.offset ?? 0, args.limit ?? 25);
        return { runs: result.items.map(run => ({ runId:run.runId, kind:run.kind || 'scan', engines:copy(run.engines), operation:run.operation || null, state:run.state, tabId:run.tabId, sourceRunId:run.sourceRunId || null, createdAt:run.createdAt, summary:copy(run.summary) })), total:result.total, nextOffset:result.nextOffset, referenceGuide:'For candidates and evidence packages, use the original scan runId. Reproduction executionRunId is a separate operation reference.' };
      }
      if (op === 'activity') {
        for (const run of runs.values()) if (run.owner === context.owner && run.tabId === args.tabId && run.engines.includes('IAST') && ACTIVE.has(run.state)) await remember(run, { activity: [...(run.activity || []), copy(args.action)].slice(-100) });
        return { recorded: true };
      }
      if (op === 'configure') {
        if (!context.userAction) throw Error('Only a direct settings action can change saved defaults or explicit limits.');
        const change = settingsWrites.then(async () => {
          const current = cleanSettings((await storage.get(SETTINGS_KEY))[SETTINGS_KEY] || {});
          let destination = current;
          if (args.scope === 'workspace') { if (!context.workspaceId || (args.workspaceId && args.workspaceId !== context.workspaceId)) throw Error('Select the workspace to configure.'); destination = current.workspaces[context.workspaceId] ||= { defaults: {}, limits: {} }; }
          else if (args.scope !== 'global' && args.scope != null) throw Error('Unknown settings scope.');
          if (Object.hasOwn(args, 'defaults')) { const changes = validateOptions(args.defaults); destination.defaults = { ...destination.defaults, ...changes, ...(changes.acquisition ? { acquisition: { ...destination.defaults?.acquisition, ...changes.acquisition } } : {}) }; }
          if (Object.hasOwn(args, 'limits')) { const changes = validateLimits(args.limits); destination.limits = { ...destination.limits, ...changes, ...(changes.acquisition ? { acquisition: { ...destination.limits?.acquisition, ...changes.acquisition } } : {}) }; }
          settings = cleanSettings(current); await storage.set({ [SETTINGS_KEY]: settings }); return { settings: copy(settings), config: resolveConfig(settings, context.workspaceId) };
        }); settingsWrites = change.catch(() => {}); return change;
      }
      if (op === 'start') { const operation = starts.then(() => start(args, context)); starts = operation.catch(() => {}); return operation; }
      if (op === 'status') return args.waitForIdle !== undefined || args.timeoutMs !== undefined ? waitForDastIdle(args, context) : status(args.runId, context);
      if (op === 'stop') return stop(args.runId, context);
      if (op === 'extend') {
        const run = owned(args.runId, context); if (!ACTIVE.has(run.state)) throw Error('Only an active observation can be extended.');
        const seconds = args.durationSeconds ?? 300; validateOptions({ durationSeconds: seconds });
        const durationSeconds = Math.max((now() - run.createdAt) / 1000, run.config.durationSeconds || 0) + seconds;
        const updated = await service.resolveConfig(run.workspaceId, { durationSeconds }); await context.recheck?.();
        run.config.durationSeconds = updated.durationSeconds; const execution = live.get(run.runId); if (!execution) throw Error('The original execution context is unavailable.');
        clearTimeout(execution.timer); execution.timer = setTimeout(() => stop(run.runId, context, 'Configured duration reached.').catch(() => {}), Math.min(Math.max(0, run.createdAt + durationSeconds * 1000 - now()), 2147483647));
        return remember(run, { config: run.config });
      }
      if (op === 'refresh') { const result = []; for (const run of runs.values()) if (ACTIVE.has(run.state)) result.push(await status(run.runId, { owner: run.owner })); return result; }
      if (op === 'revalidate') {
        const result = [];
        for (const run of runs.values()) if (ACTIVE.has(run.state)) {
          const execution = live.get(run.runId); if (!execution) continue;
          try {
            await execution.context.recheck?.();
            if (execution.context.scopeNow) {
              const scope = await execution.context.scopeNow();
              if (!scopeWithin(run.scope, scope) || (scope.excludePaths || []).some(path => !run.scope.excludePaths.includes(path))) throw Error('Target scope was restricted while testing.');
            }
            const config = await service.resolveConfig(run.workspaceId);
            if (run.engines.some(engine => ['SCA','SAST'].includes(engine)) && Object.entries(config.limits.acquisition || {}).some(([key, value]) => value != null && run.config.acquisition?.[key] > value)) throw Error('Acquisition limits were reduced. Partial evidence is retained; start a new scan with the current limits.');
            if (run.requestsSent >= (config.limits.maxRequests ?? Infinity) || now() - run.createdAt >= (config.limits.durationSeconds ?? Infinity) * 1000) throw Error('The explicit user testing budget was exhausted.');
          } catch (error) { result.push(await stop(run.runId, { owner: run.owner }, errorText(error))); }
        }
        return result;
      }
      if (op === 'findings' || op === 'evidence') {
        const run = owned(args.runId, context); if (ACTIVE.has(run.state) && run.kind !== 'operation') await collect(run, context);
        const saved = evidence.get(run.runId) || {}, values = saved.findings || [], result = page(values, args.offset ?? 0, args.limit ?? 50);
        if (op === 'evidence' && run.kind === 'operation') return { runId: run.runId, operation: run.operation, result: copy(saved.result), coverage: copy(run.coverage), state: run.state, error: run.error || null };
        if (op === 'evidence' && run.runtimeId) {
          const available = (await runtime.describe()).operations || [];
          if (available.some(item => (typeof item === 'string' ? item : item.id || item.name) === 'getEvidence')) {
            try { const native = checked(protect(await runtime.invoke('getEvidence', argumentsFor(run, { evidenceId: args.evidenceId, offset: args.offset, limit: args.limit }), contextFor(run, context)), run.runId, context)); evidence.set(run.runId, { ...saved, nativeEvidence: copy(native) }); await persist(); return { runId: run.runId, ...copy(native), coverage: copy(run.coverage) }; }
            catch (error) { if (!saved.nativeFindings) throw error; run.evidenceError = 'Live evidence unavailable: ' + errorText(error); }
          }
        }
        if (op === 'evidence' && args.evidenceId != null) { const finding = values.find(item => String(item.id || item.findingId) === String(args.evidenceId)); if (!finding) throw Error('This finding is not retained.'); return { runId: run.runId, finding: copy(finding), coverage: copy(run.coverage) }; }
        return { runId: run.runId, findings: copy(result.items), total: result.total, nextOffset: result.nextOffset, truncated: saved.truncated === true, summary: copy(run.summary), selectedEngines: copy(run.engines), coverage: copy(run.coverage),
          requestBudget: { used:run.requestsSent, limit:run.config?.maxRequests ?? null, exhausted:run.config?.maxRequests != null && run.requestsSent >= run.config.maxRequests },
          error: run.evidenceError || run.recoveryError || null, ...(op === 'evidence' ? { native: copy(saved.nativeEvidence || saved.nativeFindings) } : {}) };
      }
      if (op === 'export') {
        const run = owned(args.runId, context); await context.recheck?.();
        const format = args.format || 'json'; if (!['json', 'pdf', 'markdown'].includes(format)) throw Error('Unsupported report format.');
        if (args.options?.preset && !['technical', 'executive'].includes(args.options.preset)) throw Error('Unknown report preset.');
        let native; try { native = checked(protect(await runtime.invoke('exportFullReport', argumentsFor(run, { format, options: copy(args.options || {}) }), contextFor(run, { ...context, reportRun: { runId: run.runId, state: run.state, config: copy(run.config), coverage: actionableCoverage(run.coverage, run) }, transformReport: value => protect(value, run.runId, context) })), run.runId, context)); } catch (error) { if (format !== 'json' || !evidence.has(run.runId)) throw error; native = { unavailable: errorText(error), retainedEvidence: copy(evidence.get(run.runId)) }; }
        if (format !== 'json' && native.artifact?.format !== format) throw Error('The engine did not produce the requested ' + format + ' artifact.');
        return { run: publicRun(run), report: { schema: 'cert-x-security-report/v1', run: publicRun(run), native, evidence: copy(evidence.get(run.runId) || {}) }, ...(native.artifact ? { artifact: copy(native.artifact) } : {}), warnings: native.unavailable ? [native.unavailable] : [] };
      }
      if (op === 'execute') {
        if (!context.owner) throw Error('Choose a chat before executing security operations.');
        const capability = args.capability; if (typeof capability !== 'string') throw Error('Select a security capability.');
        const description = await runtime.describe(), available = description.operations || description.capabilities || [];
        const entry = available.find(item => (typeof item === 'string' ? item : item.id || item.name) === capability);
        if (!entry || ['startScan', 'scanStatus', 'stopScan', 'getFindings', 'exportFullReport'].includes(capability)) throw Error('Use the declared security operation for this capability.');
        await context.recheck?.(); context.signal?.throwIfAborted();
        const config = await service.resolveConfig(context.workspaceId, args.options || {});
        const input = copy(args.arguments || {}), tabId = args.tabId ?? input.tabId;
        if (capability === 'browser' && !OPERATION_SCHEMAS.browser.schema.properties.action.enum.includes(input.action)) {
          throw Error('Unsupported browser action. Use security_candidates for candidate reproduction and job status/stop. No local operation was sent.');
        }
        if (capability === 'candidate' && ['status','stop'].includes(input.action) && !input.executionRunId) {
          throw Error('Candidate job status/stop requires executionRunId from reproduce; keep the source scan runId separately. No local operation was sent.');
        }
        if (capability === 'browser' && !['create','list','reopen'].includes(input.action) && !input.runId) {
          throw Error('Browser follow-ups require the original runId returned by create/reopen (or listed with the session). No local operation was sent.');
        }
        validateOperationSelection(capability, input);
        // Follow-ups retain the original operation lease and budget. A source
        // scan runId for candidates is handled separately below.
        if (external.has(capability) && (capability==='candidate'?input.executionRunId:input.runId)) {
          const prior = owned(capability==='candidate'?input.executionRunId:input.runId, context); if (prior.operation !== capability) throw Error('This run belongs to a different security capability.');
          if (capability === 'browser') {
            if (!['create','reopen'].includes(prior.action)) throw Error('Use the browser session runId returned by create/reopen.');
            if (input.sessionId && prior.runtimeHandle?.sessionId && input.sessionId !== prior.runtimeHandle.sessionId) throw Error('Browser session does not match the original runId. No local operation was sent.');
          }
          if (['stop', 'close', 'cleanup'].includes(input.action)) return stop(prior.runId, context, undefined, input.action);
          const execution = live.get(prior.runId);
          if (!execution && !['status','events','export','findings','evidence','getJob','readArtifact'].includes(input.action)) throw Error('The original execution lease ended. Reopen or create a new operation explicitly.');
          const resumed = contextFor(prior, {...context, ...(prior.sourceRunId?{sourceRun:publicRun(owned(prior.sourceRunId,context))}:{}),checkRequest:async request=>{if(request?.kind!=='control')throw Error('The original execution lease ended; target requests require a new operation.');await context.recheck?.();return {control:true,runId:prior.runId};}});
          bindBackends(resumed,context);
          // Keep the original accounting lease, but never borrow the previous
          // action's approval. Each follow-up gets its own permission context;
          // concurrent calls cannot overwrite one another's approval flags.
          const activeContext={...(execution?.context||resumed),permissionApproved:context.permissionApproved===true,userAction:context.userAction===true,currentActionApproval:{approved:context.permissionApproved===true,userAction:context.userAction===true},toolCallId:context.toolCallId};
          bindBackends(activeContext,context);
          if (prior.result?.connectionId && context.resolveConnection) activeContext.oastConnection=await context.resolveConnection(prior.result.connectionId);
          await activeContext.recheck?.();
          const result = checked(protect(await runtime.invoke(capability, externalArguments(prior, input.action, input), activeContext), prior.runId, activeContext));
          evidence.set(prior.runId, { operation: capability, result: copy(result), capturedAt: now() }); await remember(prior, { result: copy(result), state: runState(result, prior.state) }); if(!ACTIVE.has(prior.state))release(prior);
          return { ...copy(result), runId: prior.runId };
        }
        let sourceRun;
        if (['candidate','evidencePackage'].includes(capability) || capability === 'utility' && input.tool === 'api_explorer' && input.runId) { sourceRun = owned(input.runId, context); if (!sourceRun.runtimeId) throw Error('This run has no native scan evidence.'); input.sessionId = sourceRun.runtimeId; if (!context.scope?.origins?.length) context.scope = copy(sourceRun.scope); }
        if (['macro', 'capture'].includes(capability) && input.action === 'stop') {
          const existing = [...runs.values()].find(run => run.owner === context.owner && run.kind === 'operation' && run.operation === capability && ACTIVE.has(run.state) && (tabId == null || run.tabId === tabId));
          if (existing) return stop(existing.runId, context);
        }
        const run = { runId: uuid(), kind: 'operation', operation: capability, action: input.action || null, ...(sourceRun?{sourceRunId:sourceRun.runId}:{}),owner: context.owner, workspaceId: context.workspaceId || null, tabId, engines: [], scope: copy(context.scope || { origins: [], excludePaths: [] }), config, state: 'starting', createdAt: now(), updatedAt: now(), requestsSent: 0, summary: {}, coverage: {} };
        runs.set(run.runId, run);
        const groupKey = context.budgetGroup || context.owner, group = groups.get(groupKey) || { requestsSent: 0, nextRequestAt: 0, runs: new Set() }; group.runs.add(run.runId); groups.set(groupKey, group);
        const execution = { runId: run.runId, groupKey, controller: new AbortController(), context }; live.set(run.runId, execution);
        const abort = () => execution.controller.abort(context.signal.reason || Error('Parent task cancelled.')); context.signal?.addEventListener('abort', abort, { once: true }); execution.unlink = () => context.signal?.removeEventListener('abort', abort);
        const runtimeContext = bindBackends(contextFor(run, { ...context, ...(sourceRun ? { sourceRun: publicRun(sourceRun) } : {}), signal: execution.controller.signal, checkRequest: requestGuard(run, execution, context), withRequest: withRequest(run, execution, context) }), context); execution.context = runtimeContext; execution.caller = context;
        await persist();
        try {
          execution.controller.signal.throwIfAborted();
          execution.pending = Promise.resolve(runtime.invoke(capability, input, runtimeContext));
          const result = checked(protect(await execution.pending, run.runId, context));
          const staysActive = result.persistent === true || result.active === true || capability === 'capture' && result.active === true || capability === 'macro' && ['record','replay','start'].includes(input.action);
          evidence.set(run.runId, { operation: capability, result: copy(result), capturedAt: now() });
          await remember(run, { state: staysActive ? 'running' : 'completed', summary: { operation: capability }, result: copy(result), ...(external.has(capability) ? { runtimeHandle: copy(result), operationArguments: retainedArguments(input) } : {}) });
          if (!staysActive) release(run);
          return { ...copy(result), runId: run.runId };
        } catch (error) { if (error.nativeResult) evidence.set(run.runId, { operation: capability, result: error.nativeResult, capturedAt: now() }); await remember(run, { state: execution.controller.signal.aborted ? 'cancelled' : 'error', ...(execution.controller.signal.aborted ? {} : { error: errorText(error) }) }); release(run); throw Object.assign(error, { runId: run.runId }); }
      }
      throw Error('Unknown security operation.');
    },
  };
  return service;
}

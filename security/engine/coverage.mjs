// Recovery guidance is authored here, never derived as instructions from target content.
const ACTIVE = new Set(['starting', 'running', 'stopping']);
export function actionableCoverage(coverage = {}, { runId, engines = [], state } = {}) {
  const items = new Map();
  const add = (code, engine, summary, action, detail) => {
    const key = engine + ':' + code;
    const item = items.get(key) || { code, engine, summary, sampledOccurrences: 0, retryUnchanged: false, recovery: action, examples: [] };
    item.sampledOccurrences++;
    if (detail && item.examples.length < 3) item.examples.push(detail);
    items.set(key, item);
  };
  const browse = { action: 'exercise_workflow', instruction: 'Browse the relevant application workflow in the target tab, then inspect this run with security_scan_status. Do not start duplicate scans.' };
  const inspect = { action: 'inspect_error', instruction: 'Inspect the retained error or skip and correct its prerequisite before retrying. Preserve partial evidence in the report.' };
  for (const failure of (coverage.engineFailures || []).slice(0, 4)) add('engine_error', failure.engine || 'Run', 'The selected engine did not finish successfully.', inspect, { error: failure.error });
  const phase = coverage.dast?.phase;
  if (['error', 'unknown', 'interrupted', 'incomplete'].includes(state)) add('execution_incomplete', 'Run', 'This run did not establish complete execution.', { action: 'inspect_run', tool: 'security_scan_status', instruction: 'Inspect this run and its retained evidence before retrying. Resolve the failure or report the untested work; never infer a clean result from missing findings.' });
  if (['waiting_for_interaction', 'waiting_for_requests', 'no_requests'].includes(phase)) add('no_application_requests', 'DAST', 'No qualifying application requests were tested.', browse);
  if (['waiting_for_attackable_inputs', 'no_executed_probes', 'no_active_probes', 'passive_execution'].includes(phase)) add('no_active_probe_coverage', 'DAST', 'A page or baseline was captured, but active probe coverage is absent.', { ...browse, instruction: 'Exercise forms or API workflows with attackable inputs. Inspect selected modules and task skips; do not repeatedly restart an unchanged scan.' });
  if (['partial_error', 'probing_with_errors', 'engine_error'].includes(phase)) add('engine_error', 'DAST', 'Execution errors left testing incomplete.', inspect, { error: coverage.dast?.error || coverage.dast?.lastTaskError });
  if (['limited_by_skips', 'probing_with_skips'].includes(phase)) add('skipped_checks', 'DAST', 'Some selected checks did not execute.', inspect, { reason: coverage.dast?.lastTaskSkip });
  if (!ACTIVE.has(state) && coverage.dast?.plannedMinusEntered > 0) add('planned_tasks_not_entered', 'DAST', 'The planner count exceeds tasks entered at stop; selected testing was not fully accounted as executed.',
    { action:'inspect_run', instruction:'Compare planned, entered, strategy-skipped and error counts. This difference is not an exact number of unsent HTTP requests; report the measured gap without calling the scan complete.' },
    { planned:coverage.dast.tasksPlanned, entered:coverage.dast.tasksExecuted, difference:coverage.dast.plannedMinusEntered });
  if (phase === 'dispatch_attribution_unknown') add('dispatch_attribution_unknown', 'DAST', 'Request counts cannot be attributed to DAST.', { action: 'inspect_evidence', instruction: 'Use retained request/response evidence; do not count other engines’ traffic as DAST probes.' });

  const classify = reason => {
    if (/drain|barrier|timeout/.test(reason)) return ['drain_incomplete', 'Capture did not finish before its stop deadline.', { action: 'adjust_acquisition', option: 'acquisition.drainTimeoutMs', instruction: 'Keep partial evidence. If needed, use a longer drain timeout on a new run and repeat only the affected workflow explicitly.' }];
    if (/budget|limit|too_large|oversiz|truncat|capacity/.test(reason)) return ['acquisition_limit', 'An acquisition limit excluded content.', { action: 'adjust_acquisition', option: 'acquisition', instruction: 'Inspect effective acquisition limits and shared capture capacity. Raise the relevant preference within user ceilings, or narrow the workflow; do not bypass explicit limits.' }];
    if (/401|403|auth/.test(reason)) return ['authentication_required', 'A resource could not be acquired under the current identity.', { action: 'verify_account', instruction: 'Verify the intended account in this browser session, restore login if needed, then repeat only the affected workflow.' }];
    if (/scope/.test(reason)) return ['outside_scope', 'A resource or frame was outside the selected scope.', { action: 'review_scope', instruction: 'Compare the missing origin with the authorized workspace targets. Correct scope only when authorized; otherwise retain the exclusion in the report.' }];
    if (/owner|revok|document|navigat|session|detach|context/.test(reason)) return ['document_unavailable', 'The resource document or capture ownership changed.', { action: 'reacquire_document', instruction: 'Inspect the current target tab and account. Start a new run for that document if needed; never borrow a body from a different document or account.' }];
    if (/debugger|protocol|source_unavailable|child_sources/.test(reason)) return ['source_unavailable', 'Loaded script acquisition was unavailable.', { action: 'inspect_browser_resource', instruction: 'Check the target frame and debugger owner. Finish conflicting browser work or explicitly revisit the workflow under capture; do not detach another consumer.' }];
    return ['resource_unavailable', 'Some resource content was not analyzed.', { action: 'inspect_resource', instruction: 'Inspect the resource URL, status, MIME type and acquisition reason. Revisit the affected route under capture if appropriate; report unsupported or unavailable content as a gap.' }];
  };
  if (coverage.sast) {
    const { acquisition, preloaded, preloadedAcquisition } = coverage.sast;
    if (preloaded?.originalHtmlUnavailable) add('original_html_unavailable', 'SAST', 'Preloaded scripts were inspected without the original HTML response.', { action:'exercise_workflow', instruction:'Keep the client-script findings. If original-HTML checks matter, revisit that route while the same scan is active. Browser SAST cannot inspect server-side source.' });
    const missing = acquisition?.missingResources || [];
    for (const item of missing.slice(0, 20)) add('source_acquisition_partial', 'SAST', 'A client source was unavailable for analysis.', { action:'inspect_resource', instruction:'Inspect the missing URL and acquisition reason. Verify the browser identity and revisit the affected route if useful; retain findings from sources already analyzed.' }, {url:item.url,reason:item.reason});
    if ((acquisition?.sourceGaps > 0 || preloadedAcquisition?.gaps > 0) && !missing.length) add('source_acquisition_partial', 'SAST', 'Client-source collection was partial.', inspect, {reason:acquisition?.reasons || 'preloaded_source_acquisition_incomplete'});
    for (const warning of (coverage.sast.sourceWarnings || []).slice(0, 20)) {
      const limited = /acquisition_.*limit/.test(warning.reason || '');
      add(limited ? 'acquisition_limit' : 'source_acquisition_partial', 'SAST', limited ? 'A client-source acquisition limit was reached.' : 'A client-source batch was incomplete.', limited ? {action:'adjust_acquisition',option:'acquisition',instruction:'Inspect effective acquisition limits and retained evidence. Adjust preferences within user ceilings or narrow the workflow; do not silently bypass limits.'} : {action:'inspect_resource',instruction:'Inspect the retained document and missing-script references; preserve successful analysis and revisit only the affected workflow if needed.'}, {url:warning.documentUrl || warning.url,reason:warning.reason,documentId:warning.documentId,missingScripts:warning.missingScripts,...(warning.limit ? {limit:warning.limit} : {})});
    }
    if (preloaded && preloaded.analyzedScripts === 0 && !acquisition?.capturedDocuments) add('no_client_source_analyzed', 'SAST', 'No client-source analysis was established.', {action:'exercise_workflow',instruction:'Inspect source-acquisition diagnostics and visit the relevant application route while scanning. Do not infer a clean client-code assessment from no findings.'});
  }
  for (const warning of (coverage.scaBodyWarnings || []).slice(0, 50)) {
    const reason = String(warning?.reason || 'unknown');
    const [code, summary, recovery] = classify([401, 403].includes(warning?.status) ? 'response_status_' + warning.status : reason);
    add(code, 'SCA', summary, recovery, { reason, ...(warning?.status ? { status: warning.status } : {}), url: warning?.url || null, documentId: warning?.documentId || null });
  }
  if (coverage.scaAcquisition?.drain?.complete === false && !items.has('SCA:drain_incomplete')) {
    const [code, summary, recovery] = classify('capture_drain_incomplete');
    add(code, 'SCA', summary, recovery, { reason: coverage.scaAcquisition.drain.reason || 'capture_drain_incomplete' });
  }
  if (engines.includes('SCA') && (coverage.scaBodies || coverage.scaSources)) {
    const analyzed = (coverage.scaBodies?.analyzed || 0) + (coverage.scaSources?.analyzed || 0);
    if (!analyzed) add('no_content_analyzed', 'SCA', 'No JavaScript content has been analyzed.', { action: 'exercise_workflow', instruction: 'Verify login and browse routes that load application scripts. Inspect acquisition warnings; URI matches alone cannot establish a negative content assessment.' });
    const gaps = (coverage.scaBodies?.gaps || 0) + (coverage.scaSources?.gaps || 0);
    if (gaps && !(coverage.scaBodyWarnings || []).length) add('resource_unavailable', 'SCA', 'Acquisition reported gaps without retained resource details.', inspect);
  }
  const gaps = [...items.values()];
  return { ...coverage, actionableGaps: gaps, recovery: { runId: runId || null, state: ACTIVE.has(state) ? 'in_progress' : gaps.length ? 'incomplete' : 'reported_checks_finished',
    instruction: gaps.length ? 'Address applicable recovery steps or include unresolved gaps in the final report. Do not repeat unchanged failed calls.' : 'Assess only the checks and evidence actually recorded; absence of reported gaps is not proof of full application coverage.' } };
}

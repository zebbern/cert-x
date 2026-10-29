// Summarize comparable real-model investigations without treating alert counts
// or the model's prose as independently verified vulnerabilities.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const files = process.argv.slice(2);
assert.ok(files.length >= 2, 'Pass at least two retained live-model evidence JSON paths.');
const runs = files.map(file => {
  const absolute = path.resolve(file), e = JSON.parse(fs.readFileSync(absolute, 'utf8'));
  assert.equal(e.kind, 'live_model');
  const scan = (e.runs || []).find(run => run.engines?.includes('DAST')) || null;
  const requests = e.requests || [], toolCalls = requests.flatMap(request => request.toolCalls || []);
  const paths = [...new Set((e.traffic || []).map(item => {
    try { return new URL(item.url).pathname.match(/^\/vulnerabilities\/([^/]+)\//)?.[1] || null; } catch { return null; }
  }).filter(Boolean))].sort();
  const report = e.reportPath && fs.existsSync(e.reportPath) ? fs.readFileSync(e.reportPath, 'utf8') : '';
  const requestLimit = scan?.config?.maxRequests ?? null, requestsSent = scan?.requestsSent ?? null;
  return {
    evidence: absolute, arm:e.arm, model:e.model, target:e.target, prompt:e.prompt,
    bounds:e.limits,
    completed:e.terminalReason === 'model_stop' && !!report, terminalReason:e.terminalReason,
    elapsedSeconds:Math.round((Date.parse(e.finishedAt) - Date.parse(e.liveStartedAt)) / 1000),
    providerRequests:requests.length, parentProviderRequests:requests.filter(item=>item.parent!==false).length, delegatedProviderRequests:requests.filter(item=>item.parent===false).length,
    providerLatencySeconds:Math.round(requests.reduce((sum, item) => sum + (item.providerLatencyMs || 0), 0) / 1000),
    toolCalls:toolCalls.length, toolSchemaBytes:requests[0]?.advertisedToolBytes ?? null,
    browserRequests:(e.traffic || []).length, browserPosts:(e.traffic || []).filter(item => item.method === 'POST').length,
    routes:paths, scan:scan && { runId:scan.runId, state:scan.state, engines:scan.engines, requestsSent, requestLimit,
      requestBudgetExhausted:requestLimit != null && requestsSent >= requestLimit,
      tasksPlanned:scan.coverage?.dast?.tasksPlanned ?? null, tasksEntered:scan.coverage?.dast?.tasksExecuted ?? null,
      taskSkips:scan.coverage?.dast?.taskSkips ?? null, rawAlerts:scan.summary?.findings ?? null,
      rawAlertsByModule:scan.summary?.byModule || {} },
    reportChars:report.length, retainedErrors:(e.errors || []).length
  };
});
assert.ok(runs.every(run => run.model === runs[0].model), 'Comparison arms must use the same model.');
assert.ok(runs.every(run => run.prompt === runs[0].prompt), 'Comparison arms must use the same task prompt.');
const comparableBounds = value => Object.fromEntries(['modelRequests','durationMs','toolIdleTimeoutMs','scanRequests','scanRate','scanConcurrency','planningConcurrency'].map(key => [key,value?.[key] ?? null]));
assert.ok(runs.every(run => JSON.stringify(comparableBounds(run.bounds)) === JSON.stringify(comparableBounds(runs[0].bounds))), 'Comparison arms must use the same evaluation bounds.');
console.log(JSON.stringify({ comparison:'observed_execution_only', model:runs[0].model, runs }, null, 2));

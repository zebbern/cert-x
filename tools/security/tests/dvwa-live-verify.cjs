// Historical composed-outcome validator for the output-truncated 19:09 run.
// Autonomous command/report follow-up uses command-report-live-verify.cjs.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const file=path.resolve(process.argv[2]),e=JSON.parse(fs.readFileSync(file,'utf8'));
const calls=e.requests.flatMap(r=>r.toolCalls||[]),forTool=name=>e.toolResults.filter(r=>calls.some(c=>c.id===r.id&&c.name===name)).at(-1)?.result;
const status=forTool('security_scan_status'),findings=forTool('security_get_findings')?.findings||[],completionFile=file.replace(/\.json$/,'.report-completion.json');
const completion=JSON.parse(fs.readFileSync(completionFile,'utf8')),report=fs.readFileSync(completion.report,'utf8');
const checks={};const check=(name,condition)=>{checks[name]=!!condition;assert.ok(condition,name)};
check('actual_selected_model',e.kind==='live_model'&&e.model==='xiaomi/mimo-v2.6-flash'&&e.setup.scriptedScan===false&&e.setup.scriptedInteractions===false);
check('provider_responses_retained',e.requests.every(r=>r.httpStatus===200&&r.settled&&r.sseDone));
const input=(module,field)=>e.traffic.some(r=>{const u=new URL(r.url);return u.pathname===`/vulnerabilities/${module}/`&&(u.searchParams.has(field)||new URLSearchParams(r.body||'').has(field))});
for(const [module,field] of [['xss_r','name'],['sqli','id'],['exec','ip']])check('submitted_'+module,input(module,field));
check('model_started_and_stopped_scan',calls.some(c=>c.name==='security_start_scan')&&calls.some(c=>c.name==='security_stop_scan'));
check('queued_work_completed',status?.state==='completed'&&status.coverage.dast.tasksExecuted===status.coverage.dast.tasksPlanned&&status.coverage.dast.taskErrors===0&&status.coverage.dast.taskSkips===0&&status.coverage.dast.probeDispatches>0);
check('non_header_findings',findings.some(f=>f.moduleId==='xss'||/^xss_/.test(f.ruleId||''))&&findings.some(f=>/^sqlinjection_/.test(f.ruleId||'')));
check('full_export_retained',e.downloads.some(d=>fs.existsSync(d.path)&&fs.statSync(d.path).size===d.bytes&&crypto.createHash('sha256').update(fs.readFileSync(d.path)).digest('hex')===d.sha256));
check('same_model_narrative_completed',completion.model===e.model&&completion.sourceEvidence===file&&completion.finishReason==='stop'&&report.includes(status.runId));
check('report_keeps_coverage_and_uncertainty',/Module.*input.*result/i.test(report)&&/scanner candidates/i.test(report)&&/dvwa\.users/.test(report)&&/not independently confirmed/i.test(report)&&/not 11 distinct vulnerabilities/i.test(report));
check('bounds_retained',e.requests.length<=40&&e.requests.every(r=>r.usage.completion_tokens<=1200)&&status.requestsSent<=240&&completion.usage.completion_tokens<=1200&&completion.accountedTotalUSD<=.5);
check('no_database_reset',!e.traffic.some(r=>new URL(r.url).pathname==='/setup.php'));
const result={checks,scanAndNativeExportComplete:true,uninterruptedNarrativeInChat:e.requests.at(-1).finishReason==='stop',narrativeRequiredReportOnlyContinuation:true,scanRunId:status.runId,probeDispatches:status.coverage.dast.probeDispatches,baselineDispatches:status.coverage.dast.baselineDispatches,rawAlerts:findings.length,report:completion.report,exports:e.downloads,accountedTotalUSD:completion.accountedTotalUSD};
fs.writeFileSync(file.replace(/\.json$/,'.verified.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result));

// Verify the requested command-detection and autonomous-report outcome. Retain
// narrative-quality issues separately; never rewrite the original model report.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const file=path.resolve(process.argv[2]),e=JSON.parse(fs.readFileSync(file,'utf8'));
const calls=e.requests.flatMap(r=>r.toolCalls||[]),forTool=name=>e.toolResults.filter(r=>calls.some(c=>c.id===r.id&&c.name===name)).at(-1)?.result;
const stopped=forTool('security_stop_scan'),found=forTool('security_get_findings'),findings=found?.findings||[],report=fs.readFileSync(e.reportPath,'utf8');
const command=findings.find(f=>f.moduleId==='os_command_injection'),attack=command?.evidence?.dast?.meta?.attacked;
const checks={},check=(name,value)=>{checks[name]=!!value;assert.ok(value,name)};
check('actual_selected_model',e.kind==='live_model'&&e.model==='xiaomi/mimo-v2.6-flash');
check('no_scripted_scan_or_interactions',e.setup.scriptedScan===false&&e.setup.scriptedInteractions===false);
check('no_followup_or_report_continuation',e.setup.midRunPrompts===false&&e.setup.separateReportContinuation===false&&e.requests.every(r=>r.userMessageCount===e.requests[0].userMessageCount)&&!fs.existsSync(file.replace(/\.json$/,'.report-completion.json')));
check('model_finished_original_chat',e.terminalReason==='model_stop'&&e.requests.at(-1).finishReason==='stop'&&report===e.requests.at(-1).text);
check('command_detection_from_exact_input',command?.ruleId==='oscommand_inband_pipe_passwd'&&attack?.location==='form'&&attack.name==='ip'&&attack.after==='127.0.0.1|/bin/cat /etc/passwd'&&/root:.*:0:0:/.test(command.evidence.dast.proof)&&!attack.after.includes(command.evidence.dast.proof));
const wire=e.browserRequests?.events||[],request=wire.find(r=>r.phase==='request'&&r.method==='POST'&&new URL(r.url).pathname==='/vulnerabilities/exec/'&&r.formData?.ip?.includes(attack.after));
check('browser_sent_repaired_probe_and_received_response',request&&wire.some(r=>r.phase==='complete'&&r.requestId===request.requestId&&r.statusCode===200));
check('native_queue_wait_used',calls.some(c=>c.name==='security_scan_status'&&JSON.parse(c.arguments).waitForIdle===true));
check('scan_stopped_and_report_exported',stopped&&['completed','incomplete','cancelled'].includes(stopped.state)&&calls.some(c=>c.name==='security_export_report')&&e.downloads.some(d=>fs.statSync(d.path).size===d.bytes&&crypto.createHash('sha256').update(fs.readFileSync(d.path)).digest('hex')===d.sha256));
check('report_contains_command_evidence_and_limits',report.includes(stopped.runId)&&report.includes(command.evidence.dast.proof)&&/budget/i.test(report)&&/incomplete/i.test(report)&&/candidate/i.test(report));
check('bounds',e.requests.length<=40&&e.requests.every(r=>r.usage?.completion_tokens<=4096)&&stopped.requestsSent<=240&&e.accountedCostUSD<=.5);
const byModule={};for(const f of findings)byModule[f.moduleId]=(byModule[f.moduleId]||0)+1;
const qualityIssues=[];
if(/XSS reflected\*\* \(10|10 findings on `name`/.test(report)&&byModule.xss!==10)qualityIssues.push('Narrative says10 XSS alerts; retained evidence contains'+byModule.xss+'.');
if(/No IAST\/SAST\/SCA\/ZAP\/OAST \(not configured\)/.test(report))qualityIssues.push('Narrative conflates unselected IAST/SAST/SCA with unconfigured optional backends.');
const result={checks,runId:stopped.runId,byModule,total:findings.length,report:e.reportPath,narrativeQualityIssues:qualityIssues,uninterruptedNarrativeInChat:true,requests:stopped.requestsSent,skipped:stopped.coverage.dast.taskSkips,outputTokens:e.requests.at(-1).usage.completion_tokens,modelRequests:e.requests.length};
fs.writeFileSync(file.replace(/\.json$/,'.command-verified.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result));

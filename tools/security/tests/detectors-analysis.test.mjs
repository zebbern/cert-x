import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { createRequire } from 'node:module';
import { sastEngine } from '../../../security/ptk/background/sast/sastEngine.js';

const root = new URL('../../../', import.meta.url);
const sastPack = JSON.parse(await fs.readFile(new URL('security/ptk/background/sast/modules/modules.json', root), 'utf8'));
const iastPack = JSON.parse(await fs.readFile(new URL('security/ptk/background/iast/modules/modules.json', root), 'utf8'));
// Explicit code fixtures exercise each imported module through the complete
// Acorn/taint/pattern/reporting pipeline, not copied detection predicates.
const sastFixtures = {
  'dom-xss': ['document.body.innerHTML = location.hash;', 'document.body.textContent = location.hash;'],
  'cookie-manipulation': ['document.cookie = location.hash;', 'const previous = document.cookie;'],
  'open-redirection': ['window.open(location.hash);', 'const target = new URL("/account", location.origin);'],
  'javascript-injection': ['setTimeout("console.log(1)", 1);', 'setTimeout(() => console.log(1), 1);'],
  'angularjs-expression-injection': ['$parse(location.search);', 'const expression = 1 + 1;'],
  'client-template-injection': ['Handlebars.compile(location.hash);', 'Handlebars.compile("constant template");'],
  'network-destination-poisoning': ['navigator.sendBeacon(location.hash, "value");', 'const endpoint = "/api";'],
  'client-script-loader-poisoning': ['$.getScript(location.hash);', 'const script = "/fixed.js";'],
  'web-message': ['window.postMessage(location.hash, "*");', 'window.postMessage("constant", "https://app.test");'],
  'link-manipulation': ['document.querySelector("a").href = location.hash;', 'const link = document.querySelector("a").href;'],
  'dom-data-manipulation': ['document.querySelector("input").value = location.hash;', 'const value = document.querySelector("input").value;'],
};
test('every installed SAST module has an explicit execution fixture', () => assert.deepEqual(Object.keys(sastFixtures).sort(), sastPack.modules.map(module => module.id).sort()));
for (const [id, [positive, negative]] of Object.entries(sastFixtures)) test('SAST detection and negative control: ' + id, async () => {
  const run = async code => new sastEngine(0, { allowFetchPageSourceScripts: false }).scanCodeDetailed([{ src: 'https://app.test/fixture.js', code }], '', 'https://app.test/');
  const hit = (await run(positive)).findings.filter(finding => finding.module_metadata?.id === id);
  const clean = (await run(negative)).findings.filter(finding => finding.module_metadata?.id === id);
  assert.ok(hit.length, id + ' positive did not execute its detector'); assert.equal(clean.length, 0, id + ' negative produced a finding');
  assert.ok(hit.every(finding => finding.metadata?.id && finding.codeSnippet), 'Findings must retain rule and source evidence');
});

// These fixtures exercise the real runtime rule selection, source filtering,
// heuristics and report pipeline. Their source observations are explicit inputs;
// browser hook acquisition is independently exercised by browser-parity.cjs.
const iastFixtures = [
 ['iast_dom_xss','dom_inline_event_handler','dom.inline_event','query','globalThis.CERT_X_PROBE=1'],
 ['iast_dangerous_url_scheme_execution','href_javascript_url_execution','dom.attr.href.javascriptUrl','query','javascript:globalThis.CERT_X_PROBE=1'],
 ['iast_js_execution','eval_js_execution','code.eval','query','globalThis.CERT_X_PROBE=1'],
 ['iast_open_redirect','window_open_redirect','nav.window.open','query','https://outside.test/landing'],
 ['iast_angularjs_expression_injection','angularjs_expression_function_constructor','code.function.constructor','query','return 7*7'],
 ['iast_postmessage_misuse','postmessage_star_origin_leak','postmessage.anyOrigin','query','CERT_X_PRIVATE_MESSAGE'],
 ['iast_timer_js_execution','settimeout_string_execution','code.setTimeout','query','globalThis.CERT_X_PROBE=1'],
 ['iast_iframe_navigation','iframe_src_redirect','nav.iframe.src','query','https://outside.test/landing'],
 ['iast_client_http_exfiltration','fetch_url_exfiltration','http.fetch.url','query','https://outside.test/collect?value=CERT_X_PROBE'],
 ['iast_dom_link_manipulation','dom_attr_href_navigation','dom.attr.href','query','https://outside.test/landing'],
 ['iast_dom_url_navigation','location_href_redirect','nav.location.href','query','https://outside.test/landing'],
 ['iast_dom_parser_xss','domparser_parsefromstring_html_xss','dom.domParser.parseFromString','query','<img src=x onerror="globalThis.CERT_X_PROBE=1">'],
 ['iast_dom_xss_secondary_sources','dom_innerhtml_xss_secondary_sources','dom.innerHTML','localStorage','<img src=x onerror="globalThis.CERT_X_PROBE=1">'],
 ['iast_route_controlled_navigation','route_pushstate_navigation','nav.history.pushState','clientRoute','/accounts/CERT_X_PROBE'],
 ['iast_form_submission_hijack','form_action_hijack','dom.attr.action','query','https://outside.test/submit'],
 ['iast_dangerous_form_scheme_execution','form_action_javascript_url_execution','dom.attr.action.javascriptUrl','query','javascript:globalThis.CERT_X_PROBE=1'],
 ['iast_response_field_dom_reachability','response_dom_innerhtml_reachability','dom.innerHTML','apiResponseField','<img src=x onerror="globalThis.CERT_X_PROBE=1">'],
 ['iast_prototype_pollution_impact','prototype_pollution_write','runtime.prototype.pollution.write','jsonBodyField','CERT_X_PROTOTYPE_VALUE'],
 ['iast_storage_taint_to_exec','eval_storage_taint_execution','code.eval','localStorage','globalThis.CERT_X_PROBE=1'],
 ['iast_source_scoped_open_redirect','location_href_redirect_sources','nav.location.href','query','https://outside.test/landing'],
];
let browser, server, origin, instrumented;
before(async () => {
 const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
 server=http.createServer((_request,response)=>{response.setHeader('Content-Type','text/html');response.end('<!doctype html><html><body><div id="sink"></div></body></html>');});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
 browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA,'ms-playwright/chromium-1234/chrome-win64/chrome.exe')});
 const source=await fs.readFile(new URL('security/ptk/content/iast.js',root),'utf8'),end=source.lastIndexOf('})();');assert.ok(end>0);
 // Expose functions only in this isolated fixture. No production instrumentation
 // or detector logic is changed by the test harness.
 instrumented=source.slice(0,end)+'globalThis.__certXDetector = { initIastRuleIndex, maybeReportTaintedValue, setIastScanStrategy };\n'+source.slice(end);
});
after(async()=>{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));});
test('every installed IAST module has an explicit observed-source fixture',()=>assert.deepEqual(iastFixtures.map(row=>row[0]).sort(),iastPack.modules.map(module=>module.id).sort()));
for(const [id,ruleId,sinkId,sourceKind,value] of iastFixtures) test('IAST runtime detection and untainted control: '+id,async()=>{
 const context=await browser.newContext(),page=await context.newPage();
 try {
  await page.goto(origin+'/fixture');
  await page.evaluate(()=>{window.__PTK_IAST_AGENT_AUTHORIZED__=true;window.__certXObserved=[];window.addEventListener('ptk:iast:page-to-content:v1',event=>{try{const message=JSON.parse(event.detail);window.__certXObserved.push(message);}catch{}});});
  await page.addScriptTag({content:instrumented});
  const module=iastPack.modules.find(entry=>entry.id===id);
  const result=await page.evaluate(({module,ruleId,sinkId,sourceKind,value})=>{
   const api=window.__certXDetector;api.setIastScanStrategy('COMPREHENSIVE');api.initIastRuleIndex({schema:'ptk-iast-rulepack/v1',engine:'IAST',version:1,modules:[module]},{scanStrategy:'COMPREHENSIVE'});
   const extra={requestUrl:'https://outside.test/landing',destUrl:'https://outside.test/landing',framework:'AngularJS',angularService:'$parse',mimeType:'text/html',attribute:'href',targetOrigin:'*'};
   const negative=api.maybeReportTaintedValue('CERT_X_UNTAINTED_CONSTANT',{sinkId,ruleId,sink:sinkId},extra);
   const negativeFindings=window.__certXObserved.filter(message=>message.ptk_iast==='finding_report'&&message.finding?.moduleId===module.id);
   const source={key:sourceKind+':fixture',sourceKind,raw:value,value,label:'fixture input',sourceId:'fixture-source',origin:{kind:'fixture'}};
   const positive=api.maybeReportTaintedValue(value,{sinkId,ruleId,sink:sinkId},extra,{raw:value,source,allSources:[source]});
   const findings=window.__certXObserved.filter(message=>message.ptk_iast==='finding_report'&&message.finding?.moduleId===module.id).map(message=>message.finding);
   return {positive,negative,negativeCount:negativeFindings.length,findings,debug:window.__PTK_IAST_LAST_REPORT_DEBUG__};
  },{module,ruleId,sinkId,sourceKind,value});
  assert.equal(result.negative,false,id+' reported untainted input');assert.equal(result.positive,true,id+' positive rejected: '+JSON.stringify(result.debug));
  assert.equal(result.negativeCount,0);assert.ok(result.findings.some(finding=>finding.ruleId===ruleId&&finding.sinkId===sinkId&&finding.matched===value),'The actual reporting pipeline must emit the matching rule, sink and value');
 } finally {await context.close();}
});

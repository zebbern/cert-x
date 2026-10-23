// End-to-end report export from real native SAST findings through Downloads and Outputs.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http'), cp = require('node:child_process'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-security-reporting-'));
let browser, server;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const normalized = value => String(value).replace(/\\([^\w\s])/g, '$1').replace(/\s+/g, ' ').toLowerCase();
async function main() {
  server = http.createServer((req, res) => {
    if (req.url.startsWith('/report.js')) { res.setHeader('Content-Type', 'application/javascript'); return res.end('function render(){document.getElementById("sink").innerHTML=new URLSearchParams(location.search).get("q")||"fixture";} document.querySelector("button").onclick=render; render();'); }
    res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>Report export fixture</title><button>Render</button><div id="sink"></div><script src="/report.js"></script>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); const origin = 'http://127.0.0.1:' + server.address().port;
  const profile = path.join(temp, 'profile'), downloads = path.join(temp, 'downloads'); fs.mkdirSync(path.join(profile, 'Default'), { recursive: true }); fs.mkdirSync(downloads);
  fs.writeFileSync(path.join(profile, 'Default/Preferences'), JSON.stringify({ download: { default_directory: downloads, prompt_for_download: false } }));
  browser = await chromium.launchPersistentContext(profile, { headless: true, downloadsPath: downloads, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker', { timeout: 15000 }); await worker.evaluate(async () => { await certXSecurity.ready; await certXSecurityCompatibilityReady; });
  const extensionId = new URL(worker.url()).host, session = 'native-reporting';
  const settings = await browser.newPage(); await settings.goto('chrome-extension://' + extensionId + '/providers/providers.html?section=security&session=' + session); await settings.waitForFunction(() => !document.querySelector('main').inert);
  const raw = (op, args = {}) => settings.evaluate(message => chrome.runtime.sendMessage(message), { type: 'KI_SECURITY', op, session, ...args });
  const call = async (op, args = {}) => { const reply = await raw(op, args); assert.equal(reply?.ok, true, JSON.stringify(reply)); return reply.result; };
  const assigned = await settings.evaluate(session => chrome.runtime.sendMessage({ type: 'KI_CONTEXT', op: 'assign_chat', session, profileId: 'bugbounty', modelExplicit: null }), session); assert.equal(assigned.ok, true);
  const target = await browser.newPage(); await target.goto(origin + '/app?q=report-marker');
  const tabId = (await worker.evaluate(() => chrome.tabs.query({}))).find(tab => tab.url === origin + '/app?q=report-marker').id;
  const run = await call('start', { tabId, engines: ['SAST'], options: { preset: 'ptk-defaults' } }); assert.ok(run.runId);
  await target.reload(); await target.getByRole('button', { name: 'Render', exact: true }).click();
  let detected;
  for (let attempt = 0; attempt < 50; attempt++) { detected = await call('findings', { runId: run.runId, limit: 100 }); if (detected.findings?.length) break; await sleep(250); }
  assert.ok(detected.findings?.length, 'The report fixture must produce real SAST findings.');
  await call('stop', { runId: run.runId });
  const final = await call('findings', { runId: run.runId, limit: 100 });
  const names = final.findings.flatMap(finding => [finding.title, finding.ruleName, finding.moduleId]).filter(value => typeof value === 'string' && value.length >= 4);
  assert.ok(names.length); const results = [];
  for (const [format, preset] of [['json', null], ['markdown', null], ['pdf', 'technical'], ['pdf', 'executive']]) {
    const exported = await call('export', { runId: run.runId, format, ...(preset ? { options: { preset } } : {}) }); assert.equal(exported.reports?.length, 1, JSON.stringify(exported));
    const report = exported.reports[0], download = (await worker.evaluate(id => chrome.downloads.search({ id }), report.downloadId))[0];
    assert.equal(download.state, 'complete'); assert.ok(path.resolve(download.filename).startsWith(path.resolve(temp) + path.sep));
    const bytes = fs.readFileSync(download.filename); assert.equal(bytes.length, report.size); assert.ok(bytes.length > 100);
    const mime = { json: 'application/json', markdown: 'text/markdown', pdf: 'application/pdf' }[format];
    assert.ok(download.url.startsWith('data:' + mime + ';base64,'));
    let text, pages = null;
    if (format === 'json') { const value = JSON.parse(bytes.toString('utf8')); assert.equal(value.schema, 'cert-x-security-report/v1'); assert.equal(value.run.runId, run.runId); assert.equal(value.evidence.findings.length, final.findings.length); text = JSON.stringify(value); }
    else if (format === 'markdown') { text = bytes.toString('utf8'); assert.match(text, /^#/m); }
    else {
      assert.equal(bytes.subarray(0, 5).toString('ascii'), '%PDF-');
      const parsed = JSON.parse(cp.execFileSync(process.env.PYTHON_PATH || 'python', ['-c', 'import json,sys; from pypdf import PdfReader; r=PdfReader(sys.argv[1]); print(json.dumps({"pages":len(r.pages),"text":"\\n".join(p.extract_text() or "" for p in r.pages)}))', download.filename], { encoding: 'utf8', windowsHide: true, timeout: 20000 }));
      assert.ok(parsed.pages >= 1); pages = parsed.pages; text = parsed.text;
    }
    assert.ok(names.some(name => normalized(text).includes(normalized(name))), 'Exported ' + format + ' ' + (preset || '') + ' must contain an actual finding name: ' + JSON.stringify({ names, text: text.slice(0, 1200) }));
    const outputs = await settings.evaluate(session => chrome.runtime.sendMessage({ type: 'KI_WORKSPACE', op: 'outputs', session }), session); assert.equal(outputs.ok, true);
    const output = outputs.result.find(item => item.downloadId === download.id); assert.ok(output); assert.equal(output.owner, session); assert.equal(output.mime, mime); assert.equal(output.size, bytes.length);
    results.push({ format, preset, bytes: bytes.length, pages, findingPresent: true, outputOwned: true });
  }
  const prior = (await worker.evaluate(() => chrome.downloads.search({}))).length;
  const invalid = await raw('export', { runId: run.runId, format: 'html' }); assert.equal(invalid.ok, false); assert.match(invalid.error, /format/i);
  assert.equal((await worker.evaluate(() => chrome.downloads.search({}))).length, prior, 'An unsupported format must not download another artifact');
  console.log(JSON.stringify({ singleExtension: true, realSastFindings: final.findings.length, reports: results, unknownFormatRejected: true }));
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  await browser?.close(); if (server) await new Promise(resolve => server.close(resolve));
  const absolute = path.resolve(temp); if (absolute.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(absolute).startsWith('cert-x-security-reporting-')) fs.rmSync(absolute, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

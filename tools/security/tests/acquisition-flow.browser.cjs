// Real service -> runtime -> automation -> capture limits -> persisted report.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-acquisition-flow-'));
const wire = [], evidenceFile = path.join(root, 'tools/security/evidence/acquisition-flow-browser.json');
let server, browser;
async function main() {
  const angular = fs.readFileSync(path.join(__dirname, 'fixtures/angular/angular-1.1.5.min.js'));
  server = http.createServer((req, res) => {
    wire.push(req.url); res.setHeader('Cache-Control', 'no-store');
    if (req.url === '/asset.js') { res.setHeader('Content-Type', 'application/javascript'); return res.end(angular); }
    if (req.url === '/favicon.ico') { res.writeHead(204); return res.end(); }
    res.setHeader('Content-Type', 'text/html');res.end('<!doctype html><title>Acquisition flow</title><script src="/asset.js"></script>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launchPersistentContext(path.join(temp, 'profile'), { headless: true, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
  await worker.evaluate(async () => { await certXSecurity.ready; await chrome.storage.local.set({ ki_security_settings: { version: 1, defaults: { acquisition: { drainTimeoutMs: 9000 } }, limits: { acquisition: { maxResourceBytes: 1024 } } } }); });
  const page = await browser.newPage(); await page.goto(origin + '/app'); await page.waitForLoadState('load');
  const tabId = await worker.evaluate(async url => (await chrome.tabs.query({})).find(tab => tab.url === url).id, page.url());
  const context = { owner: 'acquisition-flow', scope: { origins: [origin], excludePaths: [] } };
  const started = await worker.evaluate(({ tabId, context }) => certXSecurity.handle('start', { tabId, engines: ['SCA'], options: { acquisition: { maxScripts: 256 }, engineOptions: { SCA: { acquisition: { maxResourceBytes: 8388608 } } } } }, context), { tabId, context });
  const acquisition = await worker.evaluate(tabId => ptk_app.sca.captureLeases.get(tabId).acquisition, tabId);
  assert.equal(acquisition.maxResourceBytes, 1024, 'Partial per-run settings and engineOptions cannot overwrite inherited ceilings');
  assert.equal(acquisition.maxScripts, 256);assert.equal(acquisition.drainTimeoutMs, 9000);
  assert.equal(started.coverage.scaAcquisition.limits.effective.maxResourceBytes, 1024);
  const ended = await worker.evaluate(({ runId, context }) => certXSecurity.handle('stop', { runId }, context), { runId: started.runId, context });
  assert.equal(ended.state, 'incomplete');assert.ok(ended.coverage.actionableGaps.length);assert.equal(ended.coverage.scaAcquisition.drain.complete, true);
  const report = await worker.evaluate(({ runId, context }) => certXSecurity.handle('export', { runId, format: 'markdown' }, context), { runId: started.runId, context });
  const renderedText = report.artifact.text.replace(/\\([\\`*_{}\[\]()#+\-.!|>])/g, '$1');
  assert.equal(report.artifact.format, 'markdown');
  assert.match(renderedText, /Coverage and remaining gaps/);assert.ok(renderedText.includes(started.runId));assert.match(renderedText, /State: incomplete/);assert.match(renderedText, /resource bytes 1024/);
  assert.equal(wire.filter(url => url === '/asset.js').length, 1, 'Missing content never causes an anonymous refetch');
  const saved = await worker.evaluate(async runId => (await chrome.storage.local.get('ki_security_runs')).ki_security_runs.find(run => run.runId === runId), started.runId);
  assert.equal(saved.state, 'incomplete');assert.equal(saved.config.acquisition.maxResourceBytes, 1024);
  fs.writeFileSync(evidenceFile, JSON.stringify({ acquisition, runId: started.runId, state: ended.state, coverage: ended.coverage, report: report.artifact.text, wire }, null, 2));
  console.log(JSON.stringify({ evidenceFile, inheritedCeilingEnforced: true, partialOverridePreserved: true, reportGaps: true, persisted: true, requests: wire.length }));
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  await browser?.close(); if (server) await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
  const resolved = fs.realpathSync(temp); assert.ok(resolved.startsWith(fs.realpathSync(os.tmpdir()) + path.sep) && path.basename(resolved).startsWith('cert-x-acquisition-flow-')); fs.rmSync(resolved, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

// Preloaded executable source acquisition in an authenticated local browser fixture.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-sca-preloaded-'));
const evidenceFile = path.join(root, 'tools/security/evidence/sca-preloaded-browser.json');
const angular = fs.readFileSync(path.join(__dirname, 'fixtures/angular/angular-1.1.5.min.js'), 'utf8');
const wire = [], cases = [];
let server, browser;
async function main() {
  server = http.createServer((req, res) => {
    const account = req.headers.cookie?.match(/fixture_account=(a|b)/)?.[1] || 'anonymous';
    wire.push({ url: req.url, account });
    res.setHeader('Cache-Control', 'no-store');
    if (req.url.startsWith('/login/')) { res.writeHead(302, { 'Set-Cookie': `fixture_account=${req.url.slice(-1)}; HttpOnly; Path=/`, Location: '/app' }); return res.end(); }
    if (req.url === '/favicon.ico') { res.writeHead(204); return res.end(); }
    if (req.url === '/opaque/asset.js' || req.url === '/opaque/fetch' || req.url === '/opaque/xhr') {
      res.setHeader('Content-Type', 'application/javascript');
      if (account === 'anonymous') { res.writeHead(401); return res.end('/* login required */'); }
      return res.end(account === 'a' ? angular : 'globalThis.cleanAccountLibrary = true;');
    }
    res.setHeader('Content-Type', 'text/html');
    res.end('<!doctype html><title>Preloaded SCA</title><script src="/opaque/asset.js"></script>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launchPersistentContext(path.join(temp, 'profile'), { headless: true,
    executablePath: require('../../chromium-path.cjs'),
    args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
  await worker.evaluate(async () => certXSecurity.ready);
  const page = await browser.newPage();
  for (const account of ['a', 'b', 'anonymous']) {
    await browser.clearCookies();
    await page.goto(origin + (account === 'anonymous' ? '/app' : `/login/${account}`));
    await page.waitForLoadState('load');
    const tabId = await worker.evaluate(async url => (await chrome.tabs.query({})).find(tab => tab.url === url).id, page.url());
    const context = { owner: 'sca-preloaded', tabId, scope: { origins: [origin], excludePaths: [] }, config: { preset: 'ptk-defaults' } };
    const before = wire.length;
    const started = await worker.evaluate(async ({ tabId, context }) => certXSecurity.runtime.invoke('startScan', { tabId, engines: ['SCA'], options: context.config }, context), { tabId, context });
    assert.ok(started.sessionId, JSON.stringify(started));
    await page.evaluate(async () => {
      await fetch('/opaque/fetch').then(response => response.text());
      await new Promise(resolve => { const xhr = new XMLHttpRequest(); xhr.open('GET', '/opaque/xhr'); xhr.onloadend = resolve; xhr.send(); });
    });
    await worker.evaluate(async ({ sessionId, context }) => certXSecurity.runtime.invoke('stopScan', { sessionId }, context), { sessionId: started.sessionId, context });
    const scan = await worker.evaluate(() => JSON.parse(JSON.stringify(ptk_app.sca.scanResult)));
    const extraReads = wire.slice(before).filter(item => item.url === '/opaque/asset.js');
    const liveReads = wire.slice(before).filter(item => item.url === '/opaque/fetch' || item.url === '/opaque/xhr');
    const findings = (scan.findings || []).filter(item => item.evidence?.sca?.component?.detection === 'filecontent'
      && item.evidence.sca.component.name === 'angularjs');
    cases.push({ account, findings: findings.length, bodyCoverage: scan.scaBodyCoverage,
      sourceCoverage: scan.scaSourceCoverage, acquisitions: [...new Set(findings.map(item => item.evidence.sca.acquisition))],
      extraReads, liveReads, warnings: scan.coverageWarnings || [] });
    assert.equal(extraReads.length, 0, 'SCA must not reread a preloaded resource');
    assert.deepEqual(liveReads.map(item => item.url).sort(), ['/opaque/fetch', '/opaque/xhr']);
    if (account === 'a') {
      assert.ok(findings.length > 0, 'Preloaded Angular must produce content findings');
      assert.equal(scan.scaSourceCoverage.analyzed, 1);
      assert.equal(scan.scaBodyCoverage.analyzed, 2, 'Extensionless JavaScript Fetch/XHR must be admitted after MIME arrives');
      assert.ok(findings.every(item => item.evidence.sca.acquisitions?.includes('debugger_script_source')
        && item.evidence.sca.acquisitions?.includes('captured_http_body')));
    } else assert.equal(findings.length, 0, 'Replacement account/document must not borrow A source');
  }
  fs.writeFileSync(evidenceFile, JSON.stringify({ fixture: 'Real AngularJS 1.1.5 preloaded at opaque URL, HttpOnly account cookie', cases, wire }, null, 2));
  console.log(JSON.stringify({ evidenceFile, cases }));
}
main().catch(error => { fs.writeFileSync(evidenceFile, JSON.stringify({ error: error.stack, cases, wire }, null, 2)); console.error(error); process.exitCode = 1; })
  .finally(async () => { await browser?.close(); if (server) await new Promise(resolve => server.close(resolve));
    assert.ok(path.resolve(temp).startsWith(path.resolve(os.tmpdir()) + path.sep));
    fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); });

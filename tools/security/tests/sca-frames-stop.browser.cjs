// Preloaded executable source acquisition in an authenticated local browser fixture.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:https'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-sca-frames-stop-'));
const evidenceFile = path.join(root, 'tools/security/evidence/sca-frames-stop-browser.json');
const angular = fs.readFileSync(path.join(__dirname, 'fixtures/angular/angular-1.1.5.min.js'), 'utf8');
const wire = [], cases = [];
let server, browser, origin, crossOrigin, slowSeen;
async function main() {
  const { createSetup } = require('../../host/security/setup.cjs');
  const modules = await createSetup({ root: path.join(process.env.LOCALAPPDATA, 'cert-x/security-runtime') }).componentPath('node');
  const forge = require(path.join(modules, 'node-forge')), keys = forge.pki.rsa.generateKeyPair(2048), certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey; certificate.serialNumber = '01';
  certificate.validity.notBefore = new Date(Date.now() - 1000); certificate.validity.notAfter = new Date(Date.now() + 3600000);
  certificate.setSubject([{ name: 'commonName', value: 'localhost' }]); certificate.setIssuer(certificate.subject.attributes);
  certificate.setExtensions([{ name: 'keyUsage', digitalSignature: true, keyEncipherment: true }, { name: 'extKeyUsage', serverAuth: true }]);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  const cert = { key: forge.pki.privateKeyToPem(keys.privateKey), pem: forge.pki.certificateToPem(certificate) };
  server = http.createServer({ key: cert.key, cert: cert.pem }, (req, res) => {
    const account = req.headers.cookie?.match(/fixture_account=(a|b)/)?.[1] || 'anonymous';
    wire.push({ url: req.url, account });
    res.setHeader('Cache-Control', 'no-store');
    if (req.url.startsWith('/login/')) { res.writeHead(302, { 'Set-Cookie': `fixture_account=${req.url.slice(-1)}; HttpOnly; Path=/`, Location: '/app' }); return res.end(); }
    if (req.url === '/slow.js') { res.setHeader('Content-Type', 'application/javascript'); res.write('/* pending */'); slowSeen?.(); return setTimeout(() => res.end(angular), 500); }
    if (req.url === '/favicon.ico') { res.writeHead(204); return res.end(); }
    if (/^\/opaque\/(?:asset|frame|cross|nested)\.js$/.test(req.url) || req.url === '/opaque/fetch' || req.url === '/opaque/xhr') {
      res.setHeader('Content-Type', 'application/javascript');
      if (account === 'anonymous') { res.writeHead(401); return res.end('/* login required */'); }
      return res.end(account === 'a' ? angular : 'globalThis.cleanAccountLibrary = true;');
    }
    res.setHeader('Content-Type', 'text/html');
    const scripts = { '/app': '/opaque/asset.js', '/frame': '/opaque/frame.js', '/cross': '/opaque/cross.js', '/nested': '/opaque/nested.js' };
    const frames = req.url === '/app' ? '<iframe src="/frame"></iframe>'
      : req.url === '/frame' ? `<iframe src="${crossOrigin}/cross"></iframe>`
      : req.url === '/cross' ? '<iframe src="/nested"></iframe>' : '';
    res.end(`<!doctype html><title>Frame SCA</title><script src="${scripts[req.url] || '/opaque/asset.js'}"></script>${frames}`);
  });
  await new Promise(resolve => server.listen(0, '0.0.0.0', resolve));
  origin = `https://127.0.0.1:${server.address().port}`; crossOrigin = `https://localhost:${server.address().port}`;
  browser = await chromium.launchPersistentContext(path.join(temp, 'profile'), { headless: true, ignoreHTTPSErrors: true,
    executablePath: require('../../chromium-path.cjs'),
    args: ['--site-per-process', '--disable-extensions-except=' + root, '--load-extension=' + root] });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
  await worker.evaluate(async () => certXSecurity.ready);
  await worker.evaluate(() => {
    globalThis.captureNativeTrace = [];
    const nativeSend = chrome.debugger.sendCommand.bind(chrome.debugger);
    chrome.debugger.sendCommand = (source, method, params, callback) => nativeSend(source, method, params, result => {
      if (/enable|disable|setAutoAttach/.test(method)) captureNativeTrace.push({ at: Date.now(), command: method, source, params, error: chrome.runtime.lastError?.message });
      callback?.(result);
    });
    chrome.debugger.onEvent.addListener((source, method, params) => {
      if (method.startsWith('Target.') || method === 'Page.frameNavigated' || method === 'Page.frameDetached') captureNativeTrace.push({ at: Date.now(), source, method, params });
    });
    chrome.debugger.onDetach.addListener((source, reason) => captureNativeTrace.push({ at: Date.now(), source, detach: reason }));
  });
  const page = await browser.newPage();
  for (const account of ['a', 'b', 'anonymous']) {
    await browser.clearCookies();
    if (account !== 'anonymous') await browser.addCookies([{ name: 'fixture_account', value: account, url: crossOrigin, httpOnly: true, sameSite: 'None', secure: true }]);
    await page.goto(origin + (account === 'anonymous' ? '/app' : `/login/${account}`));
    await page.waitForLoadState('load');
    const tabId = await worker.evaluate(async url => (await chrome.tabs.query({})).find(tab => tab.url === url).id, page.url());
    const context = { owner: 'sca-preloaded', tabId, scope: { origins: [origin, crossOrigin], excludePaths: [] }, config: { preset: 'ptk-defaults' } };
    await worker.evaluate(async tabId => {
      const agent = __certXSecurityResources.forOwner('fixture-browser');
      await agent.debugger.attach({ tabId }, '1.3');
      await agent.debugger.sendCommand({ tabId }, 'Runtime.enable');
    }, tabId);
    const before = wire.length;
    const started = await worker.evaluate(async ({ tabId, context }) => certXSecurity.runtime.invoke('startScan', { tabId, engines: ['SCA'], options: context.config }, context), { tabId, context });
    assert.ok(started.sessionId, JSON.stringify(started));
    const acquisition = await worker.evaluate(tabId => ptk_app.sca.captureLeases.get(tabId).executedSourceResult, tabId);
    if (!(acquisition.sessionsInspected >= 2)) cases.push({ account, acquisition, native: await worker.evaluate(async () => ({ trace: captureNativeTrace, targets: await chrome.debugger.getTargets() })), capture: await worker.evaluate(tabId => { const s = ptk_app.browserCaptureManager.adapter.tabs.get(tabId); return { frames: [...s.frames.values()], children: [...s.children], childStates: [...s.childStates.values()].map(c => ({ sessionId: c.sessionId, ready: c.ready, revoked: c.revoked })) }; }, tabId) });
    assert.ok(acquisition.sessionsInspected >= 2, 'Cross-site fixture must acquire an OOPIF session');
    await page.evaluate(async () => {
      await fetch('/opaque/fetch').then(response => response.text());
      await new Promise(resolve => { const xhr = new XMLHttpRequest(); xhr.open('GET', '/opaque/xhr'); xhr.onloadend = resolve; xhr.send(); });
    });
    await worker.evaluate(async ({ sessionId, context }) => certXSecurity.runtime.invoke('stopScan', { sessionId }, context), { sessionId: started.sessionId, context });
    const scan = await worker.evaluate(() => JSON.parse(JSON.stringify(ptk_app.sca.scanResult)));
    const agentStillLive = await worker.evaluate(async tabId => {
      const agent = __certXSecurityResources.forOwner('fixture-browser');
      const result = await agent.debugger.sendCommand({ tabId }, 'Runtime.evaluate', { expression: '6 * 7', returnByValue: true });
      await agent.debugger.detach({ tabId }); return result.result.value;
    }, tabId);
    assert.equal(agentStillLive, 42, 'Stopping SCA must preserve another browser owner');
    const extraReads = wire.slice(before).filter(item => item.url === '/opaque/asset.js');
    const liveReads = wire.slice(before).filter(item => item.url === '/opaque/fetch' || item.url === '/opaque/xhr');
    const findings = (scan.findings || []).filter(item => item.evidence?.sca?.component?.detection === 'filecontent'
      && item.evidence.sca.component.name === 'angularjs');
    cases.push({ account, acquisition, drain: scan.scaDrain, findings: findings.length, bodyCoverage: scan.scaBodyCoverage,
      sourceCoverage: scan.scaSourceCoverage, acquisitions: [...new Set(findings.map(item => item.evidence.sca.acquisition))],
      extraReads, liveReads, warnings: scan.coverageWarnings || [] });
    assert.equal(scan.scaDrain.complete, true);
    assert.equal(extraReads.length, 0, 'SCA must not reread a preloaded resource');
    assert.deepEqual(liveReads.map(item => item.url).sort(), ['/opaque/fetch', '/opaque/xhr']);
    if (account === 'a') {
      assert.ok(findings.length > 0, 'Preloaded Angular must produce content findings');
      assert.equal(scan.scaSourceCoverage.analyzed, 4, 'Root, nested same-site, OOPIF and nested OOPIF document sources');
      assert.equal(scan.scaBodyCoverage.analyzed, 2, 'Extensionless JavaScript Fetch/XHR must be admitted after MIME arrives');
      assert.ok(findings.some(item => item.evidence.sca.acquisitions?.includes('debugger_script_source')));
      assert.ok(findings.some(item => item.evidence.sca.acquisitions?.includes('captured_http_body')));
    } else assert.equal(findings.length, 0, 'Replacement account/document must not borrow A source');
  }
  await browser.clearCookies();
  await page.goto(origin + '/login/a');
  const tabId = await worker.evaluate(async url => (await chrome.tabs.query({})).find(tab => tab.url === url).id, page.url());
  const context = { owner: 'sca-stop-timeout', tabId, scope: { origins: [origin, crossOrigin], excludePaths: [] }, config: { preset: 'ptk-defaults', acquisition: { maxScripts: 1, drainTimeoutMs: 75 } } };
  const started = await worker.evaluate(async ({ tabId, context }) => certXSecurity.runtime.invoke('startScan', { tabId, engines: ['SCA'], options: context.config }, context), { tabId, context });
  const requestSeen = new Promise(resolve => { slowSeen = resolve; });
  await page.evaluate(() => { fetch('/slow.js').then(response => response.text()).catch(() => {}); });
  await requestSeen;
  await worker.evaluate(async ({ sessionId, context }) => certXSecurity.runtime.invoke('stopScan', { sessionId }, context), { sessionId: started.sessionId, context });
  const limited = await worker.evaluate(() => JSON.parse(JSON.stringify(ptk_app.sca.scanResult)));
  cases.push({ case: 'limited-diagnostic', drain: limited.scaDrain, limits: limited.scaAcquisitionLimits, sourceCoverage: limited.scaSourceCoverage, warnings: limited.coverageWarnings });
  assert.equal(limited.scaDrain.complete, false);
  assert.equal(limited.scaDrain.reason, 'capture_drain_timeout');
  assert.ok(limited.coverageWarnings.some(item => item.reason === 'script_source_limit'));
  assert.ok(limited.findings.length > 0, 'Partial acquired source evidence survives stop timeout');
  cases.push({ case: 'limited-sources-and-stop-timeout', drain: limited.scaDrain, sourceCoverage: limited.scaSourceCoverage, warnings: limited.coverageWarnings, findings: limited.findings.length });
  fs.writeFileSync(evidenceFile, JSON.stringify({ fixture: 'Nested same-site/OOPIF preloaded Angular; immediate stop after Fetch/XHR loadend; account isolation', cases, wire }, null, 2));
  console.log(JSON.stringify({ evidenceFile, cases }));
}
main().catch(error => { fs.writeFileSync(evidenceFile, JSON.stringify({ error: error.stack, cases, wire }, null, 2)); console.error(error); process.exitCode = 1; })
  .finally(async () => { await browser?.close(); if (server) await new Promise(resolve => server.close(resolve));
    assert.ok(path.resolve(temp).startsWith(path.resolve(os.tmpdir()) + path.sep));
    fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); });



// Full extension -> security service -> PTK DAST contract. Localhost only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');

const root = path.resolve(__dirname, '../../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-dast-start-'));
const events = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let browser, server;

async function main() {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://fixture');
    if (url.pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      events.push({ method: req.method, url: req.url, body, at: Date.now() });
      const q = req.method === 'POST' ? new URLSearchParams(body).get('q') : url.searchParams.get('q');
      const escaped = String(q || '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end('<!doctype html><title>DAST fixture</title><div>' + (url.pathname === '/safe' ? escaped : q || '') + '</div>');
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const profile = path.join(temp, 'profile'), downloads = path.join(temp, 'downloads');
  fs.mkdirSync(path.join(profile, 'Default'), { recursive: true }); fs.mkdirSync(downloads);
  fs.writeFileSync(path.join(profile, 'Default/Preferences'), JSON.stringify({ download: { default_directory: downloads, prompt_for_download: false } }));
  browser = await chromium.launchPersistentContext(profile, {
    headless: true, downloadsPath: downloads,
    executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),
    args: ['--disable-extensions-except=' + root, '--load-extension=' + root]
  });
  const cert = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
  await cert.evaluate(() => globalThis.certXSecurityCompatibilityReady);
  await cert.evaluate(() => chrome.storage.local.set({ sidepanel_language: 'en', sidepanel_theme: 'dark', sidepanel_approval_mode: 'full_access' }));
  const session = 'dast-start-fixture', workspaceId = 'dast-start-workspace';
  const settings = await browser.newPage();
  await settings.goto('chrome-extension://' + new URL(cert.url()).host + '/providers/providers.html?section=dast&session=' + session);
  await settings.waitForFunction(() => !document.querySelector('main').inert);
  const raw = message => settings.evaluate(message => chrome.runtime.sendMessage(message), message);
  const call = async (op, args = {}) => {
    const reply = await raw({ type: 'KI_SECURITY', op, session, ...args });
    assert.equal(reply?.ok, true, op + ': ' + JSON.stringify(reply));
    return reply.result;
  };
  const scope = { origins: [origin], excludePaths: [] };
  assert.equal((await raw({ type: 'KI_CONTEXT', op: 'save_workspace', workspace: { id: workspaceId, name: 'DAST start fixture', profileId: 'bugbounty', dastScope: scope } })).ok, true);
  assert.equal((await raw({ type: 'KI_CONTEXT', op: 'assign_chat', session, workspaceId, profileId: 'bugbounty', modelExplicit: null })).ok, true);
  const page = await browser.newPage();
  await page.goto(origin + '/reflect?q=baseline');
  await sleep(500);
  const tab = (await call('tabs')).find(item => item.url === origin + '/reflect?q=baseline');
  assert.ok(tab, 'fixture target tab');
  const options = preset => ({ preset, moduleIds: ['xss'], runCve: false, maxRequests: 30, maxRequestsPerSecond: 10, concurrency: 1, planningConcurrency: 1, durationSeconds: 45 });
  const terminal = async runId => {
    let value;
    for (let i = 0; i < 100; i++) { value = await call('status', { runId }); if (!['starting', 'running', 'stopping'].includes(value.state)) return value; await sleep(150); }
    throw Error('DAST did not stop: ' + JSON.stringify(value));
  };
  const until = async (runId, predicate) => {
    let value;
    for (let i = 0; i < 100; i++) { value = await call('status', { runId }); if (predicate(value)) return value; await sleep(150); }
    throw Error('DAST condition not reached: ' + JSON.stringify(value));
  };

  // A selected, already-loaded page has no new browser event after start.
  let offset = events.length;
  const invalidTarget = await raw({ type: 'KI_SECURITY', op: 'start', session, tab: 'not-a-tab', engines: ['DAST'] });
  assert.equal(invalidTarget.ok, false); assert.equal(invalidTarget.code, 'invalid_target_tab'); assert.equal(invalidTarget.retryable, false);
  assert.equal(events.length, offset, 'invalid target cannot drive traffic');
  // Exact provider input reported by the user: legacy browser-tool field name
  // and a decimal string, rather than the advertised integer tabId.
  const fresh = await call('start', { tab: String(tab.tabId), engines: ['DAST'], options: options('thorough') });
  assert.ok(fresh.runId, JSON.stringify(fresh));
  assert.equal(fresh.surfaceMap?.available,true,'Start should expose the selected page inventory without reading input values');
  assert.equal(fresh.surfaceMap.url,origin+'/reflect');
  assert.equal(fresh.coverage?.dast?.selectedTargetSeededRequests, 1, JSON.stringify(fresh));
  const active = await until(fresh.runId, value => value.requestsSent > 0 || value.coverage?.dast?.error);
  assert.ok(active.requestsSent > 0, JSON.stringify(active));
  assert.ok(events.length > offset, 'local fixture received a DAST dispatch');
  assert.ok(active.coverage.dast.applicationRequestsObserved == null || active.coverage.dast.applicationRequestsObserved === 0);
  const idle = await until(fresh.runId, value => value.engineStatus?.DAST?.idle === true || value.state !== 'running');
  assert.equal(idle.coverage.dast.phase, 'watching_for_activity');
  await call('stop', { runId: fresh.runId });
  const finished = await terminal(fresh.runId);
  assert.ok(finished.coverage.dast.runRequestsDispatched > 0, JSON.stringify(finished));
  assert.ok(finished.coverage.dast.probeDispatches > 0);
  assert.ok(finished.coverage.dast.baselineDispatches > 0);
  const freshFindings = await call('findings', { runId: fresh.runId });
  assert.ok(freshFindings.total > 0, 'known reflected input produced XSS candidates');

  // PTK defaults deliberately waits for interaction and must not report a clean scan.
  offset = events.length;
  const locked = await call('start', { tabId: tab.tabId, engines: ['DAST'], options: options('ptk-defaults') });
  assert.equal(locked.coverage?.dast?.phase, 'waiting_for_interaction', JSON.stringify(locked));
  await sleep(450);
  const waiting = await call('status', { runId: locked.runId });
  assert.equal(waiting.requestsSent, 0); assert.equal(events.length, offset);
  await call('stop', { runId: locked.runId });
  const empty = await terminal(locked.runId);
  assert.equal(empty.state, 'incomplete', JSON.stringify(empty));
  assert.equal(empty.coverage.dast.phase, 'no_requests');
  assert.equal(empty.coverage.dast.runRequestsDispatched, 0);

  // PTK defaults keeps its interaction guard. A later GET alone does not unlock it;
  // an explicit browser form submission does, within the request budget.
  const interactive = await call('start', { tabId: tab.tabId, engines: ['DAST'], options: { ...options('ptk-defaults'), maxRequests: 5 } });
  await page.evaluate(() => fetch('/reflect?q=after-get').then(response => response.text()));
  await sleep(350);
  const afterGet = await call('status', { runId: interactive.runId });
  assert.equal(afterGet.requestsSent, 0, JSON.stringify(afterGet.coverage));
  await page.evaluate(() => fetch('/reflect', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'q=after-post' }).then(response => response.text()));
  const afterPost = await until(interactive.runId, value => value.requestsSent > 0 || value.coverage?.dast?.error);
  assert.ok(afterPost.coverage.dast.applicationRequestsObserved > 0, JSON.stringify(afterPost.coverage));
  assert.ok(afterPost.requestsSent > 0, JSON.stringify(afterPost.coverage));
  await call('stop', { runId: interactive.runId });
  const interactiveFinished = await terminal(interactive.runId);
  assert.ok(interactiveFinished.requestsSent <= 5, 'explicit request cap binds DAST traffic');

  // Earlier application traffic is reused as a safe GET seed on the same tab.
  const safePage = await browser.newPage();
  await safePage.goto(origin + '/safe?q=baseline');
  const safeTab = (await call('tabs')).find(item => item.url === origin + '/safe?q=baseline');
  assert.ok(safeTab);
  const capture = async action => {
    return call('execute', { capability: 'capture', arguments: { tabId: safeTab.tabId, action } });
  };
  await capture('start');
  await safePage.evaluate(() => fetch('/safe?q=preexisting', { headers: { 'X-Fixture': 'safe-get' } }).then(response => response.text()));
  await safePage.evaluate(() => fetch('/safe', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'q=preexisting-post' }).then(response => response.text()));
  await sleep(250);
  await capture('stop');
  offset = events.length;
  const safe = await call('start', { tabId: safeTab.tabId, engines: ['DAST'], options: options('thorough') });
  assert.ok(safe.coverage?.dast?.proxySeededRequests > 0, JSON.stringify(safe));
  assert.ok(safe.coverage.dast.unsafeSeedSkipped > 0, 'prior POST is not an automatic seed');
  await until(safe.runId, value => (value.coverage?.dast?.tasksPlanned > 0 && value.engineStatus?.DAST?.idle === true) || value.state !== 'running');
  await call('stop', { runId: safe.runId });
  const safeFinished = await terminal(safe.runId);
  assert.equal(safeFinished.state, 'completed', JSON.stringify(safeFinished.coverage));
  assert.ok(safeFinished.coverage.dast.runRequestsDispatched > 0);
  assert.equal(events.length - offset, safeFinished.coverage.dast.runRequestsDispatched, 'fixture receipt matches admitted dispatches');
  assert.ok(events.slice(offset).every(event => event.url.startsWith('/safe') && event.method === 'GET'));
  assert.equal((await call('findings', { runId: safe.runId })).total, 0, 'escaped input is a negative control');

  offset = events.length;
  const budget = await call('start', { tabId: safeTab.tabId, engines: ['DAST'], options: { ...options('thorough'), maxRequests: 3 } });
  await until(budget.runId, value => (value.coverage?.dast?.tasksPlanned > 0 && value.engineStatus?.DAST?.idle === true) || value.state !== 'running');
  await call('stop', { runId: budget.runId });
  const limited = await terminal(budget.runId);
  assert.equal(limited.state, 'incomplete');
  assert.equal(limited.coverage.dast.runRequestsDispatched, 3, 'local request cap binds dispatches');
  assert.equal(events.length - offset, 3, 'fixture received only admitted requests');

  const plainPage = await browser.newPage();
  await plainPage.goto(origin + '/plain'); await sleep(250);
  const plainTab = (await call('tabs')).find(item => item.url === origin + '/plain');
  assert.ok(plainTab);
  offset = events.length;
  const plain = await call('start', { tabId: plainTab.tabId, engines: ['DAST'], options: { ...options('thorough'), maxRequests: 5 } });
  await until(plain.runId, value => value.engineStatus?.DAST?.idle === true || value.state !== 'running');
  await call('stop', { runId: plain.runId });
  const plainFinished = await terminal(plain.runId);
  assert.ok(events.length > offset, 'a plain selected page must receive a baseline request');
  assert.equal(plainFinished.state, 'incomplete', 'one baseline is not probe coverage');
  assert.equal(plainFinished.coverage.dast.phase, 'no_executed_probes');
  assert.equal(plainFinished.coverage.dast.tasksExecuted, 0);
  assert.equal(plainFinished.coverage.dast.baselineDispatches, 1);
  assert.equal(plainFinished.coverage.dast.probeDispatches, 0);

  offset = events.length;
  const revoked = await call('start', { tabId: safeTab.tabId, engines: ['DAST'], options: { ...options('thorough'), maxRequestsPerSecond: 1 } });
  await until(revoked.runId, value => value.requestsSent >= 1);
  for (let i = 0; i < 30 && events.length === offset; i++) await sleep(20);
  assert.ok(events.length > offset);
  const beforeRevocation = events.length;
  assert.equal((await raw({ type: 'KI_CONTEXT', op: 'save_workspace', workspace: { id: workspaceId, name: 'DAST start fixture', profileId: 'bugbounty', dastScope: { origins: [origin], excludePaths: ['/safe'] } } })).ok, true);
  await sleep(1300);
  const revokedStatus = await call('status', { runId: revoked.runId });
  assert.equal(events.length, beforeRevocation, 'scope restriction blocks queued scan requests');
  assert.ok(revokedStatus.requestsSent <= 1);
  if (['starting', 'running', 'stopping', 'unknown'].includes(revokedStatus.state)) await call('stop', { runId: revoked.runId });
  const revokedFinal = await terminal(revoked.runId);
  assert.equal(revokedFinal.state, 'incomplete', 'revoked scope must not produce a clean verdict');
  assert.equal(events.length, beforeRevocation);

  console.log(JSON.stringify({ fresh: { state: finished.state, findings: freshFindings.total, coverage: finished.coverage.dast }, noInteraction: { state: empty.state, coverage: empty.coverage.dast }, afterInteraction: { state: interactiveFinished.state, coverage: interactiveFinished.coverage.dast }, preexistingSafe: { state: safeFinished.state, coverage: safeFinished.coverage.dast }, budget: { state: limited.state, coverage: limited.coverage.dast }, plainPage: { state: plainFinished.state, coverage: plainFinished.coverage.dast }, revoked: { state: revokedFinal.state, coverage: revokedFinal.coverage.dast }, fixtureRequests: events.length }));
}

main().catch(error => { console.error(error); console.error(JSON.stringify({ events })); process.exitCode = 1; }).finally(async () => {
  await browser?.close();
  if (server) await new Promise(resolve => server.close(resolve));
  if (path.resolve(temp).startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(temp).startsWith('cert-x-dast-start-')) fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

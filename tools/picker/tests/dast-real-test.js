// Native cert-x compatibility regression. Only isolated localhost fixtures receive requests.
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-dast-real-')), events = [], outsideEvents = [], pageErrors = [];
const auth = 'Bearer fixture-private-auth', cookie = 'fixture_session=fixture-private-cookie', body = 'q=baseline%20space&keep=a%2Bb';
const jsonBody = '{ "filter": {"q":"baseline 雪", "keep":"\\u0041"}, "count":90071992547409931234, "active":true, "nothing":null }';
let browser, server, outside, authExpired = false, redirectEnabled = false;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const escaped = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
async function main() {

  outside = http.createServer((req, res) => { outsideEvents.push({ method: req.method, url: req.url }); res.end('OUTSIDE'); });
  await new Promise(resolve => outside.listen(0, '127.0.0.1', resolve));
  const outsideOrigin = 'http://127.0.0.1:' + outside.address().port;
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://fixture');
    if (url.pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }
    if (url.pathname === '/app') {
      res.setHeader('Set-Cookie', cookie + '; Path=/; HttpOnly; SameSite=Lax'); res.setHeader('Content-Type', 'text/html');
      return res.end('<!doctype html><title>Targeted DAST fixture</title><h1>Targeted DAST fixture</h1><p>Controlled request capture.</p>');
    }
    let raw = ''; req.on('data', data => raw += data); req.on('end', () => {
      events.push({ at: Date.now(), method: req.method, url: req.url, path: url.pathname, body: raw, authorization: req.headers.authorization, cookie: req.headers.cookie });
      if (url.pathname === '/redirect' && redirectEnabled) { res.writeHead(302, { Location: outsideOrigin + '/must-not-receive' }); return res.end('redirect'); }
      if (url.pathname === '/auth' && authExpired) { res.writeHead(401); return res.end('authentication expired'); }
      if (url.pathname.startsWith('/sql-')) {
        const value = url.searchParams.get('q') || '', quoted = /['"]/.test(value);
        res.setHeader('Content-Type', 'text/html');
        if (url.pathname === '/sql-error' && quoted || url.pathname === '/sql-existing') { if (quoted) res.statusCode = 500; return res.end('You have an error in your SQL syntax near the selected input'); }
        if (url.pathname === '/sql-generic' && quoted) { res.statusCode = 500; return res.end('Unexpected application failure'); }
        return res.end('Stable search result');
      }
      if (url.pathname.startsWith('/json-')) {
        let parsed; try { parsed = JSON.parse(raw); } catch { res.statusCode = 400; return res.end('Invalid JSON'); }
        const value = parsed.filter.q;
        res.setHeader('Content-Type', 'text/html');
        if (url.pathname === '/json-sql-error') { if (/['"]/.test(value)) { res.statusCode = 500; return res.end('PostgreSQL query failed: syntax error at selected input'); } return res.end('Stable JSON API result'); }
        return res.end('<div>' + (url.pathname === '/json-safe' ? escaped(value) : value) + '</div>');
      }
      if (url.pathname.startsWith('/open-redirect')) {
        const destination = url.searchParams.get('q') || '';
        if (destination.includes('cert-x-redirect.invalid')) {
          const location = new URL(destination);
          if (url.pathname.endsWith('-near-host')) location.hostname += '.evil.test';
          res.writeHead(302, { Location: location.href }); return res.end('Redirect response');
        }
        res.writeHead(302, { Location: '/landing' }); return res.end('Ordinary local redirect');
      }
      const params = req.method === 'POST' ? new URLSearchParams(raw) : url.searchParams, value = params.get('q') || '';
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      const respond = () => res.end('<!doctype html><div>' + (url.pathname === '/escaped' ? escaped(value) : value) + '</div>');
      if (url.pathname === '/slow') setTimeout(respond, 500); else respond();
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + server.address().port, downloads = path.join(temp, 'downloads'), profile = path.join(temp, 'profile');
  fs.mkdirSync(path.join(profile, 'Default'), { recursive: true }); fs.mkdirSync(downloads);
  fs.writeFileSync(path.join(profile, 'Default/Preferences'), JSON.stringify({ download: { default_directory: downloads, prompt_for_download: false } }));
  browser = await chromium.launchPersistentContext(profile, { headless: true, downloadsPath: downloads, viewport: { width: 720, height: 1000 }, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const cert=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');
  await cert.evaluate(()=>globalThis.certXSecurityCompatibilityReady);
  const manifest=await cert.evaluate(()=>globalThis.certXSecurity.runtime.describe());assert.equal(manifest.version,'10.0.0');
  const id = new URL(cert.url()).host, session = 'dast-real-chat', workspaceId = 'dast-real-workspace';
  await cert.evaluate(() => chrome.storage.local.set({ sidepanel_language: 'en', sidepanel_theme: 'dark', sidepanel_approval_mode: 'full_access' }));
  const settings = await browser.newPage(); settings.on('pageerror', error => pageErrors.push(error.message));
  await settings.goto('chrome-extension://' + id + '/providers/providers.html?section=dast&session=' + session); await settings.waitForFunction(() => !document.querySelector('main').inert);
  const raw = message => settings.evaluate(message => chrome.runtime.sendMessage(message), message);
  const call = async (op, args = {}) => { const reply = await raw({ type: 'KI_DAST', op, session, ...args }); assert.equal(reply?.ok, true, JSON.stringify(reply)); return reply.result; };
  const scope = { origins: [origin], excludePaths: ['/excluded'] };
  const saved = await raw({ type: 'KI_CONTEXT', op: 'save_workspace', workspace: { id: workspaceId, name: 'DAST fixture workspace', profileId: 'bugbounty', dastScope: scope } }); assert.equal(saved.ok, true, JSON.stringify(saved));
  const assigned = await raw({ type: 'KI_CONTEXT', op: 'assign_chat', session, workspaceId, profileId: 'bugbounty', modelExplicit: null }); assert.equal(assigned.ok, true, JSON.stringify(assigned));
  const page = await browser.newPage(); page.on('pageerror', error => pageErrors.push(error.message)); await page.goto(origin + '/app');
  const target = (await call('tabs')).find(tab => tab.url === origin + '/app'); assert.ok(target);
  await settings.bringToFront(); await settings.reload(); await settings.waitForFunction(() => !document.querySelector('main').inert);
  await call('capture',{tabId:target.tabId,expectedOrigin:origin,action:'start'});
  await page.evaluate(async ({ auth, body, jsonBody }) => {
    const headers = { Authorization: auth };
    for (const endpoint of ['reflect', 'escaped', 'redirect', 'auth', 'slow', 'excluded']) await fetch('/' + endpoint + '?q=baseline%20space&keep=a%2Bb', { headers, redirect: 'manual' }).then(response => response.text());
    await fetch('/no-cookie?q=baseline%20space&keep=a%2Bb', { headers, credentials: 'omit' }).then(response => response.text());
    await fetch('/form', { method: 'POST', headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' }, body }).then(response => response.text());
    for (const endpoint of ['sql-error', 'sql-generic', 'sql-existing', 'open-redirect', 'open-redirect-near-host']) await fetch('/' + endpoint + '?q=baseline', { headers, redirect: 'manual' }).then(response => response.text());
    for (const endpoint of ['json-reflect', 'json-safe', 'json-sql-error']) await fetch('/' + endpoint + (endpoint === 'json-reflect' ? '?search=baseline' : ''), { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8' }, body: jsonBody }).then(response => response.text());
  }, { auth, body, jsonBody });
  let requests;
  for (let attempt = 0; attempt < 100; attempt++) { requests = (await call('list')).requests; if (requests.filter(request => request.supported).length >= 15) break; await sleep(100); }
  assert.equal(requests.filter(request => request.supported).length, 15, JSON.stringify(requests.filter(request => !request.supported).map(({url,reason}) => ({url,reason})))); assert.equal(requests.some(request => request.url.includes('/excluded')), false);
  assert.ok(events.every(event => event.path === '/no-cookie' ? !event.cookie : event.cookie?.includes(cookie)), 'Original browser requests must accurately exercise present and absent Cookie headers');
  const privateHeaders = await cert.evaluate(async () => Object.values((await chrome.storage.session.get('ki_dast_private')).ki_dast_private.requests).map(request => ({ path: new URL(request.url).pathname, cookie: request.headers.some(header => header.name.toLowerCase() === 'cookie'), authorization: request.headers.some(header => header.name.toLowerCase() === 'authorization') })));
  assert.ok(privateHeaders.every(request => (request.path === '/no-cookie' ? !request.cookie : request.cookie) && request.authorization), 'Exact captured headers must preserve present/absent Cookie and Authorization: ' + JSON.stringify(privateHeaders));
  assert.ok(!JSON.stringify(requests).includes(auth)); assert.ok(!JSON.stringify(requests).includes('fixture-private-cookie')); assert.ok(!JSON.stringify(requests).includes('baseline%20space'));
  await call('capture',{tabId:target.tabId,action:'stop'});
  const byPath = suffix => requests.find(request => request.url === origin + suffix);
  const selectRequest = request => ({ requestId: request.requestId, parameters: request.parameters.filter(parameter => parameter.name === 'q' || parameter.name === '/filter/q').map(({ name, location, index }) => ({ name, location, index })), allowReplay: true });
  const prepare = (request, maxRequests = 100, families = ['xss']) => call('prepare', { requests: [selectRequest(request)], families, budget: { maxRequests, maxRequestsPerSecond: 1, concurrency: 1, durationSeconds: 60 } });
  const terminal = async batchId => { let result; for (let attempt = 0; attempt < 250; attempt++) { result = await call('status', { batchId }); if (!['starting', 'running', 'stopping'].includes(result.state)) return result; await sleep(200); } throw Error('Batch did not finish: ' + JSON.stringify(result)); };
  const assertTransport = (batch, from) => {
    const sent = events.slice(from); assert.equal(sent.length, batch.requestsSent, 'One accounting unit per actual server request');
    for (const event of sent) { assert.equal(event.authorization, auth); assert.equal(event.cookie, cookie, 'Captured HttpOnly cookie must replace the changed ambient cookie exactly'); }
    for (let index = 1; index < sent.length; index++) assert.ok(sent[index].at - sent[index - 1].at >= 850, 'The actual server must observe <=1 request/second');
    assert.equal(sent.some(event => event.path === '/excluded'), false); return sent;
  };
  // Exercise the preserved compatibility API; native UI coverage lives in ui.browser.cjs.
  const positivePlan=await prepare(byPath('/reflect'));assert.ok(!JSON.stringify(positivePlan).includes(auth));assert.ok(!JSON.stringify(positivePlan).includes('fixture-private-cookie'));
  await browser.addCookies([{ name: 'fixture_session', value: 'new-ambient-cookie', url: origin, httpOnly: true, sameSite: 'Lax' }]);
  let offset = events.length; await call('run',{planId:positivePlan.planId,planHash:positivePlan.planHash});
  let batch; for (let i = 0; i < 100; i++) { batch = (await call('state')).batches.at(-1); if (batch) break; await sleep(50); }
  const positive = await terminal(batch.batchId); assert.equal(positive.state, 'completed', JSON.stringify(positive)); const positiveSent = assertTransport(positive, offset); assert.equal(positiveSent[0].url, '/reflect?q=baseline%20space&keep=a%2Bb');
  const findings = await call('findings', { batchId: batch.batchId }); assert.ok(findings.findings.length > 0, JSON.stringify(findings)); assert.ok(findings.findings.every(finding => finding.verifiedImpact === false));
  await call('export',{batchId:batch.batchId});
  const positiveRecord = (await call('state')).batches.find(item => item.batchId === batch.batchId), report = positiveRecord.reports[0]; assert.ok(report);
  const download = (await cert.evaluate(id => chrome.downloads.search({ id }), report.downloadId))[0]; assert.equal(download.state, 'complete'); const file = path.resolve(download.filename); assert.ok(file.startsWith(path.resolve(temp) + path.sep));
  const artifact = JSON.parse(fs.readFileSync(file, 'utf8')); assert.equal(artifact.schema, 'cert-x-dast/v1'); assert.ok(!JSON.stringify(artifact).includes(auth)); assert.ok(!JSON.stringify(artifact).includes('fixture-private-cookie'));
  const outputs = await raw({ type: 'KI_WORKSPACE', op: 'outputs', session }); assert.ok(outputs.result.some(item => item.downloadId === report.downloadId && item.owner === session));
  // Sanitized negative control uses the same PTK module and selected input.
  let plan = await prepare(byPath('/escaped')); offset = events.length; batch = await call('run', { planId: plan.planId, planHash: plan.planHash }); const negative = await terminal(batch.batchId); assert.equal(negative.state, 'completed', JSON.stringify(negative)); assertTransport(negative, offset);
  assert.equal((await call('findings', { batchId: batch.batchId })).findings.length, 0, 'Escaped reflection must not become a reflected-XSS candidate');
  // Exact baseline body and authentication are preserved for a captured POST.
  plan = await prepare(byPath('/form'), 2); offset = events.length; batch = await call('run', { planId: plan.planId, planHash: plan.planHash }); const form = await terminal(batch.batchId); assert.equal(form.state, 'budget_exhausted'); const formSent = assertTransport(form, offset); assert.equal(formSent.length, 2); assert.equal(formSent[0].body, body); assert.equal(formSent[0].method, 'POST');
  // An absent captured Cookie must not silently adopt the changed browser identity.
  plan = await prepare(byPath('/no-cookie'), 1); offset = events.length; batch = await call('run', { planId: plan.planId, planHash: plan.planHash }); const noCookie = await terminal(batch.batchId); assert.equal(noCookie.state, 'budget_exhausted');
  assert.equal(noCookie.requestsSent, 1); assert.equal(events.length - offset, 1); assert.equal(events[offset].cookie, undefined); assert.equal(events[offset].authorization, auth);
  // A changed server response cannot turn a selected endpoint into a redirect hop.
  plan = await prepare(byPath('/redirect')); redirectEnabled = true; offset = events.length; batch = await call('run', { planId: plan.planId, planHash: plan.planHash }); const redirect = await terminal(batch.batchId); assert.equal(redirect.state, 'failed', JSON.stringify(redirect)); assert.equal(assertTransport(redirect, offset).length, 1); assert.equal(outsideEvents.length, 0);
  plan = await prepare(byPath('/auth')); authExpired = true; offset = events.length; batch = await call('run', { planId: plan.planId, planHash: plan.planHash }); const expiredAuth = await terminal(batch.batchId); assert.ok(['failed', 'auth_expired'].includes(expiredAuth.state)); assert.match(expiredAuth.errors.join(' '), /Authentication|access/i); assert.equal(assertTransport(expiredAuth, offset).length, 1);
  // Stop while the first baseline is in flight; queued mutations never dispatch.
  plan = await prepare(byPath('/slow')); offset = events.length; batch = await call('run', { planId: plan.planId, planHash: plan.planHash }); for (let i = 0; i < 100 && events.length === offset; i++) await sleep(20);
  assert.equal(events.length, offset + 1); await call('stop', { batchId: batch.batchId }); const stopped = await terminal(batch.batchId); assert.equal(stopped.state, 'stopped'); await sleep(1100); assert.equal(assertTransport(stopped, offset).length, 1);
  // New families use their own response evidence and controls, not XSS reflection logic.
  const familyResults = {};
  for (const [endpoint, families, classification, expected] of [
    ['/sql-error', ['sql_injection'], 'reproduced_sql_error', true],
    ['/sql-generic', ['sql_injection'], null, false],
    ['/sql-existing', ['sql_injection'], null, false],
    ['/open-redirect', ['open_redirect'], 'reproduced_redirect', true],
    ['/open-redirect-near-host', ['open_redirect'], null, false],
    ['/json-reflect', ['xss'], 'reproduced_reflection', true],
    ['/json-safe', ['xss'], null, false],
    ['/json-sql-error', ['sql_injection'], 'reproduced_sql_error', true],
  ]) {
    plan = await prepare(byPath(endpoint), 100, families); offset = events.length;
    batch = await call('run', { planId: plan.planId, planHash: plan.planHash }); const final = await terminal(batch.batchId);
    assert.equal(final.state, 'completed', endpoint + ': ' + JSON.stringify(final)); const sent = assertTransport(final, offset);
    const evidence = await call('findings', { batchId: batch.batchId });
    assert.equal(evidence.findings.length > 0, expected, endpoint + ': ' + JSON.stringify(evidence));
    if (expected) assert.ok(evidence.findings.every(item => item.family === families[0] && item.classification === classification && item.verifiedImpact === false));
    if (endpoint.startsWith('/json-')) {
      assert.equal(sent[0].body, jsonBody, 'JSON baseline must preserve raw bytes, types, whitespace and escapes');
      for (const request of sent) {
        assert.ok(request.body.includes('"count":90071992547409931234')); assert.ok(request.body.includes('"active":true')); assert.ok(request.body.includes('"nothing":null')); assert.ok(request.body.includes('"keep":"\\u0041"'));
        const parsed = JSON.parse(request.body); assert.equal(typeof parsed.filter.q, 'string'); assert.equal(parsed.filter.keep, 'A');
      }
      assert.ok(byPath(endpoint).parameters.filter(item => item.valueType !== 'string').every(item => item.supported === false));
    }
    assert.equal(outsideEvents.length, 0, 'No redirect target may receive a request');
    familyResults[endpoint] = { findings: evidence.findings.length, requests: final.requestsSent };
  }
  // Query-only and mixed selections must not trigger PTK's whole-object JSON rewrite.
  const jsonRequest = byPath('/json-reflect');
  for (const mixed of [false, true]) {
    const parameters = jsonRequest.parameters.filter(item => item.location === 'query' || mixed && item.name === '/filter/q').map(({location,name,index}) => ({location,name,index}));
    // Controls now run lazily with each selected field. Give both fields enough
    // budget to finish rather than assuming a particular five-probe ordering.
    const limit = mixed ? 20 : 5;
    plan = await call('prepare', { requests: [{requestId:jsonRequest.requestId,parameters,allowReplay:true}], families:['xss'], budget:{maxRequests:limit,maxRequestsPerSecond:1,durationSeconds:60} });
    offset = events.length; batch = await call('run', {planId:plan.planId,planHash:plan.planHash}); const final = await terminal(batch.batchId);
    assert.equal(final.state,'completed',JSON.stringify(final)); const sent = assertTransport(final,offset);
    assert.ok(sent.length<=limit); if(!mixed)assert.equal(sent.length,5);assert.equal(sent[0].body,jsonBody);
    for (const request of sent) {
      if (!mixed) assert.equal(request.body,jsonBody,'Query-only variants must preserve the entire raw JSON body');
      else { assert.ok(request.body.includes('"count":90071992547409931234')); assert.ok(request.body.includes('"keep":"\\u0041"')); assert.equal(JSON.parse(request.body).active,true);if(new URL(request.url,origin).searchParams.get('search')!=='baseline')assert.equal(request.body,jsonBody,'Query mutation must not also mutate the selected JSON field');if(request.body!==jsonBody)assert.equal(new URL(request.url,origin).searchParams.get('search'),'baseline','JSON mutation must not also mutate the selected query field'); }
    }
    assert.ok(sent.some(request => new URL(request.url,origin).searchParams.get('search') !== 'baseline'));
    if(mixed){assert.ok(sent.some(request=>request.body!==jsonBody));const checked=await call('findings',{batchId:batch.batchId});assert.equal(checked.coverage.filter(item=>item.family==='xss'&&item.state==='tested').length,2);}
    familyResults[mixed ? 'mixed-query-json' : 'query-only-json'] = {requests:final.requestsSent,state:final.state};
  }
  // Tampered hashes and newly excluded paths fail before companion dispatch.
  plan = await prepare(byPath('/reflect')); offset = events.length;
  const tampered = await raw({ type: 'KI_DAST', op: 'run', session, planId: plan.planId, planHash: 'tampered' }); assert.equal(tampered.ok, false);
  const updated = await raw({ type: 'KI_CONTEXT', op: 'save_workspace', workspace: { id: workspaceId, name: 'DAST fixture workspace', profileId: 'bugbounty', dastScope: { origins: [origin], excludePaths: ['/excluded', '/reflect'] } } }); assert.equal(updated.ok, true);
  const revoked = await raw({ type: 'KI_DAST', op: 'run', session, planId: plan.planId, planHash: plan.planHash }); assert.equal(revoked.ok, false); assert.equal(events.length, offset);
  const foreign = await raw({ type: 'KI_DAST', op: 'findings', session: 'other-chat', batchId: positiveRecord.batchId }); assert.equal(foreign.ok, false);
  assert.deepEqual(pageErrors, []); await settings.screenshot({ path: path.join(os.tmpdir(), 'cert-x-dast-real.png'), fullPage: true });
  console.log(JSON.stringify({ actualPtkVersion: manifest.version, singleExtension: true, actualCdpCapture: true, httpOnlyCookieAndAuthorizationReplay: true, frozenCookieOverridesAmbient: true, absentCookieDoesNotUseAmbient: true, exactPostBaseline: true, positiveCandidates: findings.findings.length, sanitizedNegative: true, actualRequestAccounting: true, rateBound: true, smallBudgetEnforced: true, redirectNotFollowed: true, excludedPathsNotTested: true, expiredAuthenticationStops: true, stopPreventsQueuedRequests: true, immutablePlan: true, reportParsed: true, outputOwnership: true, crossChatBlocked: true, familyResults, pageErrors }));
}
main().catch(error => { console.error(error); console.error(JSON.stringify({ pageErrors, events: events.map(({ authorization, cookie, ...event }) => event), outsideEvents })); process.exitCode = 1; }).finally(async () => {
  await browser?.close(); if (server) await new Promise(resolve => server.close(resolve)); if (outside) await new Promise(resolve => outside.close(resolve));
  const absolute = path.resolve(temp); if (absolute.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(absolute).startsWith('cert-x-dast-real-')) fs.rmSync(absolute, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

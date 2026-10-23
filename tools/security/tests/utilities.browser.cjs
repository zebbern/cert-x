// End-to-end tests of native supporting tools, using one installed cert-x and local targets.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http'), crypto = require('node:crypto'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-security-utilities-'));
let browser, referenceBrowser, referenceCopy, primary, secondary; const requests = [], secondaryRequests = [], results = [], failures = [];
const phase = process.env.SECURITY_UTILITY_PHASE;
const brief = value => JSON.stringify(value).slice(0, 3000);
async function check(name, fn) { if (phase && phase !== name) return; try { const evidence = await fn(); results.push({ name, passed: true, evidence }); console.log('PASS', name, JSON.stringify(evidence)); } catch (error) { failures.push({ name, error: error.stack || error.message }); console.error('FAIL', name, error.stack || error.message); } }
async function waitFor(fn, description, timeout = 12000) { const end = Date.now() + timeout; let value; while (Date.now() < end) { value = await fn(); if (value) return value; await new Promise(resolve => setTimeout(resolve, 100)); } throw Error('Timed out: ' + description + '; last=' + JSON.stringify(value)); }
async function main() {
  secondary = http.createServer((req, res) => { secondaryRequests.push(req.url); res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Content-Type', 'text/plain'); res.end('secondary'); });
  await new Promise(resolve => secondary.listen(0, '127.0.0.1', resolve)); const otherOrigin = 'http://127.0.0.1:' + secondary.address().port;
  primary = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk); const body = Buffer.concat(chunks).toString('utf8'); requests.push({ method: req.method, url: req.url, headers: req.headers, body });
    const url = new URL(req.url, 'http://fixture'); res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('X-Powered-By', 'cert-x-fixture');
    if (url.pathname === '/redirect-out') { res.writeHead(302, { Location: otherOrigin + '/escaped' }); return res.end(); }
    if (url.pathname === '/redirect-in') { res.writeHead(302, { Location: '/echo?redirected=yes' }); return res.end(); }
    if (url.pathname === '/failure') { req.socket.destroy(); return; }
    if (url.pathname === '/echo') { res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({ method: req.method, headers: req.headers, body, query: Object.fromEntries(url.searchParams) })); }
    if (url.pathname === '/fixture.js') { res.setHeader('Content-Type', 'application/javascript'); return res.end('if(location.pathname==="/app")window.jQuery={fn:{jquery:"3.7.1"}};document.getElementById("click-me").addEventListener("click",()=>{document.getElementById("result").textContent="clicked";window.fixtureClicks=(window.fixtureClicks||0)+1;fetch("/echo?clicked=yes");});'); }
    res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><title>Native utility fixture</title>' + (url.pathname === '/app' ? '<meta name="generator" content="WordPress 6.5">' : '') + '<button id="click-me">Click fixture</button><div id="result">ready</div><script src="/fixture.js"></script>');
  });
  await new Promise(resolve => primary.listen(0, '127.0.0.1', resolve)); const origin = 'http://127.0.0.1:' + primary.address().port;
  browser = await chromium.launchPersistentContext(path.join(temp, 'profile'), { headless: true, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker', { timeout: 15000 });
  await worker.evaluate(async () => { await globalThis.certXSecurity.ready; await globalThis.certXSecurityCompatibilityReady; });
  const extensionId = new URL(worker.url()).host, session = 'security-utilities', workspaceId = 'utilities-workspace';
  const settings = await browser.newPage(); await settings.goto('chrome-extension://' + extensionId + '/providers/providers.html?section=security&session=' + session); await settings.waitForFunction(() => !document.querySelector('main').inert);
  const raw = async (op, args = {}) => settings.evaluate(message => chrome.runtime.sendMessage(message), { type: 'KI_SECURITY', op, session, ...args });
  const call = async (op, args = {}) => { const reply = await raw(op, args); assert.equal(reply?.ok, true, brief(reply)); assert.notEqual(reply.result?.success, false, brief(reply)); assert.notEqual(reply.result?.ok, false, brief(reply)); return reply.result; };
  const context = async value => { const reply = await settings.evaluate(message => chrome.runtime.sendMessage(message), { type: 'KI_CONTEXT', ...value }); assert.equal(reply.ok, true, brief(reply)); return reply.result; };
  const saveWorkspace = async origins => context({ op: 'save_workspace', workspace: { id: workspaceId, name: 'Utility fixtures', profileId: 'bugbounty', dastScope: { origins, excludePaths: ['/excluded'] } } });
  await saveWorkspace([origin]); await context({ op: 'assign_chat', session, workspaceId, profileId: 'bugbounty', modelExplicit: null });
  const target = await browser.newPage(); await target.goto(origin + '/app');
  const tabId = (await worker.evaluate(() => chrome.tabs.query({}))).find(tab => tab.url === origin + '/app').id;
  const execute = (capability, args, options) => call('execute', { capability, tabId, arguments: args, ...(options ? { options } : {}) });
  const deny = async (capability, args, pattern, options) => { const result = await raw('execute', { capability, tabId, arguments: args, ...(options ? { options } : {}) }); assert.equal(result.ok, false, brief(result)); if (pattern) assert.match(result.error, pattern); return result; };
  const capabilities = await call('capabilities'); assert.ok(capabilities.operations.includes('security_utility')); assert.ok(capabilities.operations.includes('security_macro')); assert.ok(capabilities.operations.includes('security_replay_request'));

  await check('codecs', async () => {
    const encoded = await execute('utility', { tool: 'encode', method: 'base64', text: 'cert-x – café' }); assert.equal(encoded.result, Buffer.from('cert-x – café').toString('base64'));
    const decoded = await execute('utility', { tool: 'decode', method: 'base64', text: encoded.result }); assert.equal(decoded.result, 'cert-x – café');
    const base64url = await execute('utility', { tool: 'encode', method: 'base64url', text: '😄' }); assert.equal(base64url.result, Buffer.from('😄').toString('base64url'));
    assert.equal((await execute('utility', { tool: 'decode', method: 'base64url', text: base64url.result })).result, '😄');
    const url = await execute('utility', { tool: 'encode', method: 'uriComponent', text: 'a/b ?&' }); assert.equal(url.result, encodeURIComponent('a/b ?&'));
    for (const method of ['md5', 'sha1']) { const digest = await execute('utility', { tool: 'encode', method, text: 'cert-x' }); assert.equal(digest.result, crypto.createHash(method).update('cert-x').digest('hex')); }
    const hex = await execute('utility', { tool: 'encode', method: 'hex', text: 'cert-x' }); assert.equal(hex.result, Buffer.from('cert-x').toString('hex'));
    assert.equal((await execute('utility', { tool: 'decode', method: 'hex', text: hex.result })).result, 'cert-x');
    const html = await execute('utility', { tool: 'encode', method: 'html_entity', text: '<script>&' }); assert.equal(html.result, '&lt;script&gt;&amp;');
    assert.equal((await execute('utility', { tool: 'decode', method: 'html_entity', text: html.result })).result, '<script>&');
    await deny('utility', { tool: 'decode', method: 'uriComponent', text: '%E0%A4%A' }, /URI|malformed/i);
    await deny('utility', { tool: 'decode', method: 'not-a-codec', text: 'x' }, /Unsupported codec/i);
    return { unicodeRoundtrip: true, hashes: true, hex: true, htmlEntities: true, invalidInputRejected: true, unknownCodecRejected: true };
  });
  await check('jwt', async () => {
    const header = { alg: 'HS256', typ: 'JWT' }, claims = { sub: 'alice', iss: 'cert-x-fixture', role: 'member' }, secret = 'cert-x-fixture-secret-32-characters';
    const body = Buffer.from(JSON.stringify(header)).toString('base64url') + '.' + Buffer.from(JSON.stringify(claims)).toString('base64url');
    const token = body + '.' + crypto.createHmac('sha256', secret).update(body).digest('base64url');
    const decoded = await execute('utility', { tool: 'jwt', action: 'decode', token }); assert.deepEqual(decoded.header, header); assert.deepEqual(decoded.claims, claims);
    const verified = await execute('utility', { tool: 'jwt', action: 'verify', token, secret, options: { algorithms: ['HS256'], issuer: 'cert-x-fixture' } }); assert.deepEqual(verified.payload, claims);
    await deny('utility', { tool: 'jwt', action: 'verify', token, secret: 'wrong-secret', options: { algorithms: ['HS256'] } }, /signature|verification/i);
    await deny('utility', { tool: 'jwt', action: 'decode', token: 'not-a-token' }, /JWT|JWS|Invalid/i);
    const signed = await execute('utility', { tool: 'jwt', action: 'sign', header, payload: claims, secret });
    const signedToken = signed.token || signed.result; assert.equal(typeof signedToken, 'string', brief(signed));
    const roundtrip = await execute('utility', { tool: 'jwt', action: 'verify', token: signedToken, secret, options: { algorithms: ['HS256'] } }); assert.equal(roundtrip.payload.sub, 'alice');
    const brute = await execute('utility', { tool: 'jwt', action: 'bruteforce', token, words: ['incorrect', secret] }); assert.equal(brute.found, true, brief(brute)); assert.equal(brute.secret, secret); assert.equal(brute.attempts, 2);
    const absent = await execute('utility', { tool: 'jwt', action: 'bruteforce', token, words: ['incorrect'] }); assert.equal(absent.found, false, brief(absent));
    return { decode: true, verify: true, sign: true, dictionaryCheck: true, wrongKeyRejected: true, malformedRejected: true };
  });
  await check('replay', async () => {
    const body = '{"text":"caf\u00e9","number":9007199254740993}';
    const replay = await execute('replay', { request: { url: origin + '/echo?replay=post', method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CertX-Fixture': 'preserved' }, body } });
    const received = requests.find(request => request.url === '/echo?replay=post'); assert.ok(received, brief(replay)); assert.equal(received.method, 'POST'); assert.equal(received.body, body); assert.equal(received.headers['x-certx-fixture'], 'preserved');
    assert.ok(brief(replay).includes('preserved'), 'Native response evidence retained');
    const redirected = await execute('replay', { request: { url: origin + '/redirect-in', method: 'GET' }, options: { follow_redirect: true } }); assert.ok(requests.some(request => request.url === '/echo?redirected=yes'), brief({ redirected, requests }));
    const before = secondaryRequests.length; const blocked = await deny('replay', { request: { url: origin + '/redirect-out', method: 'GET' }, options: { follow_redirect: true } }, /scope|origin|target|opaque|inconclusive|HTTP response/i); assert.equal(secondaryRequests.length, before, 'Out-of-scope redirect never dispatched');
    assert.ok(blocked.runId); const failedRun = await call('status', { runId: blocked.runId }); assert.equal(failedRun.state, 'error');
    const failedEvidence = await call('evidence', { runId: blocked.runId }); assert.equal(failedEvidence.operation, 'replay'); assert.ok(failedEvidence.result?.response, brief(failedEvidence));
    const budgetBefore = requests.filter(request => request.url === '/echo?redirected=yes').length;
    await deny('replay', { request: { url: origin + '/redirect-in', method: 'GET' }, options: { follow_redirect: true } }, /budget/i, { maxRequests: 1 });
    assert.equal(requests.filter(request => request.url === '/echo?redirected=yes').length, budgetBefore, 'Redirect hops count toward the run budget');
    const excluded = requests.filter(request => request.url === '/excluded').length; await deny('replay', { request: { url: origin + '/excluded', method: 'GET' } }, /scope|excluded|target/i); assert.equal(requests.filter(request => request.url === '/excluded').length, excluded);
    await deny('replay', { request: { url: origin + '/failure', method: 'GET' } }, /fetch|network|request|fail/i);
    return { postBodyAndHeaders: true, responseEvidence: true, inScopeRedirect: true, outOfScopeRedirectBlocked: true, redirectBudget: true, excludedPathBlocked: true, networkFailureReported: true };
  });
  await check('capture', async () => {
    const started = await execute('capture', { action: 'start' }); assert.equal(started.active, true);
    await target.evaluate(() => fetch('/echo?capture=observed').then(response => response.json()));
    const captured = await waitFor(async () => { const value = await execute('listRequests', { limit: 100 }); return JSON.stringify(value).includes('capture=observed') ? value : null; }, 'capture includes actual request');
    assert.ok(captured.total > 0);
    const otherSession = 'security-other-capture'; await context({ op: 'assign_chat', session: otherSession, workspaceId, profileId: 'bugbounty', modelExplicit: null });
    const other = await browser.newPage(); await other.goto(origin + '/other'); const otherTabId = (await worker.evaluate(() => chrome.tabs.query({}))).find(tab => tab.url === origin + '/other').id;
    const otherCall = async (capability, arguments_, id = otherTabId) => settings.evaluate(message => chrome.runtime.sendMessage(message), { type: 'KI_SECURITY', op: 'execute', session: otherSession, tabId: id, capability, arguments: arguments_ });
    assert.equal((await otherCall('capture', { action: 'start' })).ok, true);
    await other.evaluate(() => fetch('/echo?capture=other').then(response => response.json()));
    const foreign = await otherCall('listRequests', {}, tabId); assert.equal(foreign.ok, false); assert.match(foreign.error, /another chat|belong/i);
    const recon = await execute('utility', { tool: 'recon' }); assert.equal(recon.tabId, tabId, brief(recon)); assert.ok(recon.url.startsWith(origin + '/app'), 'Reconnaissance must describe the selected target, not latest active tab');
    assert.equal(recon.coverage?.domComplete, true, brief(recon.coverage));
    const technologies = recon.technologies.map(technology => technology.name); assert.ok(technologies.includes('jQuery'), brief(recon.technologies)); assert.ok(technologies.includes('WordPress'), brief(recon.technologies));
    assert.equal(JSON.stringify(recon).includes('capture=other'), false, 'Other chat traffic does not leak into reconnaissance');
    referenceCopy = require('../prepare-reference.cjs').resolveReference(process.env.PTK_REFERENCE_ROOT);
    referenceBrowser = await chromium.launchPersistentContext(path.join(temp, 'reference-profile'), { headless: true, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + referenceCopy.extensionPath, '--load-extension=' + referenceCopy.extensionPath] });
    const referenceWorker = referenceBrowser.serviceWorkers()[0] || await referenceBrowser.waitForEvent('serviceworker', { timeout: 15000 });
    await referenceWorker.evaluate(async () => { for (let i = 0; i < 200 && !globalThis.ptk_app?.ready; i++) await new Promise(resolve => setTimeout(resolve, 25)); await globalThis.ptk_app.ready; });
    const referencePage = await referenceBrowser.newPage(); await referencePage.goto(origin + '/app');
    const referenceTab = await referenceWorker.evaluate(async url => (await chrome.tabs.query({})).find(tab => tab.url === url), origin + '/app');
    await waitFor(() => referenceWorker.evaluate(async tabId => { try { return (await chrome.tabs.sendMessage(tabId, { channel: 'ptk_popup2content', type: 'ping' }))?.ok === true; } catch { return false; } }, referenceTab.id), 'original PTK content readiness');
    // PTK's original dashboard forwards init_complete observations to its analysis API.
    // Exercise that real UI rather than substituting the owned adapter in the oracle.
    const referenceDashboard = await referenceBrowser.newPage(); await referenceDashboard.goto('chrome-extension://' + new URL(referenceWorker.url()).host + '/ptk/browser/index.html');
    await referenceWorker.evaluate(async tab => { await ptk_app.proxy.ensureActiveTabContext({ tabId: tab.id }); await ptk_app.dashboard.msg_init({ tabId: tab.id, url: tab.url }); await ptk_app.dashboard.msg_get_full_dashboard({ tabId: tab.id }); }, referenceTab);
    const baseline = await waitFor(async () => { const value = await referenceWorker.evaluate(tabId => ptk_app.dashboard._getTabAnalysisCache(tabId)?.technologies || [], referenceTab.id); return value.some(technology => technology.name === 'WordPress') && value.some(technology => technology.name === 'jQuery') ? value : null; }, 'original PTK DOM/JS technology results');
    const normalized = values => values.map(technology => ({ name: technology.name, version: technology.version || '' })).sort((a, b) => a.name.localeCompare(b.name));
    assert.deepEqual(normalized(recon.technologies), normalized(baseline), 'Native reconnaissance preserves original PTK technology results');
    await referenceBrowser.close(); referenceBrowser = null;
    assert.equal((await otherCall('capture', { action: 'stop' })).ok, true); await other.close();
    const stopped = await execute('capture', { action: 'stop' }); assert.ok(stopped.state === 'cancelled' || stopped.active === false || stopped.state === 'completed', brief(stopped));
    await deny('listRequests', {}, /capture/i);
    return { captured: captured.total, detectedTechnologies: technologies, domAndJavascript: true, originalPtkParity: true, ownership: true, exactReconTab: true, stop: true };
  });
  await check('macros', async () => {
    const flow = { schema: 'ptk-flow/v1', metadata: { name: 'Click fixture' }, startUrl: origin + '/app', steps: [{ id: 'click', type: 'click', locators: [{ type: 'css', value: '#click-me' }] }] };
    const imported = await execute('import', { format: 'ptk-flow', data: JSON.stringify(flow) }); assert.equal(imported.flow.schema, 'ptk-flow/v1'); assert.equal(imported.flow.steps[0].type, 'click');
    await deny('import', { format: 'ptk-flow', data: '{not-json' }, /JSON|parse|invalid/i);
    const replayed = await execute('macro', { action: 'replay', url: origin + '/app', flow: imported.flow, tabId }); assert.ok(replayed.runId);
    try { await target.getByText('clicked', { exact: true }).waitFor({ timeout: 12000 }); }
    catch (error) { const detail = await worker.evaluate(async () => ({ mode: ptk_app.recorder.mode, replay: ptk_app.recorder.replay, result: ptk_app.recorder.replayResult, tab: ptk_app.recorder.openerTabId, storage: await chrome.storage.local.get(['ptk_replay_result', 'ptk_replay_step', 'ptk_recording_log']) })); throw Error(error.message + '\nReplay diagnostics: ' + brief(detail)); }
    const complete = await waitFor(async () => { const status = await execute('macro', { action: 'status' }); return status.replayResult?.status === 'completed' ? status : null; }, 'macro replay terminal completion');
    await execute('macro', { action: 'stop' });
    await target.goto(origin + '/app'); await settings.bringToFront(); const originalSettingsUrl = settings.url();
    const recorded = await execute('macro', { action: 'record', url: origin + '/app', tabId }); assert.ok(recorded.runId);
    assert.equal(recorded.ready, true, 'Recording API confirms that listeners are ready before agent actions');
    await target.getByRole('button', { name: 'Click fixture', exact: true }).click();
    await target.getByText('clicked', { exact: true }).waitFor();
    await execute('macro', { action: 'stop' }); assert.equal(settings.url(), originalSettingsUrl, 'Recording must not navigate active unrelated settings tab');
    const exported = await execute('macro', { action: 'export', format: 'ptk-flow' }); const text = typeof exported.result === 'string' ? exported.result : exported.result?.text || exported.text;
    assert.equal(typeof text, 'string', brief(exported)); const parsed = await execute('import', { format: 'ptk-flow', data: text }); assert.ok(parsed.flow.steps.some(step => step.type === 'click'), brief(parsed));
    return { import: true, replayCompleted: complete.replayResult.completedSteps, clickExecuted: true, recordingReady: true, immediateStopFlush: true, exportImportRoundtrip: true, exactTab: true };
  });
  await check('portprobe', async () => {
    await saveWorkspace([origin, otherOrigin]);
    const probe = await execute('utility', { tool: 'portscan', host: '127.0.0.1', ports: [primary.address().port], baselinePort: secondary.address().port, samples: 1, timeoutMs: 1500 });
    assert.equal(probe.results?.length, 1, brief(probe)); assert.equal(probe.results[0].confirmedOpen, false); assert.ok(['timing_difference', 'no_timing_difference'].includes(probe.results[0].observation));
    await deny('utility', { tool: 'portscan', host: '127.0.0.1', ports: [0], samples: 1 }, /valid|port/i);
    return { timingObservation: true, confirmedOpen: false, invalidPortRejected: true };
  });
  console.log(JSON.stringify({ singleExtension: true, phase: phase || 'all', results, failures }, null, 2));
  if (failures.length) throw Error(failures.length + ' utility integration scenarios failed.');
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  await browser?.close(); await referenceBrowser?.close(); if (primary) await new Promise(resolve => primary.close(resolve)); if (secondary) await new Promise(resolve => secondary.close(resolve));
  const absolute = path.resolve(temp); if (absolute.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(absolute).startsWith('cert-x-security-utilities-')) fs.rmSync(absolute, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  if (referenceCopy?.directory) { const directory = path.resolve(referenceCopy.directory); if (directory.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(directory).startsWith('cert-x-security-reference-')) fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
});

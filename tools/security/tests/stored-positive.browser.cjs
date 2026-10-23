// Positive stored-XSS parity through PTK's planner, task runner, tracking and real browser adapter.
// The supplied pro stored module is metadata-only; the executable fixture rule is derived
// from the imported canonical XSS rule shape and is identical for both runtimes.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const { resolveReference } = require('../prepare-reference.cjs');

const root = path.resolve(__dirname, '../../..');
const evidenceDir = path.join(root, 'tools/security/evidence');
const evidenceFile = path.join(evidenceDir, 'stored-positive.json');
const profileRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-stored-positive-'));
const marker = 'CERTX_STORED_EXEC_48291';
const payload = `<img src=x onerror="document.documentElement.setAttribute('data-ptk-xss','${marker}')">`;
const cases = process.env.STORED_CASE ? [process.env.STORED_CASE] : ['executing', 'escaped', 'retrieved_only', 'no_retrieval', 'authenticated'];
let server, browser, reference, currentSide = '', currentCase = '', stored = '';
const wire = [], evidence = { scope: 'Local, synthetic stored-XSS execution parity', marker, cases: {} };
function save() { fs.mkdirSync(evidenceDir, { recursive: true }); fs.writeFileSync(evidenceFile, JSON.stringify(evidence, null, 2) + '\n'); }
function pageHtml(content) { return '<!doctype html><html><head><title>Stored fixture</title></head><body>' + content + '</body></html>'; }
function escapeHtml(value) { return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;'); }
function projectResult(sample) {
  const finding = sample.result.finding;
  const proof = finding?.proof ? JSON.parse(finding.proof) : null;
  return {
    planned: sample.result.planned.map(task => ({ moduleId: task.moduleId, attackId: task.attackId,
      attacked: { location: task.attacked?.location, name: task.attacked?.name, before: task.attacked?.before, after: task.attacked?.after } })),
    finding: finding ? { success: finding.success, tier: finding.trackingTier,
      confirmation: finding.metadata?.confirmation && { channel: finding.metadata.confirmation.channel,
        tier: finding.metadata.confirmation.tier, source: finding.metadata.confirmation.source,
        marker: finding.metadata.confirmation.marker },
      mutations: finding.metadata?.mutations?.map(item => ({ location: item.location, name: item.name, before: item.before, after: item.after })),
      proof: proof && { check: proof.check, executed: proof.executed, marker: proof.marker,
        submissionMethod: proof.submission?.method, retrievalSource: proof.retrieval?.source,
        renderReflected: proof.render?.reflected, contextType: proof.render?.context?.type } } : null,
    events: sample.result.events.map(event => ({ type: event.type, reason: event.reason || null, error: event.error || null }))
  };
}

async function run(extension, integrated, origin, mode) {
  currentSide = integrated ? 'owned' : 'reference'; currentCase = mode; stored = '';
  const profile = path.join(profileRoot, `${currentSide}-${mode}`);
  browser = await chromium.launchPersistentContext(profile, {
    headless: true,
    executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'),
    args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension]
  });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
  let sessionCookie = '';
  if (mode === 'authenticated') {
    const loginPage = await browser.newPage();
    await loginPage.goto(origin + '/login');
    const login = await loginPage.evaluate(async () => {
      const response = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username: 'fixture-alice', password: 'local-only-password' }), credentials: 'include' });
      return { status: response.status, body: await response.text() };
    });
    assert.deepEqual(login, { status: 200, body: 'signed in' }, 'Synthetic account login failed');
    const cookie = (await browser.cookies(origin)).find(entry => entry.name === 'sid');
    assert.equal(cookie?.value, 'fixture-alice-session', 'Synthetic session cookie missing');
    sessionCookie = cookie.name + '=' + cookie.value;
    await loginPage.close();
  }
  const page = await browser.newPage();
  await page.goto('chrome-extension://' + new URL(worker.url()).host + '/manifest.json');
  const result = await page.evaluate(async ({ integrated, origin, marker, payload, sessionCookie }) => {
    const prefix = integrated ? 'security/ptk/' : 'ptk/';
    const load = file => import(chrome.runtime.getURL(prefix + file));
    await load('packages/browser-polyfill/browser-polyfill.min.js');
    const [{ dastEngine }, { ptk_request }, { DastPrivilegedBrowserAdapter }, { loadCanonicalDastRulepack }] = await Promise.all([
      load('background/dast/dastEngine.js'), load('background/rbuilder.js'), load('background/dast/runtime/privilegedBrowserAdapter.js'), load('background/dast/contract/index.js')
    ]);
    const canonical = await (await fetch(chrome.runtime.getURL(prefix + 'background/dast/modules/modules.json'))).json();
    const xss = canonical.modules.find(entry => entry.id === 'xss');
    if (!xss?.attacks?.length) throw Error('Canonical executable XSS rule unavailable');
    const fixtureModule = structuredClone(xss);
    fixtureModule.id = 'stored_xss_blind';
    fixtureModule.name = 'Synthetic stored XSS execution fixture';
    fixtureModule.metadata.taxonomy.vulnId = 'stored_xss';
    fixtureModule.attacks = [structuredClone(xss.attacks.find(entry => entry.id === 'xss_1'))];
    const attack = fixtureModule.attacks[0];
    attack.id = 'stored_fixture_execution';
    attack.action.params = [{ value: payload, position: 'replace', operation: 'replace' }];
    attack.runtime.confirmation.tracking = { enabled: true, mode: 'followup_get', marker, confidence: 90 };
    // Keep the canonical validation contract. The POST response contains no
    // payload, so a finding requires the independent stored tracking channel.
    const rulepack = { schema: 'ptk-dast-rulepack/v1', engine: 'DAST', version: 1, modules: [fixtureModule] };
    loadCanonicalDastRulepack(rulepack, { label: 'stored-positive-fixture' });
    const adapter = new DastPrivilegedBrowserAdapter({ browserApi: globalThis.browser });
    const ownerId = 'stored-positive-fixture';
    const browserOperations = {
      remote: true,
      call: (method, args) => adapter.execute({ type: 'browser_call', ownerId, method, args }),
      sendRuntimeMessage: message => chrome.runtime.sendMessage(message)
    };
    const engine = new dastEngine({ scanStrategy: 'SMART', maxRequestsPerSecond: 5, concurrency: 1, planningConcurrency: 1, rulepack, cveRulepack: { modules: [] }, runCve: false }, { browserOperations });
    await engine._moduleLoadPromise;
    engine.host = new URL(origin).host;
    engine.domains = [];
    const body = 'comment=baseline';
    const raw = 'POST ' + origin + '/submit HTTP/1.1\r\nHost: ' + new URL(origin).host + '\r\nContent-Type: application/x-www-form-urlencoded\r\n'
      + (sessionCookie ? 'Cookie: ' + sessionCookie + '\r\n' : '')
      + 'Content-Length: ' + new TextEncoder().encode(body).length + '\r\n\r\n' + body;
    // A captured baseline is supplied to the real planner. This avoids a second
    // state-changing POST during baseline acquisition.
    engine.taskPlanner.resolveOriginal = async schema => ({ request: schema.request, response: { statusCode: 200, body: '<!doctype html><form><input name="comment"></form>' } });
    const plan = await engine.buildAttackPlan({ raw, ui_url: origin + '/submit' });
    const planned = plan?.tasks?.map(task => ({ moduleId: task.moduleId, attackId: task.attack?.id, attacked: task.payload?.metadata?.attacked, request: task.payload?.request?.raw || task.payload?.request?.url })) || [];
    if (plan?.tasks?.length !== 1) throw Error('Expected one planned stored-XSS task, got ' + (plan?.tasks?.length ?? 'null') + ': ' + JSON.stringify(planned.slice(0, 5)));
    const context = engine._createTaskContext(plan.original, { rateLimited: false, respectEngineState: false });
    const finding = await engine._runTask(plan.tasks[0], context);
    const events = engine.scanResult?.runtimeEvents || engine.runtimeEvents || [];
    await engine._unregisterBrowserNavHarnessScript();
    await adapter.cleanup(ownerId);
    return { planned, finding, events, stats: engine.scanStats };
  }, { integrated, origin, marker, payload, sessionCookie });
  await browser.close(); browser = null;
  const requests = wire.filter(entry => entry.side === currentSide && entry.case === mode).map(({ side, case: _case, ...entry }) => entry);
  assert.equal(requests.filter(entry => entry.method === 'POST' && entry.path === '/submit').length, 1, `${currentSide}/${mode}: expected one mutation`);
  return { result, wire: requests };
}

async function main() {
  reference = resolveReference(process.env.PTK_REFERENCE_ROOT);
  evidence.referenceSha256 = reference.sha256;
  server = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    wire.push({ side: currentSide, case: currentCase, method: req.method, path: req.url, body });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (req.url === '/login' && req.method === 'POST') {
      const fields = new URLSearchParams(body);
      if (fields.get('username') !== 'fixture-alice' || fields.get('password') !== 'local-only-password') {
        res.statusCode = 401; return res.end('bad account');
      }
      res.setHeader('Set-Cookie', 'sid=fixture-alice-session; HttpOnly; SameSite=Lax; Path=/');
      return res.end('signed in');
    }
    if (req.url === '/login') return res.end(pageHtml('synthetic login'));
    if (currentCase === 'authenticated' && !String(req.headers.cookie || '').includes('sid=fixture-alice-session') && req.url !== '/favicon.ico') {
      res.statusCode = 401; return res.end('login required');
    }
    if (req.method === 'POST' && req.url === '/submit') {
      stored = new URLSearchParams(body).get('comment') || '';
      res.statusCode = 302; res.setHeader('Location', '/view'); return res.end('stored');
    }
    if (req.url === '/view') {
      const output = currentCase === 'no_retrieval' ? '' : currentCase === 'escaped' ? escapeHtml(stored)
        : currentCase === 'retrieved_only' ? '<template>' + stored + '</template>' : stored;
      return res.end(pageHtml(output));
    }
    if (req.url === '/submit') return res.end(pageHtml('submission endpoint'));
    res.statusCode = 404; res.end(pageHtml('missing'));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + server.address().port;
  for (const mode of cases) {
    const ref = await run(reference.extensionPath, false, origin, mode);
    const owned = await run(root, true, origin, mode);
    evidence.cases[mode] = { reference: ref, owned };
    save();
    const projectWire = entries => entries.filter(entry => entry.path !== '/favicon.ico').map(entry => {
      if (entry.method !== 'POST') return entry;
      const params = new URLSearchParams(entry.body); params.delete('ptk_rnd');
      return { ...entry, body: params.toString() };
    });
    assert.deepEqual(projectWire(owned.wire), projectWire(ref.wire), `${mode}: wire parity after generated nonce projection`);
    assert.deepEqual(projectResult(owned), projectResult(ref), `${mode}: planner, mutation, confirmation, and event parity`);
    for (const [side, sample] of Object.entries({ reference: ref, owned })) {
      assert.equal(sample.result.planned.length, 1, `${side}/${mode}: planner must select exactly one task`);
      assert.equal(sample.result.planned[0].attacked?.name, 'comment', `${side}/${mode}: wrong mutation target`);
      assert.equal(sample.result.events.some(event => event.error || /failed/.test(event.type)), false,
        `${side}/${mode}: browser or engine error`);
      const skips = sample.result.events.filter(event => /skip/.test(event.type));
      assert.deepEqual(skips.map(event => ({ type: event.type, reason: event.reason, surface: event.surface, samples: event.samples })),
        mode === 'authenticated' ? [{ type: 'dast_selector_skip', reason: 'hard_deny', surface: 'cookies', samples: ['sid'] }] : [],
        `${side}/${mode}: unexpected planner skip`);
    }
    assert.equal(!!owned.result.finding?.success, !!ref.result.finding?.success, `${mode}: finding parity`);
    assert.equal(!!ref.result.finding?.success, mode === 'executing' || mode === 'authenticated', `${mode}: expected positive only for execution`);
    if (mode === 'executing' || mode === 'authenticated') for (const [side, sample] of Object.entries({ reference: ref, owned })) {
      assert.equal(sample.result.finding?.trackingTier, 'executed', `${side}: browser execution tier`);
      assert.equal(sample.result.finding?.metadata?.confirmation?.source, 'stored_xss_retrieval', `${side}: retrieval-backed confirmation`);
      assert.equal(JSON.parse(sample.result.finding.proof).check, 'stored_xss_browser_execution', `${side}: execution proof`);
      assert.equal(JSON.parse(sample.result.finding.proof).render.context?.type, 'attribute_event_handler', `${side}: actual PTK execution context`);
      assert.equal(sample.result.finding.metadata?.mutations?.[0]?.name, 'comment', `${side}: persisted mutation evidence`);
    }
    if (mode === 'escaped' || mode === 'retrieved_only') for (const [side, sample] of Object.entries({ reference: ref, owned })) {
      assert.ok(sample.result.events.some(event => event.type === 'dast_stored_xss_retrieved_unconfirmed'),
        `${side}/${mode}: retrieval must reach browser confirmation and remain unconfirmed`);
    }
    console.log('STORED-POSITIVE', mode, 'reference=' + !!ref.result.finding?.success, 'owned=' + !!owned.result.finding?.success);
  }
  evidence.summary = { parity: true, passedCases: cases, originalHashVerified: true };
  save();
  console.log(JSON.stringify({ evidenceFile, ...evidence.summary }));
}

main().catch(error => { evidence.error = error.stack || error.message; save(); console.error(error); process.exitCode = 1; }).finally(async () => {
  await browser?.close();
  if (server) await new Promise(resolve => server.close(resolve));
  const parent = path.resolve(os.tmpdir()) + path.sep;
  for (const folder of [profileRoot, reference?.directory]) {
    if (folder && path.resolve(folder).startsWith(parent) && /^cert-x-(?:stored-positive|security-reference)-/.test(path.basename(folder))) {
      fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
});

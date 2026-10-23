// Scripted provider -> actual agent/browser tools -> full DAST planner and transport.
// The browser supplies normal authenticated workflow inputs; scanner payloads come from PTK.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-dast-workflow-'));
const evidenceFile = path.join(root, 'tools/security/evidence/dast-workflow-browser.json');
const wire = [], results = new Map(), cases = [], errors = [], modelCalls = [];
let failWorkflow; const fatal = new Promise(resolve => { failWorkflow = resolve; });
let browser, server, worker, panel, origin, tabId, currentCase = 'reflect', stage = 'navigate', poll = 0, sequence = 0, priming = true;
const decode = value => { try { return JSON.parse(String(value).replace(/^<system>.*?<\/system>\s*/s, '')); } catch { return { text: value }; } };
const result = name => { const value = results.get(currentCase + '-' + name); assert.ok(value, 'Missing tool result ' + name); return value; };
const cdp = expression => ({ method: 'Runtime.evaluate', params: { expression, returnByValue: true, awaitPromise: true } });
const options = { preset: 'thorough', moduleIds: ['xss'], runCve: false, maxRequests: 60, maxRequestsPerSecond: 20, concurrency: 1, planningConcurrency: 1, durationSeconds: 60 };
async function nextTask() {
  if (stage === 'navigate') { stage = 'login'; return ['navigate', 'navigate', { url: origin + '/login?next=' + currentCase, newTab: true }]; }
  if (stage === 'login') { stage = 'start'; return ['login', 'cdp', cdp(`document.querySelector('[name=username]').value='fixture';document.querySelector('form').requestSubmit();'submitted'`)]; }
  if (stage === 'start') {
    for (let attempt = 0; attempt < 100; attempt++) {
      tabId = await worker.evaluate(async url => (await chrome.tabs.query({})).find(tab => tab.url === url)?.id, origin + '/app/' + currentCase);
      if (Number.isInteger(tabId)) break;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.ok(Number.isInteger(tabId), 'Login must reach authenticated form before scan');
    stage = 'shallow'; poll = 0; return ['start', 'security_start_scan', { tabId, engines: ['DAST'], options }];
  }
  if (stage === 'shallow') {
    const latest = results.get(currentCase + '-shallow-' + (poll - 1));
    if (latest?.engineStatus?.DAST?.idle === true && latest?.coverage?.dast?.baselineDispatches >= 1) {
      assert.equal(latest.coverage.dast.probeDispatches, 0, 'A page without submitted inputs has no active probes');
      cases.push({ name: currentCase, runId: result('start').runId, shallow: latest.coverage });
      stage = 'submit';
    } else { assert.ok(poll < 80, 'Initial scanner work did not finish'); await new Promise(resolve => setTimeout(resolve, 150)); return ['shallow-' + poll++, 'security_scan_status', { runId: result('start').runId }]; }
  }
  if (stage === 'submit') { stage = 'active'; poll = 0; return ['submit', 'cdp', cdp(`document.querySelector('[name=q]').value='workflow-marker';document.querySelector('form').requestSubmit();'submitted'`)]; }
  if (stage === 'active') {
    const latest = results.get(currentCase + '-active-' + (poll - 1));
    if (latest?.engineStatus?.DAST?.idle === true && latest?.coverage?.dast?.probeDispatches > 0 && latest?.coverage?.dast?.tasksPlanned > 0) {
      assert.equal(latest.state, 'running'); assert.equal(latest.coverage.dast.taskErrors, 0);
      assert.equal(latest.coverage.dast.taskSkips, 0); cases.at(-1).afterWorkflow = latest.coverage;
      stage = 'stop';
    } else { assert.ok(poll < 100, 'Submitted form was not fully scanned: ' + JSON.stringify(latest)); await new Promise(resolve => setTimeout(resolve, 150)); return ['active-' + poll++, 'security_scan_status', { runId: result('start').runId }]; }
  }
  if (stage === 'stop') { stage = 'findings'; return ['stop', 'security_stop_scan', { runId: result('start').runId }]; }
  if (stage === 'findings') { stage = 'check'; return ['findings', 'security_get_findings', { runId: result('start').runId }]; }
  if (stage === 'check') {
    const ended = result('stop'), findings = result('findings');
    assert.equal(ended.state, 'completed', JSON.stringify(ended.coverage));
    cases.at(-1).state = ended.state; cases.at(-1).findings = findings.findings;
    const posts = wire.filter(item => item.path === '/test/' + currentCase && item.method === 'POST');
    assert.ok(posts.length > 2);assert.ok(posts.every(item => item.authenticated), 'Scanner uses the authenticated browser request');
    const mutations = posts.filter(item => item.body !== 'q=workflow-marker');
    assert.ok(mutations.length > 0, 'Scanner mutates the form body');
    cases.at(-1).postCount = posts.length; cases.at(-1).mutations = mutations.length;
    const xss = findings.findings.filter(item => /xss/i.test(item.moduleId || item.ruleId || item.title || ''));
    if (currentCase === 'reflect') { assert.ok(xss.length > 0, JSON.stringify(findings)); currentCase = 'safe'; stage = 'navigate'; return nextTask(); }
    assert.equal(findings.total, 0, 'Escaped control must not yield a reflected XSS finding');
    stage = 'done'; return null;
  }
}
async function main() {
  server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');res.setHeader('Access-Control-Allow-Headers', '*');
    if (req.method === 'OPTIONS') return res.end();
    if (req.url.endsWith('/models')) { res.setHeader('Content-Type', 'application/json');return res.end(JSON.stringify({ data: [{ id: 'fixture/workflow', name: 'Workflow fixture' }] })); }
    let body = ''; for await (const chunk of req) body += chunk;
    if (req.url.includes('/chat/completions')) {
      try {
        const request = JSON.parse(body);
        for (const message of request.messages || []) if (message.role === 'tool' && message.tool_call_id?.startsWith('wf-')) {
          const value = decode(typeof message.content === 'string' ? message.content : message.content?.filter(part => part.type === 'text').map(part => part.text).join('\n'));
          results.set(message.tool_call_id.slice(3), value); assert.ok(value.error == null, message.tool_call_id + ': ' + JSON.stringify(value));
        }
        const task = priming ? null : await nextTask();
        console.log('Workflow step', currentCase, task?.[0] || 'complete');
        if (task) assert.ok((request.tools || []).some(tool => tool.function.name === task[1]), 'Tool must be advertised: ' + task[1]);
        modelCalls.push({ case: currentCase, stage, tool: task?.[1] || null });
        const delta = task ? { role: 'assistant', tool_calls: [{ index: 0, id: 'wf-' + currentCase + '-' + task[0], type: 'function', function: { name: task[1], arguments: JSON.stringify(task[2]) } }] } : { role: 'assistant', content: priming ? 'DAST WORKFLOW PRIME COMPLETE' : 'DAST WORKFLOW FIXTURE COMPLETE' };
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        for (const value of [{ id: 'wf-' + ++sequence, object: 'chat.completion.chunk', choices: [{ index: 0, delta }] }, { id: 'wf-' + sequence, object: 'chat.completion.chunk', choices: [{ index: 0, delta: {}, finish_reason: task ? 'tool_calls' : 'stop' }] }]) res.write('data: ' + JSON.stringify(value) + '\n\n');
        return res.end('data: [DONE]\n\n');
      } catch (error) { errors.push(error.stack);console.error(error);failWorkflow(error);res.statusCode = 500;return res.end(error.message); }
    }
    const url = new URL(req.url, 'http://fixture'), authenticated = /fixture_auth=1/.test(req.headers.cookie || '');
    if (url.pathname === '/favicon.ico') { res.writeHead(204);return res.end(); }
    wire.push({ method: req.method, path: url.pathname, body, authenticated });
    res.setHeader('Content-Type', 'text/html');res.setHeader('Cache-Control', 'no-store');
    if (url.pathname === '/login') {
      const next = url.searchParams.get('next') === 'safe' ? 'safe' : 'reflect';
      if (req.method === 'POST') { assert.equal(new URLSearchParams(body).get('username'), 'fixture');res.writeHead(303, { 'Set-Cookie': 'fixture_auth=1; HttpOnly; SameSite=Lax; Path=/', Location: '/app/' + next });return res.end(); }
      return res.end('<!doctype html><title>Login</title><form method="POST"><input name="username"><button>Login</button></form>');
    }
    if (!authenticated) { res.writeHead(401);return res.end('Sign in required'); }
    if (url.pathname.startsWith('/app/')) return res.end('<!doctype html><title>Authenticated application</title><h1>Fixture account</h1><form method="POST" action="/test/' + url.pathname.split('/').at(-1) + '"><input name="q"><button>Search</button></form>');
    const q = new URLSearchParams(body).get('q') || '';
    const output = url.pathname === '/test/safe' ? q.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;') : q;
    res.end('<!doctype html><title>Results</title><div>' + output + '</div>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));origin = 'http://127.0.0.1:' + server.address().port;
  browser = await chromium.launchPersistentContext(path.join(temp, 'profile'), { headless: true, viewport: { width: 720, height: 950 }, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');await worker.evaluate(() => certXSecurity.ready);
  await worker.evaluate(async origin => chrome.storage.local.set({ sidepanel_language: 'en', sidepanel_approval_mode: 'full_access', sidepanel_connections: [{ id: 'fixture', label: 'Workflow fixture', presetId: 'openrouter', apiKey: 'fixture', host: origin + '/api/v1' }] }), origin);
  panel = await browser.newPage();await panel.goto('chrome-extension://' + new URL(worker.url()).host + '/pages/sidepanel.html');await panel.waitForFunction(() => document.querySelector('.wb-composer-model .wb-mode-toggle')?.disabled === false);
  await panel.locator('.wb-editor').first().click();await panel.keyboard.type('Prepare the local scan workflow fixture.');await panel.keyboard.press('Enter');await panel.getByText('DAST WORKFLOW PRIME COMPLETE', { exact: true }).waitFor({ timeout: 30000 });
  await panel.getByLabel('Profile', { exact: true }).selectOption('bugbounty');await panel.waitForFunction(() => document.querySelector('[aria-label="Profile"]').disabled === false);priming = false;
  await panel.locator('.wb-editor').first().click();await panel.keyboard.type('Run the local authenticated scan workflow fixture.');await panel.keyboard.press('Enter');await Promise.race([panel.getByText('DAST WORKFLOW FIXTURE COMPLETE', { exact: true }).waitFor({ timeout: 180000 }), fatal.then(error => { throw error; })]);
  assert.deepEqual(errors, []);assert.equal(cases.length, 2);
  fs.writeFileSync(evidenceFile, JSON.stringify({ provider: 'scripted_fixture', liveModelInference: false, cases, wire, modelCalls }, null, 2));
  console.log(JSON.stringify({ evidenceFile, cases: cases.map(item => ({ name: item.name, state: item.state, findings: item.findings.length, posts: item.postCount, mutations: item.mutations })), providerCalls: modelCalls.length }));
}
main().catch(async error => { console.error(error);fs.writeFileSync(evidenceFile, JSON.stringify({ error: error.stack, stage, currentCase, cases, wire, modelCalls, errors, results: Object.fromEntries(results) }, null, 2));process.exitCode = 1; }).finally(async () => {
  await browser?.close();if (server) await new Promise(resolve => { server.close(resolve);server.closeAllConnections(); });
  const resolved = fs.realpathSync(temp);assert.ok(resolved.startsWith(fs.realpathSync(os.tmpdir()) + path.sep) && path.basename(resolved).startsWith('cert-x-dast-workflow-'));fs.rmSync(resolved, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

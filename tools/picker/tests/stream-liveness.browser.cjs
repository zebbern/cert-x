// Subagent model streams through the real side panel against a scripted provider:
// - think: the subagent reasons (OpenRouter's delta.reasoning / reasoning_details,
//   the wire format captured from xiaomi/mimo-v2.6-pro) for longer than the stall
//   budget, then calls a tool, then answers. The stream is alive, so there is no
//   stall retry, and the reasoning is neither echoed in the next request nor shown.
// - silent: headers, then nothing. The orchestrator must get the stall error itself,
//   after the retries, not an error thrown by the error handling.
// - cut: the stream closes without a finish reason. That is a retryable
//   incomplete-response error and must be reported as one.
// - error: the provider reports an error inside the stream, a generic provider error
//   whose retry decision goes through the media-error check (Rd, Fd).
// - quiet: only OpenRouter's keep-alive comments (": OPENROUTER PROCESSING") for
//   longer than the stall budget, then the answer: a model working without
//   streaming anything is alive too.
// - refused, gone: a content-filter refusal and a 404 for the model. Delegating
//   again fails the same way, so the orchestrator is told it is not retryable and
//   that the user has to act; silent, cut and error are retryable.
// The stall budget is shortened through a test hook, so this needs a test build:
// KI_TEST_HOOKS=1 node tools/picker/apply-picker.js
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), http = require('node:http'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-stream-liveness-'));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
// 1.5 s instead of 90 s; the think scenario reasons for three budgets.
const IDLE_MS = 1500, THINK_MS = 3 * IDLE_MS, THINK_EVERY_MS = 200;
const SCENARIOS = ['think', 'silent', 'cut', 'error', 'quiet', 'refused', 'gone'];
const sub = Object.fromEntries(SCENARIOS.map(s => [s, { requests: 0, resumes: 0 }])), results = {}, pageErrors = [];
let echoed = null;

const text = content => typeof content === 'string' ? content : (content || []).map(part => part.text || '').join('');
const chunk = delta => 'data: ' + JSON.stringify({ id: 'liveness', object: 'chat.completion.chunk', model: 'mock/liveness', choices: [{ index: 0, delta, finish_reason: null }] }) + '\n\n';
const finish = reason => 'data: ' + JSON.stringify({ id: 'liveness', object: 'chat.completion.chunk', model: 'mock/liveness', choices: [{ index: 0, delta: {}, finish_reason: reason }] }) + '\n\ndata: [DONE]\n\n';

async function subagent(scenario, res, request) {
  if (scenario === 'gone') {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: { message: 'No endpoints found for mock/liveness.', code: 404 } }));
  }
  res.writeHead(200, { 'Content-Type': 'text/event-stream' });
  if (scenario === 'refused') return res.end(chunk({ role: 'assistant', content: '' }) + 'data: ' + JSON.stringify({ choices: [{ index: 0, delta: { refusal: 'blocked' }, finish_reason: 'content_filter' }] }) + '\n\n');
  if (scenario === 'quiet') {
    res.flushHeaders();
    for (const end = Date.now() + THINK_MS; Date.now() < end && !res.destroyed;) {
      res.write(': OPENROUTER PROCESSING\n\n');
      await sleep(THINK_EVERY_MS);
    }
    return res.end(chunk({ role: 'assistant', content: 'SUB-QUIET-OK' }) + finish('stop'));
  }
  // Headers out, then nothing: what the live run saw (NET-RES 200, then silence).
  if (scenario === 'silent') return res.flushHeaders();
  if (scenario === 'cut') return res.end(chunk({ role: 'assistant', content: 'partial' }));
  // OpenRouter's in-stream error shape (HTTP 200, then an error event).
  if (scenario === 'error') return res.end(chunk({ role: 'assistant', content: '' }) + 'data: ' + JSON.stringify({ error: { message: 'Provider returned error', code: 502 } }) + '\n\n');
  if (request.messages.some(m => m.role === 'tool')) {
    // The request after the tool call carries the reasoning turn back as history.
    echoed = JSON.stringify(request.messages).includes('step ') || request.messages.some(m => m.reasoning_content || m.reasoning);
    return res.end(chunk({ role: 'assistant', content: 'SUB-THOUGHT-OK' }) + finish('stop'));
  }
  res.write(chunk({ role: 'assistant', content: '' }));
  for (const end = Date.now() + THINK_MS; Date.now() < end && !res.destroyed;) {
    res.write(chunk({ content: '', reasoning: 'step ', reasoning_details: [{ type: 'reasoning.text', text: 'step ', format: 'unknown', index: 0 }] }));
    await sleep(THINK_EVERY_MS);
  }
  const tool = (request.tools || []).map(t => t.function?.name).find(n => n === 'graph_digest') || 'graph_digest';
  res.end(chunk({ tool_calls: [{ index: 0, id: 'call-think', type: 'function', function: { name: tool, arguments: '{}' } }] }) + finish('tool_calls'));
}

const provider = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://fixture');
  if (url.pathname.endsWith('/models')) { res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({ data: [{ id: 'mock/liveness', name: 'Liveness', context_length: 128000 }] })); }
  if (!url.pathname.endsWith('/chat/completions')) { res.writeHead(404); return res.end(); }
  let body = ''; req.on('data', part => body += part); req.on('end', () => {
    const request = JSON.parse(body), messages = request.messages || [];
    const users = messages.filter(m => m.role === 'user').map(m => text(m.content));
    const brief = users.find(u => /SUB-(\w+)/.test(u));
    if (brief) {
      const scenario = brief.match(/SUB-(\w+)/)[1];
      sub[scenario].requests++; if (brief.includes('[resume]')) sub[scenario].resumes++;
      return subagent(scenario, res, request).catch(() => res.destroy());
    }
    // Orchestrator: delegate once per user message, then report what came back.
    // Requests without a marker (a chat title, say) get a plain answer.
    const scenario = users.findLast(u => /RUN-\w+/.test(u))?.match(/RUN-(\w+)/)[1], last = messages.at(-1);
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    if (!scenario) return res.end(chunk({ role: 'assistant', content: 'Liveness' }) + finish('stop'));
    if (last.role === 'tool') {
      results[scenario] = text(last.content);
      return res.end(chunk({ role: 'assistant', content: 'MAIN-DONE-' + scenario }) + finish('stop'));
    }
    const call = { index: 0, id: 'call-' + scenario, type: 'function', function: { name: 'agent', arguments: JSON.stringify({ description: 'Liveness ' + scenario, prompt: 'SUB-' + scenario + ': answer in one line.' }) } };
    res.end(chunk({ role: 'assistant', tool_calls: [call] }) + finish('tool_calls'));
  });
});

async function main() {
  let browser;
  try {
    await new Promise(resolve => provider.listen(0, '127.0.0.1', resolve));
    browser = await chromium.launchPersistentContext(temp, { headless: true, viewport: { width: 720, height: 1000 }, executablePath: require('../../chromium-path.cjs'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
    const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker', { timeout: 15000 });
    assert.equal(await worker.evaluate(() => typeof globalThis.kiTest?.setStreamIdle), 'function', 'kiTest exposes the stall budget (build with KI_TEST_HOOKS=1 node tools/picker/apply-picker.js)');
    await worker.evaluate(ms => kiTest.setStreamIdle(ms), IDLE_MS);
    const base = 'chrome-extension://' + new URL(worker.url()).host, host = 'http://127.0.0.1:' + provider.address().port + '/api/v1';
    for (let i = 0; i < 8; i++) {
      await worker.evaluate(h => chrome.storage.local.set({ sidepanel_language: 'en', sidepanel_approval_mode: 'full_access', sidepanel_connections: [{ id: 'mock', label: 'Mock', presetId: 'openrouter', apiKey: 'fixture', host: h }] }), host);
      await sleep(300);
      if ((await worker.evaluate(() => chrome.storage.local.get('sidepanel_connections'))).sidepanel_connections?.length) break;
    }
    const target = await browser.newPage(); await target.goto('about:blank');
    const tabId = await worker.evaluate(() => chrome.tabs.query({}).then(tabs => Math.max(...tabs.map(t => t.id))));
    const panel = await browser.newPage(); panel.on('pageerror', error => pageErrors.push(error.message));
    await panel.goto(base + '/pages/sidepanel.html?tabId=' + tabId);
    await panel.waitForFunction(() => document.querySelector('[aria-label="Profile"]')?.disabled === false);
    for (const scenario of SCENARIOS) {
      const started = Date.now();
      await panel.locator('.wb-editor').first().click();
      await panel.keyboard.type('RUN-' + scenario);
      await panel.keyboard.press('Enter');
      await panel.getByText('MAIN-DONE-' + scenario, { exact: true }).waitFor({ timeout: 90000 });
      console.log(scenario.padEnd(6), ((Date.now() - started) / 1000).toFixed(1) + 's', JSON.stringify(sub[scenario]), JSON.stringify((results[scenario] || '').slice(0, 160)));
      await panel.waitForFunction(() => document.querySelector('[aria-label="Profile"]')?.disabled === false);
    }

    assert.equal(sub.think.requests, 2, 'a subagent that keeps streaming reasoning is alive: its reasoning turn and the turn after its tool call, no stall retry');
    assert.match(results.think, /SUB-THOUGHT-OK/, 'the reasoning subagent answer reaches the orchestrator');
    assert.equal(echoed, false, 'reasoning kept the stream alive but is not sent back in the history');
    assert.doesNotMatch(await panel.locator('body').innerText(), /step step/, 'reasoning is not shown in the panel');
    // Three tries per run (Rj maxAttempts 3), then the runner's one [resume] rerun.
    for (const scenario of ['silent', 'cut', 'error']) {
      assert.equal(sub[scenario].requests, 6, scenario + ': retried three times per run, and the run once more with [resume]');
      assert.equal(sub[scenario].resumes, 3, scenario + ': the second run is the [resume] rerun');
      assert.doesNotMatch(results[scenario], /Class constructor|object Object|is not a function/, scenario + ': the error handling must not throw its own error');
    }
    assert.match(results.silent, /no chunk arrived for 1500ms/, 'the orchestrator gets the stall error itself');
    assert.match(results.cut, /ended without a finish reason/, 'the orchestrator gets the incomplete-response error itself');
    assert.match(results.error, /Provider returned error/, 'the orchestrator gets the provider error itself');
    assert.equal(sub.quiet.requests, 1, 'keep-alive comments keep the stream alive: no stall retry');
    assert.match(results.quiet, /SUB-QUIET-OK/, 'the quiet subagent answer reaches the orchestrator');
    const envelope = scenario => JSON.parse(results[scenario].slice(results[scenario].indexOf('{')));
    for (const scenario of ['silent', 'cut', 'error']) assert.equal(envelope(scenario).retryable, true, scenario + ': delegating again can work');
    for (const scenario of ['refused', 'gone']) {
      assert.equal(sub[scenario].requests, 1, scenario + ': neither the stream retry nor the [resume] rerun repeats it');
      assert.equal(envelope(scenario).retryable, false, scenario + ': delegating again fails the same way');
      assert.equal(envelope(scenario).userAction, true, scenario + ': only the user can fix it');
    }
    assert.match(results.refused, /provider refused this request/, 'the refusal names its cause');
    assert.match(results.gone, /No endpoints found/, 'the 404 quotes the provider');
    assert.deepEqual(pageErrors, [], 'no page errors');
    console.log('STREAM-LIVENESS-PASS');
  } catch (error) {
    console.error('STREAM-LIVENESS-FAIL', error.message);
    console.error('DEBUG', JSON.stringify({ sub, results: Object.fromEntries(Object.entries(results).map(([k, v]) => [k, v.slice(0, 300)])) }));
    process.exitCode = 1;
  } finally {
    try { await Promise.race([browser?.close(), sleep(5000)]); } catch {}
    provider.close(); fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    process.exit(process.exitCode || 0);
  }
}
main();

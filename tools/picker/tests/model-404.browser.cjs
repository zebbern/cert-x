// The provider starts answering 404 for the chosen model (OpenRouter's "No
// endpoints found" body) through the real side panel. Both the next turn and a
// manual /compact fail with a message that names the model, quotes the provider
// and points at the model menu; no other model is called (the other one still
// works, so a silent switch would succeed) and the saved default model is left as
// it was.
// Production build: node tools/picker/apply-picker.js
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), http = require('node:http'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-model-404-'));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const GONE = 'mock/gone', OTHER = 'mock/other', SAVED = { connectionId: 'mock', modelId: GONE };
const PROVIDER_SAID = 'No endpoints found for ' + GONE + '.';
const requested = [], pageErrors = [];
let gone = false;

const chunk = (model, delta, finish) => 'data: ' + JSON.stringify({ id: 'model-404', object: 'chat.completion.chunk', model, choices: [{ index: 0, delta, finish_reason: finish }] }) + '\n\n';
const provider = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://fixture');
  // The other model is listed first: a silent fallback to the first catalog entry would call it.
  if (url.pathname.endsWith('/models')) { res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({ data: [{ id: OTHER, name: 'Other', context_length: 128000 }, { id: GONE, name: 'Gone', context_length: 128000 }] })); }
  if (!url.pathname.endsWith('/chat/completions')) { res.writeHead(404); return res.end(); }
  let body = ''; req.on('data', part => body += part); req.on('end', () => {
    const { model, stream } = JSON.parse(body);
    if (gone) requested.push(model);
    if (gone && model === GONE) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: { message: PROVIDER_SAID, code: 404 } }));
    }
    if (!stream) { res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({ id: 'model-404', object: 'chat.completion', model, choices: [{ index: 0, message: { role: 'assistant', content: 'HELLO-OK' }, finish_reason: 'stop' }] })); }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.end(chunk(model, { role: 'assistant', content: 'HELLO-OK' }, null) + chunk(model, {}, 'stop') + 'data: [DONE]\n\n');
  });
});

async function main() {
  let browser, panel, notice = '', compactNotice = '';
  try {
    await new Promise(resolve => provider.listen(0, '127.0.0.1', resolve));
    browser = await chromium.launchPersistentContext(temp, { headless: true, viewport: { width: 720, height: 1000 }, executablePath: require('../../chromium-path.cjs'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
    const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker', { timeout: 15000 });
    const base = 'chrome-extension://' + new URL(worker.url()).host, host = 'http://127.0.0.1:' + provider.address().port + '/api/v1';
    for (let i = 0; i < 8; i++) {
      await worker.evaluate(([h, saved]) => chrome.storage.local.set({ sidepanel_language: 'en', sidepanel_approval_mode: 'full_access', sidepanel_connections: [{ id: 'mock', label: 'Mock', presetId: 'openrouter', apiKey: 'fixture', host: h }], sidepanel_last_model_v2: saved }), [host, SAVED]);
      await sleep(300);
      if ((await worker.evaluate(() => chrome.storage.local.get('sidepanel_connections'))).sidepanel_connections?.length) break;
    }
    const target = await browser.newPage(); await target.goto('about:blank');
    const tabId = await worker.evaluate(() => chrome.tabs.query({}).then(tabs => Math.max(...tabs.map(t => t.id))));
    panel = await browser.newPage(); panel.on('pageerror', error => pageErrors.push(error.message));
    await panel.goto(base + '/pages/sidepanel.html?tabId=' + tabId);
    const idle = () => panel.waitForFunction(() => document.querySelector('[aria-label="Profile"]')?.disabled === false, null, { timeout: 60000 });
    const send = async text => { await panel.locator('.wb-editor').first().click(); await panel.keyboard.type(text); await panel.keyboard.press('Enter'); };
    await idle();

    // A working turn first, so the conversation has something to compact.
    await send('MODEL-404 say hi');
    await panel.getByText('HELLO-OK').first().waitFor({ timeout: 60000 });
    await idle();
    gone = true;

    await send('MODEL-404 again');
    await panel.locator('.wb-notice-error .wb-notice-text').first().waitFor({ timeout: 60000 });
    await idle();
    await sleep(1500); // a fallback to another model would show up here
    notice = await panel.locator('.wb-notice-error .wb-notice-text').first().innerText();
    console.log('notice   ', JSON.stringify(notice));
    const afterTurn = requested.length;

    await send('/compact'); // Enter picks the command from the slash menu; the next Enter sends it
    await sleep(300); await panel.keyboard.press('Enter');
    await panel.waitForFunction(() => document.querySelectorAll('.wb-notice-error .wb-notice-text').length >= 2 || /Context compacted|switched to/.test(document.body.innerText), null, { timeout: 60000 });
    await idle();
    const errors = await panel.locator('.wb-notice-error .wb-notice-text').allInnerTexts();
    compactNotice = errors[1] || '';
    console.log('compact  ', JSON.stringify(compactNotice));
    console.log('requested', JSON.stringify(requested));

    for (const [label, text] of [['turn', notice], ['compaction', compactNotice]]) {
      assert.ok(text.includes(GONE), label + ': the message names the model');
      assert.ok(text.includes(PROVIDER_SAID), label + ': the message quotes the provider');
      assert.match(text, /model menu/, label + ': the message says where to pick another model');
    }
    assert.match(compactNotice, /^Compaction failed/, 'the compaction notice says what failed');
    assert.ok(afterTurn > 0 && requested.length > afterTurn, 'the chosen model was called for the turn and for the compaction');
    assert.deepEqual([...new Set(requested)], [GONE], 'no other model is called');
    assert.doesNotMatch(await panel.locator('body').innerText(), /switched to/, 'no model switch notice');
    assert.deepEqual((await worker.evaluate(() => chrome.storage.local.get('sidepanel_last_model_v2'))).sidepanel_last_model_v2, SAVED, 'the saved default model is unchanged');
    assert.deepEqual(pageErrors, [], 'no page errors');
    console.log('MODEL-404-PASS');
  } catch (error) {
    console.error('MODEL-404-FAIL', error.message);
    const notices = await panel?.locator('.wb-notice-text').allInnerTexts().catch(() => []);
    const editor = await panel?.locator('.wb-editor').first().innerText().catch(() => '');
    console.error('DEBUG', JSON.stringify({ notice, compactNotice, requested, pageErrors, notices, editor }));
    process.exitCode = 1;
  } finally {
    try { await Promise.race([browser?.close(), sleep(5000)]); } catch {}
    provider.close(); fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    process.exit(process.exitCode || 0);
  }
}
main();

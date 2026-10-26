// Real Chromium: the Fast browse switch in Settings → Models and in the side
// panel's model menu, with a stub decision function standing in for the key check.
// Covers: off with nothing configured, a rejected key is not saved, a working key
// turns it on (Save or the switch), the switch turns it off and on and keeps
// keyboard focus, an OpenRouter key is recognized, a failed check survives the menu
// closing, a saved OpenRouter provider needs no key, both switches stay in sync,
// and the agent is not told to re-enable a switch the user turned off.
// Needs a test build: KI_TEST_HOOKS=1 node tools/picker/apply-picker.js
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-fast-browse-'));
const shots = process.env.SHOTS;
let browser, server, failures = [];
async function check(name, fn) { try { await fn(); } catch (error) { failures.push(name + ': ' + error.message.split('\n')[0]); } }

async function main() {
  server = http.createServer((req, res) => {
    res.setHeader('access-control-allow-origin', '*'); res.setHeader('access-control-allow-headers', '*');
    if (req.method === 'OPTIONS') return res.end();
    if (req.url.endsWith('/models')) { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify({ data: [{ id: 'acme/agent-1', name: 'Acme: Agent 1', context_length: 200000 }] })); }
    res.statusCode = 404; res.end();
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const origin = 'http://127.0.0.1:' + server.address().port;
  browser = await chromium.launchPersistentContext(temp, { headless: true, viewport: { width: 420, height: 820 }, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
  const id = new URL(worker.url()).host;
  assert.equal(await worker.evaluate(() => typeof globalThis.kiTest?.setBrowseDecide), 'function', 'kiTest exposes the decision hook (build with KI_TEST_HOOKS=1 node tools/picker/apply-picker.js)');
  // A model provider that is not OpenRouter, so Fast browse starts with nothing to use.
  const custom = { id: 'c1', label: 'Acme', presetId: 'custom', apiKey: 'x', host: origin + '/api/v1' };
  await new Promise(r => setTimeout(r, 1500));
  await worker.evaluate(c => chrome.storage.local.set({ sidepanel_connections: [c] }).then(() => chrome.storage.local.remove('ki_fast_browse')), custom);
  // The key check: "bad-key" is rejected the way TypeSafe rejects one (HTTP 401).
  await worker.evaluate(() => kiTest.setBrowseDecide(async config => {
    (globalThis.kiChecks ||= []).push(config.backend);
    if (config.key === 'slow-bad-key') await new Promise(r => setTimeout(r, 1500));
    if (/bad-key$/.test(config.key)) throw Object.assign(Error('Decision model returned HTTP 401: invalid key; nothing was executed.'), { status: 401 });
    return { op: 'CLICK', target: 'e1', model: 'stub' };
  }));
  const saved = () => worker.evaluate(() => chrome.storage.local.get('ki_fast_browse').then(s => s.ki_fast_browse || {}));
  const ready = () => worker.evaluate(() => kiTest.browseReady());

  const settings = await browser.newPage();
  const errors = [];
  settings.on('pageerror', e => errors.push('settings: ' + e.message));
  await settings.goto('chrome-extension://' + id + '/providers/providers.html?section=models');
  const status = settings.locator('#fast-browse-status'), toggle = settings.locator('#fast-browse-switch'), key = settings.locator('#fast-browse-key'), error = settings.locator('#fast-browse-error');
  const statusIs = async re => { for (let i = 0; i < 50 && !re.test(await status.innerText()); i++) await settings.waitForTimeout(100); assert.match(await status.innerText(), re); };

  await check('settings: off with no key and no OpenRouter provider', async () => {
    await statusIs(/^Off · paste a key/);
    assert.equal(await toggle.getAttribute('aria-checked'), 'false');
    await toggle.click();
    assert.match(await error.innerText(), /Paste a TypeSafe or OpenRouter key first/);
    assert.equal(await settings.evaluate(() => document.activeElement?.id), 'fast-browse-key', 'the switch points at the key box');
  });
  await check('settings: a rejected key is not saved', async () => {
    await key.fill('bad-key');
    await settings.locator('#fast-browse-save').click();
    await error.waitFor({ state: 'visible' });
    for (let i = 0; i < 50 && !/did not accept/.test(await error.innerText()); i++) await settings.waitForTimeout(100);
    assert.match(await error.innerText(), /^TypeSafe did not accept this key\. The key was not saved\.$/);
    assert.equal((await saved()).key, undefined);
    assert.equal(await ready(), false);
  });
  await check('settings: a working key turns it on', async () => {
    await key.fill('good-key');
    await settings.locator('#fast-browse-save').click();
    await statusIs(/^On · TypeSafe Jev · key works \(\d+ ms\)$/);
    assert.equal(await error.isHidden(), true, 'the earlier error is cleared');
    assert.equal(await toggle.getAttribute('aria-checked'), 'true');
    assert.deepEqual(await saved(), { key: 'good-key', on: true });
    assert.equal(await ready(), true, 'browse is offered to the agent');
  });
  if (shots) await settings.locator('#fast-browse-bar').evaluate(el => el.scrollIntoView()), await settings.screenshot({ path: path.join(shots, 'settings-on.png') });
  await check('settings: the switch turns it off and on', async () => {
    await toggle.click();
    await statusIs(/^Off$/);
    assert.equal(await settings.evaluate(() => document.activeElement?.id), 'fast-browse-switch', 'focus stays on the switch');
    assert.equal((await saved()).on, false);
    assert.equal(await ready(), false);
    await toggle.click();
    await statusIs(/^On · TypeSafe Jev$/);
    assert.equal(await ready(), true);
  });
  await check('settings: an OpenRouter key is recognized', async () => {
    await key.fill('sk-or-v1-test');
    await settings.locator('#fast-browse-save').click();
    await statusIs(/^On · Gemini 3\.1 Flash Lite via OpenRouter · key works/);
    assert.equal(await worker.evaluate(() => globalThis.kiChecks.at(-1)), 'openrouter');
  });
  await check('settings: clearing the key removes it', async () => {
    await key.fill('');
    await settings.locator('#fast-browse-save').click();
    await statusIs(/^Off · paste a key/);
    assert.equal((await saved()).key, undefined);
  });
  await check('settings: pasting a key and flipping the switch uses that key', async () => {
    await key.fill('good-key');
    await toggle.click();
    await statusIs(/^On · TypeSafe Jev · key works/);
    assert.deepEqual(await saved(), { key: 'good-key', on: true });
    assert.equal(await settings.evaluate(() => document.activeElement?.id), 'fast-browse-switch');
    await key.fill('');
    await settings.locator('#fast-browse-save').click();
    await statusIs(/^Off · paste a key/);
  });

  const panel = await browser.newPage();
  panel.on('pageerror', e => errors.push('panel: ' + e.message));
  await panel.goto('chrome-extension://' + id + '/pages/sidepanel.html');
  const pill = panel.locator('.wb-composer-model .wb-mode-toggle'), row = panel.locator('.ki-fb-row'), sub = row.locator('.ki-mm-sub');
  const subIs = async re => { for (let i = 0; i < 50 && !re.test(await sub.innerText()); i++) await panel.waitForTimeout(100); assert.match(await sub.innerText(), re); };
  const openMenu = async () => {
    for (let i = 0; i < 30 && await pill.isDisabled(); i++) await panel.waitForTimeout(500);
    if (!await panel.locator('.ki-mm').count()) await pill.click();
    await row.waitFor();
  };

  await check('model menu: the switch is there and asks for a key', async () => {
    await openMenu();
    await subIs(/^Add a key to turn on$/);
    assert.equal(await row.getAttribute('aria-checked'), 'false');
    await row.click();
    await panel.locator('.ki-fb-form').waitFor();
    assert.equal(await panel.evaluate(() => document.activeElement?.className), 'ki-fb-key', 'the key box takes focus');
  });
  await check('model menu: a rejected key shows why', async () => {
    await panel.keyboard.type('bad-key');
    await panel.keyboard.press('Enter');
    await panel.locator('.ki-fb-err').waitFor();
    assert.match(await panel.locator('.ki-fb-err').innerText(), /did not accept this key/);
    assert.equal(await panel.locator('.ki-mm').count(), 1, 'the menu stays open');
  });
  if (shots) await panel.screenshot({ path: path.join(shots, 'menu-key.png') });
  await check('model menu: a working key turns it on', async () => {
    await panel.locator('.ki-fb-key').fill('good-key');
    await panel.locator('.ki-fb-go').click();
    await subIs(/^TypeSafe Jev$/);
    assert.equal(await row.getAttribute('aria-checked'), 'true');
    assert.equal(await panel.locator('.ki-fb-form').count(), 0, 'the key box closes');
    assert.equal(await panel.locator('.ki-fb-err').count(), 0);
    assert.equal(await ready(), true);
    assert.equal(await panel.evaluate(() => document.activeElement?.classList.contains('ki-fb-row')), true, 'focus returns to the switch');
    await statusIs(/^On · TypeSafe Jev$/);
  });
  if (shots) await panel.screenshot({ path: path.join(shots, 'menu-on.png') });
  await check('model menu: the switch turns it off from the keyboard, and Settings follows', async () => {
    await row.focus();
    await panel.keyboard.press('Space');
    await subIs(/^Off$/);
    assert.equal(await row.getAttribute('aria-checked'), 'false');
    assert.equal(await ready(), false);
    assert.equal(await panel.locator('.ki-mm').count(), 1, 'the menu stays open');
    assert.equal(await panel.evaluate(() => document.activeElement?.classList.contains('ki-fb-row')), true, 'focus stays on the switch');
    await statusIs(/^Off$/);
    assert.equal(await toggle.getAttribute('aria-checked'), 'false');
  });
  await check('browse: switched off is not presented as setup to ask the user for', async () => {
    const message = await worker.evaluate(() => kiTest.tools.browse.execute({ goal: 'x' }).then(() => 'ran', e => e.message));
    assert.match(message, /^browse: the user switched Fast browse off. Drive the page with snapshot, click and fill.$/);
  });
  await check('model menu: a failed check is still shown after the menu closed mid-check', async () => {
    await panel.keyboard.press('Escape');
    await worker.evaluate(() => chrome.storage.local.set({ ki_fast_browse: {} }));
    await openMenu();
    await subIs(/^Add a key to turn on$/);
    await row.click();
    await panel.locator('.ki-fb-key').fill('slow-bad-key');
    await panel.keyboard.press('Enter');
    await panel.keyboard.press('Escape');
    assert.equal(await panel.locator('.ki-mm').count(), 0, 'Escape closed the menu during the check');
    await panel.waitForTimeout(2000);
    await openMenu();
    await panel.locator('.ki-fb-err').waitFor();
    assert.match(await panel.locator('.ki-fb-err').innerText(), /^TypeSafe did not accept this key. The key was not saved.$/);
    assert.equal(await panel.locator('.ki-fb-form').count(), 1, 'the key box is open again');
  });
  await check('model menu: a saved OpenRouter provider works with nothing to set up', async () => {
    await worker.evaluate(c => chrome.storage.local.set({ ki_fast_browse: {}, sidepanel_connections: [c, { id: 'or', label: 'OpenRouter', presetId: 'openrouter', apiKey: 'sk-or-provider', host: c.host }] }), custom);
    await pill.click();
    await panel.waitForTimeout(300);
    await openMenu();
    await subIs(/^Gemini 3\.1 Flash Lite via OpenRouter$/);
    assert.equal(await row.getAttribute('aria-checked'), 'true');
    assert.equal(await ready(), true);
    await statusIs(/^On · Gemini 3\.1 Flash Lite via OpenRouter, using your saved provider$/);
  });

  await check('no page errors', async () => assert.deepEqual(errors, []));
  console.log(JSON.stringify({ fastBrowseUi: failures.length ? 'FAIL' : 'pass', failures }));
  if (failures.length) process.exitCode = 1;
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => { await browser?.close(); server?.close(); fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); });

// Macro recording follows its tabs: a recorded page that loads asks RECORD_QUERY and
// is armed; a tab opened in the recording's tab group is adopted; activating a tab
// in another window pauses the recording, and coming back resumes it. Both paths go through the recording's tab-scope check, which the
// vendor bundle had replaced with a script string (a scope clash, see scope-check.mjs),
// so the query was never answered and tab switches threw.
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), http = require('node:http'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(process.env.CERTX_ROOT || path.join(__dirname, '../../..')), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-record-arm-'));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const server = http.createServer((req, res) => {
  if (req.url.endsWith('/models')) { res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({ data: [{ id: 'mock/record', name: 'Record', context_length: 128000 }] })); }
  res.setHeader('Content-Type', 'text/html'); res.end('<title>record</title><button>go</button>');
});

async function main() {
  let browser;
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = 'http://127.0.0.1:' + server.address().port;
    browser = await chromium.launchPersistentContext(temp, { headless: true, executablePath: require('../../chromium-path.cjs'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
    const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker', { timeout: 15000 });
    // Recording needs a usable model; a local catalog is enough.
    for (let i = 0; i < 8; i++) {
      await worker.evaluate(h => chrome.storage.local.set({ sidepanel_language: 'en', sidepanel_connections: [{ id: 'mock', label: 'Mock', presetId: 'openrouter', apiKey: 'fixture', host: h + '/api/v1' }] }), origin);
      await sleep(300);
      if ((await worker.evaluate(() => chrome.storage.local.get('sidepanel_connections'))).sidepanel_connections?.length) break;
    }
    const recorded = await browser.newPage(); await recorded.goto(origin + '/recorded');
    const tabOf = url => worker.evaluate(u => chrome.tabs.query({}).then(tabs => tabs.find(t => t.url === u).id), url);
    const tabId = await tabOf(origin + '/recorded');
    const ext = await browser.newPage(); await ext.goto('chrome-extension://' + new URL(worker.url()).host + '/pages/sidepanel.html?tabId=' + tabId);
    let started; for (let i = 0; i < 10 && !started?.ok; i++) { started = await ext.evaluate(id => chrome.runtime.sendMessage({ type: 'START_RECORDING', tabId: id }), tabId); if (!started?.ok) await sleep(500); }
    assert.equal(started?.ok, true, 'recording starts: ' + JSON.stringify(started));
    const status = () => worker.evaluate(() => chrome.storage.session.get('recording_session').then(v => v.recording_session?.status));
    // What record.js asks when a page in the tab loads, from that tab's isolated world.
    const query = id => worker.evaluate(t => chrome.scripting.executeScript({ target: { tabId: t }, world: 'ISOLATED', func: () => Promise.race([chrome.runtime.sendMessage({ type: 'RECORD_QUERY' }), new Promise(r => setTimeout(() => r('no answer in 3 s'), 3000))]) }).then(([r]) => r.result), id);
    const activate = async id => { await worker.evaluate(t => chrome.tabs.update(t, { active: true }), id); await sleep(800); };

    assert.deepEqual(await query(tabId), { armed: true }, 'a recorded tab is armed when it asks');
    // A tab opened next to the recorded one joins its tab group, so the recording adopts it.
    const joined = await browser.newPage(); await joined.goto(origin + '/joined');
    const joinedId = await tabOf(origin + '/joined');
    await activate(joinedId);
    assert.equal(await status(), 'recording', 'a tab in the recording\'s group keeps it recording');
    assert.deepEqual(await query(joinedId), { armed: true }, 'and is armed');
    // A tab in another window is outside the recording.
    await worker.evaluate(u => chrome.windows.create({ url: u, focused: true }), origin + '/elsewhere'); await sleep(1500);
    const otherId = await tabOf(origin + '/elsewhere');
    await activate(otherId);
    assert.equal(await status(), 'paused', 'activating a tab outside the recording pauses it');
    assert.deepEqual(await query(otherId), { armed: false }, 'a tab outside the recording is not armed');
    await worker.evaluate(t => chrome.tabs.get(t).then(tab => chrome.windows.update(tab.windowId, { focused: true })), tabId);
    await activate(tabId);
    assert.equal(await status(), 'recording', 'coming back to the recorded tab resumes it');
    assert.deepEqual(await query(tabId), { armed: true }, 'and arms it again');
    await ext.evaluate(() => chrome.runtime.sendMessage({ type: 'CANCEL_RECORDING' }));
    console.log(JSON.stringify({ recordArm: 'pass', failures: [] }));
  } catch (error) {
    const state = await browser?.serviceWorkers()[0]?.evaluate(async () => ({ session: (await chrome.storage.session.get('recording_session')).recording_session, tabs: (await chrome.tabs.query({})).map(t => ({ id: t.id, url: t.url, active: t.active, windowId: t.windowId, groupId: t.groupId })) })).catch(e => e.message);
    console.log(JSON.stringify({ recordArm: 'fail', failures: [error.message], state: { status: state?.session?.status, scope: state?.session?.scope, tabs: state?.session?.tabs, all: state?.tabs } }));
    process.exitCode = 1;
  } finally {
    try { await Promise.race([browser?.close(), sleep(5000)]); } catch {}
    server.close(); fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    process.exit(process.exitCode || 0);
  }
}
main();

// Real Chromium, local fixtures: the browse(goal) loop with a scripted decision
// function in place of the model, so every check is deterministic. Covers the
// mechanics a model cannot fix: one submit across a slow navigation, values never
// reaching the decision state, SPA content that renders late, native selects,
// checkboxes and Enter, stall detection, Stop, and the changed-element guard.
// Needs a test build: KI_TEST_HOOKS=1 node tools/picker/apply-picker.js
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http'), assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-browse-'));
const SECRET = 's3cret-Pass!', EMAIL = 'alice@example.test';
const hits = { login: 0, api: [], search: [] };
const page = (title, body) => '<!doctype html><title>' + title + '</title><body style="font:16px sans-serif;padding:30px">' + body;
const routes = {
  '/login': () => page('Sign in', '<h1>Sign in</h1><form method="post" action="/login"><p><label>Email <input name="email" type="email"></label></p><p><label>Password <input name="password" type="password"></label></p><button>Sign in</button></form>'),
  '/home': () => page('Home', '<h1>Welcome back, alice</h1><a href="/settings">Settings</a>'),
  '/spa': () => page('Shop', '<nav><button onclick="go(\'products\')">Products</button> <button onclick="go(\'cart\')">Cart</button> <button onclick="go(\'forum\')">Forum</button></nav><main id="out">Pick a section</main>' +
    '<script>async function go(s){const r=await fetch("/api/"+s);const j=await r.json();document.getElementById("out").innerHTML="<h2>"+j.title+"</h2>"}</script>'),
  '/form': () => page('Preferences', '<form action="/search"><p><select name="country" aria-label="Country"><option>Sweden</option><option>Norway</option><option>Denmark</option></select></p>' +
    '<p><select name="qty" aria-label="Quantity"><option value="0">1</option><option value="1">2</option><option value="2">3</option></select></p>' +
    '<p><label><input type="checkbox" name="sub"> Subscribe</label></p><p><input name="q" type="search" aria-label="Search"></p></form>'),
  '/static': () => page('Static', '<button>Nothing happens</button><button id="go" onclick="window.clicked=(window.clicked||0)+1">Delete</button>'),
};
let browser, server, failures = [];
async function check(name, fn) { try { await fn(); } catch (error) { failures.push(name + ': ' + error.message.split('\n')[0]); } }

async function main() {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'POST' && url.pathname === '/login') {
      hits.login++;
      let body = ''; req.on('data', c => body += c);
      // Slow server: the old page stays alive and "complete" while this is pending.
      req.on('end', () => setTimeout(() => { res.writeHead(303, { location: '/home' }); res.end(); }, 900));
      return;
    }
    if (url.pathname.startsWith('/api/')) { const s = url.pathname.slice(5); hits.api.push(s); return setTimeout(() => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ title: { products: 'All products', cart: 'Your cart', forum: 'Forum threads' }[s] })); }, 350); }
    if (url.pathname === '/search') { hits.search.push(url.search); res.setHeader('content-type', 'text/html'); return res.end(page('Results', '<h1>Results for ' + url.searchParams.get('q') + '</h1>')); }
    const route = routes[url.pathname];
    res.setHeader('content-type', 'text/html');
    res.end(route ? route() : 'not found');
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const origin = 'http://127.0.0.1:' + server.address().port;
  browser = await chromium.launchPersistentContext(temp, { headless: true, viewport: { width: 900, height: 700 }, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
  const tab = await browser.newPage();
  await tab.goto(origin + '/login');
  const tabId = await worker.evaluate(url => chrome.tabs.query({ url: url + '/*' }).then(tabs => tabs[0].id), origin);
  assert.equal(await worker.evaluate(() => typeof globalThis.kiTest?.browseRun), 'function', 'kiTest exposes browse (build with KI_TEST_HOOKS=1 node tools/picker/apply-picker.js)');
  await worker.evaluate(id => { kiTest.setTab(id); globalThis.kiCdpLog = []; const send = chrome.debugger.sendCommand.bind(chrome.debugger); chrome.debugger.sendCommand = (target, method, ...rest) => { kiCdpLog.push(method); return send(target, method, ...rest); }; }, tabId);

  // A script is an ordered list of steps; the stub answers the current step if its
  // target is on the page (else WAIT), and DONE once `done` matches the page text.
  const run = (args, script, extra = {}) => worker.evaluate(async ([args, script, extra, tabId]) => {
    const steps = script.map(s => ({ ...s, re: s.re && new RegExp(s.re) })), states = [], spaces = [];
    let i = 0;
    kiTest.setBrowseDecide(async (config, goal, state, space) => {
      globalThis.kiStubCalls = (globalThis.kiStubCalls || 0) + 1;
      states.push(JSON.stringify(state)); spaces.push(JSON.stringify(space));
      if (extra.delay) await new Promise(r => setTimeout(r, extra.delay));
      const step = steps[i];
      if (!step) return { op: 'BLOCKED', target: null };
      if (step.op === 'DONE') return new RegExp(step.done).test(state.page) ? { op: 'DONE', target: null } : { op: 'WAIT', target: null };
      if (step.after && !new RegExp(step.after).test(state.page)) return { op: 'WAIT', target: null };
      const targets = space.targets[step.op];
      if (!targets) { if (!space.ops[step.op]) return { op: 'BLOCKED', target: null }; i += step.repeat ? 0 : 1; return { op: step.op, target: null }; }
      const hit = Object.entries(targets).find(([, d]) => step.re.test(d));
      if (!hit) return step.missing === 'BLOCKED' ? { op: 'BLOCKED', target: null } : { op: 'WAIT', target: null };
      if (step.relabel) await chrome.debugger.sendCommand({ tabId }, 'Runtime.evaluate', { expression: step.relabel });
      i += step.repeat ? 0 : 1;
      return { op: step.op, target: hit[0] };
    });
    const controller = new AbortController();
    if (extra.abortAfter) setTimeout(() => controller.abort(new DOMException('Stopped', 'AbortError')), extra.abortAfter);
    try { return { result: await kiTest.browseRun({ ...args, _tabId: tabId, _signal: controller.signal }, { backend: 'stub', model: 'scripted' }), states, spaces }; }
    catch (error) { return { error: error.name + ': ' + error.message, states, spaces }; }
  }, [args, script, extra, tabId]);

  await check('login across a slow navigation submits once and never sends the values', async () => {
    await worker.evaluate(() => { kiCdpLog.length = 0; });
    const out = await run({ goal: 'Sign in with email and password', values: { email: EMAIL, password: SECRET } }, [
      { op: 'TYPE', re: 'Email.*type value "email"' }, { op: 'TYPE', re: 'Password.*type value "password"' }, { op: 'CLICK', re: 'button "Sign in"' }, { op: 'DONE', done: 'Welcome back' }]);
    assert.equal(out.result?.status, 'done', JSON.stringify(out.result || out.error));
    assert.equal(hits.login, 1, 'exactly one POST /login');
    assert.equal(new URL(out.result.url).pathname, '/home');
    assert.deepEqual(out.result.steps.map(s => s.split(' ')[0]), ['type', 'type', 'click']);
    const sent = out.states.join('\n') + out.spaces.join('\n') + JSON.stringify(out.result);
    assert.ok(!sent.includes(SECRET) && !sent.includes(EMAIL), 'no value text in any decision state or the result');
    assert.ok(out.states.some(s => s.includes('holds email')) || out.spaces.some(s => s.includes('holds email')), 'a typed field is shown by its value name');
    const marks = await worker.evaluate(() => kiCdpLog.filter(m => m === 'Overlay.highlightNode').length);
    assert.ok(marks >= 3, 'each action is highlighted (' + marks + ')');
  });

  await check('SPA sections that render after a fetch are waited for, not raced', async () => {
    await tab.goto(origin + '/spa');
    // Each step only proceeds once the previous section is on the page; a WAIT in the
    // result means the loop read the page before the click's own request had landed.
    const out = await run({ goal: 'Open products, cart and forum' }, [
      { op: 'CLICK', re: 'button "Products"' }, { op: 'CLICK', re: 'button "Cart"', after: 'All products' }, { op: 'CLICK', re: 'button "Forum"', after: 'Your cart' }, { op: 'DONE', done: 'Forum threads' }]);
    assert.equal(out.result?.status, 'done', JSON.stringify(out.result || out.error));
    assert.deepEqual(hits.api, ['products', 'cart', 'forum']);
    assert.deepEqual(out.result.steps.map(s => s.split(' ')[0]), ['click', 'click', 'click'], 'no WAIT was needed: ' + JSON.stringify(out.result.steps));
    assert.ok(out.result.page.includes('Forum threads'), 'final page carries the rendered section');
  });

  await check('native select, checkbox and Enter run through the executors', async () => {
    await tab.goto(origin + '/form');
    const out = await run({ goal: 'Country Norway, subscribe, search laptops', values: { query: 'laptops' } }, [
      { op: 'SELECT', re: '"Country" → "Norway"' }, { op: 'SELECT', re: '"Quantity" → "2"' }, { op: 'CLICK', re: 'checkbox "Subscribe" checked=false' }, { op: 'TYPE', re: 'Search.*type value "query"' }, { op: 'ENTER' }, { op: 'DONE', done: 'Results for' }]);
    assert.equal(out.result?.status, 'done', JSON.stringify(out.result || out.error));
    assert.equal(hits.search.length, 1, 'one search submitted');
    const q = new URLSearchParams(hits.search[0]);
    // Quantity "2" has value 1: selecting by label through select_option would have picked value 2.
    assert.deepEqual([q.get('country'), q.get('qty'), q.get('sub'), q.get('q')], ['Norway', '1', 'on', 'laptops']);
    assert.ok(!JSON.stringify(out.result).includes('laptops') && out.result.url.includes('q=‹query›'), 'the value is redacted from the result URL: ' + out.result.url);
  });

  await check('repeating an action on an unchanged page stops as stalled', async () => {
    await tab.goto(origin + '/static');
    const out = await run({ goal: 'Make something happen' }, [{ op: 'CLICK', re: 'button "Nothing happens"', repeat: true }]);
    assert.equal(out.result?.status, 'stalled', JSON.stringify(out.result || out.error));
    assert.equal(out.result.steps.length, 1, 'stopped before repeating the click: ' + JSON.stringify(out.result.steps));
    assert.ok(out.result.recovery && out.result.note);
  });

  await check('a relabelled element is not clicked; the loop re-reads instead', async () => {
    await tab.goto(origin + '/static');
    const out = await run({ goal: 'Delete it' }, [{ op: 'CLICK', re: 'button "Delete"', relabel: "document.getElementById('go').textContent='Cancel'", missing: 'BLOCKED' }]);
    assert.equal(out.result?.status, 'blocked', JSON.stringify(out.result || out.error));
    assert.equal(await tab.evaluate(() => window.clicked || 0), 0, 'the button that became "Cancel" was never clicked');
    assert.ok(out.states.length >= 2, 'the page was read again after the refusal');
  });

  await check('Stop aborts the loop and no action runs after it', async () => {
    await tab.goto(origin + '/static');
    const out = await run({ goal: 'Keep clicking', max_steps: 60 }, [{ op: 'WAIT', repeat: true }], { delay: 150, abortAfter: 900 });
    assert.match(out.error || '', /AbortError/, JSON.stringify(out.result || out.error));
    const calls = await worker.evaluate(() => globalThis.kiStubCalls);
    await new Promise(r => setTimeout(r, 700));
    assert.equal(await worker.evaluate(() => globalThis.kiStubCalls), calls, 'no decision after the abort');
    assert.ok(out.states.length >= 1, 'the loop was running when Stop came');
  });

  await check('bad arguments teach the fix', async () => {
    const out = await worker.evaluate(async id => { try { await kiTest.browseRun({ goal: 'x', values: ['a'], _tabId: id }, { backend: 'stub', model: 'x' }); return null; } catch (error) { return { message: error.message, recovery: error.recovery }; } }, tabId);
    // The browser tool wrapper passes on only the message, so the fix has to be in it.
    assert.match(out?.message || '', /values must be an object.*"values":\{/);
  });

  await check('browse is advertised only while a backend is configured', async () => {
    const before = await worker.evaluate(() => kiTest.browseReady());
    await worker.evaluate(() => chrome.storage.local.set({ ki_fast_browse: { key: 'test-key' } }));
    const after = await worker.evaluate(() => kiTest.browseReady());
    await worker.evaluate(() => chrome.storage.local.set({ ki_fast_browse: { key: 'test-key', on: false } }));
    const off = await worker.evaluate(() => kiTest.browseReady());
    assert.deepEqual([before, after, off], [false, true, false]);
  });

  console.log(JSON.stringify({ browse: failures.length ? 'FAIL' : 'pass', failures }));
  if (failures.length) process.exitCode = 1;
}
main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => { await browser?.close(); server?.close(); fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); });

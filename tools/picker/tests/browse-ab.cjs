// Fast browse on vs off, end to end: the real side panel and a real chat model get
// one instruction per browse-live fixture, and nothing else is scripted. Per run it
// records whether the task was done (judged by what the fixture server received),
// wall time, chat-model calls, and which tools the model chose. Keys come from
// .env.local (OPENROUTER_API_KEY for the chat model, TYPESAFE_API_KEY for Fast
// browse) and are never printed. Works on the production build.
//   node tools/picker/tests/browse-ab.cjs --model=xiaomi/mimo-v2.6-pro [--modes=on,off] [--runs=1] [--only=login,signup]
// AB_DUMP=<file> saves the first chat request body (system prompt and tool list).
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const { handler, scenarios, reset, env } = require('./browse-live.cjs');
const root = path.resolve(__dirname, '../../..'), args = process.argv.slice(2);
const opt = (name, fallback) => (args.find(a => a.startsWith('--' + name + '=')) || '').slice(name.length + 3) || fallback;
const model = opt('model', 'xiaomi/mimo-v2.6-pro'), modes = opt('modes', 'on,off').split(','), runs = Number(opt('runs', '1'));
// A chat that has not called the model for 8 s has ended its turn (tool calls and
// browse steps keep requests flowing); 4 minutes bounds a model that never stops.
const IDLE_MS = 8000, RUN_MS = 240000;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const instruction = s => 'In the attached tab: ' + s.goal + (Object.keys(s.values).length ? '. Use ' + Object.entries(s.values).map(([k, v]) => k + ' "' + v + '"').join(', ') : '') + '. Reply with one short line when it is done.';

async function runMode(mode, origin) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-browse-ab-'));
  const browser = await chromium.launchPersistentContext(temp, { headless: true, viewport: { width: 1200, height: 900 }, executablePath: process.env.CHROMIUM_PATH || path.join(process.env.LOCALAPPDATA, 'ms-playwright/chromium-1234/chrome-win64/chrome.exe'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const rows = [];
  // Chat-model traffic (OpenRouter) and Fast browse traffic (TypeSafe), from the worker.
  const net = { chat: 0, inflight: 0, lastEnd: 0, fast: 0, model: '', offered: null };
  browser.on('request', req => {
    if (req.method() !== 'POST') return;
    if (req.url().includes('openrouter.ai')) { net.chat++; net.inflight++; if (process.env.AB_DUMP && !fs.existsSync(process.env.AB_DUMP)) fs.writeFileSync(process.env.AB_DUMP, req.postData() || '');
      try { const body = JSON.parse(req.postData() || '{}'); net.model ||= body.model || ''; net.last = body; net.offered ??= (body.tools || []).some(t => (t.function?.name || t.name) === 'browse'); net.routed ??= JSON.stringify(body.messages?.filter(m => m.role === 'system')).includes('[Fast browse]'); } catch {} }
    if (req.url().includes('api.typesafe.ai')) net.fast++;
  });
  const end = req => { if (req.method() === 'POST' && req.url().includes('openrouter.ai')) { net.inflight--; net.lastEnd = Date.now(); } };
  browser.on('requestfinished', end); browser.on('requestfailed', end);
  try {
    const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
    const base = 'chrome-extension://' + new URL(worker.url()).host;
    const settings = { sidepanel_language: 'en', sidepanel_approval_mode: 'full_access', sidepanel_connections: [{ id: 'or', label: 'OpenRouter', presetId: 'openrouter', apiKey: env.OPENROUTER_API_KEY, host: 'https://openrouter.ai/api/v1', modelIds: [model] }], ki_fast_browse: mode === 'on' ? { key: env.TYPESAFE_API_KEY } : { on: false } };
    for (let i = 0; i < 8; i++) { await worker.evaluate(s => chrome.storage.local.set(s), settings); await sleep(300); if ((await worker.evaluate(() => chrome.storage.local.get('sidepanel_connections'))).sidepanel_connections?.length) break; }
    for (const s of scenarios) for (let r = 0; r < runs; r++) {
      reset();
      await browser.clearCookies();
      const target = await browser.newPage();
      await target.goto(origin + s.start);
      const tabId = await worker.evaluate(url => chrome.tabs.query({}).then(tabs => Math.max(...tabs.filter(t => t.url.startsWith(url)).map(t => t.id))), origin);
      const panel = await browser.newPage();
      await panel.goto(base + '/pages/sidepanel.html?tabId=' + tabId);
      await panel.waitForFunction(() => document.querySelector('[aria-label="Profile"]')?.disabled === false);
      Object.assign(net, { chat: 0, inflight: 0, lastEnd: 0, fast: 0, model: '', offered: null, routed: null, last: null });
      await panel.locator('.wb-editor').first().click();
      await panel.keyboard.type(instruction(s));
      const sent = Date.now();
      await panel.keyboard.press('Enter');
      await sleep(3000);
      if (!net.chat) await panel.locator('.wb-send').first().click({ timeout: 3000 }).catch(() => {});
      while (Date.now() - sent < RUN_MS && !(net.chat && !net.inflight && Date.now() - net.lastEnd > IDLE_MS)) await sleep(500);
      // Tool calls from the conversation the model sent last (the final reply's request
      // carries every earlier call); telemetry reaches storage up to 10 s late.
      const tools = {};
      for (const m of net.last?.messages || []) for (const c of m.tool_calls || []) tools[c.function?.name] = (tools[c.function?.name] || 0) + 1;
      rows.push({ mode, model: net.model, scenario: s.id, ok: s.ok(), ms: (net.lastEnd || Date.now()) - sent, chatCalls: net.chat, fastCalls: net.fast, offered: net.offered, routed: net.routed, browse: tools.browse || 0, tools, timedOut: Date.now() - sent >= RUN_MS });
      const row = rows.at(-1);
      console.log([mode.padEnd(3), s.id.padEnd(8), row.ok ? 'PASS' : 'FAIL', (row.ms / 1000).toFixed(1).padStart(6) + 's', 'chat calls ' + row.chatCalls, 'browse ' + (row.offered ? 'offered' : 'not offered') + (row.routed ? '+prompt' : '') + '/used ' + row.browse, row.timedOut ? 'TIMEOUT' : '', JSON.stringify(tools)].join('  '));
      await panel.close(); await target.close();
    }
  } finally { await browser.close(); fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  return rows;
}

async function main() {
  if (!env.OPENROUTER_API_KEY || !env.TYPESAFE_API_KEY) throw Error('needs OPENROUTER_API_KEY and TYPESAFE_API_KEY in .env.local');
  const server = http.createServer((req, res) => handler(req, res).catch(e => { res.statusCode = 500; res.end(String(e)); }));
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const origin = 'http://127.0.0.1:' + server.address().port, rows = [];
  try { for (const mode of modes) rows.push(...await runMode(mode, origin)); }
  finally { server.close(); }
  const median = a => { const s = [...a].sort((x, y) => x - y); return s.length ? s[s.length >> 1] : 0; };
  console.log('\nSUMMARY ' + model);
  for (const mode of modes) {
    const m = rows.filter(r => r.mode === mode);
    console.log(mode.padEnd(3), m.filter(r => r.ok).length + '/' + m.length + ' done', 'median ' + (median(m.map(r => r.ms)) / 1000).toFixed(1) + 's', 'median chat calls ' + median(m.map(r => r.chatCalls)), 'browse used in ' + m.filter(r => r.browse).length + '/' + m.length);
  }
  fs.writeFileSync(path.join(os.tmpdir(), 'cert-x-browse-ab.json'), JSON.stringify(rows, null, 1));
}
main().catch(error => { console.error(error); process.exitCode = 1; });

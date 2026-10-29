// Live browse(goal) evaluation: real decision models on local fixtures shaped like
// the UI stretches seen in cert-x runs (login, consent wall, SPA walk, open an item
// and post, filters + Enter, a 150-card catalog with identical buttons, sign-up).
// Each scenario is judged by what the server received, not by the model's DONE.
// Keys come from .env.local (TYPESAFE_API_KEY, OPENROUTER_API_KEY) and are never
// printed; only fixture page text is sent. Needs a KI_TEST_HOOKS=1 build.
//   node tools/picker/tests/browse-live.cjs [typesafe:jev-latest] [openrouter:anthropic/claude-haiku-5.5] ... [--runs=2] [--only=login,catalog]
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const root = path.resolve(__dirname, '../../..');
const env = Object.fromEntries(fs.readFileSync(path.join(root, '.env.local'), 'utf8').split(/\r?\n/).map(l => /^([A-Z_]+)=(.*)$/.exec(l)).filter(Boolean).map(m => [m[1], m[2].trim()]));
const args = process.argv.slice(2), runs = Number((args.find(a => a.startsWith('--runs=')) || '--runs=1').slice(7));
const only = (args.find(a => a.startsWith('--only=')) || '').slice(7).split(',').filter(Boolean);
const backends = (args.filter(a => !a.startsWith('--')).length ? args.filter(a => !a.startsWith('--')) : ['typesafe:jev-latest']).map(spec => {
  const [backend, ...model] = spec.split(':');
  return backend === 'typesafe' ? { backend, key: env.TYPESAFE_API_KEY, model: model.join(':') || 'jev-latest' } : { backend, key: env.OPENROUTER_API_KEY, base: 'https://openrouter.ai/api/v1', model: model.join(':') };
});

const page = (title, body) => '<!doctype html><meta charset="utf-8"><title>' + title + '</title><body style="font:15px sans-serif;padding:24px;max-width:900px">' + body;
const nav = '<header><nav><a href="/">Home</a> · <a href="/deals">Deals</a> · <a href="/help">Help</a> · <a href="/cart">Cart</a></nav></header>';
// 150 cards with identical 'Add to cart' buttons; the one Blue Kettle sits far below the page-text cap.
const products = Array.from({ length: 150 }, (_, i) => i === 117 ? 'Blue Kettle' : ['Steel Pan', 'Oak Shelf', 'Wool Rug', 'Glass Vase', 'Desk Lamp', 'Green Kettle', 'Clay Pot', 'Tea Towel', 'Brass Hook', 'Linen Throw'][i % 10] + ' ' + (i + 1));
let state;
const reset = () => { state = { posts: [], api: [], search: [], cart: [], consent: false, loginPage: false, signups: [], logins: [] }; };
const body = req => new Promise(r => { let b = ''; req.on('data', c => b += c); req.on('end', () => r(new URLSearchParams(b))); });
const handler = async (req, res) => {
  const url = new URL(req.url, 'http://x'), cookies = req.headers.cookie || '', html = s => { res.setHeader('content-type', 'text/html'); res.end(s); };
  const p = url.pathname;
  if (req.method === 'POST' && p === '/login') { const f = await body(req); state.logins.push([f.get('email'), f.get('password')]); return setTimeout(() => { res.writeHead(303, { location: '/home' }); res.end(); }, 700); }
  if (p === '/login') { state.loginPage = /consent=1/.test(cookies); return html(page('Sign in', nav + '<h1>Sign in</h1><form method="post" action="/login"><p><label>Email address <input name="email" type="email" autocomplete="username"></label></p><p><label>Password <input name="password" type="password"></label></p><p><a href="/forgot">Forgot your password?</a></p><button>Sign in</button> <a href="/register">Create an account</a></form>')); }
  if (p === '/home') return html(page('Dashboard', nav + '<h1>Welcome back, alice</h1><p>You have 2 new messages.</p>'));
  if (p === '/consent') return html(page('Store', '<header><a href="/">Store</a> <a href="/login" style="float:right">Log in</a></header><h1>Spring sale</h1><p>Up to 40% off.</p>' +
    '<div id="wall" style="position:fixed;inset:0;background:#0008"><div role="dialog" aria-modal="true" aria-labelledby="ct" style="background:#fff;margin:80px auto;padding:20px;width:420px"><h2 id="ct">We value your privacy</h2><p>We use cookies to improve your experience.</p><button>Manage options</button> <button onclick="document.cookie=\'consent=1;path=/\';document.getElementById(\'wall\').remove()">Accept all</button></div></div>'));
  if (p === '/spa') return html(page('Shop', '<nav><button onclick="go(\'products\')">Products</button> <button onclick="go(\'cart\')">Cart</button> <button onclick="go(\'forum\')">Forum</button> <button onclick="go(\'account\')">Account</button></nav><main id="out"><p>Welcome to the shop.</p></main><script>async function go(s){document.getElementById("out").textContent="Loading…";const r=await fetch("/api/"+s);const j=await r.json();document.getElementById("out").innerHTML="<h2>"+j.title+"</h2><p>"+j.text+"</p>"}</script>'));
  if (p === '/api/cart-add') { state.cart.push(products[Number(url.searchParams.get('i'))]); res.end('{}'); return; }
  if (p.startsWith('/api/')) { const s = p.slice(5); state.api.push(s); return setTimeout(() => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ title: { products: 'All products', cart: 'Your cart', forum: 'Forum threads', account: 'Your account' }[s], text: 'Section ' + s + ' loaded.' })); }, 400); }
  if (p === '/items') return html(page('Items', nav + '<h1>Latest items</h1><ul>' + ['Copper Bowl', 'Brass Lamp', 'Walnut Tray', 'Cotton Quilt', 'Iron Kettle'].map((n, i) => '<li><a href="/item/' + (i + 1) + '">' + n + '</a> — 2 comments</li>').join('') + '</ul>'));
  if (/^\/item\/\d$/.test(p)) {
    const n = p.slice(6), name = ['Copper Bowl', 'Brass Lamp', 'Walnut Tray', 'Cotton Quilt', 'Iron Kettle'][n - 1];
    if (req.method === 'POST') { const f = await body(req); state.posts.push([n, f.get('comment')]); return html(page(name, nav + '<h1>' + name + '</h1><p role="status">Comment posted.</p><p>' + f.get('comment') + '</p>')); }
    return html(page(name, nav + '<h1>' + name + '</h1><p>Hand made. Ships in 3 days.</p><h2>Comments</h2><p>Nice! — bob</p><form method="post"><label>Your comment <textarea name="comment"></textarea></label><br><button>Post comment</button></form><a href="/items">Back to items</a>'));
  }
  if (p === '/filters') return html(page('Find products', nav + '<h1>Find products</h1><form action="/search"><p><label>Ship to <select name="country"><option>Sweden</option><option>Norway</option><option>Denmark</option><option>Finland</option></select></label></p><p><label><input type="checkbox" name="instock"> In stock only</label> <label><input type="checkbox" name="sale"> On sale</label></p><p><input name="q" type="search" placeholder="Search products"></p></form>'));
  if (p === '/search') { state.search.push(Object.fromEntries(url.searchParams)); return html(page('Results', nav + '<h1>Results for ' + (url.searchParams.get('q') || '') + '</h1><p>12 products found.</p>')); }
  if (p === '/catalog') return html(page('Catalog', nav + '<h1>All products</h1><div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">' + products.map((n, i) => '<div style="border:1px solid #ccc;padding:8px"><h3>' + n + '</h3><p>' + (9 + i % 30) + '.99 EUR</p><button onclick="fetch(\'/api/cart-add?i=' + i + '\',{method:\'POST\'}).then(()=>{document.getElementById(\'count\').textContent=+document.getElementById(\'count\').textContent+1})">Add to cart</button></div>').join('') + '</div><p><a href="/cart">Cart (<span id="count">0</span>)</a></p>'));
  if (p === '/cart') return html(page('Cart', nav + '<h1>Your cart</h1>' + (state.cart.length ? '<ul>' + state.cart.map(n => '<li>' + n + '</li>').join('') + '</ul>' : '<p>Your cart is empty.</p>')));
  if (p === '/register') {
    if (req.method === 'POST') { const f = await body(req); state.signups.push(Object.fromEntries(f)); return html(page('Welcome', nav + '<h1>Account created</h1><p>Welcome, ' + f.get('username') + '.</p>')); }
    return html(page('Create account', nav + '<h1>Create your account</h1><form method="post"><p><label>Username <input name="username"></label></p><p><label>Email <input name="email" type="email"></label></p><p><label>Password <input name="password" type="password"></label></p><p><label>Confirm password <input name="confirm" type="password"></label></p><p><label><input type="checkbox" name="terms"> I accept the terms of service</label></p><p><label><input type="checkbox" name="news"> Send me the newsletter</label></p><button>Create account</button></form>'));
  }
  html(page('Not found', nav + '<h1>Page not found</h1>'));
};

const scenarios = [
  { id: 'login', start: '/login', goal: 'Sign in with the email and password', values: { email: 'alice@example.test', password: 'Tr0ub4dor&3' }, ok: () => state.logins.length === 1 && state.logins[0].join() === 'alice@example.test,Tr0ub4dor&3' },
  { id: 'consent', start: '/consent', goal: 'Accept the cookie banner, then open the log in page', values: {}, ok: () => state.loginPage },
  { id: 'spa', start: '/spa', goal: 'Open the Products, Cart and Forum sections one after another so each one loads', values: {}, ok: () => ['products', 'cart', 'forum'].every(s => state.api.includes(s)) },
  { id: 'comment', start: '/items', goal: 'Open the Brass Lamp item and post the comment on it', values: { comment: 'Lovely finish, does it come in black?' }, ok: () => state.posts.length === 1 && state.posts[0].join() === '2,Lovely finish, does it come in black?' },
  { id: 'filters', start: '/filters', goal: 'Ship to Norway, show only in-stock products, and search for the query', values: { query: 'laptop stand' }, ok: () => state.search.length >= 1 && state.search.at(-1).country === 'Norway' && state.search.at(-1).instock === 'on' && !state.search.at(-1).sale && state.search.at(-1).q === 'laptop stand' },
  { id: 'catalog', start: '/catalog', goal: 'Add the Blue Kettle to the cart, then open the cart', values: {}, ok: () => state.cart.length === 1 && state.cart[0] === 'Blue Kettle' },
  { id: 'signup', start: '/register', goal: 'Create an account with the username, email and password, accepting the terms but not the newsletter', values: { username: 'zeb_tester', email: 'zeb@example.test', password: 'Corr3ct-Horse' }, ok: () => { const s = state.signups[0]; return state.signups.length === 1 && s.username === 'zeb_tester' && s.email === 'zeb@example.test' && s.password === 'Corr3ct-Horse' && s.confirm === 'Corr3ct-Horse' && s.terms === 'on' && !s.news; } },
].filter(s => !only.length || only.includes(s.id));

async function main() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-browse-live-'));
  const server = http.createServer((req, res) => handler(req, res).catch(e => { res.statusCode = 500; res.end(String(e)); }));
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const browser = await chromium.launchPersistentContext(temp, { headless: true, viewport: { width: 1200, height: 800 }, executablePath: require('../../chromium-path.cjs'), args: ['--disable-extensions-except=' + root, '--load-extension=' + root] });
  const rows = [];
  try {
    const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
    const tab = await browser.newPage();
    await tab.goto(origin + '/login');
    const tabId = await worker.evaluate(url => chrome.tabs.query({ url: url + '/*' }).then(tabs => tabs[0].id), origin);
    if (await worker.evaluate(() => typeof globalThis.kiTest?.browseRun) !== 'function') throw Error('needs a KI_TEST_HOOKS=1 build');
    await worker.evaluate(id => kiTest.setTab(id), tabId);
    for (const config of backends) {
      if (!config.key) throw Error('missing key for ' + config.backend + ' in .env.local');
      for (const s of scenarios) for (let r = 0; r < runs; r++) {
        reset();
        await tab.context().clearCookies();
        await tab.goto(origin + s.start);
        const out = await worker.evaluate(async ([s, config, tabId]) => {
          try { return { result: await kiTest.browseRun({ goal: s.goal, values: s.values, _tabId: tabId }, config) }; }
          catch (error) { return { error: error.message }; }
        }, [{ goal: s.goal, values: s.values }, config, tabId]);
        const res = out.result || {}, ok = s.ok();
        rows.push({ backend: config.backend + ':' + config.model, scenario: s.id, ok, status: res.status || 'throw', steps: res.steps?.length ?? 0, calls: res.model_calls ?? 0, model_ms: res.model_ms ?? 0, ms: res.ms ?? 0, note: (out.error || res.note || '').slice(0, 160), trace: res.steps });
        const row = rows.at(-1);
        console.log([row.backend.padEnd(42), row.scenario.padEnd(8), row.ok ? 'PASS' : 'FAIL', row.status.padEnd(9), 'steps ' + row.steps, 'calls ' + row.calls, 'model ' + row.model_ms + 'ms', 'total ' + row.ms + 'ms', row.note].join('  '));
        if (!row.ok && process.env.BROWSE_TRACE) console.log('   ' + (row.trace || []).join('\n   '));
      }
    }
  } finally { await browser.close(); server.close(); fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  const by = {};
  for (const r of rows) { const b = by[r.backend] ||= { pass: 0, n: 0, ms: [], modelPerCall: [] }; b.n++; b.pass += r.ok; b.ms.push(r.ms); if (r.calls) b.modelPerCall.push(r.model_ms / r.calls); }
  const median = a => { const s = [...a].sort((x, y) => x - y); return s.length ? Math.round(s[s.length >> 1]) : 0; };
  console.log('\nSUMMARY');
  for (const [k, b] of Object.entries(by)) console.log(k.padEnd(42), b.pass + '/' + b.n + ' pass', 'median run ' + median(b.ms) + 'ms', 'median decision ' + median(b.modelPerCall) + 'ms');
  fs.writeFileSync(path.join(os.tmpdir(), 'cert-x-browse-live.json'), JSON.stringify(rows, null, 1));
}
// browse-ab.cjs reuses the fixtures to compare whole chats with Fast browse on and off.
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { handler, scenarios, reset, env };

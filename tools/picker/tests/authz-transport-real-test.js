// Actual Chromium transport isolation; all servers and credentials are fixtures.
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const parent = path.resolve(os.tmpdir()), temp = fs.mkdtempSync(path.join(parent, 'cert-x-authz-transport-')), observed = [];
let browser, server, outside, outsideCount = 0, holdResponse;
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
(async () => {
  outside = http.createServer((req, res) => { outsideCount++; res.end('outside'); }); await listen(outside);
  server = http.createServer((req, res) => {
    observed.push({ path: req.url, cookie: req.headers.cookie || '', authorization: req.headers.authorization || '', custom: req.headers['x-account-key'] || '', cache: req.headers['cache-control'] || '' });
    if (req.url === '/held' && req.headers.authorization === 'Bearer isolated-hold') { holdResponse = () => { res.setHeader('Content-Type', 'application/json'); res.end('{"held":true}'); }; return; }
    if (req.headers.authorization !== 'Bearer independent-tab') res.setHeader('Set-Cookie', 'fixture_session=response-poison; Path=/; HttpOnly; SameSite=Lax');
    if (req.url === '/redirect') { res.writeHead(302, { Location: 'http://127.0.0.1:' + outside.address().port + '/escaped' }); return res.end(); }
    res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'public, max-age=3600'); res.end(JSON.stringify({ ok: true }));
  }); await listen(server);
  const origin = 'http://127.0.0.1:' + server.address().port, extension = path.join(temp, 'extension'); fs.mkdirSync(extension);
  for (const name of ['authz-transport.mjs', 'dast-core.mjs', 'dast-inputs.js']) fs.copyFileSync(path.resolve(__dirname, '../../../security/compat', name), path.join(extension, name));
  fs.writeFileSync(path.join(extension, 'manifest.json'), JSON.stringify({ manifest_version: 3, name: 'Isolated access transport fixture', version: '1.0', permissions: ['declarativeNetRequestWithHostAccess'], host_permissions: ['http://127.0.0.1/*'], background: { service_worker: 'background.js', type: 'module' } }));
  fs.writeFileSync(path.join(extension, 'background.js'), "import { createIsolatedTransport } from './authz-transport.mjs'; globalThis.testSend = createIsolatedTransport();");
  fs.writeFileSync(path.join(extension, 'fixture.html'), '<!doctype html><title>Independent extension tab</title>');
  browser = await chromium.launchPersistentContext(path.join(temp, 'profile'), { headless: true, executablePath: require('../../chromium-path.cjs'), args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension] });
  const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
  await browser.addCookies([{ name: 'fixture_session', value: 'ambient-original', url: origin, httpOnly: true, sameSite: 'Lax' }]);
  const baseHeaders = [{ name: 'Cookie', value: 'stale=browser-capture' }, { name: 'Authorization', value: 'Bearer stale-capture' }, { name: 'X-Account-Key', value: 'stale-custom' }];
  const send = (credentials, endpoint = '/resource') => worker.evaluate(async ({ origin, credentials, endpoint, baseHeaders }) => testSend({ request: { url: origin + endpoint, method: 'GET', headers: baseHeaders, body: '' }, credentials, credentialNames: ['x-account-key'], scope: { origins: [origin], excludePaths: [] }, deadline: Date.now() + 10000 }), { origin, credentials, endpoint, baseHeaders });
  for (const identity of ['a', 'b']) {
    const response = await send([{ name: 'Cookie', value: 'fixture_session=account-' + identity }, { name: 'Authorization', value: 'Bearer account-' + identity }, { name: 'X-Account-Key', value: 'key-' + identity }]);
    assert.equal(response.status, 200); const seen = observed.at(-1); assert.equal(seen.cookie, 'fixture_session=account-' + identity); assert.equal(seen.authorization, 'Bearer account-' + identity); assert.equal(seen.custom, 'key-' + identity);
    assert.equal((await browser.cookies(origin)).find(cookie => cookie.name === 'fixture_session').value, 'ambient-original', 'Response Set-Cookie must not change browser jar');
  }
  await send([]); assert.equal(observed.at(-1).cookie, ''); assert.equal(observed.at(-1).authorization, ''); assert.equal(observed.at(-1).custom, '');
  await send([]); assert.equal(observed.length, 4, 'Identical GETs must reach server instead of HTTP cache');
  const redirect = await send([], '/redirect'); assert.ok(redirect.opaque || redirect.status === 302); assert.equal(outsideCount, 0);
  assert.ok(observed.every(item => item.cache.includes('no-store')));
  const tab = await browser.newPage(); await tab.goto('chrome-extension://' + new URL(worker.url()).hostname + '/fixture.html');
  const held = send([{ name: 'Cookie', value: 'fixture_session=isolated-hold' }, { name: 'Authorization', value: 'Bearer isolated-hold' }], '/held');
  for (let index = 0; index < 100 && !holdResponse; index++) await new Promise(resolve => setTimeout(resolve, 20)); assert.ok(holdResponse);
  await tab.evaluate(async origin => fetch(origin + '/held', { headers: { Authorization: 'Bearer independent-tab' }, credentials: 'include', cache: 'no-store' }).then(response => response.text()), origin);
  const independent = observed.at(-1); assert.equal(independent.authorization, 'Bearer independent-tab'); assert.equal(independent.cookie, 'fixture_session=ambient-original', 'Worker DNR identity must not replace an independent extension UI tab cookie');
  holdResponse(); await held;
  assert.equal((await browser.cookies(origin)).find(cookie => cookie.name === 'fixture_session').value, 'ambient-original');
  assert.equal((await worker.evaluate(() => chrome.declarativeNetRequest.getSessionRules())).length, 0);
  console.log('PASS: explicit Cookie/bearer/custom credentials, anonymous stripping, no cache, no redirect, unchanged cookie jar, independent extension-tab isolation, DNR cleanup (7 actual requests).');
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  if (browser) await browser.close();
  for (const service of [server, outside]) if (service) await new Promise(resolve => service.close(resolve));
  const resolved = path.resolve(temp); if (path.dirname(resolved) === parent && path.basename(resolved).startsWith('cert-x-authz-transport-')) fs.rmSync(resolved, { recursive: true, force: true });
});
